//! Layer 2 / Raw Ethernet Transport (§5.14)
//!
//! # What is the Layer 2 Transport?
//!
//! This transport moves Mesh Infinity packets directly over raw Ethernet
//! frames (IEEE 802.3) using a custom EtherType, bypassing the IP layer
//! entirely.  It is useful when:
//!
//! - Both nodes share a LAN/WiFi segment but DHCP has failed or is
//!   intentionally absent (e.g. isolated ad-hoc networks).
//! - Operating in infrastructure-less IEEE 802.11 IBSS (ad-hoc) mode
//!   where an IP stack is not running.
//! - A hostile environment has disabled IP routing but cannot prevent
//!   raw Ethernet traffic from crossing a switch.
//!
//! # Ethernet Frame Layout
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ Destination MAC  [6 bytes]                                   │
//! │ Source MAC       [6 bytes]                                   │
//! │ EtherType        [2 bytes]  0x88B5 — "experimental use"     │
//! │ Payload length   [2 bytes]                                   │
//! │ Payload          [N bytes]  mesh packet                      │
//! │ FCS              [4 bytes]  appended by the kernel           │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Payload Layout
//!
//! Every payload byte-string begins with a 32-byte sender peer-ID hash
//! followed by the actual mesh packet bytes:
//!
//! ```text
//! [ 32 bytes: peer_id_hash ][ ...mesh packet bytes... ]
//! ```
//!
//! # Platform Support
//!
//! On **Linux** raw Ethernet is accessed via `AF_PACKET / SOCK_RAW` using
//! the `pnet` crate.  On other platforms (macOS, Windows) this transport
//! returns [`Layer2Error::NotAvailable`] for all operations; it is a
//! compile-time stub only.
//!
//! # Reference
//!
//! Spec §5.14 — Layer 2 Ethernet transport.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Custom EtherType for Mesh Infinity Layer 2 frames.
///
/// 0x88B5 is allocated by IEEE for "IEEE Std 802 — Local Experimental
/// EtherType" and is safe to use for private/experimental protocols on a
/// local LAN segment.  Unlike a registered EtherType, 0x88B5 will never be
/// confused with production protocols (IPv4 = 0x0800, IPv6 = 0x86DD, ARP =
/// 0x0806) by any switch, firewall, or network monitoring tool.  Frames with
/// this EtherType will pass through unmanaged L2 switches but may be blocked
/// by managed switches with strict VLAN/protocol filtering.
pub const MESH_INFINITY_ETHERTYPE: u16 = 0x88B5;

/// Ethernet broadcast MAC address — `FF:FF:FF:FF:FF:FF`.
pub const MAC_BROADCAST: [u8; 6] = [0xFF; 6];

/// Minimum length of the fixed header that precedes the mesh packet in
/// every payload: 32 bytes of peer-ID hash.
const PEER_ID_HEADER_LEN: usize = 32;

/// Maximum Ethernet payload (MTU 1500) minus the 4-byte length header
/// that this transport prepends.  The raw Ethernet payload field is
/// 1500 bytes maximum; we reserve 2 bytes for the payload-length field.
///
/// 1500 - 2 = 1498, but the spec §5.14 specifies 1496 to leave room for
/// a 2-byte reserved/version field that future revisions may use.
pub const MAX_PAYLOAD: usize = 1496;

// ---------------------------------------------------------------------------
// MacAddress
// ---------------------------------------------------------------------------

/// A 6-byte IEEE 802 MAC address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl std::str::FromStr for MacAddress {
    type Err = Layer2Error;

    /// Parse a colon-separated MAC address string such as `"aa:bb:cc:dd:ee:ff"`.
    ///
    /// Returns `Err` with a human-readable description if the string is not a
    /// valid 6-octet colon-separated hex address.
    fn from_str(s: &str) -> Result<Self, Layer2Error> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(Layer2Error::ParseError(format!(
                "expected 6 colon-separated octets, got {}: {:?}",
                parts.len(),
                s
            )));
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).map_err(|e| {
                Layer2Error::ParseError(format!("invalid hex octet {:?}: {}", part, e))
            })?;
        }
        Ok(MacAddress(bytes))
    }
}

impl MacAddress {
    /// Returns `true` if this is the Ethernet broadcast address
    /// `FF:FF:FF:FF:FF:FF`.
    pub fn is_broadcast(&self) -> bool {
        self.0 == MAC_BROADCAST
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Inline the formatting directly to avoid calling self.to_string(),
        // which would delegate back to Display::fmt and recurse infinitely.
        let b = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

// ---------------------------------------------------------------------------
// Layer2Frame
// ---------------------------------------------------------------------------

/// A decoded Mesh Infinity Layer 2 frame.
#[derive(Debug, Clone)]
pub struct Layer2Frame {
    /// Source MAC address as seen on the wire.
    pub src_mac: MacAddress,
    /// Destination MAC address (unicast or broadcast).
    pub dst_mac: MacAddress,
    /// Raw payload bytes (everything after the EtherType + length field).
    pub payload: Vec<u8>,
}

impl Layer2Frame {
    /// Extract the 32-byte sender peer-ID hash embedded at the start of
    /// every Mesh Infinity payload.
    ///
    /// Returns `None` if the payload is shorter than 32 bytes.
    pub fn peer_id(&self) -> Option<[u8; 32]> {
        if self.payload.len() < PEER_ID_HEADER_LEN {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&self.payload[..PEER_ID_HEADER_LEN]);
        Some(id)
    }

    /// Return the actual mesh packet bytes, i.e. everything after the
    /// 32-byte peer-ID header.
    ///
    /// Returns an empty slice if the payload is shorter than 32 bytes.
    pub fn mesh_payload(&self) -> &[u8] {
        if self.payload.len() < PEER_ID_HEADER_LEN {
            return &[];
        }
        &self.payload[PEER_ID_HEADER_LEN..]
    }
}

// ---------------------------------------------------------------------------
// Layer2Error
// ---------------------------------------------------------------------------

/// Errors that can occur in the Layer 2 transport.
#[derive(Debug)]
pub enum Layer2Error {
    /// Raw Ethernet is not available on this platform (non-Linux).
    NotAvailable,
    /// The requested network interface does not exist.
    InterfaceNotFound(String),
    /// The process does not have permission to open a raw socket.
    /// On Linux, either `CAP_NET_RAW` or running as root is required.
    PermissionDenied,
    /// An I/O error occurred during send or receive.
    IoError(String),
    /// The payload exceeds [`MAX_PAYLOAD`] bytes and cannot be sent in a
    /// single Ethernet frame.
    FrameTooLarge,
    /// A received frame or address could not be parsed.
    ParseError(String),
}

impl std::fmt::Display for Layer2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layer2Error::NotAvailable => {
                write!(
                    f,
                    "Layer 2 raw Ethernet transport is not available on this platform"
                )
            }
            Layer2Error::InterfaceNotFound(name) => {
                write!(f, "network interface not found: {}", name)
            }
            Layer2Error::PermissionDenied => {
                write!(
                    f,
                    "permission denied: CAP_NET_RAW or root is required for AF_PACKET sockets"
                )
            }
            Layer2Error::IoError(msg) => write!(f, "I/O error: {}", msg),
            Layer2Error::FrameTooLarge => write!(
                f,
                "payload exceeds maximum Ethernet frame size ({} bytes)",
                MAX_PAYLOAD
            ),
            Layer2Error::ParseError(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for Layer2Error {}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
    use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::Packet;
    use pnet::util::MacAddr;

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Convert our [`MacAddress`] to a `pnet` [`MacAddr`].
    fn to_pnet_mac(addr: &MacAddress) -> MacAddr {
        let b = addr.0;
        MacAddr(b[0], b[1], b[2], b[3], b[4], b[5])
    }

    /// Convert a `pnet` [`MacAddr`] to our [`MacAddress`].
    fn from_pnet_mac(addr: MacAddr) -> MacAddress {
        MacAddress([addr.0, addr.1, addr.2, addr.3, addr.4, addr.5])
    }

    /// Find a `pnet` [`NetworkInterface`] by name.
    fn find_interface(name: &str) -> Result<NetworkInterface, Layer2Error> {
        datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| Layer2Error::InterfaceNotFound(name.to_owned()))
    }

    // -----------------------------------------------------------------------
    // Layer2Transport — Linux
    // -----------------------------------------------------------------------

    /// Layer 2 raw Ethernet transport (Linux implementation).
    pub struct Layer2Transport {
        pub(super) interface_name: String,
        pub(super) our_mac: MacAddress,
        pub(super) inbound: Mutex<VecDeque<Layer2Frame>>,
        /// The pnet datalink sender.  Wrapped in `Option` so that
        /// `start_receive_loop` can move out the receiver while keeping the
        /// sender here.
        pub(super) tx: Mutex<Option<Box<dyn DataLinkSender + Send>>>,
        /// The pnet datalink receiver, stored until `start_receive_loop` is
        /// called.  After that it is moved into the background thread and
        /// this field is `None`.
        pub(super) rx: Mutex<Option<Box<dyn DataLinkReceiver + Send>>>,
    }

    impl Layer2Transport {
        /// List all network interfaces that are suitable for Layer 2 use
        /// (UP, not loopback, have a MAC address).
        pub fn list_interfaces() -> Vec<String> {
            datalink::interfaces()
                .into_iter()
                .filter(|iface| !iface.is_loopback() && iface.is_up() && iface.mac.is_some())
                .map(|iface| iface.name.clone())
                .collect()
        }

        /// Open a raw datalink channel on `interface_name`.
        ///
        /// # Errors
        ///
        /// - [`Layer2Error::InterfaceNotFound`] if the interface does not exist.
        /// - [`Layer2Error::PermissionDenied`] if the process lacks `CAP_NET_RAW`.
        /// - [`Layer2Error::IoError`] for other OS errors.
        pub fn new(interface_name: &str) -> Result<Self, Layer2Error> {
            let iface = find_interface(interface_name)?;

            // Extract our own MAC from the interface descriptor.
            let our_mac = match iface.mac {
                Some(m) => from_pnet_mac(m),
                None => {
                    return Err(Layer2Error::IoError(format!(
                        "interface {} has no MAC address",
                        interface_name
                    )))
                }
            };

            // Open the raw datalink channel.
            let channel = match datalink::channel(&iface, Default::default()) {
                Ok(ch) => ch,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("Permission denied") || msg.contains("EPERM") {
                        return Err(Layer2Error::PermissionDenied);
                    }
                    return Err(Layer2Error::IoError(msg));
                }
            };

            let (tx, rx) = match channel {
                Channel::Ethernet(tx, rx) => (tx, rx),
                _ => {
                    return Err(Layer2Error::IoError(
                        "unexpected channel type returned by pnet".to_owned(),
                    ))
                }
            };

            Ok(Layer2Transport {
                interface_name: interface_name.to_owned(),
                our_mac,
                inbound: Mutex::new(VecDeque::new()),
                tx: Mutex::new(Some(tx)),
                rx: Mutex::new(Some(rx)),
            })
        }

        /// Build and send a raw Ethernet frame carrying `payload` to `dst_mac`.
        ///
        /// The EtherType is always [`MESH_INFINITY_ETHERTYPE`].  The 2-byte
        /// payload-length field is written immediately after the EtherType.
        ///
        /// # Errors
        ///
        /// - [`Layer2Error::FrameTooLarge`] if `payload.len() > MAX_PAYLOAD`.
        /// - [`Layer2Error::IoError`] if `send` returns an error or `None`.
        pub fn send_to(&self, dst_mac: &MacAddress, payload: &[u8]) -> Result<(), Layer2Error> {
            if payload.len() > MAX_PAYLOAD {
                return Err(Layer2Error::FrameTooLarge);
            }

            // Ethernet frame structure:
            //   dst (6) + src (6) + ethertype (2) + length (2) + payload (N)
            // Minimum Ethernet payload is 46 bytes; pad if necessary.
            let inner_len = 2 + payload.len(); // length field + payload
            let raw_payload_len = inner_len.max(46);
            let frame_len = 14 + raw_payload_len; // 14-byte Ethernet header

            let mut frame_buf = vec![0u8; frame_len];

            {
                let mut pkt = MutableEthernetPacket::new(&mut frame_buf).ok_or_else(|| {
                    Layer2Error::IoError("failed to construct MutableEthernetPacket".to_owned())
                })?;

                pkt.set_destination(to_pnet_mac(dst_mac));
                pkt.set_source(to_pnet_mac(&self.our_mac));
                pkt.set_ethertype(EtherType(MESH_INFINITY_ETHERTYPE));

                // Build the payload: [length: u16 BE][payload bytes][padding]
                let mut inner = vec![0u8; raw_payload_len];
                let len_u16 = payload.len() as u16;
                inner[0] = (len_u16 >> 8) as u8;
                inner[1] = (len_u16 & 0xFF) as u8;
                inner[2..2 + payload.len()].copy_from_slice(payload);
                pkt.set_payload(&inner);
            }

            let mut guard = self.tx.lock().unwrap_or_else(|e| e.into_inner());
            let tx = guard.as_mut().ok_or_else(|| {
                Layer2Error::IoError("TX channel has been consumed by the receive loop".to_owned())
            })?;

            match tx.send_to(&frame_buf, None) {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(Layer2Error::IoError(e.to_string())),
                None => Err(Layer2Error::IoError(
                    "pnet send_to returned None (interface may have disappeared)".to_owned(),
                )),
            }
        }

        /// Broadcast `payload` to all nodes on the local LAN segment by
        /// sending to the Ethernet broadcast address `FF:FF:FF:FF:FF:FF`.
        pub fn broadcast(&self, payload: &[u8]) -> Result<(), Layer2Error> {
            self.send_to(&MacAddress(MAC_BROADCAST), payload)
        }

        /// Start the background receive loop.
        ///
        /// Spawns a dedicated OS thread that reads raw Ethernet frames from
        /// the interface in a blocking loop.  Only frames carrying
        /// [`MESH_INFINITY_ETHERTYPE`] are accepted; all others are silently
        /// discarded.  Accepted frames are decoded and pushed into the
        /// internal inbound queue.
        ///
        /// Call [`Layer2Transport::drain_inbound`] periodically to consume
        /// queued frames.
        ///
        /// # Panics
        ///
        /// Panics if called a second time on the same transport (the receiver
        /// has already been moved into the background thread).
        pub fn start_receive_loop(self: Arc<Self>) -> std::thread::JoinHandle<()> {
            // Move the receiver out of the Mutex.  Subsequent calls will find
            // `None` and this method will panic, which is intentional.
            let mut rx = self
                .rx
                .lock()
                .unwrap()
                .take()
                .expect("start_receive_loop called more than once on the same Layer2Transport");

            let transport = Arc::clone(&self);
            std::thread::spawn(move || {
                loop {
                    match rx.next() {
                        Ok(raw) => {
                            if let Some(frame) = Self::try_decode_frame(raw) {
                                transport.inbound.lock().unwrap().push_back(frame);
                            }
                        }
                        Err(e) => {
                            // Log but do not abort — transient errors on a
                            // live interface (e.g. buffer overrun) should not
                            // bring down the receive loop.
                            eprintln!(
                                "[layer2] receive error on {}: {}",
                                transport.interface_name, e
                            );
                        }
                    }
                }
            })
        }

        /// Decode a raw byte slice into a [`Layer2Frame`].
        ///
        /// Returns `None` if the frame is not a valid Mesh Infinity frame
        /// (wrong EtherType, malformed length field, or truncated payload).
        pub(crate) fn try_decode_frame(raw: &[u8]) -> Option<Layer2Frame> {
            let eth = EthernetPacket::new(raw)?;

            if eth.get_ethertype() != EtherType(MESH_INFINITY_ETHERTYPE) {
                return None;
            }

            let src_mac = MacAddress([
                eth.get_source().0,
                eth.get_source().1,
                eth.get_source().2,
                eth.get_source().3,
                eth.get_source().4,
                eth.get_source().5,
            ]);
            let dst_mac = MacAddress([
                eth.get_destination().0,
                eth.get_destination().1,
                eth.get_destination().2,
                eth.get_destination().3,
                eth.get_destination().4,
                eth.get_destination().5,
            ]);

            let raw_payload = eth.payload();

            // Validate that we have at least 2 bytes for the length field.
            if raw_payload.len() < 2 {
                return None;
            }

            let declared_len = ((raw_payload[0] as usize) << 8) | (raw_payload[1] as usize);

            // Validate that the declared length is within the available bytes.
            if 2 + declared_len > raw_payload.len() {
                return None;
            }

            let payload = raw_payload[2..2 + declared_len].to_vec();

            Some(Layer2Frame {
                src_mac,
                dst_mac,
                payload,
            })
        }

        /// Drain all queued inbound frames and return them.
        ///
        /// This is the primary way for higher layers to consume received
        /// data.  Frames are returned in the order they were received.
        pub fn drain_inbound(&self) -> Vec<Layer2Frame> {
            let mut guard = self.inbound.lock().unwrap_or_else(|e| e.into_inner());
            guard.drain(..).collect()
        }

        /// Return our MAC address on this interface.
        pub fn our_mac(&self) -> &MacAddress {
            &self.our_mac
        }

        /// Maximum payload size in bytes for a single frame.
        ///
        /// Ethernet MTU is 1500 bytes.  We reserve 2 bytes for the
        /// payload-length header, and 2 bytes for a future version/reserved
        /// field, giving 1496 usable bytes.
        pub fn max_payload() -> usize {
            MAX_PAYLOAD
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Linux stub
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::*;

    /// Layer 2 raw Ethernet transport — stub for non-Linux platforms.
    ///
    /// All operations return [`Layer2Error::NotAvailable`].  This type is
    /// present so that code that conditionally uses Layer 2 can be compiled
    /// on all platforms without `#[cfg]` guards at every call site.
    pub struct Layer2Transport {
        pub(super) our_mac: MacAddress,
    }

    impl Layer2Transport {
        /// Always returns an empty list on non-Linux platforms.
        pub fn list_interfaces() -> Vec<String> {
            vec![]
        }

        /// Always returns [`Layer2Error::NotAvailable`] on non-Linux platforms.
        pub fn new(_interface_name: &str) -> Result<Self, Layer2Error> {
            Err(Layer2Error::NotAvailable)
        }

        pub fn send_to(&self, _dst_mac: &MacAddress, _payload: &[u8]) -> Result<(), Layer2Error> {
            Err(Layer2Error::NotAvailable)
        }

        pub fn broadcast(&self, _payload: &[u8]) -> Result<(), Layer2Error> {
            Err(Layer2Error::NotAvailable)
        }

        pub fn start_receive_loop(self: Arc<Self>) -> std::thread::JoinHandle<()> {
            std::thread::spawn(|| {})
        }

        pub fn drain_inbound(&self) -> Vec<Layer2Frame> {
            vec![]
        }

        pub fn our_mac(&self) -> &MacAddress {
            &self.our_mac
        }

        pub fn max_payload() -> usize {
            MAX_PAYLOAD
        }
    }
}

// ---------------------------------------------------------------------------
// Re-export the platform-specific implementation under a single name
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub use linux::Layer2Transport;

// Expose `try_decode_frame` for tests on Linux (it is `fn`, so we cannot
// use `#[cfg(test)]` on the method itself without duplicating it).  We add
// a thin test-only wrapper here rather than making the real method `pub`.
#[cfg(all(target_os = "linux", test))]
impl linux::Layer2Transport {
    pub fn try_decode_frame_pub(raw: &[u8]) -> Option<Layer2Frame> {
        Self::try_decode_frame(raw)
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::Layer2Transport;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;

    // -----------------------------------------------------------------------
    // MacAddress — parsing and formatting
    // -----------------------------------------------------------------------

    #[test]
    fn mac_roundtrip_lowercase() {
        let s = "de:ad:be:ef:ca:fe";
        let mac = MacAddress::from_str(s).expect("parse failed");
        assert_eq!(mac.0, [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
        assert_eq!(mac.to_string(), s);
    }

    #[test]
    fn mac_roundtrip_uppercase() {
        // from_str must accept uppercase hex digits.
        let mac = MacAddress::from_str("DE:AD:BE:EF:CA:FE").expect("parse failed");
        assert_eq!(mac.0, [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
        // to_string always produces lowercase.
        assert_eq!(mac.to_string(), "de:ad:be:ef:ca:fe");
    }

    #[test]
    fn mac_broadcast_detection() {
        let bcast = MacAddress(MAC_BROADCAST);
        assert!(bcast.is_broadcast());

        let unicast = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!unicast.is_broadcast());
    }

    #[test]
    fn mac_parse_invalid_octet_count() {
        assert!(MacAddress::from_str("aa:bb:cc:dd:ee").is_err()); // 5 octets
        assert!(MacAddress::from_str("aa:bb:cc:dd:ee:ff:00").is_err()); // 7 octets
        assert!(MacAddress::from_str("").is_err());
    }

    #[test]
    fn mac_parse_invalid_hex() {
        assert!(MacAddress::from_str("gg:bb:cc:dd:ee:ff").is_err());
        assert!(MacAddress::from_str("aa:bb:cc:dd:ee:zz").is_err());
    }

    #[test]
    fn mac_display_trait() {
        let mac = MacAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(format!("{}", mac), "01:02:03:04:05:06");
    }

    // -----------------------------------------------------------------------
    // Layer2Frame — peer_id and mesh_payload helpers
    // -----------------------------------------------------------------------

    #[test]
    fn frame_peer_id_and_mesh_payload() {
        let mut payload = vec![0u8; 32 + 10];
        // Fill peer-ID area with a known pattern.
        for (i, b) in payload[..32].iter_mut().enumerate() {
            *b = i as u8;
        }
        // Fill mesh payload with a different pattern.
        for b in payload[32..].iter_mut() {
            *b = 0xAB;
        }

        let frame = Layer2Frame {
            src_mac: MacAddress([0x00; 6]),
            dst_mac: MacAddress(MAC_BROADCAST),
            payload,
        };

        let pid = frame.peer_id().expect("peer_id should be Some");
        for (i, &b) in pid.iter().enumerate() {
            assert_eq!(b, i as u8, "peer_id byte {} mismatch", i);
        }

        let mp = frame.mesh_payload();
        assert_eq!(mp.len(), 10);
        assert!(mp.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn frame_peer_id_too_short() {
        let frame = Layer2Frame {
            src_mac: MacAddress([0x00; 6]),
            dst_mac: MacAddress([0x00; 6]),
            payload: vec![0u8; 10], // shorter than 32
        };
        assert!(frame.peer_id().is_none());
        assert_eq!(frame.mesh_payload(), &[] as &[u8]);
    }

    #[test]
    fn frame_peer_id_exactly_32_bytes() {
        let frame = Layer2Frame {
            src_mac: MacAddress([0x00; 6]),
            dst_mac: MacAddress([0x00; 6]),
            payload: vec![0xFFu8; 32],
        };
        assert!(frame.peer_id().is_some());
        assert_eq!(frame.mesh_payload(), &[] as &[u8]);
    }

    // -----------------------------------------------------------------------
    // list_interfaces — must not panic
    // -----------------------------------------------------------------------

    #[test]
    fn list_interfaces_does_not_panic() {
        // We do not assert anything about the result because in a CI sandbox
        // there may be no suitable interfaces.  The important invariant is
        // that this call does not panic.
        let _ifaces = Layer2Transport::list_interfaces();
    }

    // -----------------------------------------------------------------------
    // new() with a non-existent interface — must return an error, not panic
    // -----------------------------------------------------------------------

    #[test]
    fn new_nonexistent_interface_returns_error() {
        let result =
            Layer2Transport::new("mesh_infinity_test_iface_that_does_not_exist_xyzzy_12345");
        match result {
            Err(Layer2Error::NotAvailable) => {
                // Acceptable on non-Linux platforms.
            }
            Err(Layer2Error::InterfaceNotFound(_)) => {
                // Expected on Linux.
            }
            Err(Layer2Error::PermissionDenied) => {
                // Acceptable if the test runs without CAP_NET_RAW —
                // pnet may attempt to open the socket before checking
                // that the interface exists.
            }
            Err(_) => {
                // Any other error variant is also acceptable; the key
                // requirement is that it must not be Ok(_) or panic.
            }
            Ok(_) => {
                panic!("expected an error for a nonexistent interface, got Ok");
            }
        }
    }

    // -----------------------------------------------------------------------
    // MAX_PAYLOAD constant
    // -----------------------------------------------------------------------

    #[test]
    fn max_payload_constant() {
        assert_eq!(Layer2Transport::max_payload(), 1496);
        assert_eq!(MAX_PAYLOAD, 1496);
    }

    // -----------------------------------------------------------------------
    // MESH_INFINITY_ETHERTYPE constant
    // -----------------------------------------------------------------------

    #[test]
    fn ethertype_value() {
        assert_eq!(MESH_INFINITY_ETHERTYPE, 0x88B5);
    }

    // -----------------------------------------------------------------------
    // Frame construction round-trip (Linux only — uses the decode helper)
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn frame_decode_rejects_wrong_ethertype() {
        use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
        use pnet::util::MacAddr;

        let inner_payload = b"hello mesh";
        let inner_len = 2 + inner_payload.len();
        let frame_len = 14 + inner_len.max(46);
        let mut buf = vec![0u8; frame_len];
        {
            let mut pkt = MutableEthernetPacket::new(&mut buf).unwrap();
            pkt.set_destination(MacAddr::broadcast());
            pkt.set_source(MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF));
            // Use IPv4 EtherType — should be rejected.
            pkt.set_ethertype(EtherTypes::Ipv4);
            let mut inner = vec![0u8; inner_len.max(46)];
            inner[0] = (inner_payload.len() >> 8) as u8;
            inner[1] = (inner_payload.len() & 0xFF) as u8;
            inner[2..2 + inner_payload.len()].copy_from_slice(inner_payload);
            pkt.set_payload(&inner);
        }
        assert!(linux::Layer2Transport::try_decode_frame_pub(&buf).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn frame_decode_accepts_mesh_ethertype() {
        use pnet::packet::ethernet::{EtherType, MutableEthernetPacket};
        use pnet::util::MacAddr;

        let inner_payload = b"hello mesh";
        let inner_len = 2 + inner_payload.len();
        let frame_len = 14 + inner_len.max(46);
        let mut buf = vec![0u8; frame_len];
        {
            let mut pkt = MutableEthernetPacket::new(&mut buf).unwrap();
            pkt.set_destination(MacAddr::broadcast());
            pkt.set_source(MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF));
            pkt.set_ethertype(EtherType(MESH_INFINITY_ETHERTYPE));
            let mut inner = vec![0u8; inner_len.max(46)];
            inner[0] = (inner_payload.len() >> 8) as u8;
            inner[1] = (inner_payload.len() & 0xFF) as u8;
            inner[2..2 + inner_payload.len()].copy_from_slice(inner_payload);
            pkt.set_payload(&inner);
        }
        let frame = linux::Layer2Transport::try_decode_frame_pub(&buf)
            .expect("should decode a valid Mesh Infinity frame");
        assert_eq!(frame.payload.as_slice(), &inner_payload[..]);
        assert!(frame.dst_mac.is_broadcast());
        assert_eq!(frame.src_mac.to_string(), "aa:bb:cc:dd:ee:ff");
    }
}
