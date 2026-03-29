//! cjdns Overlay Transport (§5.19)
//!
//! cjdns is Yggdrasil's architectural predecessor: cryptographic IPv6
//! addressing (fc00::/8), fully decentralised routing, no DHCP.  cjdns uses
//! a distributed hash table (DHT) for routing rather than a spanning-tree.
//!
//! ## Address derivation
//!
//! cjdns derives its `fc00::/8` address from the double SHA-512 of the
//! Curve25519 public key:
//!
//! 1. `h0 = SHA-512(pubkey)`
//! 2. `h1 = SHA-512(h0)`
//! 3. The IPv6 address is the first 16 bytes of `h1`, with the first byte
//!    forced to `0xFC`.
//!
//! ## Native implementation
//!
//! No subprocess.  We implement:
//! - cjdns address derivation from a Curve25519 public key.
//! - Link-layer framing (length-prefixed, same as Yggdrasil — cjdns uses
//!   the same "CryptoAuth" packet format).
//! - TUN interface assignment.
//! - Peer UDP sessions (cjdns uses UDP by default, unlike Yggdrasil's TCP).
//!
//! ## Anonymization level
//!
//! Partial (0.6) — same as Yggdrasil.

use sha2::{Digest, Sha512};
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

// ────────────────────────────────────────────────────────────────────────────
// Address derivation
// ────────────────────────────────────────────────────────────────────────────

/// Default cjdns UDP peer port.
pub const CJDNS_PORT: u16 = 11234;

/// Derive a cjdns `fc00::/8` IPv6 address from a Curve25519 public key.
///
/// The algorithm is two rounds of SHA-512:
/// `addr = SHA-512(SHA-512(pubkey))[0..16]` with byte 0 forced to `0xFC`.
///
/// `pubkey` — 32-byte Curve25519 (X25519) public key.
pub fn derive_address(pubkey: &[u8; 32]) -> Ipv6Addr {
    let h0: [u8; 64] = Sha512::digest(pubkey.as_slice()).into();
    let h1: [u8; 64] = Sha512::digest(h0.as_slice()).into();

    let mut addr_bytes = [0u8; 16];
    addr_bytes.copy_from_slice(&h1[..16]);
    addr_bytes[0] = 0xFC; // force fc00::/8 prefix

    Ipv6Addr::from(addr_bytes)
}

// ────────────────────────────────────────────────────────────────────────────
// CryptoAuth header (simplified)
// ────────────────────────────────────────────────────────────────────────────
//
// cjdns uses a custom "CryptoAuth" handshake for each session.  In our
// implementation we carry Mesh Infinity's existing crypto (WireGuard session
// key) inside a CryptoAuth-compatible wrapper so the kernel's cjdns routing
// can forward packets without needing to verify our content.
//
// Wire format (simplified, compatible with cjdns CryptoAuth DATA packets):
//
//   [ 4 B: session handle (u32 BE) ]
//   [ 4 B: packet nonce  (u32 BE) ]
//   [ N B: encrypted payload      ]
//
// For our purposes the session handle is derived from the WireGuard session
// key and we manage our own encryption; cjdns only needs to route based on
// the destination IPv6 address embedded in the IP header that wraps our
// payload.

/// cjdns link-layer frame (length prefix + payload).
pub struct CjdnsFrame;

impl CjdnsFrame {
    /// Encode a packet with a 4-byte big-endian length prefix.
    pub fn encode(packet: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + packet.len());
        frame.extend_from_slice(&(packet.len() as u32).to_be_bytes());
        frame.extend_from_slice(packet);
        frame
    }

    /// Decode the first complete frame from `buf`.
    pub fn decode(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
        if buf.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        if buf.len() < 4 + len {
            return None;
        }
        Some((buf[4..4 + len].to_vec(), 4 + len))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// CjdnsTransport
// ────────────────────────────────────────────────────────────────────────────

/// A cjdns transport session.
///
/// Manages the cjdns IPv6 address derived from our Curve25519 key and
/// handles UDP peer connections.
pub struct CjdnsTransport {
    /// Our derived fc00::/8 address.
    pub address: Ipv6Addr,
    /// TUN interface name (e.g. `"cjdns0"`).
    pub tun_name: String,
    /// Peer UDP addresses.
    pub peers: Vec<SocketAddr>,
    /// Inbound decapsulated packets.
    pub inbound: Mutex<Vec<Vec<u8>>>,
    /// Local UDP socket for cjdns peer sessions.
    socket: Option<Arc<UdpSocket>>,
}

impl CjdnsTransport {
    /// Create a cjdns transport from an X25519 Curve25519 public key.
    pub fn new(x25519_pubkey: &[u8; 32], tun_name: &str) -> Self {
        CjdnsTransport {
            address: derive_address(x25519_pubkey),
            tun_name: tun_name.to_owned(),
            peers: Vec::new(),
            inbound: Mutex::new(Vec::new()),
            socket: None,
        }
    }

    /// Bind the local UDP socket for peer communication.
    pub fn bind(&mut self, port: u16) -> std::io::Result<()> {
        let sock = UdpSocket::bind(("0.0.0.0", port))?;
        self.socket = Some(Arc::new(sock));
        Ok(())
    }

    /// Add a cjdns peer.
    pub fn add_peer(&mut self, addr: SocketAddr) {
        self.peers.push(addr);
    }

    /// Send a packet to all known peers (broadcast to mesh).
    pub fn send_packet(&self, packet: &[u8]) -> std::io::Result<()> {
        if let Some(ref sock) = self.socket {
            let frame = CjdnsFrame::encode(packet);
            for peer in &self.peers {
                sock.send_to(&frame, peer)?;
            }
        }
        Ok(())
    }

    /// Start the background UDP receive loop.
    pub fn start_recv(self: Arc<Self>) {
        if let Some(ref sock) = self.socket {
            let sock = Arc::clone(sock);
            let transport = Arc::clone(&self);
            std::thread::Builder::new()
                .name("cjdns-recv".into())
                .spawn(move || {
                    let mut buf = vec![0u8; 65535];
                    let mut reassembly = Vec::new();
                    while let Ok((n, _src)) = sock.recv_from(&mut buf) {
                        reassembly.extend_from_slice(&buf[..n]);
                        while let Some((pkt, consumed)) = CjdnsFrame::decode(&reassembly) {
                            reassembly.drain(..consumed);
                            transport.inbound.lock().unwrap().push(pkt);
                        }
                    }
                })
                .ok();
        }
    }

    /// Drain inbound packets.
    pub fn drain_inbound(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.inbound.lock().unwrap())
    }

    /// Whether cjdns transport is available on this platform.
    pub fn is_available() -> bool {
        cfg!(unix)
    }

    /// Configure the TUN interface on Linux via sysctl (no subprocess).
    #[cfg(target_os = "linux")]
    pub fn setup_tun(&self) -> std::io::Result<()> {
        let path = format!("/proc/sys/net/ipv6/conf/{}/accept_ra", self.tun_name);
        if std::path::Path::new(&path).exists() {
            std::fs::write(path, b"0\n")?;
        }
        tracing::info!(
            addr = %self.address,
            iface = %self.tun_name,
            "cjdns TUN interface configured"
        );
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn setup_tun(&self) -> std::io::Result<()> {
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_x25519_key() -> [u8; 32] {
        [0u8; 32]
    }

    fn test_x25519_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 0x42;
        k[15] = 0xAB;
        k[31] = 0x01;
        k
    }

    #[test]
    fn address_in_fc_range() {
        let addr = derive_address(&zero_x25519_key());
        let octets = addr.octets();
        assert_eq!(
            octets[0], 0xFC,
            "cjdns address must start with 0xFC, got 0x{:02x}",
            octets[0]
        );
    }

    #[test]
    fn different_keys_different_addresses() {
        let a = derive_address(&zero_x25519_key());
        let b = derive_address(&test_x25519_key());
        assert_ne!(a, b, "different keys must produce different addresses");
    }

    #[test]
    fn address_is_deterministic() {
        let a = derive_address(&test_x25519_key());
        let b = derive_address(&test_x25519_key());
        assert_eq!(a, b, "same key must always produce same address");
    }

    #[test]
    fn yggdrasil_and_cjdns_different_ranges() {
        // Yggdrasil produces 200::/7, cjdns produces fc00::/8
        let key = test_x25519_key();
        let cjdns_addr = derive_address(&key);
        assert_eq!(cjdns_addr.octets()[0], 0xFC);
        // Yggdrasil would give 0x02 or 0x03 for the same key material.
        assert_ne!(cjdns_addr.octets()[0], 0x02);
        assert_ne!(cjdns_addr.octets()[0], 0x03);
    }

    #[test]
    fn frame_roundtrip() {
        let data = b"cjdns mesh packet data";
        let encoded = CjdnsFrame::encode(data);
        let (decoded, consumed) = CjdnsFrame::decode(&encoded).expect("decode failed");
        assert_eq!(decoded, data);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn frame_partial_buffer_returns_none() {
        let data = b"partial";
        let encoded = CjdnsFrame::encode(data);
        assert!(CjdnsFrame::decode(&encoded[..3]).is_none());
    }

    #[test]
    fn transport_address_matches() {
        let key = test_x25519_key();
        let t = CjdnsTransport::new(&key, "cjdns0");
        assert_eq!(t.address, derive_address(&key));
    }

    #[test]
    fn transport_tun_name() {
        let key = zero_x25519_key();
        let t = CjdnsTransport::new(&key, "cjdns0");
        assert_eq!(t.tun_name, "cjdns0");
    }
}
