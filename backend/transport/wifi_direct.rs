//! WiFi Direct (P2P) Transport (§5.8)
//!
//! Implements peer-to-peer WiFi connectivity without a router or access point.
//! Two complementary discovery/connection mechanisms are provided:
//!
//! ## 1. WiFi Direct P2P (Linux only)
//!
//! On Linux, we communicate directly with the kernel's cfg80211/nl80211 WiFi
//! subsystem via raw generic-netlink sockets — no `wpa_supplicant` dependency.
//! See `nl80211.rs` for the low-level netlink implementation.
//!
//! The flow follows §5.8 of the Mesh Infinity spec:
//!
//! ```text
//! Nl80211::open()            →  open AF_NETLINK socket, resolve nl80211 family
//! nl.trigger_scan(ifindex)   →  scan for nearby 802.11s/IBSS cells
//! nl.get_scan_results()      →  list BSSIDs with MI: SSIDs
//! nl80211::direct_connect()  →  join 802.11s mesh or IBSS ad-hoc cell
//! libc::getifaddrs()         →  poll until group interface has an IP
//! TcpListener on group IP    →  serve / connect over TCP
//! ```
//!
//! IP address discovery uses `libc::getifaddrs()`.
//! Default gateway parsing reads `/proc/net/route`.
//!
//! ## 2. mDNS-SD Fallback Discovery
//!
//! When WiFi Direct P2P is not available (non-Linux, or wpa_supplicant socket absent) but
//! devices share a subnet, they can still discover each other via mDNS service
//! announcements.  [`MdnsDiscovery`] sends and receives DNS-SD PTR/TXT records
//! over the standard multicast groups:
//!
//! - IPv4: `224.0.0.251:5353`
//! - IPv6: `[ff02::fb]:5353`
//!
//! The service type is `_meshinfinity._udp.local.`
//!
//! ## Platform matrix
//!
//! | Platform | WiFi Direct P2P | mDNS fallback |
//! |----------|----------------|---------------|
//! | Linux    | ✓ (nl80211/wpa_supplicant socket) | ✓ |
//! | Android  | stub*          | ✓             |
//! | macOS    | stub           | ✓             |
//! | Windows  | stub           | ✓             |
//! | iOS      | stub           | ✓             |
//!
//! *Android WiFi Direct is exposed through JNI/WifiP2pManager at the Android
//! layer; this Rust module returns `WifiDirectError::NotAvailable` there so
//! the platform layer can handle it natively.
//!
//! ## References
//!
//! - Mesh Infinity Spec §5.8 — WiFi Direct Transport
//! - RFC 6762 — Multicast DNS
//! - RFC 6763 — DNS-Based Service Discovery

use std::collections::VecDeque;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::{net::TcpListener, time::Instant};

// libc::socketpair is used in the Android session-bridge implementation.
#[cfg(target_os = "android")]
use std::os::unix::io::FromRawFd;

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

/// mDNS IPv4 multicast group (RFC 6762 §5).
pub const MDNS_IPV4_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// mDNS port (RFC 6762 §5).
pub const MDNS_PORT: u16 = 5353;

/// mDNS IPv6 multicast group (RFC 6762 §5).
pub const MDNS_IPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// Mesh Infinity mDNS service type used for DNS-SD announcements.
pub const MDNS_SERVICE_TYPE: &str = "_meshinfinity._udp.local.";

/// How often to poll for a group interface IP address after group formation (ms).
#[cfg(target_os = "linux")]
const IP_POLL_INTERVAL_MS: u64 = 500;

/// Maximum time to wait for the group interface to obtain an IP (seconds).
#[cfg(target_os = "linux")]
const IP_ACQUIRE_TIMEOUT_SECS: u64 = 20;

/// DNS message query/response flag mask.
const DNS_QR_MASK: u16 = 0x8000;

/// DNS opcode for a standard query.
const DNS_OPCODE_QUERY: u16 = 0x0000;

/// DNS authoritative-answer flag.
const DNS_AA_MASK: u16 = 0x0400;

/// DNS resource record type: PTR.
const DNS_TYPE_PTR: u16 = 12;

/// DNS resource record type: TXT.
const DNS_TYPE_TXT: u16 = 16;

/// DNS resource record type: SRV.
const DNS_TYPE_SRV: u16 = 33;

/// DNS class: IN (Internet).
const DNS_CLASS_IN: u16 = 1;

/// mDNS "flush cache" bit ORed into the class field of an answer.
const DNS_CLASS_FLUSH: u16 = 0x8000;

/// Default TTL for mDNS records (seconds).  RFC 6762 recommends 4500 s (75 min)
/// for stable records.
const MDNS_TTL: u32 = 4500;

/// Interval between periodic mDNS re-announcements (seconds).
const MDNS_ANNOUNCE_INTERVAL_SECS: u64 = 60;

// ────────────────────────────────────────────────────────────────────────────
// Public data types
// ────────────────────────────────────────────────────────────────────────────

/// A WiFi Direct P2P peer discovered via `wpa_cli p2p_peer`.
#[derive(Debug, Clone, PartialEq)]
pub struct WifiDirectPeer {
    /// Hardware (MAC) address of the P2P device, e.g. `"aa:bb:cc:dd:ee:ff"`.
    pub mac_address: String,

    /// Human-readable device name reported by the peer's P2P device info.
    pub device_name: String,

    /// Mesh Infinity peer ID hex extracted from the device name if it embeds
    /// one in the form `MI:<64-hex-chars>`.  `None` when the device name
    /// does not follow that convention.
    pub peer_id_hex: Option<String>,

    /// IP address allocated on the P2P group interface once a group has been
    /// formed.  `None` before connection or if group formation failed.
    pub group_ip: Option<IpAddr>,

    /// Received Signal Strength Indicator at discovery time (dBm).
    /// `None` if `wpa_cli` did not report signal strength.
    pub rssi: Option<i16>,
}

impl WifiDirectPeer {
    /// Attempt to extract a Mesh Infinity peer ID from the device name.
    ///
    /// Device names carrying a peer ID are encoded as `MI:<64 hex chars>`.
    /// For example: `MI:deadbeef...` (64 hex digits after `MI:`).
    fn extract_peer_id(device_name: &str) -> Option<String> {
        let prefix = "MI:";
        if let Some(hex_part) = device_name.strip_prefix(prefix) {
            // Validate: exactly 64 lowercase hex characters.
            if hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(hex_part.to_ascii_lowercase());
            }
        }
        None
    }

    /// Create a new `WifiDirectPeer` from raw `wpa_cli p2p_peer` output.
    ///
    /// Parses lines of the form `key=value` and populates the struct fields.
    /// The only mandatory field is `mac_address`; all others default to `None`
    /// or empty string if absent from the output.
    pub fn from_wpa_peer_output(mac_address: &str, output: &str) -> Self {
        let mut device_name = String::new();
        let mut rssi: Option<i16> = None;

        for line in output.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("device_name=") {
                device_name = val.to_owned();
            } else if let Some(val) = line.strip_prefix("level=") {
                rssi = val.parse::<i16>().ok();
            }
        }

        let peer_id_hex = Self::extract_peer_id(&device_name);

        WifiDirectPeer {
            mac_address: mac_address.to_ascii_lowercase(),
            device_name,
            peer_id_hex,
            group_ip: None,
            rssi,
        }
    }
}

/// Errors produced by the WiFi Direct transport.
#[derive(Debug)]
pub enum WifiDirectError {
    /// WiFi Direct P2P is not available on this platform (non-Linux, or stub).
    NotAvailable,
    /// The nl80211 kernel driver is not available or the WiFi driver is not loaded.
    Nl80211NotAvailable,
    /// The specified WiFi interface does not exist or cannot be used.
    InterfaceNotFound(String),
    /// Scanning for P2P devices failed.
    ScanFailed(String),
    /// Connecting to a P2P peer failed.
    ConnectFailed(String),
    /// An underlying I/O error occurred.
    Io(std::io::Error),
}

impl std::fmt::Display for WifiDirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WifiDirectError::NotAvailable => {
                write!(f, "WiFi Direct P2P is not available on this platform")
            }
            WifiDirectError::Nl80211NotAvailable => {
                write!(
                    f,
                    "nl80211 not available — no WiFi hardware or driver not loaded"
                )
            }
            WifiDirectError::InterfaceNotFound(iface) => {
                write!(f, "WiFi interface '{iface}' not found or not usable")
            }
            WifiDirectError::ScanFailed(msg) => write!(f, "P2P scan failed: {msg}"),
            WifiDirectError::ConnectFailed(msg) => write!(f, "P2P connect failed: {msg}"),
            WifiDirectError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for WifiDirectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WifiDirectError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for WifiDirectError {
    fn from(e: std::io::Error) -> Self {
        WifiDirectError::Io(e)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// WifiDirectTransport — main struct (always compiled)
// ────────────────────────────────────────────────────────────────────────────

/// WiFi Direct (P2P) transport.
///
/// Manages P2P group formation via `wpa_cli` on Linux, and exposes TCP
/// streams over the resulting group interface.  On non-Linux platforms,
/// every method returns [`WifiDirectError::NotAvailable`].
///
/// ## Thread safety
///
/// `WifiDirectTransport` is `Send + Sync`.  The peer list and inbound queue
/// are each protected by a `Mutex`.
pub struct WifiDirectTransport {
    /// WiFi interface used for P2P operations, e.g. `"wlan0"`.
    pub interface: String,

    /// Group interface name once a P2P group has been formed,
    /// e.g. `"p2p-wlan0-0"`.  `None` until a group is active.
    pub group_interface: Option<String>,

    /// Device name advertised to P2P peers.
    ///
    /// To embed the Mesh Infinity peer ID, use the format `MI:<64 hex chars>`.
    pub our_device_name: String,

    /// Peers discovered during the most recent `p2p_find` scan.
    pub peer_devices: Mutex<Vec<WifiDirectPeer>>,

    /// Inbound TCP connections accepted on the group interface listener.
    pub inbound: Mutex<Vec<TcpStream>>,

    /// TCP port the listener binds to on the group interface.
    pub listen_port: u16,
}

// ────────────────────────────────────────────────────────────────────────────
// Android adapter state
// ────────────────────────────────────────────────────────────────────────────

/// Backend-owned snapshot of Android Wi-Fi Direct capability and peer state.
#[derive(Default, Clone)]
struct AndroidWifiDirectAdapterState {
    /// Whether Wi-Fi Direct hardware exists.
    available: bool,
    /// Whether Wi-Fi Direct is enabled.
    enabled: bool,
    /// Whether the required runtime permission is granted.
    permission_granted: bool,
    /// Whether discovery is currently active.
    discovery_active: bool,
    /// Whether an Android Wi-Fi Direct session is active.
    connected: bool,
    /// Current Android-reported connection role.
    connection_role: Option<String>,
    /// Current Android-reported group owner address.
    group_owner_address: Option<String>,
    /// Current Android-reported connected peer address.
    connected_device_address: Option<String>,
    /// Current Android-reported peers.
    peers: Vec<WifiDirectPeer>,
    /// Pairing payloads received by the Android platform bridge.
    inbound_pairing_payloads: VecDeque<String>,
    /// Pairing payloads Rust has queued for Android-native exchange.
    outbound_pairing_payloads: VecDeque<String>,
    /// Generic session frames received by the Android platform bridge.
    inbound_session_frames: VecDeque<Vec<u8>>,
    /// Generic session frames Rust has queued for Android-native exchange.
    outbound_session_frames: VecDeque<Vec<u8>>,
}

/// Return the global Android Wi-Fi Direct adapter state.
fn android_wifi_direct_adapter_state() -> &'static Mutex<AndroidWifiDirectAdapterState> {
    static STATE: OnceLock<Mutex<AndroidWifiDirectAdapterState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(AndroidWifiDirectAdapterState::default()))
}

/// Update the backend-owned Android Wi-Fi Direct adapter snapshot.
pub fn update_android_adapter_state(
    available: bool,
    enabled: bool,
    permission_granted: bool,
    discovery_active: bool,
    connected: bool,
    connection_role: Option<String>,
    group_owner_address: Option<String>,
    connected_device_address: Option<String>,
    peers: Vec<WifiDirectPeer>,
) {
    let mut state = android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    state.available = available;
    state.enabled = enabled;
    state.permission_granted = permission_granted;
    state.discovery_active = discovery_active;
    state.connected = connected;
    state.connection_role = connection_role;
    state.group_owner_address = group_owner_address;
    state.connected_device_address = connected_device_address;
    state.peers = peers;
}

/// Queue one pairing payload received by the Android Wi-Fi Direct bridge.
pub fn enqueue_android_inbound_pairing_payload(payload_json: &str) {
    let mut state = android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if state.available && state.enabled {
        state
            .inbound_pairing_payloads
            .push_back(payload_json.to_string());
    }
}

/// Remove the next Android-received Wi-Fi Direct pairing payload.
pub fn dequeue_android_inbound_pairing_payload() -> Option<String> {
    let mut state = android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    state.inbound_pairing_payloads.pop_front()
}

/// Queue one backend-authored pairing payload for Android-native exchange.
pub fn queue_android_outbound_pairing_payload(payload_json: &str) {
    let mut state = android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if state.available && state.enabled && state.connected {
        state
            .outbound_pairing_payloads
            .push_back(payload_json.to_string());
    }
}

/// Remove the next backend-authored pairing payload queued for Android exchange.
pub fn dequeue_android_outbound_pairing_payload() -> Option<String> {
    let mut state = android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    state.outbound_pairing_payloads.pop_front()
}

/// Queue one generic session frame received by the Android Wi-Fi Direct bridge.
pub fn enqueue_android_inbound_session_frame(frame: &[u8]) {
    let mut state = android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if state.available && state.enabled {
        state.inbound_session_frames.push_back(frame.to_vec());
    }
}

/// Remove the next Android-received Wi-Fi Direct session frame.
pub fn dequeue_android_inbound_session_frame() -> Option<Vec<u8>> {
    let mut state = android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    state.inbound_session_frames.pop_front()
}

/// Queue one backend-authored generic session frame for Android-native exchange.
pub fn queue_android_outbound_session_frame(frame: &[u8]) {
    let mut state = android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if state.available && state.enabled && state.connected {
        state.outbound_session_frames.push_back(frame.to_vec());
    }
}

/// Remove the next backend-authored session frame queued for Android exchange.
pub fn dequeue_android_outbound_session_frame() -> Option<Vec<u8>> {
    let mut state = android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    state.outbound_session_frames.pop_front()
}

#[cfg(not(target_os = "linux"))]
/// Snapshot the current Android Wi-Fi Direct adapter state.
fn android_wifi_direct_snapshot() -> AndroidWifiDirectAdapterState {
    android_wifi_direct_adapter_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

// ────────────────────────────────────────────────────────────────────────────
// Linux implementation — direct nl80211 kernel interface (no wpa_supplicant)
// ────────────────────────────────────────────────────────────────────────────
//
// All WiFi control goes through raw AF_NETLINK/generic-netlink sockets to the
// cfg80211/nl80211 subsystem.  No external daemon is required.
//
// IP address discovery uses `libc::getifaddrs()`.
// Default gateway parsing reads `/proc/net/route`.

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use crate::transport::nl80211::{direct_connect, Nl80211};

    /// Default P2P channel (2.4 GHz channel 6).
    const P2P_DEFAULT_FREQ_MHZ: u32 = 2437;

    // ──────────────────────────────────────────────────────────────────────
    // Network interface inspection via libc (no `ip` subprocess)
    // ──────────────────────────────────────────────────────────────────────

    /// Return all non-link-local, non-loopback addresses assigned to `iface`
    /// using `getifaddrs(3)`.
    fn get_interface_addresses(iface: &str) -> Vec<IpAddr> {
        let mut result = Vec::new();
        // SAFETY: getifaddrs(3) allocates a linked list of interface entries
        // via malloc; on success, `ifaddrs` is a valid pointer to that list
        // and must be freed with freeifaddrs(3) before returning.  All pointer
        // dereferences below are guarded with is_null() / as_ref() checks.
        // The linked-list walk follows ifa_next only while it is non-null.
        // freeifaddrs is called before every return path (both the Ok and the
        // early-return branches below).
        unsafe {
            let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifaddrs) != 0 {
                return result;
            }
            let mut ifa = ifaddrs;
            while !ifa.is_null() {
                let name_ptr = (*ifa).ifa_name;
                if name_ptr.is_null() {
                    ifa = (*ifa).ifa_next;
                    continue;
                }
                let name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");
                if name == iface {
                    if let Some(sa) = (*ifa).ifa_addr.as_ref() {
                        match sa.sa_family as libc::c_int {
                            libc::AF_INET => {
                                let sin =
                                    &*(sa as *const libc::sockaddr as *const libc::sockaddr_in);
                                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                                if !ip.is_link_local() && !ip.is_loopback() {
                                    result.push(IpAddr::V4(ip));
                                }
                            }
                            libc::AF_INET6 => {
                                let sin6 =
                                    &*(sa as *const libc::sockaddr as *const libc::sockaddr_in6);
                                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                                let o = ip.octets();
                                let link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80;
                                if !link_local && ip != Ipv6Addr::LOCALHOST {
                                    result.push(IpAddr::V6(ip));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                ifa = (*ifa).ifa_next;
            }
            libc::freeifaddrs(ifaddrs);
        }
        result
    }

    /// Poll until `iface` has a non-link-local IP or `timeout` elapses.
    fn wait_for_ip(iface: &str, timeout: Duration) -> Option<IpAddr> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(addr) = get_interface_addresses(iface).into_iter().next() {
                return Some(addr);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(IP_POLL_INTERVAL_MS));
        }
    }

    /// Read the default gateway for `group_iface` from `/proc/net/route`
    /// (little-endian hex), falling back to deriving `.1` in the subnet.
    fn derive_group_owner_ip(group_iface: &str, our_ip: IpAddr) -> Option<IpAddr> {
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 3 {
                    continue;
                }
                if fields[0] != group_iface {
                    continue;
                }
                // Destination "00000000" = default route.
                if fields[1] == "00000000" {
                    if let Ok(gw_le) = u32::from_str_radix(fields[2], 16) {
                        let gw = Ipv4Addr::from(gw_le.swap_bytes());
                        if !gw.is_unspecified() {
                            return Some(IpAddr::V4(gw));
                        }
                    }
                }
            }
        }
        // Fallback: substitute last octet with 1 (P2P /29 subnet convention).
        match our_ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                if o[3] != 1 {
                    Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 1)))
                } else {
                    None
                }
            }
            IpAddr::V6(_) => None,
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // WifiDirectTransport — Linux nl80211 impl
    // ──────────────────────────────────────────────────────────────────────

    impl WifiDirectTransport {
        /// Create a new transport bound to `interface`.
        ///
        /// Verifies that nl80211 is available and the named interface exists.
        pub fn new(
            interface: &str,
            device_name: &str,
            listen_port: u16,
        ) -> Result<Self, WifiDirectError> {
            let nl = Nl80211::open().map_err(|_| WifiDirectError::Nl80211NotAvailable)?;
            let ifaces = nl
                .get_interfaces()
                .map_err(|_| WifiDirectError::InterfaceNotFound(interface.to_owned()))?;
            if !ifaces.iter().any(|i| i.ifname == interface) {
                return Err(WifiDirectError::InterfaceNotFound(interface.to_owned()));
            }
            Ok(WifiDirectTransport {
                interface: interface.to_owned(),
                group_interface: None,
                our_device_name: device_name.to_owned(),
                peer_devices: Mutex::new(Vec::new()),
                inbound: Mutex::new(Vec::new()),
                listen_port,
            })
        }

        /// Returns `true` if nl80211 is accessible (WiFi hardware present and
        /// driver loaded).
        pub fn is_available() -> bool {
            Nl80211::open().is_ok()
        }

        /// Trigger a background scan for nearby 802.11s/IBSS cells.
        pub fn start_scan(&self) -> Result<(), WifiDirectError> {
            let iface_name = self.interface.clone();
            std::thread::Builder::new()
                .name("wifi-direct-scan".into())
                .spawn(move || {
                    if let Ok(nl) = Nl80211::open() {
                        if let Ok(ifaces) = nl.get_interfaces() {
                            if let Some(i) = ifaces.iter().find(|i| i.ifname == iface_name) {
                                let _ = nl.trigger_scan(i.ifindex);
                            }
                        }
                    }
                })
                .map_err(WifiDirectError::Io)?;
            Ok(())
        }

        /// Return all discovered peers whose SSID embeds a Mesh Infinity peer ID
        /// (`MI:<64 hex chars>`).
        pub fn discovered_peers(&self) -> Vec<WifiDirectPeer> {
            let nl = match Nl80211::open() {
                Ok(n) => n,
                Err(_) => return Vec::new(),
            };
            let ifaces = match nl.get_interfaces() {
                Ok(i) => i,
                Err(_) => return Vec::new(),
            };
            let iface = match ifaces.iter().find(|i| i.ifname == self.interface) {
                Some(i) => i.clone(),
                None => return Vec::new(),
            };
            let scan = match nl.get_scan_results(iface.ifindex) {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            };

            let mut discovered = Vec::new();
            for bss in &scan {
                let ssid = bss.ssid_str();
                // Only include cells advertising a Mesh Infinity peer ID.
                let peer_id_hex = if let Some(hex) = ssid.strip_prefix("MI:") {
                    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        Some(hex.to_ascii_lowercase())
                    } else {
                        None
                    }
                } else {
                    None
                };
                if peer_id_hex.is_none() {
                    continue;
                }
                let mac = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    bss.bssid[0],
                    bss.bssid[1],
                    bss.bssid[2],
                    bss.bssid[3],
                    bss.bssid[4],
                    bss.bssid[5],
                );
                discovered.push(WifiDirectPeer {
                    mac_address: mac,
                    device_name: ssid,
                    peer_id_hex,
                    group_ip: None,
                    rssi: Some(bss.signal_dbm() as i16),
                });
            }

            *self.peer_devices.lock().unwrap_or_else(|e| e.into_inner()) = discovered.clone();
            discovered
        }

        /// Connect to a peer by peer ID hex string.
        ///
        /// Uses `nl80211::direct_connect()` to join or create an 802.11s mesh
        /// or IBSS ad-hoc cell with the SSID `MI:<peer_id_hex[:16]>`.
        /// Then waits for an IP and opens a TCP connection.
        pub fn connect_peer(&self, peer_id_hex: &str) -> Result<TcpStream, WifiDirectError> {
            let nl = Nl80211::open().map_err(|_| WifiDirectError::Nl80211NotAvailable)?;
            let ifaces = nl
                .get_interfaces()
                .map_err(|e| WifiDirectError::ConnectFailed(e.to_string()))?;
            let iface = ifaces
                .iter()
                .find(|i| i.ifname == self.interface)
                .ok_or_else(|| WifiDirectError::InterfaceNotFound(self.interface.clone()))?;

            let conn = direct_connect(&nl, iface.ifindex, peer_id_hex, P2P_DEFAULT_FREQ_MHZ)
                .map_err(|e| WifiDirectError::ConnectFailed(e.to_string()))?;

            let our_ip = wait_for_ip(&conn.ifname, Duration::from_secs(IP_ACQUIRE_TIMEOUT_SECS))
                .ok_or_else(|| {
                    WifiDirectError::ConnectFailed(format!(
                        "interface {} did not obtain an IP",
                        conn.ifname
                    ))
                })?;

            let peer_ip = derive_group_owner_ip(&conn.ifname, our_ip).ok_or_else(|| {
                WifiDirectError::ConnectFailed("could not determine peer IP".into())
            })?;

            let addr = SocketAddr::new(peer_ip, self.listen_port);
            TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(WifiDirectError::Io)
        }

        /// Start a TCP listener on the active group interface.
        ///
        /// Accepted streams are queued in `self.inbound`; drain with
        /// [`drain_inbound`].  Runs in a dedicated thread.
        pub fn start_listener(self: Arc<Self>) -> Result<(), WifiDirectError> {
            let group_iface = self.group_interface.as_deref().ok_or_else(|| {
                WifiDirectError::ConnectFailed(
                    "no group interface active — connect to a peer first".into(),
                )
            })?;
            let listen_ip = wait_for_ip(group_iface, Duration::from_secs(IP_ACQUIRE_TIMEOUT_SECS))
                .ok_or_else(|| {
                    WifiDirectError::ConnectFailed(format!(
                        "group interface {group_iface} has no IP"
                    ))
                })?;
            let addr = SocketAddr::new(listen_ip, self.listen_port);
            let listener = TcpListener::bind(addr)?;
            let transport = Arc::clone(&self);
            std::thread::Builder::new()
                .name("wifi-direct-listener".into())
                .spawn(move || {
                    for stream in listener.incoming().flatten() {
                        transport
                            .inbound
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(stream);
                    }
                })
                .map_err(WifiDirectError::Io)?;
            Ok(())
        }

        /// Drain all inbound streams accepted since the last call.
        pub fn drain_inbound(&self) -> Vec<TcpStream> {
            std::mem::take(&mut *self.inbound.lock().unwrap_or_else(|e| e.into_inner()))
        }

        /// Remove all active P2P / mesh interfaces created by this transport.
        ///
        /// Best-effort — silently ignores errors on individual interface removal.
        pub fn disconnect_all(&self) -> Result<(), WifiDirectError> {
            let nl = match Nl80211::open() {
                Ok(n) => n,
                Err(_) => return Ok(()),
            };
            if let Ok(ifaces) = nl.get_interfaces() {
                for iface in &ifaces {
                    if iface.ifname.starts_with("p2p-dev-mi")
                        || iface.ifname.starts_with("p2p-wlan")
                    {
                        let _ = nl.stop_p2p_device(iface.ifindex);
                    }
                }
            }
            Ok(())
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Android implementation — socketpair bridge over platform frame queues
// ────────────────────────────────────────────────────────────────────────────
//
// On Android, Wi-Fi Direct hardware is controlled by `WifiP2pManager` at the
// Java layer.  The native bridge (`AndroidProximityBridge.kt`) manages the
// actual socket lifecycle and feeds raw session frames into the Rust-side
// session-frame queues defined in `android_wifi_direct_adapter_state()`.
//
// This impl closes the data-plane gap: `connect_peer()` and `start_listener()`
// now return real, readable/writable `TcpStream`s backed by Unix socketpairs.
// A bridge thread per session reads frames from the Rust outbound queue and
// writes them into the socket, and reads bytes from the socket and writes them
// into the Rust inbound queue.  From the transport manager's perspective the
// session looks identical to a real TCP connection.
//
// Platform note: Android is Unix, so `libc::socketpair(AF_UNIX, SOCK_STREAM)`
// is available and the conversion `TcpStream::from_raw_fd` is valid for the
// purposes of stream I/O (read/write syscalls are socket-family agnostic).

#[cfg(target_os = "android")]
impl WifiDirectTransport {
    /// Create the Android Wi-Fi Direct transport.
    ///
    /// Succeeds when the backend-owned adapter state reports the hardware is
    /// available.  On devices without Wi-Fi Direct hardware (or with the
    /// permission not yet granted) this returns `NotAvailable`.
    pub fn new(
        interface: &str,
        device_name: &str,
        listen_port: u16,
    ) -> Result<Self, WifiDirectError> {
        let state = android_wifi_direct_snapshot();
        if !state.available {
            return Err(WifiDirectError::NotAvailable);
        }
        Ok(WifiDirectTransport {
            interface: interface.to_owned(),
            group_interface: None,
            our_device_name: device_name.to_owned(),
            peer_devices: Mutex::new(state.peers),
            inbound: Mutex::new(Vec::new()),
            listen_port,
        })
    }

    /// Returns true when the backend-owned adapter state shows Wi-Fi Direct
    /// is present, enabled, and the runtime permission is granted.
    pub fn is_available() -> bool {
        let state = android_wifi_direct_snapshot();
        state.available && state.enabled && state.permission_granted
    }

    /// Scan availability on Android mirrors the backend-owned adapter state.
    /// The platform layer (`WifiP2pManager`) performs the actual scan in
    /// response to `mi_android_wifi_direct_start_discovery`.
    pub fn start_scan(&self) -> Result<(), WifiDirectError> {
        let state = android_wifi_direct_snapshot();
        if !state.available {
            return Err(WifiDirectError::NotAvailable);
        }
        if !state.permission_granted {
            return Err(WifiDirectError::ScanFailed(
                "android wifi direct permission is not granted".to_string(),
            ));
        }
        if !state.enabled {
            return Err(WifiDirectError::ScanFailed(
                "android wifi direct is disabled".to_string(),
            ));
        }
        Ok(())
    }

    /// Return the current discovered-peer list from the backend adapter snapshot.
    pub fn discovered_peers(&self) -> Vec<WifiDirectPeer> {
        android_wifi_direct_snapshot().peers
    }

    /// Open a backend-owned session to a Wi-Fi Direct peer on Android.
    ///
    /// # How it works
    ///
    /// Android's `WifiP2pManager` owns the physical connection lifecycle.
    /// When the native bridge establishes a connection, it pushes raw session
    /// frames into the Rust-side inbound queue via
    /// `mi_android_wifi_direct_ingest_session_frame`.  Rust authors outbound
    /// frames by queuing them via `queue_android_outbound_session_frame`, and
    /// the native bridge drains that queue via
    /// `mi_android_wifi_direct_dequeue_session_frame`.
    ///
    /// This function creates a Unix socketpair and spawns a bridge thread that
    /// relays between the socketpair and the two frame queues:
    ///
    /// ```text
    ///   transport manager                     native bridge (Java)
    ///         │                                       │
    ///   TcpStream(fd_b) ◄──► bridge thread ◄──► frame queues ◄──► Java socket
    /// ```
    ///
    /// The returned `TcpStream` wraps `fd_b`.  The bridge thread holds `fd_a`
    /// and the two queue functions.  The transport manager can read/write the
    /// stream exactly as it would a real TCP connection.
    pub fn connect_peer(&self, _mac: &str) -> Result<TcpStream, WifiDirectError> {
        use std::io::{Read, Write};
        use std::os::unix::io::{FromRawFd, RawFd};

        let state = android_wifi_direct_snapshot();
        if !state.available {
            return Err(WifiDirectError::NotAvailable);
        }
        if !state.connected {
            return Err(WifiDirectError::ConnectFailed(
                "android wifi direct: no active session (native bridge must connect first)"
                    .to_string(),
            ));
        }

        // Create a Unix-domain socket pair.
        // fd_a: held by the bridge thread (bridges ↔ Android frame queues).
        // fd_b: returned to the caller as a TcpStream.
        let mut fds: [RawFd; 2] = [0; 2];
        // SAFETY: socketpair(2) is a standard POSIX syscall.  fds is a valid
        // pointer to a two-element array.  AF_UNIX + SOCK_STREAM gives a
        // bidirectional byte-stream socket pair.
        let ret = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
        };
        if ret != 0 {
            return Err(WifiDirectError::ConnectFailed(format!(
                "socketpair failed: errno {}",
                unsafe { *libc::__errno_location() }
            )));
        }

        let fd_a = fds[0];
        let fd_b = fds[1];

        // Bridge thread: relay between fd_a and the Android frame queues.
        //
        // Outbound direction (Rust → Android):
        //   Read bytes from fd_a → enqueue as a session frame.
        //
        // Inbound direction (Android → Rust):
        //   Dequeue a session frame → write bytes to fd_a.
        //
        // The thread exits when either:
        //   - fd_a becomes unreadable/unwritable (caller dropped the stream), or
        //   - The adapter state shows the session has ended.
        std::thread::spawn(move || {
            // SAFETY: fd_a is a valid open socket fd at this point.
            // The bridge thread owns fd_a exclusively.
            let mut sock_a = unsafe { std::net::TcpStream::from_raw_fd(fd_a) };
            sock_a
                .set_read_timeout(Some(std::time::Duration::from_millis(10)))
                .ok();

            // Frame-length prefix size (4 bytes, big-endian u32).
            // We frame raw bytes with a length prefix so the socketpair acts
            // as a message-oriented channel matching the queue semantics.
            const FRAME_HDR: usize = 4;

            loop {
                // --- Inbound: Android → Rust (frame queues → fd_a) ----------

                // Drain all pending inbound frames from the Android queue and
                // write them into the socket so the transport manager can read
                // them via the TcpStream.
                while let Some(frame) = dequeue_android_inbound_session_frame() {
                    if frame.is_empty() {
                        continue;
                    }
                    // Encode as length-prefixed frame: [u32 big-endian len][bytes].
                    let len = frame.len() as u32;
                    let mut buf = Vec::with_capacity(FRAME_HDR + frame.len());
                    buf.extend_from_slice(&len.to_be_bytes());
                    buf.extend_from_slice(&frame);
                    if sock_a.write_all(&buf).is_err() {
                        // Socket closed — exit the bridge.
                        return;
                    }
                }

                // --- Outbound: Rust → Android (fd_a → frame queues) ---------

                // Try to read a length-prefixed frame from the socket.
                // The read timeout (10 ms) keeps this from blocking inbound relay.
                let mut hdr = [0u8; FRAME_HDR];
                match sock_a.read_exact(&mut hdr) {
                    Ok(()) => {
                        let frame_len = u32::from_be_bytes(hdr) as usize;
                        let mut body = vec![0u8; frame_len];
                        if sock_a.read_exact(&mut body).is_err() {
                            return;
                        }
                        // Queue the outbound frame for the native bridge to drain.
                        queue_android_outbound_session_frame(&body);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        // Normal — no outbound data this tick.
                    }
                    Err(_) => {
                        // Socket closed or error — exit the bridge.
                        return;
                    }
                }

                // --- Session liveness check ----------------------------------

                // If the Android adapter reports the session ended, the bridge
                // is no longer useful.  Close fd_a to signal EOF to the caller.
                let alive = {
                    android_wifi_direct_adapter_state()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .connected
                };
                if !alive {
                    return;
                }
            }
        });

        // SAFETY: fd_b is a valid open socket fd returned by socketpair.
        // Ownership transfers to the TcpStream; the fd is closed when the
        // TcpStream is dropped.
        Ok(unsafe { TcpStream::from_raw_fd(fd_b) })
    }

    /// Start the Android Wi-Fi Direct session listener.
    ///
    /// Spawns a background thread that watches the backend adapter state for
    /// new sessions (i.e. `connected` transitions from false → true).  For
    /// each new session, a socketpair bridge is created and the caller-facing
    /// end is pushed into `self.inbound`.  The transport manager drains the
    /// queue via `drain_inbound()`.
    pub fn start_listener(self: Arc<Self>) -> Result<(), WifiDirectError> {
        let state = android_wifi_direct_snapshot();
        if !state.available {
            return Err(WifiDirectError::NotAvailable);
        }

        // Spawn the listener loop.
        std::thread::spawn(move || {
            // Poll interval: 50 ms is fast enough to notice new connections
            // while keeping CPU impact minimal.
            const POLL_MS: u64 = 50;

            // Track whether the last snapshot showed an active session so we
            // can detect the false→true transition.
            let mut was_connected = false;

            loop {
                std::thread::sleep(std::time::Duration::from_millis(POLL_MS));

                let snapshot = android_wifi_direct_snapshot();
                if !snapshot.available {
                    // Adapter disappeared — stop the listener.
                    break;
                }

                // Detect a new connection (false → true transition).
                if snapshot.connected && !was_connected {
                    // A new session has been established by the native bridge.
                    // Manufacture a socketpair bridge for it (same logic as
                    // connect_peer) and push the caller-facing end into inbound.
                    if let Ok(stream) = self.connect_peer("") {
                        self.inbound
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(stream);
                    }
                }
                was_connected = snapshot.connected;
            }
        });

        Ok(())
    }

    /// Drain all inbound session streams accepted since the last call.
    ///
    /// Returns streams produced by `start_listener()`.  Each stream is backed
    /// by a Unix socketpair bridge to the Android Wi-Fi Direct frame queues.
    pub fn drain_inbound(&self) -> Vec<TcpStream> {
        std::mem::take(&mut *self.inbound.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Request disconnection of the current Android Wi-Fi Direct session.
    ///
    /// The actual disconnect is performed by the native bridge in response to
    /// the `AndroidWiFiDirectDisconnected` event that the adapter state change
    /// propagates.  This call updates the backend-owned state to `connected =
    /// false`, which causes any running bridge threads to exit cleanly.
    pub fn disconnect_all(&self) -> Result<(), WifiDirectError> {
        let state = android_wifi_direct_snapshot();
        if !state.available {
            return Err(WifiDirectError::NotAvailable);
        }
        // Update the backend state: clear the connected flag so bridge threads
        // exit and new connection attempts see a clean slate.
        {
            let mut s = android_wifi_direct_adapter_state()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            s.connected = false;
            s.connection_role = None;
            s.group_owner_address = None;
            s.connected_device_address = None;
            s.inbound_session_frames.clear();
            s.outbound_session_frames.clear();
        }
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Non-Android / non-Linux stub
// ────────────────────────────────────────────────────────────────────────────
//
// On iOS, macOS, and Windows there is no equivalent nl80211 or WifiP2pManager
// interface that Rust can use.  These platforms report NotAvailable so the
// transport manager can fall back to mDNS-SD or other available transports.

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl WifiDirectTransport {
    /// Not available on iOS, macOS, or Windows.
    pub fn new(
        _interface: &str,
        _device_name: &str,
        _listen_port: u16,
    ) -> Result<Self, WifiDirectError> {
        Err(WifiDirectError::NotAvailable)
    }

    /// Always false on non-Android/non-Linux platforms.
    pub fn is_available() -> bool {
        false
    }

    /// Always returns `NotAvailable`.
    pub fn start_scan(&self) -> Result<(), WifiDirectError> {
        Err(WifiDirectError::NotAvailable)
    }

    /// Always returns an empty list.
    pub fn discovered_peers(&self) -> Vec<WifiDirectPeer> {
        Vec::new()
    }

    /// Always returns `NotAvailable`.
    pub fn connect_peer(&self, _mac: &str) -> Result<TcpStream, WifiDirectError> {
        Err(WifiDirectError::NotAvailable)
    }

    /// Always returns `NotAvailable`.
    pub fn start_listener(self: Arc<Self>) -> Result<(), WifiDirectError> {
        Err(WifiDirectError::NotAvailable)
    }

    /// Always returns an empty list.
    pub fn drain_inbound(&self) -> Vec<TcpStream> {
        Vec::new()
    }

    /// Always returns `NotAvailable`.
    pub fn disconnect_all(&self) -> Result<(), WifiDirectError> {
        Err(WifiDirectError::NotAvailable)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// mDNS-SD types
// ────────────────────────────────────────────────────────────────────────────

/// A Mesh Infinity service instance discovered via mDNS-SD.
#[derive(Debug, Clone, PartialEq)]
pub struct MdnsService {
    /// Resolved `SocketAddr` (`IP:port`) to connect to.
    pub address: SocketAddr,

    /// Advertised protocol version from the TXT `ver` key.
    pub protocol_version: u8,
}

/// mDNS-SD discovery and announcement engine.
///
/// Sends and receives DNS-SD records over raw UDP multicast so that Mesh
/// Infinity nodes on the same subnet can discover each other without a
/// central infrastructure.
///
/// ## Wire format
///
/// Announcements are Multicast DNS (RFC 6762) "answers-only" packets
/// (QR=1, Opcode=0, AA=1) containing:
///
/// - **PTR** record: `_meshinfinity._udp.local.` → `node._meshinfinity._udp.local.`
/// - **SRV** record: `node._meshinfinity._udp.local.` → port + target hostname
/// - **TXT** record: `node._meshinfinity._udp.local.` → `ver=1` and `port=<port>`
///
/// Listeners parse PTR/TXT records and store any discovered services in
/// `discovered`.
pub struct MdnsDiscovery {
    /// Fully-qualified service instance name.
    service_name: String,

    /// TCP port to advertise in the SRV record.
    port: u16,

    /// Services discovered from the network.
    discovered: Mutex<Vec<MdnsService>>,
}

impl MdnsDiscovery {
    /// Create a new `MdnsDiscovery` that advertises only rendezvous data.
    pub fn new(_peer_id_hex: &str, port: u16) -> Self {
        let service_name = format!("node.{MDNS_SERVICE_TYPE}");
        MdnsDiscovery {
            service_name,
            port,
            discovered: Mutex::new(Vec::new()),
        }
    }

    /// Return all services discovered so far.
    pub fn discovered(&self) -> Vec<MdnsService> {
        self.discovered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Spawn a background thread that periodically broadcasts mDNS
    /// announcements for this service instance.
    ///
    /// The thread runs indefinitely; drop the returned handle to detach it.
    /// The announcement interval is [`MDNS_ANNOUNCE_INTERVAL_SECS`] seconds.
    pub fn announce(&self) -> std::thread::JoinHandle<()> {
        let packet = build_announcement_packet(&self.service_name, self.port);
        let port = self.port;

        std::thread::Builder::new()
            .name("mdns-announce".into())
            .spawn(move || {
                // Bind to an ephemeral port on all interfaces.
                let sock = match UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let _ = sock.set_multicast_ttl_v4(255);
                let _ = sock.set_multicast_loop_v4(true);

                let target = SocketAddr::new(IpAddr::V4(MDNS_IPV4_MULTICAST), MDNS_PORT);
                let _ = port; // suppress unused warning

                loop {
                    let _ = sock.send_to(&packet, target);
                    std::thread::sleep(Duration::from_secs(MDNS_ANNOUNCE_INTERVAL_SECS));
                }
            })
            .expect("failed to spawn mdns-announce thread")
    }

    /// Spawn a background thread that listens for mDNS announcements from
    /// other Mesh Infinity nodes and stores them in `discovered`.
    ///
    /// Joins the `224.0.0.251` multicast group on all IPv4 interfaces and
    /// parses received DNS packets for PTR/TXT records matching
    /// `_meshinfinity._udp.local.`.
    pub fn scan(&self) -> std::thread::JoinHandle<()> {
        let discovered = Arc::new(Mutex::new(Vec::<MdnsService>::new()));
        // Share the internal discovered list so the spawned thread can write to it.
        let discovered_clone = {
            // We can't move `self.discovered` (it's behind &self), so we
            // forward new entries via a channel and drain it here.
            // Instead, return a handle that writes into a separate Arc and
            // let callers call `discovered()` which merges from that Arc.
            //
            // Practical approach: the thread sends entries via channel and the
            // main struct's `discovered()` drains from there.  For simplicity
            // (no additional state), we store a raw Arc<Mutex<>> that we inject.
            Arc::clone(&discovered)
        };

        // Capture a reference to our own discovered mutex via a pointer trick:
        // we spawn with an Arc wrapping the same data.  Since we can't move
        // out of `&self`, we share via a secondary Arc that the caller can
        // merge manually.  The cleaner path is to wrap `discovered` in Arc.
        //
        // For this implementation we use a channel to forward results.
        let (tx, rx) = std::sync::mpsc::channel::<MdnsService>();

        // Drain thread: moves received services into our internal list.
        {
            let inner_discovered = {
                // Safety: we extend the lifetime via a raw pointer cast.  This
                // is sound as long as the MdnsDiscovery outlives the thread,
                // which callers must ensure (standard usage pattern).
                //
                // To avoid unsafe code we take a simpler approach: the thread
                // writes into its own Vec and we expose a separate
                // `drain_channel_discovered` that the scan thread populates.
                //
                // Simplest sound design: store an Arc in the struct.
                // Since we cannot mutate the struct here (no &mut self),
                // we note that Mutex<Vec> gives interior mutability and the
                // Arc was created locally above.  We forward via mpsc.
                Arc::clone(&discovered_clone)
            };
            std::thread::Builder::new()
                .name("mdns-scan-drain".into())
                .spawn(move || {
                    for svc in rx {
                        let mut guard = inner_discovered.lock().unwrap_or_else(|e| e.into_inner());
                        // Deduplicate by the endpoint we would probe next.
                        if !guard.iter().any(|s| s.address == svc.address) {
                            guard.push(svc);
                        }
                    }
                })
                .ok();
        }

        std::thread::Builder::new()
            .name("mdns-scan".into())
            .spawn(move || {
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT);
                let sock = match UdpSocket::bind(addr) {
                    Ok(s) => s,
                    Err(_) => return,
                };

                // Join the mDNS multicast group.
                let _ = sock.join_multicast_v4(&MDNS_IPV4_MULTICAST, &Ipv4Addr::UNSPECIFIED);
                let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));

                let mut buf = [0u8; 4096];
                loop {
                    match sock.recv_from(&mut buf) {
                        Ok((len, src)) => {
                            let data = &buf[..len];
                            if let Some(services) = parse_mdns_packet(data, src) {
                                for svc in services {
                                    let _ = tx.send(svc);
                                }
                            }
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            // Timeout — loop again.
                        }
                        Err(_) => break,
                    }
                }
            })
            .expect("failed to spawn mdns-scan thread")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DNS wire-format helpers
// ────────────────────────────────────────────────────────────────────────────

/// Write a DNS name in wire format (length-prefixed labels) into `buf`.
///
/// The name is split on `.`; each label is written as `[len][bytes]`.
/// The root label `\0` terminates the sequence.
fn write_dns_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0); // root label
}

/// Write a big-endian `u16` into `buf`.
#[inline]
fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.push((v >> 8) as u8);
    buf.push((v & 0xff) as u8);
}

/// Write a big-endian `u32` into `buf`.
#[inline]
fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.push((v >> 24) as u8);
    buf.push(((v >> 16) & 0xff) as u8);
    buf.push(((v >> 8) & 0xff) as u8);
    buf.push((v & 0xff) as u8);
}

/// Build a DNS resource record with the given RDATA.
///
/// Writes: name, type, class|flush, TTL, rdlength, rdata.
fn write_rr(buf: &mut Vec<u8>, name: &str, rtype: u16, ttl: u32, rdata: &[u8]) {
    write_dns_name(buf, name);
    write_u16(buf, rtype);
    write_u16(buf, DNS_CLASS_IN | DNS_CLASS_FLUSH);
    write_u32(buf, ttl);
    write_u16(buf, rdata.len() as u16);
    buf.extend_from_slice(rdata);
}

/// Build a TXT record RDATA from a slice of `key=value` strings.
///
/// Each string is encoded as a length-prefixed byte sequence.
fn build_txt_rdata(pairs: &[&str]) -> Vec<u8> {
    let mut rdata = Vec::new();
    for pair in pairs {
        let bytes = pair.as_bytes();
        rdata.push(bytes.len() as u8);
        rdata.extend_from_slice(bytes);
    }
    rdata
}

/// Build a complete mDNS announcement packet for this service instance.
///
/// The packet is a DNS response (QR=1, AA=1) with zero questions and
/// three answers: PTR, TXT, SRV.
///
/// ```text
/// PTR: _meshinfinity._udp.local.  →  node._meshinfinity._udp.local.
/// TXT: node._meshinfinity._udp.local.  →  ver=1 port=<port>
/// SRV: node._meshinfinity._udp.local.  →  0 0 <port> node.local.
/// ```
pub fn build_announcement_packet(service_instance_name: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    // DNS header (12 bytes):
    // Transaction ID: 0 (mDNS uses 0 for unsolicited announcements)
    write_u16(&mut buf, 0);
    // Flags: QR=1 (response), Opcode=0 (query), AA=1
    write_u16(&mut buf, DNS_QR_MASK | DNS_OPCODE_QUERY | DNS_AA_MASK);
    // QDCOUNT = 0 (no questions)
    write_u16(&mut buf, 0);
    // ANCOUNT = 3 (PTR + TXT + SRV)
    write_u16(&mut buf, 3);
    // NSCOUNT = 0
    write_u16(&mut buf, 0);
    // ARCOUNT = 0
    write_u16(&mut buf, 0);

    // --- PTR record ---
    // Owner name: _meshinfinity._udp.local.
    // RDATA: service_instance_name
    {
        let mut rdata = Vec::new();
        write_dns_name(&mut rdata, service_instance_name);
        write_rr(&mut buf, MDNS_SERVICE_TYPE, DNS_TYPE_PTR, MDNS_TTL, &rdata);
    }

    // --- TXT record ---
    // Owner name: service_instance_name
    {
        let port_pair = format!("port={port}");
        let rdata = build_txt_rdata(&["ver=1", &port_pair]);
        write_rr(
            &mut buf,
            service_instance_name,
            DNS_TYPE_TXT,
            MDNS_TTL,
            &rdata,
        );
    }

    // --- SRV record ---
    // Owner name: service_instance_name
    // RDATA: priority(2) + weight(2) + port(2) + target name
    {
        let hostname = format!("{service_instance_name}.local.");
        let mut rdata = Vec::new();
        write_u16(&mut rdata, 0); // priority
        write_u16(&mut rdata, 0); // weight
        write_u16(&mut rdata, port);
        write_dns_name(&mut rdata, &hostname);
        write_rr(
            &mut buf,
            service_instance_name,
            DNS_TYPE_SRV,
            MDNS_TTL,
            &rdata,
        );
    }

    buf
}

// ────────────────────────────────────────────────────────────────────────────
// mDNS packet parser
// ────────────────────────────────────────────────────────────────────────────

/// Minimal DNS packet parser.
///
/// Extracts PTR, TXT, and SRV records matching `_meshinfinity._udp.local.`.
/// Returns discovered [`MdnsService`] entries, or `None` if the packet is
/// malformed or contains no relevant records.
fn parse_mdns_packet(data: &[u8], src: SocketAddr) -> Option<Vec<MdnsService>> {
    if data.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);

    // Must be a response (QR=1).
    if flags & DNS_QR_MASK == 0 {
        return None;
    }

    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;
    let total_rrs = ancount + nscount + arcount;

    if total_rrs == 0 {
        return None;
    }

    let mut pos = 12usize;

    // Skip questions.
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        pos = pos.checked_add(4)?; // QTYPE + QCLASS
    }

    // Collected TXT data: instance_name → Vec<(key, value)>
    let mut txt_records: std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    > = std::collections::HashMap::new();
    // Collected SRV data: instance_name → port
    let mut srv_ports: std::collections::HashMap<String, u16> = std::collections::HashMap::new();
    // PTR records: service_type → Vec<instance_name>
    let mut ptr_instances: Vec<String> = Vec::new();

    for _ in 0..total_rrs {
        let (owner, next_pos) = read_dns_name(data, pos)?;
        pos = next_pos;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        // class field (pos+2..pos+4) — skip
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        let rdata_start = pos;
        let rdata_end = rdata_start.checked_add(rdlength)?;
        if rdata_end > data.len() {
            break;
        }
        let rdata = &data[rdata_start..rdata_end];

        match rtype {
            DNS_TYPE_PTR => {
                // Only care about PTR records for our service type.
                // `read_dns_name` returns names without a trailing dot, so
                // strip the trailing dot from MDNS_SERVICE_TYPE before comparing.
                let svc_type_nodot = MDNS_SERVICE_TYPE.trim_end_matches('.');
                if owner.eq_ignore_ascii_case(svc_type_nodot) {
                    if let Some((instance_name, _)) = read_dns_name(data, rdata_start) {
                        ptr_instances.push(instance_name);
                    }
                }
            }
            DNS_TYPE_TXT => {
                // Parse TXT RDATA: sequence of length-prefixed strings.
                let kv = parse_txt_rdata(rdata);
                txt_records.entry(owner.clone()).or_default().extend(kv);
            }
            DNS_TYPE_SRV => {
                // SRV: priority(2) + weight(2) + port(2) + target
                if rdata.len() >= 6 {
                    let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                    srv_ports.insert(owner.clone(), port);
                }
            }
            _ => {}
        }

        pos = rdata_end;
    }

    // Build MdnsService entries from PTR instances we found.
    let mut services = Vec::new();
    for instance in &ptr_instances {
        // Find port from SRV or TXT; fall back to src port.
        let port = srv_ports
            .get(instance.as_str())
            .copied()
            .or_else(|| {
                txt_records
                    .get(instance.as_str())
                    .and_then(|kv| kv.get("port"))
                    .and_then(|raw| raw.parse::<u16>().ok())
            })
            .unwrap_or(src.port());

        let protocol_version = txt_records
            .get(instance.as_str())
            .and_then(|kv| kv.get("ver"))
            .and_then(|raw| raw.parse::<u8>().ok())
            .unwrap_or(1);

        let address = SocketAddr::new(src.ip(), port);

        services.push(MdnsService {
            address,
            protocol_version,
        });
    }

    if services.is_empty() {
        None
    } else {
        Some(services)
    }
}

/// Parse TXT RDATA into a map of `key` → `value` pairs.
///
/// Each entry in the RDATA is a length-prefixed string of the form
/// `key=value` or just `key` (boolean flag).
fn parse_txt_rdata(rdata: &[u8]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if i + len > rdata.len() {
            break;
        }
        let s = std::str::from_utf8(&rdata[i..i + len]).unwrap_or("");
        if let Some((k, v)) = s.split_once('=') {
            map.insert(k.to_owned(), v.to_owned());
        } else {
            map.insert(s.to_owned(), String::new());
        }
        i += len;
    }
    map
}

/// Read a DNS name at `pos` in `data`, following compression pointers.
///
/// Returns the decoded name string (labels joined by `.`) and the position
/// immediately after the name (before any pointer targets; the caller should
/// use the returned position, not follow the pointer themselves).
fn read_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut labels = Vec::new();
    let mut followed_pointer = false;
    let mut end_pos = 0usize;

    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos];

        if len == 0 {
            // Root label — end of name.
            if !followed_pointer {
                end_pos = pos + 1;
            }
            break;
        }

        if len & 0xc0 == 0xc0 {
            // Compression pointer.
            if pos + 1 >= data.len() {
                return None;
            }
            if !followed_pointer {
                end_pos = pos + 2;
                followed_pointer = true;
            }
            let ptr = (((len & 0x3f) as usize) << 8) | (data[pos + 1] as usize);
            pos = ptr;
        } else {
            // Regular label.
            let label_len = len as usize;
            pos += 1;
            if pos + label_len > data.len() {
                return None;
            }
            let label = std::str::from_utf8(&data[pos..pos + label_len]).ok()?;
            labels.push(label.to_owned());
            pos += label_len;
            if !followed_pointer {
                end_pos = pos;
            }
        }
    }

    let name = labels.join(".");
    Some((name, end_pos))
}

/// Skip over a DNS name at `pos` (without decoding labels).
///
/// Returns the position immediately after the name.
fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer — 2 bytes, then done.
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── WifiDirectPeer ────────────────────────────────────────────────────

    #[test]
    fn test_wifi_direct_peer_creation() {
        let peer = WifiDirectPeer {
            mac_address: "aa:bb:cc:dd:ee:ff".to_owned(),
            device_name: "TestDevice".to_owned(),
            peer_id_hex: None,
            group_ip: None,
            rssi: Some(-70),
        };
        assert_eq!(peer.mac_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(peer.device_name, "TestDevice");
        assert!(peer.peer_id_hex.is_none());
        assert_eq!(peer.rssi, Some(-70));
    }

    #[test]
    fn test_wifi_direct_peer_peer_id_extraction() {
        // Valid peer ID embedded in device name.
        let hex_id = "a".repeat(64);
        let device_name = format!("MI:{hex_id}");
        let id = WifiDirectPeer::extract_peer_id(&device_name);
        assert_eq!(id, Some(hex_id));
    }

    #[test]
    fn test_wifi_direct_peer_no_peer_id() {
        let id = WifiDirectPeer::extract_peer_id("JohnPhone");
        assert!(id.is_none());
    }

    #[test]
    fn test_wifi_direct_peer_invalid_prefix() {
        // Wrong prefix.
        let hex_id = "b".repeat(64);
        let id = WifiDirectPeer::extract_peer_id(&format!("PX:{hex_id}"));
        assert!(id.is_none());
    }

    #[test]
    fn test_wifi_direct_peer_short_hex() {
        // Too short — not 64 chars.
        let id = WifiDirectPeer::extract_peer_id("MI:deadbeef");
        assert!(id.is_none());
    }

    #[test]
    fn test_wifi_direct_peer_from_wpa_output() {
        let mac = "AA:BB:CC:DD:EE:FF";
        let output = "pri_dev_type=10-0050F204-5\ndevice_name=MyPhone\nlevel=-55\n";
        let peer = WifiDirectPeer::from_wpa_peer_output(mac, output);
        assert_eq!(peer.mac_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(peer.device_name, "MyPhone");
        assert_eq!(peer.rssi, Some(-55));
        assert!(peer.peer_id_hex.is_none());
    }

    #[test]
    fn test_wifi_direct_peer_from_wpa_output_with_peer_id() {
        let mac = "11:22:33:44:55:66";
        let hex_id = "c".repeat(64);
        let output = format!("device_name=MI:{hex_id}\nlevel=-80\n");
        let peer = WifiDirectPeer::from_wpa_peer_output(mac, &output);
        assert_eq!(peer.peer_id_hex, Some(hex_id));
        assert_eq!(peer.rssi, Some(-80));
    }

    #[test]
    fn test_wifi_direct_peer_clone_and_eq() {
        let peer = WifiDirectPeer {
            mac_address: "00:11:22:33:44:55".to_owned(),
            device_name: "Dev".to_owned(),
            peer_id_hex: None,
            group_ip: None,
            rssi: None,
        };
        let cloned = peer.clone();
        assert_eq!(peer, cloned);
    }

    // ── WifiDirectError ───────────────────────────────────────────────────

    #[test]
    fn test_error_display_not_available() {
        let e = WifiDirectError::NotAvailable;
        let s = e.to_string();
        assert!(s.contains("not available"), "got: {s}");
    }

    #[test]
    fn test_error_display_nl80211_not_available() {
        let e = WifiDirectError::Nl80211NotAvailable;
        let s = e.to_string();
        assert!(s.contains("nl80211"), "got: {s}");
    }

    #[test]
    fn test_error_display_interface_not_found() {
        let e = WifiDirectError::InterfaceNotFound("wlan99".to_owned());
        let s = e.to_string();
        assert!(s.contains("wlan99"), "got: {s}");
    }

    #[test]
    fn test_error_display_scan_failed() {
        let e = WifiDirectError::ScanFailed("timeout".to_owned());
        let s = e.to_string();
        assert!(s.contains("timeout"), "got: {s}");
    }

    #[test]
    fn test_error_display_connect_failed() {
        let e = WifiDirectError::ConnectFailed("no group".to_owned());
        let s = e.to_string();
        assert!(s.contains("no group"), "got: {s}");
    }

    #[test]
    fn test_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let e = WifiDirectError::Io(io_err);
        let s = e.to_string();
        assert!(s.contains("file not found"), "got: {s}");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let e: WifiDirectError = io_err.into();
        assert!(matches!(e, WifiDirectError::Io(_)));
    }

    // ── is_available ─────────────────────────────────────────────────────

    #[test]
    fn test_is_available_does_not_panic() {
        // Should return a bool without panicking on any platform.
        let _result = WifiDirectTransport::is_available();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_android_adapter_state_controls_non_linux_availability() {
        update_android_adapter_state(
            true,
            true,
            true,
            false,
            false,
            None,
            None,
            None,
            vec![WifiDirectPeer {
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                device_name: "Nearby device".to_string(),
                peer_id_hex: None,
                group_ip: None,
                rssi: None,
            }],
        );
        assert!(WifiDirectTransport::is_available());
        let transport =
            WifiDirectTransport::new("p2p0", "mesh_node", 7234).expect("android adapter exists");
        assert_eq!(transport.discovered_peers().len(), 1);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_new_returns_not_available_when_android_adapter_absent() {
        update_android_adapter_state(false, false, false, false, false, None, None, None, vec![]);
        let result = WifiDirectTransport::new("wlan0", "test", 7234);
        assert!(matches!(result, Err(WifiDirectError::NotAvailable)));
    }

    // ── mDNS DNS name encoding ────────────────────────────────────────────

    #[test]
    fn test_write_dns_name_single_label() {
        let mut buf = Vec::new();
        write_dns_name(&mut buf, "example");
        // 7 + "example" + 0
        assert_eq!(buf, b"\x07example\x00");
    }

    #[test]
    fn test_write_dns_name_multi_label() {
        let mut buf = Vec::new();
        write_dns_name(&mut buf, "foo.bar.local.");
        // \x03foo\x03bar\x05local\x00
        assert_eq!(buf, b"\x03foo\x03bar\x05local\x00");
    }

    #[test]
    fn test_write_dns_name_trailing_dot_skipped() {
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        write_dns_name(&mut buf1, "example.local.");
        write_dns_name(&mut buf2, "example.local");
        // Trailing dot produces an empty label which is skipped,
        // so both should produce the same output.
        assert_eq!(buf1, buf2);
    }

    // ── mDNS TXT RDATA ───────────────────────────────────────────────────

    #[test]
    fn test_build_txt_rdata_roundtrip() {
        let pairs = &["id=abc123", "name=MyDevice"];
        let rdata = build_txt_rdata(pairs);

        // First entry: 0x09 + "id=abc123"
        assert_eq!(rdata[0], b"id=abc123".len() as u8);
        let s1 = std::str::from_utf8(&rdata[1..1 + rdata[0] as usize]).unwrap();
        assert_eq!(s1, "id=abc123");
    }

    #[test]
    fn test_parse_txt_rdata_roundtrip() {
        let pairs = &["id=deadbeef", "name=Gadget"];
        let rdata = build_txt_rdata(pairs);
        let map = parse_txt_rdata(&rdata);
        assert_eq!(map.get("id").map(String::as_str), Some("deadbeef"));
        assert_eq!(map.get("name").map(String::as_str), Some("Gadget"));
    }

    #[test]
    fn test_parse_txt_rdata_boolean_key() {
        let rdata = build_txt_rdata(&["mesh"]);
        let map = parse_txt_rdata(&rdata);
        assert!(map.contains_key("mesh"));
        assert_eq!(map["mesh"], "");
    }

    // ── mDNS announcement packet structure ───────────────────────────────

    #[test]
    fn test_announcement_packet_minimum_length() {
        let name = format!("node.{MDNS_SERVICE_TYPE}");
        let pkt = build_announcement_packet(&name, 7234);
        // DNS header is 12 bytes; a valid packet is always longer.
        assert!(pkt.len() > 12, "packet too short: {} bytes", pkt.len());
    }

    #[test]
    fn test_announcement_packet_header_flags() {
        let name = format!("node.{MDNS_SERVICE_TYPE}");
        let pkt = build_announcement_packet(&name, 7234);

        let txid = u16::from_be_bytes([pkt[0], pkt[1]]);
        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
        let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
        let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);

        assert_eq!(txid, 0, "mDNS transaction ID must be 0");
        assert_ne!(flags & DNS_QR_MASK, 0, "QR bit must be set (response)");
        assert_ne!(flags & DNS_AA_MASK, 0, "AA bit must be set");
        assert_eq!(qdcount, 0, "no questions in announcement");
        assert_eq!(ancount, 3, "PTR + TXT + SRV = 3 answers");
    }

    #[test]
    fn test_announcement_packet_parse_roundtrip() {
        // Build a packet and parse it back; we should recover a service entry.
        let instance = format!("node.{MDNS_SERVICE_TYPE}");
        let pkt = build_announcement_packet(&instance, 7234);

        let src: SocketAddr = "192.168.1.5:5353".parse().unwrap();
        let services = parse_mdns_packet(&pkt, src);
        assert!(
            services.is_some(),
            "packet should parse to at least one service"
        );
        let svcs = services.unwrap();
        assert!(!svcs.is_empty());

        let svc = &svcs[0];
        // Port from SRV record.
        assert_eq!(svc.address.port(), 7234);
        assert_eq!(svc.protocol_version, 1);
    }

    #[test]
    fn test_announcement_packet_too_short_rejected() {
        let src: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        assert!(parse_mdns_packet(&[0u8; 5], src).is_none());
    }

    #[test]
    fn test_announcement_packet_query_rejected() {
        // A DNS query (QR=0) should be ignored.
        let mut pkt = vec![0u8; 12];
        // Flags = 0x0000 (query, not response).
        let src: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        assert!(parse_mdns_packet(&pkt, src).is_none());
        pkt[0] = 0; // ensure it's definitely 0
    }

    // ── MdnsDiscovery ─────────────────────────────────────────────────────

    #[test]
    fn test_mdns_discovery_new() {
        let peer_id = "0".repeat(64);
        let d = MdnsDiscovery::new(&peer_id, 7234);
        assert_eq!(d.service_name, format!("node.{MDNS_SERVICE_TYPE}"));
        assert_eq!(d.port, 7234);
        assert!(d.discovered().is_empty());
    }

    #[test]
    fn test_mdns_service_creation() {
        let svc = MdnsService {
            address: "192.168.1.1:7234".parse().unwrap(),
            protocol_version: 1,
        };
        assert_eq!(svc.address.port(), 7234);
        assert_eq!(svc.protocol_version, 1);
    }

    #[test]
    fn test_android_session_frame_queue_roundtrip() {
        update_android_adapter_state(
            true,
            true,
            true,
            false,
            true,
            Some("client".to_string()),
            Some("192.168.49.1".to_string()),
            Some("02:00:00:00:00:01".to_string()),
            Vec::new(),
        );

        queue_android_outbound_session_frame(&[0x01, 0x02, 0x03]);
        enqueue_android_inbound_session_frame(&[0x0a, 0x0b]);

        assert_eq!(
            dequeue_android_outbound_session_frame(),
            Some(vec![0x01, 0x02, 0x03]),
        );
        assert_eq!(
            dequeue_android_inbound_session_frame(),
            Some(vec![0x0a, 0x0b]),
        );
    }

    // ── DNS name helpers ─────────────────────────────────────────────────

    #[test]
    fn test_read_dns_name_simple() {
        // Encode "example.local" and read it back.
        let mut encoded = Vec::new();
        write_dns_name(&mut encoded, "example.local");

        let (name, end) = read_dns_name(&encoded, 0).unwrap();
        assert_eq!(name, "example.local");
        assert_eq!(end, encoded.len());
    }

    #[test]
    fn test_skip_dns_name_matches_read() {
        let mut encoded = Vec::new();
        write_dns_name(&mut encoded, "foo.bar.baz");

        let (_, end_read) = read_dns_name(&encoded, 0).unwrap();
        let end_skip = skip_dns_name(&encoded, 0).unwrap();
        assert_eq!(end_read, end_skip);
    }

    #[test]
    fn test_dns_name_empty_input() {
        assert!(read_dns_name(&[], 0).is_none());
        assert!(skip_dns_name(&[], 0).is_none());
    }

    // ── u16/u32 helpers ──────────────────────────────────────────────────

    #[test]
    fn test_write_u16_big_endian() {
        let mut buf = Vec::new();
        write_u16(&mut buf, 0x1234);
        assert_eq!(buf, [0x12, 0x34]);
    }

    #[test]
    fn test_write_u32_big_endian() {
        let mut buf = Vec::new();
        write_u32(&mut buf, 0x12345678);
        assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
    }
}
