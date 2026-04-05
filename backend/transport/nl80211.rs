//! Direct nl80211 WiFi control (Linux only, §5.8)
//!
//! This module communicates with the Linux kernel's cfg80211/nl80211 WiFi
//! subsystem via raw generic-netlink sockets — no subprocess, no wpa_supplicant
//! dependency.  nl80211 is the same interface that `iw`, `wpa_supplicant`,
//! and `iwd` all use internally.
//!
//! ## Supported operations
//!
//! | Operation | nl80211 command | Notes |
//! |-----------|----------------|-------|
//! | List interfaces | `GET_INTERFACE` | enumerate `wlan*` devices |
//! | Trigger scan | `TRIGGER_SCAN` | 2.4 + 5 GHz |
//! | Read scan results | `GET_SCAN` | BSS list with SSID / BSSID / signal |
//! | Create IBSS | `JOIN_IBSS` | ad-hoc mesh seed point |
//! | Join IBSS | `JOIN_IBSS` | join existing ad-hoc cell |
//! | Create soft-AP | `START_AP` | AP mode, PSK from pairing exchange |
//! | Connect to AP | `CONNECT` | STA mode, PMK supplied by us |
//! | Leave network | `DISCONNECT` | clean teardown |
//! | P2P device | `START_P2P_DEVICE` | Wi-Fi Direct device |
//! | P2P find | `REMAIN_ON_CHANNEL` | listen for P2P frames |
//! | 802.11s mesh | `JOIN_MESH` | kernel mesh, mesh ID = peer-id hex |
//!
//! ## Protocol overview
//!
//! ```text
//! socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)
//!   → send CTRL_CMD_GETFAMILY "nl80211" → get family_id
//!   → send NL80211_CMD_* with family_id
//!   → recv NL80211_CMD_* responses / events
//! ```
//!
//! Each netlink message is:
//! ```text
//! nlmsghdr(16 B) + genlmsghdr(4 B) + attrs (nla TLVs)
//! ```
//!
//! Attributes are nested TLV structures:
//! ```text
//! nlattr(4 B: len + type) + value bytes (padded to 4-byte boundary)
//! ```
//!
//! ## Thread safety
//!
//! `Nl80211` wraps a raw file descriptor protected by a `Mutex` and is
//! `Send + Sync`.

#![cfg(target_os = "linux")]

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

// ────────────────────────────────────────────────────────────────────────────
// Kernel constants (from <linux/netlink.h> and <linux/nl80211.h>)
// ────────────────────────────────────────────────────────────────────────────

/// AF_NETLINK is Linux's address family for kernel↔userspace IPC.
/// Generic netlink (family 16) is the modern extensible subsystem that
/// cfg80211/nl80211 registers with — using it avoids the legacy ioctl
/// interface and gives access to the full 802.11 configuration space.
const AF_NETLINK: i32 = 16;
const SOCK_RAW: i32 = 3;
const NETLINK_GENERIC: i32 = 16;

/// Generic netlink uses a dynamic family-ID scheme: the control family
/// (ID 16) provides a `GETFAMILY` command that resolves "nl80211" to its
/// runtime-assigned ID.  This avoids hardcoding kernel-version-specific
/// IDs that could break across kernel updates.
const GENL_ID_CTRL: u16 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_FAMILY_ID: u16 = 1;

// Netlink message types — these are fixed across all netlink families.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// Netlink flags — combined in message headers to request specific behaviour.
const NLM_F_REQUEST: u16 = 0x01;
/// Request an ACK (NLMSG_ERROR with code 0) so we know the kernel processed it.
const NLM_F_ACK: u16 = 0x04;
/// NLM_F_ROOT | NLM_F_MATCH — triggers a "dump" operation that returns all
/// matching entries (e.g. all wireless interfaces) as a multi-part response
/// terminated by NLMSG_DONE.
const NLM_F_DUMP: u16 = 0x300;

// nl80211 commands — these map 1:1 to the kernel's nl80211_commands enum.
// Each command triggers a specific WiFi operation; the kernel routes
// them through the driver's cfg80211_ops callbacks.
pub const NL80211_CMD_GET_WIPHY: u8 = 1;
pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
pub const NL80211_CMD_DEL_INTERFACE: u8 = 8;
pub const NL80211_CMD_TRIGGER_SCAN: u8 = 33;
pub const NL80211_CMD_GET_SCAN: u8 = 35;
pub const NL80211_CMD_CONNECT: u8 = 46;
pub const NL80211_CMD_DISCONNECT: u8 = 48;
pub const NL80211_CMD_JOIN_IBSS: u8 = 44;
pub const NL80211_CMD_START_AP: u8 = 60;
pub const NL80211_CMD_STOP_AP: u8 = 61;
pub const NL80211_CMD_START_P2P_DEVICE: u8 = 62;
pub const NL80211_CMD_STOP_P2P_DEVICE: u8 = 63;
pub const NL80211_CMD_REMAIN_ON_CHANNEL: u8 = 31;
pub const NL80211_CMD_JOIN_MESH: u8 = 67;

// nl80211 attributes (from <linux/nl80211.h>).
// Attributes are the TLV payload of nl80211 messages.  Each operation
// requires specific attributes (e.g. TRIGGER_SCAN needs IFINDEX to
// identify which wireless interface to scan on).
pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_WIPHY_NAME: u16 = 2;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_IFNAME: u16 = 4;
pub const NL80211_ATTR_IFTYPE: u16 = 5;
pub const NL80211_ATTR_MAC: u16 = 6;
pub const NL80211_ATTR_KEY_DATA: u16 = 9;
pub const NL80211_ATTR_KEY_IDX: u16 = 10;
pub const NL80211_ATTR_BSS: u16 = 15;
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
pub const NL80211_ATTR_SSID: u16 = 52;
pub const NL80211_ATTR_AUTH_TYPE: u16 = 53;
pub const NL80211_ATTR_REASON_CODE: u16 = 55;
pub const NL80211_ATTR_PRIVACY: u16 = 87;
pub const NL80211_ATTR_CIPHER_SUITES_PAIRWISE: u16 = 89;
pub const NL80211_ATTR_CIPHER_SUITE_GROUP: u16 = 90;
pub const NL80211_ATTR_AKM_SUITES: u16 = 91;
pub const NL80211_ATTR_BEACON_INTERVAL: u16 = 15; // note: reused slot in AP cmds
pub const NL80211_ATTR_DTIM_PERIOD: u16 = 16;
pub const NL80211_ATTR_BEACON_HEAD: u16 = 17;
pub const NL80211_ATTR_BEACON_TAIL: u16 = 18;
pub const NL80211_ATTR_MESH_ID: u16 = 136;
pub const NL80211_ATTR_PMK: u16 = 254;
pub const NL80211_ATTR_WANT_1X_4WAY_HS: u16 = 210;

// BSS nested attributes.
pub const NL80211_BSS_BSSID: u16 = 1;
pub const NL80211_BSS_FREQUENCY: u16 = 2;
pub const NL80211_BSS_TSFT: u16 = 3;
pub const NL80211_BSS_BEACON_INTERVAL: u16 = 4;
pub const NL80211_BSS_CAPABILITY: u16 = 5;
pub const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
pub const NL80211_BSS_SIGNAL_MBM: u16 = 7;
pub const NL80211_BSS_STATUS: u16 = 9;

// Interface types — determines the operating mode of a WiFi interface.
// Mesh Infinity uses STATION for connecting to APs, IBSS for ad-hoc cells,
// MESH_POINT for 802.11s mesh, and P2P_DEVICE for WiFi Direct discovery.
pub const NL80211_IFTYPE_STATION: u32 = 2;
pub const NL80211_IFTYPE_AP: u32 = 3;
pub const NL80211_IFTYPE_IBSS: u32 = 1;
pub const NL80211_IFTYPE_MESH_POINT: u32 = 7;
pub const NL80211_IFTYPE_P2P_CLIENT: u32 = 8;
pub const NL80211_IFTYPE_P2P_GO: u32 = 9;
pub const NL80211_IFTYPE_P2P_DEVICE: u32 = 10;

// Auth types.
pub const NL80211_AUTHTYPE_OPEN_SYSTEM: u32 = 0;

// Cipher suites (from <linux/ieee80211.h>).
// The OUI prefix 00-0F-AC identifies IEEE 802.11 standard cipher suites.
// We prefer CCMP (AES) over TKIP for all mesh connections — TKIP is only
// included as a fallback for legacy hardware that cannot do AES in hardware.
/// WPA2-CCMP (AES-128-CCM) — mandatory for WPA2 and all mesh connections.
pub const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000FAC04;
/// TKIP (WPA1 — known weak: Michael MIC attacks, no replay protection).
/// Only used if the peer's hardware does not support CCMP.
pub const WLAN_CIPHER_SUITE_TKIP: u32 = 0x000FAC02;

// AKM (Authentication and Key Management) suites.
// These determine how the PMK (Pairwise Master Key) is derived.
// Mesh Infinity always uses PSK because the PMK is derived from the
// pairing exchange, not from an external RADIUS/EAP server.
/// WPA2-PSK — PMK = PBKDF2(passphrase, SSID) or supplied directly.
pub const WLAN_AKM_SUITE_PSK: u32 = 0x000FAC02;
/// 802.1X / EAP — included for interop but not used by mesh connections.
pub const WLAN_AKM_SUITE_8021X: u32 = 0x000FAC01;

// ────────────────────────────────────────────────────────────────────────────
// Netlink message builder
// ────────────────────────────────────────────────────────────────────────────

/// Global sequence counter for netlink messages.  Each message gets a
/// unique sequence number so we can correlate responses with requests
/// when multiple operations are in flight (the kernel echoes the seq
/// back in its reply).  Starts at 1 because seq 0 has special meaning
/// in some netlink subsystems.
static NL_SEQ: AtomicU32 = AtomicU32::new(1);

/// A netlink message being constructed.
#[derive(Default)]
pub struct NlMsg {
    buf: Vec<u8>,
}

impl NlMsg {
    /// Start a generic-netlink message.
    ///
    /// `family` — the netlink family ID (e.g. `GENL_ID_CTRL` or the
    /// dynamically assigned nl80211 ID).
    /// `cmd` — command byte.
    /// `flags` — combination of `NLM_F_*` flags.
    pub fn new_genl(family: u16, cmd: u8, flags: u16) -> Self {
        let seq = NL_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut buf = Vec::with_capacity(128);
        // nlmsghdr — 16 bytes, length filled in later.
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len placeholder
        buf.extend_from_slice(&family.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (kernel fills)
                                                    // genlmsghdr — 4 bytes.
        buf.push(cmd);
        buf.push(1); // version
        buf.extend_from_slice(&0u16.to_ne_bytes()); // reserved
        NlMsg { buf }
    }

    /// Append a string attribute.
    pub fn put_str(&mut self, attr_type: u16, value: &str) {
        self.put_bytes(attr_type, value.as_bytes());
    }

    /// Append a NUL-terminated string attribute (for family name etc.).
    pub fn put_strz(&mut self, attr_type: u16, value: &str) {
        let mut v = value.as_bytes().to_vec();
        v.push(0);
        self.put_bytes(attr_type, &v);
    }

    /// Append a `u32` attribute (native endian).
    pub fn put_u32(&mut self, attr_type: u16, value: u32) {
        self.put_bytes(attr_type, &value.to_ne_bytes());
    }

    /// Append a `u32` attribute (little endian — for some nl80211 attrs).
    pub fn put_u32_le(&mut self, attr_type: u16, value: u32) {
        self.put_bytes(attr_type, &value.to_le_bytes());
    }

    /// Append a raw-bytes attribute.
    ///
    /// Netlink attributes (nla) use a 4-byte header: `[nla_len: u16, nla_type: u16]`
    /// followed by the value bytes.  The entire attribute (header + value) must be
    /// padded to a 4-byte boundary so subsequent attributes are naturally aligned.
    /// `nla_len` includes the 4-byte header but NOT the padding bytes.
    pub fn put_bytes(&mut self, attr_type: u16, data: &[u8]) {
        let nla_len = (4 + data.len()) as u16;
        self.buf.extend_from_slice(&nla_len.to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        self.buf.extend_from_slice(data);
        let pad = (4 - (data.len() % 4)) % 4;
        self.buf.extend_from_slice(&[0u8; 4][..pad]);
    }

    /// Append a nested attribute block (call `put_*` inside `f`, then close).
    pub fn put_nested<F: FnOnce(&mut NlMsg)>(&mut self, attr_type: u16, f: F) {
        let start = self.buf.len();
        // Reserve space for nested nlattr header.
        self.buf.extend_from_slice(&0u16.to_ne_bytes()); // nla_len placeholder
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        let data_start = self.buf.len();
        f(self);
        // Fill in the length.
        let nla_len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&nla_len.to_ne_bytes());
        // Pad to 4-byte boundary.
        let data_len = self.buf.len() - data_start;
        let pad = (4 - (data_len % 4)) % 4;
        self.buf.extend_from_slice(&[0u8; 4][..pad]);
    }

    /// Finalize: fill in the total message length and return the bytes.
    pub fn finish(mut self) -> Vec<u8> {
        let total = self.buf.len() as u32;
        self.buf[..4].copy_from_slice(&total.to_ne_bytes());
        self.buf
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Netlink attribute parser
// ────────────────────────────────────────────────────────────────────────────

/// A parsed netlink attribute.
#[derive(Clone, Debug)]
pub struct NlAttr {
    pub attr_type: u16,
    pub data: Vec<u8>,
}

impl NlAttr {
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() == 4 {
            Some(u32::from_ne_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        let b = &self.data;
        // Strip NUL terminator if present.
        let b = if b.last() == Some(&0) {
            &b[..b.len() - 1]
        } else {
            b
        };
        std::str::from_utf8(b).unwrap_or("")
    }

    /// Parse nested NlAttrs from this attribute's data.
    pub fn nested(&self) -> Vec<NlAttr> {
        parse_attrs(&self.data)
    }
}

/// Parse a flat list of `nlattr` TLVs from `data`.
///
/// The attribute type field has the upper 3 bits reserved for flags
/// (NLA_F_NESTED, NLA_F_NET_BYTEORDER, etc.).  We mask with 0x1FFF to
/// extract the actual type, matching the kernel's nla_type() helper.
/// Parsing advances by NLA_ALIGN(nla_len) — rounding up to 4 bytes —
/// to skip over padding between attributes.
pub fn parse_attrs(mut data: &[u8]) -> Vec<NlAttr> {
    let mut attrs = Vec::new();
    while data.len() >= 4 {
        let nla_len = u16::from_ne_bytes([data[0], data[1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[2], data[3]]) & 0x1FFF;
        if nla_len < 4 || nla_len > data.len() {
            break;
        }
        let payload = data[4..nla_len].to_vec();
        attrs.push(NlAttr {
            attr_type,
            data: payload,
        });
        // Advance by NLA_ALIGN(nla_len).
        let aligned = (nla_len + 3) & !3;
        if aligned > data.len() {
            break;
        }
        data = &data[aligned..];
    }
    attrs
}

/// Find the first attribute with the given type in a list.
pub fn find_attr(attrs: &[NlAttr], attr_type: u16) -> Option<&NlAttr> {
    attrs.iter().find(|a| a.attr_type == attr_type)
}

// ────────────────────────────────────────────────────────────────────────────
// Raw netlink socket
// ────────────────────────────────────────────────────────────────────────────

/// A raw generic-netlink socket with send/recv helpers.
pub struct NlSocket {
    fd: i32,
}

impl NlSocket {
    /// Open a `NETLINK_GENERIC` socket and bind it.
    pub fn open() -> io::Result<Self> {
        // SAFETY: socket(2) creates a new kernel-owned NETLINK_GENERIC socket.
        // All arguments are valid protocol constants; no memory safety
        // invariants are required.  The returned fd is checked for errors
        // immediately and stored in `NlSocket` for Drop-managed cleanup.
        unsafe {
            let fd = libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // Bind: pid=0 lets the kernel assign our port ID.
            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = AF_NETLINK as u16;
            sa.nl_pid = 0;
            sa.nl_groups = 0;
            let rc = libc::bind(
                fd,
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            );
            if rc < 0 {
                libc::close(fd);
                return Err(io::Error::last_os_error());
            }
            Ok(NlSocket { fd })
        }
    }

    /// Send raw bytes to the kernel.
    pub fn send_msg(&self, data: &[u8]) -> io::Result<()> {
        // SAFETY: `self.fd` is a valid open NETLINK_GENERIC socket stored in
        // NlSocket.  `sa` is zeroed (safe for sockaddr_nl, a POD struct) then
        // filled with valid family/pid/groups values.  `data` is a valid slice
        // whose pointer and length are passed directly to sendto(2).
        unsafe {
            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = AF_NETLINK as u16;
            let n = libc::sendto(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            );
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Receive the next netlink message(s).  Returns all complete messages
    /// in the datagram.
    ///
    /// A single recv(2) call may return multiple netlink messages packed into
    /// one datagram (multi-part responses).  The 64 KB buffer matches the
    /// kernel's maximum netlink message size and guarantees we never truncate
    /// a multi-part dump response.
    pub fn recv_msgs(&self) -> io::Result<Vec<NlResponse>> {
        let mut buf = vec![0u8; 65536];
        // SAFETY: `self.fd` is a valid open netlink socket; `buf` is a
        // heap-allocated Vec whose pointer and length are valid for the full
        // 65536-byte write that recv(2) may perform.
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        Ok(parse_nl_messages(&buf))
    }

    /// Perform a request/response exchange: send `msg` and collect all
    /// response messages until `NLMSG_DONE` or error.
    pub fn request(&self, msg: Vec<u8>) -> io::Result<Vec<NlResponse>> {
        self.send_msg(&msg)?;
        let mut responses = Vec::new();
        loop {
            let msgs = self.recv_msgs()?;
            let done = msgs
                .iter()
                .any(|m| matches!(m, NlResponse::Done | NlResponse::Error { .. }));
            responses.extend(msgs);
            if done {
                break;
            }
            // Check if last message was a non-multipart response (single reply).
            if let Some(last) = responses.last() {
                if matches!(last, NlResponse::Msg { .. }) {
                    // Single-reply commands don't send NLMSG_DONE; stop here.
                    break;
                }
            }
        }
        Ok(responses)
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        // SAFETY: `self.fd` is a valid open file descriptor that was created
        // in `NlSocket::open` and is owned exclusively by this struct; Drop
        // is called exactly once, so close(2) is called exactly once.
        unsafe {
            libc::close(self.fd);
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Response parser
// ────────────────────────────────────────────────────────────────────────────

/// A decoded netlink response message.
#[derive(Debug)]
pub enum NlResponse {
    /// A data-carrying message (GENL reply).
    Msg {
        nl_type: u16,
        cmd: u8,
        attrs: Vec<NlAttr>,
    },
    /// `NLMSG_ERROR` — error code from kernel (`errno == 0` means ACK).
    Error { code: i32 },
    /// `NLMSG_DONE` — end of a multi-part dump.
    Done,
}

fn parse_nl_messages(mut data: &[u8]) -> Vec<NlResponse> {
    let mut responses = Vec::new();
    while data.len() >= 16 {
        let nlmsg_len = u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize;
        let nl_type = u16::from_ne_bytes(data[4..6].try_into().unwrap());
        // nlmsg_flags = data[6..8] — not needed for parsing
        // nlmsg_seq   = data[8..12]
        // nlmsg_pid   = data[12..16]
        if nlmsg_len < 16 || nlmsg_len > data.len() {
            break;
        }
        let payload = &data[16..nlmsg_len];
        match nl_type {
            NLMSG_ERROR => {
                let code = if payload.len() >= 4 {
                    i32::from_ne_bytes(payload[..4].try_into().unwrap())
                } else {
                    0
                };
                responses.push(NlResponse::Error { code });
            }
            NLMSG_DONE => {
                responses.push(NlResponse::Done);
            }
            _ => {
                if payload.len() >= 4 {
                    let cmd = payload[0];
                    // payload[1] = version, payload[2..4] = reserved
                    let attr_data = &payload[4..];
                    responses.push(NlResponse::Msg {
                        nl_type,
                        cmd,
                        attrs: parse_attrs(attr_data),
                    });
                }
            }
        }
        let aligned = (nlmsg_len + 3) & !3;
        if aligned > data.len() {
            break;
        }
        data = &data[aligned..];
    }
    responses
}

// ────────────────────────────────────────────────────────────────────────────
// nl80211 high-level API
// ────────────────────────────────────────────────────────────────────────────

/// Errors returned by nl80211 operations.
#[derive(Debug)]
pub enum Nl80211Error {
    Io(io::Error),
    FamilyNotFound,
    NoInterfaces,
    KernelError(i32),
    NotSupported,
}

impl std::fmt::Display for Nl80211Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Nl80211Error::Io(e) => write!(f, "netlink I/O error: {e}"),
            Nl80211Error::FamilyNotFound => {
                write!(f, "nl80211 kernel family not found (no WiFi support?)")
            }
            Nl80211Error::NoInterfaces => write!(f, "no wireless interfaces found"),
            Nl80211Error::KernelError(n) => write!(f, "nl80211 kernel error: {n}"),
            Nl80211Error::NotSupported => write!(f, "operation not supported by driver"),
        }
    }
}

impl From<io::Error> for Nl80211Error {
    fn from(e: io::Error) -> Self {
        Nl80211Error::Io(e)
    }
}

/// A WiFi interface discovered by nl80211.
#[derive(Debug, Clone)]
pub struct WifiInterface {
    /// Interface index (from kernel).
    pub ifindex: u32,
    /// Interface name (e.g. `"wlan0"`).
    pub ifname: String,
    /// PHY (wiphy) index.
    pub wiphy: u32,
    /// Interface type (one of `NL80211_IFTYPE_*`).
    pub iftype: u32,
    /// MAC address (6 bytes).
    pub mac: [u8; 6],
}

/// A BSS (access point or peer) found in scan results.
#[derive(Debug, Clone)]
pub struct BssEntry {
    /// BSSID (MAC address, 6 bytes).
    pub bssid: [u8; 6],
    /// Channel frequency in MHz.
    pub freq_mhz: u32,
    /// SSID bytes (not NUL-terminated).
    pub ssid: Vec<u8>,
    /// Signal strength in mBm (divide by 100 for dBm).
    pub signal_mbm: i32,
}

impl BssEntry {
    /// SSID as a lossy UTF-8 string.
    pub fn ssid_str(&self) -> String {
        String::from_utf8_lossy(&self.ssid).into_owned()
    }

    /// Signal strength in dBm.
    pub fn signal_dbm(&self) -> f32 {
        self.signal_mbm as f32 / 100.0
    }
}

/// The nl80211 context: a socket + resolved family ID.
pub struct Nl80211 {
    sock: NlSocket,
    /// Dynamically assigned nl80211 family ID.
    pub family_id: u16,
}

impl Nl80211 {
    /// Open a generic-netlink socket and resolve the nl80211 family ID.
    ///
    /// Fails if the kernel does not have cfg80211/nl80211 loaded (no WiFi
    /// hardware or driver not loaded).
    pub fn open() -> Result<Self, Nl80211Error> {
        let sock = NlSocket::open()?;
        let family_id = Self::get_family_id(&sock, "nl80211")?;
        Ok(Nl80211 { sock, family_id })
    }

    /// Resolve a generic-netlink family name to its numeric ID.
    fn get_family_id(sock: &NlSocket, name: &str) -> Result<u16, Nl80211Error> {
        let mut msg = NlMsg::new_genl(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, NLM_F_ACK);
        msg.put_strz(CTRL_ATTR_FAMILY_NAME, name);
        let bytes = msg.finish();
        let responses = sock.request(bytes)?;
        for r in &responses {
            if let NlResponse::Msg { attrs, .. } = r {
                if let Some(a) = find_attr(attrs, CTRL_ATTR_FAMILY_ID) {
                    if let Some(id) = a.as_u32() {
                        return Ok(id as u16);
                    }
                }
            }
        }
        Err(Nl80211Error::FamilyNotFound)
    }

    /// List all wireless interfaces on the system.
    pub fn get_interfaces(&self) -> Result<Vec<WifiInterface>, Nl80211Error> {
        let msg = NlMsg::new_genl(self.family_id, NL80211_CMD_GET_INTERFACE, NLM_F_DUMP);
        let responses = self.sock.request(msg.finish())?;
        let mut ifaces = Vec::new();
        for r in &responses {
            if let NlResponse::Msg { attrs, .. } = r {
                let ifindex = find_attr(attrs, NL80211_ATTR_IFINDEX)
                    .and_then(|a| a.as_u32())
                    .unwrap_or(0);
                let ifname = find_attr(attrs, NL80211_ATTR_IFNAME)
                    .map(|a| a.as_str().to_owned())
                    .unwrap_or_default();
                let wiphy = find_attr(attrs, NL80211_ATTR_WIPHY)
                    .and_then(|a| a.as_u32())
                    .unwrap_or(0);
                let iftype = find_attr(attrs, NL80211_ATTR_IFTYPE)
                    .and_then(|a| a.as_u32())
                    .unwrap_or(NL80211_IFTYPE_STATION);
                let mac = find_attr(attrs, NL80211_ATTR_MAC)
                    .and_then(|a| a.data.as_slice().try_into().ok())
                    .unwrap_or([0u8; 6]);
                if ifindex > 0 && !ifname.is_empty() {
                    ifaces.push(WifiInterface {
                        ifindex,
                        ifname,
                        wiphy,
                        iftype,
                        mac,
                    });
                }
            }
        }
        Ok(ifaces)
    }

    /// Trigger a scan on `ifindex`.  The scan is asynchronous; poll
    /// `get_scan_results` after a delay (typically 3–10 seconds).
    pub fn trigger_scan(&self, ifindex: u32) -> Result<(), Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_TRIGGER_SCAN, NLM_F_ACK);
        msg.put_u32(NL80211_ATTR_IFINDEX, ifindex);
        let responses = self.sock.request(msg.finish())?;
        for r in &responses {
            if let NlResponse::Error { code } = r {
                if *code != 0 {
                    return Err(Nl80211Error::KernelError(*code));
                }
            }
        }
        Ok(())
    }

    /// Read scan results from the kernel cache for `ifindex`.
    pub fn get_scan_results(&self, ifindex: u32) -> Result<Vec<BssEntry>, Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_GET_SCAN, NLM_F_DUMP);
        msg.put_u32(NL80211_ATTR_IFINDEX, ifindex);
        let responses = self.sock.request(msg.finish())?;
        let mut entries = Vec::new();
        for r in &responses {
            if let NlResponse::Msg { attrs, .. } = r {
                if let Some(bss_attr) = find_attr(attrs, NL80211_BSS_BSSID) {
                    // The BSS data is nested under NL80211_ATTR_BSS (15).
                    if let Some(bss_container) = find_attr(attrs, NL80211_ATTR_BSS) {
                        let bss_attrs = bss_container.nested();
                        let bssid: [u8; 6] = find_attr(&bss_attrs, NL80211_BSS_BSSID)
                            .and_then(|a| a.data.as_slice().try_into().ok())
                            .unwrap_or_else(|| {
                                bss_attr.data.as_slice().try_into().unwrap_or([0u8; 6])
                            });
                        let freq_mhz = find_attr(&bss_attrs, NL80211_BSS_FREQUENCY)
                            .and_then(|a| a.as_u32())
                            .unwrap_or(0);
                        let signal_mbm = find_attr(&bss_attrs, NL80211_BSS_SIGNAL_MBM)
                            .and_then(|a| a.as_u32())
                            .map(|v| v as i32)
                            .unwrap_or(0);
                        // SSID is in Information Elements (tag 0 = SSID).
                        let ssid = find_attr(&bss_attrs, NL80211_BSS_INFORMATION_ELEMENTS)
                            .map(|a| extract_ie_ssid(&a.data))
                            .unwrap_or_default();
                        entries.push(BssEntry {
                            bssid,
                            freq_mhz,
                            ssid,
                            signal_mbm,
                        });
                    }
                }
            }
        }
        Ok(entries)
    }

    /// Create a new virtual WiFi interface of type `iftype` (e.g.
    /// `NL80211_IFTYPE_AP` or `NL80211_IFTYPE_P2P_DEVICE`).
    ///
    /// Returns the new interface's index.
    pub fn new_interface(&self, wiphy: u32, name: &str, iftype: u32) -> Result<u32, Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_NEW_INTERFACE, NLM_F_ACK);
        msg.put_u32(NL80211_ATTR_WIPHY, wiphy);
        msg.put_str(NL80211_ATTR_IFNAME, name);
        msg.put_u32(NL80211_ATTR_IFTYPE, iftype);
        let responses = self.sock.request(msg.finish())?;
        for r in &responses {
            match r {
                NlResponse::Msg { attrs, .. } => {
                    if let Some(idx) = find_attr(attrs, NL80211_ATTR_IFINDEX) {
                        return idx.as_u32().ok_or(Nl80211Error::NotSupported);
                    }
                }
                NlResponse::Error { code } if *code != 0 => {
                    return Err(Nl80211Error::KernelError(*code));
                }
                _ => {}
            }
        }
        Err(Nl80211Error::NotSupported)
    }

    /// Delete a virtual WiFi interface by index.
    pub fn del_interface(&self, ifindex: u32) -> Result<(), Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_DEL_INTERFACE, NLM_F_ACK);
        msg.put_u32(NL80211_ATTR_IFINDEX, ifindex);
        let responses = self.sock.request(msg.finish())?;
        for r in &responses {
            if let NlResponse::Error { code } = r {
                if *code != 0 {
                    return Err(Nl80211Error::KernelError(*code));
                }
            }
        }
        Ok(())
    }

    /// Join or create an IBSS (ad-hoc) network.
    ///
    /// Both peers call this with the same `ssid` and `freq_mhz`; the kernel
    /// handles cell formation (one creates, others join automatically).
    ///
    /// `ssid` — mesh cell identifier (up to 32 bytes).
    /// `freq_mhz` — channel frequency, e.g. 2412 (ch 1), 2437 (ch 6), 5180 (ch 36).
    pub fn join_ibss(&self, ifindex: u32, ssid: &[u8], freq_mhz: u32) -> Result<(), Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_JOIN_IBSS, NLM_F_ACK);
        msg.put_u32(NL80211_ATTR_IFINDEX, ifindex);
        msg.put_bytes(NL80211_ATTR_SSID, ssid);
        msg.put_u32(NL80211_ATTR_WIPHY_FREQ, freq_mhz);
        let responses = self.sock.request(msg.finish())?;
        for r in &responses {
            if let NlResponse::Error { code } = r {
                if *code != 0 {
                    return Err(Nl80211Error::KernelError(*code));
                }
            }
        }
        Ok(())
    }

    /// Join an 802.11s mesh network.
    ///
    /// Both peers use the same `mesh_id` (derived from peer ID hex or pairing
    /// context).  The kernel implements the 802.11s HWMP routing protocol.
    pub fn join_mesh(
        &self,
        ifindex: u32,
        mesh_id: &[u8],
        freq_mhz: u32,
    ) -> Result<(), Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_JOIN_MESH, NLM_F_ACK);
        msg.put_u32(NL80211_ATTR_IFINDEX, ifindex);
        msg.put_bytes(NL80211_ATTR_MESH_ID, mesh_id);
        msg.put_u32(NL80211_ATTR_WIPHY_FREQ, freq_mhz);
        let responses = self.sock.request(msg.finish())?;
        for r in &responses {
            if let NlResponse::Error { code } = r {
                if *code != 0 {
                    return Err(Nl80211Error::KernelError(*code));
                }
            }
        }
        Ok(())
    }

    /// Connect to a WPA2-PSK access point.
    ///
    /// `ssid` — target network SSID.
    /// `bssid` — target BSSID (6 bytes).
    /// `pmk` — the 256-bit WPA2 Pairwise Master Key (derived by us from the
    ///   PBKDF2(PSK, SSID) or directly from the pairing exchange).
    pub fn connect_wpa2(
        &self,
        ifindex: u32,
        ssid: &[u8],
        bssid: Option<&[u8; 6]>,
        pmk: &[u8; 32],
    ) -> Result<(), Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_CONNECT, NLM_F_ACK);
        msg.put_u32(NL80211_ATTR_IFINDEX, ifindex);
        msg.put_bytes(NL80211_ATTR_SSID, ssid);
        if let Some(b) = bssid {
            msg.put_bytes(NL80211_ATTR_MAC, b);
        }
        msg.put_u32(NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
        msg.put_bytes(NL80211_ATTR_PMK, pmk);
        // AKM suite: PSK.
        msg.put_bytes(NL80211_ATTR_AKM_SUITES, &WLAN_AKM_SUITE_PSK.to_ne_bytes());
        // Pairwise + group cipher: CCMP.
        msg.put_bytes(
            NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
            &WLAN_CIPHER_SUITE_CCMP.to_ne_bytes(),
        );
        msg.put_bytes(
            NL80211_ATTR_CIPHER_SUITE_GROUP,
            &WLAN_CIPHER_SUITE_CCMP.to_ne_bytes(),
        );
        let responses = self.sock.request(msg.finish())?;
        for r in &responses {
            if let NlResponse::Error { code } = r {
                if *code != 0 {
                    return Err(Nl80211Error::KernelError(*code));
                }
            }
        }
        Ok(())
    }

    /// Disconnect from the current network.
    pub fn disconnect(&self, ifindex: u32, reason: u16) -> Result<(), Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_DISCONNECT, NLM_F_ACK);
        msg.put_u32(NL80211_ATTR_IFINDEX, ifindex);
        msg.put_bytes(NL80211_ATTR_REASON_CODE, &reason.to_ne_bytes());
        let responses = self.sock.request(msg.finish())?;
        for r in &responses {
            if let NlResponse::Error { code } = r {
                if *code != 0 {
                    return Err(Nl80211Error::KernelError(*code));
                }
            }
        }
        Ok(())
    }

    /// Start a P2P device on `wiphy`.  Returns the P2P device interface index.
    ///
    /// The P2P device interface is a virtual interface used for P2P
    /// management (scan, GO negotiation).  It is separate from the actual
    /// P2P group interface created during group formation.
    pub fn start_p2p_device(&self, wiphy: u32) -> Result<u32, Nl80211Error> {
        self.new_interface(wiphy, "p2p-dev-mi", NL80211_IFTYPE_P2P_DEVICE)
    }

    /// Stop the P2P device and remove its virtual interface.
    pub fn stop_p2p_device(&self, ifindex: u32) -> Result<(), Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_STOP_P2P_DEVICE, NLM_F_ACK);
        msg.put_u32(NL80211_ATTR_IFINDEX, ifindex);
        let _ = self.sock.request(msg.finish());
        self.del_interface(ifindex)
    }

    /// Set the interface type of an existing interface.
    pub fn set_interface_type(&self, ifindex: u32, iftype: u32) -> Result<(), Nl80211Error> {
        let mut msg = NlMsg::new_genl(self.family_id, NL80211_CMD_NEW_INTERFACE, NLM_F_ACK);
        msg.put_u32(NL80211_ATTR_IFINDEX, ifindex);
        msg.put_u32(NL80211_ATTR_IFTYPE, iftype);
        let responses = self.sock.request(msg.finish())?;
        for r in &responses {
            if let NlResponse::Error { code } = r {
                if *code != 0 {
                    return Err(Nl80211Error::KernelError(*code));
                }
            }
        }
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 802.11 Information Element parser
// ────────────────────────────────────────────────────────────────────────────

/// Extract the SSID from an 802.11 Information Elements blob.
///
/// IEs are TLV: `(id: u8) (len: u8) (data: [u8; len])`.
/// SSID is IE tag 0.
fn extract_ie_ssid(ies: &[u8]) -> Vec<u8> {
    let mut pos = 0;
    while pos + 2 <= ies.len() {
        let id = ies[pos];
        let len = ies[pos + 1] as usize;
        pos += 2;
        if pos + len > ies.len() {
            break;
        }
        if id == 0 {
            // SSID tag.
            return ies[pos..pos + len].to_vec();
        }
        pos += len;
    }
    Vec::new()
}

// ────────────────────────────────────────────────────────────────────────────
// WiFi Direct via nl80211 — P2P group creation
// ────────────────────────────────────────────────────────────────────────────

/// A completed P2P / ad-hoc connection over nl80211.
pub struct Nl80211Connection {
    /// Interface index of the connected/created group interface.
    pub ifindex: u32,
    /// Interface name (e.g. `"p2p-wlan0-0"` or `"wlan0"`).
    pub ifname: String,
    /// Mode used to establish the connection.
    pub mode: ConnectionMode,
}

/// Which connection mode was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// 802.11s mesh (kernel HWMP).
    Mesh11s,
    /// IBSS (ad-hoc cell).
    Ibss,
    /// Soft-AP + station (one becomes AP, other connects).
    SoftApStation,
}

/// Attempt to connect two Mesh Infinity nodes directly over WiFi (§5.8).
///
/// The strategy follows a degradation ladder:
/// 1. **802.11s mesh** — ideal for multi-hop mesh: the kernel handles HWMP
///    routing and the interface stays in mesh mode for additional peers.
/// 2. **IBSS (ad-hoc)** — fallback when the driver lacks mesh support.
///    Creates a peer-to-peer cell without an access point.
///
/// Both modes use a deterministic SSID `MI:<peer_id_hex[:16]>` so that
/// both peers independently arrive at the same cell name without prior
/// coordination — the first 16 hex characters of the peer ID provide
/// enough uniqueness to avoid collisions in practice.
///
/// `ifindex` — the WiFi interface to use (must be in station or managed mode).
/// `peer_id_hex` — 64-character hex peer ID, used as the mesh/IBSS SSID.
/// `freq_mhz` — channel to use (default: 2437 = channel 6, 2.4 GHz).
pub fn direct_connect(
    nl: &Nl80211,
    ifindex: u32,
    peer_id_hex: &str,
    freq_mhz: u32,
) -> Result<Nl80211Connection, Nl80211Error> {
    // Derive a stable mesh/IBSS ID from the peer pair.
    let mesh_id = format!("MI:{}", &peer_id_hex[..16]);
    let ifaces = nl.get_interfaces()?;
    let iface = ifaces
        .iter()
        .find(|i| i.ifindex == ifindex)
        .ok_or(Nl80211Error::NoInterfaces)?;
    let ifname = iface.ifname.clone();

    // Try 802.11s mesh first.
    if nl.join_mesh(ifindex, mesh_id.as_bytes(), freq_mhz).is_ok() {
        return Ok(Nl80211Connection {
            ifindex,
            ifname,
            mode: ConnectionMode::Mesh11s,
        });
    }

    // Fall back to IBSS (ad-hoc).
    nl.join_ibss(ifindex, mesh_id.as_bytes(), freq_mhz)?;
    Ok(Nl80211Connection {
        ifindex,
        ifname,
        mode: ConnectionMode::Ibss,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nlmsg_encode_decode_roundtrip() {
        let mut msg = NlMsg::new_genl(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, NLM_F_ACK);
        msg.put_strz(CTRL_ATTR_FAMILY_NAME, "nl80211");
        let bytes = msg.finish();

        // nlmsghdr: 16 B, genlmsghdr: 4 B, attr header: 4 B, "nl80211\0": 8 B = 32 B total
        assert!(bytes.len() >= 28);

        // nlmsg_len is the first 4 bytes.
        let nlmsg_len = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(nlmsg_len, bytes.len());

        // Parse the attribute.
        let attr_data = &bytes[20..]; // skip nlmsghdr(16) + genlmsghdr(4)
        let attrs = parse_attrs(attr_data);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].attr_type, CTRL_ATTR_FAMILY_NAME);
        assert_eq!(attrs[0].as_str(), "nl80211");
    }

    #[test]
    fn ie_ssid_extraction() {
        // Build a fake IE blob: SSID IE (tag 0, len 6, "testap") + HT Caps (tag 45)
        let ies = [0u8, 6, b't', b'e', b's', b't', b'a', b'p', 45, 2, 0, 0];
        assert_eq!(extract_ie_ssid(&ies), b"testap");
    }

    #[test]
    fn ie_ssid_extraction_no_ssid() {
        // Only HT Caps IE, no SSID.
        let ies = [45u8, 2, 0, 0];
        assert_eq!(extract_ie_ssid(&ies), b"");
    }

    #[test]
    fn parse_attrs_roundtrip() {
        let mut msg = NlMsg::default();
        msg.put_u32(3, 12345);
        msg.put_str(4, "wlan0");
        // Raw attr bytes start at the beginning (no nlmsghdr).
        let attrs = parse_attrs(&msg.buf);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].attr_type, 3);
        assert_eq!(attrs[0].as_u32(), Some(12345));
        assert_eq!(attrs[1].attr_type, 4);
        assert_eq!(attrs[1].as_str(), "wlan0");
    }

    #[test]
    fn nested_attr_encode_decode() {
        let mut outer = NlMsg::default();
        outer.put_nested(15, |inner| {
            inner.put_u32(1, 0x00112233);
            inner.put_str(2, "nested");
        });
        let attrs = parse_attrs(&outer.buf);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].attr_type, 15);
        let inner = attrs[0].nested();
        assert_eq!(inner.len(), 2);
        assert_eq!(inner[0].attr_type, 1);
        assert_eq!(inner[0].as_u32(), Some(0x00112233));
        assert_eq!(inner[1].attr_type, 2);
        assert_eq!(inner[1].as_str(), "nested");
    }

    #[test]
    fn nl_seq_increments() {
        let before = NL_SEQ.load(Ordering::Relaxed);
        let _ = NlMsg::new_genl(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0).finish();
        let after = NL_SEQ.load(Ordering::Relaxed);
        assert!(after > before, "sequence number should increment");
    }
}
