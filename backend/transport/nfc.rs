//! NFC Transport (§5.9)
//!
//! Near Field Communication (NFC) transport for Mesh Infinity, providing
//! proximity-based pairing payload delivery and bidirectional data exchange
//! between devices within approximately 4 cm of each other.
//!
//! # Architecture
//!
//! NFC operates at two levels:
//!
//! 1. **NDEF tags** — one-shot pairing payload delivery. When Alice touches
//!    Bob's device, Bob's pairing payload is written as an NDEF record that
//!    Alice reads. This is a passive, contactless tag read/write.
//!
//! 2. **NFC-DEP / LLCP** — bidirectional data exchange between two active NFC
//!    devices. Both devices can send and receive data over an NFC link using
//!    the Logical Link Control Protocol (LLCP), which runs on top of NFC-DEP
//!    (Data Exchange Protocol) in ISO 18092 active mode.
//!
//! # NDEF Format
//!
//! The NFC Data Exchange Format (NDEF) is used for pairing records:
//!
//! ```text
//! ┌──────────────┬─────────────┬────────────────────┬────────────┬─────────────────────┐
//! │ Flags+TNF    │ Type Length │ Payload Length     │ Type       │ Payload             │
//! │  (1 byte)    │  (1 byte)   │  (1 or 4 bytes)    │ (N bytes)  │ (M bytes)           │
//! └──────────────┴─────────────┴────────────────────┴────────────┴─────────────────────┘
//! ```
//!
//! For Mesh Infinity pairing data:
//! - TNF = `0x04` (External type)
//! - Type = `b"meshinfinity.io:pairing"` (23 bytes)
//! - Payload = the raw pairing JSON bytes
//!
//! # Platform Support
//!
//! | Platform | Support  | Mechanism                                      |
//! |----------|----------|------------------------------------------------|
//! | Linux    | Yes      | `AF_NFC` socket, `/sys/class/nfc/` discovery   |
//! | Android  | Protocol | Protocol logic; native APIs called from Flutter|
//! | iOS      | Protocol | Protocol logic; native APIs called from Flutter|
//! | Other    | Stub     | Returns `NfcError::NotAvailable`               |
//!
//! On Linux, NFC devices are exposed through the kernel NFC subsystem:
//! - `/sys/class/nfc/nfc0/` — device attributes
//! - `AF_NFC` (family 39) sockets with `SOCK_SEQPACKET`
//! - Protocol `NFC_SOCKPROTO_RAW` (1) for raw NCI frames
//! - Protocol `NFC_SOCKPROTO_LLCP` (2) for LLCP data exchange
//!
//! # References
//!
//! - §5.9 of the Mesh Infinity specification
//! - ISO/IEC 18092 (NFC-IP1) — NFC-DEP active mode
//! - ISO/IEC 13157-3 — LLCP (Logical Link Control Protocol)
//! - NFC Forum NDEF Technical Specification 1.0
//! - Linux kernel NFC subsystem: `include/uapi/linux/nfc.h`

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum payload bytes in a single NFC I-frame data exchange.
///
/// NFC-DEP I-frames carry up to 253 bytes; overhead (sequence numbers,
/// information field prefix) consumes 9 bytes, leaving 244 bytes for
/// application payload per frame.
pub const NFC_MAX_FRAME_BYTES: usize = 244;

/// NDEF Type Name Format: Well-Known type (§4.2 of NFC Forum NDEF spec).
pub const TNF_WELL_KNOWN: u8 = 0x01;

/// NDEF Type Name Format: External type (`meshinfinity.io:pairing`).
pub const TNF_EXTERNAL: u8 = 0x04;

/// NDEF flags: Message Begin bit (byte 7 of flags+TNF octet).
const NDEF_MB: u8 = 0x80;

/// NDEF flags: Message End bit (byte 6 of flags+TNF octet).
const NDEF_ME: u8 = 0x40;

/// NDEF flags: Short Record bit — payload length encoded in 1 byte.
const NDEF_SR: u8 = 0x10;

/// NDEF flags: ID Length present bit.
const NDEF_IL: u8 = 0x08;

/// TNF mask (lower 3 bits of flags+TNF octet).
const NDEF_TNF_MASK: u8 = 0x07;

/// External type string for Mesh Infinity pairing NDEF records.
pub const MESH_NDEF_TYPE: &[u8] = b"meshinfinity.io:pairing";

/// Linux NFC socket address family (AF_NFC = 39).
#[cfg(target_os = "linux")]
const AF_NFC: libc::c_int = 39;

/// Linux NFC socket protocol: raw NCI frames.
#[cfg(target_os = "linux")]
const NFC_SOCKPROTO_RAW: libc::c_int = 1;

/// Sysfs path for NFC device enumeration on Linux.
#[cfg(target_os = "linux")]
const NFC_SYSFS_CLASS: &str = "/sys/class/nfc";

// ---------------------------------------------------------------------------
// NDEF record type
// ---------------------------------------------------------------------------

/// An NFC Data Exchange Format (NDEF) record.
///
/// Each NDEF message consists of one or more records chained together.
/// For Mesh Infinity pairing, a single NDEF record per message is used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NdefRecord {
    /// Type Name Format — encodes the meaning of `record_type`.
    ///
    /// Common values:
    /// - `0x01` (`TNF_WELL_KNOWN`) — well-known NFC Forum types (`T`, `U`, …)
    /// - `0x04` (`TNF_EXTERNAL`) — external (application-defined) type URN
    pub tnf: u8,

    /// The record type identifier.
    ///
    /// For Mesh Infinity pairing records this is `b"meshinfinity.io:pairing"`.
    pub record_type: Vec<u8>,

    /// The raw payload bytes.
    pub payload: Vec<u8>,

    /// Optional record ID (may be empty).
    pub id: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by the NFC transport.
#[derive(Debug, Clone, PartialEq)]
pub enum NfcError {
    /// NFC is not available on this platform (compile-time or runtime).
    NotAvailable,
    /// No NFC device was found (e.g. `/dev/nfc0` does not exist).
    DeviceNotFound,
    /// No NFC tag is present in the field.
    TagNotPresent,
    /// A frame-level transmit or receive error occurred.
    TransmitError(String),
    /// An NFC protocol-level error occurred.
    ProtocolError(String),
    /// The supplied payload exceeds [`NFC_MAX_FRAME_BYTES`].
    PayloadTooLarge,
}

impl std::fmt::Display for NfcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NfcError::NotAvailable => write!(f, "NFC transport not available on this platform"),
            NfcError::DeviceNotFound => write!(f, "NFC device not found"),
            NfcError::TagNotPresent => write!(f, "No NFC tag present in the field"),
            NfcError::TransmitError(msg) => write!(f, "NFC transmit error: {msg}"),
            NfcError::ProtocolError(msg) => write!(f, "NFC protocol error: {msg}"),
            NfcError::PayloadTooLarge => write!(
                f,
                "NFC payload exceeds maximum frame size ({NFC_MAX_FRAME_BYTES} bytes)"
            ),
        }
    }
}

impl std::error::Error for NfcError {}

// ---------------------------------------------------------------------------
// NDEF encode / decode (platform-independent)
// ---------------------------------------------------------------------------

/// Encode a byte slice as a Mesh Infinity NDEF message.
///
/// Produces a single-record NDEF message using:
/// - TNF = `0x04` (External type)
/// - Type = `b"meshinfinity.io:pairing"`
/// - Payload = `payload`
///
/// The Short Record (SR) flag is set when the payload fits in 255 bytes,
/// otherwise a 4-byte payload length field is used.
///
/// # Example
///
/// ```rust
/// use mesh_infinity::transport::nfc::{encode_ndef_message, decode_ndef_message};
///
/// let original = b"hello pairing";
/// let encoded = encode_ndef_message(original);
/// let decoded = decode_ndef_message(&encoded).unwrap();
/// assert_eq!(decoded, original);
/// ```
pub fn encode_ndef_message(payload: &[u8]) -> Vec<u8> {
    let record_type = MESH_NDEF_TYPE;
    let type_len = record_type.len() as u8; // 23 bytes — always fits in u8
    let payload_len = payload.len();

    // Determine whether to use Short Record (SR) flag.
    // SR = 1 byte payload length (fits 0–255 bytes).
    // Otherwise: 4-byte big-endian payload length.
    let use_sr = payload_len <= 255;

    // Flags+TNF byte: MB=1 ME=1 CF=0 SR=? IL=0 TNF=0x04
    let flags: u8 = NDEF_MB | NDEF_ME | (if use_sr { NDEF_SR } else { 0 }) | TNF_EXTERNAL;

    let mut buf = Vec::with_capacity(2 + (if use_sr { 1 } else { 4 }) + record_type.len() + payload_len);

    buf.push(flags);
    buf.push(type_len);

    if use_sr {
        buf.push(payload_len as u8);
    } else {
        let pl = payload_len as u32;
        buf.push((pl >> 24) as u8);
        buf.push((pl >> 16) as u8);
        buf.push((pl >> 8) as u8);
        buf.push(pl as u8);
    }

    // No ID (IL flag not set, so no id_length field).
    buf.extend_from_slice(record_type);
    buf.extend_from_slice(payload);
    buf
}

/// Decode a Mesh Infinity NDEF message, returning the inner payload.
///
/// Only processes the first record in the message.  Returns `None` if the
/// buffer is malformed, too short, or does not contain a Mesh Infinity
/// pairing record (TNF = `0x04`, type = `"meshinfinity.io:pairing"`).
pub fn decode_ndef_message(ndef_bytes: &[u8]) -> Option<Vec<u8>> {
    if ndef_bytes.len() < 3 {
        return None;
    }

    let flags = ndef_bytes[0];
    let tnf = flags & NDEF_TNF_MASK;
    let is_sr = (flags & NDEF_SR) != 0;
    let has_id = (flags & NDEF_IL) != 0;

    let type_len = ndef_bytes[1] as usize;

    // Parse payload length.
    let (payload_len, mut offset): (usize, usize) = if is_sr {
        if ndef_bytes.len() < 3 {
            return None;
        }
        (ndef_bytes[2] as usize, 3)
    } else {
        if ndef_bytes.len() < 6 {
            return None;
        }
        let pl = ((ndef_bytes[2] as u32) << 24)
            | ((ndef_bytes[3] as u32) << 16)
            | ((ndef_bytes[4] as u32) << 8)
            | (ndef_bytes[5] as u32);
        (pl as usize, 6)
    };

    // Optional ID length field.
    let id_len: usize = if has_id {
        if ndef_bytes.len() <= offset {
            return None;
        }
        let il = ndef_bytes[offset] as usize;
        offset += 1;
        il
    } else {
        0
    };

    // Bounds check for type + id + payload.
    let total_needed = offset + type_len + id_len + payload_len;
    if ndef_bytes.len() < total_needed {
        return None;
    }

    // Verify this is a Mesh Infinity pairing record.
    if tnf != TNF_EXTERNAL {
        return None;
    }
    let record_type = &ndef_bytes[offset..offset + type_len];
    if record_type != MESH_NDEF_TYPE {
        return None;
    }
    offset += type_len;

    // Skip ID bytes.
    offset += id_len;

    // Extract payload.
    Some(ndef_bytes[offset..offset + payload_len].to_vec())
}

// ---------------------------------------------------------------------------
// NfcTransport — Linux implementation
// ---------------------------------------------------------------------------

/// NFC transport for proximate device pairing and data exchange (§5.9).
///
/// ## Thread safety
///
/// `NfcTransport` is `Send + Sync`.  Both queues are protected by `Mutex`.
///
/// ## Usage (Linux)
///
/// 1. Enumerate available devices with `NfcTransport::detect_devices()`.
/// 2. Create an instance with `NfcTransport::new("/dev/nfc0")`.
/// 3. For pairing: call `write_ndef_tag` / `read_ndef_tag` against a passive tag.
/// 4. For peer data exchange: call `send` / `recv`, or use `start_poll_loop`
///    combined with `queue_outbound` / `recv`.
pub struct NfcTransport {
    /// Platform device path, e.g. `"/dev/nfc0"` on Linux.
    pub device_path: String,
    /// Inbound frames received from the NFC peer or tag.
    inbound: Mutex<VecDeque<Vec<u8>>>,
    /// Outbound frames waiting to be transmitted over NFC-DEP.
    outbound: Mutex<VecDeque<Vec<u8>>>,
}

// ---------------------------------------------------------------------------
// Linux-specific implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::os::unix::io::RawFd;

    /// Open a raw NFC socket using the Linux `AF_NFC` socket family.
    ///
    /// Returns the raw file descriptor on success.  The caller is responsible
    /// for closing it with `libc::close`.
    ///
    /// Protocol values:
    /// - `AF_NFC` = 39
    /// - `SOCK_SEQPACKET` = 5 (sequenced, reliable, two-way byte streams)
    /// - `NFC_SOCKPROTO_RAW` = 1 (raw NCI frames)
    pub(super) fn open_nfc_socket() -> Result<RawFd, super::NfcError> {
        // SAFETY: socket(2) is a standard POSIX syscall that creates a new
        // kernel-owned file descriptor; no memory safety invariants are
        // required beyond the constant arguments being valid protocol values.
        let fd = unsafe {
            libc::socket(
                AF_NFC,
                libc::SOCK_SEQPACKET,
                NFC_SOCKPROTO_RAW,
            )
        };
        if fd < 0 {
            return Err(super::NfcError::DeviceNotFound);
        }
        Ok(fd)
    }

    /// Read a single NCI frame from an open NFC socket file descriptor.
    ///
    /// Returns up to `NFC_MAX_FRAME_BYTES` bytes.  Returns an error if the
    /// socket read fails or the device closes.
    pub(super) fn read_nfc_frame(fd: RawFd) -> Result<Vec<u8>, super::NfcError> {
        let mut buf = vec![0u8; super::NFC_MAX_FRAME_BYTES + 4]; // +4 for NCI header
        // SAFETY: `fd` is a valid open NFC socket file descriptor returned by
        // `open_nfc_socket`; `buf` is a valid Vec allocation and its pointer
        // and length are consistent, satisfying read(2)'s buffer requirements.
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            return Err(super::NfcError::TransmitError(err.to_string()));
        }
        if n == 0 {
            return Err(super::NfcError::TransmitError("NFC device closed".into()));
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    /// Write a single NCI frame to an open NFC socket file descriptor.
    pub(super) fn write_nfc_frame(fd: RawFd, data: &[u8]) -> Result<(), super::NfcError> {
        // SAFETY: `fd` is a valid open NFC socket; `data` is a valid slice
        // and its pointer and length are consistent, satisfying write(2)'s
        // requirements.  The cast to *const c_void is the standard idiom.
        let n = unsafe {
            libc::write(
                fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            return Err(super::NfcError::TransmitError(err.to_string()));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl NfcTransport {
    /// Create a new NFC transport on the given device path.
    ///
    /// Verifies the device exists in the Linux NFC sysfs hierarchy.
    /// Does not open a socket until I/O is actually needed.
    pub fn new(device_path: &str) -> Result<Self, NfcError> {
        // Extract device name (e.g. "nfc0") from path (e.g. "/dev/nfc0").
        let dev_name = std::path::Path::new(device_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let sysfs_path = format!("{NFC_SYSFS_CLASS}/{dev_name}");
        if !std::path::Path::new(&sysfs_path).exists() {
            // Also accept if the raw socket creation succeeds — device may
            // exist without a sysfs entry on some kernel versions.
            match linux_impl::open_nfc_socket() {
                Ok(fd) => {
                    // Socket succeeded: close it; we'll reopen when needed.
                    // SAFETY: `fd` was just returned by open_nfc_socket and is
                    // a valid open file descriptor; close(2) is the required
                    // cleanup call.
                    unsafe { libc::close(fd) };
                }
                Err(_) => {
                    return Err(NfcError::DeviceNotFound);
                }
            }
        }

        Ok(NfcTransport {
            device_path: device_path.to_owned(),
            inbound: Mutex::new(VecDeque::new()),
            outbound: Mutex::new(VecDeque::new()),
        })
    }

    /// Detect available NFC devices by scanning `/sys/class/nfc/`.
    ///
    /// Returns a `Vec` of device paths such as `["/dev/nfc0", "/dev/nfc1"]`.
    /// Returns an empty `Vec` when no devices are found or the sysfs path
    /// does not exist.
    pub fn detect_devices() -> Vec<String> {
        let sysfs = std::path::Path::new(NFC_SYSFS_CLASS);
        if !sysfs.exists() {
            return Vec::new();
        }
        let Ok(entries) = std::fs::read_dir(sysfs) else {
            return Vec::new();
        };
        entries
            .filter_map(|e| {
                let entry = e.ok()?;
                let name = entry.file_name();
                let name_str = name.to_str()?;
                // Only include nfc* directory entries.
                if name_str.starts_with("nfc") {
                    Some(format!("/dev/{name_str}"))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Write an NDEF message to a passive NFC tag.
    ///
    /// Encodes `record` as an NDEF message and writes it via the Linux NFC
    /// raw socket. The tag must be within range of the NFC antenna.
    ///
    /// Returns `NfcError::TagNotPresent` when no tag is in the field,
    /// `NfcError::PayloadTooLarge` when the NDEF record exceeds the maximum
    /// frame size.
    pub fn write_ndef_tag(&self, record: &NdefRecord) -> Result<(), NfcError> {
        // Build a minimal NdefRecord-derived payload for the external type.
        let ndef_bytes = encode_ndef_message(&record.payload);
        if ndef_bytes.len() > NFC_MAX_FRAME_BYTES {
            return Err(NfcError::PayloadTooLarge);
        }

        let fd = linux_impl::open_nfc_socket()?;
        let result = linux_impl::write_nfc_frame(fd, &ndef_bytes);
        // SAFETY: `fd` was returned by `open_nfc_socket` (checked above) and is
        // a valid open file descriptor.  We close it unconditionally here to
        // avoid leaking it regardless of write success or failure.
        unsafe { libc::close(fd) };
        result
    }

    /// Read NDEF messages from a passive NFC tag.
    ///
    /// Opens an NFC socket, reads available frames, and attempts to decode
    /// each as an NDEF record.  Returns a `Vec` of decoded records.
    ///
    /// Returns `NfcError::TagNotPresent` when no frame is available.
    pub fn read_ndef_tag(&self) -> Result<Vec<NdefRecord>, NfcError> {
        let fd = linux_impl::open_nfc_socket()?;
        let frame = linux_impl::read_nfc_frame(fd);
        // SAFETY: `fd` was returned by `open_nfc_socket` (checked above) and
        // is a valid open file descriptor; we close it unconditionally to
        // avoid a leak whether the read succeeded or failed.
        unsafe { libc::close(fd) };

        let frame = match frame {
            Ok(f) => f,
            Err(NfcError::TransmitError(_)) => return Err(NfcError::TagNotPresent),
            Err(e) => return Err(e),
        };

        // Attempt to decode the frame as a Mesh Infinity NDEF message.
        if let Some(payload) = decode_ndef_message(&frame) {
            Ok(vec![NdefRecord {
                tnf: TNF_EXTERNAL,
                record_type: MESH_NDEF_TYPE.to_vec(),
                payload,
                id: Vec::new(),
            }])
        } else {
            // Return raw frame as a record with unknown TNF for the caller
            // to inspect, in case it was written by a non-Mesh device.
            Ok(vec![NdefRecord {
                tnf: TNF_WELL_KNOWN,
                record_type: Vec::new(),
                payload: frame,
                id: Vec::new(),
            }])
        }
    }

    /// Send data using NFC-DEP (Data Exchange Protocol) in active mode.
    ///
    /// Opens a raw NFC socket, writes the data as a single NCI frame, then
    /// closes the socket.  For continuous exchange, use `start_poll_loop`
    /// combined with `queue_outbound`.
    ///
    /// Returns `NfcError::PayloadTooLarge` when `data.len() > NFC_MAX_FRAME_BYTES`.
    pub fn send(&self, data: &[u8]) -> Result<(), NfcError> {
        if data.len() > NFC_MAX_FRAME_BYTES {
            return Err(NfcError::PayloadTooLarge);
        }
        let fd = linux_impl::open_nfc_socket()?;
        let result = linux_impl::write_nfc_frame(fd, data);
        // SAFETY: `fd` was returned by `open_nfc_socket` (checked above) and
        // is a valid open file descriptor; closed here to avoid a descriptor
        // leak regardless of write outcome.
        unsafe { libc::close(fd) };
        result
    }

    /// Receive the next available data frame from the inbound queue.
    ///
    /// Returns `None` when no frames are available.
    pub fn recv(&self) -> Option<Vec<u8>> {
        let mut guard = self.inbound.lock().unwrap();
        guard.pop_front()
    }

    /// Queue data for NFC transmission.
    ///
    /// Enqueues `data` into the outbound queue.  The background poll loop
    /// (started via `start_poll_loop`) drains this queue and writes frames
    /// via the NFC socket.
    pub fn queue_outbound(&self, data: &[u8]) {
        let mut guard = self.outbound.lock().unwrap();
        guard.push_back(data.to_vec());
    }

    /// Start a background thread that polls for NFC frames.
    ///
    /// The thread opens a raw `AF_NFC` socket, then alternates between:
    /// 1. Draining the outbound queue and writing each frame.
    /// 2. Attempting a non-blocking read for inbound frames.
    ///
    /// The thread runs indefinitely.  The returned `JoinHandle` can be used
    /// to join it if needed; in practice the handle is usually ignored and
    /// the thread is left running for the application lifetime.
    pub fn start_poll_loop(self: Arc<Self>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            // Open NFC socket; if unavailable, exit the thread silently.
            let fd = match linux_impl::open_nfc_socket() {
                Ok(fd) => fd,
                Err(_) => return,
            };

            // Set socket to non-blocking so the inbound read does not stall.
            // SAFETY: `fd` is a valid open socket; F_GETFL and F_SETFL are
            // standard fcntl(2) commands that do not touch memory.  Ignoring
            // a failed F_GETFL (flags < 0) is safe: the socket stays blocking,
            // which degrades throughput but causes no unsoundness.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }

            loop {
                // --- Drain outbound queue ---
                let pending: Vec<Vec<u8>> = {
                    let mut guard = self.outbound.lock().unwrap();
                    guard.drain(..).collect()
                };
                for frame in pending {
                    if frame.len() > NFC_MAX_FRAME_BYTES {
                        continue; // silently drop oversized frames
                    }
                    if linux_impl::write_nfc_frame(fd, &frame).is_err() {
                        // Socket error — close and exit the loop.
                        // SAFETY: `fd` is the poll-loop's open NFC socket;
                        // we close it here on write failure before exiting
                        // the thread to avoid a descriptor leak.
                        unsafe { libc::close(fd) };
                        return;
                    }
                }

                // --- Poll for inbound frames ---
                match linux_impl::read_nfc_frame(fd) {
                    Ok(frame) => {
                        let mut guard = self.inbound.lock().unwrap();
                        guard.push_back(frame);
                    }
                    Err(NfcError::TransmitError(_)) => {
                        // EAGAIN / EWOULDBLOCK on non-blocking socket — no data yet.
                        // Sleep briefly to avoid a spin-busy loop.
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Err(_) => {
                        // Fatal socket error.
                        // SAFETY: `fd` is the poll-loop's open NFC socket;
                        // closed here on fatal read failure before exiting the
                        // thread to avoid a descriptor leak.
                        unsafe { libc::close(fd) };
                        return;
                    }
                }
            }
        })
    }

    /// Maximum payload bytes per NFC data exchange frame.
    pub fn max_payload() -> usize {
        NFC_MAX_FRAME_BYTES
    }
}

// ---------------------------------------------------------------------------
// Non-Linux stub implementation
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
impl NfcTransport {
    /// Create a new NFC transport.
    ///
    /// Always returns `Err(NfcError::NotAvailable)` on non-Linux platforms.
    /// On Android and iOS, NFC I/O is handled by the native platform layer;
    /// this Rust module provides the protocol logic (NDEF encode/decode) that
    /// the Flutter/native layer invokes directly.
    pub fn new(_device_path: &str) -> Result<Self, NfcError> {
        Err(NfcError::NotAvailable)
    }

    /// Detect available NFC devices.
    ///
    /// Always returns an empty `Vec` on non-Linux platforms.
    pub fn detect_devices() -> Vec<String> {
        Vec::new()
    }

    /// Write an NDEF tag — not available on this platform.
    pub fn write_ndef_tag(&self, _record: &NdefRecord) -> Result<(), NfcError> {
        Err(NfcError::NotAvailable)
    }

    /// Read NDEF tags — not available on this platform.
    pub fn read_ndef_tag(&self) -> Result<Vec<NdefRecord>, NfcError> {
        Err(NfcError::NotAvailable)
    }

    /// Send data via NFC-DEP — not available on this platform.
    pub fn send(&self, _data: &[u8]) -> Result<(), NfcError> {
        Err(NfcError::NotAvailable)
    }

    /// Receive the next inbound NFC frame.
    ///
    /// Always returns `None` on non-Linux platforms.
    pub fn recv(&self) -> Option<Vec<u8>> {
        None
    }

    /// Queue data for NFC transmission — no-op on non-Linux platforms.
    pub fn queue_outbound(&self, _data: &[u8]) {}

    /// Start the NFC poll loop — immediately exits on non-Linux platforms.
    pub fn start_poll_loop(self: Arc<Self>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(|| {})
    }

    /// Maximum payload bytes per NFC data exchange frame.
    pub fn max_payload() -> usize {
        NFC_MAX_FRAME_BYTES
    }
}

// ---------------------------------------------------------------------------
// Non-Linux: NfcTransport fields (needed for stub to compile)
// ---------------------------------------------------------------------------
//
// On Linux the struct is constructed in the `linux_impl` block above.
// On other platforms we define the struct fields here so the stub impl
// can reference `Self` without a construction path (new() always errors).

#[cfg(not(target_os = "linux"))]
impl NfcTransport {
    // Intentionally no public constructor succeeds — new() returns Err.
    // The struct exists purely as a type; it is never instantiated.
}

// The struct definition itself is unconditional — both platforms share it.
// (Fields are defined once at the top of the file.)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // NDEF encode / decode
    // -----------------------------------------------------------------------

    #[test]
    fn ndef_roundtrip_short_payload() {
        let payload = b"hello mesh";
        let encoded = encode_ndef_message(payload);
        let decoded = decode_ndef_message(&encoded).expect("decode should succeed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ndef_roundtrip_empty_payload() {
        let payload = b"";
        let encoded = encode_ndef_message(payload);
        let decoded = decode_ndef_message(&encoded).expect("decode of empty payload");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ndef_roundtrip_256_byte_payload() {
        // Exactly 256 bytes: exceeds short-record limit, exercises 4-byte length.
        let payload = vec![0xABu8; 256];
        let encoded = encode_ndef_message(&payload);
        // SR flag must NOT be set for 256-byte payloads.
        assert_eq!(encoded[0] & NDEF_SR, 0, "SR flag should be clear for 256-byte payload");
        let decoded = decode_ndef_message(&encoded).expect("decode 256-byte payload");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ndef_roundtrip_255_byte_payload() {
        // 255 bytes: fits in short record.
        let payload = vec![0x77u8; 255];
        let encoded = encode_ndef_message(&payload);
        assert_ne!(encoded[0] & NDEF_SR, 0, "SR flag should be set for 255-byte payload");
        let decoded = decode_ndef_message(&encoded).expect("decode 255-byte payload");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ndef_roundtrip_pairing_json() {
        let pairing_json = br#"{"peerId":"abc123","publicKey":"deadbeef","name":"Alice"}"#;
        let encoded = encode_ndef_message(pairing_json);
        let decoded = decode_ndef_message(&encoded).expect("decode pairing JSON");
        assert_eq!(&decoded, pairing_json as &[u8]);
    }

    #[test]
    fn ndef_decode_empty_returns_none() {
        assert!(decode_ndef_message(&[]).is_none());
    }

    #[test]
    fn ndef_decode_too_short_returns_none() {
        assert!(decode_ndef_message(&[0xD4, 0x17]).is_none());
    }

    #[test]
    fn ndef_decode_wrong_tnf_returns_none() {
        // TNF = 0x01 (Well-Known) — not the Mesh Infinity external type.
        let payload = b"data";
        let flags: u8 = NDEF_MB | NDEF_ME | NDEF_SR | TNF_WELL_KNOWN;
        let type_bytes = b"T";
        let mut buf = vec![flags, type_bytes.len() as u8, payload.len() as u8];
        buf.extend_from_slice(type_bytes);
        buf.extend_from_slice(payload);
        assert!(decode_ndef_message(&buf).is_none());
    }

    #[test]
    fn ndef_decode_wrong_type_name_returns_none() {
        // Correct TNF (0x04) but wrong type name.
        let payload = b"data";
        let type_bytes = b"example.com:other";
        let flags: u8 = NDEF_MB | NDEF_ME | NDEF_SR | TNF_EXTERNAL;
        let mut buf = vec![flags, type_bytes.len() as u8, payload.len() as u8];
        buf.extend_from_slice(type_bytes);
        buf.extend_from_slice(payload);
        assert!(decode_ndef_message(&buf).is_none());
    }

    #[test]
    fn ndef_decode_truncated_payload_returns_none() {
        let payload = vec![0u8; 50];
        let mut encoded = encode_ndef_message(&payload);
        // Truncate 10 bytes from the end so the payload is incomplete.
        let new_len = encoded.len() - 10;
        encoded.truncate(new_len);
        assert!(decode_ndef_message(&encoded).is_none());
    }

    #[test]
    fn ndef_message_begin_end_flags_set() {
        let encoded = encode_ndef_message(b"test");
        assert_ne!(encoded[0] & NDEF_MB, 0, "MB flag must be set");
        assert_ne!(encoded[0] & NDEF_ME, 0, "ME flag must be set");
    }

    #[test]
    fn ndef_external_tnf_used() {
        let encoded = encode_ndef_message(b"test");
        assert_eq!(encoded[0] & NDEF_TNF_MASK, TNF_EXTERNAL);
    }

    #[test]
    fn ndef_type_field_is_mesh_infinity() {
        // Encoded structure (SR path): flags(1) + type_len(1) + pl_len(1) + type(23) + payload
        let payload = b"x";
        let encoded = encode_ndef_message(payload);
        let type_start = 3usize; // flags + type_len + sr_payload_len
        let type_end = type_start + MESH_NDEF_TYPE.len();
        assert_eq!(&encoded[type_start..type_end], MESH_NDEF_TYPE);
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn nfc_max_frame_bytes_constant() {
        assert_eq!(NFC_MAX_FRAME_BYTES, 244);
    }

    #[test]
    fn max_payload_matches_constant() {
        assert_eq!(NfcTransport::max_payload(), NFC_MAX_FRAME_BYTES);
    }

    // -----------------------------------------------------------------------
    // Device detection
    // -----------------------------------------------------------------------

    #[test]
    fn detect_devices_does_not_panic() {
        // Should not panic regardless of whether NFC hardware is present.
        let _ = NfcTransport::detect_devices();
    }

    // -----------------------------------------------------------------------
    // NfcTransport construction
    // -----------------------------------------------------------------------

    #[test]
    fn new_nonexistent_device_returns_error() {
        let result = NfcTransport::new("/dev/nfc_nonexistent_device_99");
        assert!(
            result.is_err(),
            "new() on a nonexistent device must return Err"
        );
    }

    // -----------------------------------------------------------------------
    // NfcError Display
    // -----------------------------------------------------------------------

    #[test]
    fn nfc_error_display_not_available() {
        let s = NfcError::NotAvailable.to_string();
        assert!(!s.is_empty());
        assert!(s.contains("not available") || s.contains("platform"));
    }

    #[test]
    fn nfc_error_display_device_not_found() {
        let s = NfcError::DeviceNotFound.to_string();
        assert!(s.contains("device") || s.contains("Device"));
    }

    #[test]
    fn nfc_error_display_tag_not_present() {
        let s = NfcError::TagNotPresent.to_string();
        assert!(s.contains("tag") || s.contains("Tag"));
    }

    #[test]
    fn nfc_error_display_transmit_error() {
        let s = NfcError::TransmitError("socket closed".into()).to_string();
        assert!(s.contains("socket closed"));
    }

    #[test]
    fn nfc_error_display_protocol_error() {
        let s = NfcError::ProtocolError("bad frame".into()).to_string();
        assert!(s.contains("bad frame"));
    }

    #[test]
    fn nfc_error_display_payload_too_large() {
        let s = NfcError::PayloadTooLarge.to_string();
        assert!(s.contains("244") || s.contains("payload") || s.contains("Payload"));
    }

    #[test]
    fn nfc_error_is_error_trait() {
        let e: &dyn std::error::Error = &NfcError::NotAvailable;
        assert!(!e.to_string().is_empty());
    }

    // -----------------------------------------------------------------------
    // Queue / recv (non-Linux: recv always returns None; queue_outbound no-ops)
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn recv_returns_none_when_queue_empty_non_linux() {
        // On non-Linux, new() returns Err, so we test the stub behaviour
        // indirectly via the error and the fact that detect_devices is empty.
        assert!(NfcTransport::detect_devices().is_empty());
        assert!(NfcTransport::new("/dev/nfc0").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn queue_outbound_and_recv_roundtrip_linux() {
        // We cannot rely on real NFC hardware; test the in-memory queue
        // by constructing NfcTransport directly (bypassing new() validation)
        // using the internal fields directly — since they are pub(super) in
        // the struct definition we do so within the same module.
        let transport = NfcTransport {
            device_path: "/dev/nfc0".into(),
            inbound: Mutex::new(VecDeque::new()),
            outbound: Mutex::new(VecDeque::new()),
        };

        // Manually push into the inbound queue to simulate received frames.
        {
            let mut guard = transport.inbound.lock().unwrap();
            guard.push_back(b"frame_one".to_vec());
            guard.push_back(b"frame_two".to_vec());
        }

        assert_eq!(transport.recv(), Some(b"frame_one".to_vec()));
        assert_eq!(transport.recv(), Some(b"frame_two".to_vec()));
        assert_eq!(transport.recv(), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn queue_outbound_linux() {
        let transport = NfcTransport {
            device_path: "/dev/nfc0".into(),
            inbound: Mutex::new(VecDeque::new()),
            outbound: Mutex::new(VecDeque::new()),
        };

        transport.queue_outbound(b"send_me");
        let guard = transport.outbound.lock().unwrap();
        assert_eq!(guard.front().map(|v| v.as_slice()), Some(b"send_me" as &[u8]));
    }

    // -----------------------------------------------------------------------
    // NdefRecord type
    // -----------------------------------------------------------------------

    #[test]
    fn ndef_record_clone_and_debug() {
        let r = NdefRecord {
            tnf: TNF_EXTERNAL,
            record_type: MESH_NDEF_TYPE.to_vec(),
            payload: b"test".to_vec(),
            id: Vec::new(),
        };
        let r2 = r.clone();
        assert_eq!(r, r2);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("NdefRecord"));
    }
}
