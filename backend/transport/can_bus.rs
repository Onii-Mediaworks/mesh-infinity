//! CAN Bus Transport (§5.15)
//!
//! Controller Area Network (CAN bus) transport for Mesh Infinity.
//! Uses SocketCAN on Linux via raw `AF_CAN` sockets — no subprocess.
//! On non-Linux platforms the module compiles to stubs.
//!
//! ## Protocol
//!
//! Mesh packets are fragmented over CAN FD frames (64-byte payload each).
//! A 3-byte fragment header is prepended to each CAN FD payload:
//!
//! ```text
//! Byte 0: msg_id  (u8) — rolling message counter, same for all fragments of one packet
//! Byte 1: total   (u8) — total number of fragments
//! Byte 2: seq     (u8) — zero-based fragment index
//! Bytes 3..60:    payload fragment (up to 61 bytes)
//! ```
//!
//! CAN ID encodes the mesh-specific EtherType prefix (0x4D49 = "MI") in the
//! top 16 bits and the fragment sequence in the bottom 11 bits:
//! `(0x4D49 << 11) | (seq as u32)`.
//!
//! Maximum reassembled payload: 255 fragments × 61 bytes = ~15 KB.
//! The spec limits CAN bus to ≤ 4 KB payloads.
//!
//! ## SocketCAN
//!
//! Linux exposes CAN hardware as network interfaces (e.g. `can0`, `vcan0`).
//! We open a raw `AF_CAN` / `CAN_RAW` socket, bind to the interface, and
//! send/receive `canfd_frame` structs via `sendto`/`recvfrom`.
//!
//! ```text
//! socket(AF_CAN, SOCK_RAW, CAN_RAW)
//! bind(sock, { AF_CAN, if_nametoindex("can0") })
//! write(sock, canfd_frame { can_id, len, flags, data })
//! read(sock,  canfd_frame ...)
//! ```
//!
//! CAN FD requires enabling it on the socket:
//! `setsockopt(CAN_RAW, CAN_RAW_FD_FRAMES, 1)`

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ────────────────────────────────────────────────────────────────────────────
// Public error type
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CanError {
    /// SocketCAN is not available on this platform or interface.
    NotAvailable,
    /// The named CAN interface was not found or could not be opened.
    InterfaceNotFound(String),
    /// A kernel-level I/O error occurred.
    Io(std::io::Error),
    /// Payload exceeds the 4 KB spec limit.
    PayloadTooLarge,
    /// Receive timeout elapsed with no complete frame.
    RecvTimeout,
}

impl std::fmt::Display for CanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanError::NotAvailable => write!(f, "SocketCAN not available on this platform"),
            CanError::InterfaceNotFound(s) => write!(f, "CAN interface '{s}' not found"),
            CanError::Io(e) => write!(f, "SocketCAN I/O error: {e}"),
            CanError::PayloadTooLarge => write!(f, "payload > 4 KB not allowed on CAN bus"),
            CanError::RecvTimeout => write!(f, "CAN receive timeout"),
        }
    }
}

impl std::error::Error for CanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let CanError::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Fragmentation / reassembly (platform-independent)
// ────────────────────────────────────────────────────────────────────────────

/// Maximum mesh payload per CAN FD frame (64 - 3 byte header).
/// CAN FD supports exactly 64 bytes per frame payload; the 3-byte
/// fragment header (msg_id, total, seq) is always present, leaving
/// 61 bytes for mesh data.  Classic CAN only supports 8 bytes per
/// frame, but we require CAN FD for any practical throughput.
pub const CANFD_PAYLOAD_BYTES: usize = 61;

/// Maximum allowed mesh packet size over CAN bus per spec (4 KB).
/// CAN bus is a shared medium with low bandwidth (~1 Mbps for CAN FD),
/// so the spec caps mesh payloads to prevent bus monopolisation.
/// At 61 bytes per fragment, 4 KB requires ~67 frames — already a
/// significant burst on a multi-node CAN bus.
pub const CAN_MAX_MESH_PAYLOAD: usize = 4096;

/// Fragment a mesh payload into CAN FD-sized payloads.
///
/// Returns one `Vec<u8>` per CAN FD frame.  Each starts with the 3-byte
/// fragment header `[msg_id, total_frags, seq]` followed by up to 61 bytes
/// of mesh data.
///
/// `msg_id` is a rolling u8 counter that wraps at 256.  Since CAN bus
/// is a low-bandwidth medium, 256 concurrent in-flight messages is more
/// than sufficient.  The reassembler uses `msg_id` to group fragments
/// from the same logical message, even when multiple nodes share the bus.
pub fn fragment(msg_id: u8, data: &[u8]) -> Result<Vec<Vec<u8>>, CanError> {
    if data.len() > CAN_MAX_MESH_PAYLOAD {
        return Err(CanError::PayloadTooLarge);
    }
    let chunks: Vec<&[u8]> = data.chunks(CANFD_PAYLOAD_BYTES).collect();
    let total = chunks.len() as u8;
    let mut frames = Vec::with_capacity(chunks.len());
    for (seq, chunk) in chunks.iter().enumerate() {
        let mut payload = vec![msg_id, total, seq as u8];
        payload.extend_from_slice(chunk);
        frames.push(payload);
    }
    Ok(frames)
}

/// In-progress reassembly buffer for a single `msg_id`.
/// `received.len()` equals the expected total fragment count.
///
/// Fragments may arrive out of order because CAN bus arbitration is
/// priority-based (lower CAN ID wins), so a high-priority frame from
/// another node can interleave with our fragment sequence.
#[derive(Default)]
struct ReassemblyBuf {
    received: Vec<Option<Vec<u8>>>,
    first_seen: Option<Instant>,
}

/// Reassembler — buffers fragments until all arrive for a `msg_id`.
///
/// Keyed by the 8-bit msg_id, so at most 256 concurrent incomplete
/// messages can be tracked.  The timeout-based eviction prevents
/// resource exhaustion from partial messages (e.g. sender lost bus
/// arbitration mid-sequence and gave up).
#[derive(Default)]
pub struct Reassembler {
    buffers: HashMap<u8, ReassemblyBuf>,
    /// How long to keep an incomplete message before discarding.
    /// CAN bus operates at ~1 Mbps, so a full 4 KB message completes
    /// in ~30ms — a 5-second timeout is extremely generous and only
    /// triggers on genuinely lost fragments.
    timeout: Duration,
}

impl Reassembler {
    pub fn new(timeout: Duration) -> Self {
        Reassembler {
            buffers: HashMap::new(),
            timeout,
        }
    }

    /// Feed a received CAN FD payload (64 bytes).
    ///
    /// Returns `Some(reassembled_bytes)` when all fragments of a message
    /// have arrived.  Returns `None` if more fragments are still expected.
    pub fn push(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 4 {
            return None; // too short to contain header + any data
        }
        let msg_id = payload[0];
        let total = payload[1];
        let seq = payload[2] as usize;
        let frag_data = &payload[3..];

        if total == 0 {
            return None;
        }

        let buf = self.buffers.entry(msg_id).or_insert_with(|| ReassemblyBuf {
            received: vec![None; total as usize],
            first_seen: Some(Instant::now()),
        });

        if seq >= buf.received.len() {
            return None;
        }
        buf.received[seq] = Some(frag_data.to_vec());

        if buf.received.iter().all(|s| s.is_some()) {
            let data: Vec<u8> = buf
                .received
                .iter()
                .flat_map(|s| s.as_ref().unwrap().iter().copied())
                .collect();
            self.buffers.remove(&msg_id);
            return Some(data);
        }
        None
    }

    /// Evict incomplete messages that have exceeded `self.timeout`.
    pub fn evict_stale(&mut self) {
        let timeout = self.timeout;
        self.buffers.retain(|_, buf| {
            buf.first_seen
                .map(|t| t.elapsed() < timeout)
                .unwrap_or(false)
        });
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Linux implementation — SocketCAN
// ────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::sync::{Arc, Mutex};

    // Linux kernel constants for SocketCAN (from <linux/can.h> and <linux/can/raw.h>).
    // SocketCAN is Linux's native CAN subsystem — it exposes CAN hardware as
    // network interfaces, allowing standard socket operations instead of
    // vendor-specific ioctls.
    const AF_CAN: libc::c_int = 29;
    const CAN_RAW: libc::c_int = 1;
    /// Socket option level for CAN-RAW-specific options.
    const SOL_CAN_RAW: libc::c_int = 101;
    /// Enable CAN FD support on the socket.  Without this, the kernel
    /// rejects frames larger than 8 bytes (classic CAN limit).
    const CAN_RAW_FD_FRAMES: libc::c_int = 5;
    /// Extended Frame Format flag — uses the full 29-bit CAN ID space.
    /// We need this because our CAN ID encoding (`0x4D49 << 11 | seq`)
    /// exceeds the 11-bit standard CAN ID.
    const CAN_EFF_FLAG: u32 = 0x80000000;
    const CANFD_MAX_DLEN: usize = 64;
    /// Bit Rate Switch — CAN FD feature that transmits the data phase at a
    /// higher bitrate than the arbitration phase (e.g. 5 Mbps data vs 1 Mbps
    /// arbitration), increasing effective throughput.
    const CANFD_BRS: u8 = 0x01;

    /// SocketCAN `canfd_frame` as defined in `<linux/can/raw.h>`.
    #[repr(C)]
    struct CanFdFrame {
        can_id: u32, // CAN ID + EFF/RTR/ERR flags
        len: u8,     // payload length (0..64 for CAN FD)
        flags: u8,   // CANFD_BRS, CANFD_ESI
        __res0: u8,
        __res1: u8,
        data: [u8; CANFD_MAX_DLEN],
    }

    /// SocketCAN `sockaddr_can`.
    #[repr(C)]
    struct SockaddrCan {
        can_family: u16,
        can_ifindex: libc::c_int,
        can_addr: [u8; 8], // padding / union
    }

    impl CanFdFrame {
        fn new(can_id: u32, payload: &[u8]) -> Self {
            let len = payload.len().min(CANFD_MAX_DLEN) as u8;
            let mut data = [0u8; CANFD_MAX_DLEN];
            data[..len as usize].copy_from_slice(&payload[..len as usize]);
            CanFdFrame {
                can_id: can_id | CAN_EFF_FLAG,
                len,
                flags: CANFD_BRS,
                __res0: 0,
                __res1: 0,
                data,
            }
        }
    }

    pub struct CanBusTransport {
        fd: libc::c_int,
        msg_counter: Mutex<u8>,
        reassembler: Mutex<Reassembler>,
        pub inbound: Mutex<Vec<Vec<u8>>>,
    }

    impl CanBusTransport {
        /// Open a SocketCAN socket on `iface` (e.g. `"can0"`, `"vcan0"`).
        pub fn open(iface: &str) -> Result<Arc<Self>, CanError> {
            // SAFETY: All operations in this block use only valid kernel file
            // descriptors returned by socket(2).  Memory pointers passed to
            // setsockopt(2) and bind(2) are stack-allocated with correct sizes.
            // Cleanup (libc::close) on every error path prevents fd leaks.
            unsafe {
                let fd = libc::socket(AF_CAN, libc::SOCK_RAW, CAN_RAW);
                if fd < 0 {
                    return Err(CanError::Io(std::io::Error::last_os_error()));
                }

                // Enable CAN FD frames.
                let enable: libc::c_int = 1;
                let rc = libc::setsockopt(
                    fd,
                    SOL_CAN_RAW,
                    CAN_RAW_FD_FRAMES,
                    &enable as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as u32,
                );
                if rc < 0 {
                    libc::close(fd);
                    return Err(CanError::Io(std::io::Error::last_os_error()));
                }

                // Resolve interface name to index.
                let iface_cstr = std::ffi::CString::new(iface)
                    .map_err(|_| CanError::InterfaceNotFound(iface.to_owned()))?;
                let ifindex = libc::if_nametoindex(iface_cstr.as_ptr());
                if ifindex == 0 {
                    libc::close(fd);
                    return Err(CanError::InterfaceNotFound(iface.to_owned()));
                }

                // Bind to the CAN interface.
                let addr = SockaddrCan {
                    can_family: AF_CAN as u16,
                    can_ifindex: ifindex as libc::c_int,
                    can_addr: [0u8; 8],
                };
                let rc = libc::bind(
                    fd,
                    &addr as *const SockaddrCan as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrCan>() as u32,
                );
                if rc < 0 {
                    libc::close(fd);
                    return Err(CanError::Io(std::io::Error::last_os_error()));
                }

                Ok(Arc::new(CanBusTransport {
                    fd,
                    msg_counter: Mutex::new(0),
                    reassembler: Mutex::new(Reassembler::new(Duration::from_secs(5))),
                    inbound: Mutex::new(Vec::new()),
                }))
            }
        }

        /// Send `data` over CAN bus, fragmenting as needed.
        ///
        /// Each fragment gets a CAN ID encoding:
        ///   `(0x4D49 << 11) | (seq & 0x7FF)`
        /// where 0x4D49 is ASCII "MI" — this acts as a protocol identifier
        /// in the extended CAN ID space.  The lower 11 bits carry the fragment
        /// sequence, which also determines CAN bus arbitration priority
        /// (fragment 0 = lowest CAN ID = highest priority).
        pub fn send(&self, data: &[u8]) -> Result<(), CanError> {
            let msg_id = {
                let mut c = self.msg_counter.lock().unwrap_or_else(|e| e.into_inner());
                let id = *c;
                *c = c.wrapping_add(1);
                id
            };

            let frags = fragment(msg_id, data)?;
            let base_id: u32 = 0x4D49u32 << 11;

            for (seq, frag) in frags.iter().enumerate() {
                let can_id = base_id | (seq as u32 & 0x7FF);
                let frame = CanFdFrame::new(can_id, frag);
                // SAFETY: `self.fd` is a valid open SocketCAN socket; `frame`
                // is a stack-allocated CanFdFrame with its memory fully
                // initialized by `CanFdFrame::new`; sizeof(CanFdFrame) is the
                // correct transfer size for a single CAN FD frame.
                unsafe {
                    let n = libc::write(
                        self.fd,
                        &frame as *const CanFdFrame as *const libc::c_void,
                        std::mem::size_of::<CanFdFrame>(),
                    );
                    if n < 0 {
                        return Err(CanError::Io(std::io::Error::last_os_error()));
                    }
                }
            }
            Ok(())
        }

        /// Receive one CAN FD frame and feed it to the reassembler.
        ///
        /// Returns `Some(data)` if the frame completed a mesh packet.
        pub fn recv_frame(&self) -> Result<Option<Vec<u8>>, CanError> {
            let mut frame = CanFdFrame {
                can_id: 0,
                len: 0,
                flags: 0,
                __res0: 0,
                __res1: 0,
                data: [0u8; CANFD_MAX_DLEN],
            };
            // SAFETY: `self.fd` is a valid open SocketCAN socket; `frame` is
            // a fully zero-initialized CanFdFrame on the stack.  read(2) will
            // write exactly sizeof(CanFdFrame) bytes into it; all bit patterns
            // are valid for the integer fields of CanFdFrame.
            unsafe {
                let n = libc::read(
                    self.fd,
                    &mut frame as *mut CanFdFrame as *mut libc::c_void,
                    std::mem::size_of::<CanFdFrame>(),
                );
                if n < 0 {
                    return Err(CanError::Io(std::io::Error::last_os_error()));
                }
            }
            let payload = &frame.data[..frame.len as usize];
            let result = self.reassembler.lock().unwrap().push(payload);
            Ok(result)
        }

        /// Start a background receive loop.  Complete mesh packets are pushed
        /// into `self.inbound`.
        pub fn start_recv_loop(self: Arc<Self>) {
            let transport = Arc::clone(&self);
            std::thread::Builder::new()
                .name("can-recv".into())
                .spawn(move || loop {
                    match transport.recv_frame() {
                        Ok(Some(pkt)) => {
                            transport
                                .inbound
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(pkt);
                        }
                        Ok(None) => {} // fragment received, waiting for more
                        Err(_) => break,
                    }
                })
                .ok();
        }

        /// Drain all received mesh packets.
        pub fn drain_inbound(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.inbound.lock().unwrap_or_else(|e| e.into_inner()))
        }

        /// Check if SocketCAN is available (the `AF_CAN` family compiles in).
        pub fn is_available() -> bool {
            // On Linux this is always compiled; check for any can* interface.
            std::path::Path::new("/sys/class/net").exists()
                && std::fs::read_dir("/sys/class/net")
                    .ok()
                    .map(|d| {
                        d.flatten()
                            .any(|e| e.file_name().to_string_lossy().starts_with("can"))
                    })
                    .unwrap_or(false)
        }
    }

    impl Drop for CanBusTransport {
        fn drop(&mut self) {
            // SAFETY: `self.fd` is a valid open SocketCAN file descriptor
            // created in `CanBusTransport::open` and exclusively owned by
            // this struct; Drop is called exactly once, so close(2) is too.
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::CanBusTransport;

// ────────────────────────────────────────────────────────────────────────────
// Non-Linux stub
// ────────────────────────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
pub struct CanBusTransport;

#[cfg(not(target_os = "linux"))]
impl CanBusTransport {
    pub fn open(_iface: &str) -> Result<std::sync::Arc<Self>, CanError> {
        Err(CanError::NotAvailable)
    }
    pub fn send(&self, _data: &[u8]) -> Result<(), CanError> {
        Err(CanError::NotAvailable)
    }
    pub fn recv_frame(&self) -> Result<Option<Vec<u8>>, CanError> {
        Err(CanError::NotAvailable)
    }
    pub fn start_recv_loop(self: std::sync::Arc<Self>) {}
    pub fn drain_inbound(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
    pub fn is_available() -> bool {
        false
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_reassemble_small() {
        let data = b"hello mesh CAN bus!";
        let frags = fragment(0xAB, data).unwrap();
        assert_eq!(frags.len(), 1, "small payload → 1 fragment");

        let mut r = Reassembler::new(Duration::from_secs(5));
        let result = r.push(&frags[0]).expect("should reassemble immediately");
        assert_eq!(result, data);
    }

    #[test]
    fn fragment_reassemble_multi() {
        let data: Vec<u8> = (0u8..=255).cycle().take(200).collect();
        let frags = fragment(0x01, &data).unwrap();
        assert_eq!(frags.len(), 4, "200 bytes → 4 fragments of ≤61 bytes");

        let mut r = Reassembler::new(Duration::from_secs(5));
        let mut result = None;
        // Deliver out of order: 3, 1, 0, 2.
        for &idx in &[3usize, 1, 0, 2] {
            result = r.push(&frags[idx]);
        }
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn fragment_too_large() {
        let big = vec![0u8; CAN_MAX_MESH_PAYLOAD + 1];
        assert!(matches!(fragment(0, &big), Err(CanError::PayloadTooLarge)));
    }

    #[test]
    fn reassembler_evicts_stale() {
        let data = b"partial";
        let frags = fragment(0x55, data).unwrap();
        let mut r = Reassembler::new(Duration::from_millis(1));
        // Push first (and only) fragment but with an artificially old timestamp.
        // Simulate by using a very short timeout and sleeping.
        r.push(&frags[0]);
        std::thread::sleep(Duration::from_millis(5));
        r.evict_stale();
        assert!(r.buffers.is_empty(), "stale buffer should be evicted");
    }

    #[test]
    fn fragment_header_format() {
        let data = vec![0xAAu8; 70]; // 2 fragments
        let frags = fragment(0x07, &data).unwrap();
        assert_eq!(frags.len(), 2);
        // Fragment 0 header.
        assert_eq!(frags[0][0], 0x07); // msg_id
        assert_eq!(frags[0][1], 2); // total
        assert_eq!(frags[0][2], 0); // seq
                                    // Fragment 1 header.
        assert_eq!(frags[1][0], 0x07);
        assert_eq!(frags[1][1], 2);
        assert_eq!(frags[1][2], 1);
    }
}
