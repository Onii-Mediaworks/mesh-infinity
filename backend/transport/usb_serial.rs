//! USB Serial Transport (§5.13)
//!
//! This module implements a USB serial (UART over USB) transport for Mesh
//! Infinity.  It allows two devices to exchange encrypted mesh packets over
//! a physical USB cable, using the host OS serial port interface together with
//! SLIP framing to recover discrete packets from the raw byte stream.
//!
//! # Use Cases
//!
//! - **Air-gapped data transfer** — two computers connected by a USB-serial
//!   cable with all network interfaces disabled.
//! - **Device-to-device / IoT** — microcontrollers or single-board computers
//!   (Raspberry Pi, Arduino, ESP32) that expose a CDC-ACM serial port.
//! - **Emergency channel** — a last-resort path when every wireless transport
//!   (Tor, I2P, BLE, RF) is unavailable or blocked.
//!
//! # Wire Framing (SLIP — RFC 1055)
//!
//! A serial port is a raw byte stream with no inherent packet boundaries.
//! SLIP (Serial Line Internet Protocol) provides minimal framing:
//!
//! ```text
//! 0xC0  [escaped payload bytes …]  0xC0
//! ```
//!
//! Two special sequences escape reserved bytes in the payload:
//!
//! | Payload byte | Transmitted as |
//! |:---:|:---:|
//! | `0xC0` (END) | `0xDB 0xDC` |
//! | `0xDB` (ESC) | `0xDB 0xDD` |
//!
//! All other bytes are transmitted unchanged.  This encoding is implemented
//! by [`slip_encode`] / [`slip_decode`] and the stateful [`SlipDecoder`].
//!
//! # Platform Serial Port Interface
//!
//! ## Linux / macOS (Unix)
//!
//! Serial ports are opened as regular file descriptors with `O_RDWR |
//! O_NOCTTY | O_NONBLOCK`.  The port is then configured in raw 8N1 mode with
//! a 100 ms read timeout via the `termios` API (`cfmakeraw`, `cfsetispeed`,
//! `cfsetospeed`, `tcsetattr`).  The module uses the `libc` crate for all
//! termios calls so it compiles without any external serial-port crate.
//!
//! Ports are discovered by scanning well-known device paths:
//! - Linux: `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/ttyS0`–`/dev/ttyS7`
//! - macOS: `/dev/tty.usb*`
//!
//! ## Windows
//!
//! `list_ports()` probes `COM1`–`COM9` by attempting to open each path.
//! Full read/write on Windows requires `CreateFile` / `SetCommState`; that
//! path is marked `unimplemented!()` with a clear error so Windows users see
//! a helpful message rather than a silent failure.
//!
//! # Thread Model
//!
//! [`UsbSerialTransport::start_read_loop`] spawns a background OS thread.
//! The thread feeds raw bytes from the serial port into a [`SlipDecoder`] and
//! pushes complete decoded frames into the shared `inbound` queue.  The
//! calling thread can then drain frames with [`UsbSerialTransport::drain_inbound`].
//!
//! # Spec Reference
//!
//! §5.13 — USB Serial transport.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ────────────────────────────────────────────────────────────────────────────
// SLIP constants
// ────────────────────────────────────────────────────────────────────────────

/// SLIP frame delimiter byte (0xC0).
///
/// Marks the beginning and end of every SLIP-framed packet.  Also used as
/// a "flush" signal: transmitting an extra END before a packet ensures the
/// receiver discards any accumulated noise from a prior incomplete frame.
pub const SLIP_END: u8 = 0xC0;

/// SLIP escape byte (0xDB).
///
/// Precedes an escaped byte whenever `SLIP_END` or `SLIP_ESC` appears in the
/// payload.  The byte following `SLIP_ESC` determines which original byte is
/// restored.
pub const SLIP_ESC: u8 = 0xDB;

/// SLIP escaped-END byte (0xDC).
///
/// When the receiver sees `SLIP_ESC` followed by `SLIP_ESC_END`, it decodes
/// the pair as a literal `0xC0` in the payload.
pub const SLIP_ESC_END: u8 = 0xDC;

/// SLIP escaped-ESC byte (0xDD).
///
/// When the receiver sees `SLIP_ESC` followed by `SLIP_ESC_ESC`, it decodes
/// the pair as a literal `0xDB` in the payload.
pub const SLIP_ESC_ESC: u8 = 0xDD;

// ────────────────────────────────────────────────────────────────────────────
// Transport constants
// ────────────────────────────────────────────────────────────────────────────

/// Maximum SLIP payload size accepted by this implementation (65 535 bytes).
///
/// Frames larger than this are rejected by [`slip_decode`] and
/// [`UsbSerialTransport::send`] to protect against runaway allocations.
pub const USB_SERIAL_MAX_FRAME: usize = 65_535;

/// Default baud rate used when opening a port without an explicit rate.
///
/// 115 200 bps is universally supported by USB CDC-ACM adapters and provides
/// ~11 KB/s throughput — adequate for encrypted mesh control traffic.
pub const USB_SERIAL_BAUD_DEFAULT: u32 = 115_200;

// ────────────────────────────────────────────────────────────────────────────
// SLIP encoding
// ────────────────────────────────────────────────────────────────────────────

/// Encode `data` using SLIP framing.
///
/// The output has the form:
/// ```text
/// SLIP_END  [escaped payload bytes]  SLIP_END
/// ```
///
/// A leading `SLIP_END` flushes any garbage that may have accumulated in the
/// receiver's buffer before the current packet.
///
/// # Examples
///
/// ```
/// use mesh_infinity::transport::usb_serial::{slip_encode, SLIP_END};
/// let encoded = slip_encode(b"hello");
/// assert_eq!(encoded[0], SLIP_END);
/// assert_eq!(*encoded.last().unwrap(), SLIP_END);
/// ```
pub fn slip_encode(data: &[u8]) -> Vec<u8> {
    // Worst case: every byte is escaped → 2× payload + 2 END markers.
    let mut out = Vec::with_capacity(data.len() * 2 + 2);
    out.push(SLIP_END);
    for &b in data {
        match b {
            SLIP_END => {
                out.push(SLIP_ESC);
                out.push(SLIP_ESC_END);
            }
            SLIP_ESC => {
                out.push(SLIP_ESC);
                out.push(SLIP_ESC_ESC);
            }
            other => out.push(other),
        }
    }
    out.push(SLIP_END);
    out
}

/// Decode a single SLIP-framed packet.
///
/// `frame` must include the surrounding `SLIP_END` markers (i.e. the raw
/// bytes as received from the wire, including the delimiters).  The function
/// strips the delimiters, un-escapes the payload, and returns the original
/// data.
///
/// Returns `None` if:
/// - `frame` is empty or contains no `SLIP_END` markers.
/// - An escape byte (`0xDB`) at the end of the frame is not followed by a
///   valid escape code.
/// - The decoded payload exceeds [`USB_SERIAL_MAX_FRAME`] bytes.
///
/// # Examples
///
/// ```
/// use mesh_infinity::transport::usb_serial::{slip_encode, slip_decode};
/// let original = b"test payload";
/// let encoded  = slip_encode(original);
/// let decoded  = slip_decode(&encoded).unwrap();
/// assert_eq!(decoded, original);
/// ```
pub fn slip_decode(frame: &[u8]) -> Option<Vec<u8>> {
    // Strip leading and trailing END bytes.
    let inner = frame
        .iter()
        .position(|&b| b == SLIP_END)
        .and_then(|start| {
            frame[start + 1..]
                .iter()
                .position(|&b| b == SLIP_END)
                .map(|rel| &frame[start + 1..start + 1 + rel])
        })?;

    let mut out = Vec::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        match inner[i] {
            SLIP_ESC => {
                i += 1;
                match *inner.get(i)? {
                    SLIP_ESC_END => out.push(SLIP_END),
                    SLIP_ESC_ESC => out.push(SLIP_ESC),
                    _ => return None, // Invalid escape sequence.
                }
            }
            b => out.push(b),
        }
        i += 1;
    }

    if out.len() > USB_SERIAL_MAX_FRAME {
        return None;
    }

    Some(out)
}

// ────────────────────────────────────────────────────────────────────────────
// Stateful SLIP decoder
// ────────────────────────────────────────────────────────────────────────────

/// Stateful SLIP decoder for streaming / fragmented input.
///
/// Unlike [`slip_decode`], which requires a complete framed packet,
/// `SlipDecoder` accumulates bytes fed to it in arbitrary chunks (as delivered
/// by `read()` syscalls) and emits complete decoded frames whenever a
/// `SLIP_END` delimiter is encountered.
///
/// # Example
///
/// ```
/// use mesh_infinity::transport::usb_serial::{SlipDecoder, slip_encode};
/// let payload = b"streaming test";
/// let encoded = slip_encode(payload);
///
/// let mut dec = SlipDecoder::new();
/// // Feed the frame in two halves to simulate fragmented reads.
/// let mid = encoded.len() / 2;
/// let mut frames = dec.feed(&encoded[..mid]);
/// frames.extend(dec.feed(&encoded[mid..]));
///
/// assert_eq!(frames.len(), 1);
/// assert_eq!(frames[0], payload);
/// ```
pub struct SlipDecoder {
    /// Bytes accumulated for the current in-progress frame.
    buf: Vec<u8>,
    /// Whether the previous byte was a `SLIP_ESC` awaiting its partner.
    escaped: bool,
}

impl SlipDecoder {
    /// Create a new, empty `SlipDecoder`.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            escaped: false,
        }
    }

    /// Feed `bytes` into the decoder.
    ///
    /// Returns a (possibly empty) vector of complete decoded frames extracted
    /// from the input.  Any bytes belonging to a partial frame are retained
    /// in the internal buffer and will be completed by subsequent `feed`
    /// calls.
    ///
    /// Frames that exceed [`USB_SERIAL_MAX_FRAME`] bytes after decoding are
    /// silently dropped and the decoder resets for the next frame.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();

        for &b in bytes {
            if self.escaped {
                self.escaped = false;
                match b {
                    SLIP_ESC_END => self.buf.push(SLIP_END),
                    SLIP_ESC_ESC => self.buf.push(SLIP_ESC),
                    _ => {
                        // Invalid escape: discard current partial frame and
                        // reset, treating this byte as the start of a fresh
                        // frame boundary search.
                        self.buf.clear();
                        if b == SLIP_END {
                            // This END could be the start of the next frame;
                            // just reset state (buf is already clear).
                        }
                    }
                }
                continue;
            }

            match b {
                SLIP_END => {
                    // A SLIP_END delimits a frame.  Non-empty buffers contain
                    // a complete payload; empty buffers mean two consecutive
                    // END bytes (used as a "flush" prefix) — discard silently.
                    if !self.buf.is_empty() {
                        if self.buf.len() <= USB_SERIAL_MAX_FRAME {
                            frames.push(self.buf.clone());
                        }
                        self.buf.clear();
                    }
                }
                SLIP_ESC => {
                    self.escaped = true;
                }
                other => {
                    self.buf.push(other);
                }
            }
        }

        frames
    }
}

impl Default for SlipDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

/// Errors returned by [`UsbSerialTransport`] operations.
#[derive(Debug)]
pub enum UsbSerialError {
    /// No serial port device found at the requested path.
    NotFound(String),
    /// The process does not have permission to open the serial port.
    ///
    /// On Linux, add the user to the `dialout` group (`usermod -aG dialout
    /// $USER`) or grant read/write access to the device node.
    PermissionDenied(String),
    /// An underlying I/O error from the OS.
    IoError(std::io::Error),
    /// The payload exceeds [`USB_SERIAL_MAX_FRAME`] bytes and cannot be sent.
    FrameTooLarge,
    /// The serial port has not been opened yet.
    PortNotOpen,
}

impl std::fmt::Display for UsbSerialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsbSerialError::NotFound(port) => {
                write!(f, "serial port not found: {port}")
            }
            UsbSerialError::PermissionDenied(port) => {
                write!(
                    f,
                    "permission denied opening serial port {port} \
                     (try: sudo usermod -aG dialout $USER)"
                )
            }
            UsbSerialError::IoError(e) => write!(f, "serial port I/O error: {e}"),
            UsbSerialError::FrameTooLarge => write!(
                f,
                "payload exceeds maximum SLIP frame size ({USB_SERIAL_MAX_FRAME} bytes)"
            ),
            UsbSerialError::PortNotOpen => write!(f, "serial port is not open"),
        }
    }
}

impl std::error::Error for UsbSerialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UsbSerialError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Unix termios helper
// ────────────────────────────────────────────────────────────────────────────

/// Configure a serial port file descriptor for raw 8N1 operation.
///
/// Sets:
/// - Raw mode (no echo, no line discipline, no signal generation).
/// - The requested baud rate (fallback: 115 200 bps).
/// - 8 data bits, no parity, 1 stop bit (8N1).
/// - Non-blocking read with 100 ms timeout (`VTIME=1`, `VMIN=0`).
///
/// Called immediately after `open(2)` on Unix before the fd is stored in
/// [`UsbSerialTransport`].
#[cfg(unix)]
fn configure_port(fd: libc::c_int, baud: u32) -> Result<(), UsbSerialError> {
    use libc::*;

    let speed = match baud {
        9_600 => B9600,
        19_200 => B19200,
        38_400 => B38400,
        57_600 => B57600,
        115_200 => B115200,
        _ => B115200,
    };

    // SAFETY: termios is a plain-old-data struct; zeroing is safe and matches
    // the documented approach before calling tcgetattr.
    let mut tty: termios = unsafe { std::mem::zeroed() };

    // Read current attributes so we preserve any hardware-specific flags the
    // driver requires.
    // SAFETY: `fd` is a valid open file descriptor and `tty` is a correctly
    // sized, stack-allocated termios struct; tcgetattr writes exactly
    // sizeof(termios) bytes into it.
    if unsafe { tcgetattr(fd, &mut tty) } != 0 {
        return Err(UsbSerialError::IoError(std::io::Error::last_os_error()));
    }

    // Switch to raw mode: disables input processing, echo, line discipline,
    // signal generation, software flow control, and output processing.
    // SAFETY: `tty` was successfully populated by tcgetattr above; cfmakeraw
    // only mutates the struct in-place, taking an exclusive mutable reference.
    unsafe { cfmakeraw(&mut tty) };

    // Apply the requested baud rate to both input and output.
    // SAFETY: `tty` is a valid termios struct; cfsetispeed/cfsetospeed mutate
    // it in-place and return 0 on success or -1 on an invalid speed constant —
    // B115200 and the other Bxxx constants are all defined by POSIX.
    unsafe { cfsetispeed(&mut tty, speed) };
    unsafe { cfsetospeed(&mut tty, speed) };

    // VTIME=1 → 100 ms read timeout (units are 1/10 s).
    // VMIN=0  → return immediately even if no bytes are available.
    tty.c_cc[VTIME] = 1;
    tty.c_cc[VMIN] = 0;

    // SAFETY: `fd` is a valid open fd, `tty` is a well-formed termios struct
    // (just written by tcgetattr and modified above), and TCSANOW is a valid
    // optional_actions constant.
    if unsafe { tcsetattr(fd, TCSANOW, &tty) } != 0 {
        return Err(UsbSerialError::IoError(std::io::Error::last_os_error()));
    }

    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// UsbSerialTransport
// ────────────────────────────────────────────────────────────────────────────

/// USB serial transport.
///
/// Wraps a host serial port device node (e.g. `/dev/ttyUSB0` on Linux,
/// `/dev/tty.usbmodem1` on macOS, `COM3` on Windows) and provides a
/// SLIP-framed packet channel on top of the raw byte stream.
///
/// # Thread Safety
///
/// All state is protected by `Mutex`, so `UsbSerialTransport` is `Send + Sync`
/// and may be shared across threads via `Arc<UsbSerialTransport>`.  The
/// [`start_read_loop`] method consumes an `Arc<Self>` so the background thread
/// and the caller can share the same instance.
///
/// [`start_read_loop`]: UsbSerialTransport::start_read_loop
pub struct UsbSerialTransport {
    /// OS device path, e.g. `/dev/ttyUSB0` or `COM3`.
    port_name: String,
    /// Configured baud rate (symbols per second).
    baud_rate: u32,
    /// Inbound queue: decoded SLIP frames waiting to be consumed.
    inbound: Mutex<VecDeque<Vec<u8>>>,
    /// Outbound queue: frames waiting to be sent by the write half.
    outbound: Mutex<VecDeque<Vec<u8>>>,
    /// Raw file descriptor for the open serial port (Unix only).
    ///
    /// `None` while the port is closed.
    #[cfg(unix)]
    fd: Mutex<Option<libc::c_int>>,
    /// Whether the port is currently open.
    ///
    /// Used on all platforms so `is_open()` compiles on Windows too.
    open_flag: std::sync::atomic::AtomicBool,
}

impl UsbSerialTransport {
    // ── Private constructor (platform-specific open is below) ────────────────

    /// Build a `UsbSerialTransport` from an already-opened Unix fd.
    #[cfg(unix)]
    fn from_fd(port_name: &str, baud_rate: u32, fd: libc::c_int) -> Self {
        Self {
            port_name: port_name.to_owned(),
            baud_rate,
            inbound: Mutex::new(VecDeque::new()),
            outbound: Mutex::new(VecDeque::new()),
            fd: Mutex::new(Some(fd)),
            open_flag: std::sync::atomic::AtomicBool::new(true),
        }
    }

    // ── Port enumeration ──────────────────────────────────────────────────────

    /// List available serial ports on the current platform.
    ///
    /// The returned strings are OS device paths suitable for passing directly
    /// to [`UsbSerialTransport::open`].
    ///
    /// | Platform | Candidates checked |
    /// |---|---|
    /// | Linux | `/dev/ttyUSB0-9`, `/dev/ttyACM0-9`, `/dev/ttyS0-7` |
    /// | macOS | `/dev/tty.usb*` (glob via `/dev` readdir) |
    /// | Windows | `COM1`–`COM9` (attempts to open each, closes on success) |
    ///
    /// This function never panics.  If the OS cannot be determined or device
    /// scanning fails, an empty vector is returned.
    pub fn list_ports() -> Vec<String> {
        #[cfg(target_os = "linux")]
        {
            Self::list_ports_linux()
        }
        #[cfg(target_os = "macos")]
        {
            Self::list_ports_macos()
        }
        #[cfg(windows)]
        {
            Self::list_ports_windows()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            Vec::new()
        }
    }

    #[cfg(target_os = "linux")]
    fn list_ports_linux() -> Vec<String> {
        let mut ports = Vec::new();

        // USB-serial adapters (FTDI, CH340, CP210x, etc.)
        for i in 0..10 {
            let p = format!("/dev/ttyUSB{i}");
            if std::path::Path::new(&p).exists() {
                ports.push(p);
            }
        }
        // CDC-ACM devices (Arduino, Teensy, STM32 via USB CDC)
        for i in 0..10 {
            let p = format!("/dev/ttyACM{i}");
            if std::path::Path::new(&p).exists() {
                ports.push(p);
            }
        }
        // Built-in UARTs (useful for Raspberry Pi UART0/UART1)
        for i in 0..8 {
            let p = format!("/dev/ttyS{i}");
            if std::path::Path::new(&p).exists() {
                ports.push(p);
            }
        }

        ports
    }

    #[cfg(target_os = "macos")]
    fn list_ports_macos() -> Vec<String> {
        let mut ports = Vec::new();

        // macOS USB serial devices appear as /dev/tty.usbmodem*, /dev/tty.usbserial*, etc.
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("tty.usb") || name_str.starts_with("tty.SLAB")
                    || name_str.starts_with("tty.wchusbserial")
                {
                    ports.push(format!("/dev/{name_str}"));
                }
            }
        }
        ports.sort();
        ports
    }

    #[cfg(windows)]
    fn list_ports_windows() -> Vec<String> {
        let mut ports = Vec::new();

        // Probe COM1–COM9 by attempting to open each one.  We use the
        // `\\.\COMn` form which works for COM ports with numbers > 9 too.
        for i in 1..=9 {
            let path = format!("\\\\.\\COM{i}");
            use std::os::windows::ffi::OsStrExt;
            let wide: Vec<u16> = std::ffi::OsStr::new(&path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: CreateFileW is a standard Win32 call; the wide string is
            // properly NUL-terminated above.
            let handle = unsafe {
                windows_sys::Win32::Storage::FileSystem::CreateFileW(
                    wide.as_ptr(),
                    windows_sys::Win32::Foundation::GENERIC_READ
                        | windows_sys::Win32::Foundation::GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            const INVALID_HANDLE_VALUE: isize = -1_isize;
            if handle != INVALID_HANDLE_VALUE as _ {
                // SAFETY: `handle` is a valid Win32 HANDLE returned by
                // CreateFileW above and not equal to INVALID_HANDLE_VALUE;
                // CloseHandle is the required cleanup call for such handles.
                unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
                ports.push(format!("COM{i}"));
            }
        }

        ports
    }

    // ── Opening / closing ─────────────────────────────────────────────────────

    /// Open `port_name` at the given `baud_rate`.
    ///
    /// On success returns an [`UsbSerialTransport`] with the port already
    /// configured in raw 8N1 mode.
    ///
    /// # Errors
    ///
    /// | Error | Cause |
    /// |---|---|
    /// | [`UsbSerialError::NotFound`] | Device node does not exist |
    /// | [`UsbSerialError::PermissionDenied`] | Process lacks read/write access |
    /// | [`UsbSerialError::IoError`] | Any other OS error from `open(2)` / `termios` |
    pub fn open(port_name: &str, baud_rate: u32) -> Result<Self, UsbSerialError> {
        #[cfg(unix)]
        {
            Self::open_unix(port_name, baud_rate)
        }
        #[cfg(windows)]
        {
            let _ = (port_name, baud_rate);
            unimplemented!(
                "USB serial read/write on Windows requires CreateFile/SetCommState; \
                 only port enumeration (list_ports) is implemented for Windows in this build."
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(UsbSerialError::NotFound(format!(
                "USB serial ports are not supported on this platform (port: {port_name})"
            )))
        }
    }

    #[cfg(unix)]
    fn open_unix(port_name: &str, baud_rate: u32) -> Result<Self, UsbSerialError> {
        use libc::{O_NOCTTY, O_NONBLOCK, O_RDWR};
        use std::ffi::CString;

        let cpath = CString::new(port_name).map_err(|_| {
            UsbSerialError::NotFound(format!("invalid port name: {port_name}"))
        })?;

        // SAFETY: open(2) with a valid NUL-terminated path.
        let fd = unsafe { libc::open(cpath.as_ptr(), O_RDWR | O_NOCTTY | O_NONBLOCK) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(match err.kind() {
                std::io::ErrorKind::NotFound => {
                    UsbSerialError::NotFound(port_name.to_owned())
                }
                std::io::ErrorKind::PermissionDenied => {
                    UsbSerialError::PermissionDenied(port_name.to_owned())
                }
                _ => UsbSerialError::IoError(err),
            });
        }

        configure_port(fd, baud_rate)?;

        Ok(Self::from_fd(port_name, baud_rate, fd))
    }

    /// Close the serial port and release the file descriptor.
    ///
    /// Safe to call multiple times; subsequent calls are no-ops.
    pub fn close(&self) {
        use std::sync::atomic::Ordering;

        #[cfg(unix)]
        {
            let mut guard = self.fd.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(fd) = guard.take() {
                // SAFETY: we own the fd and have just set the guard to None,
                // so no other code path can close it again.
                unsafe { libc::close(fd) };
            }
        }

        self.open_flag.store(false, Ordering::Release);
    }

    /// Returns `true` if the serial port is currently open.
    pub fn is_open(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.open_flag.load(Ordering::Acquire)
    }

    // ── Sending ───────────────────────────────────────────────────────────────

    /// SLIP-encode `data` and write it to the serial port immediately.
    ///
    /// Blocks until all bytes have been written or an error occurs.
    ///
    /// # Errors
    ///
    /// - [`UsbSerialError::PortNotOpen`] — the port is not open.
    /// - [`UsbSerialError::FrameTooLarge`] — `data.len() > USB_SERIAL_MAX_FRAME`.
    /// - [`UsbSerialError::IoError`] — the underlying `write(2)` failed.
    pub fn send(&self, data: &[u8]) -> Result<(), UsbSerialError> {
        if !self.is_open() {
            return Err(UsbSerialError::PortNotOpen);
        }
        if data.len() > USB_SERIAL_MAX_FRAME {
            return Err(UsbSerialError::FrameTooLarge);
        }

        let frame = slip_encode(data);

        #[cfg(unix)]
        {
            let guard = self.fd.lock().unwrap_or_else(|e| e.into_inner());
            let fd = guard.as_ref().copied().ok_or(UsbSerialError::PortNotOpen)?;
            write_all_fd(fd, &frame)?;
        }
        #[cfg(not(unix))]
        {
            let _ = frame;
            return Err(UsbSerialError::PortNotOpen);
        }

        Ok(())
    }

    /// Enqueue `data` for later transmission.
    ///
    /// Frames placed here can be drained and sent by a writer thread.  This
    /// is a convenience helper for producer-consumer architectures; the
    /// current implementation does **not** automatically drain the outbound
    /// queue — the caller is responsible for draining and calling [`send`].
    ///
    /// [`send`]: UsbSerialTransport::send
    pub fn queue_outbound(&self, data: &[u8]) {
        let mut q = self.outbound.lock().unwrap_or_else(|e| e.into_inner());
        q.push_back(data.to_vec());
    }

    // ── Background read loop ─────────────────────────────────────────────────

    /// Spawn a background OS thread that continuously reads from the serial
    /// port and pushes decoded SLIP frames into the inbound queue.
    ///
    /// The thread exits when [`close`] is called (the fd is closed, causing
    /// `read(2)` to return an error or 0 bytes).
    ///
    /// Returns the `JoinHandle` so the caller can optionally `join()` it on
    /// shutdown.
    ///
    /// [`close`]: UsbSerialTransport::close
    pub fn start_read_loop(self: Arc<Self>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            self.run_read_loop();
        })
    }

    #[cfg(unix)]
    fn run_read_loop(&self) {
        let mut decoder = SlipDecoder::new();
        let mut buf = [0u8; 4096];

        loop {
            // Check whether the transport has been closed before each read.
            if !self.is_open() {
                break;
            }

            let fd = {
                let guard = self.fd.lock().unwrap_or_else(|e| e.into_inner());
                match *guard {
                    Some(fd) => fd,
                    None => break,
                }
            };

            // SAFETY: buf is valid for `buf.len()` bytes; fd is open (we just
            // checked).  read(2) may return -1 on EAGAIN/EWOULDBLOCK (the fd
            // is non-blocking) — we treat that as "no data yet".
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

            if n < 0 {
                let err = std::io::Error::last_os_error();
                match err.kind() {
                    // Non-blocking fd: no data available yet.
                    std::io::ErrorKind::WouldBlock => {
                        // VTIME=1 gives a 100 ms timeout; on EAGAIN just spin.
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    _ => {
                        // Real error (device disconnected, etc.) — stop loop.
                        break;
                    }
                }
            } else if n == 0 {
                // EOF / device closed.
                break;
            } else {
                let bytes = &buf[..n as usize];
                let frames = decoder.feed(bytes);
                if !frames.is_empty() {
                    let mut q = self.inbound.lock().unwrap_or_else(|e| e.into_inner());
                    for frame in frames {
                        q.push_back(frame);
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    fn run_read_loop(&self) {
        // Windows and other platforms: not yet implemented; thread exits immediately.
    }

    // ── Draining inbound ──────────────────────────────────────────────────────

    /// Drain all decoded SLIP frames received since the last call.
    ///
    /// Returns frames in the order they were received.  The internal queue is
    /// cleared by this call.
    pub fn drain_inbound(&self) -> Vec<Vec<u8>> {
        let mut q = self.inbound.lock().unwrap_or_else(|e| e.into_inner());
        q.drain(..).collect()
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// The OS device path this transport was opened on.
    pub fn port_name(&self) -> &str {
        &self.port_name
    }

    /// The baud rate this transport was opened with.
    pub fn baud_rate(&self) -> u32 {
        self.baud_rate
    }
}

impl Drop for UsbSerialTransport {
    fn drop(&mut self) {
        self.close();
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Unix write helper
// ────────────────────────────────────────────────────────────────────────────

/// Write all bytes in `data` to `fd`, retrying on `EINTR`.
#[cfg(unix)]
fn write_all_fd(fd: libc::c_int, data: &[u8]) -> Result<(), UsbSerialError> {
    let mut offset = 0usize;
    while offset < data.len() {
        // SAFETY: pointer arithmetic stays within the slice bounds checked above.
        let n = unsafe {
            libc::write(
                fd,
                data[offset..].as_ptr() as *const libc::c_void,
                data.len() - offset,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                // EINTR — retry.
                continue;
            }
            return Err(UsbSerialError::IoError(err));
        }
        offset += n as usize;
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SLIP encode / decode roundtrips ──────────────────────────────────────

    #[test]
    fn slip_roundtrip_simple() {
        let payload = b"hello, world!";
        let encoded = slip_encode(payload);
        let decoded = slip_decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn slip_roundtrip_empty_payload() {
        let payload: &[u8] = b"";
        let encoded = slip_encode(payload);
        // Empty payload produces two consecutive END bytes; slip_decode should
        // return an empty vec.
        let decoded = slip_decode(&encoded).expect("decode should succeed for empty payload");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn slip_roundtrip_contains_end_byte() {
        // Payload containing 0xC0 must be escaped.
        let payload = &[0x01, SLIP_END, 0x02];
        let encoded = slip_encode(payload);
        // The 0xC0 in the payload must NOT appear unescaped between the
        // framing END markers.
        let inner = &encoded[1..encoded.len() - 1];
        assert!(
            !inner.contains(&SLIP_END),
            "raw SLIP_END must not appear inside encoded frame"
        );
        let decoded = slip_decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.as_slice(), payload);
    }

    #[test]
    fn slip_roundtrip_contains_esc_byte() {
        // Payload containing 0xDB must be escaped.
        let payload = &[0x01, SLIP_ESC, 0x02];
        let encoded = slip_encode(payload);
        let decoded = slip_decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.as_slice(), payload);
    }

    #[test]
    fn slip_roundtrip_all_special_bytes() {
        // Payload that is entirely special bytes.
        let payload = &[SLIP_END, SLIP_ESC, SLIP_END, SLIP_ESC];
        let encoded = slip_encode(payload);
        let decoded = slip_decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.as_slice(), payload);
    }

    #[test]
    fn slip_roundtrip_binary_payload() {
        // Arbitrary binary data including every byte value 0x00–0xFF.
        let payload: Vec<u8> = (0..=255u8).collect();
        let encoded = slip_encode(&payload);
        let decoded = slip_decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn slip_roundtrip_large_payload() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(USB_SERIAL_MAX_FRAME).collect();
        let encoded = slip_encode(&payload);
        let decoded = slip_decode(&encoded).expect("decode should succeed for max-size payload");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn slip_decode_rejects_oversized() {
        // Build a raw SLIP frame whose decoded size would exceed USB_SERIAL_MAX_FRAME.
        // We fabricate a frame with USB_SERIAL_MAX_FRAME + 1 non-special bytes.
        let mut frame = Vec::with_capacity(USB_SERIAL_MAX_FRAME + 3);
        frame.push(SLIP_END);
        frame.extend(std::iter::repeat(0x41u8).take(USB_SERIAL_MAX_FRAME + 1));
        frame.push(SLIP_END);
        assert!(
            slip_decode(&frame).is_none(),
            "oversized frame must be rejected"
        );
    }

    #[test]
    fn slip_decode_rejects_invalid_escape() {
        // 0xDB followed by 0x00 is not a valid SLIP escape sequence.
        let frame = &[SLIP_END, SLIP_ESC, 0x00, SLIP_END];
        assert!(
            slip_decode(frame).is_none(),
            "invalid escape must cause None"
        );
    }

    #[test]
    fn slip_decode_returns_none_for_empty_input() {
        assert!(slip_decode(&[]).is_none());
    }

    #[test]
    fn slip_decode_returns_none_for_no_end_marker() {
        // A stream with no SLIP_END at all.
        assert!(slip_decode(b"just some bytes").is_none());
    }

    // ── SlipDecoder — streaming / fragmented input ───────────────────────────

    #[test]
    fn slip_decoder_single_frame_in_one_feed() {
        let payload = b"single frame";
        let encoded = slip_encode(payload);
        let mut dec = SlipDecoder::new();
        let frames = dec.feed(&encoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], payload);
    }

    #[test]
    fn slip_decoder_fragmented_frame() {
        let payload = b"fragmented delivery test";
        let encoded = slip_encode(payload);

        let mut dec = SlipDecoder::new();
        let mut all_frames: Vec<Vec<u8>> = Vec::new();

        // Feed one byte at a time — worst-case fragmentation.
        for byte in &encoded {
            all_frames.extend(dec.feed(std::slice::from_ref(byte)));
        }

        assert_eq!(all_frames.len(), 1, "expected exactly one complete frame");
        assert_eq!(all_frames[0], payload);
    }

    #[test]
    fn slip_decoder_two_frames_split_across_feeds() {
        let p1 = b"frame one";
        let p2 = b"frame two";
        let mut combined = slip_encode(p1);
        combined.extend_from_slice(&slip_encode(p2));

        // Split at an arbitrary point in the middle.
        let split = combined.len() / 3;
        let mut dec = SlipDecoder::new();
        let mut frames = dec.feed(&combined[..split]);
        frames.extend(dec.feed(&combined[split..]));

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], p1 as &[u8]);
        assert_eq!(frames[1], p2 as &[u8]);
    }

    #[test]
    fn slip_decoder_multiple_frames_in_one_feed() {
        let payloads: &[&[u8]] = &[b"alpha", b"beta", b"gamma", b"delta"];
        let combined: Vec<u8> = payloads
            .iter()
            .flat_map(|p| slip_encode(p))
            .collect();

        let mut dec = SlipDecoder::new();
        let frames = dec.feed(&combined);

        assert_eq!(frames.len(), payloads.len());
        for (frame, &expected) in frames.iter().zip(payloads.iter()) {
            assert_eq!(frame.as_slice(), expected);
        }
    }

    #[test]
    fn slip_decoder_with_special_bytes_fragmented() {
        let payload = &[SLIP_END, 0x42, SLIP_ESC, 0xFF];
        let encoded = slip_encode(payload);

        let mut dec = SlipDecoder::new();
        let mut frames: Vec<Vec<u8>> = Vec::new();
        // Feed two bytes at a time to stress the escape-spanning-boundary case.
        let mut i = 0;
        while i < encoded.len() {
            let end = (i + 2).min(encoded.len());
            frames.extend(dec.feed(&encoded[i..end]));
            i = end;
        }

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].as_slice(), payload as &[u8]);
    }

    #[test]
    fn slip_decoder_ignores_flush_end_bytes() {
        // A double SLIP_END (flush prefix) before the real frame must not
        // produce a spurious empty frame.
        let payload = b"preceded by flush";
        let mut buf = vec![SLIP_END, SLIP_END]; // flush prefix
        buf.extend_from_slice(&slip_encode(payload));

        let mut dec = SlipDecoder::new();
        let frames = dec.feed(&buf);

        // Exactly one non-empty frame.
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], payload);
    }

    #[test]
    fn slip_decoder_empty_feed() {
        let mut dec = SlipDecoder::new();
        let frames = dec.feed(&[]);
        assert!(frames.is_empty());
    }

    #[test]
    fn slip_decoder_partial_frame_retained_across_feeds() {
        let payload = b"partial then complete";
        let encoded = slip_encode(payload);

        let mut dec = SlipDecoder::new();
        // Feed everything except the final END.
        let partial = &encoded[..encoded.len() - 1];
        let frames_partial = dec.feed(partial);
        assert!(
            frames_partial.is_empty(),
            "incomplete frame must not be emitted"
        );

        // Feed the remaining final END.
        let frames_final = dec.feed(&[SLIP_END]);
        assert_eq!(frames_final.len(), 1);
        assert_eq!(frames_final[0], payload);
    }

    // ── list_ports doesn't panic ─────────────────────────────────────────────

    #[test]
    fn list_ports_does_not_panic() {
        let ports = UsbSerialTransport::list_ports();
        // We cannot assert specific contents (CI may have no serial hardware),
        // but the call must not panic and must return a reasonable type.
        for port in &ports {
            assert!(!port.is_empty(), "port name must be non-empty");
        }
    }

    // ── UsbSerialError Display ───────────────────────────────────────────────

    #[test]
    fn error_display_not_found() {
        let e = UsbSerialError::NotFound("/dev/ttyUSB0".to_owned());
        let s = e.to_string();
        assert!(s.contains("ttyUSB0"), "display must mention the port");
        assert!(s.contains("not found"), "display must indicate not-found");
    }

    #[test]
    fn error_display_permission_denied() {
        let e = UsbSerialError::PermissionDenied("/dev/ttyACM0".to_owned());
        let s = e.to_string();
        assert!(s.contains("permission denied") || s.contains("Permission denied"));
        assert!(s.contains("ttyACM0"));
    }

    #[test]
    fn error_display_io_error() {
        let io = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let e = UsbSerialError::IoError(io);
        let s = e.to_string();
        assert!(s.contains("I/O") || s.contains("error"), "display must describe I/O error");
    }

    #[test]
    fn error_display_frame_too_large() {
        let e = UsbSerialError::FrameTooLarge;
        let s = e.to_string();
        assert!(
            s.contains("65535") || s.contains("frame"),
            "display must mention frame size"
        );
    }

    #[test]
    fn error_display_port_not_open() {
        let e = UsbSerialError::PortNotOpen;
        let s = e.to_string();
        assert!(s.contains("not open") || s.contains("open"));
    }

    // ── send rejects too-large payload ───────────────────────────────────────

    #[test]
    fn send_rejects_oversized_payload_without_open_port() {
        // We can't easily open a real port in CI, but we can verify that when
        // the port is not open the error is PortNotOpen (checked before the
        // size check), and when we have a fake "open" transport the size check
        // fires first on oversized payloads.
        //
        // Build a transport with open_flag=true but no real fd so write() would
        // fail, then test the size gate by passing a too-large payload.
        #[cfg(unix)]
        {
            // We create a transport with an invalid fd (-1 sentinel: safe
            // because we never actually read/write in this test).  We set
            // open_flag=true manually to bypass the is_open() guard.
            let t = UsbSerialTransport {
                port_name: "test".to_owned(),
                baud_rate: USB_SERIAL_BAUD_DEFAULT,
                inbound: Mutex::new(VecDeque::new()),
                outbound: Mutex::new(VecDeque::new()),
                fd: Mutex::new(None), // no real fd
                open_flag: std::sync::atomic::AtomicBool::new(true),
            };
            let huge = vec![0u8; USB_SERIAL_MAX_FRAME + 1];
            let result = t.send(&huge);
            // open_flag is true but fd is None → PortNotOpen is returned from
            // the fd guard, but the FrameTooLarge check fires first.
            assert!(
                matches!(result, Err(UsbSerialError::FrameTooLarge)),
                "expected FrameTooLarge, got: {result:?}"
            );
        }
        #[cfg(not(unix))]
        {
            // On non-Unix builds we at least verify the error types exist.
            let _e = UsbSerialError::FrameTooLarge.to_string();
        }
    }

    // ── SLIP encode structure ────────────────────────────────────────────────

    #[test]
    fn slip_encode_starts_and_ends_with_end() {
        let enc = slip_encode(b"any data");
        assert_eq!(enc.first().copied(), Some(SLIP_END));
        assert_eq!(enc.last().copied(), Some(SLIP_END));
    }

    #[test]
    fn slip_encode_escapes_end_byte() {
        let enc = slip_encode(&[SLIP_END]);
        // Inner bytes (strip leading/trailing END): should be ESC ESC_END.
        let inner = &enc[1..enc.len() - 1];
        assert_eq!(inner, &[SLIP_ESC, SLIP_ESC_END]);
    }

    #[test]
    fn slip_encode_escapes_esc_byte() {
        let enc = slip_encode(&[SLIP_ESC]);
        let inner = &enc[1..enc.len() - 1];
        assert_eq!(inner, &[SLIP_ESC, SLIP_ESC_ESC]);
    }

    // ── SlipDecoder default ──────────────────────────────────────────────────

    #[test]
    fn slip_decoder_default_same_as_new() {
        // SlipDecoder::default() must behave identically to SlipDecoder::new().
        let payload = b"default test";
        let encoded = slip_encode(payload);
        let mut dec: SlipDecoder = Default::default();
        let frames = dec.feed(&encoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], payload);
    }
}
