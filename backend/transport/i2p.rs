//! I2P transport (§5.4)
//!
//! Implements the I2P anonymising transport using the SAM v3 (Socket Application
//! Mapping) bridge protocol.  The SAM bridge is a TCP service that every I2P
//! router exposes, typically on `127.0.0.1:7656`.  It provides a simple
//! text-command interface for creating streaming (TCP-like) sessions and
//! connecting to / accepting connections from other I2P destinations.
//!
//! ## SAM v3 Protocol Overview
//!
//! All SAM commands are terminated with `\n` and responses are single lines:
//!
//! ```text
//! Client → SAM:  HELLO VERSION MIN=3.0 MAX=3.3\n
//! SAM → Client:  HELLO REPLY RESULT=OK VERSION=3.1\n
//!
//! Client → SAM:  SESSION CREATE STYLE=STREAM ID=<id> DESTINATION=TRANSIENT\n
//! SAM → Client:  SESSION STATUS RESULT=OK DESTINATION=<b64dest>\n
//!
//! (new TCP connection to SAM)
//! Client → SAM:  HELLO VERSION MIN=3.0 MAX=3.3\n
//! SAM → Client:  HELLO REPLY RESULT=OK VERSION=3.1\n
//! Client → SAM:  STREAM ACCEPT ID=<id>\n
//! SAM → Client:  STREAM STATUS RESULT=OK\n
//! -- connection hangs until a peer connects --
//! -- then data flows directly on the TCP socket --
//!
//! (new TCP connection to SAM)
//! Client → SAM:  HELLO VERSION MIN=3.0 MAX=3.3\n
//! SAM → Client:  HELLO REPLY RESULT=OK VERSION=3.1\n
//! Client → SAM:  STREAM CONNECT ID=<id> DESTINATION=<b64dest> SILENT=false\n
//! SAM → Client:  STREAM STATUS RESULT=OK\n
//! -- bidirectional data flows on the same TCP socket --
//! ```
//!
//! ## Design Notes
//!
//! * All I/O is **blocking** (`std::net::TcpStream`) — consistent with the Tor
//!   transport's sync/loopback-bridge pattern.
//! * [`I2pTransport::accept_loop`] runs in a dedicated OS thread so blocking
//!   `STREAM ACCEPT` calls never stall the event loop.
//! * Session IDs are 8 random hex characters, unique per run.
//! * Destinations are I2P base64: uses `+`, `/`, and `=` (not URL-safe base64).
//!
//! ## References
//!
//! * SAM v3 specification: <https://geti2p.net/en/docs/api/samv3>
//! * §5.4 of the Mesh Infinity protocol specification.

use std::{
    fmt,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use rand_core::{OsRng, RngCore};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default SAM bridge address (§5.4).
pub const DEFAULT_SAM_ADDR: &str = "127.0.0.1:7656";

/// SAM v3 minimum version we require.
const SAM_MIN_VERSION: &str = "3.0";

/// SAM v3 maximum version we support.
const SAM_MAX_VERSION: &str = "3.3";

/// TCP connect timeout when probing the SAM bridge.
const SAM_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// TCP connect timeout for all other SAM connections.
const SAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a single-line SAM reply before giving up.
const SAM_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the accept loop waits for an inbound connection before re-trying.
/// Long enough that it won't spin-burn CPU; short enough to notice shutdown.
const ACCEPT_LOOP_TIMEOUT: Duration = Duration::from_secs(60);

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can arise from the I2P / SAM transport layer (§5.4).
#[derive(Debug)]
pub enum I2pError {
    /// The SAM bridge TCP port was not reachable.
    SamUnavailable,
    /// The SAM HELLO handshake failed (e.g. version mismatch or unexpected reply).
    HandshakeFailed(String),
    /// `SESSION CREATE` was rejected by the SAM bridge.
    SessionFailed(String),
    /// `STREAM CONNECT` or `STREAM ACCEPT` was rejected.
    ConnectFailed(String),
    /// An underlying I/O error.
    Io(std::io::Error),
}

impl fmt::Display for I2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            I2pError::SamUnavailable => write!(f, "SAM bridge is not reachable"),
            I2pError::HandshakeFailed(s) => write!(f, "SAM handshake failed: {s}"),
            I2pError::SessionFailed(s) => write!(f, "SAM session creation failed: {s}"),
            I2pError::ConnectFailed(s) => write!(f, "SAM stream connect/accept failed: {s}"),
            I2pError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for I2pError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            I2pError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for I2pError {
    fn from(e: std::io::Error) -> Self {
        I2pError::Io(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// I2pTransport
// ─────────────────────────────────────────────────────────────────────────────

/// The I2P streaming transport layer (§5.4).
///
/// Wraps a SAM v3 STREAM session.  After calling [`I2pTransport::connect`] the
/// struct owns a live session with a base64 I2P destination address.  Peers
/// can then dial us at that destination and we can dial them at theirs.
///
/// All accepted inbound streams are pushed into an internal `Vec<TcpStream>`
/// by the background accept loop and can be drained by the mesh context via
/// [`I2pTransport::drain_inbound`].
pub struct I2pTransport {
    /// Our base64 I2P destination address (516+ chars).
    ///
    /// Share this address with peers so they can reach us.
    pub destination: String,

    /// Address of the I2P SAM bridge.
    sam_addr: SocketAddr,

    /// SAM session ID (8 random hex chars, e.g. `"a3f8c12d"`).
    session_id: String,

    /// Inbound [`TcpStream`]s delivered by the accept loop.
    inbound: Mutex<Vec<TcpStream>>,
}

impl std::fmt::Debug for I2pTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("I2pTransport")
            .field("destination", &self.destination)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl I2pTransport {
    // ─────────────────────────────────────────────────────────────────────
    // Construction / session setup
    // ─────────────────────────────────────────────────────────────────────

    /// Create a SAM STREAM session and return a ready [`I2pTransport`].
    ///
    /// Steps performed:
    /// 1. Open a TCP connection to `sam_addr`.
    /// 2. Perform the SAM HELLO handshake.
    /// 3. Send `SESSION CREATE STYLE=STREAM ID=<id> DESTINATION=TRANSIENT`.
    /// 4. Parse the resulting `DESTINATION=<b64>` from the reply.
    ///
    /// The returned struct owns the session.  Call [`accept_loop`] to begin
    /// accepting inbound connections.
    ///
    /// [`accept_loop`]: I2pTransport::accept_loop
    pub fn connect(sam_addr: SocketAddr) -> Result<Self, I2pError> {
        let session_id = generate_session_id();

        let mut stream = TcpStream::connect_timeout(&sam_addr, SAM_CONNECT_TIMEOUT)
            .map_err(|_| I2pError::SamUnavailable)?;
        stream
            .set_read_timeout(Some(SAM_READ_TIMEOUT))
            .map_err(I2pError::Io)?;
        stream
            .set_write_timeout(Some(SAM_CONNECT_TIMEOUT))
            .map_err(I2pError::Io)?;

        // HELLO handshake.
        sam_hello(&mut stream)?;

        // SESSION CREATE.
        let cmd = format!(
            "SESSION CREATE STYLE=STREAM ID={} DESTINATION=TRANSIENT\n",
            session_id
        );
        stream
            .write_all(cmd.as_bytes())
            .map_err(I2pError::Io)?;
        stream.flush().map_err(I2pError::Io)?;

        let reply = read_line(&stream)?;
        // Expected: SESSION STATUS RESULT=OK DESTINATION=<b64>\n
        if !reply.starts_with("SESSION STATUS") {
            return Err(I2pError::SessionFailed(format!(
                "unexpected reply: {reply}"
            )));
        }
        let result = parse_kv(&reply, "RESULT").unwrap_or_default();
        if result != "OK" {
            return Err(I2pError::SessionFailed(format!(
                "RESULT={result}: {reply}"
            )));
        }
        let destination = parse_kv(&reply, "DESTINATION").ok_or_else(|| {
            I2pError::SessionFailed(format!("no DESTINATION in reply: {reply}"))
        })?;

        tracing::info!(
            session_id = %session_id,
            dest_prefix = %&destination[..destination.len().min(16)],
            "I2P SAM session created"
        );

        // The session TCP connection must stay open for the session's lifetime.
        // We intentionally do not close it — it is kept alive inside the struct
        // implicitly by not binding it to a local that drops.  We store nothing
        // of it because SAM does not send further messages on the session socket
        // after the `SESSION STATUS` reply; the socket just needs to remain open.
        //
        // We leak the stream intentionally: dropping it would close the session.
        // The session lives for the process lifetime; cleanup happens on exit.
        std::mem::forget(stream);

        Ok(Self {
            destination,
            sam_addr,
            session_id,
            inbound: Mutex::new(Vec::new()),
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Outbound connections
    // ─────────────────────────────────────────────────────────────────────

    /// Dial `peer_dest` (a base64 I2P destination) and return a live
    /// bidirectional [`TcpStream`].
    ///
    /// Steps:
    /// 1. New TCP connection to the SAM bridge.
    /// 2. HELLO handshake.
    /// 3. `STREAM CONNECT ID=<session_id> DESTINATION=<peer_dest> SILENT=false`.
    /// 4. On `RESULT=OK` the same socket carries the peer's data.
    pub fn dial(&self, peer_dest: &str) -> Result<TcpStream, I2pError> {
        let mut stream = TcpStream::connect_timeout(&self.sam_addr, SAM_CONNECT_TIMEOUT)
            .map_err(|_| I2pError::SamUnavailable)?;
        stream
            .set_read_timeout(Some(SAM_READ_TIMEOUT))
            .map_err(I2pError::Io)?;
        stream
            .set_write_timeout(Some(SAM_CONNECT_TIMEOUT))
            .map_err(I2pError::Io)?;

        sam_hello(&mut stream)?;

        let cmd = format!(
            "STREAM CONNECT ID={} DESTINATION={} SILENT=false\n",
            self.session_id, peer_dest
        );
        stream
            .write_all(cmd.as_bytes())
            .map_err(I2pError::Io)?;
        stream.flush().map_err(I2pError::Io)?;

        let reply = read_line(&stream)?;
        // Expected: STREAM STATUS RESULT=OK\n
        if !reply.starts_with("STREAM STATUS") {
            return Err(I2pError::ConnectFailed(format!(
                "unexpected reply: {reply}"
            )));
        }
        let result = parse_kv(&reply, "RESULT").unwrap_or_default();
        if result != "OK" {
            return Err(I2pError::ConnectFailed(format!(
                "RESULT={result}: {reply}"
            )));
        }

        // Remove timeouts — the stream is now live data.
        stream.set_read_timeout(None).map_err(I2pError::Io)?;
        stream.set_write_timeout(None).map_err(I2pError::Io)?;

        tracing::debug!(
            session_id = %self.session_id,
            dest_prefix = %&peer_dest[..peer_dest.len().min(16)],
            "I2P outbound stream connected"
        );

        Ok(stream)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Inbound accept loop
    // ─────────────────────────────────────────────────────────────────────

    /// Spawn a background thread that continuously accepts inbound I2P
    /// connections and pushes them into `self.inbound`.
    ///
    /// The thread runs for the lifetime of the `Arc<I2pTransport>`.  If the
    /// SAM bridge becomes unreachable the thread logs the error and retries
    /// with a short back-off, so the transport is self-healing.
    ///
    /// Each accepted [`TcpStream`] has no outstanding timeouts set (the
    /// read timeout used during the handshake is cleared before the stream
    /// is stored).
    pub fn accept_loop(self: Arc<Self>) {
        let transport = Arc::clone(&self);
        thread::Builder::new()
            .name(format!("i2p-accept-{}", self.session_id))
            .spawn(move || {
                loop {
                    match transport.accept_one() {
                        Ok(stream) => {
                            tracing::debug!(
                                session_id = %transport.session_id,
                                "I2P inbound stream accepted"
                            );
                            transport
                                .inbound
                                .lock()
                                .unwrap()
                                .push(stream);
                        }
                        Err(e) => {
                            tracing::warn!(
                                session_id = %transport.session_id,
                                error = %e,
                                "I2P accept error; retrying in 5s"
                            );
                            thread::sleep(Duration::from_secs(5));
                        }
                    }
                }
            })
            .expect("failed to spawn i2p-accept thread");
    }

    /// Perform a single `STREAM ACCEPT` cycle.
    ///
    /// Opens a new TCP connection to the SAM bridge, sends `STREAM ACCEPT`,
    /// waits (blocks) until an inbound peer connection arrives, then returns
    /// the live data stream.
    fn accept_one(&self) -> Result<TcpStream, I2pError> {
        let mut stream = TcpStream::connect_timeout(&self.sam_addr, SAM_CONNECT_TIMEOUT)
            .map_err(|_| I2pError::SamUnavailable)?;
        stream
            .set_read_timeout(Some(SAM_READ_TIMEOUT))
            .map_err(I2pError::Io)?;
        stream
            .set_write_timeout(Some(SAM_CONNECT_TIMEOUT))
            .map_err(I2pError::Io)?;

        sam_hello(&mut stream)?;

        let cmd = format!("STREAM ACCEPT ID={}\n", self.session_id);
        stream
            .write_all(cmd.as_bytes())
            .map_err(I2pError::Io)?;
        stream.flush().map_err(I2pError::Io)?;

        // The SAM bridge sends `STREAM STATUS RESULT=OK\n` immediately to
        // acknowledge the accept request; it then blocks until a peer connects.
        let ack = read_line(&stream)?;
        if !ack.starts_with("STREAM STATUS") {
            return Err(I2pError::ConnectFailed(format!(
                "unexpected ACCEPT ack: {ack}"
            )));
        }
        let result = parse_kv(&ack, "RESULT").unwrap_or_default();
        if result != "OK" {
            return Err(I2pError::ConnectFailed(format!(
                "ACCEPT RESULT={result}: {ack}"
            )));
        }

        // Now block waiting for a peer to connect.  The SAM bridge will send
        // one line containing the peer's destination followed by a newline,
        // then raw bidirectional data begins.
        //
        // Extend the read timeout to the accept loop timeout for the blocking
        // wait phase; a timeout here is recoverable — we just retry.
        stream
            .set_read_timeout(Some(ACCEPT_LOOP_TIMEOUT))
            .map_err(I2pError::Io)?;

        // Read the peer destination line delivered by SAM on connect.
        let peer_dest_line = read_line(&stream).map_err(|e| {
            // A timeout here is normal when there are no inbound connections;
            // surface it as a ConnectFailed so the loop retries.
            I2pError::ConnectFailed(format!("waiting for inbound peer: {e}"))
        })?;

        // An empty line means SAM closed the connection (EOF) before any peer
        // arrived — treat this as a transient error so the accept loop retries.
        if peer_dest_line.is_empty() {
            return Err(I2pError::ConnectFailed(
                "SAM closed connection before peer destination delivered".to_string(),
            ));
        }

        tracing::debug!(
            session_id = %self.session_id,
            peer_dest_prefix = %&peer_dest_line[..peer_dest_line.len().min(16)],
            "I2P inbound connection from peer"
        );

        // Clear timeouts — the stream is now a live data channel.
        stream.set_read_timeout(None).map_err(I2pError::Io)?;
        stream.set_write_timeout(None).map_err(I2pError::Io)?;

        Ok(stream)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Inbound drain
    // ─────────────────────────────────────────────────────────────────────

    /// Drain and return all inbound [`TcpStream`]s collected by the accept loop.
    ///
    /// The caller is responsible for performing the mesh pairing handshake on
    /// each returned stream (same as for direct TCP and Tor transports).
    pub fn drain_inbound(&self) -> Vec<TcpStream> {
        let mut guard = self.inbound.lock().unwrap();
        std::mem::take(&mut *guard)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Availability probe
    // ─────────────────────────────────────────────────────────────────────

    /// Return `true` if the SAM bridge at `sam_addr` is reachable.
    ///
    /// This is a fast TCP-connect probe with a short timeout.  It does NOT
    /// perform a HELLO handshake — it only confirms that something is listening
    /// on the expected port.  Use [`I2pTransport::connect`] for a full check.
    pub fn is_available(sam_addr: SocketAddr) -> bool {
        TcpStream::connect_timeout(&sam_addr, SAM_PROBE_TIMEOUT).is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SAM protocol helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Perform the SAM v3 HELLO handshake on `stream`.
///
/// Sends `HELLO VERSION MIN=3.0 MAX=3.3\n` and validates the reply.
fn sam_hello(stream: &mut TcpStream) -> Result<(), I2pError> {
    let cmd = format!(
        "HELLO VERSION MIN={} MAX={}\n",
        SAM_MIN_VERSION, SAM_MAX_VERSION
    );
    stream.write_all(cmd.as_bytes()).map_err(I2pError::Io)?;
    stream.flush().map_err(I2pError::Io)?;

    let reply = read_line(stream)?;
    // Expected: HELLO REPLY RESULT=OK VERSION=3.x\n
    if !reply.starts_with("HELLO REPLY") {
        return Err(I2pError::HandshakeFailed(format!(
            "unexpected HELLO reply: {reply}"
        )));
    }
    let result = parse_kv(&reply, "RESULT").unwrap_or_default();
    if result != "OK" {
        return Err(I2pError::HandshakeFailed(format!(
            "RESULT={result}: {reply}"
        )));
    }
    Ok(())
}

/// Read exactly one `\n`-terminated line from `stream`.
///
/// Returns the line with the trailing newline stripped.
/// Uses a [`BufReader`] internally, which buffers reads to avoid
/// one-byte-at-a-time syscalls.
fn read_line(stream: &TcpStream) -> Result<String, I2pError> {
    // Clone the stream so BufReader can own it without consuming the original.
    // The clone shares the underlying OS socket (same file descriptor on Unix,
    // same SOCKET on Windows), so the read cursor advances on both handles.
    let cloned = stream.try_clone().map_err(I2pError::Io)?;
    let mut reader = BufReader::new(cloned);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(I2pError::Io)?;
    // Strip trailing \r\n or \n.
    let line = line.trim_end_matches(['\r', '\n']).to_string();
    Ok(line)
}

/// Parse a `KEY=VALUE` pair from a SAM reply line.
///
/// Returns `Some(value)` if `key=` is present, `None` otherwise.
///
/// Handles both plain values (no spaces) and quoted values (not used by SAM
/// v3 for most fields, but tolerated here for robustness).
///
/// ## Example
///
/// ```text
/// let line = "SESSION STATUS RESULT=OK DESTINATION=ABC123==";
/// assert_eq!(parse_kv(line, "RESULT"), Some("OK".to_string()));
/// assert_eq!(parse_kv(line, "DESTINATION"), Some("ABC123==".to_string()));
/// ```
fn parse_kv(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = line.find(needle.as_str())?;
    let value_start = start + needle.len();
    let rest = &line[value_start..];
    // Values run until the next space or end of string.
    let value = if let Some(end) = rest.find(' ') {
        &rest[..end]
    } else {
        rest
    };
    Some(value.to_string())
}

/// Generate a random 8-character hex session ID.
///
/// Uses [`OsRng`] (the OS CSPRNG) for unpredictability.
fn generate_session_id() -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    // ─────────────────────────────────────────────────────────────
    // Unit tests: SAM response parsing (no network required)
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_kv_result_ok() {
        let line = "HELLO REPLY RESULT=OK VERSION=3.1";
        assert_eq!(parse_kv(line, "RESULT"), Some("OK".to_string()));
        assert_eq!(parse_kv(line, "VERSION"), Some("3.1".to_string()));
    }

    #[test]
    fn parse_kv_result_error() {
        let line = "SESSION STATUS RESULT=I2P_ERROR MESSAGE=no_session";
        assert_eq!(parse_kv(line, "RESULT"), Some("I2P_ERROR".to_string()));
        assert_eq!(parse_kv(line, "MESSAGE"), Some("no_session".to_string()));
    }

    #[test]
    fn parse_kv_destination() {
        // Simulate a real SAM destination (abbreviated for test brevity).
        let dest = "ABC123abcDEF456==";
        let line = format!("SESSION STATUS RESULT=OK DESTINATION={dest}");
        assert_eq!(parse_kv(&line, "DESTINATION"), Some(dest.to_string()));
    }

    #[test]
    fn parse_kv_missing_key() {
        let line = "SESSION STATUS RESULT=OK";
        assert_eq!(parse_kv(line, "DESTINATION"), None);
    }

    #[test]
    fn parse_kv_last_field() {
        // Value at the very end of the line (no trailing space).
        let line = "STREAM STATUS RESULT=OK";
        assert_eq!(parse_kv(line, "RESULT"), Some("OK".to_string()));
    }

    #[test]
    fn parse_kv_empty_line() {
        assert_eq!(parse_kv("", "RESULT"), None);
    }

    #[test]
    fn parse_kv_does_not_confuse_partial_keys() {
        // "DESTINATION2=x" must NOT match the key "DESTINATION" because the
        // needle is "DESTINATION=" and "DESTINATION2=" is a different prefix.
        // The search finds "DESTINATION=abc" further along the line.
        let line = "SESSION STATUS RESULT=OK DESTINATION2=x DESTINATION=abc";
        assert_eq!(parse_kv(line, "DESTINATION"), Some("abc".to_string()));
        // Also verify DESTINATION2 is independently reachable.
        assert_eq!(parse_kv(line, "DESTINATION2"), Some("x".to_string()));
    }

    #[test]
    fn session_id_is_8_hex_chars() {
        let id = generate_session_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn session_ids_are_unique() {
        // Probabilistically: two 4-byte random IDs should almost never collide.
        let ids: Vec<_> = (0..100).map(|_| generate_session_id()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "session IDs should be unique");
    }

    #[test]
    fn is_available_returns_false_for_closed_port() {
        // Use a port where nothing is listening; bind+immediately drop to get a free port.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // Now nothing is listening.
        // Give the OS a moment to clean up.
        thread::sleep(Duration::from_millis(50));
        assert!(!I2pTransport::is_available(addr));
    }

    #[test]
    fn is_available_returns_true_when_listening() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // listener is still alive — something is listening.
        assert!(I2pTransport::is_available(addr));
    }

    // ─────────────────────────────────────────────────────────────
    // Integration-style tests: mock SAM bridge over loopback
    //
    // These tests spin up a minimal TCP server that speaks the SAM
    // text protocol.  They exercise the actual connect/dial/accept
    // code paths without requiring a real I2P router to be installed.
    // ─────────────────────────────────────────────────────────────

    /// A minimal SAM bridge stub: services exactly `n_accepts` sequential
    /// control connections, speaking just enough SAM v3 to satisfy our client.
    struct MockSam {
        listener: TcpListener,
    }

    impl MockSam {
        fn bind() -> (Self, SocketAddr) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            (MockSam { listener }, addr)
        }

        /// Accept a single SAM control connection and handle one full transaction.
        /// `handler` is called with the raw TcpStream to implement the mock logic.
        /// Returns immediately — the accept and handler run in a background thread.
        fn accept_one<F>(&self, handler: F)
        where
            F: FnOnce(TcpStream) + Send + 'static,
        {
            // Clone the listener so the background thread can own it.
            // Both handles share the same OS socket.
            let listener = self.listener.try_clone().unwrap();
            thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                handler(stream);
            });
        }

        /// Read one `\n`-terminated line from a stream (test-side helper).
        fn read_line(stream: &mut TcpStream) -> String {
            let cloned = stream.try_clone().unwrap();
            let mut reader = BufReader::new(cloned);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            line.trim_end_matches(['\r', '\n']).to_string()
        }

        /// Write `msg` (must end with `\n`) to `stream`.
        fn write(stream: &mut TcpStream, msg: &str) {
            stream.write_all(msg.as_bytes()).unwrap();
            stream.flush().unwrap();
        }

        /// Perform the HELLO exchange as the server side.
        fn server_hello(stream: &mut TcpStream) {
            let cmd = Self::read_line(stream);
            assert!(
                cmd.starts_with("HELLO VERSION"),
                "expected HELLO VERSION, got: {cmd}"
            );
            Self::write(stream, "HELLO REPLY RESULT=OK VERSION=3.1\n");
        }
    }

    /// Fake base64 I2P destination used in tests (516 chars of 'A').
    const FAKE_DEST: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    #[test]
    fn connect_creates_session() {
        let (mock, addr) = MockSam::bind();

        // Spawn the mock SAM handler for the SESSION CREATE connection.
        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let cmd = MockSam::read_line(&mut stream);
            assert!(
                cmd.contains("SESSION CREATE"),
                "expected SESSION CREATE, got: {cmd}"
            );
            let reply = format!(
                "SESSION STATUS RESULT=OK DESTINATION={}\n",
                FAKE_DEST
            );
            MockSam::write(&mut stream, &reply);
            // Keep the stream alive (SAM session socket must stay open).
            // We just block-read forever; the test will drop the socket.
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        });

        let transport = I2pTransport::connect(addr).expect("connect should succeed");
        assert_eq!(transport.destination, FAKE_DEST);
        assert_eq!(transport.session_id.len(), 8);
        assert!(transport
            .session_id
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn connect_fails_when_sam_unavailable() {
        // Bind and immediately drop — nothing listening.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        thread::sleep(Duration::from_millis(50));

        let result = I2pTransport::connect(addr);
        assert!(
            matches!(result, Err(I2pError::SamUnavailable)),
            "expected SamUnavailable, got: {:?}",
            result
        );
    }

    #[test]
    fn connect_fails_on_session_error() {
        let (mock, addr) = MockSam::bind();

        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let _cmd = MockSam::read_line(&mut stream);
            MockSam::write(
                &mut stream,
                "SESSION STATUS RESULT=DUPLICATED_ID\n",
            );
        });

        let result = I2pTransport::connect(addr);
        assert!(
            matches!(result, Err(I2pError::SessionFailed(_))),
            "expected SessionFailed, got: {:?}",
            result
        );
    }

    #[test]
    fn connect_fails_on_hello_mismatch() {
        let (mock, addr) = MockSam::bind();

        mock.accept_one(|mut stream| {
            let _cmd = MockSam::read_line(&mut stream);
            // Respond with a garbage reply.
            MockSam::write(&mut stream, "GARBAGE NOPE\n");
        });

        let result = I2pTransport::connect(addr);
        assert!(
            matches!(result, Err(I2pError::HandshakeFailed(_))),
            "expected HandshakeFailed, got: {:?}",
            result
        );
    }

    #[test]
    fn dial_connects_to_peer() {
        let (mock, addr) = MockSam::bind();

        // First accept: SESSION CREATE (for I2pTransport::connect).
        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let _cmd = MockSam::read_line(&mut stream);
            let reply = format!("SESSION STATUS RESULT=OK DESTINATION={}\n", FAKE_DEST);
            MockSam::write(&mut stream, &reply);
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        });

        let transport = I2pTransport::connect(addr).unwrap();

        // Second accept: STREAM CONNECT.
        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let cmd = MockSam::read_line(&mut stream);
            assert!(
                cmd.contains("STREAM CONNECT"),
                "expected STREAM CONNECT, got: {cmd}"
            );
            assert!(
                cmd.contains("SILENT=false"),
                "SILENT=false must be present"
            );
            MockSam::write(&mut stream, "STREAM STATUS RESULT=OK\n");
            // Keep alive so the client's stream stays readable.
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        });

        let peer_dest = "BBBBBBBBBBBBBBBB==";
        let result = transport.dial(peer_dest);
        assert!(result.is_ok(), "dial should succeed: {:?}", result);
    }

    #[test]
    fn dial_fails_on_error_result() {
        let (mock, addr) = MockSam::bind();

        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let _cmd = MockSam::read_line(&mut stream);
            let reply = format!("SESSION STATUS RESULT=OK DESTINATION={}\n", FAKE_DEST);
            MockSam::write(&mut stream, &reply);
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        });

        let transport = I2pTransport::connect(addr).unwrap();

        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let _cmd = MockSam::read_line(&mut stream);
            MockSam::write(&mut stream, "STREAM STATUS RESULT=CANT_REACH_PEER\n");
        });

        let result = transport.dial("CCCCCCCC==");
        assert!(
            matches!(result, Err(I2pError::ConnectFailed(_))),
            "expected ConnectFailed, got: {:?}",
            result
        );
    }

    #[test]
    fn drain_inbound_empty_initially() {
        let (mock, addr) = MockSam::bind();

        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let _cmd = MockSam::read_line(&mut stream);
            let reply = format!("SESSION STATUS RESULT=OK DESTINATION={}\n", FAKE_DEST);
            MockSam::write(&mut stream, &reply);
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        });

        let transport = I2pTransport::connect(addr).unwrap();
        let inbound = transport.drain_inbound();
        assert!(inbound.is_empty(), "should start empty");
    }

    #[test]
    fn drain_inbound_delivers_accepted_streams() {
        let (mock, addr) = MockSam::bind();

        // SESSION CREATE connection.
        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let _cmd = MockSam::read_line(&mut stream);
            let reply = format!("SESSION STATUS RESULT=OK DESTINATION={}\n", FAKE_DEST);
            MockSam::write(&mut stream, &reply);
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        });

        let transport = Arc::new(I2pTransport::connect(addr).unwrap());
        let peer_dest_line = format!("{}\n", FAKE_DEST);

        // STREAM ACCEPT connection — mock SAM delivers a fake peer connection.
        mock.accept_one({
            let peer_dest_line = peer_dest_line.clone();
            move |mut stream| {
                MockSam::server_hello(&mut stream);
                let cmd = MockSam::read_line(&mut stream);
                assert!(
                    cmd.contains("STREAM ACCEPT"),
                    "expected STREAM ACCEPT, got: {cmd}"
                );
                MockSam::write(&mut stream, "STREAM STATUS RESULT=OK\n");
                // Send the peer's destination line to simulate an inbound connect.
                MockSam::write(&mut stream, &peer_dest_line);
                // Keep the stream alive briefly for data exchange.
                thread::sleep(Duration::from_millis(200));
            }
        });

        transport.clone().accept_loop();

        // Wait for the accept thread to complete the handshake.
        thread::sleep(Duration::from_millis(500));

        let inbound = transport.drain_inbound();
        assert_eq!(inbound.len(), 1, "one inbound stream expected");

        // Drain again should be empty.
        let inbound2 = transport.drain_inbound();
        assert!(inbound2.is_empty(), "drain should clear the buffer");
    }

    #[test]
    fn accept_one_retries_after_sam_disconnect() {
        // Verify the accept loop re-enters after a transient error by checking
        // that accept_one returns an error for a SAM that immediately closes
        // the connection after STREAM ACCEPT ack.
        let (mock, addr) = MockSam::bind();

        // SESSION CREATE.
        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let _cmd = MockSam::read_line(&mut stream);
            let reply = format!("SESSION STATUS RESULT=OK DESTINATION={}\n", FAKE_DEST);
            MockSam::write(&mut stream, &reply);
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        });

        let transport = I2pTransport::connect(addr).unwrap();

        // STREAM ACCEPT — SAM closes the connection after ack, before any peer.
        mock.accept_one(|mut stream| {
            MockSam::server_hello(&mut stream);
            let _cmd = MockSam::read_line(&mut stream);
            MockSam::write(&mut stream, "STREAM STATUS RESULT=OK\n");
            // Close immediately — no peer destination line.
            drop(stream);
        });

        // accept_one should return Err because SAM closed before sending peer dest.
        let result = transport.accept_one();
        assert!(
            result.is_err(),
            "should error when SAM closes before delivering peer dest"
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Error display tests
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn error_display_sam_unavailable() {
        let e = I2pError::SamUnavailable;
        assert!(e.to_string().contains("SAM bridge"));
    }

    #[test]
    fn error_display_handshake_failed() {
        let e = I2pError::HandshakeFailed("bad version".to_string());
        assert!(e.to_string().contains("bad version"));
    }

    #[test]
    fn error_display_session_failed() {
        let e = I2pError::SessionFailed("DUPLICATED_ID".to_string());
        assert!(e.to_string().contains("DUPLICATED_ID"));
    }

    #[test]
    fn error_display_connect_failed() {
        let e = I2pError::ConnectFailed("CANT_REACH_PEER".to_string());
        assert!(e.to_string().contains("CANT_REACH_PEER"));
    }

    #[test]
    fn error_display_io() {
        let e = I2pError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert!(e.to_string().contains("refused"));
    }

    #[test]
    fn error_from_io() {
        let io_err =
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe");
        let e: I2pError = io_err.into();
        assert!(matches!(e, I2pError::Io(_)));
    }
}
