//! `Transport` trait — the pluggable byte-carrier abstraction (§5).
//!
//! # Why a trait?
//!
//! Mesh Infinity runs over 26 different physical/virtual transports: clearnet
//! TCP, Tor, I2P, BLE, NFC, SDR, telephone, ultrasonic, USB serial, etc.
//! Without a common abstraction each call site must exhaustively enumerate
//! every transport type, which leads to copy-pasted send/receive logic and
//! makes adding a new transport a multi-file surgery.
//!
//! The `Transport` trait defines the minimum interface that ALL transports
//! must implement. The routing layer (§6) and the transport solver (§5.10)
//! operate on `Box<dyn Transport>` — they never see the concrete type.
//!
//! # Where transports fit in the stack
//!
//! ```text
//! Application message
//!     ↓
//! Four-layer encryption (§7.2)           ← crypto crate
//!     ↓
//! KCP reliability sublayer (§5.30)       ← transport::kcp
//!     ↓
//! WireGuard per-hop encryption (§5.2)    ← transport::wireguard
//!     ↓
//! Traffic shaping + obfuscation (§15.4)  ← transport::obfuscation
//!     ↓
//! [ Transport trait ]  ←  this file
//!     ↓
//! Physical carrier (TCP, Tor, BLE …)     ← individual transport modules
//! ```
//!
//! # Endpoint encoding
//!
//! The `endpoint` parameter in `send()` and the return value of `poll_recv()`
//! are opaque strings whose format is transport-specific:
//!
//! | Transport | Endpoint format              |
//! |-----------|------------------------------|
//! | Clearnet  | `"1.2.3.4:7234"`             |
//! | Tor       | `"xxxx.onion:7234"`           |
//! | I2P       | `"xxxx.b32.i2p:7234"`         |
//! | BLE       | `"AA:BB:CC:DD:EE:FF"`         |
//! | NFC       | `"nfc:<tag-id-hex>"`          |
//! | SDR       | `"sdr:<freq-hz>:<node-id>"`  |
//! | Telephone | `"+15551234567"`              |
//! | USB       | `"usb:/dev/ttyUSB0"`          |
//!
//! The transport solver encodes endpoints in this format when handing an
//! outgoing packet to a transport, and transports return the same format
//! in `poll_recv()` so the routing layer can attribute the packet to a peer.
//!
//! # Threading model
//!
//! All transports are accessed from a single-threaded poll loop (the same
//! thread that calls `mi_poll_events`). The `Send + Sync` bounds are required
//! so transports can be stored in `Mutex<Box<dyn Transport>>` inside
//! `MeshRuntime`, not because they are accessed concurrently.

use crate::error::MeshError;

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

/// A pluggable byte-carrier for Mesh Infinity (§5).
///
/// Implementations move WireGuard-encrypted bytes between nodes over a
/// specific physical or virtual network. The routing layer and transport
/// solver work entirely through this trait — they never depend on the
/// concrete transport type.
///
/// # Implementing a new transport
///
/// 1. Create `backend/transport/<name>.rs`
/// 2. Define a struct (e.g. `ClearnetTransport`) and `impl Transport for` it.
/// 3. Register it in `TransportManager::new()` in `transport/manager.rs`.
/// 4. Add the endpoint format to the table in this module's doc comment.
///
/// # Object safety
///
/// This trait is object-safe — all methods take `&self` or `&mut self`
/// (no generics, no `Self` in return positions). This allows `Box<dyn Transport>`.
pub trait Transport: Send + Sync {
    // -----------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------

    /// The short, lowercase name of this transport (e.g. `"clearnet"`, `"tor"`, `"ble"`).
    ///
    /// Used in log messages, status JSON, and as the key in the transport map.
    /// Must be unique across all registered transports.
    fn name(&self) -> &'static str;

    // -----------------------------------------------------------------------
    // Availability
    // -----------------------------------------------------------------------

    /// Returns `true` if this transport is ready to send and receive.
    ///
    /// A transport is available when ALL of the following are true:
    /// - The user has enabled it in Settings (`transport_flags`)
    /// - The required hardware is detected (BLE adapter present, etc.)
    /// - The runtime precondition is met (Tor has bootstrapped, etc.)
    ///
    /// The transport solver MUST check `is_available()` before selecting
    /// a transport for routing (§5.10). An unavailable transport must never
    /// be used for routing, even as a fallback.
    fn is_available(&self) -> bool;

    // -----------------------------------------------------------------------
    // Data plane
    // -----------------------------------------------------------------------

    /// Send `data` to the node at `endpoint`.
    ///
    /// `endpoint` format is transport-specific — see the table in the module
    /// doc comment. The caller must supply the correct format for this transport.
    ///
    /// Returns `Ok(())` when the bytes have been handed off to the transport
    /// layer. This does NOT guarantee delivery — use WireGuard or KCP
    /// acknowledgements for reliable delivery.
    ///
    /// Errors:
    /// - `MeshError::TransportDisabled` — transport is not available.
    /// - `MeshError::ConnectionFailed` — the OS rejected the send.
    /// - `MeshError::MalformedFrame` — `endpoint` is in the wrong format.
    fn send(&self, endpoint: &str, data: &[u8]) -> Result<(), MeshError>;

    /// Poll for the next received packet. Non-blocking.
    ///
    /// Returns `Some((sender_endpoint, data))` if a packet is waiting in
    /// the receive buffer. Returns `None` if there is nothing to process.
    ///
    /// Called on every poll cycle (every ~200ms from `mi_poll_events`).
    /// Implementations must be non-blocking — they must not sleep or wait
    /// for I/O inside this method.
    ///
    /// `sender_endpoint` uses the same encoding as the `endpoint` parameter
    /// to `send()` — the caller can use it to attribute the packet to a peer.
    fn poll_recv(&self) -> Option<(String, Vec<u8>)>;

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Enable this transport: start listening, bootstrap, connect, etc.
    ///
    /// Called when the user enables the transport in Settings, or during
    /// startup for transports that are on by default (clearnet). The method
    /// is idempotent — calling it on an already-enabled transport is safe.
    ///
    /// Long-running bootstrap operations (Tor circuit establishment) should
    /// be started in the background; `is_available()` returns `false` until
    /// bootstrap completes.
    ///
    /// Errors:
    /// - `MeshError::TransportUnavailable` — hardware absent or init failed.
    fn enable(&mut self) -> Result<(), MeshError>;

    /// Disable this transport: stop listening, disconnect, clean up.
    ///
    /// Called when the user disables the transport in Settings, or during
    /// shutdown. Idempotent — calling on an already-disabled transport is safe.
    ///
    /// After `disable()`, `is_available()` must return `false` and `send()`
    /// must return `MeshError::TransportDisabled`.
    fn disable(&mut self);

    // -----------------------------------------------------------------------
    // Status reporting
    // -----------------------------------------------------------------------

    /// Returns transport-specific status as a JSON value for the Settings UI.
    ///
    /// The JSON object should include at minimum:
    /// - `"name"`: the transport name
    /// - `"available"`: bool, same as `is_available()`
    ///
    /// Additional fields are transport-specific (e.g., Tor includes
    /// `"onion_address"` and `"bootstrap_progress"`; BLE includes the
    /// connected device count).
    fn status_json(&self) -> serde_json::Value;
}

// ---------------------------------------------------------------------------
// Blanket helpers
// ---------------------------------------------------------------------------

/// Extension methods available on any `&dyn Transport` or `Box<dyn Transport>`.
///
/// These are convenience wrappers over the trait methods, provided as free
/// functions so they can be called without `use`-ing a separate trait.
/// They are kept here (rather than in the trait itself) to keep the trait
/// object-safe.
pub struct TransportExt;

impl TransportExt {
    /// Send `data` to `endpoint`, logging a warning on failure instead of
    /// propagating the error.
    ///
    /// Use this in fire-and-forget send paths where the send is best-effort
    /// (e.g. mDNS presence announcements). For reliable sends use `send()`
    /// directly and handle the `MeshError`.
    pub fn send_best_effort(transport: &dyn Transport, endpoint: &str, data: &[u8]) {
        if let Err(e) = transport.send(endpoint, data) {
            // Log at warn level — this is expected in degraded network conditions.
            log::warn!(
                "transport '{}' best-effort send to {} failed: {}",
                transport.name(),
                endpoint,
                e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -----------------------------------------------------------------------
    // Stub transport for testing trait mechanics.
    // -----------------------------------------------------------------------

    /// A minimal in-memory transport stub used in unit tests.
    ///
    /// Stores sent packets in an `outbox` and serves inbound packets from an
    /// `inbox` — no real I/O. Tests use this to verify routing-layer logic
    /// without needing a real network.
    struct StubTransport {
        /// Whether this transport is currently enabled.
        available: bool,
        /// Packets enqueued for `poll_recv()` to return.
        inbox: Mutex<Vec<(String, Vec<u8>)>>,
        /// Packets captured by `send()` for test assertions.
        outbox: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl StubTransport {
        /// Create a new stub, optionally pre-enabled.
        fn new(available: bool) -> Self {
            Self {
                available,
                inbox: Mutex::new(Vec::new()),
                outbox: Mutex::new(Vec::new()),
            }
        }

        /// Enqueue a fake inbound packet. The next `poll_recv()` will return it.
        fn inject(&self, sender: &str, data: Vec<u8>) {
            self.inbox
                .lock()
                .unwrap()
                .push((sender.to_string(), data));
        }

        /// Drain the outbox and return all sent packets for assertion.
        fn drain_outbox(&self) -> Vec<(String, Vec<u8>)> {
            self.outbox.lock().unwrap().drain(..).collect()
        }
    }

    impl Transport for StubTransport {
        fn name(&self) -> &'static str {
            "stub"
        }

        fn is_available(&self) -> bool {
            self.available
        }

        fn send(&self, endpoint: &str, data: &[u8]) -> Result<(), MeshError> {
            // Reject sends when disabled — mirrors what real transports do.
            if !self.available {
                return Err(MeshError::TransportDisabled("stub".to_string()));
            }
            self.outbox
                .lock()
                .unwrap()
                .push((endpoint.to_string(), data.to_vec()));
            Ok(())
        }

        fn poll_recv(&self) -> Option<(String, Vec<u8>)> {
            // Return the first injected packet, or None if the inbox is empty.
            self.inbox.lock().unwrap().pop()
        }

        fn enable(&mut self) -> Result<(), MeshError> {
            self.available = true;
            Ok(())
        }

        fn disable(&mut self) {
            self.available = false;
        }

        fn status_json(&self) -> serde_json::Value {
            serde_json::json!({
                "name": "stub",
                "available": self.available,
            })
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// A disabled transport must reject sends with `TransportDisabled`.
    #[test]
    fn test_disabled_transport_rejects_send() {
        let t = StubTransport::new(false);
        let result = t.send("127.0.0.1:7234", b"hello");
        assert!(
            matches!(result, Err(MeshError::TransportDisabled(_))),
            "disabled transport must return TransportDisabled"
        );
    }

    /// An enabled transport must accept sends and return Ok.
    #[test]
    fn test_enabled_transport_accepts_send() {
        let t = StubTransport::new(true);
        let result = t.send("127.0.0.1:7234", b"hello");
        assert!(result.is_ok(), "enabled transport must accept sends");

        let outbox = t.drain_outbox();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].0, "127.0.0.1:7234");
        assert_eq!(outbox[0].1, b"hello");
    }

    /// `poll_recv` must return injected packets FIFO from the inbox.
    #[test]
    fn test_poll_recv_returns_injected_packets() {
        let t = StubTransport::new(true);
        t.inject("peer-a", vec![0x01, 0x02]);
        t.inject("peer-b", vec![0x03, 0x04]);

        // poll_recv returns the most recently injected (Vec::pop = LIFO in our stub,
        // real transports should be FIFO — the stub is simpler for testing).
        let pkt = t.poll_recv();
        assert!(pkt.is_some(), "must return injected packet");

        let pkt2 = t.poll_recv();
        assert!(pkt2.is_some(), "must return second injected packet");

        // After draining, must return None.
        assert!(t.poll_recv().is_none(), "inbox must be empty after drain");
    }

    /// Enabling a disabled transport makes it available.
    #[test]
    fn test_enable_makes_transport_available() {
        let mut t = StubTransport::new(false);
        assert!(!t.is_available());

        t.enable().expect("enable must succeed for stub");
        assert!(t.is_available(), "transport must be available after enable()");
    }

    /// Disabling an enabled transport makes it unavailable.
    #[test]
    fn test_disable_makes_transport_unavailable() {
        let mut t = StubTransport::new(true);
        assert!(t.is_available());

        t.disable();
        assert!(!t.is_available(), "transport must be unavailable after disable()");
    }

    /// `status_json` must include required fields.
    #[test]
    fn test_status_json_has_required_fields() {
        let t = StubTransport::new(true);
        let status = t.status_json();

        assert!(
            status.get("name").is_some(),
            "status_json must include 'name'"
        );
        assert!(
            status.get("available").is_some(),
            "status_json must include 'available'"
        );
        assert_eq!(
            status["available"].as_bool(),
            Some(true),
            "status_json 'available' must reflect is_available()"
        );
    }

    /// Transport can be used as a trait object (`Box<dyn Transport>`).
    ///
    /// This test verifies object-safety — if the trait were not object-safe,
    /// this would fail to compile.
    #[test]
    fn test_trait_object_works() {
        let t: Box<dyn Transport> = Box::new(StubTransport::new(true));
        assert_eq!(t.name(), "stub");
        assert!(t.is_available());
        assert!(t.send("ep", b"data").is_ok());
    }

    /// `TransportExt::send_best_effort` must not panic on failure.
    #[test]
    fn test_send_best_effort_does_not_panic_on_disabled() {
        let t = StubTransport::new(false);
        // Must not panic even though the transport is disabled.
        TransportExt::send_best_effort(&t, "127.0.0.1:7234", b"test");
    }
}
