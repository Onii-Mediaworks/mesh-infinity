//! Service layer — owns all backend state and exposes typed methods.
//!
//! The `backend/ffi/lib.rs` file is a *thin* C-ABI shim: every `pub unsafe
//! extern "C"` function does nothing more than null-check its pointer,
//! parse arguments, call a method on `MeshRuntime`, and forward the result.
//! All non-trivial logic lives here.
//!
//! ## Module layout
//! ```text
//! service/
//!   mod.rs          - this file; re-exports `MeshRuntime`
//!   runtime.rs      - struct definition, `new()`, helpers
//!   vault_ops.rs    - vault load/save operations
//!   poll.rs         - `advance_*` poll methods, clearnet TCP loop
//!   messaging.rs    - send_message, reactions, receipts, edits
//!   identity_ops.rs - create/unlock/import/reset/profile
//!   file_ops.rs     - file transfer start/cancel/accept
//!   pairing_ops.rs  - peer pairing, pairing payload, peer list
//!   call_ops.rs     - call offer/answer/hangup/status
//!   transport_ops.rs- clearnet, Tor, WireGuard, SDR, overlay transport
//!   discovery.rs    - LAN discovery logic
//! ```

// --- sub-modules -----------------------------------------------------------
/// Core runtime struct and construction helpers.
pub mod runtime;
/// Vault persistence: load and save for all data collections.
pub mod vault_ops;
/// Poll-cycle advance methods called on every `mi_poll_events` tick.
pub mod poll;
/// Messaging: send, react, receipt, edit, delete, reply, pin, etc.
pub mod messaging;
/// Identity: create, unlock, import, reset, public/private profile.
pub mod identity_ops;
/// File transfer: start, cancel, accept.
pub mod file_ops;
/// Peer pairing: pair, pairing payload, peer list, trust ops.
pub mod pairing_ops;
/// Voice/video call: offer, answer, hangup, status.
pub mod call_ops;
/// Transport management: clearnet, Tor, WireGuard, SDR, overlay.
pub mod transport_ops;
/// LAN peer discovery: UDP broadcast announce and TCP handshake.
pub mod discovery;
/// Message request queue: first-contact messages from unpaired senders (§10.1.1).
pub mod message_request_ops;

// Re-export the primary type so callers can write `service::MeshRuntime`.
pub use runtime::MeshRuntime;
