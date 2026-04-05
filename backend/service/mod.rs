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
//!   garden_ops.rs   - Garden feed/discovery adapter over group rooms
//!   android_proximity_ops.rs - backend-owned Android proximity state/intake
//!   android_startup_ops.rs - backend-owned Android startup/unlock state
//!   pairing_ops.rs  - peer pairing, pairing payload, peer list
//!   call_ops.rs     - call offer/answer/hangup/status
//!   transport_ops.rs- clearnet, Tor, WireGuard, SDR, overlay transport
//!   discovery.rs    - LAN discovery logic
//! ```

// --- sub-modules -----------------------------------------------------------
/// Android proximity state and pairing intake.
pub mod android_proximity_ops;
/// Android startup and unlock state intake.
pub mod android_startup_ops;
/// Voice/video call: offer, answer, hangup, status.
pub mod call_ops;
/// LAN peer discovery: UDP broadcast announce and TCP handshake.
pub mod discovery;
/// File transfer: start, cancel, accept.
pub mod file_ops;
/// Garden feed/discovery backed by backend-owned service records and room state.
pub mod garden_ops;
/// Identity: create, unlock, import, reset, public/private profile.
pub mod identity_ops;
/// Message request queue: first-contact messages from unpaired senders (§10.1.1).
pub mod message_request_ops;
/// Messaging: send, react, receipt, edit, delete, reply, pin, etc.
pub mod messaging;
/// Peer pairing: pair, pairing payload, peer list, trust ops.
pub mod pairing_ops;
/// Poll-cycle advance methods called on every `mi_poll_events` tick.
pub mod poll;
/// Core runtime struct and construction helpers.
pub mod runtime;
/// Transport management: clearnet, Tor, WireGuard, SDR, overlay.
pub mod transport_ops;
/// Vault persistence: load and save for all data collections.
pub mod vault_ops;

// Re-export the primary type so callers can write `service::MeshRuntime`.
pub use runtime::MeshRuntime;
