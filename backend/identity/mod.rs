//! Identity Model (§3.1, §17.2)
//!
//! Three-layer identity:
//! - Layer 1 — Mesh Identity: WireGuard keypair, always active after device unlock
//! - Layer 2 — Self: root cryptographic identity, requires PIN/auth
//! - Layer 3 — Masks: contextual presentations derived from self
//!
//! Each layer is cryptographically isolated. Compromising one reveals nothing
//! about the others.

// Sub-module: mesh_identity — see module-level docs for details.
pub mod mesh_identity;
// Sub-module: self_identity — see module-level docs for details.
pub mod self_identity;
// Sub-module: mask — see module-level docs for details.
pub mod mask;
// Sub-module: peer_id — see module-level docs for details.
pub mod peer_id;
// Sub-module: pin — see module-level docs for details.
pub mod pin;
pub mod killswitch;
pub mod profile;
// Sub-module: key_change — key change validation with 72h wait (§4.6).
pub mod key_change;
