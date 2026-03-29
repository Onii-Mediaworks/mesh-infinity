//! Identity Model (§3.1, §17.2)
//!
//! Three-layer identity:
//! - Layer 1 — Mesh Identity: WireGuard keypair, always active after device unlock
//! - Layer 2 — Self: root cryptographic identity, requires PIN/auth
//! - Layer 3 — Masks: contextual presentations derived from self
//!
//! Each layer is cryptographically isolated. Compromising one reveals nothing
//! about the others.

pub mod mesh_identity;
pub mod self_identity;
pub mod mask;
pub mod peer_id;
pub mod pin;
pub mod killswitch;
pub mod profile;
