//! Cryptographic subsystem.
//!
//! Implements all cryptographic primitives for Mesh Infinity:
//! - Secure memory management (§15.1, §5.27.2)
//! - X3DH / PQXDH key agreement (§7.0.2, §3.4.1)
//! - Double Ratchet (§7.0.3)
//! - Four-layer message encryption (§7.2)
//! - Vault encryption (§17.9)
//! - Backup encryption (§3.7.4)
//! - AOS ring signatures (§3.5.2) — NOT YET IMPLEMENTED; see groups/group.rs

// Sub-module: primitives — see module-level docs for details.
pub mod primitives;
// Sub-module: secmem — see module-level docs for details.
pub mod secmem;
// Sub-module: x3dh — see module-level docs for details.
pub mod x3dh;
// Sub-module: double_ratchet — see module-level docs for details.
pub mod double_ratchet;
// Sub-module: message_encrypt — see module-level docs for details.
pub mod message_encrypt;
// Sub-module: channel_key — see module-level docs for details.
pub mod channel_key;
// Sub-module: safety_number — see module-level docs for details.
pub mod safety_number;
// Sub-module: backup — see module-level docs for details.
pub mod backup;
// Sub-module: sender_keys — see module-level docs for details.
pub mod sender_keys;
// Sub-module: sigma — see module-level docs for details.
pub mod sigma;
// Sub-module: session — see module-level docs for details.
pub mod session;
// Sub-module: signing — see module-level docs for details.
pub mod signing;
