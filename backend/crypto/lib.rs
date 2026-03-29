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

pub mod primitives;
pub mod secmem;
pub mod x3dh;
pub mod double_ratchet;
pub mod message_encrypt;
pub mod channel_key;
pub mod safety_number;
pub mod backup;
pub mod sender_keys;
pub mod sigma;
pub mod session;
pub mod signing;
