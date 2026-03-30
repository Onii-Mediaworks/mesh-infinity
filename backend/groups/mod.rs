//! Trusted Groups (§8.7)
//!
//! # What are Trusted Groups?
//!
//! Groups are first-class network entities with their own keypairs,
//! addresses, and membership management. They provide encrypted
//! group communication using Signal Sender Keys (§3.6) with
//! per-group key distribution.
//!
//! # Group Identity
//!
//! Groups have Ed25519 + X25519 keypairs, appear in the network map,
//! can be endorsed, and can be flagged Disavowed — just like peers.
//! But they are NOT peers: trust levels, pairing, and profile exchange
//! work differently for groups.
//!
//! # Encryption Model
//!
//! Group messages use Sender Keys — each member has a per-group
//! Sender Key distributed via individual X3DH-encrypted direct
//! messages. This provides efficient group encryption (one encrypt,
//! many decrypt) at the cost of no forward secrecy within a
//! sending chain. Scheduled rekeying (default: 7 days) bounds
//! the forward secrecy window.
//!
//! # Module Layout
//!
//! - **group** — core group structure, membership, and lifecycle
//! - **membership** — member management, roles, and permissions
//! - **rekey** — Sender Key rekeying and the superset ring model

pub mod group;
pub mod membership;
pub mod rekey;
pub mod garden;
// Sub-module: governance — quorum-based group governance (§8.10).
pub mod governance;
