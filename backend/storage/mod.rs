//! Storage subsystem — encrypted vault (§17.9).
//!
//! All persistent data is stored as encrypted blobs using XChaCha20-Poly1305.
//! Each data collection gets its own `.vault` file. On disk, files are opaque
//! ciphertext — no schema, no queryable structure, no portable format.

pub mod vault;

pub use vault::{VaultCollection, VaultError, VaultManager};
