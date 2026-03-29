//! Encrypted Vault Storage (§17.9)
//!
//! All persistent data is stored as encrypted blobs. There is no database,
//! no SQL, no queryable structure on disk. Each data collection is a single
//! `.vault` file:
//!
//! ```text
//! [1-byte schema_version][24-byte XNonce][XChaCha20-Poly1305 ciphertext of JSON]
//! ```
//!
//! Per-collection encryption keys are derived from the identity master key
//! via HKDF-SHA256 with domain-separated info strings.
//!
//! Writes are atomic: write to `.vault.tmp`, then rename to `.vault`.
//! On crash, either old or new version is intact — never a partial write.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current schema version for vault files.
const SCHEMA_VERSION: u8 = 1;

/// XNonce size for XChaCha20-Poly1305 (24 bytes).
const NONCE_SIZE: usize = 24;

/// Header size: 1 byte schema version + 24 byte nonce.
const HEADER_SIZE: usize = 1 + NONCE_SIZE;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("HKDF key derivation failed")]
    HkdfExpand,
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("AEAD decryption failed — file may be corrupted or wrong key")]
    DecryptFailed,
    #[error("JSON serialization: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("Vault file too short (expected >= {HEADER_SIZE} bytes, got {0})")]
    FileTooShort(usize),
    #[error("Unknown schema version {0} (this build supports version {SCHEMA_VERSION})")]
    UnknownSchemaVersion(u8),
}

// ---------------------------------------------------------------------------
// Vault collection
// ---------------------------------------------------------------------------

/// A single encrypted collection on disk.
///
/// Each collection (rooms, messages, peers, etc.) is a separate `.vault` file.
/// The collection key is derived from the master key with a unique info string.
pub struct VaultCollection {
    /// Path to the `.vault` file
    path: PathBuf,
    /// Derived encryption key for this collection (32 bytes)
    key: Zeroizing<[u8; 32]>,
}

impl VaultCollection {
    /// Create a vault collection handle.
    ///
    /// The `master_key` is the identity master key (§3.6.2).
    /// The `collection_name` provides domain separation (e.g., "rooms", "messages").
    pub fn new(
        data_dir: &Path,
        collection_name: &str,
        master_key: &[u8; 32],
    ) -> Result<Self, VaultError> {
        let path = data_dir.join(format!("{collection_name}.vault"));

        // Derive per-collection key: HKDF-SHA256(master_key, info="meshinfinity-storage-v1-<name>")
        let info = format!("meshinfinity-storage-v1-{collection_name}");
        let hk = Hkdf::<Sha256>::new(None, master_key);
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(info.as_bytes(), &mut *key)
            .map_err(|_| VaultError::HkdfExpand)?;

        Ok(Self { path, key })
    }

    /// Read and decrypt the collection. Returns `None` if the file doesn't exist.
    pub fn load<T: DeserializeOwned>(&self) -> Result<Option<T>, VaultError> {
        let raw = match fs::read(&self.path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(VaultError::Io(e)),
        };

        if raw.len() < HEADER_SIZE {
            return Err(VaultError::FileTooShort(raw.len()));
        }

        // Parse header
        let schema_version = raw[0];
        if schema_version > SCHEMA_VERSION {
            // Forward compatibility: unknown schema versions are rejected (§17.0.1 says
            // unknown FIELDS are ignored, but unknown schema VERSIONS are breaking changes)
            return Err(VaultError::UnknownSchemaVersion(schema_version));
        }

        let nonce = XNonce::from_slice(&raw[1..HEADER_SIZE]);
        let ciphertext = &raw[HEADER_SIZE..];

        // Decrypt
        let cipher = XChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|_| VaultError::DecryptFailed)?;
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| VaultError::DecryptFailed)?;

        // Deserialize JSON (with serde's ignore_unknown_fields for forward compat)
        let value: T = serde_json::from_slice(&plaintext)?;
        Ok(Some(value))
    }

    /// Encrypt and write the collection atomically.
    pub fn save<T: Serialize>(&self, value: &T) -> Result<(), VaultError> {
        let json = serde_json::to_vec(value)?;

        // Generate fresh nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Encrypt
        let cipher = XChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|_| VaultError::EncryptFailed)?;
        let ciphertext = cipher
            .encrypt(nonce, json.as_ref())
            .map_err(|_| VaultError::EncryptFailed)?;

        // Build output: [schema_version][nonce][ciphertext]
        let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        output.push(SCHEMA_VERSION);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        // Atomic write: write to .tmp, then rename
        let tmp_path = self.path.with_extension("vault.tmp");
        fs::write(&tmp_path, &output)?;
        fs::rename(&tmp_path, &self.path)?;

        Ok(())
    }

    /// Delete the collection file.
    pub fn delete(&self) -> Result<(), VaultError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VaultError::Io(e)),
        }
    }

    /// Check if the collection file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Clean up any leftover .tmp files from crashed writes.
    pub fn cleanup_tmp(&self) -> Result<(), VaultError> {
        let tmp_path = self.path.with_extension("vault.tmp");
        match fs::remove_file(&tmp_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VaultError::Io(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Vault Manager — manages all collections
// ---------------------------------------------------------------------------

/// Manages all vault collections for a node.
pub struct VaultManager {
    data_dir: PathBuf,
    master_key: Zeroizing<[u8; 32]>,
}

impl VaultManager {
    /// Create a vault manager with the given data directory and master key.
    pub fn new(data_dir: PathBuf, master_key: [u8; 32]) -> Self {
        Self {
            data_dir,
            master_key: Zeroizing::new(master_key),
        }
    }

    /// Open a named collection.
    pub fn collection(&self, name: &str) -> Result<VaultCollection, VaultError> {
        VaultCollection::new(&self.data_dir, name, &self.master_key)
    }

    /// Clean up all leftover .tmp files from previous crashes.
    pub fn cleanup_all_tmp(&self) -> Result<(), VaultError> {
        if let Ok(entries) = fs::read_dir(&self.data_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "tmp").unwrap_or(false) {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        Ok(())
    }

    /// Get the data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestData {
        name: String,
        count: u32,
        #[serde(default)]
        items: Vec<String>,
    }

    fn test_master_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_roundtrip() {
        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "test", &test_master_key()).unwrap();

        let data = TestData {
            name: "hello".into(),
            count: 42,
            items: vec!["a".into(), "b".into()],
        };

        coll.save(&data).unwrap();
        let loaded: TestData = coll.load().unwrap().unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn test_load_nonexistent_returns_none() {
        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "missing", &test_master_key()).unwrap();
        let result: Option<TestData> = coll.load().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_different_collections_different_keys() {
        let dir = TempDir::new().unwrap();
        let master = test_master_key();

        let coll_a = VaultCollection::new(dir.path(), "rooms", &master).unwrap();
        let coll_b = VaultCollection::new(dir.path(), "peers", &master).unwrap();

        // Different collection names should derive different keys
        assert_ne!(*coll_a.key, *coll_b.key);
    }

    #[test]
    fn test_wrong_key_fails_decrypt() {
        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "test", &test_master_key()).unwrap();

        coll.save(&"secret data").unwrap();

        // Try loading with a different master key
        let wrong_key = [0x99u8; 32];
        let coll_wrong = VaultCollection::new(dir.path(), "test", &wrong_key).unwrap();
        let result: Result<Option<String>, _> = coll_wrong.load();
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_file_fails() {
        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "test", &test_master_key()).unwrap();

        coll.save(&"original").unwrap();

        // Tamper with the file
        let path = dir.path().join("test.vault");
        let mut data = fs::read(&path).unwrap();
        if data.len() > HEADER_SIZE + 1 {
            data[HEADER_SIZE + 1] ^= 0xFF;
        }
        fs::write(&path, &data).unwrap();

        let result: Result<Option<String>, _> = coll.load();
        assert!(result.is_err());
    }

    #[test]
    fn test_atomic_write_leaves_no_tmp() {
        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "test", &test_master_key()).unwrap();

        coll.save(&"data").unwrap();

        // Check no .tmp file exists after successful write
        let tmp_path = dir.path().join("test.vault.tmp");
        assert!(!tmp_path.exists());
    }

    #[test]
    fn test_delete_collection() {
        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "test", &test_master_key()).unwrap();

        coll.save(&"data").unwrap();
        assert!(coll.exists());

        coll.delete().unwrap();
        assert!(!coll.exists());
    }

    #[test]
    fn test_overwrite_collection() {
        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "test", &test_master_key()).unwrap();

        coll.save(&"version1").unwrap();
        coll.save(&"version2").unwrap();

        let loaded: String = coll.load().unwrap().unwrap();
        assert_eq!(loaded, "version2");
    }

    #[test]
    fn test_vault_manager() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::new(dir.path().to_path_buf(), test_master_key());

        let rooms = mgr.collection("rooms").unwrap();
        let peers = mgr.collection("peers").unwrap();

        rooms.save(&vec!["room1", "room2"]).unwrap();
        peers.save(&vec!["peer1"]).unwrap();

        let loaded_rooms: Vec<String> = rooms.load().unwrap().unwrap();
        let loaded_peers: Vec<String> = peers.load().unwrap().unwrap();

        assert_eq!(loaded_rooms, vec!["room1", "room2"]);
        assert_eq!(loaded_peers, vec!["peer1"]);
    }

    #[test]
    fn test_forward_compatible_unknown_fields() {
        // Simulate a newer version that added fields
        #[derive(Serialize)]
        struct NewVersion {
            name: String,
            count: u32,
            new_field: String, // Added in v2
        }

        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "test", &test_master_key()).unwrap();

        let new_data = NewVersion {
            name: "test".into(),
            count: 1,
            new_field: "extra".into(),
        };
        coll.save(&new_data).unwrap();

        // Old version without the new field should still load (ignore unknown)
        let loaded: TestData = coll.load().unwrap().unwrap();
        assert_eq!(loaded.name, "test");
        assert_eq!(loaded.count, 1);
    }
}
