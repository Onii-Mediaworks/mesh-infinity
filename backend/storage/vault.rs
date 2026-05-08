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
    // AEAD cipher for authenticated encryption.
    XChaCha20Poly1305,
    XNonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;
// Securely erase key material to prevent forensic recovery.
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current schema version for vault files.
// SCHEMA_VERSION — protocol constant.
// Defined by the spec; must not change without a version bump.
// SCHEMA_VERSION — protocol constant.
// Defined by the spec; must not change without a version bump.
// SCHEMA_VERSION — protocol constant.
// Defined by the spec; must not change without a version bump.
// SCHEMA_VERSION — protocol constant.
// Defined by the spec; must not change without a version bump.
const SCHEMA_VERSION: u8 = 1;

/// XNonce size for XChaCha20-Poly1305 (24 bytes).
// NONCE_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// NONCE_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// NONCE_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// NONCE_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
const NONCE_SIZE: usize = 24;

/// Header size: 1 byte schema version + 24 byte nonce.
// HEADER_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// HEADER_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// HEADER_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// HEADER_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
const HEADER_SIZE: usize = 1 + NONCE_SIZE;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
// VaultError — variant enumeration.
// Match exhaustively to handle every protocol state.
// VaultError — variant enumeration.
// Match exhaustively to handle every protocol state.
// VaultError — variant enumeration.
// Match exhaustively to handle every protocol state.
// VaultError — variant enumeration.
// Match exhaustively to handle every protocol state.
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
    // JSON serialization for wire format.
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
// VaultCollection — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// VaultCollection — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// VaultCollection — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// VaultCollection — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct VaultCollection {
    /// Path to the `.vault` file
    path: PathBuf,
    /// Derived encryption key for this collection (32 bytes)
    key: Zeroizing<[u8; 32]>,
}

// VaultCollection implementation — core protocol logic.
// VaultCollection implementation — core protocol logic.
// VaultCollection implementation — core protocol logic.
// VaultCollection implementation — core protocol logic.
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
        // Resolve the filesystem path for the target resource.
        let path = data_dir.join(format!("{collection_name}.vault"));

        // Derive per-collection key: HKDF-SHA256(master_key, info="meshinfinity-storage-v1-<name>")
        let info = format!("meshinfinity-storage-v1-{collection_name}");
        // Set up the HKDF context for domain-separated key derivation.
        let hk = Hkdf::<Sha256>::new(None, master_key);
        let mut key = Zeroizing::new([0u8; 32]);
        // Expand the pseudorandom key to the required output length.
        // HKDF expand to the target key length.
        // HKDF expand to the target key length.
        // HKDF expand to the target key length.
        // HKDF expand to the target key length.
        hk.expand(info.as_bytes(), &mut *key)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| VaultError::HkdfExpand)?;

        Ok(Self { path, key })
    }

    /// Read and decrypt the collection. Returns `None` if the file doesn't exist.
    pub fn load<T: DeserializeOwned>(&self) -> Result<Option<T>, VaultError> {
        // Resolve the filesystem path for the target resource.
        let raw = match fs::read(&self.path) {
            Ok(data) => data,
            // Signal failure to the caller with a descriptive error.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            // Signal failure to the caller with a descriptive error.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            Err(e) => return Err(VaultError::Io(e)),
        };

        // Validate the input length to prevent out-of-bounds access.
        if raw.len() < HEADER_SIZE {
            return Err(VaultError::FileTooShort(raw.len()));
        }

        let value = self.decode_bytes(&raw)?;
        Ok(Some(value))
    }

    /// Decode one encrypted vault blob from raw bytes.
    ///
    /// This is the direct external-byte boundary for persisted vault data:
    /// schema header parsing, nonce extraction, authenticated decryption, and
    /// JSON deserialization.
    pub fn decode_bytes<T: DeserializeOwned>(&self, raw: &[u8]) -> Result<T, VaultError> {
        if raw.len() < HEADER_SIZE {
            return Err(VaultError::FileTooShort(raw.len()));
        }

        // Parse header
        let schema_version = raw[0];
        // Bounds check to enforce protocol constraints.
        if schema_version > SCHEMA_VERSION {
            // Forward compatibility: unknown schema versions are rejected (§17.0.1 says
            // unknown FIELDS are ignored, but unknown schema VERSIONS are breaking changes)
            return Err(VaultError::UnknownSchemaVersion(schema_version));
        }

        // Fresh nonce — must never be reused with the same key.
        let nonce = XNonce::from_slice(&raw[1..HEADER_SIZE]);
        // Initialize the AEAD cipher with the derived key material.
        let ciphertext = &raw[HEADER_SIZE..];

        // Decrypt
        let cipher = XChaCha20Poly1305::new_from_slice(&*self.key)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| VaultError::DecryptFailed)?;
        // Initialize the AEAD cipher with the derived key material.
        let plaintext = cipher
            // Decrypt and authenticate the ciphertext.
            // AEAD-decrypt and authenticate the ciphertext.
            // AEAD-decrypt and authenticate the ciphertext.
            // AEAD-decrypt and authenticate the ciphertext.
            // AEAD-decrypt and authenticate the ciphertext.
            .decrypt(nonce, ciphertext)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| VaultError::DecryptFailed)?;

        // Deserialize JSON (with serde's ignore_unknown_fields for forward compat)
        let value: T = serde_json::from_slice(&plaintext)?;
        Ok(value)
    }

    /// Encrypt and write the collection atomically.
    pub fn save<T: Serialize>(&self, value: &T) -> Result<(), VaultError> {
        let output = self.encode_bytes(value)?;

        // Atomic write: write to .tmp, then rename
        let tmp_path = self.path.with_extension("vault.tmp");
        // Persist the data to the filesystem.
        fs::write(&tmp_path, &output)?;
        fs::rename(&tmp_path, &self.path)?;

        Ok(())
    }

    /// Encode one value as an encrypted vault blob without touching the filesystem.
    pub fn encode_bytes<T: Serialize>(&self, value: &T) -> Result<Vec<u8>, VaultError> {
        // Serialize to the wire format for transmission or storage.
        let json = serde_json::to_vec(value)?;

        // Generate fresh nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        // OS-provided cryptographic random number generator.
        OsRng.fill_bytes(&mut nonce_bytes);
        // Fresh nonce — must never be reused with the same key.
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Encrypt
        let cipher = XChaCha20Poly1305::new_from_slice(&*self.key)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| VaultError::EncryptFailed)?;
        // Initialize the AEAD cipher with the derived key material.
        let ciphertext = cipher
            // Encrypt the plaintext under the current session key.
            // AEAD-encrypt the plaintext.
            // AEAD-encrypt the plaintext.
            // AEAD-encrypt the plaintext.
            .encrypt(nonce, json.as_ref())
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| VaultError::EncryptFailed)?;

        // Build output: [schema_version][nonce][ciphertext]
        let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        output.push(SCHEMA_VERSION);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        output.extend_from_slice(&nonce_bytes);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Delete the collection file.
    pub fn delete(&self) -> Result<(), VaultError> {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            // Signal failure to the caller with a descriptive error.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            // Signal failure to the caller with a descriptive error.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            Err(e) => Err(VaultError::Io(e)),
        }
    }

    /// Check if the collection file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Clean up any leftover .tmp files from crashed writes.
    pub fn cleanup_tmp(&self) -> Result<(), VaultError> {
        // Resolve the filesystem path for the target resource.
        let tmp_path = self.path.with_extension("vault.tmp");
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match fs::remove_file(&tmp_path) {
            Ok(()) => Ok(()),
            // Signal failure to the caller with a descriptive error.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            // Signal failure to the caller with a descriptive error.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            Err(e) => Err(VaultError::Io(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Vault Manager — manages all collections
// ---------------------------------------------------------------------------

/// Manages all vault collections for a node.
// VaultManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// VaultManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// VaultManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct VaultManager {
    data_dir: PathBuf,
    master_key: Zeroizing<[u8; 32]>,
}

// VaultManager implementation — core protocol logic.
// VaultManager implementation — core protocol logic.
// VaultManager implementation — core protocol logic.
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
            // Iterate over each file entry in the collection.
            // Iterate over each element.
            // Iterate over each element.
            // Iterate over each element.
            for entry in entries.flatten() {
                // Resolve the filesystem path for the target resource.
                let path = entry.path();
                if path.extension().map(|e| e == "tmp").unwrap_or(false) {
                    // Resolve the filesystem path for the target resource.
                    let _ = fs::remove_file(&path);
                }
            }
        }
        Ok(())
    }

    /// Get the data directory path.
    pub fn data_dir(&self) -> &Path {
        // Chain the operation on the intermediate result.
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
    fn test_encode_decode_bytes_roundtrip() {
        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "test", &test_master_key()).unwrap();

        let data = TestData {
            name: "bytes".into(),
            count: 7,
            items: vec!["x".into()],
        };

        let encoded = coll.encode_bytes(&data).unwrap();
        let decoded: TestData = coll.decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bytes_rejects_short_input() {
        let dir = TempDir::new().unwrap();
        let coll = VaultCollection::new(dir.path(), "test", &test_master_key()).unwrap();

        let error = coll
            .decode_bytes::<TestData>(&[0x01, 0x02, 0x03])
            .expect_err("short vault blob must be rejected");
        assert!(matches!(error, VaultError::FileTooShort(3)));
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
