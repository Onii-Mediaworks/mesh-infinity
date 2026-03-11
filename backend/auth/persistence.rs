//! Keyfile-encrypted on-disk identity persistence.
//!
//! Identity material and local profile data are stored as a ChaCha20-Poly1305
//! ciphertext keyed by a 32-byte random keyfile.
//!
//! To permanently destroy all identity data without leaving recoverable
//! plaintext, call [`IdentityStore::destroy`]: it deletes the encryption key
//! from the platform keystore first (making the existing ciphertext permanently
//! unreadable even if `identity.dat` was copied elsewhere), then removes any
//! remaining files.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::core::error::{MeshInfinityError, Result};
use crate::auth::keystore;

/// All identity material persisted to disk for a single local node.
#[derive(Clone, Serialize, Deserialize)]
pub struct PersistedIdentity {
    /// Ed25519 signing secret key scalar (32 bytes).
    pub ed25519_secret: Vec<u8>,
    /// X25519 static DH secret key (32 bytes).
    pub x25519_secret: Vec<u8>,
    /// Display name carried in the identity (shared with trusted peers in WoT).
    pub name: Option<String>,
    /// Publicly visible display name shown in peer discovery.
    pub public_display_name: Option<String>,
    /// Whether this node is discoverable by unknown peers.
    pub identity_is_public: bool,
    /// Private (device-local) display name — never transmitted to peers.
    pub private_display_name: Option<String>,
    /// Private (device-local) freeform bio — never transmitted to peers.
    pub private_bio: Option<String>,
}

/// Manages the files that protect a local identity:
///
/// * Platform keystore (macOS Keychain / iOS Keychain / Windows Credential Manager /
///   Linux Secret Service) — holds the 32-byte ChaCha20 encryption key.
///   On Android the key is wrapped by the Android Keystore and stored as
///   `identity.key.wrap`.  On headless Linux without a Secret Service daemon
///   the key falls back to a 0600-restricted `identity.key` file.
/// * `identity.dat` — 12-byte nonce followed by ChaCha20-Poly1305 ciphertext
///                    of the JSON-serialised [`PersistedIdentity`].
pub struct IdentityStore {
    dir: PathBuf,
}

impl IdentityStore {
    /// Create a store whose files will live in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("identity.key")
    }

    fn wrapped_key_path(&self) -> PathBuf {
        self.dir.join("identity.key.wrap")
    }

    fn data_path(&self) -> PathBuf {
        self.dir.join("identity.dat")
    }

    /// Returns `true` if both the keyfile and data file are present on disk.
    pub fn exists(&self) -> bool {
        self.key_exists() && self.data_path().exists()
    }

    #[cfg(target_os = "android")]
    fn key_exists(&self) -> bool {
        self.wrapped_key_path().exists() || self.key_path().exists()
    }

    #[cfg(not(target_os = "android"))]
    fn key_exists(&self) -> bool {
        keystore::key_in_keystore() || self.key_path().exists()
    }

    #[cfg(target_os = "android")]
    fn load_key_bytes(&self) -> Result<Vec<u8>> {
        if self.wrapped_key_path().exists() {
            let wrapped = std::fs::read(self.wrapped_key_path())?;
            return keystore::unwrap_key_bytes(&wrapped);
        }

        let key_bytes = std::fs::read(self.key_path())?;
        if key_bytes.len() != 32 {
            return Err(MeshInfinityError::CryptoError(
                "Identity keyfile has unexpected length".to_string(),
            ));
        }
        let wrapped = keystore::wrap_key_bytes(&key_bytes)?;
        std::fs::write(self.wrapped_key_path(), &wrapped)?;
        let _ = std::fs::remove_file(self.key_path());
        Ok(key_bytes)
    }

    #[cfg(not(target_os = "android"))]
    fn load_key_bytes(&self) -> Result<Vec<u8>> {
        // Try platform keystore first.
        if let Ok(key) = keystore::load_key() {
            return Ok(key);
        }
        // Fall back to legacy plain file (e.g. headless Linux, or pre-keystore install).
        let key = std::fs::read(self.key_path()).map_err(MeshInfinityError::IoError)?;
        // Opportunistically migrate to the keystore; ignore errors (headless Linux).
        if keystore::store_key(&key).is_ok() {
            let _ = std::fs::remove_file(self.key_path());
        }
        Ok(key)
    }

    /// Decrypt and deserialise the persisted identity from disk.
    pub fn load(&self) -> Result<PersistedIdentity> {
        let key_bytes = self.load_key_bytes()?;
        if key_bytes.len() != 32 {
            return Err(MeshInfinityError::CryptoError(
                "Identity keyfile has unexpected length".to_string(),
            ));
        }

        let data_bytes = std::fs::read(self.data_path())?;
        if data_bytes.len() < 13 {
            return Err(MeshInfinityError::CryptoError(
                "Identity data file is too short".to_string(),
            ));
        }

        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        let (nonce_bytes, ciphertext) = data_bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            MeshInfinityError::CryptoError("Failed to decrypt identity data".to_string())
        })?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| MeshInfinityError::DeserializationError(e.to_string()))
    }

    /// Serialise, encrypt, and write the identity to disk.
    ///
    /// A new keyfile is generated on the first save. Subsequent saves reuse
    /// the existing keyfile so that previously exported backups remain valid.
    pub fn save(&self, identity: &PersistedIdentity) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;

        let key_bytes: Vec<u8> = if self.key_exists() {
            self.load_key_bytes()?
        } else {
            let mut k = vec![0u8; 32];
            OsRng.fill_bytes(&mut k);
            self.store_key_bytes(&k)?;
            k
        };

        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = serde_json::to_vec(identity)
            .map_err(|e| MeshInfinityError::SerializationError(e.to_string()))?;

        let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).map_err(|_| {
            MeshInfinityError::CryptoError("Failed to encrypt identity data".to_string())
        })?;

        let mut data = Vec::with_capacity(12 + ciphertext.len());
        data.extend_from_slice(&nonce_bytes);
        data.extend_from_slice(&ciphertext);
        std::fs::write(self.data_path(), &data)?;

        Ok(())
    }

    /// Killswitch: overwrite the keyfile with random bytes, then remove both
    /// files.
    ///
    /// After this call the ciphertext in the data file is permanently
    /// unreadable even if copies of either file were made beforehand.
    pub fn destroy(&self) -> Result<()> {
        self.destroy_keyfile()?;
        if self.data_path().exists() {
            std::fs::remove_file(self.data_path())?;
        }
        Ok(())
    }

    #[cfg(target_os = "android")]
    fn store_key_bytes(&self, key: &[u8]) -> Result<()> {
        let wrapped = keystore::wrap_key_bytes(key)?;
        std::fs::write(self.wrapped_key_path(), &wrapped)?;
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    fn store_key_bytes(&self, key: &[u8]) -> Result<()> {
        // Prefer the platform keystore; fall back to a 0600-restricted file on
        // headless Linux where the Secret Service daemon is unavailable.
        if keystore::store_key(key).is_ok() {
            return Ok(());
        }
        // Fallback: write to filesystem with restrictive permissions.
        std::fs::write(self.key_path(), key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(self.key_path(), std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    #[cfg(target_os = "android")]
    fn destroy_keyfile(&self) -> Result<()> {
        if self.wrapped_key_path().exists() {
            let mut random_key = vec![0u8; 32];
            OsRng.fill_bytes(&mut random_key);
            let wrapped = keystore::wrap_key_bytes(&random_key)?;
            std::fs::write(self.wrapped_key_path(), &wrapped)?;
            std::fs::remove_file(self.wrapped_key_path())?;
            let _ = keystore::delete_key_alias();
        } else if self.key_path().exists() {
            let mut random_key = vec![0u8; 32];
            OsRng.fill_bytes(&mut random_key);
            std::fs::write(self.key_path(), &random_key)?;
            std::fs::remove_file(self.key_path())?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    fn destroy_keyfile(&self) -> Result<()> {
        // Critical first step: remove the keystore entry.  Once gone, identity.dat
        // is permanently unreadable even if a copy of it exists elsewhere.
        keystore::delete_key()?;
        // Clean up any legacy plain-file remnant.
        if self.key_path().exists() {
            let mut random_key = vec![0u8; 32];
            OsRng.fill_bytes(&mut random_key);
            std::fs::write(self.key_path(), &random_key)?;
            std::fs::remove_file(self.key_path())?;
        }
        Ok(())
    }
}
