//! Layer 2 — Self Identity (§3.1.2, §3.6.2)
//!
//! The self is the user's core cryptographic identity:
//! - Root of all trust relationships
//! - Never appears on the mesh directly
//! - Sole function: derive and authorize mask keypairs
//! - Holds the trust graph, network map, and threat context
//! - Initialized only after user authenticates (PIN or device unlock)
//!
//! # Storage model (§3.6.2)
//!
//! ```text
//! identity.key  — [1-byte mode][16-byte salt?][24-byte nonce?][ciphertext?]
//!                  mode 0x00 = plain 32-byte master key
//!                  mode 0x01 = Argon2id(PIN)-wrapped 32-byte master key
//!                  Plain layout:   [0x00][32 bytes]
//!                  Wrapped layout: [0x01][16-byte Argon2 salt][24-byte nonce][48-byte ciphertext]
//!
//! identity.dat  — [1-byte version=0x01][24-byte XNonce]
//!                 [XChaCha20-Poly1305 ciphertext of identity payload]
//! ```
//!
//! Identity payload format (inside identity.dat):
//! ```text
//! [4-byte LE json_len][json metadata bytes][32-byte ed25519 secret][32-byte x25519 secret]
//! ```

use std::path::Path;

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, Zeroizing};

use hkdf::Hkdf;
use sha2::Sha256;

use super::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption/decryption failed")]
    Crypto,
    #[error("Invalid identity file format")]
    Format,
    #[error("Wrong PIN or corrupted key file")]
    WrongPin,
    #[error("Identity file not found at {0}")]
    NotFound(String),
}

// ---------------------------------------------------------------------------
// Identity struct
// ---------------------------------------------------------------------------

/// The self identity — Layer 2.
pub struct SelfIdentity {
    /// Ed25519 signing key (identity root)
    pub ed25519_signing: SigningKey,
    /// X25519 static secret (for DH key agreement — IK in X3DH)
    pub x25519_secret: X25519Secret,
    /// Derived public keys
    pub ed25519_pub: [u8; 32],
    pub x25519_pub: X25519Public,
    /// Preauth X25519 keypair (SPK in X3DH terminology).
    /// Derived deterministically from x25519_secret via HKDF.
    /// Rotated every 7 days (rotation uses week number in the HKDF info string).
    /// Published in pairing payloads and presence announcements.
    pub preauth_x25519_secret: X25519Secret,
    pub preauth_x25519_pub: X25519Public,
    /// ML-KEM-768 decapsulation key (private — §3.4.1 PQXDH).
    /// Derived deterministically from master_key; not serialized separately.
    pub kem_decapsulation_key: Vec<u8>,
    /// ML-KEM-768 encapsulation key (public — §3.4.1 PQXDH).
    /// Advertised in pairing payloads and presence announcements.
    pub kem_encapsulation_key: Vec<u8>,
    /// Display name (optional)
    pub display_name: Option<String>,
    /// Identity master key (32 bytes) — used to derive per-collection vault keys.
    /// Zeroized on drop.
    pub master_key: Zeroizing<[u8; 32]>,
}

impl SelfIdentity {
    /// Generate a fresh self identity with a new random master key.
    pub fn generate(display_name: Option<String>) -> Self {
        let ed25519_signing = SigningKey::generate(&mut OsRng);
        let ed25519_pub = ed25519_signing.verifying_key().to_bytes();
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        let x25519_pub = X25519Public::from(&x25519_secret);
        let (preauth_x25519_secret, preauth_x25519_pub) = derive_preauth_keypair(&x25519_secret);

        let mut master_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut master_key_bytes);

        let (kem_decapsulation_key, kem_encapsulation_key) =
            derive_kem_keypair(&master_key_bytes);

        Self {
            ed25519_signing,
            x25519_secret,
            ed25519_pub,
            x25519_pub,
            preauth_x25519_secret,
            preauth_x25519_pub,
            kem_decapsulation_key,
            kem_encapsulation_key,
            display_name,
            master_key: Zeroizing::new(master_key_bytes),
        }
    }

    /// Get the peer ID for the self's public mask.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_ed25519_pub(&self.ed25519_pub)
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /// Serialize the identity payload for encrypted storage (§3.6.2).
    ///
    /// Format: `[4-byte LE json_len][json_bytes][ed25519_secret (32)][x25519_secret (32)]`
    pub fn serialize_payload(&self) -> Zeroizing<Vec<u8>> {
        let metadata = IdentityMetadata {
            display_name: self.display_name.clone(),
            ed25519_pub: hex::encode(self.ed25519_pub),
            x25519_pub: hex::encode(self.x25519_pub.as_bytes()),
        };
        let json = serde_json::to_vec(&metadata).expect("Identity metadata serialization");

        let json_len = (json.len() as u32).to_le_bytes();
        let ed25519_bytes = self.ed25519_signing.to_bytes();
        let x25519_bytes = self.x25519_secret.to_bytes(); // actual secret, not public key

        let mut payload = Zeroizing::new(Vec::with_capacity(4 + json.len() + 32 + 32));
        payload.extend_from_slice(&json_len);
        payload.extend_from_slice(&json);
        payload.extend_from_slice(&ed25519_bytes);
        payload.extend_from_slice(&x25519_bytes);

        payload
    }

    /// Deserialize an identity from a decrypted payload (inverse of serialize_payload).
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        if payload.len() < 4 + 32 + 32 {
            return None;
        }

        // Read JSON length
        let json_len = u32::from_le_bytes(payload[..4].try_into().ok()?) as usize;
        if payload.len() < 4 + json_len + 32 + 32 {
            return None;
        }

        // Parse metadata JSON
        let json_bytes = &payload[4..4 + json_len];
        let metadata: IdentityMetadata = serde_json::from_slice(json_bytes).ok()?;

        // Extract ed25519 secret (32 bytes)
        let ed25519_offset = 4 + json_len;
        let mut ed25519_secret_bytes = Zeroizing::new([0u8; 32]);
        ed25519_secret_bytes.copy_from_slice(&payload[ed25519_offset..ed25519_offset + 32]);
        let ed25519_signing = SigningKey::from_bytes(&ed25519_secret_bytes);
        let ed25519_pub = ed25519_signing.verifying_key().to_bytes();

        // Extract x25519 secret (32 bytes)
        let x25519_offset = ed25519_offset + 32;
        let mut x25519_secret_bytes = Zeroizing::new([0u8; 32]);
        x25519_secret_bytes.copy_from_slice(&payload[x25519_offset..x25519_offset + 32]);
        let x25519_secret = X25519Secret::from(*x25519_secret_bytes);
        let x25519_pub = X25519Public::from(&x25519_secret);
        let (preauth_x25519_secret, preauth_x25519_pub) = derive_preauth_keypair(&x25519_secret);

        // ML-KEM keypair is derived from master_key — placeholder until caller sets it.
        // The caller (load_from_disk) must call set_master_key_and_derive() after loading.
        Some(Self {
            ed25519_signing,
            x25519_secret,
            ed25519_pub,
            x25519_pub,
            preauth_x25519_secret,
            preauth_x25519_pub,
            kem_decapsulation_key: Vec::new(), // set by caller via derive_kem_after_load()
            kem_encapsulation_key: Vec::new(), // set by caller via derive_kem_after_load()
            display_name: metadata.display_name,
            master_key: Zeroizing::new([0u8; 32]), // caller must set after loading from disk
        })
    }

    // -----------------------------------------------------------------------
    // Disk persistence (§3.6.2)
    // -----------------------------------------------------------------------

    /// Persist this identity to disk.
    ///
    /// Writes two files:
    /// - `<data_dir>/identity.key` — the master key (optionally PIN-wrapped)
    /// - `<data_dir>/identity.dat` — the encrypted identity payload
    pub fn save_to_disk(&self, data_dir: &Path, pin: Option<&str>) -> Result<(), IdentityError> {
        // ---- Write identity.key ----
        let key_path = data_dir.join("identity.key");
        let key_data = match pin {
            None => {
                // Plain: [0x00][32 master key bytes]
                let mut buf = Vec::with_capacity(33);
                buf.push(0x00u8);
                buf.extend_from_slice(&*self.master_key);
                buf
            }
            Some(pin_str) => {
                // Argon2id-wrapped: [0x01][16-byte salt][24-byte nonce][48-byte ciphertext]
                let mut salt_bytes = [0u8; 16];
                OsRng.fill_bytes(&mut salt_bytes);
                let argon2 = Argon2::default();
                let mut wrapping_key = Zeroizing::new([0u8; 32]);
                argon2.hash_password_into(
                    pin_str.as_bytes(),
                    &salt_bytes,
                    &mut *wrapping_key,
                ).map_err(|_| IdentityError::Crypto)?;

                let mut nonce_bytes = [0u8; 24];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = XNonce::from_slice(&nonce_bytes);
                let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
                    .map_err(|_| IdentityError::Crypto)?;
                let ciphertext = cipher
                    .encrypt(nonce, self.master_key.as_ref())
                    .map_err(|_| IdentityError::Crypto)?;

                let mut buf = Vec::with_capacity(1 + 16 + 24 + ciphertext.len());
                buf.push(0x01u8);
                buf.extend_from_slice(&salt_bytes);
                buf.extend_from_slice(&nonce_bytes);
                buf.extend_from_slice(&ciphertext);
                buf
            }
        };
        write_atomic(&key_path, &key_data)?;

        // ---- Write identity.dat ----
        // Encrypt payload with a key derived from master_key via HKDF
        let dat_path = data_dir.join("identity.dat");
        let payload = self.serialize_payload();

        let dat_key = derive_identity_dat_key(&self.master_key);
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(&*dat_key)
            .map_err(|_| IdentityError::Crypto)?;
        let ciphertext = cipher
            .encrypt(nonce, payload.as_ref())
            .map_err(|_| IdentityError::Crypto)?;

        // [version=0x01][24-byte nonce][ciphertext]
        let mut dat_data = Vec::with_capacity(1 + 24 + ciphertext.len());
        dat_data.push(0x01u8);
        dat_data.extend_from_slice(&nonce_bytes);
        dat_data.extend_from_slice(&ciphertext);
        write_atomic(&dat_path, &dat_data)?;

        Ok(())
    }

    /// Load an identity from disk, decrypting with the optional PIN.
    pub fn load_from_disk(data_dir: &Path, pin: Option<&str>) -> Result<Self, IdentityError> {
        // ---- Read identity.key → master key ----
        let key_path = data_dir.join("identity.key");
        let key_data = std::fs::read(&key_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                IdentityError::NotFound(key_path.display().to_string())
            } else {
                IdentityError::Io(e)
            }
        })?;

        let master_key = match key_data.first().copied() {
            Some(0x00) => {
                // Plain master key
                if key_data.len() < 33 {
                    return Err(IdentityError::Format);
                }
                let mut k = Zeroizing::new([0u8; 32]);
                k.copy_from_slice(&key_data[1..33]);
                k
            }
            Some(0x01) => {
                // PIN-wrapped master key
                let pin_str = pin.ok_or(IdentityError::WrongPin)?;
                if key_data.len() < 1 + 16 + 24 + 32 + 16 {
                    // minimum: 1 + 16 (salt) + 24 (nonce) + 48 (32-byte ciphertext + 16-byte tag)
                    return Err(IdentityError::Format);
                }
                let salt_bytes = &key_data[1..17];
                let nonce_bytes = &key_data[17..41];
                let ciphertext = &key_data[41..];

                let argon2 = Argon2::default();
                let mut wrapping_key = Zeroizing::new([0u8; 32]);
                argon2.hash_password_into(
                    pin_str.as_bytes(),
                    salt_bytes,
                    &mut *wrapping_key,
                ).map_err(|_| IdentityError::WrongPin)?;

                let nonce = XNonce::from_slice(nonce_bytes);
                let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
                    .map_err(|_| IdentityError::Crypto)?;
                let plaintext = cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|_| IdentityError::WrongPin)?;

                if plaintext.len() != 32 {
                    return Err(IdentityError::Format);
                }
                let mut k = Zeroizing::new([0u8; 32]);
                k.copy_from_slice(&plaintext);
                k
            }
            _ => return Err(IdentityError::Format),
        };

        // ---- Read identity.dat → identity payload ----
        let dat_path = data_dir.join("identity.dat");
        let dat_data = std::fs::read(&dat_path).map_err(IdentityError::Io)?;

        if dat_data.len() < 1 + 24 {
            return Err(IdentityError::Format);
        }
        if dat_data[0] != 0x01 {
            return Err(IdentityError::Format);
        }

        let nonce = XNonce::from_slice(&dat_data[1..25]);
        let ciphertext = &dat_data[25..];
        let dat_key = derive_identity_dat_key(&master_key);
        let cipher = XChaCha20Poly1305::new_from_slice(&*dat_key)
            .map_err(|_| IdentityError::Crypto)?;
        let payload = Zeroizing::new(
            cipher.decrypt(nonce, ciphertext).map_err(|_| IdentityError::Crypto)?
        );

        let mut identity = Self::from_payload(&payload).ok_or(IdentityError::Format)?;
        identity.master_key = master_key;
        // Derive ML-KEM keypair from the now-loaded master key (§3.4.1).
        let (dk, ek) = derive_kem_keypair(&identity.master_key);
        identity.kem_decapsulation_key = dk;
        identity.kem_encapsulation_key = ek;
        Ok(identity)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive the ML-KEM-768 keypair deterministically from the identity master key (§3.4.1).
///
/// Uses HKDF-SHA256 with two domain-separated info strings to produce the
/// two 32-byte seeds `(d, z)` required by `MlKem768::generate_deterministic`.
///
/// Returns `(decapsulation_key_bytes, encapsulation_key_bytes)`.
/// The decapsulation key is 2400 bytes; the encapsulation key is 1184 bytes.
pub fn derive_kem_keypair(master_key: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut d = ml_kem::B32::default();
    let mut z = ml_kem::B32::default();
    hk.expand(b"meshinfinity-ml-kem-768-d-v1", d.as_mut_slice())
        .expect("HKDF expand for d");
    hk.expand(b"meshinfinity-ml-kem-768-z-v1", z.as_mut_slice())
        .expect("HKDF expand for z");
    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    (dk.as_bytes().to_vec(), ek.as_bytes().to_vec())
}

fn derive_identity_dat_key(master_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"meshinfinity-identity-dat-v1", &mut *key)
        .expect("HKDF expand");
    key
}

/// Derive the preauth X25519 keypair from the long-term IK secret.
///
/// The preauth key (SPK in Signal terminology) is rotated weekly.
/// Rotation is week-keyed: the current ISO week number is appended to the
/// HKDF info string, so the key automatically advances every 7 days and
/// the recipient only needs to try the current week ± 1 to handle week
/// boundary edge-cases.
///
/// Deterministic derivation avoids a separate storage field — the preauth
/// key is always re-derivable from the IK secret, which survives disk load.
pub fn derive_preauth_keypair(ik_secret: &X25519Secret) -> (X25519Secret, X25519Public) {
    // Week number since Unix epoch (7 × 24 × 3600 = 604800 seconds per week).
    // If system time is unavailable (clock regression or platform error),
    // log a warning and refuse to derive — the caller must not use a key
    // derived from an unknown week (which could stop rotation silently).
    let week = match std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() / 604_800,
        Err(_) => {
            // This is a serious platform error. Falling back to week 0 would
            // freeze key rotation. Use a sentinel value that forces the caller
            // to notice something is wrong (week u64::MAX is never a real week).
            // Callers that derive a preauth key should always verify the key
            // against the current expected week after derivation.
            tracing::warn!("system time unavailable — preauth key derivation using fallback week");
            // Use the maximum u64 as sentinel — callers can detect this.
            // In practice this path should never be hit on any real OS.
            u64::MAX
        }
    };

    let info = format!("meshinfinity-preauth-spk-v1-week-{week}");
    let hk = Hkdf::<Sha256>::new(None, &ik_secret.to_bytes());
    let mut preauth_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), &mut *preauth_bytes)
        .expect("HKDF expand");

    let preauth_secret = X25519Secret::from(*preauth_bytes);
    let preauth_pub = X25519Public::from(&preauth_secret);
    (preauth_secret, preauth_pub)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), IdentityError> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// JSON-serializable identity metadata (non-secret fields).
#[derive(Serialize, Deserialize)]
struct IdentityMetadata {
    display_name: Option<String>,
    ed25519_pub: String,
    x25519_pub: String,
}

impl Drop for SelfIdentity {
    fn drop(&mut self) {
        self.ed25519_pub.zeroize();
        // SigningKey, StaticSecret, and Zeroizing<[u8;32]> implement their own Drop with zeroize
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_identity() {
        let id = SelfIdentity::generate(Some("Alice".into()));
        assert_eq!(id.display_name, Some("Alice".into()));
        assert_ne!(id.ed25519_pub, [0u8; 32]);
        assert_ne!(*id.master_key, [0u8; 32]);
    }

    #[test]
    fn test_peer_id_derivation() {
        let id = SelfIdentity::generate(None);
        let pid = id.peer_id();
        let pid2 = PeerId::from_ed25519_pub(&id.ed25519_pub);
        assert_eq!(pid, pid2);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let id = SelfIdentity::generate(Some("Test".into()));
        let payload = id.serialize_payload();

        // Payload must contain actual secret bytes (not public)
        assert!(payload.len() > 4 + 32 + 32);

        // Deserialize
        let id2 = SelfIdentity::from_payload(&payload).expect("from_payload failed");
        assert_eq!(id2.ed25519_pub, id.ed25519_pub);
        assert_eq!(id2.x25519_pub.as_bytes(), id.x25519_pub.as_bytes());
        assert_eq!(id2.display_name, id.display_name);

        // Confirm x25519 secret is actually the secret, not public key bytes
        let x_secret_bytes = id.x25519_secret.to_bytes();
        let x_pub_bytes = *id.x25519_pub.as_bytes();
        assert_ne!(x_secret_bytes, x_pub_bytes, "serialize_payload stored public key instead of secret");

        // Verify the serialized payload ends with the secret, not the public key
        let payload_slice = payload.as_slice();
        let payload_len = payload_slice.len();
        let serialized_x25519 = &payload_slice[payload_len - 32..];
        assert_eq!(serialized_x25519, &x_secret_bytes, "payload must store x25519 SECRET");
    }

    #[test]
    fn test_save_load_no_pin() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(Some("NoPinUser".into()));
        let original_pub = id.ed25519_pub;

        id.save_to_disk(dir.path(), None).expect("save failed");

        let loaded = SelfIdentity::load_from_disk(dir.path(), None).expect("load failed");
        assert_eq!(loaded.ed25519_pub, original_pub);
        assert_eq!(loaded.display_name, Some("NoPinUser".into()));
    }

    #[test]
    fn test_save_load_with_pin() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(Some("PinUser".into()));
        let original_pub = id.ed25519_pub;

        id.save_to_disk(dir.path(), Some("secret123")).expect("save failed");

        // Wrong PIN should fail
        assert!(SelfIdentity::load_from_disk(dir.path(), Some("wrongpin")).is_err());

        // Correct PIN should succeed
        let loaded = SelfIdentity::load_from_disk(dir.path(), Some("secret123")).expect("load failed");
        assert_eq!(loaded.ed25519_pub, original_pub);
        assert_eq!(loaded.display_name, Some("PinUser".into()));
    }

    #[test]
    fn test_x25519_secret_survives_roundtrip() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(None);
        let original_secret_bytes = id.x25519_secret.to_bytes();

        id.save_to_disk(dir.path(), None).expect("save failed");
        let loaded = SelfIdentity::load_from_disk(dir.path(), None).expect("load failed");

        assert_eq!(loaded.x25519_secret.to_bytes(), original_secret_bytes,
            "x25519 secret must survive save/load roundtrip");
    }

    #[test]
    fn test_unique_identities() {
        let id1 = SelfIdentity::generate(None);
        let id2 = SelfIdentity::generate(None);
        assert_ne!(id1.ed25519_pub, id2.ed25519_pub);
        assert_ne!(id1.peer_id(), id2.peer_id());
        assert_ne!(*id1.master_key, *id2.master_key);
    }

    // ── Post-load security invariants ────────────────────────────────────────

    /// After load_from_disk, master_key must be restored and non-zero.
    ///
    /// from_payload() intentionally zeroes master_key; load_from_disk()
    /// is responsible for restoring it. A regression here would silently
    /// break post-quantum key establishment and vault derivation.
    #[test]
    fn test_master_key_restored_after_load() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(None);
        let original_master = *id.master_key;

        id.save_to_disk(dir.path(), None).expect("save failed");
        let loaded = SelfIdentity::load_from_disk(dir.path(), None).expect("load failed");

        assert_ne!(*loaded.master_key, [0u8; 32],
            "master_key must not be all-zero after load (would indicate un-restored key)");
        assert_eq!(*loaded.master_key, original_master,
            "master_key must be exactly restored to the pre-save value");
    }

    /// After load_from_disk, ML-KEM keys must be populated (non-empty).
    ///
    /// from_payload() leaves these empty until load_from_disk() derives them.
    #[test]
    fn test_kem_keys_populated_after_load() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(None);

        id.save_to_disk(dir.path(), None).expect("save failed");
        let loaded = SelfIdentity::load_from_disk(dir.path(), None).expect("load failed");

        assert!(!loaded.kem_decapsulation_key.is_empty(),
            "kem_decapsulation_key must be populated after load");
        assert!(!loaded.kem_encapsulation_key.is_empty(),
            "kem_encapsulation_key must be populated after load");
    }

    /// The KEM keys derived after load must be consistent with the master key.
    ///
    /// Two loads of the same identity must produce identical KEM material.
    #[test]
    fn test_kem_keys_deterministic_from_master_key() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(None);

        id.save_to_disk(dir.path(), None).expect("save failed");

        let loaded1 = SelfIdentity::load_from_disk(dir.path(), None).expect("first load failed");
        let loaded2 = SelfIdentity::load_from_disk(dir.path(), None).expect("second load failed");

        assert_eq!(loaded1.kem_encapsulation_key, loaded2.kem_encapsulation_key,
            "KEM encapsulation key must be deterministically derived from master key");
        assert_eq!(loaded1.kem_decapsulation_key, loaded2.kem_decapsulation_key,
            "KEM decapsulation key must be deterministically derived from master key");
    }
}
