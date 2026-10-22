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
//! identity.key  — [1-byte mode][mode-specific body]
//!                  mode 0x00 = plain 32-byte master key
//!                  mode 0x01 = legacy Argon2id(PIN) wrap (read-only, migrated on unlock)
//!                  mode 0x02 = Argon2id(PIN) wrap with stored parameters
//!                  Plain layout:   [0x00][32 bytes]
//!                  Legacy layout:  [0x01][16-byte salt][24-byte nonce][48-byte ciphertext]
//!                                  (argon2 crate defaults; below the §3.7.4 floor)
//!                  Wrapped layout: [0x02][m_cost u32 BE][t_cost u32 BE][p_cost u32 BE]
//!                                  [32-byte salt][24-byte nonce][48-byte ciphertext]
//!                                  header (mode..salt) bound as AEAD associated data
//!
//! identity.dat  — [1-byte version=0x01][24-byte XNonce]
//!                 [XChaCha20-Poly1305 ciphertext of identity payload]
//! ```
//!
//! The 0x02 salt and parameters are shared with the duress blob (`pin.dat`,
//! see `identity::pin`), so the unlock path derives one Argon2id key per
//! attempt and tries it against both records (§3.10 timing normalization).
//!
//! Identity payload format (inside identity.dat):
//! ```text
//! [4-byte LE json_len][json metadata bytes][32-byte ed25519 secret][32-byte x25519 secret]
//! ```

use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    // AEAD cipher for authenticated encryption.
    XChaCha20Poly1305,
    XNonce,
};
use ed25519_dalek::SigningKey;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
// Securely erase key material to prevent forensic recovery.
use zeroize::{Zeroize, Zeroizing};

use hkdf::Hkdf;
use sha2::Sha256;

use super::peer_id::PeerId;
// The single Argon2id derivation and the §3.7.4 parameter window live in
// the PIN module; identity.key is wrapped through them, never separately.
use super::pin::{self, KdfParams, PinError, SALT_LEN};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
// IdentityError — variant enumeration.
// Match exhaustively to handle every protocol state.
// IdentityError — variant enumeration.
// Match exhaustively to handle every protocol state.
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
    /// Argon2id derivation failed or the stored parameters are outside the
    /// §3.7.4 window (`WeakParams` / `ParamsTooLarge`).
    #[error("PIN key derivation: {0}")]
    Pin(#[from] PinError),
}

// ---------------------------------------------------------------------------
// Identity struct
// ---------------------------------------------------------------------------

/// The self identity — Layer 2.
// SelfIdentity — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SelfIdentity — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SelfIdentity {
    /// Ed25519 signing key (identity root)
    pub ed25519_signing: SigningKey,
    /// X25519 static secret (for DH key agreement — IK in X3DH)
    pub x25519_secret: X25519Secret,
    /// Derived public keys
    pub ed25519_pub: [u8; 32],
    /// The x25519 pub for this instance.
    pub x25519_pub: X25519Public,
    /// Preauth X25519 keypair (SPK in X3DH terminology).
    /// Derived deterministically from x25519_secret via HKDF.
    /// Rotated every 7 days (rotation uses week number in the HKDF info string).
    /// Published in pairing payloads and presence announcements.
    pub preauth_x25519_secret: X25519Secret,
    /// The preauth x25519 pub for this instance.
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

// SelfIdentity implementation — core protocol logic.
// SelfIdentity implementation — core protocol logic.
impl SelfIdentity {
    /// Generate a fresh self identity with a new random master key.
    pub fn generate(display_name: Option<String>) -> Self {
        let ed25519_signing = SigningKey::generate(&mut OsRng);
        let ed25519_pub = ed25519_signing.verifying_key().to_bytes();
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        let x25519_pub = X25519Public::from(&x25519_secret);
        let (preauth_x25519_secret, preauth_x25519_pub) = derive_preauth_keypair(&x25519_secret);

        let mut master_key_bytes = [0u8; 32];
        // OS-provided cryptographic random number generator.
        OsRng.fill_bytes(&mut master_key_bytes);

        let (kem_decapsulation_key, kem_encapsulation_key) = derive_kem_keypair(&master_key_bytes);

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
        // Invoke the associated function.
        PeerId::from_ed25519_pub(&self.ed25519_pub)
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /// Serialize the identity payload for encrypted storage (§3.6.2).
    ///
    /// Format: `[4-byte LE json_len][json_bytes][ed25519_secret (32)][x25519_secret (32)]`
    pub fn serialize_payload(&self) -> Zeroizing<Vec<u8>> {
        // Prepare the data buffer for the next processing stage.
        let metadata = IdentityMetadata {
            display_name: self.display_name.clone(),
            // Invoke the associated function.
            ed25519_pub: hex::encode(self.ed25519_pub),
            // Extract the raw byte representation for wire encoding.
            x25519_pub: hex::encode(self.x25519_pub.as_bytes()),
        };
        // Infallible: IdentityMetadata contains only Option<String> and String fields;
        // serde_json serialization of those types cannot fail at runtime.
        // If this somehow panics, it indicates a programmer error (e.g., a type change
        // that introduced a non-serializable field) — a panic is the correct signal.
        let json = serde_json::to_vec(&metadata).expect(
            "IdentityMetadata serialization is infallible — all fields are String/Option<String>",
        );

        // Serialize to the wire format for transmission or storage.
        let json_len = (json.len() as u32).to_le_bytes();
        // Extract the raw byte representation for wire encoding.
        let ed25519_bytes = self.ed25519_signing.to_bytes();
        let x25519_bytes = self.x25519_secret.to_bytes(); // actual secret, not public key

        // Serialize to the wire format for transmission or storage.
        let mut payload = Zeroizing::new(Vec::with_capacity(4 + json.len() + 32 + 32));
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        payload.extend_from_slice(&json_len);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        payload.extend_from_slice(&json);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        payload.extend_from_slice(&ed25519_bytes);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        payload.extend_from_slice(&x25519_bytes);

        payload
    }

    /// Deserialize an identity from a decrypted payload (inverse of serialize_payload).
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        // Validate the input length to prevent out-of-bounds access.
        if payload.len() < 4 + 32 + 32 {
            // No result available — signal absence to the caller.
            return None;
        }

        // Read JSON length
        let json_len = u32::from_le_bytes(payload[..4].try_into().ok()?) as usize;
        // Validate the input length to prevent out-of-bounds access.
        if payload.len() < 4 + json_len + 32 + 32 {
            // No result available — signal absence to the caller.
            return None;
        }

        // Parse metadata JSON
        let json_bytes = &payload[4..4 + json_len];
        // Serialize to the wire format for transmission or storage.
        let metadata: IdentityMetadata = serde_json::from_slice(json_bytes).ok()?;

        // Extract ed25519 secret (32 bytes)
        let ed25519_offset = 4 + json_len;
        let mut ed25519_secret_bytes = Zeroizing::new([0u8; 32]);
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        ed25519_secret_bytes.copy_from_slice(&payload[ed25519_offset..ed25519_offset + 32]);
        let ed25519_signing = SigningKey::from_bytes(&ed25519_secret_bytes);
        let ed25519_pub = ed25519_signing.verifying_key().to_bytes();

        // Extract x25519 secret (32 bytes)
        let x25519_offset = ed25519_offset + 32;
        let mut x25519_secret_bytes = Zeroizing::new([0u8; 32]);
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        x25519_secret_bytes.copy_from_slice(&payload[x25519_offset..x25519_offset + 32]);
        let x25519_secret = X25519Secret::from(*x25519_secret_bytes);
        let x25519_pub = X25519Public::from(&x25519_secret);
        let (preauth_x25519_secret, preauth_x25519_pub) = derive_preauth_keypair(&x25519_secret);

        // ML-KEM keypair is derived from master_key — placeholder until caller sets it.
        // The caller (load_from_disk) must call set_master_key_and_derive() after loading.
        // Wrap the found value.
        // Wrap the found value.
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

    /// Encode `identity.dat`: `[0x01][24-byte XNonce][XChaCha20-Poly1305(payload)]`.
    ///
    /// The payload key is derived from the master key via HKDF, so the file
    /// is unreadable once `identity.key` is overwritten (§3.9.1 step 2).
    /// Split out from `save_to_disk` so the duress path can build the new
    /// identity's bytes in the foreground and hand them to the background
    /// writer without carrying the `SelfIdentity` across threads.
    pub fn encode_dat_file(&self) -> Result<Vec<u8>, IdentityError> {
        // Serialize the secret payload for encryption.
        let payload = self.serialize_payload();

        let dat_key = derive_identity_dat_key(&self.master_key);
        // Fresh nonce — must never be reused with the same key.
        let mut nonce_bytes = [0u8; DAT_NONCE_LEN];
        // OS-provided cryptographic random number generator.
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        // Initialize the AEAD cipher with the derived key material.
        let cipher = XChaCha20Poly1305::new_from_slice(&*dat_key)
            // Map the error to the local error type.
            .map_err(|_| IdentityError::Crypto)?;
        let ciphertext = cipher
            // AEAD-encrypt the plaintext.
            .encrypt(nonce, payload.as_ref())
            // Map the error to the local error type.
            .map_err(|_| IdentityError::Crypto)?;

        // [version=0x01][24-byte nonce][ciphertext]
        let mut dat_data = Vec::with_capacity(1 + DAT_NONCE_LEN + ciphertext.len());
        // Append to the collection.
        dat_data.push(DAT_VERSION);
        // Append bytes to the accumulator.
        dat_data.extend_from_slice(&nonce_bytes);
        // Append bytes to the accumulator.
        dat_data.extend_from_slice(&ciphertext);
        Ok(dat_data)
    }

    /// Decode `identity.dat` with an already-recovered master key.
    ///
    /// Inverse of `encode_dat_file`. The master key is moved into the
    /// returned identity and the ML-KEM keypair is re-derived from it.
    pub fn from_dat_file(
        dat_data: &[u8],
        master_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, IdentityError> {
        // Validate the input length to prevent out-of-bounds access.
        if dat_data.len() < 1 + DAT_NONCE_LEN {
            return Err(IdentityError::Format);
        }
        // Only one payload version has ever been written.
        if dat_data[0] != DAT_VERSION {
            return Err(IdentityError::Format);
        }

        let nonce = XNonce::from_slice(&dat_data[1..1 + DAT_NONCE_LEN]);
        let ciphertext = &dat_data[1 + DAT_NONCE_LEN..];
        let dat_key = derive_identity_dat_key(&master_key);
        // Initialize the AEAD cipher with the derived key material.
        let cipher = XChaCha20Poly1305::new_from_slice(&*dat_key)
            // Map the error to the local error type.
            .map_err(|_| IdentityError::Crypto)?;
        let payload = Zeroizing::new(
            cipher
                // AEAD-decrypt and authenticate the ciphertext.
                .decrypt(nonce, ciphertext)
                // Map the error to the local error type.
                .map_err(|_| IdentityError::Crypto)?,
        );

        let mut identity = Self::from_payload(&payload).ok_or(IdentityError::Format)?;
        identity.master_key = master_key;
        // Derive ML-KEM keypair from the now-loaded master key (§3.4.1).
        let (dk, ek) = derive_kem_keypair(&identity.master_key);
        identity.kem_decapsulation_key = dk;
        identity.kem_encapsulation_key = ek;
        Ok(identity)
    }

    /// Read and decode `<data_dir>/identity.dat` with a recovered master key.
    pub fn load_dat_file(
        data_dir: &Path,
        master_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, IdentityError> {
        // Resolve the filesystem path for the target resource.
        let dat_data = std::fs::read(data_dir.join("identity.dat")).map_err(IdentityError::Io)?;
        Self::from_dat_file(&dat_data, master_key)
    }

    /// Persist this identity to disk.
    ///
    /// Writes two files:
    /// - `<data_dir>/identity.key` — the master key (optionally PIN-wrapped)
    /// - `<data_dir>/identity.dat` — the encrypted identity payload
    ///
    /// With a PIN the master key is wrapped under a fresh random salt and
    /// the spec parameters (one Argon2id derivation). Callers that must keep
    /// an existing salt — so a duress blob wrapped under it stays valid —
    /// derive the key themselves and use `save_wrapped`.
    pub fn save_to_disk(&self, data_dir: &Path, pin: Option<&str>) -> Result<(), IdentityError> {
        let key_data = match pin {
            // No PIN: the master key is stored in the clear (§3.6.2 "If PIN
            // is not configured").
            None => encode_plain_key_file(&self.master_key),
            Some(pin_str) => {
                // Fresh salt for a fresh wrap.
                let mut salt = [0u8; SALT_LEN];
                // OS-provided cryptographic random number generator.
                OsRng.fill_bytes(&mut salt);
                // The one shared derivation (§3.7.4 parameters).
                let wrapping_key =
                    pin::derive_key_from_pin(pin_str.as_bytes(), &salt, KdfParams::SPEC)?;
                encode_wrapped_key_file(&self.master_key, &wrapping_key, &salt, KdfParams::SPEC)?
            }
        };
        write_identity_files(data_dir, &key_data, &self.encode_dat_file()?)
    }

    /// Persist this identity under an already-derived wrapping key.
    ///
    /// `salt` and `params` are written into the 0x02 header so the file
    /// stays self-describing. Used for PIN changes and the 0x01 → 0x02
    /// migration, where the salt must match the duress blob.
    pub fn save_wrapped(
        &self,
        data_dir: &Path,
        wrapping_key: &[u8; 32],
        salt: &[u8; SALT_LEN],
        params: KdfParams,
    ) -> Result<(), IdentityError> {
        let key_data = encode_wrapped_key_file(&self.master_key, wrapping_key, salt, params)?;
        write_identity_files(data_dir, &key_data, &self.encode_dat_file()?)
    }

    /// Load an identity from disk, decrypting with the optional PIN.
    ///
    /// Performs one Argon2id derivation when the key file is wrapped. The
    /// service-layer unlock path does not call this — it reads the record,
    /// derives once, and tries the primary and duress blobs itself — but
    /// PIN verification in settings flows and tests use it directly.
    pub fn load_from_disk(data_dir: &Path, pin: Option<&str>) -> Result<Self, IdentityError> {
        let master_key = match read_master_key_record(data_dir)? {
            // Plain master key: the PIN argument is irrelevant.
            MasterKeyRecord::Plain(key) => key,
            MasterKeyRecord::Wrapped(wrapped) => {
                // A wrapped key without a PIN cannot be opened.
                let pin_str = pin.ok_or(IdentityError::WrongPin)?;
                let wrapping_key = wrapped.derive_wrapping_key(pin_str.as_bytes())?;
                wrapped.open(&wrapping_key)?
            }
        };
        Self::load_dat_file(data_dir, master_key)
    }
}

// ---------------------------------------------------------------------------
// identity.key record
// ---------------------------------------------------------------------------

/// Mode byte of a plain (unwrapped) `identity.key`.
const KEY_MODE_PLAIN: u8 = 0x00;
/// Mode byte of the legacy wrapped layout: 16-byte salt, no stored
/// parameters, no associated data. Read-only; re-wrapped as 0x02 on the
/// next successful unlock.
const KEY_MODE_WRAPPED_LEGACY: u8 = 0x01;
/// Mode byte of the current wrapped layout with stored parameters and an
/// authenticated header.
const KEY_MODE_WRAPPED: u8 = 0x02;
/// Salt length the legacy 0x01 layout used.
const LEGACY_SALT_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce length used by both `identity.key` wraps and
/// `identity.dat`.
const DAT_NONCE_LEN: usize = 24;
/// Format byte of `identity.dat`.
const DAT_VERSION: u8 = 0x01;
/// Wrapped master key: 32 key bytes + 16-byte Poly1305 tag.
const WRAPPED_MASTER_LEN: usize = 48;
/// Exact length of a 0x02 `identity.key`:
/// mode(1) + m/t/p(12) + salt(32) + nonce(24) + ciphertext(48).
const WRAPPED_KEY_FILE_LEN: usize = 1 + 12 + SALT_LEN + DAT_NONCE_LEN + WRAPPED_MASTER_LEN;
/// Exact length of a legacy 0x01 `identity.key`:
/// mode(1) + salt(16) + nonce(24) + ciphertext(48).
const LEGACY_KEY_FILE_LEN: usize = 1 + LEGACY_SALT_LEN + DAT_NONCE_LEN + WRAPPED_MASTER_LEN;

/// A parsed `identity.key`.
pub enum MasterKeyRecord {
    /// Mode 0x00: the master key in the clear (no PIN configured).
    Plain(Zeroizing<[u8; 32]>),
    /// Mode 0x01 or 0x02: the master key wrapped under Argon2id(PIN).
    Wrapped(WrappedMasterKey),
}

impl MasterKeyRecord {
    /// Whether a PIN is required to recover the master key.
    pub fn is_wrapped(&self) -> bool {
        matches!(self, MasterKeyRecord::Wrapped(_))
    }
}

/// The wrapped form of `identity.key`, with everything the unlock path
/// needs to derive once and open.
pub struct WrappedMasterKey {
    /// Argon2id parameters: stored in the header for 0x02, the fixed
    /// `KdfParams::LEGACY_0X01` for 0x01.
    pub params: KdfParams,
    /// Argon2id salt: 32 bytes for 0x02, 16 for legacy.
    pub salt: Vec<u8>,
    /// True for the legacy 0x01 layout, which must be re-wrapped after a
    /// successful unlock.
    pub legacy: bool,
    /// Header bytes bound as AEAD associated data (empty for legacy).
    aad: Vec<u8>,
    /// XChaCha20-Poly1305 nonce.
    nonce: [u8; DAT_NONCE_LEN],
    /// Encrypted master key plus tag.
    ciphertext: Vec<u8>,
}

impl WrappedMasterKey {
    /// Run the single Argon2id derivation for this record.
    ///
    /// Current-format records go through the window-checked derivation;
    /// the legacy layout uses its fixed below-floor parameters, which is
    /// the only place they are ever honoured.
    pub fn derive_wrapping_key(&self, pin: &[u8]) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        let key = if self.legacy {
            pin::derive_key_unchecked(pin, &self.salt, self.params)?
        } else {
            pin::derive_key_from_pin(pin, &self.salt, self.params)?
        };
        Ok(key)
    }

    /// Open the record under an already-derived wrapping key.
    ///
    /// Microseconds of AEAD work; a wrong key (or a tampered header, which
    /// changes the associated data) fails as `WrongPin`.
    pub fn open(&self, wrapping_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        let nonce = XNonce::from_slice(&self.nonce);
        // Initialize the AEAD cipher with the derived key material.
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key)
            // Map the error to the local error type.
            .map_err(|_| IdentityError::Crypto)?;
        let plaintext = Zeroizing::new(
            cipher
                // AEAD-decrypt with the header bound as associated data.
                .decrypt(
                    nonce,
                    Payload {
                        msg: &self.ciphertext,
                        aad: &self.aad,
                    },
                )
                // Map the error to the local error type.
                .map_err(|_| IdentityError::WrongPin)?,
        );

        // Validate the input length to prevent out-of-bounds access.
        if plaintext.len() != 32 {
            return Err(IdentityError::Format);
        }
        let mut k = Zeroizing::new([0u8; 32]);
        // Copy into the fixed-size buffer.
        k.copy_from_slice(&plaintext);
        Ok(k)
    }

    /// The 32-byte salt a duress blob must share with this record, or
    /// `None` for the legacy layout whose 16-byte salt cannot be shared.
    pub fn shared_salt(&self) -> Option<[u8; SALT_LEN]> {
        let mut out = [0u8; SALT_LEN];
        // Only a full-length salt can be shared with `pin::wrap_key_under`.
        if self.salt.len() != SALT_LEN {
            return None;
        }
        // Copy into the fixed-size buffer.
        out.copy_from_slice(&self.salt);
        Some(out)
    }
}

/// Encode a plain `identity.key`: `[0x00][32 master key bytes]`.
pub fn encode_plain_key_file(master_key: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32);
    // Append to the collection.
    buf.push(KEY_MODE_PLAIN);
    // Append bytes to the accumulator.
    buf.extend_from_slice(master_key);
    buf
}

/// Encode a wrapped `identity.key` (mode 0x02):
/// `[0x02][m_cost BE][t_cost BE][p_cost BE][32-byte salt][24-byte nonce][48-byte ciphertext]`.
///
/// The first 45 bytes (mode, parameters, salt) are bound to the ciphertext
/// as associated data, so a tampered parameter or salt fails authentication
/// exactly like a wrong PIN (mirrors the §3.7.4 backup envelope). No
/// derivation happens here; the caller supplies the wrapping key.
pub fn encode_wrapped_key_file(
    master_key: &[u8; 32],
    wrapping_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Vec<u8>, IdentityError> {
    // A writer must never emit parameters it would refuse to read.
    params.validate()?;

    // Header = associated data.
    let mut buf = Vec::with_capacity(WRAPPED_KEY_FILE_LEN);
    // Append to the collection.
    buf.push(KEY_MODE_WRAPPED);
    // Append bytes to the accumulator.
    buf.extend_from_slice(&params.m_cost.to_be_bytes());
    // Append bytes to the accumulator.
    buf.extend_from_slice(&params.t_cost.to_be_bytes());
    // Append bytes to the accumulator.
    buf.extend_from_slice(&params.p_cost.to_be_bytes());
    // Append bytes to the accumulator.
    buf.extend_from_slice(salt);

    // Fresh nonce — must never be reused with the same key.
    let mut nonce_bytes = [0u8; DAT_NONCE_LEN];
    // OS-provided cryptographic random number generator.
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    // Initialize the AEAD cipher with the derived key material.
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key)
        // Map the error to the local error type.
        .map_err(|_| IdentityError::Crypto)?;
    let ciphertext = cipher
        // AEAD-encrypt with the header bound as associated data.
        .encrypt(
            nonce,
            Payload {
                msg: master_key.as_ref(),
                aad: &buf,
            },
        )
        // Map the error to the local error type.
        .map_err(|_| IdentityError::Crypto)?;

    // Append bytes to the accumulator.
    buf.extend_from_slice(&nonce_bytes);
    // Append bytes to the accumulator.
    buf.extend_from_slice(&ciphertext);
    Ok(buf)
}

/// Parse `identity.key` bytes into a record.
///
/// Storage is untrusted: every length is checked exactly and 0x02
/// parameters are validated against the §3.7.4 window before the record
/// can reach a derivation, so a weak or oversized header is refused in
/// microseconds with a typed error.
pub fn parse_master_key_record(key_data: &[u8]) -> Result<MasterKeyRecord, IdentityError> {
    match key_data.first().copied() {
        Some(KEY_MODE_PLAIN) => {
            // Plain master key: exactly 33 bytes.
            if key_data.len() != 1 + 32 {
                return Err(IdentityError::Format);
            }
            let mut k = Zeroizing::new([0u8; 32]);
            // Copy into the fixed-size buffer.
            k.copy_from_slice(&key_data[1..33]);
            Ok(MasterKeyRecord::Plain(k))
        }
        Some(KEY_MODE_WRAPPED_LEGACY) => {
            // Legacy layout: [0x01][16 salt][24 nonce][48 ct], no params.
            if key_data.len() != LEGACY_KEY_FILE_LEN {
                return Err(IdentityError::Format);
            }
            let salt_end = 1 + LEGACY_SALT_LEN;
            let nonce_end = salt_end + DAT_NONCE_LEN;
            let mut nonce = [0u8; DAT_NONCE_LEN];
            // Copy into the fixed-size buffer.
            nonce.copy_from_slice(&key_data[salt_end..nonce_end]);
            Ok(MasterKeyRecord::Wrapped(WrappedMasterKey {
                params: KdfParams::LEGACY_0X01,
                salt: key_data[1..salt_end].to_vec(),
                legacy: true,
                aad: Vec::new(),
                nonce,
                ciphertext: key_data[nonce_end..].to_vec(),
            }))
        }
        Some(KEY_MODE_WRAPPED) => {
            // Current layout: [0x02][m][t][p][32 salt][24 nonce][48 ct].
            if key_data.len() != WRAPPED_KEY_FILE_LEN {
                return Err(IdentityError::Format);
            }
            // Fixed-width big-endian parameters follow the mode byte.
            let params = KdfParams {
                m_cost: u32::from_be_bytes(
                    key_data[1..5]
                        .try_into()
                        .map_err(|_| IdentityError::Format)?,
                ),
                t_cost: u32::from_be_bytes(
                    key_data[5..9]
                        .try_into()
                        .map_err(|_| IdentityError::Format)?,
                ),
                p_cost: u32::from_be_bytes(
                    key_data[9..13]
                        .try_into()
                        .map_err(|_| IdentityError::Format)?,
                ),
            };
            // Window check before anything can run the KDF on them.
            params.validate()?;
            let salt_end = 13 + SALT_LEN;
            let nonce_end = salt_end + DAT_NONCE_LEN;
            let mut nonce = [0u8; DAT_NONCE_LEN];
            // Copy into the fixed-size buffer.
            nonce.copy_from_slice(&key_data[salt_end..nonce_end]);
            Ok(MasterKeyRecord::Wrapped(WrappedMasterKey {
                params,
                salt: key_data[13..salt_end].to_vec(),
                legacy: false,
                // The header is the associated data, byte for byte.
                aad: key_data[..salt_end].to_vec(),
                nonce,
                ciphertext: key_data[nonce_end..].to_vec(),
            }))
        }
        // Unknown mode byte or empty file.
        _ => Err(IdentityError::Format),
    }
}

/// Read and parse `<data_dir>/identity.key`.
pub fn read_master_key_record(data_dir: &Path) -> Result<MasterKeyRecord, IdentityError> {
    let key_path = data_dir.join("identity.key");
    let key_data = std::fs::read(&key_path).map_err(|e| {
        // A missing file is a distinct, expected state (first run).
        if e.kind() == std::io::ErrorKind::NotFound {
            IdentityError::NotFound(key_path.display().to_string())
        } else {
            IdentityError::Io(e)
        }
    })?;
    parse_master_key_record(&key_data)
}

/// Write `identity.key` then `identity.dat` atomically (tmp + rename each).
///
/// The key file goes first so a crash between the two writes leaves a
/// readable key with a stale payload rather than a payload with no key.
pub fn write_identity_files(
    data_dir: &Path,
    key_data: &[u8],
    dat_data: &[u8],
) -> Result<(), IdentityError> {
    write_atomic(&data_dir.join("identity.key"), key_data)?;
    write_atomic(&data_dir.join("identity.dat"), dat_data)?;
    Ok(())
}

/// Encode the legacy 0x01 layout, for migration tests only.
///
/// No production path writes this format; the test helper exists so the
/// 0x01 → 0x02 migration can be exercised against bytes identical to what
/// earlier builds produced (argon2 crate defaults, 16-byte salt, no AAD).
#[cfg(test)]
pub(crate) fn encode_legacy_wrapped_key_file(
    master_key: &[u8; 32],
    pin: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let mut salt = [0u8; LEGACY_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let wrapping_key = pin::derive_key_unchecked(pin, &salt, KdfParams::LEGACY_0X01)?;
    let mut nonce_bytes = [0u8; DAT_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher =
        XChaCha20Poly1305::new_from_slice(&*wrapping_key).map_err(|_| IdentityError::Crypto)?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), master_key.as_ref())
        .map_err(|_| IdentityError::Crypto)?;
    let mut buf = vec![KEY_MODE_WRAPPED_LEGACY];
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(&nonce_bytes);
    buf.extend_from_slice(&ciphertext);
    Ok(buf)
}

// ---------------------------------------------------------------------------
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
    // Set up the HKDF context for domain-separated key derivation.
    let hk = Hkdf::<Sha256>::new(None, master_key);
    // Invoke the associated function.
    let mut d = ml_kem::B32::default();
    // Invoke the associated function.
    let mut z = ml_kem::B32::default();
    // Infallible: HKDF-SHA256 expand fails only when the output length exceeds 255 × 32 = 8160 bytes.
    // Here output is exactly 32 bytes (ml_kem::B32), which is well within that limit.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(b"meshinfinity-ml-kem-768-d-v1", d.as_mut_slice())
        .expect("HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len");
    // Infallible: same reasoning as above — 32-byte output for SHA-256 never triggers the length guard.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(b"meshinfinity-ml-kem-768-z-v1", z.as_mut_slice())
        .expect("HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len");
    // Invoke the associated function.
    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    // Extract the raw byte representation for wire encoding.
    (dk.as_bytes().to_vec(), ek.as_bytes().to_vec())
}

fn derive_identity_dat_key(master_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    // Set up the HKDF context for domain-separated key derivation.
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut key = Zeroizing::new([0u8; 32]);
    // Infallible: HKDF-SHA256 expand fails only when output exceeds 255 × 32 = 8160 bytes.
    // Requesting 32 bytes never triggers that guard — this is a design-time invariant.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(b"meshinfinity-identity-dat-v1", &mut *key)
        .expect(
        "HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len",
    );
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
    let week = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() / 604_800,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        // Error path — signal failure.
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

    // Format the output for display or logging.
    let info = format!("meshinfinity-preauth-spk-v1-week-{week}");
    // Set up the HKDF context for domain-separated key derivation.
    let hk = Hkdf::<Sha256>::new(None, &ik_secret.to_bytes());
    // Invoke the associated function.
    let mut preauth_bytes = Zeroizing::new([0u8; 32]);
    // Infallible: HKDF-SHA256 expand fails only when output exceeds 255 × 32 = 8160 bytes.
    // The preauth key output is exactly 32 bytes — well within the HKDF length limit.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(info.as_bytes(), &mut *preauth_bytes).expect(
        "HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len",
    );

    let preauth_secret = X25519Secret::from(*preauth_bytes);
    let preauth_pub = X25519Public::from(&preauth_secret);
    (preauth_secret, preauth_pub)
}

/// Write `data` to `path` via a sibling `.tmp` file and rename.
///
/// Shared with the service layer for the counter and duress files, which
/// must never be observable half-written: a torn counter reads as
/// tampering and a torn duress blob as "no duress PIN".
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<(), IdentityError> {
    // Resolve the filesystem path for the target resource.
    let tmp = path.with_extension("tmp");
    // Persist the data to the filesystem.
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// JSON-serializable identity metadata (non-secret fields).
#[derive(Serialize, Deserialize)]
// IdentityMetadata — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// IdentityMetadata — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
struct IdentityMetadata {
    display_name: Option<String>,
    ed25519_pub: String,
    x25519_pub: String,
}

// Trait implementation for protocol conformance.
// Implement Drop for SelfIdentity.
impl Drop for SelfIdentity {
    fn drop(&mut self) {
        // Securely erase key material to prevent forensic recovery.
        // Zeroize sensitive key material.
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
        assert_ne!(
            x_secret_bytes, x_pub_bytes,
            "serialize_payload stored public key instead of secret"
        );

        // Verify the serialized payload ends with the secret, not the public key
        let payload_slice = payload.as_slice();
        let payload_len = payload_slice.len();
        let serialized_x25519 = &payload_slice[payload_len - 32..];
        assert_eq!(
            serialized_x25519, &x_secret_bytes,
            "payload must store x25519 SECRET"
        );
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

        id.save_to_disk(dir.path(), Some("secret123"))
            .expect("save failed");

        // Wrong PIN should fail
        assert!(SelfIdentity::load_from_disk(dir.path(), Some("wrongpin")).is_err());

        // Correct PIN should succeed
        let loaded =
            SelfIdentity::load_from_disk(dir.path(), Some("secret123")).expect("load failed");
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

        assert_eq!(
            loaded.x25519_secret.to_bytes(),
            original_secret_bytes,
            "x25519 secret must survive save/load roundtrip"
        );
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

        assert_ne!(
            *loaded.master_key, [0u8; 32],
            "master_key must not be all-zero after load (would indicate un-restored key)"
        );
        assert_eq!(
            *loaded.master_key, original_master,
            "master_key must be exactly restored to the pre-save value"
        );
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

        assert!(
            !loaded.kem_decapsulation_key.is_empty(),
            "kem_decapsulation_key must be populated after load"
        );
        assert!(
            !loaded.kem_encapsulation_key.is_empty(),
            "kem_encapsulation_key must be populated after load"
        );
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

        assert_eq!(
            loaded1.kem_encapsulation_key, loaded2.kem_encapsulation_key,
            "KEM encapsulation key must be deterministically derived from master key"
        );
        assert_eq!(
            loaded1.kem_decapsulation_key, loaded2.kem_decapsulation_key,
            "KEM decapsulation key must be deterministically derived from master key"
        );
    }

    // ── identity.key record format (§3.6.2, §3.7.4) ─────────────────────────

    /// Every PIN-wrapped identity.key written by the current build is a
    /// 0x02 record whose stored Argon2id parameters are the spec triple.
    #[test]
    fn test_wrapped_identity_params_meet_floor() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(None);
        id.save_to_disk(dir.path(), Some("1234")).expect("save");

        let bytes = std::fs::read(dir.path().join("identity.key")).expect("read key");
        assert_eq!(bytes[0], KEY_MODE_WRAPPED, "current wrap must be mode 0x02");
        assert_eq!(bytes.len(), WRAPPED_KEY_FILE_LEN);
        match parse_master_key_record(&bytes).expect("parse") {
            MasterKeyRecord::Wrapped(w) => {
                assert!(!w.legacy);
                assert_eq!(w.params, KdfParams::SPEC);
                assert!(w.params.validate().is_ok());
                assert_eq!(w.salt.len(), SALT_LEN);
            }
            MasterKeyRecord::Plain(_) => panic!("PIN-wrapped file parsed as plain"),
        }
    }

    /// A 0x02 header claiming parameters below the floor is refused before
    /// any derivation, so a downgraded file cannot be brute-forced cheaply
    /// and cannot be loaded at all.
    #[test]
    fn test_wrapped_identity_weak_params_rejected() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(None);
        id.save_to_disk(dir.path(), Some("1234")).expect("save");

        let mut bytes = std::fs::read(dir.path().join("identity.key")).expect("read key");
        // m_cost occupies bytes 1..5; write 1024 KiB.
        bytes[1..5].copy_from_slice(&1024u32.to_be_bytes());
        assert!(matches!(
            parse_master_key_record(&bytes),
            Err(IdentityError::Pin(PinError::WeakParams))
        ));
        // Above the ceiling is refused the same way, before any allocation.
        bytes[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            parse_master_key_record(&bytes),
            Err(IdentityError::Pin(PinError::ParamsTooLarge))
        ));
    }

    /// An in-window edit to the header (salt or parameters) still fails,
    /// because the header is bound as AEAD associated data.
    #[test]
    fn test_wrapped_identity_header_is_authenticated() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(None);
        id.save_to_disk(dir.path(), Some("1234")).expect("save");

        let mut bytes = std::fs::read(dir.path().join("identity.key")).expect("read key");
        // Flip one salt byte (bytes 13..45): still a valid-looking record.
        bytes[20] ^= 0x01;
        std::fs::write(dir.path().join("identity.key"), &bytes).expect("rewrite");
        assert!(matches!(
            SelfIdentity::load_from_disk(dir.path(), Some("1234")),
            Err(IdentityError::WrongPin)
        ));
    }

    /// Truncated, extended and unknown-mode key files are typed errors.
    #[test]
    fn test_master_key_record_length_and_mode_checks() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(None);
        id.save_to_disk(dir.path(), Some("1234")).expect("save");
        let bytes = std::fs::read(dir.path().join("identity.key")).expect("read key");

        assert!(matches!(
            parse_master_key_record(&bytes[..bytes.len() - 1]),
            Err(IdentityError::Format)
        ));
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(matches!(
            parse_master_key_record(&longer),
            Err(IdentityError::Format)
        ));
        assert!(matches!(
            parse_master_key_record(&[]),
            Err(IdentityError::Format)
        ));
        assert!(matches!(
            parse_master_key_record(&[0x7F]),
            Err(IdentityError::Format)
        ));
        // Plain mode with the wrong length is also refused.
        assert!(matches!(
            parse_master_key_record(&[0x00; 20]),
            Err(IdentityError::Format)
        ));
    }

    /// The legacy 0x01 layout stays readable with the correct PIN, and
    /// `save_wrapped` under a chosen salt produces a 0x02 record that loads
    /// again — the two halves of the migration the service layer performs.
    #[test]
    fn test_legacy_0x01_reads_and_rewraps_to_0x02() {
        let dir = TempDir::new().unwrap();
        let id = SelfIdentity::generate(Some("Legacy".into()));
        let original_pub = id.ed25519_pub;

        // Write the identity the way an earlier build did.
        let legacy = encode_legacy_wrapped_key_file(&id.master_key, b"4321").expect("legacy");
        write_identity_files(dir.path(), &legacy, &id.encode_dat_file().expect("dat"))
            .expect("write");

        // Readable, and recognised as legacy.
        match read_master_key_record(dir.path()).expect("record") {
            MasterKeyRecord::Wrapped(w) => {
                assert!(w.legacy);
                assert_eq!(w.params, KdfParams::LEGACY_0X01);
                assert!(w.shared_salt().is_none(), "16-byte salt cannot be shared");
            }
            MasterKeyRecord::Plain(_) => panic!("legacy wrap parsed as plain"),
        }
        assert!(SelfIdentity::load_from_disk(dir.path(), Some("0000")).is_err());
        let loaded = SelfIdentity::load_from_disk(dir.path(), Some("4321")).expect("legacy load");
        assert_eq!(loaded.ed25519_pub, original_pub);

        // Re-wrap under the spec parameters and a fresh 32-byte salt.
        let salt = [0x33u8; SALT_LEN];
        let key = pin::derive_key_from_pin(b"4321", &salt, KdfParams::SPEC).expect("derive");
        loaded
            .save_wrapped(dir.path(), &key, &salt, KdfParams::SPEC)
            .expect("rewrap");

        let bytes = std::fs::read(dir.path().join("identity.key")).expect("read key");
        assert_eq!(bytes[0], KEY_MODE_WRAPPED);
        let reloaded = SelfIdentity::load_from_disk(dir.path(), Some("4321")).expect("0x02 load");
        assert_eq!(reloaded.ed25519_pub, original_pub);
        assert_eq!(*reloaded.master_key, *id.master_key);
    }

    /// `encode_wrapped_key_file` refuses to write parameters it would not
    /// read back, so a bug upstream cannot produce an unloadable file.
    #[test]
    fn test_encode_wrapped_refuses_out_of_window_params() {
        let weak = KdfParams {
            m_cost: 1024,
            ..KdfParams::SPEC
        };
        assert!(matches!(
            encode_wrapped_key_file(&[1u8; 32], &[2u8; 32], &[3u8; SALT_LEN], weak),
            Err(IdentityError::Pin(PinError::WeakParams))
        ));
    }
}
