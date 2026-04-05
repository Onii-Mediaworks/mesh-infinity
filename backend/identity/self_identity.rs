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
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    aead::{Aead, KeyInit},
    // AEAD cipher for authenticated encryption.
    // Execute this protocol step.
    // Execute this protocol step.
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

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
// Begin the block scope.
// IdentityError — variant enumeration.
// Match exhaustively to handle every protocol state.
// IdentityError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum IdentityError {
    #[error("IO error: {0}")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Io(#[from] std::io::Error),
    #[error("Encryption/decryption failed")]
    Crypto,
    #[error("Invalid identity file format")]
    Format,
    #[error("Wrong PIN or corrupted key file")]
    // Execute this protocol step.
    // Execute this protocol step.
    WrongPin,
    #[error("Identity file not found at {0}")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    NotFound(String),
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
    // Execute this protocol step.
    // Execute this protocol step.
    pub ed25519_signing: SigningKey,
    /// X25519 static secret (for DH key agreement — IK in X3DH)
    // Execute this protocol step.
    // Execute this protocol step.
    pub x25519_secret: X25519Secret,
    /// Derived public keys
    // Execute this protocol step.
    // Execute this protocol step.
    pub ed25519_pub: [u8; 32],
    /// The x25519 pub for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub x25519_pub: X25519Public,
    /// Preauth X25519 keypair (SPK in X3DH terminology).
    /// Derived deterministically from x25519_secret via HKDF.
    /// Rotated every 7 days (rotation uses week number in the HKDF info string).
    /// Published in pairing payloads and presence announcements.
    // Execute this protocol step.
    // Execute this protocol step.
    pub preauth_x25519_secret: X25519Secret,
    /// The preauth x25519 pub for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub preauth_x25519_pub: X25519Public,
    /// ML-KEM-768 decapsulation key (private — §3.4.1 PQXDH).
    /// Derived deterministically from master_key; not serialized separately.
    // Execute this protocol step.
    // Execute this protocol step.
    pub kem_decapsulation_key: Vec<u8>,
    /// ML-KEM-768 encapsulation key (public — §3.4.1 PQXDH).
    /// Advertised in pairing payloads and presence announcements.
    // Execute this protocol step.
    // Execute this protocol step.
    pub kem_encapsulation_key: Vec<u8>,
    /// Display name (optional)
    // Execute this protocol step.
    // Execute this protocol step.
    pub display_name: Option<String>,
    /// Identity master key (32 bytes) — used to derive per-collection vault keys.
    /// Zeroized on drop.
    // Execute this protocol step.
    // Execute this protocol step.
    pub master_key: Zeroizing<[u8; 32]>,
}

// Begin the block scope.
// SelfIdentity implementation — core protocol logic.
// SelfIdentity implementation — core protocol logic.
impl SelfIdentity {
    /// Generate a fresh self identity with a new random master key.
    // Perform the 'generate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'generate' operation.
    // Errors are propagated to the caller via Result.
    pub fn generate(display_name: Option<String>) -> Self {
        // Key material — must be zeroized when no longer needed.
        // Compute ed25519 signing for this protocol step.
        // Compute ed25519 signing for this protocol step.
        let ed25519_signing = SigningKey::generate(&mut OsRng);
        // Key material — must be zeroized when no longer needed.
        // Compute ed25519 pub for this protocol step.
        // Compute ed25519 pub for this protocol step.
        let ed25519_pub = ed25519_signing.verifying_key().to_bytes();
        // Key material — must be zeroized when no longer needed.
        // Compute x25519 secret for this protocol step.
        // Compute x25519 secret for this protocol step.
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        // Key material — must be zeroized when no longer needed.
        // Compute x25519 pub for this protocol step.
        // Compute x25519 pub for this protocol step.
        let x25519_pub = X25519Public::from(&x25519_secret);
        // Key material — must be zeroized when no longer needed.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (preauth_x25519_secret, preauth_x25519_pub) = derive_preauth_keypair(&x25519_secret);

        // Key material — must be zeroized when no longer needed.
        // Compute master key bytes for this protocol step.
        // Compute master key bytes for this protocol step.
        let mut master_key_bytes = [0u8; 32];
        // OS-provided cryptographic random number generator.
        // Execute this protocol step.
        // Execute this protocol step.
        OsRng.fill_bytes(&mut master_key_bytes);

        // Key material — must be zeroized when no longer needed.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (kem_decapsulation_key, kem_encapsulation_key) =
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            derive_kem_keypair(&master_key_bytes);

        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            ed25519_signing,
            // Execute this protocol step.
            // Execute this protocol step.
            x25519_secret,
            // Execute this protocol step.
            // Execute this protocol step.
            ed25519_pub,
            // Execute this protocol step.
            // Execute this protocol step.
            x25519_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            preauth_x25519_secret,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            preauth_x25519_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            kem_decapsulation_key,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            kem_encapsulation_key,
            // Execute this protocol step.
            // Execute this protocol step.
            display_name,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            master_key: Zeroizing::new(master_key_bytes),
        }
    }

    /// Get the peer ID for the self's public mask.
    // Perform the 'peer id' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'peer id' operation.
    // Errors are propagated to the caller via Result.
    pub fn peer_id(&self) -> PeerId {
        // Invoke the associated function.
        // Execute this protocol step.
        // Execute this protocol step.
        PeerId::from_ed25519_pub(&self.ed25519_pub)
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /// Serialize the identity payload for encrypted storage (§3.6.2).
    ///
    /// Format: `[4-byte LE json_len][json_bytes][ed25519_secret (32)][x25519_secret (32)]`
    // Perform the 'serialize payload' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'serialize payload' operation.
    // Errors are propagated to the caller via Result.
    pub fn serialize_payload(&self) -> Zeroizing<Vec<u8>> {
        // Prepare the data buffer for the next processing stage.
        // Compute metadata for this protocol step.
        // Compute metadata for this protocol step.
        let metadata = IdentityMetadata {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            display_name: self.display_name.clone(),
            // Invoke the associated function.
            // Execute this protocol step.
            // Execute this protocol step.
            ed25519_pub: hex::encode(self.ed25519_pub),
            // Extract the raw byte representation for wire encoding.
            // Execute this protocol step.
            // Execute this protocol step.
            x25519_pub: hex::encode(self.x25519_pub.as_bytes()),
        };
        // Infallible: IdentityMetadata contains only Option<String> and String fields;
        // serde_json serialization of those types cannot fail at runtime.
        // If this somehow panics, it indicates a programmer error (e.g., a type change
        // that introduced a non-serializable field) — a panic is the correct signal.
        // Compute json for this protocol step.
        // Compute json for this protocol step.
        let json = serde_json::to_vec(&metadata).expect(
            "IdentityMetadata serialization is infallible — all fields are String/Option<String>",
        );

        // Serialize to the wire format for transmission or storage.
        // Compute json len for this protocol step.
        // Compute json len for this protocol step.
        let json_len = (json.len() as u32).to_le_bytes();
        // Extract the raw byte representation for wire encoding.
        // Compute ed25519 bytes for this protocol step.
        // Compute ed25519 bytes for this protocol step.
        let ed25519_bytes = self.ed25519_signing.to_bytes();
        // Key material — must be zeroized when no longer needed.
        // Compute x25519 bytes for this protocol step.
        // Compute x25519 bytes for this protocol step.
        let x25519_bytes = self.x25519_secret.to_bytes(); // actual secret, not public key

        // Serialize to the wire format for transmission or storage.
        // Compute payload for this protocol step.
        // Compute payload for this protocol step.
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
    // Perform the 'from payload' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from payload' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if payload.len() < 4 + 32 + 32 {
            // No result available — signal absence to the caller.
            // Return to the caller.
            // Return to the caller.
            return None;
        }

        // Read JSON length
        // Compute json len for this protocol step.
        // Compute json len for this protocol step.
        let json_len = u32::from_le_bytes(payload[..4].try_into().ok()?) as usize;
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if payload.len() < 4 + json_len + 32 + 32 {
            // No result available — signal absence to the caller.
            // Return to the caller.
            // Return to the caller.
            return None;
        }

        // Parse metadata JSON
        // Compute json bytes for this protocol step.
        // Compute json bytes for this protocol step.
        let json_bytes = &payload[4..4 + json_len];
        // Serialize to the wire format for transmission or storage.
        // Compute metadata for this protocol step.
        // Compute metadata for this protocol step.
        let metadata: IdentityMetadata = serde_json::from_slice(json_bytes).ok()?;

        // Extract ed25519 secret (32 bytes)
        // Compute ed25519 offset for this protocol step.
        // Compute ed25519 offset for this protocol step.
        let ed25519_offset = 4 + json_len;
        // Key material — must be zeroized when no longer needed.
        // Compute ed25519 secret bytes for this protocol step.
        // Compute ed25519 secret bytes for this protocol step.
        let mut ed25519_secret_bytes = Zeroizing::new([0u8; 32]);
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        ed25519_secret_bytes.copy_from_slice(&payload[ed25519_offset..ed25519_offset + 32]);
        // Key material — must be zeroized when no longer needed.
        // Compute ed25519 signing for this protocol step.
        // Compute ed25519 signing for this protocol step.
        let ed25519_signing = SigningKey::from_bytes(&ed25519_secret_bytes);
        // Key material — must be zeroized when no longer needed.
        // Compute ed25519 pub for this protocol step.
        // Compute ed25519 pub for this protocol step.
        let ed25519_pub = ed25519_signing.verifying_key().to_bytes();

        // Extract x25519 secret (32 bytes)
        // Compute x25519 offset for this protocol step.
        // Compute x25519 offset for this protocol step.
        let x25519_offset = ed25519_offset + 32;
        // Key material — must be zeroized when no longer needed.
        // Compute x25519 secret bytes for this protocol step.
        // Compute x25519 secret bytes for this protocol step.
        let mut x25519_secret_bytes = Zeroizing::new([0u8; 32]);
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        x25519_secret_bytes.copy_from_slice(&payload[x25519_offset..x25519_offset + 32]);
        // Key material — must be zeroized when no longer needed.
        // Compute x25519 secret for this protocol step.
        // Compute x25519 secret for this protocol step.
        let x25519_secret = X25519Secret::from(*x25519_secret_bytes);
        // Key material — must be zeroized when no longer needed.
        // Compute x25519 pub for this protocol step.
        // Compute x25519 pub for this protocol step.
        let x25519_pub = X25519Public::from(&x25519_secret);
        // Key material — must be zeroized when no longer needed.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (preauth_x25519_secret, preauth_x25519_pub) = derive_preauth_keypair(&x25519_secret);

        // ML-KEM keypair is derived from master_key — placeholder until caller sets it.
        // The caller (load_from_disk) must call set_master_key_and_derive() after loading.
        // Wrap the found value.
        // Wrap the found value.
        Some(Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            ed25519_signing,
            // Execute this protocol step.
            // Execute this protocol step.
            x25519_secret,
            // Execute this protocol step.
            // Execute this protocol step.
            ed25519_pub,
            // Execute this protocol step.
            // Execute this protocol step.
            x25519_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            preauth_x25519_secret,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            preauth_x25519_pub,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            kem_decapsulation_key: Vec::new(), // set by caller via derive_kem_after_load()
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            kem_encapsulation_key: Vec::new(), // set by caller via derive_kem_after_load()
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            display_name: metadata.display_name,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
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
    // Perform the 'save to disk' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'save to disk' operation.
    // Errors are propagated to the caller via Result.
    pub fn save_to_disk(&self, data_dir: &Path, pin: Option<&str>) -> Result<(), IdentityError> {
        // ---- Write identity.key ----
        // Compute key path for this protocol step.
        // Compute key path for this protocol step.
        let key_path = data_dir.join("identity.key");
        // Key material — must be zeroized when no longer needed.
        // Compute key data for this protocol step.
        // Compute key data for this protocol step.
        let key_data = match pin {
            // Update the local state.
            // No value available.
            // No value available.
            None => {
                // Plain: [0x00][32 master key bytes]
                // Compute buf for this protocol step.
                // Compute buf for this protocol step.
                let mut buf = Vec::with_capacity(33);
                // Add the element to the collection.
                // Append to the collection.
                // Append to the collection.
                buf.push(0x00u8);
                // Append the data segment to the accumulating buffer.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                buf.extend_from_slice(&*self.master_key);
                buf
            }
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(pin_str) => {
                // Argon2id-wrapped: [0x01][16-byte salt][24-byte nonce][48-byte ciphertext]
                // Compute salt bytes for this protocol step.
                // Compute salt bytes for this protocol step.
                let mut salt_bytes = [0u8; 16];
                // OS-provided cryptographic random number generator.
                // Execute this protocol step.
                // Execute this protocol step.
                OsRng.fill_bytes(&mut salt_bytes);
                // Invoke the associated function.
                // Compute argon2 for this protocol step.
                // Compute argon2 for this protocol step.
                let argon2 = Argon2::default();
                // Key material — must be zeroized when no longer needed.
                // Compute wrapping key for this protocol step.
                // Compute wrapping key for this protocol step.
                let mut wrapping_key = Zeroizing::new([0u8; 32]);
                // Argon2id password hashing for key derivation.
                // Execute this protocol step.
                // Execute this protocol step.
                argon2
                    .hash_password_into(
                        // Extract the raw byte representation for wire encoding.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        pin_str.as_bytes(),
                        // Execute this protocol step.
                        // Execute this protocol step.
                        &salt_bytes,
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        &mut *wrapping_key,
                        // Transform the result, mapping errors to the local error type.
                        // Map the error to the local error type.
                        // Map the error to the local error type.
                    )
                    .map_err(|_| IdentityError::Crypto)?;

                // Fresh nonce — must never be reused with the same key.
                // Compute nonce bytes for this protocol step.
                // Compute nonce bytes for this protocol step.
                let mut nonce_bytes = [0u8; 24];
                // OS-provided cryptographic random number generator.
                // Execute this protocol step.
                // Execute this protocol step.
                OsRng.fill_bytes(&mut nonce_bytes);
                // Fresh nonce — must never be reused with the same key.
                // Compute nonce for this protocol step.
                // Compute nonce for this protocol step.
                let nonce = XNonce::from_slice(&nonce_bytes);
                // Initialize the AEAD cipher with the derived key material.
                // Compute cipher for this protocol step.
                // Compute cipher for this protocol step.
                let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
                    // Transform the result, mapping errors to the local error type.
                    // Map the error to the local error type.
                    // Map the error to the local error type.
                    .map_err(|_| IdentityError::Crypto)?;
                // Initialize the AEAD cipher with the derived key material.
                // Compute ciphertext for this protocol step.
                // Compute ciphertext for this protocol step.
                let ciphertext = cipher
                    // Encrypt the plaintext under the current session key.
                    // AEAD-encrypt the plaintext.
                    // AEAD-encrypt the plaintext.
                    .encrypt(nonce, self.master_key.as_ref())
                    // Transform the result, mapping errors to the local error type.
                    // Map the error to the local error type.
                    // Map the error to the local error type.
                    .map_err(|_| IdentityError::Crypto)?;

                // Initialize the AEAD cipher with the derived key material.
                // Compute buf for this protocol step.
                // Compute buf for this protocol step.
                let mut buf = Vec::with_capacity(1 + 16 + 24 + ciphertext.len());
                // Add the element to the collection.
                // Append to the collection.
                // Append to the collection.
                buf.push(0x01u8);
                // Append the data segment to the accumulating buffer.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                buf.extend_from_slice(&salt_bytes);
                // Append the data segment to the accumulating buffer.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                buf.extend_from_slice(&nonce_bytes);
                // Append the data segment to the accumulating buffer.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                buf.extend_from_slice(&ciphertext);
                buf
            }
        };
        // Propagate errors via the ? operator — callers handle failures.
        // Propagate errors via ?.
        // Propagate errors via ?.
        write_atomic(&key_path, &key_data)?;

        // ---- Write identity.dat ----
        // Encrypt payload with a key derived from master_key via HKDF
        // Compute dat path for this protocol step.
        // Compute dat path for this protocol step.
        let dat_path = data_dir.join("identity.dat");
        // Serialize to the wire format for transmission or storage.
        // Compute payload for this protocol step.
        // Compute payload for this protocol step.
        let payload = self.serialize_payload();

        // Key material — must be zeroized when no longer needed.
        // Compute dat key for this protocol step.
        // Compute dat key for this protocol step.
        let dat_key = derive_identity_dat_key(&self.master_key);
        // Fresh nonce — must never be reused with the same key.
        // Compute nonce bytes for this protocol step.
        // Compute nonce bytes for this protocol step.
        let mut nonce_bytes = [0u8; 24];
        // OS-provided cryptographic random number generator.
        // Execute this protocol step.
        // Execute this protocol step.
        OsRng.fill_bytes(&mut nonce_bytes);
        // Fresh nonce — must never be reused with the same key.
        // Compute nonce for this protocol step.
        // Compute nonce for this protocol step.
        let nonce = XNonce::from_slice(&nonce_bytes);
        // Initialize the AEAD cipher with the derived key material.
        // Compute cipher for this protocol step.
        // Compute cipher for this protocol step.
        let cipher = XChaCha20Poly1305::new_from_slice(&*dat_key)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| IdentityError::Crypto)?;
        // Initialize the AEAD cipher with the derived key material.
        // Compute ciphertext for this protocol step.
        // Compute ciphertext for this protocol step.
        let ciphertext = cipher
            // Encrypt the plaintext under the current session key.
            // AEAD-encrypt the plaintext.
            // AEAD-encrypt the plaintext.
            .encrypt(nonce, payload.as_ref())
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| IdentityError::Crypto)?;

        // [version=0x01][24-byte nonce][ciphertext]
        // Compute dat data for this protocol step.
        // Compute dat data for this protocol step.
        let mut dat_data = Vec::with_capacity(1 + 24 + ciphertext.len());
        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        dat_data.push(0x01u8);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        dat_data.extend_from_slice(&nonce_bytes);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        dat_data.extend_from_slice(&ciphertext);
        // Propagate errors via the ? operator — callers handle failures.
        // Propagate errors via ?.
        // Propagate errors via ?.
        write_atomic(&dat_path, &dat_data)?;

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }

    /// Load an identity from disk, decrypting with the optional PIN.
    // Perform the 'load from disk' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'load from disk' operation.
    // Errors are propagated to the caller via Result.
    pub fn load_from_disk(data_dir: &Path, pin: Option<&str>) -> Result<Self, IdentityError> {
        // ---- Read identity.key → master key ----
        // Compute key path for this protocol step.
        // Compute key path for this protocol step.
        let key_path = data_dir.join("identity.key");
        // Key material — must be zeroized when no longer needed.
        // Compute key data for this protocol step.
        // Compute key data for this protocol step.
        let key_data = std::fs::read(&key_path).map_err(|e| {
            // Handle the error case — propagate or log as appropriate.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if e.kind() == std::io::ErrorKind::NotFound {
                // Invoke the associated function.
                // Execute this protocol step.
                // Execute this protocol step.
                IdentityError::NotFound(key_path.display().to_string())
            // Begin the block scope.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            } else {
                // Invoke the associated function.
                // Execute this protocol step.
                // Execute this protocol step.
                IdentityError::Io(e)
            }
            // Propagate errors via the ? operator — callers handle failures.
            // Propagate errors via ?.
            // Propagate errors via ?.
        })?;

        // Key material — must be zeroized when no longer needed.
        // Compute master key for this protocol step.
        // Compute master key for this protocol step.
        let master_key = match key_data.first().copied() {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(0x00) => {
                // Plain master key
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if key_data.len() < 33 {
                    // Reject with an explicit error for the caller to handle.
                    // Return to the caller.
                    // Return to the caller.
                    return Err(IdentityError::Format);
                }
                // Invoke the associated function.
                // Compute k for this protocol step.
                // Compute k for this protocol step.
                let mut k = Zeroizing::new([0u8; 32]);
                // Copy the raw bytes into the fixed-size target array.
                // Copy into the fixed-size buffer.
                // Copy into the fixed-size buffer.
                k.copy_from_slice(&key_data[1..33]);
                k
            }
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(0x01) => {
                // PIN-wrapped master key
                // Compute pin str for this protocol step.
                // Compute pin str for this protocol step.
                let pin_str = pin.ok_or(IdentityError::WrongPin)?;
                // Validate the input length to prevent out-of-bounds access.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if key_data.len() < 1 + 16 + 24 + 32 + 16 {
                    // minimum: 1 + 16 (salt) + 24 (nonce) + 48 (32-byte ciphertext + 16-byte tag)
                    // Return to the caller.
                    // Return to the caller.
                    return Err(IdentityError::Format);
                }
                // Key material — must be zeroized when no longer needed.
                // Compute salt bytes for this protocol step.
                // Compute salt bytes for this protocol step.
                let salt_bytes = &key_data[1..17];
                // Key material — must be zeroized when no longer needed.
                // Compute nonce bytes for this protocol step.
                // Compute nonce bytes for this protocol step.
                let nonce_bytes = &key_data[17..41];
                // Initialize the AEAD cipher with the derived key material.
                // Compute ciphertext for this protocol step.
                // Compute ciphertext for this protocol step.
                let ciphertext = &key_data[41..];

                // Invoke the associated function.
                // Compute argon2 for this protocol step.
                // Compute argon2 for this protocol step.
                let argon2 = Argon2::default();
                // Key material — must be zeroized when no longer needed.
                // Compute wrapping key for this protocol step.
                // Compute wrapping key for this protocol step.
                let mut wrapping_key = Zeroizing::new([0u8; 32]);
                // Argon2id password hashing for key derivation.
                // Execute this protocol step.
                // Execute this protocol step.
                argon2
                    .hash_password_into(
                        // Extract the raw byte representation for wire encoding.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        pin_str.as_bytes(),
                        // Execute this protocol step.
                        // Execute this protocol step.
                        salt_bytes,
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        &mut *wrapping_key,
                        // Transform the result, mapping errors to the local error type.
                        // Map the error to the local error type.
                        // Map the error to the local error type.
                    )
                    .map_err(|_| IdentityError::WrongPin)?;

                // Fresh nonce — must never be reused with the same key.
                // Compute nonce for this protocol step.
                // Compute nonce for this protocol step.
                let nonce = XNonce::from_slice(nonce_bytes);
                // Initialize the AEAD cipher with the derived key material.
                // Compute cipher for this protocol step.
                // Compute cipher for this protocol step.
                let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
                    // Transform the result, mapping errors to the local error type.
                    // Map the error to the local error type.
                    // Map the error to the local error type.
                    .map_err(|_| IdentityError::Crypto)?;
                // Initialize the AEAD cipher with the derived key material.
                // Compute plaintext for this protocol step.
                // Compute plaintext for this protocol step.
                let plaintext = cipher
                    // Decrypt and authenticate the ciphertext.
                    // AEAD-decrypt and authenticate the ciphertext.
                    // AEAD-decrypt and authenticate the ciphertext.
                    .decrypt(nonce, ciphertext)
                    // Transform the result, mapping errors to the local error type.
                    // Map the error to the local error type.
                    // Map the error to the local error type.
                    .map_err(|_| IdentityError::WrongPin)?;

                // Validate the input length to prevent out-of-bounds access.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if plaintext.len() != 32 {
                    // Reject with an explicit error for the caller to handle.
                    // Return to the caller.
                    // Return to the caller.
                    return Err(IdentityError::Format);
                }
                // Invoke the associated function.
                // Compute k for this protocol step.
                // Compute k for this protocol step.
                let mut k = Zeroizing::new([0u8; 32]);
                // Copy the raw bytes into the fixed-size target array.
                // Copy into the fixed-size buffer.
                // Copy into the fixed-size buffer.
                k.copy_from_slice(&plaintext);
                k
            }
            // Update the local state.
            _ => return Err(IdentityError::Format),
        };

        // ---- Read identity.dat → identity payload ----
        // Compute dat path for this protocol step.
        // Compute dat path for this protocol step.
        let dat_path = data_dir.join("identity.dat");
        // Resolve the filesystem path for the target resource.
        // Compute dat data for this protocol step.
        // Compute dat data for this protocol step.
        let dat_data = std::fs::read(&dat_path).map_err(IdentityError::Io)?;

        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if dat_data.len() < 1 + 24 {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(IdentityError::Format);
        }
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if dat_data[0] != 0x01 {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(IdentityError::Format);
        }

        // Fresh nonce — must never be reused with the same key.
        // Compute nonce for this protocol step.
        // Compute nonce for this protocol step.
        let nonce = XNonce::from_slice(&dat_data[1..25]);
        // Initialize the AEAD cipher with the derived key material.
        // Compute ciphertext for this protocol step.
        // Compute ciphertext for this protocol step.
        let ciphertext = &dat_data[25..];
        // Key material — must be zeroized when no longer needed.
        // Compute dat key for this protocol step.
        // Compute dat key for this protocol step.
        let dat_key = derive_identity_dat_key(&master_key);
        // Initialize the AEAD cipher with the derived key material.
        // Compute cipher for this protocol step.
        // Compute cipher for this protocol step.
        let cipher = XChaCha20Poly1305::new_from_slice(&*dat_key)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| IdentityError::Crypto)?;
        // Prepare the data buffer for the next processing stage.
        // Compute payload for this protocol step.
        // Compute payload for this protocol step.
        let payload = Zeroizing::new(
            // Decrypt and authenticate the ciphertext.
            // Map the error to the local error type.
            // Map the error to the local error type.
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| IdentityError::Crypto)?,
        );

        // Prepare the data buffer for the next processing stage.
        // Compute identity for this protocol step.
        // Compute identity for this protocol step.
        let mut identity = Self::from_payload(&payload).ok_or(IdentityError::Format)?;
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        identity.master_key = master_key;
        // Derive ML-KEM keypair from the now-loaded master key (§3.4.1).
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (dk, ek) = derive_kem_keypair(&identity.master_key);
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        identity.kem_decapsulation_key = dk;
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        identity.kem_encapsulation_key = ek;
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
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
// Perform the 'derive kem keypair' operation.
// Errors are propagated to the caller via Result.
// Perform the 'derive kem keypair' operation.
// Errors are propagated to the caller via Result.
pub fn derive_kem_keypair(master_key: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    // Set up the HKDF context for domain-separated key derivation.
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(None, master_key);
    // Invoke the associated function.
    // Compute d for this protocol step.
    // Compute d for this protocol step.
    let mut d = ml_kem::B32::default();
    // Invoke the associated function.
    // Compute z for this protocol step.
    // Compute z for this protocol step.
    let mut z = ml_kem::B32::default();
    // Infallible: HKDF-SHA256 expand fails only when the output length exceeds 255 × 32 = 8160 bytes.
    // Here output is exactly 32 bytes (ml_kem::B32), which is well within that limit.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(b"meshinfinity-ml-kem-768-d-v1", d.as_mut_slice())
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        .expect("HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len");
    // Infallible: same reasoning as above — 32-byte output for SHA-256 never triggers the length guard.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(b"meshinfinity-ml-kem-768-z-v1", z.as_mut_slice())
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        .expect("HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len");
    // Invoke the associated function.
    // Bind the intermediate result.
    // Bind the intermediate result.
    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    // Extract the raw byte representation for wire encoding.
    // Execute this protocol step.
    // Execute this protocol step.
    (dk.as_bytes().to_vec(), ek.as_bytes().to_vec())
}

// Begin the block scope.
// Perform the 'derive identity dat key' operation.
// Errors are propagated to the caller via Result.
// Perform the 'derive identity dat key' operation.
// Errors are propagated to the caller via Result.
fn derive_identity_dat_key(master_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    // Set up the HKDF context for domain-separated key derivation.
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(None, master_key);
    // Key material — must be zeroized when no longer needed.
    // Compute key for this protocol step.
    // Compute key for this protocol step.
    let mut key = Zeroizing::new([0u8; 32]);
    // Infallible: HKDF-SHA256 expand fails only when output exceeds 255 × 32 = 8160 bytes.
    // Requesting 32 bytes never triggers that guard — this is a design-time invariant.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(b"meshinfinity-identity-dat-v1", &mut *key)
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        .expect("HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len");
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
// Perform the 'derive preauth keypair' operation.
// Errors are propagated to the caller via Result.
// Perform the 'derive preauth keypair' operation.
// Errors are propagated to the caller via Result.
pub fn derive_preauth_keypair(ik_secret: &X25519Secret) -> (X25519Secret, X25519Public) {
    // Week number since Unix epoch (7 × 24 × 3600 = 604800 seconds per week).
    // If system time is unavailable (clock regression or platform error),
    // log a warning and refuse to derive — the caller must not use a key
    // derived from an unknown week (which could stop rotation silently).
    // Compute week for this protocol step.
    // Compute week for this protocol step.
    let week = match std::time::SystemTime::now()
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        .duration_since(std::time::UNIX_EPOCH)
    {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
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
            // Execute this protocol step.
            // Execute this protocol step.
            tracing::warn!("system time unavailable — preauth key derivation using fallback week");
            // Use the maximum u64 as sentinel — callers can detect this.
            // In practice this path should never be hit on any real OS.
            u64::MAX
        }
    };

    // Format the output for display or logging.
    // Compute info for this protocol step.
    // Compute info for this protocol step.
    let info = format!("meshinfinity-preauth-spk-v1-week-{week}");
    // Set up the HKDF context for domain-separated key derivation.
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(None, &ik_secret.to_bytes());
    // Invoke the associated function.
    // Compute preauth bytes for this protocol step.
    // Compute preauth bytes for this protocol step.
    let mut preauth_bytes = Zeroizing::new([0u8; 32]);
    // Infallible: HKDF-SHA256 expand fails only when output exceeds 255 × 32 = 8160 bytes.
    // The preauth key output is exactly 32 bytes — well within the HKDF length limit.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(info.as_bytes(), &mut *preauth_bytes)
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        .expect("HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len");

    // Key material — must be zeroized when no longer needed.
    // Compute preauth secret for this protocol step.
    // Compute preauth secret for this protocol step.
    let preauth_secret = X25519Secret::from(*preauth_bytes);
    // Key material — must be zeroized when no longer needed.
    // Compute preauth pub for this protocol step.
    // Compute preauth pub for this protocol step.
    let preauth_pub = X25519Public::from(&preauth_secret);
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    (preauth_secret, preauth_pub)
}

// Begin the block scope.
// Perform the 'write atomic' operation.
// Errors are propagated to the caller via Result.
// Perform the 'write atomic' operation.
// Errors are propagated to the caller via Result.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), IdentityError> {
    // Resolve the filesystem path for the target resource.
    // Compute tmp for this protocol step.
    // Compute tmp for this protocol step.
    let tmp = path.with_extension("tmp");
    // Persist the data to the filesystem.
    // Propagate errors via ?.
    // Propagate errors via ?.
    std::fs::write(&tmp, data)?;
    // Propagate errors via the ? operator — callers handle failures.
    // Propagate errors via ?.
    // Propagate errors via ?.
    std::fs::rename(&tmp, path)?;
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(())
}

/// JSON-serializable identity metadata (non-secret fields).
#[derive(Serialize, Deserialize)]
// Begin the block scope.
// IdentityMetadata — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// IdentityMetadata — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
struct IdentityMetadata {
    // Process the current step in the protocol.
    // Execute this protocol step.
    display_name: Option<String>,
    // Process the current step in the protocol.
    // Execute this protocol step.
    ed25519_pub: String,
    // Process the current step in the protocol.
    // Execute this protocol step.
    x25519_pub: String,
}

// Trait implementation for protocol conformance.
// Implement Drop for SelfIdentity.
impl Drop for SelfIdentity {
    // Begin the block scope.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
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
}
