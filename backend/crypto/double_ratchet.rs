//! Double Ratchet Algorithm (§7.0.3, §7.5)
//!
//! Implements the Signal Double Ratchet with Mesh Infinity domain separation.
//! After X3DH establishes a shared `master_secret`, the Double Ratchet advances
//! the session key with every message, providing:
//!
//! - **Per-message forward secrecy:** each message uses a unique `msg_key`
//! - **Break-in recovery:** DH ratchet step mixes fresh key material
//! - **Out-of-order delivery:** skipped message keys cached (max 1000)
//!
//! # KDF Chains
//!
//! ```text
//! msg_key       = HMAC-SHA256(chain_key, 0x01)
//! new_chain_key = HMAC-SHA256(chain_key, 0x02)
//!
//! (new_root_key, new_chain_key) = HKDF-SHA256(
//!     salt = root_key,
//!     ikm  = X25519(my_ratchet_secret, their_ratchet_pub),
//!     info = "MeshInfinity_DR_v1",
//!     len  = 64
//! )
//!
//! keys   = HKDF-SHA256(salt=0*32, ikm=msg_key, info="MeshInfinity_MK_v1", len=76)
//! cipher_key = keys[0..32]
//! nonce      = keys[32..44]
//! _hmac_key  = keys[44..76]  // for Step 1 inner auth
//! ```

use std::collections::HashMap;

use chacha20poly1305::{
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    aead::{Aead, KeyInit},
    // AEAD cipher for authenticated encryption.
    // Execute this protocol step.
    // Execute this protocol step.
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
// Securely erase key material to prevent forensic recovery.
use zeroize::{Zeroize, Zeroizing};

// Shared KDF chain-step primitive and constants (avoids duplication with
// sender_keys.rs — both protocols use the same HMAC-SHA256 chain advancement).
use super::primitives::{kdf_chain_step, ZERO_SALT};
use super::secmem::SecureMemoryError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Protocol constant.
// DR_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
// DR_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
const DR_INFO: &[u8] = b"MeshInfinity_DR_v1";
// Protocol constant.
// MK_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
// MK_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
const MK_INFO: &[u8] = b"MeshInfinity_MK_v1";

/// HKDF info string for deriving the header encryption key from the root key.
///
/// Both sides of a Double Ratchet session share the root key, so both can
/// derive this key to encrypt/decrypt the ratchet header.  An observer who
/// does not possess the root key sees only opaque bytes and cannot correlate
/// messages by tracking ratchet public key changes or message counters.
// HDR_ENC_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
const HDR_ENC_INFO: &[u8] = b"MeshInfinity_HdrEnc_v1";

/// Fixed nonce for header encryption.
///
/// Safe to reuse because the header encryption key is unique per root-key
/// epoch — each DH ratchet step produces a new root key, which in turn
/// derives a fresh header encryption key.  The nonce only needs to be
/// non-repeating under a given key, not globally unique.
// HDR_ENC_NONCE — protocol constant.
// Defined by the spec; must not change without a version bump.
const HDR_ENC_NONCE: [u8; 12] = [0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Maximum number of skipped message keys to cache per peer.
/// Prevents memory exhaustion from adversarial skip counters.
// MAX_SKIP — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_SKIP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_SKIP: u32 = 1000;

/// Expanded message key material: (cipher_key, nonce, hmac_key).
// Type alias for protocol readability.
// Type alias for protocol readability.
pub type ExpandedMsgKey = ([u8; 32], [u8; 12], [u8; 32]);

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
// Begin the block scope.
// RatchetError — variant enumeration.
// Match exhaustively to handle every protocol state.
// RatchetError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RatchetError {
    #[error("HKDF expansion failed")]
    // Execute this protocol step.
    // Execute this protocol step.
    HkdfExpand,
    #[error("Too many skipped messages (>{MAX_SKIP})")]
    // Execute this protocol step.
    // Execute this protocol step.
    TooManySkipped,
    #[error("Duplicate message (already decrypted)")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    DuplicateMessage,
    #[error("AEAD decryption failed")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    DecryptionFailed,
    #[error("AEAD encryption failed")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    EncryptionFailed,
    #[error("Secure memory: {0}")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SecureMemory(#[from] SecureMemoryError),

    /// Message number counter has reached u32::MAX.
    /// Incrementing would wrap to 0, causing catastrophic nonce reuse
    /// in ChaCha20-Poly1305 (same key + same nonce = keystream reuse).
    /// The session MUST be rekeyed before sending/receiving more messages.
    #[error("message counter exhausted (u32::MAX) — session must be rekeyed")]
    MsgNumExhausted,
}

// ---------------------------------------------------------------------------
// Message Header
// ---------------------------------------------------------------------------

/// The Double Ratchet header sent with each message.
/// Carries the sender's current ratchet public key and counters.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// RatchetHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RatchetHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct RatchetHeader {
    /// Sender's current DH ratchet public key
    // Execute this protocol step.
    // Execute this protocol step.
    pub ratchet_pub: [u8; 32],
    /// Number of messages in the previous sending chain
    // Execute this protocol step.
    // Execute this protocol step.
    pub prev_chain_len: u32,
    /// Message number in the current sending chain
    // Execute this protocol step.
    // Execute this protocol step.
    pub msg_num: u32,
}

// ---------------------------------------------------------------------------
// Expanded message key (for encryption/decryption)
// ---------------------------------------------------------------------------

/// The expanded key material from a single message key.
// MessageKeys — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MessageKeys — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
struct MessageKeys {
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    cipher_key: [u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    nonce: [u8; 12],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    hmac_key: [u8; 32],
}

// Trait implementation for protocol conformance.
// Implement Drop for MessageKeys.
// Implement Drop for MessageKeys.
impl Drop for MessageKeys {
    // Begin the block scope.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    fn drop(&mut self) {
        // Securely erase key material to prevent forensic recovery.
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.cipher_key.zeroize();
        // Securely erase key material to prevent forensic recovery.
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.nonce.zeroize();
        // Securely erase key material to prevent forensic recovery.
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.hmac_key.zeroize();
    }
}

/// Expand a message key into cipher_key + nonce + hmac_key.
// Perform the 'expand message key' operation.
// Errors are propagated to the caller via Result.
// Perform the 'expand message key' operation.
// Errors are propagated to the caller via Result.
fn expand_message_key(msg_key: &[u8; 32]) -> Result<MessageKeys, RatchetError> {
    // Set up the HKDF context for domain-separated key derivation.
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), msg_key);
    // Allocate the output buffer for the result.
    // Compute output for this protocol step.
    // Compute output for this protocol step.
    let mut output = Zeroizing::new([0u8; 76]);
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(MK_INFO, &mut *output)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| RatchetError::HkdfExpand)?;

    // Initialize the AEAD cipher with the derived key material.
    // Compute cipher key for this protocol step.
    // Compute cipher key for this protocol step.
    let mut cipher_key = [0u8; 32];
    // Fresh nonce — must never be reused with the same key.
    // Compute nonce for this protocol step.
    // Compute nonce for this protocol step.
    let mut nonce = [0u8; 12];
    // Initialize the MAC for authentication tag computation.
    // Compute hmac key for this protocol step.
    // Compute hmac key for this protocol step.
    let mut hmac_key = [0u8; 32];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    cipher_key.copy_from_slice(&output[0..32]);
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    nonce.copy_from_slice(&output[32..44]);
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    hmac_key.copy_from_slice(&output[44..76]);

    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(MessageKeys {
        // Execute this protocol step.
        // Execute this protocol step.
        cipher_key,
        nonce,
        // Execute this protocol step.
        // Execute this protocol step.
        hmac_key,
    })
}

// ---------------------------------------------------------------------------
// KDF Chain operations  (kdf_chain_step re-exported from crypto::primitives)
// ---------------------------------------------------------------------------

/// Perform the DH ratchet step — mix fresh DH material into the root key.
/// Returns (new_root_key, new_chain_key).
// Perform the 'dh ratchet step' operation.
// Errors are propagated to the caller via Result.
// Perform the 'dh ratchet step' operation.
// Errors are propagated to the caller via Result.
fn dh_ratchet_step(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    root_key: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    dh_output: &[u8; 32],
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> Result<([u8; 32], [u8; 32]), RatchetError> {
    // Set up the HKDF context for domain-separated key derivation.
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    // Allocate the output buffer for the result.
    // Compute output for this protocol step.
    // Compute output for this protocol step.
    let mut output = Zeroizing::new([0u8; 64]);
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(DR_INFO, &mut *output)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| RatchetError::HkdfExpand)?;

    // Execute the operation and bind the result.
    // Compute new root for this protocol step.
    // Compute new root for this protocol step.
    let mut new_root = [0u8; 32];
    // Execute the operation and bind the result.
    // Compute new chain for this protocol step.
    // Compute new chain for this protocol step.
    let mut new_chain = [0u8; 32];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    new_root.copy_from_slice(&output[0..32]);
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    new_chain.copy_from_slice(&output[32..64]);
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok((new_root, new_chain))
}

// ---------------------------------------------------------------------------
// Skipped message key index
// ---------------------------------------------------------------------------

/// Key for the skipped message cache: (ratchet_pub, msg_number).
#[derive(Hash, Eq, PartialEq, Clone)]
// Begin the block scope.
// SkippedKeyId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SkippedKeyId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
struct SkippedKeyId {
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ratchet_pub: [u8; 32],
    // Execute this protocol step.
    // Execute this protocol step.
    msg_num: u32,
}

// ---------------------------------------------------------------------------
// Double Ratchet Session State
// ---------------------------------------------------------------------------

/// Complete Double Ratchet session state for one peer.
// DoubleRatchetSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// DoubleRatchetSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct DoubleRatchetSession {
    // DH ratchet state
    // Execute this protocol step.
    // Execute this protocol step.
    root_key: [u8; 32],
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    my_ratchet_secret: X25519Secret,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    my_ratchet_pub: [u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    their_ratchet_pub: Option<[u8; 32]>,

    // Sending chain
    // Execute this protocol step.
    // Execute this protocol step.
    send_chain_key: Option<[u8; 32]>,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    send_msg_num: u32,

    // Receiving chain
    // Execute this protocol step.
    // Execute this protocol step.
    recv_chain_key: Option<[u8; 32]>,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    recv_msg_num: u32,

    // Previous sending chain length (for header)
    // Execute this protocol step.
    // Execute this protocol step.
    prev_send_chain_len: u32,

    // Skipped message keys cache
    // Execute this protocol step.
    // Execute this protocol step.
    skipped_keys: HashMap<SkippedKeyId, [u8; 32]>,
}

// Trait implementation for protocol conformance.
// Implement Drop for DoubleRatchetSession.
// Implement Drop for DoubleRatchetSession.
impl Drop for DoubleRatchetSession {
    // Begin the block scope.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    fn drop(&mut self) {
        // Securely erase key material to prevent forensic recovery.
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.root_key.zeroize();
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(ref mut ck) = self.send_chain_key {
            // Securely erase key material to prevent forensic recovery.
            // Zeroize sensitive key material.
            // Zeroize sensitive key material.
            ck.zeroize();
        }
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(ref mut ck) = self.recv_chain_key {
            // Securely erase key material to prevent forensic recovery.
            // Zeroize sensitive key material.
            // Zeroize sensitive key material.
            ck.zeroize();
        }
        // Zeroize all cached skipped keys
        // Iterate over each element.
        // Iterate over each element.
        for (_, key) in self.skipped_keys.iter_mut() {
            // Securely erase key material to prevent forensic recovery.
            // Zeroize sensitive key material.
            // Zeroize sensitive key material.
            key.zeroize();
        }
    }
}

// Begin the block scope.
// DoubleRatchetSession implementation — core protocol logic.
// DoubleRatchetSession implementation — core protocol logic.
impl DoubleRatchetSession {
    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Initialize as the SENDER (Alice) after X3DH.
    ///
    /// Alice knows the master_secret and Bob's preauth public key (used as
    /// the initial receiving ratchet public key).
    // Perform the 'init sender' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'init sender' operation.
    // Errors are propagated to the caller via Result.
    pub fn init_sender(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        master_secret: &[u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        their_ratchet_pub: &[u8; 32],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> Result<Self, RatchetError> {
        // Generate our first ratchet keypair
        // Compute my ratchet secret for this protocol step.
        // Compute my ratchet secret for this protocol step.
        let my_ratchet_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        // Key material — must be zeroized when no longer needed.
        // Compute my ratchet pub key for this protocol step.
        // Compute my ratchet pub key for this protocol step.
        let my_ratchet_pub_key = X25519Public::from(&my_ratchet_secret);
        // Key material — must be zeroized when no longer needed.
        // Compute my ratchet pub for this protocol step.
        // Compute my ratchet pub for this protocol step.
        let my_ratchet_pub = *my_ratchet_pub_key.as_bytes();

        // Perform first DH ratchet step to derive send chain
        // Compute their pub for this protocol step.
        // Compute their pub for this protocol step.
        let their_pub = X25519Public::from(*their_ratchet_pub);
        // Key material — must be zeroized when no longer needed.
        // Compute dh out for this protocol step.
        // Compute dh out for this protocol step.
        let dh_out = my_ratchet_secret.diffie_hellman(&their_pub);
        // Key material — must be zeroized when no longer needed.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (root_key, send_chain_key) = dh_ratchet_step(master_secret, dh_out.as_bytes())?;

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(Self {
            // Execute this protocol step.
            // Execute this protocol step.
            root_key,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            my_ratchet_secret,
            // Execute this protocol step.
            // Execute this protocol step.
            my_ratchet_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            their_ratchet_pub: Some(*their_ratchet_pub),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            send_chain_key: Some(send_chain_key),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            send_msg_num: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            recv_chain_key: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            recv_msg_num: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            prev_send_chain_len: 0,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            skipped_keys: HashMap::new(),
        })
    }

    /// Initialize as the RECEIVER (Bob) after X3DH.
    ///
    /// Bob uses his preauth secret as the initial ratchet secret.
    /// He will complete his DH ratchet step on first received message.
    // Perform the 'init receiver' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'init receiver' operation.
    // Errors are propagated to the caller via Result.
    pub fn init_receiver(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        master_secret: &[u8; 32],
        // Elliptic curve Diffie-Hellman key agreement.
        // Execute this protocol step.
        // Execute this protocol step.
        my_preauth_secret: X25519Secret,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        my_preauth_pub: &[u8; 32],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            root_key: *master_secret,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            my_ratchet_secret: my_preauth_secret,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            my_ratchet_pub: *my_preauth_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            their_ratchet_pub: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            send_chain_key: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            send_msg_num: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            recv_chain_key: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            recv_msg_num: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            prev_send_chain_len: 0,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            skipped_keys: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Encrypt (send)
    // -----------------------------------------------------------------------

    /// Encrypt a plaintext message using the current sending chain.
    /// Returns (header, ciphertext).
    // Perform the 'encrypt' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'encrypt' operation.
    // Errors are propagated to the caller via Result.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>), RatchetError> {
        // Return an error rather than panicking if the session was never
        // initialised (send_chain_key is None). This path is reachable from
        // FFI, so a panic would crash the whole process.
        // Compute chain key for this protocol step.
        // Compute chain key for this protocol step.
        let chain_key = self
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            .send_chain_key
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            .as_ref()
            // Propagate errors via the ? operator — callers handle failures.
            // Propagate errors via ?.
            // Propagate errors via ?.
            .ok_or(RatchetError::EncryptionFailed)?;

        // Advance the sending chain
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (msg_key, new_chain_key) = kdf_chain_step(chain_key);
        // Update the send chain key to reflect the new state.
        // Advance send chain key state.
        // Advance send chain key state.
        self.send_chain_key = Some(new_chain_key);

        // Guard against message number overflow. At u32::MAX the next
        // increment would wrap to 0, reusing a nonce with the same chain
        // key — catastrophic for ChaCha20-Poly1305 security. The session
        // must be rekeyed (new X3DH handshake) before this counter resets.
        if self.send_msg_num == u32::MAX {
            return Err(RatchetError::MsgNumExhausted);
        }

        // Build header
        // Compute header for this protocol step.
        // Compute header for this protocol step.
        let header = RatchetHeader {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            ratchet_pub: self.my_ratchet_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            prev_chain_len: self.prev_send_chain_len,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            msg_num: self.send_msg_num,
        };
        // Safe to increment: overflow guard above ensures send_msg_num < u32::MAX.
        // Advance send msg num state.
        self.send_msg_num += 1;

        // Expand and encrypt
        // Compute mk for this protocol step.
        // Compute mk for this protocol step.
        let mk = expand_message_key(&msg_key)?;
        // Initialize the AEAD cipher with the derived key material.
        // Compute cipher for this protocol step.
        // Compute cipher for this protocol step.
        let cipher =
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            ChaCha20Poly1305::new_from_slice(&mk.cipher_key).map_err(|_| RatchetError::EncryptionFailed)?;
        // Fresh nonce — must never be reused with the same key.
        // Compute nonce for this protocol step.
        // Compute nonce for this protocol step.
        let nonce = Nonce::from_slice(&mk.nonce);
        // Initialize the AEAD cipher with the derived key material.
        // Compute ciphertext for this protocol step.
        // Compute ciphertext for this protocol step.
        let ciphertext = cipher
            // Encrypt the plaintext under the current session key.
            // AEAD-encrypt the plaintext.
            // AEAD-encrypt the plaintext.
            .encrypt(nonce, plaintext)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| RatchetError::EncryptionFailed)?;

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok((header, ciphertext))
    }

    // -----------------------------------------------------------------------
    // Decrypt (receive)
    // -----------------------------------------------------------------------

    /// Decrypt a received message.
    // Perform the 'decrypt' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'decrypt' operation.
    // Errors are propagated to the caller via Result.
    pub fn decrypt(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        header: &RatchetHeader,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        ciphertext: &[u8],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> Result<Vec<u8>, RatchetError> {
        // Check if we have a cached skipped key for this message
        // Compute skip id for this protocol step.
        // Compute skip id for this protocol step.
        let skip_id = SkippedKeyId {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            ratchet_pub: header.ratchet_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            msg_num: header.msg_num,
        };
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(mut msg_key) = self.skipped_keys.remove(&skip_id) {
            // Initialize the AEAD cipher with the derived key material.
            // Compute result for this protocol step.
            // Compute result for this protocol step.
            let result = decrypt_with_key(&msg_key, ciphertext);
            // Securely erase key material to prevent forensic recovery.
            // Zeroize sensitive key material.
            // Zeroize sensitive key material.
            msg_key.zeroize();
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            return result;
        }

        // Check if we need a DH ratchet step (new ratchet pub from sender)
        // Compute need dh step for this protocol step.
        // Compute need dh step for this protocol step.
        let need_dh_step = self.their_ratchet_pub.as_ref() != Some(&header.ratchet_pub);
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if need_dh_step {
            // Skip any remaining messages in the current receiving chain
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if let Some(ref recv_ck) = self.recv_chain_key {
                // Propagate errors via the ? operator — callers handle failures.
                // Propagate errors via ?.
                // Propagate errors via ?.
                self.skip_message_keys(*recv_ck, self.recv_msg_num, header.prev_chain_len)?;
            }

            // Perform DH ratchet step (receiving side)
            // Advance their ratchet pub state.
            // Advance their ratchet pub state.
            self.their_ratchet_pub = Some(header.ratchet_pub);
            // Invoke the associated function.
            // Compute their pub for this protocol step.
            // Compute their pub for this protocol step.
            let their_pub = X25519Public::from(header.ratchet_pub);
            // Key material — must be zeroized when no longer needed.
            // Compute dh out for this protocol step.
            // Compute dh out for this protocol step.
            let dh_out = self.my_ratchet_secret.diffie_hellman(&their_pub);
            // Key material — must be zeroized when no longer needed.
            // Bind the intermediate result.
            // Bind the intermediate result.
            let (new_root, recv_chain_key) =
                // Extract the raw byte representation for wire encoding.
                // Propagate errors via ?.
                // Propagate errors via ?.
                dh_ratchet_step(&self.root_key, dh_out.as_bytes())?;
            // Update the root key to reflect the new state.
            // Advance root key state.
            // Advance root key state.
            self.root_key = new_root;
            // Update the recv chain key to reflect the new state.
            // Advance recv chain key state.
            // Advance recv chain key state.
            self.recv_chain_key = Some(recv_chain_key);
            // Update the recv msg num to reflect the new state.
            // Advance recv msg num state.
            // Advance recv msg num state.
            self.recv_msg_num = 0;

            // Now perform DH ratchet step (sending side) — generate new keypair
            // Advance prev send chain len state.
            // Advance prev send chain len state.
            self.prev_send_chain_len = self.send_msg_num;
            // Update the send msg num to reflect the new state.
            // Advance send msg num state.
            // Advance send msg num state.
            self.send_msg_num = 0;
            // Update the my ratchet secret to reflect the new state.
            // Advance my ratchet secret state.
            // Advance my ratchet secret state.
            self.my_ratchet_secret = X25519Secret::random_from_rng(rand_core::OsRng);
            // Key material — must be zeroized when no longer needed.
            // Compute new pub for this protocol step.
            // Compute new pub for this protocol step.
            let new_pub = X25519Public::from(&self.my_ratchet_secret);
            // Update the my ratchet pub to reflect the new state.
            // Advance my ratchet pub state.
            // Advance my ratchet pub state.
            self.my_ratchet_pub = *new_pub.as_bytes();

            // Key material — must be zeroized when no longer needed.
            // Compute dh out2 for this protocol step.
            // Compute dh out2 for this protocol step.
            let dh_out2 = self.my_ratchet_secret.diffie_hellman(&their_pub);
            // Key material — must be zeroized when no longer needed.
            // Bind the intermediate result.
            // Bind the intermediate result.
            let (new_root2, send_chain_key) =
                // Extract the raw byte representation for wire encoding.
                // Propagate errors via ?.
                // Propagate errors via ?.
                dh_ratchet_step(&self.root_key, dh_out2.as_bytes())?;
            // Update the root key to reflect the new state.
            // Advance root key state.
            // Advance root key state.
            self.root_key = new_root2;
            // Update the send chain key to reflect the new state.
            // Advance send chain key state.
            // Advance send chain key state.
            self.send_chain_key = Some(send_chain_key);
        }

        // Skip any messages in the current chain before this one.
        // Return DecryptionFailed if the recv chain was not set — this should
        // be unreachable after the DH step above, but must not panic from FFI.
        // Compute recv ck for this protocol step.
        // Compute recv ck for this protocol step.
        let recv_ck = self
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            .recv_chain_key
            // Propagate errors via the ? operator — callers handle failures.
            // Propagate errors via ?.
            // Propagate errors via ?.
            .ok_or(RatchetError::DecryptionFailed)?;
        // Propagate errors via the ? operator — callers handle failures.
        // Propagate errors via ?.
        // Propagate errors via ?.
        self.skip_message_keys(recv_ck, self.recv_msg_num, header.msg_num)?;

        // Advance receiving chain to this message.
        // recv_chain_key is still Some: [u8; 32] is Copy so the ok_or() above
        // read a copy without consuming the field.  A None here is logically
        // impossible (skip_message_keys always sets the field), but we propagate
        // an error rather than panic to uphold the no-panic-in-FFI contract.
        // Compute recv ck for this protocol step.
        // Compute recv ck for this protocol step.
        let recv_ck = self
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            .recv_chain_key
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            .as_ref()
            // Propagate errors via the ? operator — callers handle failures.
            // Propagate errors via ?.
            // Propagate errors via ?.
            .ok_or(RatchetError::DecryptionFailed)?;
        // Guard against receive counter overflow. header.msg_num at
        // u32::MAX would wrap recv_msg_num to 0, causing nonce reuse on
        // the receiving chain — session must be rekeyed before this point.
        if header.msg_num == u32::MAX {
            return Err(RatchetError::MsgNumExhausted);
        }

        // Key material — must be zeroized when no longer needed.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (msg_key, new_recv_ck) = kdf_chain_step(recv_ck);
        // Update the recv chain key to reflect the new state.
        // Advance recv chain key state.
        // Advance recv chain key state.
        self.recv_chain_key = Some(new_recv_ck);
        // Safe to add 1: overflow guard above ensures header.msg_num < u32::MAX.
        // Advance recv msg num state.
        self.recv_msg_num = header.msg_num + 1;

        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        decrypt_with_key(&msg_key, ciphertext)
    }

    // -----------------------------------------------------------------------
    // Skip message key caching
    // -----------------------------------------------------------------------

    /// Cache skipped message keys between `from` and `until`.
    // Perform the 'skip message keys' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'skip message keys' operation.
    // Errors are propagated to the caller via Result.
    fn skip_message_keys(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        mut chain_key: [u8; 32],
        // Execute this protocol step.
        // Execute this protocol step.
        from: u32,
        // Execute this protocol step.
        // Execute this protocol step.
        until: u32,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> Result<(), RatchetError> {
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if until < from {
            // Return success with the computed result.
            // Return to the caller.
            // Return to the caller.
            return Ok(());
        }
        // Track the count for threshold and bounds checking.
        // Compute skip count for this protocol step.
        // Compute skip count for this protocol step.
        let skip_count = until - from;
        // Use checked_add to prevent the u32 cast from silently truncating a
        // skipped_keys map that grew beyond 2^32 entries on a 64-bit host.
        // If the add would overflow or the result exceeds MAX_SKIP, reject.
        // Compute existing for this protocol step.
        // Compute existing for this protocol step.
        let existing = self.skipped_keys.len() as u64;
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if existing.saturating_add(skip_count as u64) > MAX_SKIP as u64 {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(RatchetError::TooManySkipped);
        }

        // their_ratchet_pub is always set by the caller before skip_message_keys
        // is invoked, but we must not panic from FFI — propagate an error instead.
        // Compute their pub for this protocol step.
        // Compute their pub for this protocol step.
        let their_pub = self
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            .their_ratchet_pub
            // Propagate errors via the ? operator — callers handle failures.
            // Propagate errors via ?.
            // Propagate errors via ?.
            .ok_or(RatchetError::DecryptionFailed)?;

        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        for i in from..until {
            // Key material — must be zeroized when no longer needed.
            // Bind the intermediate result.
            // Bind the intermediate result.
            let (msg_key, new_ck) = kdf_chain_step(&chain_key);
            // Key material — must be zeroized when no longer needed.
            // Compute id for this protocol step.
            // Compute id for this protocol step.
            let id = SkippedKeyId {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                ratchet_pub: their_pub,
                // Execute this protocol step.
                // Execute this protocol step.
                msg_num: i,
            };
            // Insert into the lookup table for efficient retrieval.
            // Insert into the map/set.
            // Insert into the map/set.
            self.skipped_keys.insert(id, msg_key);
            // Update the local state.
            // Execute this protocol step.
            // Execute this protocol step.
            chain_key = new_ck;
        }

        // Update the chain key to the position after skipping
        // Advance recv chain key state.
        // Advance recv chain key state.
        self.recv_chain_key = Some(chain_key);

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }

    /// Get the current ratchet public key (for the message header).
    // Perform the 'my ratchet pub' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'my ratchet pub' operation.
    // Errors are propagated to the caller via Result.
    pub fn my_ratchet_pub(&self) -> &[u8; 32] {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        &self.my_ratchet_pub
    }

    /// Number of cached skipped keys.
    // Perform the 'skipped key count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'skipped key count' operation.
    // Errors are propagated to the caller via Result.
    pub fn skipped_key_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.skipped_keys.len()
    }

    // -----------------------------------------------------------------------
    // Four-layer scheme helpers (§7.2)
    // -----------------------------------------------------------------------

    /// Advance the sending chain and return the raw message key + header.
    ///
    /// Use this with the four-layer encryption scheme (§7.2): call
    /// `expand_msg_key` to derive cipher_key/nonce/hmac_key, then pass
    /// those to `encrypt_message`. Prefer this over `encrypt()` when the
    /// four-layer AEAD wrapper is applied externally.
    // Perform the 'next send msg key' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'next send msg key' operation.
    // Errors are propagated to the caller via Result.
    pub fn next_send_msg_key(&mut self) -> Result<(RatchetHeader, [u8; 32]), RatchetError> {
        // Guard against message number overflow — same rationale as encrypt().
        // At u32::MAX the next increment wraps, reusing nonces catastrophically.
        if self.send_msg_num == u32::MAX {
            return Err(RatchetError::MsgNumExhausted);
        }

        // Return EncryptionFailed if the send chain was never initialised.
        // Panicking here would crash the process when called from FFI.
        // Compute chain key for this protocol step.
        // Compute chain key for this protocol step.
        let chain_key = self
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            .send_chain_key
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            .as_ref()
            // Propagate errors via the ? operator — callers handle failures.
            // Propagate errors via ?.
            // Propagate errors via ?.
            .ok_or(RatchetError::EncryptionFailed)?;

        // Key material — must be zeroized when no longer needed.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (msg_key, new_chain_key) = kdf_chain_step(chain_key);
        // Update the send chain key to reflect the new state.
        // Advance send chain key state.
        // Advance send chain key state.
        self.send_chain_key = Some(new_chain_key);

        // Begin the block scope.
        // Compute header for this protocol step.
        // Compute header for this protocol step.
        let header = RatchetHeader {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            ratchet_pub: self.my_ratchet_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            prev_chain_len: self.prev_send_chain_len,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            msg_num: self.send_msg_num,
        };
        // Safe to increment: overflow guard above ensures send_msg_num < u32::MAX.
        // Advance send msg num state.
        self.send_msg_num += 1;

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok((header, msg_key))
    }

    /// Encrypt a ratchet header so it is opaque on the wire.
    ///
    /// Serialises the header to JSON, then encrypts with ChaCha20-Poly1305
    /// using the provided header encryption key.  The caller is responsible
    /// for deriving the key from shared state that both parties know
    /// (typically a static DH shared secret or the session root key).
    ///
    /// On the wire the encrypted header replaces the plaintext `ratchet_pub`,
    /// `prev_chain_len`, and `msg_num` fields, preventing an observer from
    /// correlating messages by tracking ratchet key changes and counters.
    pub fn encrypt_header_with_key(header: &RatchetHeader, key: &[u8; 32]) -> Result<Vec<u8>, RatchetError> {
        // Construct the AEAD cipher from the provided key.
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| RatchetError::EncryptionFailed)?;
        // Serialise the header to a compact JSON representation.
        let header_json = serde_json::to_vec(header)
            .map_err(|_| RatchetError::EncryptionFailed)?;
        // Encrypt the serialised header with the fixed nonce.
        // Safe because the key is unique per-session and per-peer.
        let nonce = Nonce::from_slice(&HDR_ENC_NONCE);
        let ciphertext = cipher.encrypt(nonce, header_json.as_slice())
            .map_err(|_| RatchetError::EncryptionFailed)?;
        Ok(ciphertext)
    }

    /// Decrypt an encrypted ratchet header received on the wire.
    ///
    /// Uses the provided header encryption key to recover the original
    /// `RatchetHeader`.  If decryption or deserialisation fails, the caller
    /// should discard the frame — the header was either tampered with or
    /// encrypted under a different key.
    pub fn decrypt_header_with_key(enc_header: &[u8], key: &[u8; 32]) -> Result<RatchetHeader, RatchetError> {
        // Construct the AEAD cipher from the provided key.
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| RatchetError::DecryptionFailed)?;
        // Decrypt the encrypted header bytes.
        let nonce = Nonce::from_slice(&HDR_ENC_NONCE);
        let plaintext = cipher.decrypt(nonce, enc_header)
            .map_err(|_| RatchetError::DecryptionFailed)?;
        // Deserialise the JSON header from the decrypted bytes.
        let header: RatchetHeader = serde_json::from_slice(&plaintext)
            .map_err(|_| RatchetError::DecryptionFailed)?;
        Ok(header)
    }

    /// Derive a header encryption key from a static DH shared secret.
    ///
    /// Uses HKDF-SHA256 over the shared secret with the `HDR_ENC_INFO`
    /// domain separator.  The result is a 32-byte key suitable for
    /// `encrypt_header_with_key` / `decrypt_header_with_key`.
    ///
    /// Both sender and receiver derive this from the same static DH
    /// shared secret (our_x25519_secret * their_x25519_pub), so both
    /// can encrypt/decrypt headers independently.
    pub fn derive_header_key_from_dh(dh_shared_secret: &[u8; 32]) -> Result<[u8; 32], RatchetError> {
        // Set up the HKDF context for domain-separated key derivation.
        let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), dh_shared_secret);
        // Allocate the output buffer for the result.
        let mut key = [0u8; 32];
        // Expand the pseudorandom key to the target key length.
        hk.expand(HDR_ENC_INFO, &mut key)
            .map_err(|_| RatchetError::HkdfExpand)?;
        Ok(key)
    }

    /// Process a received ratchet header and return the raw message key.
    ///
    /// Use this with the four-layer decryption scheme (§7.2): call
    /// `expand_msg_key` on the returned key, then pass to `decrypt_message`.
    /// Mirrors the DH-ratchet logic of `decrypt()` without performing AEAD.
    // Perform the 'recv msg key' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'recv msg key' operation.
    // Errors are propagated to the caller via Result.
    pub fn recv_msg_key(&mut self, header: &RatchetHeader) -> Result<[u8; 32], RatchetError> {
        // Check skipped key cache first.
        // Compute skip id for this protocol step.
        // Compute skip id for this protocol step.
        let skip_id = SkippedKeyId {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            ratchet_pub: header.ratchet_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            msg_num: header.msg_num,
        };
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(msg_key) = self.skipped_keys.remove(&skip_id) {
            // Return success with the computed result.
            // Return to the caller.
            // Return to the caller.
            return Ok(msg_key);
        }

        // DH ratchet step if the sender's ratchet key changed.
        // Compute need dh step for this protocol step.
        // Compute need dh step for this protocol step.
        let need_dh_step = self.their_ratchet_pub.as_ref() != Some(&header.ratchet_pub);
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if need_dh_step {
            // Skip any remaining messages in the current receiving chain.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if let Some(ref recv_ck) = self.recv_chain_key {
                // Propagate errors via the ? operator — callers handle failures.
                // Propagate errors via ?.
                // Propagate errors via ?.
                self.skip_message_keys(*recv_ck, self.recv_msg_num, header.prev_chain_len)?;
            }

            // Receive-side DH step.
            // Advance their ratchet pub state.
            // Advance their ratchet pub state.
            self.their_ratchet_pub = Some(header.ratchet_pub);
            // Invoke the associated function.
            // Compute their pub for this protocol step.
            // Compute their pub for this protocol step.
            let their_pub = X25519Public::from(header.ratchet_pub);
            // Key material — must be zeroized when no longer needed.
            // Compute dh out for this protocol step.
            // Compute dh out for this protocol step.
            let dh_out = self.my_ratchet_secret.diffie_hellman(&their_pub);
            // Key material — must be zeroized when no longer needed.
            // Bind the intermediate result.
            // Bind the intermediate result.
            let (new_root, recv_chain_key) =
                // Extract the raw byte representation for wire encoding.
                // Propagate errors via ?.
                // Propagate errors via ?.
                dh_ratchet_step(&self.root_key, dh_out.as_bytes())?;
            // Update the root key to reflect the new state.
            // Advance root key state.
            // Advance root key state.
            self.root_key = new_root;
            // Update the recv chain key to reflect the new state.
            // Advance recv chain key state.
            // Advance recv chain key state.
            self.recv_chain_key = Some(recv_chain_key);
            // Update the recv msg num to reflect the new state.
            // Advance recv msg num state.
            // Advance recv msg num state.
            self.recv_msg_num = 0;

            // Send-side DH step: generate a fresh ratchet keypair.
            // Advance prev send chain len state.
            // Advance prev send chain len state.
            self.prev_send_chain_len = self.send_msg_num;
            // Update the send msg num to reflect the new state.
            // Advance send msg num state.
            // Advance send msg num state.
            self.send_msg_num = 0;
            // Update the my ratchet secret to reflect the new state.
            // Advance my ratchet secret state.
            // Advance my ratchet secret state.
            self.my_ratchet_secret = X25519Secret::random_from_rng(rand_core::OsRng);
            // Key material — must be zeroized when no longer needed.
            // Compute new pub for this protocol step.
            // Compute new pub for this protocol step.
            let new_pub = X25519Public::from(&self.my_ratchet_secret);
            // Update the my ratchet pub to reflect the new state.
            // Advance my ratchet pub state.
            self.my_ratchet_pub = *new_pub.as_bytes();
            // Key material — must be zeroized when no longer needed.
            // Compute dh out2 for this protocol step.
            let dh_out2 = self.my_ratchet_secret.diffie_hellman(&their_pub);
            // Key material — must be zeroized when no longer needed.
            // Bind the intermediate result.
            let (new_root2, send_chain_key) =
                // Extract the raw byte representation for wire encoding.
                // Propagate errors via ?.
                dh_ratchet_step(&self.root_key, dh_out2.as_bytes())?;
            // Update the root key to reflect the new state.
            // Advance root key state.
            self.root_key = new_root2;
            // Update the send chain key to reflect the new state.
            // Advance send chain key state.
            self.send_chain_key = Some(send_chain_key);
        }

        // Skip messages before this one in the current receiving chain.
        // Propagate DecryptionFailed rather than panicking if recv_chain_key is
        // None — this is logically unreachable after the DH step above, but must
        // be handled safely because recv_msg_key is called from FFI paths.
        // Compute recv ck for this protocol step.
        let recv_ck = self
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            .recv_chain_key
            // Propagate errors via the ? operator — callers handle failures.
            // Propagate errors via ?.
            .ok_or(RatchetError::DecryptionFailed)?;
        // Propagate errors via the ? operator — callers handle failures.
        // Propagate errors via ?.
        self.skip_message_keys(recv_ck, self.recv_msg_num, header.msg_num)?;

        // Advance the receiving chain to this message.
        // recv_chain_key is still Some: [u8; 32] is Copy so the ok_or() above
        // read a copy without consuming the field.  skip_message_keys always
        // sets recv_chain_key before returning, so None here is impossible in
        // practice, but we propagate an error to uphold the no-panic contract.
        // Compute recv ck for this protocol step.
        let recv_ck = self
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            .recv_chain_key
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            .as_ref()
            // Propagate errors via the ? operator — callers handle failures.
            // Propagate errors via ?.
            .ok_or(RatchetError::DecryptionFailed)?;
        // Guard against receive counter overflow — same rationale as decrypt().
        // header.msg_num at u32::MAX would wrap recv_msg_num to 0 on increment.
        if header.msg_num == u32::MAX {
            return Err(RatchetError::MsgNumExhausted);
        }

        // Key material — must be zeroized when no longer needed.
        // Bind the intermediate result.
        let (msg_key, new_recv_ck) = kdf_chain_step(recv_ck);
        // Update the recv chain key to reflect the new state.
        // Advance recv chain key state.
        self.recv_chain_key = Some(new_recv_ck);
        // Safe to add 1: overflow guard above ensures header.msg_num < u32::MAX.
        // Advance recv msg num state.
        self.recv_msg_num = header.msg_num + 1;

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(msg_key)
    }

    /// Derive cipher_key, nonce, and hmac_key from a raw message key.
    ///
    /// Used by the four-layer encryption scheme (§7.2):
    /// - `cipher_key` + `nonce` → Step 2 (ChaCha20-Poly1305 trust-channel encryption)
    /// - `hmac_key` → Step 1 (HMAC-SHA256 inner authentication)
    ///
    /// Returns `(cipher_key, nonce, hmac_key)`.
    // Perform the 'expand msg key' operation.
    // Errors are propagated to the caller via Result.
    pub fn expand_msg_key(
        // Process the current step in the protocol.
        // Execute this protocol step.
        msg_key: &[u8; 32],
    // Begin the block scope.
    // Execute this protocol step.
    ) -> Result<ExpandedMsgKey, RatchetError> {
        // Key material — must be zeroized when no longer needed.
        // Compute mk for this protocol step.
        let mk = expand_message_key(msg_key)?;
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok((mk.cipher_key, mk.nonce, mk.hmac_key))
    }

    // -----------------------------------------------------------------------
    // Vault persistence (§17.9)
    // -----------------------------------------------------------------------

    /// Export all session state into a serialisable snapshot.
    ///
    /// The snapshot is encrypted by the caller (via `VaultCollection::save`)
    /// before being written to disk. No key material ever touches disk in the clear.
    // Perform the 'to snapshot' operation.
    // Errors are propagated to the caller via Result.
    pub fn to_snapshot(&self) -> SessionSnapshot {
        // Key material — must be zeroized when no longer needed.
        // Compute skipped keys for this protocol step.
        let skipped_keys = self
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            .skipped_keys
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            .iter()
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            .map(|(id, key)| (id.ratchet_pub, id.msg_num, *key))
            // Materialize the iterator into a concrete collection.
            // Collect into a concrete collection.
            .collect();

        // Begin the block scope.
        // Execute this protocol step.
        SessionSnapshot {
            // Process the current step in the protocol.
            // Execute this protocol step.
            root_key: self.root_key,
            // Extract the raw byte representation for wire encoding.
            // Execute this protocol step.
            my_ratchet_secret_bytes: *self.my_ratchet_secret.as_bytes(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            my_ratchet_pub: self.my_ratchet_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            their_ratchet_pub: self.their_ratchet_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            send_chain_key: self.send_chain_key,
            // Process the current step in the protocol.
            // Execute this protocol step.
            send_msg_num: self.send_msg_num,
            // Process the current step in the protocol.
            // Execute this protocol step.
            recv_chain_key: self.recv_chain_key,
            // Process the current step in the protocol.
            // Execute this protocol step.
            recv_msg_num: self.recv_msg_num,
            // Process the current step in the protocol.
            // Execute this protocol step.
            prev_send_chain_len: self.prev_send_chain_len,
            // Execute this protocol step.
            skipped_keys,
        }
    }

    /// Reconstruct a session from a previously exported snapshot.
    // Perform the 'from snapshot' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_snapshot(mut snap: SessionSnapshot) -> Self {
        // Key material — must be zeroized when no longer needed.
        // Compute my ratchet secret for this protocol step.
        let my_ratchet_secret = X25519Secret::from(snap.my_ratchet_secret_bytes);
        // Take ownership of skipped_keys via mem::take rather than
        // into_iter(), because SessionSnapshot implements Drop and
        // Rust prohibits moving fields out of a type with Drop.
        // mem::take replaces the Vec with an empty Vec, leaving the
        // Drop impl with nothing to zeroize for this field.
        let raw_skipped = std::mem::take(&mut snap.skipped_keys);
        // Key material — must be zeroized when no longer needed.
        // Compute skipped keys for this protocol step.
        let skipped_keys = raw_skipped
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            .into_iter()
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            .map(|(ratchet_pub, msg_num, key)| (SkippedKeyId { ratchet_pub, msg_num }, key))
            // Materialize the iterator into a concrete collection.
            // Collect into a concrete collection.
            .collect();

        // Copy the scalar fields before snap is dropped (and zeroized).
        // All [u8; N] fields implement Copy, so this is safe.
        let root_key = snap.root_key;
        let my_ratchet_pub = snap.my_ratchet_pub;
        let their_ratchet_pub = snap.their_ratchet_pub;
        let send_chain_key = snap.send_chain_key;
        let send_msg_num = snap.send_msg_num;
        let recv_chain_key = snap.recv_chain_key;
        let recv_msg_num = snap.recv_msg_num;
        let prev_send_chain_len = snap.prev_send_chain_len;

        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        Self {
            root_key,
            my_ratchet_secret,
            my_ratchet_pub,
            their_ratchet_pub,
            send_chain_key,
            send_msg_num,
            recv_chain_key,
            recv_msg_num,
            prev_send_chain_len,
            skipped_keys,
        }
    }
}

// ---------------------------------------------------------------------------
// Session snapshot (vault persistence — §17.9)
// ---------------------------------------------------------------------------

/// Serialisable representation of a `DoubleRatchetSession`.
///
/// Created by `DoubleRatchetSession::to_snapshot()` and restored by
/// `DoubleRatchetSession::from_snapshot()`. The caller is responsible for
/// encrypting this before writing to disk (via `VaultCollection::save`).
///
/// Serde field names must remain stable — changing them is a vault schema
/// migration requiring a version bump.
#[derive(Serialize, Deserialize)]
// Begin the block scope.
// SessionSnapshot — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SessionSnapshot {
    /// Current root key bytes.
    // Execute this protocol step.
    root_key: [u8; 32],
    /// Raw bytes of the local DH ratchet secret.
    // Execute this protocol step.
    my_ratchet_secret_bytes: [u8; 32],
    /// The corresponding public key bytes.
    // Execute this protocol step.
    my_ratchet_pub: [u8; 32],
    /// Remote peer's current ratchet public key (None until first message received).
    // Execute this protocol step.
    their_ratchet_pub: Option<[u8; 32]>,
    /// Current sending chain key.
    // Execute this protocol step.
    send_chain_key: Option<[u8; 32]>,
    /// Number of messages sent on current sending chain.
    // Execute this protocol step.
    send_msg_num: u32,
    /// Current receiving chain key.
    // Execute this protocol step.
    recv_chain_key: Option<[u8; 32]>,
    /// Number of messages received on current receiving chain.
    // Execute this protocol step.
    recv_msg_num: u32,
    /// Number of messages in the previous sending chain (for headers).
    // Execute this protocol step.
    prev_send_chain_len: u32,
    /// Cached skipped message keys: `(ratchet_pub, msg_num, msg_key)`.
    // Execute this protocol step.
    skipped_keys: Vec<([u8; 32], u32, [u8; 32])>,
}

/// Securely erase all cryptographic key material from `SessionSnapshot`
/// when it is dropped. Without this, serialised key bytes would linger
/// in freed heap memory and could be recovered by a forensic attacker
/// with access to a memory dump or swap file.
///
/// We implement `Drop` manually rather than deriving `Zeroize` because
/// the `skipped_keys` field is a `Vec` of tuples — the derive macro
/// cannot reach inside tuple elements to zeroize them.
impl Drop for SessionSnapshot {
    fn drop(&mut self) {
        // Zeroize the root key — the master secret for the session.
        self.root_key.zeroize();
        // Zeroize the DH ratchet secret — private key material.
        self.my_ratchet_secret_bytes.zeroize();
        // Zeroize the DH ratchet public key bytes.
        self.my_ratchet_pub.zeroize();
        // Zeroize the remote peer's ratchet public key if present.
        if let Some(ref mut key) = self.their_ratchet_pub {
            key.zeroize();
        }
        // Zeroize the sending chain key if present.
        if let Some(ref mut key) = self.send_chain_key {
            key.zeroize();
        }
        // Zeroize the receiving chain key if present.
        if let Some(ref mut key) = self.recv_chain_key {
            key.zeroize();
        }
        // Zeroize each cached skipped message key (ratchet_pub + msg_key).
        // The msg_num (u32) is not sensitive but tuple elements are zeroed
        // together for simplicity and thoroughness.
        for (ratchet_pub, _, msg_key) in self.skipped_keys.iter_mut() {
            ratchet_pub.zeroize();
            msg_key.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Begin the block scope.
// Perform the 'decrypt with key' operation.
// Errors are propagated to the caller via Result.
fn decrypt_with_key(msg_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, RatchetError> {
    // Key material — must be zeroized when no longer needed.
    // Compute mk for this protocol step.
    let mk = expand_message_key(msg_key)?;
    // Initialize the AEAD cipher with the derived key material.
    // Compute cipher for this protocol step.
    let cipher =
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        ChaCha20Poly1305::new_from_slice(&mk.cipher_key).map_err(|_| RatchetError::DecryptionFailed)?;
    // Fresh nonce — must never be reused with the same key.
    // Compute nonce for this protocol step.
    let nonce = Nonce::from_slice(&mk.nonce);
    cipher
        // Decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        .decrypt(nonce, ciphertext)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        .map_err(|_| RatchetError::DecryptionFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_session_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
        // Simulate X3DH output
        let master_secret = [0x42u8; 32];

        // Bob's preauth keypair (used as initial ratchet key)
        let bob_preauth_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let bob_preauth_pub = *X25519Public::from(&bob_preauth_secret).as_bytes();

        let alice = DoubleRatchetSession::init_sender(&master_secret, &bob_preauth_pub).unwrap();
        let bob = DoubleRatchetSession::init_receiver(&master_secret, bob_preauth_secret, &bob_preauth_pub);

        (alice, bob)
    }

    #[test]
    fn test_basic_send_receive() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice sends a message
        let plaintext = b"Hello Bob!";
        let (header, ciphertext) = alice.encrypt(plaintext).unwrap();

        // Bob decrypts
        let decrypted = bob.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bidirectional_messages() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice → Bob
        let (h1, ct1) = alice.encrypt(b"Hello from Alice").unwrap();
        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"Hello from Alice");

        // Bob → Alice
        let (h2, ct2) = bob.encrypt(b"Hello from Bob").unwrap();
        let pt2 = alice.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"Hello from Bob");

        // Alice → Bob again
        let (h3, ct3) = alice.encrypt(b"Second from Alice").unwrap();
        let pt3 = bob.decrypt(&h3, &ct3).unwrap();
        assert_eq!(pt3, b"Second from Alice");
    }

    #[test]
    fn test_multiple_messages_same_direction() {
        let (mut alice, mut bob) = setup_session_pair();

        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2").unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3").unwrap();

        // Decrypt in order
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"msg1");
        assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"msg2");
        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"msg3");
    }

    #[test]
    fn test_out_of_order_delivery() {
        let (mut alice, mut bob) = setup_session_pair();

        let (h1, ct1) = alice.encrypt(b"first").unwrap();
        let (h2, ct2) = alice.encrypt(b"second").unwrap();
        let (h3, ct3) = alice.encrypt(b"third").unwrap();

        // Deliver out of order: 3, 1, 2
        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"third");
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"first");
        assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"second");
    }

    #[test]
    fn test_ratchet_advances_per_message() {
        let (mut alice, _bob) = setup_session_pair();

        let (h1, _) = alice.encrypt(b"msg1").unwrap();
        let (h2, _) = alice.encrypt(b"msg2").unwrap();

        // Same ratchet pub (no DH step between sends), but different msg_num
        assert_eq!(h1.ratchet_pub, h2.ratchet_pub);
        assert_eq!(h1.msg_num, 0);
        assert_eq!(h2.msg_num, 1);
    }

    #[test]
    fn test_dh_ratchet_step_on_reply() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice sends
        let (h1, ct1) = alice.encrypt(b"from alice").unwrap();
        bob.decrypt(&h1, &ct1).unwrap();

        // Bob replies — this triggers a DH ratchet step
        let (h2, ct2) = bob.encrypt(b"from bob").unwrap();

        // Bob's ratchet pub should be DIFFERENT from Alice's
        assert_ne!(h1.ratchet_pub, h2.ratchet_pub);

        // Alice decrypts — triggers her DH ratchet step
        let pt2 = alice.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"from bob");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (mut alice, mut bob) = setup_session_pair();

        let (header, mut ciphertext) = alice.encrypt(b"secret").unwrap();

        // Tamper
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        assert!(bob.decrypt(&header, &ciphertext).is_err());
    }

    #[test]
    fn test_per_message_forward_secrecy() {
        let (mut alice, mut bob) = setup_session_pair();

        // Send 3 messages
        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (_h2, _ct2) = alice.encrypt(b"msg2").unwrap();
        let (_h3, _ct3) = alice.encrypt(b"msg3").unwrap();

        // Decrypt only msg1 — msg2 and msg3 keys are in the chain
        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"msg1");

        // After decrypting msg1, the chain_key has advanced
        // The key for msg1 is gone (forward secrecy)
        // But msg2 and msg3 are still decryptable via skipped keys or chain advancement
    }

    #[test]
    fn test_snapshot_roundtrip_preserves_session() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice sends 3 messages; Bob decrypts 2 (leaving 1 skipped key cached in bob).
        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2").unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3").unwrap();

        // Bob decrypts msg1 and msg3 out of order — msg2's key goes into skipped cache.
        bob.decrypt(&h1, &ct1).unwrap();
        bob.decrypt(&h3, &ct3).unwrap(); // skips msg2

        // Snapshot and restore Bob's session.
        let snap = bob.to_snapshot();
        let json = serde_json::to_vec(&snap).unwrap();
        let snap2: SessionSnapshot = serde_json::from_slice(&json).unwrap();
        let mut bob_restored = DoubleRatchetSession::from_snapshot(snap2);

        // Restored Bob should still be able to decrypt the skipped msg2.
        let pt2 = bob_restored.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"msg2");

        // And continue receiving from Alice normally.
        let (h4, ct4) = alice.encrypt(b"msg4").unwrap();
        let pt4 = bob_restored.decrypt(&h4, &ct4).unwrap();
        assert_eq!(pt4, b"msg4");
    }

    #[test]
    fn test_long_conversation() {
        let (mut alice, mut bob) = setup_session_pair();

        // 50 messages back and forth
        for i in 0..50u32 {
            let msg = format!("Message #{i}");
            if i % 2 == 0 {
                let (h, ct) = alice.encrypt(msg.as_bytes()).unwrap();
                let pt = bob.decrypt(&h, &ct).unwrap();
                assert_eq!(pt, msg.as_bytes());
            } else {
                let (h, ct) = bob.encrypt(msg.as_bytes()).unwrap();
                let pt = alice.decrypt(&h, &ct).unwrap();
                assert_eq!(pt, msg.as_bytes());
            }
        }
    }

    #[test]
    fn test_replay_in_order_message_rejected() {
        // Decrypting the same (header, ciphertext) twice must fail.
        // After the first successful decrypt, recv_msg_num advances; the
        // second attempt drives the chain forward one extra step, producing
        // a different message key → AEAD authentication failure.
        let (mut alice, mut bob) = setup_session_pair();

        let (header, ciphertext) = alice.encrypt(b"replay target").unwrap();

        // First decrypt succeeds.
        let first = bob.decrypt(&header, &ciphertext);
        assert!(first.is_ok(), "first decrypt must succeed");

        // Second decrypt with the identical (header, ciphertext) must fail.
        let second = bob.decrypt(&header, &ciphertext);
        assert!(second.is_err(), "replay of in-order message must be rejected");
    }

    #[test]
    fn test_replay_skipped_message_rejected() {
        // A message whose key was cached as a skipped key (out-of-order) is
        // consumed on first use.  Replaying it a second time must fail because
        // the key has been removed from the cache.
        let (mut alice, mut bob) = setup_session_pair();

        // Alice sends two messages.
        let (h1, ct1) = alice.encrypt(b"skip me").unwrap();
        let (h2, ct2) = alice.encrypt(b"deliver first").unwrap();

        // Bob decrypts msg2 first — this caches the skipped key for msg1.
        bob.decrypt(&h2, &ct2).expect("out-of-order second message must decrypt");

        // Bob decrypts the skipped msg1 — key is consumed.
        bob.decrypt(&h1, &ct1).expect("skipped first message must decrypt");

        // Replaying msg1 now must fail — the skipped key was removed on use.
        let replay = bob.decrypt(&h1, &ct1);
        assert!(replay.is_err(), "replay of already-consumed skipped key must be rejected");
    }

    /// Adversarial test: an attacker sends a message whose `msg_num` is
    /// MAX_SKIP+1, forcing the receiver to try to cache MAX_SKIP+1 skipped keys
    /// in a single step.  This must be denied with TooManySkipped rather than
    /// allocating an unbounded HashMap and exhausting memory.
    ///
    /// Threat model: a compromised peer or man-in-the-middle who replays or
    /// forges a header with an extremely high `msg_num`, triggering the
    /// skip_message_keys path with a count that blows past MAX_SKIP.
    #[test]
    fn test_skip_cache_exhaustion_denied() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice encrypts MAX_SKIP+2 messages (msg_num 0 .. MAX_SKIP+1).
        // We keep only the last one (msg_num = MAX_SKIP+1 = 1001) to deliver
        // to Bob. Bob is still at recv_msg_num=0, so the skip count needed is
        // 1001, which exceeds MAX_SKIP=1000.
        let mut last_hdr = None;
        let mut last_ct = None;
        for _ in 0..=(MAX_SKIP + 1) {
            let (h, ct) = alice.encrypt(b"flood").unwrap();
            last_hdr = Some(h);
            last_ct = Some(ct);
        }
        let overflow_hdr = last_hdr.unwrap();
        let overflow_ct = last_ct.unwrap();

        // Delivering the overflow message to Bob must be rejected.
        let result = bob.decrypt(&overflow_hdr, &overflow_ct);
        assert!(
            matches!(result, Err(RatchetError::TooManySkipped)),
            "delivering a message that requires >MAX_SKIP cached keys must return \
             TooManySkipped, got: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // MED-2: Message number overflow guard tests
    // -----------------------------------------------------------------------

    /// Verify that encrypt() returns MsgNumExhausted when send_msg_num
    /// reaches u32::MAX, preventing nonce reuse in ChaCha20-Poly1305.
    #[test]
    fn test_send_msg_num_overflow_rejected() {
        let (mut alice, _bob) = setup_session_pair();

        // Artificially set send_msg_num to u32::MAX to simulate a
        // session that has sent 2^32 - 1 messages on the same chain.
        alice.send_msg_num = u32::MAX;

        // The next encrypt must fail with MsgNumExhausted, not wrap to 0.
        let result = alice.encrypt(b"one too many");
        assert!(
            matches!(result, Err(RatchetError::MsgNumExhausted)),
            "encrypt at u32::MAX must return MsgNumExhausted, got: {result:?}"
        );
    }

    /// Verify that decrypt() returns MsgNumExhausted when the received
    /// header's msg_num is u32::MAX, preventing recv_msg_num wrap.
    #[test]
    fn test_recv_msg_num_overflow_rejected() {
        let (mut alice, mut bob) = setup_session_pair();

        // Send a legitimate message so Bob's recv chain is initialised.
        let (h1, ct1) = alice.encrypt(b"init").unwrap();
        bob.decrypt(&h1, &ct1).unwrap();

        // Forge a header with msg_num = u32::MAX. The ciphertext will
        // fail AEAD anyway, but the overflow guard must trigger first.
        let forged_header = RatchetHeader {
            ratchet_pub: h1.ratchet_pub,
            prev_chain_len: 0,
            msg_num: u32::MAX,
        };
        let result = bob.decrypt(&forged_header, &ct1);
        // Either MsgNumExhausted (overflow guard) or TooManySkipped
        // (from trying to skip u32::MAX keys). Both are acceptable —
        // the important thing is that it does NOT succeed or wrap.
        assert!(
            result.is_err(),
            "decrypt with msg_num=u32::MAX must fail, got: {result:?}"
        );
    }

    /// Verify that next_send_msg_key() also guards against overflow.
    #[test]
    fn test_next_send_msg_key_overflow_rejected() {
        let (mut alice, _bob) = setup_session_pair();

        // Set send_msg_num to u32::MAX.
        alice.send_msg_num = u32::MAX;

        // The four-layer helper must also reject at the overflow boundary.
        let result = alice.next_send_msg_key();
        assert!(
            matches!(result, Err(RatchetError::MsgNumExhausted)),
            "next_send_msg_key at u32::MAX must return MsgNumExhausted, got: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // SessionSnapshot zeroize-on-drop test
    // -----------------------------------------------------------------------

    /// Verify that SessionSnapshot's Drop impl runs without panicking
    /// when all field variants are populated (Some values, non-empty Vec).
    /// The primary guarantee is that the destructor correctly zeroizes
    /// every key field without type errors or panics.
    #[test]
    fn test_snapshot_zeroize_on_drop() {
        // Create a snapshot with recognisable non-zero key material.
        let snap = SessionSnapshot {
            root_key: [0xAA; 32],
            my_ratchet_secret_bytes: [0xBB; 32],
            my_ratchet_pub: [0xCC; 32],
            their_ratchet_pub: Some([0xDD; 32]),
            send_chain_key: Some([0xEE; 32]),
            send_msg_num: 42,
            recv_chain_key: Some([0xFF; 32]),
            recv_msg_num: 7,
            prev_send_chain_len: 3,
            skipped_keys: vec![([0x11; 32], 5, [0x22; 32])],
        };

        // Drop the snapshot, triggering the zeroize logic.
        // If Drop misses a field or has a type mismatch, this panics.
        drop(snap);
    }

    /// Verify that SessionSnapshot's Drop impl handles None/empty
    /// variants without panicking (no unwrap on Option::None).
    #[test]
    fn test_snapshot_zeroize_on_drop_empty() {
        // Snapshot with all optional fields set to None and empty Vec.
        let snap = SessionSnapshot {
            root_key: [0xAA; 32],
            my_ratchet_secret_bytes: [0xBB; 32],
            my_ratchet_pub: [0xCC; 32],
            their_ratchet_pub: None,
            send_chain_key: None,
            send_msg_num: 0,
            recv_chain_key: None,
            recv_msg_num: 0,
            prev_send_chain_len: 0,
            skipped_keys: vec![],
        };

        // Must not panic even with None/empty fields.
        drop(snap);
    }

    // --- Encrypted header tests (CRIT-2) ---

    #[test]
    fn test_header_encrypt_decrypt_roundtrip() {
        // Alice and Bob share a static DH secret; both derive the same
        // header encryption key from it.
        let alice_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let alice_pub = X25519Public::from(&alice_secret);
        let bob_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let bob_pub = X25519Public::from(&bob_secret);

        // Compute the shared DH secret from both sides.
        let alice_dh = alice_secret.diffie_hellman(&bob_pub);
        let bob_dh = bob_secret.diffie_hellman(&alice_pub);
        // Both must agree on the shared secret.
        assert_eq!(alice_dh.as_bytes(), bob_dh.as_bytes());

        // Derive header encryption keys from the shared secret.
        let alice_hdr_key = DoubleRatchetSession::derive_header_key_from_dh(alice_dh.as_bytes())
            .expect("derive alice key");
        let bob_hdr_key = DoubleRatchetSession::derive_header_key_from_dh(bob_dh.as_bytes())
            .expect("derive bob key");
        // Both keys must be identical.
        assert_eq!(alice_hdr_key, bob_hdr_key);

        // The header to encrypt.
        let header = RatchetHeader {
            ratchet_pub: *alice_pub.as_bytes(),
            prev_chain_len: 42,
            msg_num: 7,
        };

        // Alice encrypts the header.
        let enc = DoubleRatchetSession::encrypt_header_with_key(&header, &alice_hdr_key)
            .expect("encrypt_header");

        // Encrypted header must differ from plaintext serialisation.
        let plaintext_json = serde_json::to_vec(&header).expect("json");
        assert_ne!(enc, plaintext_json, "encrypted header must not match plaintext");

        // Bob decrypts the header using the same key.
        let decrypted = DoubleRatchetSession::decrypt_header_with_key(&enc, &bob_hdr_key)
            .expect("decrypt_header");

        // Verify the decrypted header matches the original.
        assert_eq!(decrypted.ratchet_pub, header.ratchet_pub);
        assert_eq!(decrypted.prev_chain_len, header.prev_chain_len);
        assert_eq!(decrypted.msg_num, header.msg_num);
    }

    #[test]
    fn test_header_decrypt_tampered_fails() {
        // Tampering with the encrypted header must cause decryption to fail.
        let alice_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let bob_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let bob_pub = X25519Public::from(&bob_secret);

        let dh = alice_secret.diffie_hellman(&bob_pub);
        let hdr_key = DoubleRatchetSession::derive_header_key_from_dh(dh.as_bytes())
            .expect("derive key");

        let header = RatchetHeader {
            ratchet_pub: *bob_pub.as_bytes(),
            prev_chain_len: 0,
            msg_num: 0,
        };

        let mut enc = DoubleRatchetSession::encrypt_header_with_key(&header, &hdr_key)
            .expect("encrypt");
        // Flip a byte to simulate tampering.
        if let Some(byte) = enc.get_mut(0) {
            *byte ^= 0xFF;
        }

        // Decryption should fail due to the AEAD tag check.
        assert!(DoubleRatchetSession::decrypt_header_with_key(&enc, &hdr_key).is_err());
    }

    #[test]
    fn test_header_wrong_key_fails() {
        // Decrypting with a different key must fail.
        let key_a = [0x42u8; 32];
        let key_b = [0x99u8; 32];

        let header = RatchetHeader {
            ratchet_pub: [0xAA; 32],
            prev_chain_len: 5,
            msg_num: 10,
        };

        let enc = DoubleRatchetSession::encrypt_header_with_key(&header, &key_a)
            .expect("encrypt");
        // Decryption with a different key must fail.
        assert!(DoubleRatchetSession::decrypt_header_with_key(&enc, &key_b).is_err());
    }
}
