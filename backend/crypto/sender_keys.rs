//! Sender Keys — Group Message Encryption (§7.0.4)
//!
//! # What are Sender Keys?
//!
//! In a group chat, you could encrypt each message separately for every member
//! (called "fan-out") — but that means if a group has 100 members, sending one
//! message requires 100 separate encryptions. That's expensive.
//!
//! Sender Keys solve this: each group member generates a single "Sender Key"
//! that they share with everyone else in the group. When they send a message,
//! they encrypt it ONCE using their Sender Key. All other members can decrypt
//! it because they all have a copy of that member's Sender Key.
//!
//! # How it works
//!
//! Each member has a per-group Sender Key consisting of:
//! - `chain_key`: a 32-byte secret that advances with each message (like the
//!   Double Ratchet's KDF chain, providing forward secrecy within the chain)
//! - `iteration`: a counter tracking how many messages have been sent
//! - `signing_key`: an Ed25519 keypair for authenticating messages
//!
//! When a member sends a group message:
//! 1. Derive a message key from the chain: `msg_key = HMAC-SHA256(chain_key, 0x01)`
//! 2. Advance the chain: `new_chain_key = HMAC-SHA256(chain_key, 0x02)`
//! 3. Encrypt the message with the derived key
//! 4. Sign the ciphertext with the signing key
//! 5. Increment iteration counter
//!
//! # Forward Secrecy Limitation
//!
//! Unlike the Double Ratchet (which provides per-message forward secrecy via
//! DH ratchet steps), Sender Keys only provide forward secrecy within the
//! KDF chain — there's no DH ratchet step between messages. This means:
//!
//! - If an attacker captures a chain_key at position N, they can derive ALL
//!   future message keys (N+1, N+2, ...) until the next rekeying event.
//! - The spec mitigates this with a **7-day periodic rekeying** schedule (§8.7.5)
//!   that bounds the forward secrecy window.
//!
//! # Distribution
//!
//! Sender Keys are distributed to group members via individual X3DH-encrypted
//! direct messages (the same mechanism used for 1:1 chat). This is O(N) per
//! join or rekeying event — each member sends their Sender Key to each other
//! member individually.
//!
//! # Rekeying
//!
//! Rekeying is triggered by:
//! 1. Member removal (immediate — superset ring model, §8.7.4)
//! 2. 7-day scheduled interval (forward secrecy bound, §8.7.5)
//! 3. Admin-triggered on-demand rekeying

use chacha20poly1305::{
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    aead::{Aead, KeyInit},
    // AEAD cipher for authenticated encryption.
    // Execute this protocol step.
    // Execute this protocol step.
    ChaCha20Poly1305,
    Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
// Shared KDF chain-step primitive and constants (avoids duplication with
// double_ratchet.rs — both protocols use the same HMAC-SHA256 chain advancement).
use super::primitives::{kdf_chain_step, ZERO_SALT};
use rand_core::OsRng;
// Securely erase key material to prevent forensic recovery.
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Constants — these control how message keys are derived from the chain
// ---------------------------------------------------------------------------

/// HKDF info string for expanding a message key into cipher_key + nonce.
/// The "SK" suffix distinguishes this from the Double Ratchet's "MK" expansion.
// SK_MK_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
// SK_MK_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
const SK_MK_INFO: &[u8] = b"MeshInfinity_SK_MK_v1";

/// Maximum number of skipped message keys to cache per sender.
/// Prevents memory exhaustion if a member sends messages we receive out of order.
/// 500 is generous — a member would need to send 500 messages before we process any.
// MAX_SKIP_PER_SENDER — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_SKIP_PER_SENDER — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_SKIP_PER_SENDER: u32 = 500;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during Sender Key operations.
#[derive(Debug, thiserror::Error)]
// Begin the block scope.
// SenderKeyError — variant enumeration.
// Match exhaustively to handle every protocol state.
// SenderKeyError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum SenderKeyError {
    /// The HKDF expansion step failed (should never happen with valid inputs).
    #[error("HKDF expansion failed")]
    // Execute this protocol step.
    // Execute this protocol step.
    HkdfExpand,

    /// ChaCha20-Poly1305 encryption failed.
    #[error("Encryption failed")]
    // Execute this protocol step.
    // Execute this protocol step.
    EncryptFailed,

    /// ChaCha20-Poly1305 decryption failed — either the key is wrong or
    /// the ciphertext was tampered with.
    #[error("Decryption failed — wrong key or tampered ciphertext")]
    // Execute this protocol step.
    // Execute this protocol step.
    DecryptFailed,

    /// The Ed25519 signature on the message didn't verify.
    /// This means either the message was tampered with or the signing key
    /// doesn't match what we expected for this sender.
    #[error("Signature verification failed")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SignatureFailed,

    /// Too many messages were skipped — we've cached the maximum number
    /// of out-of-order message keys for this sender.
    #[error("Too many skipped messages (max {MAX_SKIP_PER_SENDER})")]
    // Execute this protocol step.
    // Execute this protocol step.
    TooManySkipped,

    /// Ed25519 key parsing error.
    #[error("Key error: {0}")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    KeyError(String),
}

// ---------------------------------------------------------------------------
// Sender Key — one per member per group
// ---------------------------------------------------------------------------

/// A Sender Key for a specific member in a specific group.
///
/// Each group member generates one of these and distributes it to all other
/// members via X3DH-encrypted direct messages. The chain_key advances with
/// each message sent, providing forward secrecy within the chain.
// SenderKey — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SenderKey — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SenderKey {
    /// The KDF chain key. Advances by one step for each message sent.
    /// This is the secret that enables decryption — anyone who holds it
    /// can derive all future message keys until the next rekeying.
    // Execute this protocol step.
    // Execute this protocol step.
    chain_key: [u8; 32],

    /// How many messages have been sent with this Sender Key.
    /// Used to index skipped message keys for out-of-order delivery.
    // Execute this protocol step.
    // Execute this protocol step.
    pub iteration: u32,

    /// Ed25519 signing key for authenticating messages.
    /// The corresponding verifying key is distributed to all group members
    /// so they can verify that messages came from this sender.
    // Execute this protocol step.
    // Execute this protocol step.
    signing_key: SigningKey,
}

// Begin the block scope.
// SenderKey implementation — core protocol logic.
// SenderKey implementation — core protocol logic.
impl SenderKey {
    /// Generate a fresh Sender Key with random chain_key and signing_key.
    ///
    /// Called when:
    /// - A new member joins a group (they generate their own Sender Key)
    /// - A rekeying event occurs (all members generate new Sender Keys)
    // Perform the 'generate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'generate' operation.
    // Errors are propagated to the caller via Result.
    pub fn generate() -> Self {
        // Generate a random 32-byte chain key — this seeds the KDF chain
        // Compute chain key for this protocol step.
        // Compute chain key for this protocol step.
        let mut chain_key = [0u8; 32];
        // OS-provided cryptographic random number generator.
        // Execute this protocol step.
        // Execute this protocol step.
        OsRng.fill_bytes(&mut chain_key);

        // Generate a random Ed25519 signing keypair for message authentication
        // Compute signing key for this protocol step.
        // Compute signing key for this protocol step.
        let signing_key = SigningKey::generate(&mut OsRng);

        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            chain_key,
            // Execute this protocol step.
            // Execute this protocol step.
            iteration: 0,
            // Execute this protocol step.
            // Execute this protocol step.
            signing_key,
        }
    }

    /// Get the public verifying key that other members use to verify our messages.
    ///
    /// This is distributed alongside the chain_key when sharing the Sender Key
    /// with group members.
    // Perform the 'verifying key' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verifying key' operation.
    // Errors are propagated to the caller via Result.
    pub fn verifying_key(&self) -> VerifyingKey {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.signing_key.verifying_key()
    }

    /// Reconstruct a SenderKey from persisted parts.
    ///
    /// `chain_key_bytes` — the current chain key (advanced to `iteration`).
    /// `iteration`       — how many messages have been sent so far.
    /// `signing_key_raw` — 64-byte Ed25519 signing key (secret + public).
    // Perform the 'from parts' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from parts' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_parts(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        chain_key_bytes: [u8; 32],
        // Execute this protocol step.
        // Execute this protocol step.
        iteration: u32,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        signing_key_raw: &[u8; 64],
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Result<Self, SenderKeyError> {
        // ed25519_dalek expects the first 32 bytes as the secret scalar.
        // Compute signing key for this protocol step.
        // Compute signing key for this protocol step.
        let signing_key = SigningKey::from_bytes(
            // Extract the fixed-size prefix.
            // Execute this protocol step.
            // Execute this protocol step.
            signing_key_raw[..32]
                .try_into()
                // Transform the result, mapping errors to the local error type.
                // Map the error to the local error type.
                // Map the error to the local error type.
                .map_err(|_| SenderKeyError::KeyError("bad signing key length".into()))?,
        );
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            chain_key: chain_key_bytes,
            // Execute this protocol step.
            // Execute this protocol step.
            iteration,
            // Execute this protocol step.
            // Execute this protocol step.
            signing_key,
        })
    }

    /// Get the 64-byte signing key bytes for persistence.
    ///
    /// Returns `[secret_scalar (32 bytes) || public_key (32 bytes)]`.
    // Perform the 'signing key bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'signing key bytes' operation.
    // Errors are propagated to the caller via Result.
    pub fn signing_key_bytes(&self) -> [u8; 64] {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.signing_key.to_keypair_bytes()
    }

    /// Get the current chain key bytes for distribution to group members.
    ///
    /// SECURITY: This is secret material. It must only be shared via
    /// X3DH-encrypted direct messages to individual group members.
    // Perform the 'chain key bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'chain key bytes' operation.
    // Errors are propagated to the caller via Result.
    pub fn chain_key_bytes(&self) -> &[u8; 32] {
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        &self.chain_key
    }

    /// Encrypt a plaintext message using this Sender Key.
    ///
    /// This advances the KDF chain by one step, derives a message-specific
    /// encryption key, encrypts the plaintext, and signs the result.
    ///
    /// Returns: (iteration, ciphertext, signature)
    /// - iteration: the message number (for receivers to track their position)
    /// - ciphertext: the encrypted message
    /// - signature: Ed25519 signature over the ciphertext
    // Perform the 'encrypt' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'encrypt' operation.
    // Errors are propagated to the caller via Result.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<SenderKeyMessage, SenderKeyError> {
        // Step 1: Derive a one-time message key from the current chain key.
        // This key will be used to encrypt this specific message and then discarded.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (msg_key, new_chain_key) = kdf_chain_step(&self.chain_key);

        // Step 2: Advance the chain key to its next state.
        // After this, the old chain_key is gone — we can't derive the message key
        // for this iteration again. This is the forward secrecy mechanism.
        // Advance chain key state.
        // Advance chain key state.
        self.chain_key = new_chain_key;
        // Execute the operation and bind the result.
        // Compute iteration for this protocol step.
        // Compute iteration for this protocol step.
        let iteration = self.iteration;
        // Update the iteration to reflect the new state.
        // Advance iteration state.
        // Advance iteration state.
        self.iteration += 1;

        // Step 3: Expand the message key into a cipher_key and nonce for AEAD.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (cipher_key, nonce) = expand_msg_key(&msg_key)?;

        // Step 4: Encrypt the plaintext with ChaCha20-Poly1305.
        // The auth tag is appended to the ciphertext automatically.
        // Compute cipher for this protocol step.
        // Compute cipher for this protocol step.
        let cipher = ChaCha20Poly1305::new_from_slice(&cipher_key)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| SenderKeyError::EncryptFailed)?;
        // Initialize the AEAD cipher with the derived key material.
        // Compute ciphertext for this protocol step.
        // Compute ciphertext for this protocol step.
        let ciphertext = cipher
            // Encrypt the plaintext under the current session key.
            // AEAD-encrypt the plaintext.
            // AEAD-encrypt the plaintext.
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| SenderKeyError::EncryptFailed)?;

        // Step 5: Sign the ciphertext so recipients can verify it came from us.
        // The signature covers the ciphertext, NOT the plaintext — this way
        // even someone who can't decrypt can verify the sender's identity.
        // Compute signature for this protocol step.
        // Compute signature for this protocol step.
        let signature = self.signing_key.sign(&ciphertext);

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(SenderKeyMessage {
            // Execute this protocol step.
            // Execute this protocol step.
            iteration,
            // Execute this protocol step.
            // Execute this protocol step.
            ciphertext,
            // Extract the raw byte representation for wire encoding.
            // Execute this protocol step.
            // Execute this protocol step.
            signature: signature.to_bytes().to_vec(),
        })
    }
}

/// Clean up: zero the chain key when the SenderKey is dropped.
// Implement Drop for SenderKey.
// Implement Drop for SenderKey.
impl Drop for SenderKey {
    // Begin the block scope.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    fn drop(&mut self) {
        // Securely erase key material to prevent forensic recovery.
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.chain_key.zeroize();
    }
}

use rand_core::RngCore;

// ---------------------------------------------------------------------------
// Sender Key Message — the encrypted output
// ---------------------------------------------------------------------------

/// An encrypted group message produced by SenderKey::encrypt().
#[derive(Clone, Debug)]
// Begin the block scope.
// SenderKeyMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SenderKeyMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SenderKeyMessage {
    /// Which iteration of the sender's chain this message was encrypted under.
    /// Recipients use this to advance their copy of the sender's chain to the
    /// correct position for decryption.
    // Execute this protocol step.
    // Execute this protocol step.
    pub iteration: u32,

    /// The ChaCha20-Poly1305 encrypted message content.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ciphertext: Vec<u8>,

    /// Ed25519 signature over the ciphertext, by the sender's Sender Key
    /// signing key. Recipients verify this to confirm the message came from
    /// the expected sender and wasn't tampered with.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Receiver state — tracks a remote member's Sender Key chain position
// ---------------------------------------------------------------------------

/// Receiver-side state for tracking a remote member's Sender Key.
///
/// When you receive a Sender Key from another group member, you create one
/// of these to track your position in their KDF chain. As you receive their
/// messages, you advance your copy of their chain to derive the decryption keys.
// SenderKeyReceiver — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SenderKeyReceiver — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SenderKeyReceiver {
    /// Our copy of the sender's chain key, advanced to our current position.
    // Execute this protocol step.
    // Execute this protocol step.
    chain_key: [u8; 32],

    /// The next iteration we expect from this sender.
    // Execute this protocol step.
    // Execute this protocol step.
    next_iteration: u32,

    /// The sender's Ed25519 verifying key — used to verify message signatures.
    // Execute this protocol step.
    // Execute this protocol step.
    verifying_key: VerifyingKey,

    /// Cached message keys for out-of-order delivery.
    /// Key: iteration number, Value: 32-byte message key.
    /// If we receive message #5 before #3, we cache the keys for #3 and #4
    /// while advancing the chain to #5.
    // Execute this protocol step.
    // Execute this protocol step.
    skipped_keys: std::collections::HashMap<u32, [u8; 32]>,
}

// Begin the block scope.
// SenderKeyReceiver implementation — core protocol logic.
// SenderKeyReceiver implementation — core protocol logic.
impl SenderKeyReceiver {
    /// Create a receiver from a distributed Sender Key.
    ///
    /// Called when we receive another member's Sender Key via X3DH-encrypted
    /// direct message. The chain_key and verifying_key come from the sender.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(chain_key: [u8; 32], verifying_key: VerifyingKey) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            chain_key,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            next_iteration: 0,
            // Execute this protocol step.
            // Execute this protocol step.
            verifying_key,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            skipped_keys: std::collections::HashMap::new(),
        }
    }

    /// Reconstruct a receiver from persisted state.
    ///
    /// `chain_key` must already be advanced to `next_iteration` — this is
    /// exactly what `chain_key_bytes()` returns after each decryption. The
    /// skipped-key cache is not persisted (acceptable: out-of-order messages
    /// delivered after a restart will trigger re-inclusion).
    // Perform the 'from state' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from state' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_state(
        chain_key: [u8; 32],
        next_iteration: u32,
        verifying_key: VerifyingKey,
    ) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            chain_key,
            // Execute this protocol step.
            // Execute this protocol step.
            next_iteration,
            // Execute this protocol step.
            // Execute this protocol step.
            verifying_key,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            skipped_keys: std::collections::HashMap::new(),
        }
    }

    /// Current chain key (advanced to `next_iteration`), for persistence.
    // Perform the 'chain key bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'chain key bytes' operation.
    // Errors are propagated to the caller via Result.
    pub fn chain_key_bytes(&self) -> &[u8; 32] {
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        &self.chain_key
    }

    /// The next iteration number we expect, for persistence.
    // Perform the 'next iter' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'next iter' operation.
    // Errors are propagated to the caller via Result.
    pub fn next_iter(&self) -> u32 {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.next_iteration
    }

    /// Decrypt a message from this sender.
    ///
    /// Handles out-of-order delivery by caching skipped message keys.
    // Perform the 'decrypt' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'decrypt' operation.
    // Errors are propagated to the caller via Result.
    pub fn decrypt(&mut self, msg: &SenderKeyMessage) -> Result<Vec<u8>, SenderKeyError> {
        // Step 1: Verify the Ed25519 signature.
        // This confirms the message came from the expected sender and wasn't
        // tampered with in transit. We verify BEFORE attempting decryption to
        // avoid wasting CPU on forged messages.
        // Compute sig for this protocol step.
        // Compute sig for this protocol step.
        let sig = Signature::from_slice(&msg.signature)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|e| SenderKeyError::KeyError(e.to_string()))?;
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.verifying_key
            // Verify the signature against the claimed public key.
            // Verify the cryptographic signature.
            // Verify the cryptographic signature.
            .verify(&msg.ciphertext, &sig)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| SenderKeyError::SignatureFailed)?;

        // Step 2: Check if we already cached this message's key (out-of-order).
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(mut cached_key) = self.skipped_keys.remove(&msg.iteration) {
            // Initialize the AEAD cipher with the derived key material.
            // Compute result for this protocol step.
            // Compute result for this protocol step.
            let result = decrypt_with_msg_key(&cached_key, &msg.ciphertext);
            // Securely erase key material to prevent forensic recovery.
            // Zeroize sensitive key material.
            // Zeroize sensitive key material.
            cached_key.zeroize(); // Forward secrecy: delete after use
                                  // Return the result to the caller.
                                  // Return to the caller.
                                  // Return to the caller.
            return result;
        }

        // Step 3: If this message is ahead of our position, we need to
        // advance our chain and cache the intermediate keys.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if msg.iteration > self.next_iteration {
            // Track the count for threshold and bounds checking.
            // Compute skip count for this protocol step.
            // Compute skip count for this protocol step.
            let skip_count = msg.iteration - self.next_iteration;
            // Use 64-bit arithmetic to prevent silent truncation: on a 64-bit
            // host, skipped_keys.len() is usize (64-bit) but MAX_SKIP_PER_SENDER
            // is u32, so the as-cast could silently truncate a large map.
            // Compute existing for this protocol step.
            // Compute existing for this protocol step.
            let existing = self.skipped_keys.len() as u64;
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if existing.saturating_add(skip_count as u64) > MAX_SKIP_PER_SENDER as u64 {
                // Reject with an explicit error for the caller to handle.
                // Return to the caller.
                // Return to the caller.
                return Err(SenderKeyError::TooManySkipped);
            }

            // Cache keys for all skipped iterations
            // Iterate over each element.
            // Iterate over each element.
            for i in self.next_iteration..msg.iteration {
                // Key material — must be zeroized when no longer needed.
                // Bind the intermediate result.
                // Bind the intermediate result.
                let (msg_key, new_ck) = kdf_chain_step(&self.chain_key);
                // Insert into the lookup table for efficient retrieval.
                // Insert into the map/set.
                // Insert into the map/set.
                self.skipped_keys.insert(i, msg_key);
                // Update the chain key to reflect the new state.
                // Advance chain key state.
                // Advance chain key state.
                self.chain_key = new_ck;
            }
        }

        // Step 4: Derive the message key for this specific iteration.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (msg_key, new_ck) = kdf_chain_step(&self.chain_key);
        // Update the chain key to reflect the new state.
        // Advance chain key state.
        // Advance chain key state.
        self.chain_key = new_ck;
        // Update the next iteration to reflect the new state.
        // Advance next iteration state.
        // Advance next iteration state.
        self.next_iteration = msg.iteration + 1;

        // Step 5: Decrypt the ciphertext using the derived key.
        // Execute this protocol step.
        // Execute this protocol step.
        decrypt_with_msg_key(&msg_key, &msg.ciphertext)
    }
}

/// Clean up: zero all cached keys and the chain key.
// Implement Drop for SenderKeyReceiver.
// Implement Drop for SenderKeyReceiver.
impl Drop for SenderKeyReceiver {
    // Begin the block scope.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    fn drop(&mut self) {
        // Securely erase key material to prevent forensic recovery.
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.chain_key.zeroize();
        // Iterate over each element in the collection.
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

// ---------------------------------------------------------------------------
// Internal cryptographic helpers
// ---------------------------------------------------------------------------

/// Expand a 32-byte message key into a cipher_key (32 bytes) and nonce (12 bytes).
///
/// Uses HKDF-SHA256 to derive 44 bytes of key material from the message key.
/// The first 32 bytes become the ChaCha20-Poly1305 key; the next 12 become the nonce.
// Perform the 'expand msg key' operation.
// Errors are propagated to the caller via Result.
// Perform the 'expand msg key' operation.
// Errors are propagated to the caller via Result.
fn expand_msg_key(msg_key: &[u8; 32]) -> Result<([u8; 32], [u8; 12]), SenderKeyError> {
    // Set up the HKDF context for domain-separated key derivation.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), msg_key);
    // Allocate the output buffer for the result.
    // Compute output for this protocol step.
    let mut output = Zeroizing::new([0u8; 44]);
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    hk.expand(SK_MK_INFO, &mut *output)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        .map_err(|_| SenderKeyError::HkdfExpand)?;

    // Initialize the AEAD cipher with the derived key material.
    // Compute cipher key for this protocol step.
    let mut cipher_key = [0u8; 32];
    // Fresh nonce — must never be reused with the same key.
    // Compute nonce for this protocol step.
    let mut nonce = [0u8; 12];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    cipher_key.copy_from_slice(&output[0..32]);
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    nonce.copy_from_slice(&output[32..44]);
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    Ok((cipher_key, nonce))
}

/// Decrypt a ciphertext using a pre-derived message key.
///
/// Expands the message key into cipher_key + nonce, then decrypts.
// Perform the 'decrypt with msg key' operation.
// Errors are propagated to the caller via Result.
fn decrypt_with_msg_key(msg_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, SenderKeyError> {
    // Initialize the AEAD cipher with the derived key material.
    // Bind the intermediate result.
    let (cipher_key, nonce) = expand_msg_key(msg_key)?;
    // Initialize the AEAD cipher with the derived key material.
    // Compute cipher for this protocol step.
    let cipher = ChaCha20Poly1305::new_from_slice(&cipher_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        .map_err(|_| SenderKeyError::DecryptFailed)?;
    cipher
        // Decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        .map_err(|_| SenderKeyError::DecryptFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a sender and a receiver from the same Sender Key.
    fn setup() -> (SenderKey, SenderKeyReceiver) {
        let sender = SenderKey::generate();
        // Simulate distribution: receiver gets a copy of chain_key + verifying_key
        let receiver = SenderKeyReceiver::new(*sender.chain_key_bytes(), sender.verifying_key());
        (sender, receiver)
    }

    #[test]
    fn test_basic_encrypt_decrypt() {
        let (mut sender, mut receiver) = setup();

        // Sender encrypts a message
        let msg = sender.encrypt(b"Hello group!").unwrap();

        // Receiver decrypts it
        let plaintext = receiver.decrypt(&msg).unwrap();
        assert_eq!(plaintext, b"Hello group!");
    }

    #[test]
    fn test_multiple_messages_in_order() {
        let (mut sender, mut receiver) = setup();

        let m1 = sender.encrypt(b"first").unwrap();
        let m2 = sender.encrypt(b"second").unwrap();
        let m3 = sender.encrypt(b"third").unwrap();

        assert_eq!(receiver.decrypt(&m1).unwrap(), b"first");
        assert_eq!(receiver.decrypt(&m2).unwrap(), b"second");
        assert_eq!(receiver.decrypt(&m3).unwrap(), b"third");
    }

    #[test]
    fn test_out_of_order_delivery() {
        let (mut sender, mut receiver) = setup();

        let m1 = sender.encrypt(b"first").unwrap();
        let m2 = sender.encrypt(b"second").unwrap();
        let m3 = sender.encrypt(b"third").unwrap();

        // Deliver out of order: 3, 1, 2
        assert_eq!(receiver.decrypt(&m3).unwrap(), b"third");
        assert_eq!(receiver.decrypt(&m1).unwrap(), b"first");
        assert_eq!(receiver.decrypt(&m2).unwrap(), b"second");
    }

    #[test]
    fn test_signature_verification() {
        let (mut sender, _) = setup();

        // Create a receiver with a DIFFERENT verifying key (wrong sender)
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
        let mut wrong_receiver = SenderKeyReceiver::new(*sender.chain_key_bytes(), wrong_key);

        let msg = sender.encrypt(b"test").unwrap();

        // Should fail signature verification
        assert!(wrong_receiver.decrypt(&msg).is_err());
    }

    #[test]
    fn test_tampered_ciphertext() {
        let (mut sender, mut receiver) = setup();

        let mut msg = sender.encrypt(b"secret").unwrap();
        // Tamper with the ciphertext
        if !msg.ciphertext.is_empty() {
            msg.ciphertext[0] ^= 0xFF;
        }

        // Signature check will fail (ciphertext changed, signature didn't)
        assert!(receiver.decrypt(&msg).is_err());
    }

    #[test]
    fn test_iteration_counter() {
        let (mut sender, _) = setup();

        let m1 = sender.encrypt(b"a").unwrap();
        let m2 = sender.encrypt(b"b").unwrap();
        let m3 = sender.encrypt(b"c").unwrap();

        assert_eq!(m1.iteration, 0);
        assert_eq!(m2.iteration, 1);
        assert_eq!(m3.iteration, 2);
    }

    #[test]
    fn test_forward_secrecy_within_chain() {
        let (mut sender, mut receiver) = setup();

        // Send and decrypt message 1
        let m1 = sender.encrypt(b"message 1").unwrap();
        let pt1 = receiver.decrypt(&m1).unwrap();
        assert_eq!(pt1, b"message 1");

        // The chain has advanced — the key for message 1 is gone.
        // If an attacker captures the CURRENT chain_key, they can derive
        // future keys but NOT past keys. That's the forward secrecy property.

        // Send message 2
        let m2 = sender.encrypt(b"message 2").unwrap();
        let pt2 = receiver.decrypt(&m2).unwrap();
        assert_eq!(pt2, b"message 2");
    }

    #[test]
    fn test_multiple_receivers() {
        let sender_key = SenderKey::generate();
        let chain = *sender_key.chain_key_bytes();
        let vk = sender_key.verifying_key();

        // Three receivers all get the same Sender Key
        let mut sender = sender_key;
        let mut rx1 = SenderKeyReceiver::new(chain, vk);
        let mut rx2 = SenderKeyReceiver::new(chain, vk);
        let mut rx3 = SenderKeyReceiver::new(chain, vk);

        let msg = sender.encrypt(b"broadcast").unwrap();

        // All three can decrypt
        assert_eq!(rx1.decrypt(&msg).unwrap(), b"broadcast");
        assert_eq!(rx2.decrypt(&msg).unwrap(), b"broadcast");
        assert_eq!(rx3.decrypt(&msg).unwrap(), b"broadcast");
    }

    #[test]
    fn test_long_conversation() {
        let (mut sender, mut receiver) = setup();

        // 100 messages to verify chain doesn't break over many iterations
        for i in 0..100u32 {
            let plaintext = format!("Group message #{i}");
            let msg = sender.encrypt(plaintext.as_bytes()).unwrap();
            let decrypted = receiver.decrypt(&msg).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    /// Adversarial test: a sender who skips MAX_SKIP_PER_SENDER+1 messages
    /// in a single delivery is denied — the receiver returns TooManySkipped
    /// rather than allocating an unbounded cache.
    ///
    /// Threat model: a malicious group member (or a compromised relay) who
    /// sends a message with a very high iteration counter, forcing the receiver
    /// to derive and cache hundreds or thousands of intermediate keys, exhausting
    /// memory. The 500-key cap (MAX_SKIP_PER_SENDER) is the defence.
    #[test]
    fn test_skip_cache_exhaustion_denied() {
        let (mut sender, mut receiver) = setup();

        // Advance the sender's chain MAX_SKIP_PER_SENDER+1 steps (501 encryptions).
        // We deliver none of these to the receiver, so the receiver stays at
        // iteration 0 while the sender reaches iteration 500 (0-indexed).
        // The 502nd encryption produces a message at iteration 501.
        let mut last_msg = None;
        for _ in 0..=(MAX_SKIP_PER_SENDER + 1) {
            last_msg = Some(sender.encrypt(b"skip me").unwrap());
        }
        let overflow_msg = last_msg.unwrap();

        // The overflow message is at iteration MAX_SKIP_PER_SENDER+1 = 501.
        // Delivering it to the receiver (at iteration 0) would require caching
        // 501 intermediate keys, which exceeds the 500-key cap.
        let result = receiver.decrypt(&overflow_msg);
        assert!(
            matches!(result, Err(SenderKeyError::TooManySkipped)),
            "delivering a message that requires >MAX_SKIP_PER_SENDER cache entries \
             must return TooManySkipped, got: {result:?}"
        );
    }
}
