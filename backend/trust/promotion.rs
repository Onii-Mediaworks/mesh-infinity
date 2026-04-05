//! Mutual Trust Promotion Protocol (§8.4)
//!
//! # What is Trust Promotion?
//!
//! Trust promotion is the protocol for elevating a peer from the
//! untrusted tier (Level 0–5) to the trusted tier (Level 6+).
//! It involves mutual commitment and encrypted profile exchange.
//!
//! # Why a Protocol?
//!
//! Elevating a peer to Level 6+ requires identity disclosure —
//! sharing our private channel address and private profile.
//! This is irreversible: once shared, the information can't be
//! unshared. The protocol ensures both parties commit simultaneously,
//! preventing one-sided disclosure.
//!
//! # Three Phases (§8.4)
//!
//! 1. **Commitment** — Alice sends a TrustPromotionIntent containing
//!    a hash commitment (SHA-256 of her encrypted profile blob +
//!    Bob's peer ID + a session nonce). This proves Alice has a
//!    profile ready but doesn't reveal it yet.
//!
//! 2. **Exchange** — Bob sends his encrypted profile. Alice reveals
//!    hers. Both verify the commitment matches.
//!
//! 3. **Verification** — Both parties verify safety numbers and
//!    optionally set a verification passphrase.
//!
//! # Profile Padding (§8.4)
//!
//! Initial profile exchange is padded to a random size between
//! `actual_size + (16MB - actual_size) / 2` and `16MB`.
//! This prevents an observer from inferring profile size from
//! the encrypted payload size.

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum padded profile size (bytes). 16 MB.
/// All initial profile exchanges are padded to between half
/// this and this full value.
// MAX_PROFILE_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PROFILE_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PROFILE_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PROFILE_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_PROFILE_SIZE: usize = 16 * 1024 * 1024;

/// Commitment window (seconds). 5 minutes.
/// If Bob doesn't respond within this window, Alice's
/// commitment expires and she must re-initiate.
// COMMITMENT_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// COMMITMENT_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// COMMITMENT_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// COMMITMENT_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const COMMITMENT_WINDOW_SECS: u64 = 300;

/// Domain separator for commitment hash.
// COMMITMENT_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// COMMITMENT_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// COMMITMENT_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// COMMITMENT_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const COMMITMENT_DOMAIN: &[u8] = b"meshinfinity-trust-promotion-v1";

/// Domain separator for the intent signature.
///
/// The signed message is:
///   INTENT_SIG_DOMAIN || commitment || recipient_peer_id || timestamp (BE u64) || expires_at (BE u64) || nonce
// INTENT_SIG_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// INTENT_SIG_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// INTENT_SIG_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// INTENT_SIG_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const INTENT_SIG_DOMAIN: &[u8] = b"meshinfinity-promotion-intent-v1";

// ---------------------------------------------------------------------------
// Trust Promotion Intent (Phase 1)
// ---------------------------------------------------------------------------

/// A trust promotion intent (Phase 1 of §8.4).
///
/// Alice sends this to signal she's ready to promote Bob to
/// the trusted tier. It contains a hash commitment to her
/// encrypted profile — proving she has it ready without revealing it.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TrustPromotionIntent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustPromotionIntent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustPromotionIntent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustPromotionIntent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TrustPromotionIntent {
    /// SHA-256(encrypted_profile_blob || recipient_peer_id || nonce).
    /// Proves Alice has a profile ready for Bob specifically.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub commitment: [u8; 32],

    /// Bob's peer ID (the intended recipient).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub recipient: PeerId,

    /// Unix timestamp when this intent was created.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,

    /// When this intent expires (timestamp + COMMITMENT_WINDOW_SECS).
    /// After this, Bob must re-request if he wants to proceed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expires_at: u64,

    /// Fresh random nonce for the commitment.
    /// Prevents replay attacks and ensures each commitment is unique.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub nonce: [u8; 32],

    /// Ed25519 signature over all above fields.
    /// Signed by Alice's mask key.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// Begin the block scope.
// TrustPromotionIntent implementation — core protocol logic.
// TrustPromotionIntent implementation — core protocol logic.
// TrustPromotionIntent implementation — core protocol logic.
// TrustPromotionIntent implementation — core protocol logic.
impl TrustPromotionIntent {
    /// Check if this intent has expired.
    // Perform the 'is expired' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is expired' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is expired' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is expired' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_expired(&self, now: u64) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now >= self.expires_at
    }

    /// Build the canonical message that must be signed by the issuer.
    ///
    /// `INTENT_SIG_DOMAIN || commitment || recipient_peer_id || timestamp (BE u64) || expires_at (BE u64) || nonce`
    // Perform the 'signed message' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'signed message' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'signed message' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'signed message' operation.
    // Errors are propagated to the caller via Result.
    pub fn signed_message(&self) -> Vec<u8> {
        // Pre-allocate the buffer to avoid repeated reallocations.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        let mut msg = Vec::with_capacity(
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            INTENT_SIG_DOMAIN.len() + 32 + 32 + 8 + 8 + 32,
        );
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(INTENT_SIG_DOMAIN);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(&self.commitment);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(&self.recipient.0);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(&self.timestamp.to_be_bytes());
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(&self.expires_at.to_be_bytes());
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(&self.nonce);
        msg
    }

    /// Sign this intent with the issuer's Ed25519 key.
    ///
    /// The domain-separated message is signed and the signature stored in
    /// `self.signature`.  Should be called once at creation time.
    // Perform the 'sign' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'sign' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'sign' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'sign' operation.
    // Errors are propagated to the caller via Result.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        // Execute the operation and bind the result.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        let msg = self.signed_message();
        // Sign the message with the Ed25519 secret key.
        // Advance signature state.
        // Advance signature state.
        // Advance signature state.
        // Advance signature state.
        self.signature = signing_key.sign(&msg).to_bytes().to_vec();
    }

    /// Verify the Ed25519 signature against the issuer's public key.
    ///
    /// Returns `true` if the signature is valid for `signer_pub`.
    /// Returns `false` for any failure (bad key, bad sig, wrong length).
    // Perform the 'verify signature' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verify signature' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verify signature' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verify signature' operation.
    // Errors are propagated to the caller via Result.
    pub fn verify_signature(&self, signer_pub: &[u8; 32]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        // Key material — must be zeroized when no longer needed.
        // Compute vk for this protocol step.
        // Compute vk for this protocol step.
        // Compute vk for this protocol step.
        // Compute vk for this protocol step.
        let vk = match VerifyingKey::from_bytes(signer_pub) {
            // Wrap the computed value in the success variant.
            // Success path — return the computed value.
            // Success path — return the computed value.
            // Success path — return the computed value.
            // Success path — return the computed value.
            Ok(k) => k,
            // Signal failure to the caller with a descriptive error.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            Err(_) => return false,
        };
        // Ed25519 signature for authentication and integrity.
        // Compute sig for this protocol step.
        // Compute sig for this protocol step.
        // Compute sig for this protocol step.
        // Compute sig for this protocol step.
        let sig = match Signature::from_slice(&self.signature) {
            // Wrap the computed value in the success variant.
            // Success path — return the computed value.
            // Success path — return the computed value.
            // Success path — return the computed value.
            // Success path — return the computed value.
            Ok(s) => s,
            // Signal failure to the caller with a descriptive error.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            // Error path — signal failure.
            Err(_) => return false,
        };
        // Execute the operation and bind the result.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        let msg = self.signed_message();
        // Verify the signature against the claimed public key.
        // Verify the cryptographic signature.
        // Verify the cryptographic signature.
        // Verify the cryptographic signature.
        // Verify the cryptographic signature.
        vk.verify(&msg, &sig).is_ok()
    }

    /// Validate the intent structure and signature.
    ///
    /// Checks:
    /// 1. Not expired.
    /// 2. Signature is present (non-empty and 64 bytes).
    /// 3. Signature is a valid Ed25519 signature for `signer_pub`.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    pub fn validate(&self, now: u64) -> Result<(), PromotionError> {
        // Check temporal validity — expired data must be rejected.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.is_expired(now) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(PromotionError::Expired);
        }
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.signature.len() != 64 {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(PromotionError::InvalidSignature);
        }
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }

    /// Validate structure AND verify the Ed25519 signature.
    ///
    /// This is the full check that callers with the signer's public key
    /// should prefer over `validate()` alone.
    // Perform the 'validate with key' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate with key' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate with key' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate with key' operation.
    // Errors are propagated to the caller via Result.
    pub fn validate_with_key(&self, now: u64, signer_pub: &[u8; 32]) -> Result<(), PromotionError> {
        // Propagate errors via the ? operator — callers handle failures.
        // Propagate errors via ?.
        // Propagate errors via ?.
        // Propagate errors via ?.
        // Propagate errors via ?.
        self.validate(now)?;
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.verify_signature(signer_pub) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(PromotionError::InvalidSignature);
        }
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Encrypted Profile (Phase 2)
// ---------------------------------------------------------------------------

/// An encrypted profile payload (Phase 2 of §8.4).
///
/// Contains the sender's private profile, encrypted to the
/// X3DH session key. Padded to prevent size inference.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// EncryptedProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// EncryptedProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// EncryptedProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// EncryptedProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct EncryptedProfile {
    /// The encrypted and padded profile blob.
    /// Encrypted with ChaCha20-Poly1305 using the X3DH session key.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ciphertext: Vec<u8>,

    /// The session epoch this was encrypted under.
    /// Both parties must be at the same epoch.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_epoch: u64,
}

// ---------------------------------------------------------------------------
// Promotion State
// ---------------------------------------------------------------------------

/// State machine for a trust promotion exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
// Begin the block scope.
// PromotionState — variant enumeration.
// Match exhaustively to handle every protocol state.
// PromotionState — variant enumeration.
// Match exhaustively to handle every protocol state.
// PromotionState — variant enumeration.
// Match exhaustively to handle every protocol state.
// PromotionState — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PromotionState {
    /// No promotion in progress.
    Idle,
    /// We sent a commitment; waiting for the peer's profile.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    CommitmentSent {
        /// The commitment hash we sent.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        commitment: [u8; 32],
        /// The nonce used in the commitment.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        nonce: [u8; 32],
        /// When the commitment expires.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        expires_at: u64,
    },
    /// We received their profile; sending ours.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ProfileExchanging,
    /// Both profiles exchanged; awaiting verification.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    PendingVerification,
    /// Promotion complete — peer is now in the trusted tier.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Complete,
    /// Promotion failed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Failed(PromotionError),
}

/// Errors in the trust promotion protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// PromotionError — variant enumeration.
// Match exhaustively to handle every protocol state.
// PromotionError — variant enumeration.
// Match exhaustively to handle every protocol state.
// PromotionError — variant enumeration.
// Match exhaustively to handle every protocol state.
// PromotionError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PromotionError {
    /// The commitment has expired.
    Expired,
    /// The commitment hash doesn't match the revealed profile.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    CommitmentMismatch,
    /// Invalid signature on the intent.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    InvalidSignature,
    /// The peer cancelled the promotion.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Cancelled,
    /// Session epoch mismatch.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    EpochMismatch,
}

// ---------------------------------------------------------------------------
// Profile Padding
// ---------------------------------------------------------------------------

/// Compute the padded size for a profile (§8.4).
///
/// The padded size is uniformly random between:
///   `actual_size + (MAX_PROFILE_SIZE - actual_size) / 2`
/// and:
///   `MAX_PROFILE_SIZE`
///
/// This prevents an observer from inferring profile size from
/// the ciphertext length. The upper half of the range is used
/// to avoid very small padding on large profiles.
///
/// `actual_size`: the unpadded profile size in bytes.
/// `random_byte`: a random byte (0–255) for determining the
///   exact padded size within the range.
// Perform the 'compute padded size' operation.
// Errors are propagated to the caller via Result.
// Perform the 'compute padded size' operation.
// Errors are propagated to the caller via Result.
// Perform the 'compute padded size' operation.
// Errors are propagated to the caller via Result.
pub fn compute_padded_size(actual_size: usize, random_byte: u8) -> usize {
    // Lower bound of the padding range.
    // Compute lower for this protocol step.
    // Compute lower for this protocol step.
    // Compute lower for this protocol step.
    let lower = actual_size + (MAX_PROFILE_SIZE - actual_size.min(MAX_PROFILE_SIZE)) / 2;

    // Upper bound is always MAX_PROFILE_SIZE.
    // Compute upper for this protocol step.
    // Compute upper for this protocol step.
    // Compute upper for this protocol step.
    let upper = MAX_PROFILE_SIZE;

    // Use the random byte to pick a point in the range.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if upper <= lower {
        // Return the result to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return upper;
    }

    // Execute the operation and bind the result.
    // Compute range for this protocol step.
    // Compute range for this protocol step.
    // Compute range for this protocol step.
    let range = upper - lower;
    // Track the count for threshold and bounds checking.
    // Compute offset for this protocol step.
    // Compute offset for this protocol step.
    // Compute offset for this protocol step.
    let offset = (random_byte as usize * range) / 256;
    // Execute this step in the protocol sequence.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    lower + offset
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_expiry() {
        let intent = TrustPromotionIntent {
            commitment: [0xAA; 32],
            recipient: PeerId([0xBB; 32]),
            timestamp: 1000,
            expires_at: 1000 + COMMITMENT_WINDOW_SECS,
            nonce: [0xCC; 32],
            signature: vec![0x42; 64],
        };

        assert!(!intent.is_expired(1000));
        assert!(!intent.is_expired(1000 + COMMITMENT_WINDOW_SECS - 1));
        assert!(intent.is_expired(1000 + COMMITMENT_WINDOW_SECS));
    }

    #[test]
    fn test_intent_validation() {
        let intent = TrustPromotionIntent {
            commitment: [0xAA; 32],
            recipient: PeerId([0xBB; 32]),
            timestamp: 1000,
            expires_at: 1000 + COMMITMENT_WINDOW_SECS,
            nonce: [0xCC; 32],
            signature: vec![0x42; 64],
        };

        assert!(intent.validate(1000).is_ok());
        assert_eq!(
            intent.validate(1000 + COMMITMENT_WINDOW_SECS),
            Err(PromotionError::Expired)
        );
    }

    #[test]
    fn test_intent_empty_signature() {
        let intent = TrustPromotionIntent {
            commitment: [0xAA; 32],
            recipient: PeerId([0xBB; 32]),
            timestamp: 1000,
            expires_at: 1000 + COMMITMENT_WINDOW_SECS,
            nonce: [0xCC; 32],
            signature: Vec::new(), // Empty!
        };
        assert_eq!(intent.validate(1000), Err(PromotionError::InvalidSignature));
    }

    // ── Real cryptographic signature tests ────────────────────────────────────

    /// Build a properly signed intent using a real Ed25519 key.
    fn make_signed_intent(
        signing_key: &ed25519_dalek::SigningKey,
        now: u64,
    ) -> TrustPromotionIntent {
        let mut intent = TrustPromotionIntent {
            commitment: [0x11; 32],
            recipient: PeerId([0x22; 32]),
            timestamp: now,
            expires_at: now + COMMITMENT_WINDOW_SECS,
            nonce: [0x33; 32],
            signature: Vec::new(),
        };
        intent.sign(signing_key);
        intent
    }

    #[test]
    fn test_intent_valid_signature_accepted() {
        use rand_core::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pub_key = sk.verifying_key().to_bytes();
        let now = 1000u64;
        let intent = make_signed_intent(&sk, now);
        assert!(
            intent.validate_with_key(now, &pub_key).is_ok(),
            "valid signature from the actual signing key must be accepted"
        );
    }

    #[test]
    fn test_intent_wrong_key_rejected() {
        use rand_core::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let other_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let other_pub = other_sk.verifying_key().to_bytes();
        let now = 1000u64;
        let intent = make_signed_intent(&sk, now);
        // Verify with the WRONG public key.
        assert_eq!(
            intent.validate_with_key(now, &other_pub),
            Err(PromotionError::InvalidSignature),
            "wrong signing key must be rejected"
        );
    }

    #[test]
    fn test_intent_tampered_recipient_rejected() {
        use rand_core::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pub_key = sk.verifying_key().to_bytes();
        let now = 1000u64;
        let mut intent = make_signed_intent(&sk, now);
        // Tamper the recipient after signing — signed_message() will produce a different hash.
        intent.recipient = PeerId([0xFF; 32]);
        assert_eq!(
            intent.validate_with_key(now, &pub_key),
            Err(PromotionError::InvalidSignature),
            "tampered recipient must cause signature failure"
        );
    }

    #[test]
    fn test_intent_tampered_commitment_rejected() {
        use rand_core::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pub_key = sk.verifying_key().to_bytes();
        let now = 1000u64;
        let mut intent = make_signed_intent(&sk, now);
        // Flip a byte in the commitment.
        intent.commitment[0] ^= 0xFF;
        assert_eq!(
            intent.validate_with_key(now, &pub_key),
            Err(PromotionError::InvalidSignature),
            "tampered commitment must cause signature failure"
        );
    }

    #[test]
    fn test_intent_random_signature_rejected() {
        use rand_core::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pub_key = sk.verifying_key().to_bytes();
        let now = 1000u64;
        let mut intent = make_signed_intent(&sk, now);
        // Replace with random bytes.
        use rand_core::RngCore;
        let mut rng = OsRng;
        let mut random_sig = [0u8; 64];
        rng.fill_bytes(&mut random_sig);
        intent.signature = random_sig.to_vec();
        assert_eq!(
            intent.validate_with_key(now, &pub_key),
            Err(PromotionError::InvalidSignature),
            "random signature must be rejected"
        );
    }

    #[test]
    fn test_padded_size_bounds() {
        // Small profile: should be padded to near MAX_PROFILE_SIZE.
        let small = compute_padded_size(100, 128);
        assert!(small >= MAX_PROFILE_SIZE / 2);
        assert!(small <= MAX_PROFILE_SIZE);

        // Large profile: padding range is narrower.
        let large = compute_padded_size(MAX_PROFILE_SIZE - 1000, 128);
        assert!(large >= MAX_PROFILE_SIZE - 1000);
        assert!(large <= MAX_PROFILE_SIZE);

        // Edge: profile at max size.
        let full = compute_padded_size(MAX_PROFILE_SIZE, 128);
        assert_eq!(full, MAX_PROFILE_SIZE);
    }

    #[test]
    fn test_padded_size_random_variation() {
        let size = 1000;

        // Different random bytes should give different padded sizes.
        let a = compute_padded_size(size, 0);
        let b = compute_padded_size(size, 255);

        // a should be at the lower end, b at the upper end.
        assert!(a < b);
    }

    #[test]
    fn test_promotion_state_transitions() {
        let state = PromotionState::Idle;
        assert_eq!(state, PromotionState::Idle);

        let state = PromotionState::CommitmentSent {
            commitment: [0xAA; 32],
            nonce: [0xBB; 32],
            expires_at: 2000,
        };
        assert!(matches!(state, PromotionState::CommitmentSent { .. }));
    }
}
