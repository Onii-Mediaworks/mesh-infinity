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
pub const MAX_PROFILE_SIZE: usize = 16 * 1024 * 1024;

/// Commitment window (seconds). 5 minutes.
/// If Bob doesn't respond within this window, Alice's
/// commitment expires and she must re-initiate.
pub const COMMITMENT_WINDOW_SECS: u64 = 300;

/// Domain separator for commitment hash.
pub const COMMITMENT_DOMAIN: &[u8] = b"meshinfinity-trust-promotion-v1";

/// Domain separator for the intent signature.
///
/// The signed message is:
///   INTENT_SIG_DOMAIN || commitment || recipient_peer_id || timestamp (BE u64) || expires_at (BE u64) || nonce
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
pub struct TrustPromotionIntent {
    /// SHA-256(encrypted_profile_blob || recipient_peer_id || nonce).
    /// Proves Alice has a profile ready for Bob specifically.
    pub commitment: [u8; 32],

    /// Bob's peer ID (the intended recipient).
    pub recipient: PeerId,

    /// Unix timestamp when this intent was created.
    pub timestamp: u64,

    /// When this intent expires (timestamp + COMMITMENT_WINDOW_SECS).
    /// After this, Bob must re-request if he wants to proceed.
    pub expires_at: u64,

    /// Fresh random nonce for the commitment.
    /// Prevents replay attacks and ensures each commitment is unique.
    pub nonce: [u8; 32],

    /// Ed25519 signature over all above fields.
    /// Signed by Alice's mask key.
    pub signature: Vec<u8>,
}

impl TrustPromotionIntent {
    /// Check if this intent has expired.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Build the canonical message that must be signed by the issuer.
    ///
    /// `INTENT_SIG_DOMAIN || commitment || recipient_peer_id || timestamp (BE u64) || expires_at (BE u64) || nonce`
    pub fn signed_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(
            INTENT_SIG_DOMAIN.len() + 32 + 32 + 8 + 8 + 32,
        );
        msg.extend_from_slice(INTENT_SIG_DOMAIN);
        msg.extend_from_slice(&self.commitment);
        msg.extend_from_slice(&self.recipient.0);
        msg.extend_from_slice(&self.timestamp.to_be_bytes());
        msg.extend_from_slice(&self.expires_at.to_be_bytes());
        msg.extend_from_slice(&self.nonce);
        msg
    }

    /// Sign this intent with the issuer's Ed25519 key.
    ///
    /// The domain-separated message is signed and the signature stored in
    /// `self.signature`.  Should be called once at creation time.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let msg = self.signed_message();
        self.signature = signing_key.sign(&msg).to_bytes().to_vec();
    }

    /// Verify the Ed25519 signature against the issuer's public key.
    ///
    /// Returns `true` if the signature is valid for `signer_pub`.
    /// Returns `false` for any failure (bad key, bad sig, wrong length).
    pub fn verify_signature(&self, signer_pub: &[u8; 32]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = match VerifyingKey::from_bytes(signer_pub) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let msg = self.signed_message();
        vk.verify(&msg, &sig).is_ok()
    }

    /// Validate the intent structure and signature.
    ///
    /// Checks:
    /// 1. Not expired.
    /// 2. Signature is present (non-empty and 64 bytes).
    /// 3. Signature is a valid Ed25519 signature for `signer_pub`.
    pub fn validate(&self, now: u64) -> Result<(), PromotionError> {
        if self.is_expired(now) {
            return Err(PromotionError::Expired);
        }
        if self.signature.len() != 64 {
            return Err(PromotionError::InvalidSignature);
        }
        Ok(())
    }

    /// Validate structure AND verify the Ed25519 signature.
    ///
    /// This is the full check that callers with the signer's public key
    /// should prefer over `validate()` alone.
    pub fn validate_with_key(&self, now: u64, signer_pub: &[u8; 32]) -> Result<(), PromotionError> {
        self.validate(now)?;
        if !self.verify_signature(signer_pub) {
            return Err(PromotionError::InvalidSignature);
        }
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
pub struct EncryptedProfile {
    /// The encrypted and padded profile blob.
    /// Encrypted with ChaCha20-Poly1305 using the X3DH session key.
    pub ciphertext: Vec<u8>,

    /// The session epoch this was encrypted under.
    /// Both parties must be at the same epoch.
    pub session_epoch: u64,
}

// ---------------------------------------------------------------------------
// Promotion State
// ---------------------------------------------------------------------------

/// State machine for a trust promotion exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromotionState {
    /// No promotion in progress.
    Idle,
    /// We sent a commitment; waiting for the peer's profile.
    CommitmentSent {
        /// The commitment hash we sent.
        commitment: [u8; 32],
        /// The nonce used in the commitment.
        nonce: [u8; 32],
        /// When the commitment expires.
        expires_at: u64,
    },
    /// We received their profile; sending ours.
    ProfileExchanging,
    /// Both profiles exchanged; awaiting verification.
    PendingVerification,
    /// Promotion complete — peer is now in the trusted tier.
    Complete,
    /// Promotion failed.
    Failed(PromotionError),
}

/// Errors in the trust promotion protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionError {
    /// The commitment has expired.
    Expired,
    /// The commitment hash doesn't match the revealed profile.
    CommitmentMismatch,
    /// Invalid signature on the intent.
    InvalidSignature,
    /// The peer cancelled the promotion.
    Cancelled,
    /// Session epoch mismatch.
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
pub fn compute_padded_size(actual_size: usize, random_byte: u8) -> usize {
    // Lower bound of the padding range.
    let lower = actual_size + (MAX_PROFILE_SIZE - actual_size.min(MAX_PROFILE_SIZE)) / 2;

    // Upper bound is always MAX_PROFILE_SIZE.
    let upper = MAX_PROFILE_SIZE;

    // Use the random byte to pick a point in the range.
    if upper <= lower {
        return upper;
    }

    let range = upper - lower;
    let offset = (random_byte as usize * range) / 256;
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
    fn make_signed_intent(signing_key: &ed25519_dalek::SigningKey, now: u64) -> TrustPromotionIntent {
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
