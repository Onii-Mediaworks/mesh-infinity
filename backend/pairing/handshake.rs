//! Pairing Handshake (§3.5, §8.3)
//!
//! # What is the Pairing Handshake?
//!
//! After key material has been exchanged via any pairing method
//! (QR, NFC, code, etc.), both parties run the Sigma protocol
//! handshake to prove they actually possess the private keys
//! corresponding to the public keys they shared.
//!
//! # Why Sigma Protocol?
//!
//! The Sigma protocol (§3.5) is a zero-knowledge proof of key
//! possession. It proves "I hold the private key for this public
//! key" without revealing the private key. This prevents
//! impersonation attacks where an adversary replays captured
//! public keys.
//!
//! # Handshake Flow
//!
//! 1. **Initiator** sends a challenge (random nonce).
//! 2. **Responder** proves key possession by signing the challenge
//!    with their private key, and sends their own challenge.
//! 3. **Initiator** verifies the proof and sends their own proof.
//! 4. Both parties now have mutual proof of key possession.
//!
//! # After the Handshake
//!
//! Once the handshake succeeds:
//! - A contact record is created (or updated)
//! - Safety numbers are computed (§3.7.7)
//! - The user is prompted for optional trust assignment
//! - If both parties assign Level 6+, X3DH key agreement
//!   establishes a private channel

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;
use super::methods::PairingPayload;

// ---------------------------------------------------------------------------
// Handshake State
// ---------------------------------------------------------------------------

/// The state machine for a pairing handshake.
///
/// Tracks the progress of the Sigma protocol exchange between
/// two peers during pairing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting to start. No messages exchanged yet.
    Idle,

    /// We sent a challenge and are waiting for the peer's proof.
    ChallengeSent {
        /// The challenge nonce we sent.
        our_challenge: [u8; 32],
    },

    /// We received the peer's proof and sent our own.
    /// Waiting for the peer to acknowledge.
    ProofSent {
        /// The challenge nonce we sent.
        our_challenge: [u8; 32],
        /// The challenge nonce the peer sent.
        peer_challenge: [u8; 32],
    },

    /// Handshake completed successfully. Both parties have
    /// proven key possession.
    Completed {
        /// The peer's verified peer ID.
        peer_id: PeerId,
    },

    /// Handshake failed.
    Failed(HandshakeError),
}

/// Errors that can occur during the handshake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeError {
    /// The peer's proof didn't verify — they don't hold the
    /// private key for their claimed public key.
    ProofVerificationFailed,
    /// The handshake timed out — the peer didn't respond.
    Timeout,
    /// The pairing payload was invalid or expired.
    InvalidPayload,
    /// The peer ID doesn't match what we expected.
    PeerIdMismatch,
    /// The handshake was cancelled by the user or peer.
    Cancelled,
}

// ---------------------------------------------------------------------------
// Handshake Messages
// ---------------------------------------------------------------------------

/// A challenge message (Step 1 or Step 2 of the Sigma protocol).
///
/// Contains a random nonce that the other party must sign to
/// prove key possession.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeMessage {
    /// Random 32-byte challenge nonce.
    pub challenge: [u8; 32],

    /// The sender's peer ID (for identification).
    pub sender_peer_id: PeerId,

    /// Unix timestamp (for freshness checking).
    pub timestamp: u64,
}

/// A proof message (response to a challenge).
///
/// Contains the Ed25519 signature over the challenge nonce,
/// proving that the sender holds the private key corresponding
/// to their claimed public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMessage {
    /// The challenge nonce that was signed.
    pub challenge: [u8; 32],

    /// Ed25519 signature over:
    /// "meshinfinity-sigma-proof-v1" || challenge || sender_peer_id
    pub signature: Vec<u8>,

    /// The sender's peer ID.
    pub sender_peer_id: PeerId,

    /// The sender's counter-challenge (Step 2 only).
    /// Absent in the final proof (Step 3).
    pub counter_challenge: Option<[u8; 32]>,
}

/// Domain separator for Sigma protocol proofs.
///
/// Included in the signed message to prevent cross-protocol
/// signature reuse. An adversary can't take a signature from
/// a different protocol and use it as a Sigma proof.
pub const SIGMA_DOMAIN: &[u8] = b"meshinfinity-sigma-proof-v1";

// ---------------------------------------------------------------------------
// Handshake Session
// ---------------------------------------------------------------------------

/// A pairing handshake session.
///
/// Manages the state of a single pairing handshake between two peers.
/// Tracks the exchange of challenges and proofs, and determines
/// when the handshake is complete.
pub struct HandshakeSession {
    /// Current handshake state.
    pub state: HandshakeState,

    /// The peer's pairing payload (received via QR, NFC, etc.).
    pub peer_payload: PairingPayload,

    /// When this session was created (Unix timestamp).
    pub created_at: u64,

    /// Session timeout (seconds). Default: 60.
    pub timeout_secs: u64,
}

/// Default handshake timeout (seconds).
///
/// 60 seconds is generous for an interactive pairing flow.
/// The user should be physically present or on a call.
pub const DEFAULT_HANDSHAKE_TIMEOUT: u64 = 60;

impl HandshakeSession {
    /// Create a new handshake session.
    ///
    /// `peer_payload`: the pairing payload received from the peer.
    /// `now`: current unix timestamp.
    pub fn new(peer_payload: PairingPayload, now: u64) -> Self {
        Self {
            state: HandshakeState::Idle,
            peer_payload,
            created_at: now,
            timeout_secs: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Start the handshake by generating and sending a challenge.
    ///
    /// `challenge`: 32 bytes of random entropy (from CSPRNG).
    /// Returns the ChallengeMessage to send to the peer.
    pub fn initiate(
        &mut self,
        challenge: [u8; 32],
        our_peer_id: PeerId,
        now: u64,
    ) -> ChallengeMessage {
        self.state = HandshakeState::ChallengeSent {
            our_challenge: challenge,
        };

        ChallengeMessage {
            challenge,
            sender_peer_id: our_peer_id,
            timestamp: now,
        }
    }

    /// Process a received proof message from the peer.
    ///
    /// Verifies that the proof is valid (the peer signed our challenge
    /// with their Ed25519 private key). If valid, advances the
    /// handshake state.
    ///
    /// `proof`: the proof message from the peer.
    /// `verify_fn`: a closure that verifies an Ed25519 signature.
    ///   Takes (public_key, message, signature) and returns true if valid.
    ///
    /// In a full implementation, `verify_fn` would use the ed25519_dalek
    /// crate. We accept a closure for testability.
    pub fn process_proof<F>(
        &mut self,
        proof: &ProofMessage,
        verify_fn: F,
    ) -> Result<(), HandshakeError>
    where
        F: Fn(&[u8; 32], &[u8], &[u8]) -> bool,
    {
        // Verify the peer ID matches the payload.
        let expected_id = PeerId::from_ed25519_pub(&self.peer_payload.ed25519_public);
        if proof.sender_peer_id != expected_id {
            self.state = HandshakeState::Failed(HandshakeError::PeerIdMismatch);
            return Err(HandshakeError::PeerIdMismatch);
        }

        // Build the signed message:
        // SIGMA_DOMAIN || challenge || sender_peer_id
        let mut signed_msg = Vec::with_capacity(
            SIGMA_DOMAIN.len() + 32 + 32,
        );
        signed_msg.extend_from_slice(SIGMA_DOMAIN);
        signed_msg.extend_from_slice(&proof.challenge);
        signed_msg.extend_from_slice(&proof.sender_peer_id.0);

        // Verify the signature.
        if !verify_fn(
            &self.peer_payload.ed25519_public,
            &signed_msg,
            &proof.signature,
        ) {
            self.state = HandshakeState::Failed(
                HandshakeError::ProofVerificationFailed,
            );
            return Err(HandshakeError::ProofVerificationFailed);
        }

        // Advance state based on current state.
        match &self.state {
            HandshakeState::ChallengeSent { our_challenge } => {
                // We sent a challenge, peer proved it. Check that
                // the proof is for OUR challenge.
                if proof.challenge != *our_challenge {
                    self.state = HandshakeState::Failed(
                        HandshakeError::ProofVerificationFailed,
                    );
                    return Err(HandshakeError::ProofVerificationFailed);
                }

                // If the peer also sent a counter-challenge, we need
                // to respond. Otherwise, handshake is complete.
                if let Some(counter) = proof.counter_challenge {
                    self.state = HandshakeState::ProofSent {
                        our_challenge: *our_challenge,
                        peer_challenge: counter,
                    };
                } else {
                    self.state = HandshakeState::Completed {
                        peer_id: proof.sender_peer_id,
                    };
                }
            }
            HandshakeState::Idle => {
                // We received a proof without sending a challenge.
                // This can happen if the peer initiated.
                if let Some(counter) = proof.counter_challenge {
                    self.state = HandshakeState::ProofSent {
                        our_challenge: [0; 32], // We didn't challenge.
                        peer_challenge: counter,
                    };
                }
            }
            _ => {
                // Unexpected state. Ignore duplicate proofs.
            }
        }

        Ok(())
    }

    /// Generate our proof message for the peer's challenge.
    ///
    /// `peer_challenge`: the challenge nonce from the peer.
    /// `our_peer_id`: our own peer ID.
    /// `sign_fn`: a closure that signs a message with our Ed25519 key.
    ///   Takes a message and returns the 64-byte signature.
    pub fn generate_proof<F>(
        &mut self,
        peer_challenge: [u8; 32],
        our_peer_id: PeerId,
        sign_fn: F,
    ) -> ProofMessage
    where
        F: Fn(&[u8]) -> Vec<u8>,
    {
        // Build the message to sign.
        let mut msg = Vec::with_capacity(
            SIGMA_DOMAIN.len() + 32 + 32,
        );
        msg.extend_from_slice(SIGMA_DOMAIN);
        msg.extend_from_slice(&peer_challenge);
        msg.extend_from_slice(&our_peer_id.0);

        let signature = sign_fn(&msg);

        ProofMessage {
            challenge: peer_challenge,
            signature,
            sender_peer_id: our_peer_id,
            counter_challenge: None, // Set by caller if needed.
        }
    }

    /// Mark the handshake as complete.
    pub fn complete(&mut self, peer_id: PeerId) {
        self.state = HandshakeState::Completed { peer_id };
    }

    /// Check if the handshake has timed out.
    pub fn is_timed_out(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) > self.timeout_secs
    }

    /// Check if the handshake is complete.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, HandshakeState::Completed { .. })
    }

    /// Check if the handshake has failed.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, HandshakeState::Failed(_))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test pairing payload.
    fn test_payload(now: u64) -> PairingPayload {
        let ed_pub = [0x42; 32];
        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        PairingPayload {
            version: 1,
            peer_id,
            ed25519_public: ed_pub,
            x25519_public: [0x43; 32],
            pairing_token: [0x44; 32],
            display_name: None,
            display_name_sig: None,
            transport_hints: vec![],
            expiry: now + 3600,
        }
    }

    /// A mock verify function that always succeeds.
    fn always_verify(_pk: &[u8; 32], _msg: &[u8], _sig: &[u8]) -> bool {
        true
    }

    /// A mock verify function that always fails.
    fn never_verify(_pk: &[u8; 32], _msg: &[u8], _sig: &[u8]) -> bool {
        false
    }

    /// A mock sign function that returns dummy bytes.
    fn mock_sign(_msg: &[u8]) -> Vec<u8> {
        vec![0xAA; 64]
    }

    #[test]
    fn test_session_lifecycle() {
        let now = 1000;
        let payload = test_payload(now);
        let peer_id = payload.peer_id;

        let mut session = HandshakeSession::new(payload, now);
        assert_eq!(session.state, HandshakeState::Idle);

        // Step 1: Initiate with a challenge.
        let our_peer_id = PeerId([0x01; 32]);
        let challenge = [0xBB; 32];
        let _msg = session.initiate(challenge, our_peer_id, now);

        assert!(matches!(
            session.state,
            HandshakeState::ChallengeSent { .. }
        ));

        // Step 2: Receive proof from peer.
        let proof = ProofMessage {
            challenge,
            signature: vec![0xCC; 64],
            sender_peer_id: peer_id,
            counter_challenge: None, // No counter-challenge.
        };

        let result = session.process_proof(&proof, always_verify);
        assert!(result.is_ok());
        assert!(session.is_complete());
    }

    #[test]
    fn test_proof_verification_failure() {
        let now = 1000;
        let payload = test_payload(now);
        let peer_id = payload.peer_id;

        let mut session = HandshakeSession::new(payload, now);
        let challenge = [0xBB; 32];
        session.initiate(challenge, PeerId([0x01; 32]), now);

        let proof = ProofMessage {
            challenge,
            signature: vec![0xCC; 64],
            sender_peer_id: peer_id,
            counter_challenge: None,
        };

        // Verification fails.
        let result = session.process_proof(&proof, never_verify);
        assert_eq!(result, Err(HandshakeError::ProofVerificationFailed));
        assert!(session.is_failed());
    }

    #[test]
    fn test_peer_id_mismatch() {
        let now = 1000;
        let payload = test_payload(now);

        let mut session = HandshakeSession::new(payload, now);
        let challenge = [0xBB; 32];
        session.initiate(challenge, PeerId([0x01; 32]), now);

        // Proof with wrong peer ID.
        let proof = ProofMessage {
            challenge,
            signature: vec![0xCC; 64],
            sender_peer_id: PeerId([0xFF; 32]), // Wrong!
            counter_challenge: None,
        };

        let result = session.process_proof(&proof, always_verify);
        assert_eq!(result, Err(HandshakeError::PeerIdMismatch));
    }

    #[test]
    fn test_counter_challenge() {
        let now = 1000;
        let payload = test_payload(now);
        let peer_id = payload.peer_id;

        let mut session = HandshakeSession::new(payload, now);
        let challenge = [0xBB; 32];
        session.initiate(challenge, PeerId([0x01; 32]), now);

        // Peer sends proof WITH a counter-challenge.
        let counter = [0xDD; 32];
        let proof = ProofMessage {
            challenge,
            signature: vec![0xCC; 64],
            sender_peer_id: peer_id,
            counter_challenge: Some(counter),
        };

        session.process_proof(&proof, always_verify).unwrap();

        // Should be in ProofSent state (needs to respond).
        assert!(matches!(
            session.state,
            HandshakeState::ProofSent { .. }
        ));
    }

    #[test]
    fn test_generate_proof() {
        let now = 1000;
        let payload = test_payload(now);
        let mut session = HandshakeSession::new(payload, now);

        let our_peer_id = PeerId([0x01; 32]);
        let peer_challenge = [0xDD; 32];

        let proof = session.generate_proof(
            peer_challenge,
            our_peer_id,
            mock_sign,
        );

        assert_eq!(proof.challenge, peer_challenge);
        assert_eq!(proof.sender_peer_id, our_peer_id);
        assert_eq!(proof.signature.len(), 64);
    }

    #[test]
    fn test_timeout() {
        let now = 1000;
        let payload = test_payload(now);
        let session = HandshakeSession::new(payload, now);

        assert!(!session.is_timed_out(now + 30));
        assert!(session.is_timed_out(now + DEFAULT_HANDSHAKE_TIMEOUT + 1));
    }

    // ── Real cryptographic verification tests ────────────────────────────────

    /// Build a real verify closure using ed25519_dalek.
    fn real_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = match VerifyingKey::from_bytes(pk) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(msg, &sig).is_ok()
    }

    /// Build a real sign closure for a given signing key.
    fn real_sign_with(signing_key: ed25519_dalek::SigningKey) -> impl Fn(&[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        move |msg: &[u8]| signing_key.sign(msg).to_bytes().to_vec()
    }

    /// Build a PairingPayload for a given Ed25519 signing key.
    fn payload_for_key(signing_key: &ed25519_dalek::SigningKey, now: u64) -> super::super::methods::PairingPayload {
        use super::super::methods::PairingPayload;
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let peer_id = PeerId::from_ed25519_pub(&pub_bytes);
        PairingPayload {
            version: 1,
            peer_id,
            ed25519_public: pub_bytes,
            x25519_public: [0x43; 32],
            pairing_token: [0x44; 32],
            display_name: None,
            display_name_sig: None,
            transport_hints: vec![],
            expiry: now + 3600,
        }
    }

    /// Full handshake round-trip with real Ed25519 signatures.
    ///
    /// Alice sends a challenge; Bob generates a real proof (signed with his
    /// private key); Alice verifies with real Ed25519 verification.
    #[test]
    fn test_real_crypto_full_round_trip() {
        use rand_core::OsRng;
        let now = 1000;

        let bob_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let bob_payload = payload_for_key(&bob_sk, now);
        let bob_peer_id = bob_payload.peer_id;

        // Alice initiates.
        let mut alice_session = HandshakeSession::new(bob_payload, now);
        let challenge = [0xBB; 32];
        alice_session.initiate(challenge, PeerId([0x01; 32]), now);

        // Bob generates a real proof by signing SIGMA_DOMAIN || challenge || bob_peer_id.
        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(SIGMA_DOMAIN);
        signed_msg.extend_from_slice(&challenge);
        signed_msg.extend_from_slice(&bob_peer_id.0);

        use ed25519_dalek::Signer;
        let sig = bob_sk.sign(&signed_msg);

        let proof = ProofMessage {
            challenge,
            signature: sig.to_bytes().to_vec(),
            sender_peer_id: bob_peer_id,
            counter_challenge: None,
        };

        // Alice verifies with real Ed25519.
        let result = alice_session.process_proof(&proof, real_verify);
        assert!(result.is_ok(), "real proof from legitimate key must succeed");
        assert!(alice_session.is_complete(), "session must complete after valid proof");
    }

    /// Wrong key: attacker signs with a different key — verification must fail.
    #[test]
    fn test_real_crypto_wrong_key_rejected() {
        use rand_core::OsRng;
        let now = 1000;

        let legitimate_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let attacker_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let legitimate_payload = payload_for_key(&legitimate_sk, now);
        let legitimate_peer_id = legitimate_payload.peer_id;

        let mut session = HandshakeSession::new(legitimate_payload, now);
        let challenge = [0xBB; 32];
        session.initiate(challenge, PeerId([0x01; 32]), now);

        // Attacker signs with wrong key.
        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(SIGMA_DOMAIN);
        signed_msg.extend_from_slice(&challenge);
        signed_msg.extend_from_slice(&legitimate_peer_id.0);

        use ed25519_dalek::Signer;
        let forged_sig = attacker_sk.sign(&signed_msg);

        let proof = ProofMessage {
            challenge,
            signature: forged_sig.to_bytes().to_vec(),
            sender_peer_id: legitimate_peer_id,
            counter_challenge: None,
        };

        let result = session.process_proof(&proof, real_verify);
        assert_eq!(result, Err(HandshakeError::ProofVerificationFailed),
            "attacker's forged proof must be rejected");
    }

    /// Replay: a valid proof from an earlier session is rejected because
    /// the challenge bytes are different.
    #[test]
    fn test_real_crypto_wrong_challenge_rejected() {
        use rand_core::OsRng;
        let now = 1000;

        let peer_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let peer_payload = payload_for_key(&peer_sk, now);
        let peer_id = peer_payload.peer_id;

        let mut session = HandshakeSession::new(peer_payload, now);
        let challenge_a = [0x11; 32];
        session.initiate(challenge_a, PeerId([0x01; 32]), now);

        // Peer signs challenge_B (different from what Alice sent).
        let challenge_b = [0x22; 32];
        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(SIGMA_DOMAIN);
        signed_msg.extend_from_slice(&challenge_b); // wrong challenge
        signed_msg.extend_from_slice(&peer_id.0);

        use ed25519_dalek::Signer;
        let sig = peer_sk.sign(&signed_msg);

        let proof = ProofMessage {
            challenge: challenge_b,    // doesn't match our_challenge (challenge_a)
            signature: sig.to_bytes().to_vec(),
            sender_peer_id: peer_id,
            counter_challenge: None,
        };

        // process_proof checks proof.challenge == our_challenge.
        let result = session.process_proof(&proof, real_verify);
        assert!(result.is_err(), "proof for wrong challenge must be rejected");
    }

    /// generate_proof + process_proof full round-trip with real Ed25519.
    #[test]
    fn test_real_crypto_generate_and_verify() {
        use rand_core::OsRng;
        let now = 1000;

        let peer_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let peer_payload = payload_for_key(&peer_sk, now);
        let peer_id = peer_payload.peer_id;

        let mut session = HandshakeSession::new(peer_payload, now);
        let challenge = [0xBB; 32];
        session.initiate(challenge, PeerId([0x01; 32]), now);

        // Use generate_proof with a real signing closure.
        let mut scratch_session = HandshakeSession::new(
            payload_for_key(&peer_sk, now),
            now,
        );
        let proof = scratch_session.generate_proof(
            challenge,
            peer_id,
            real_sign_with(ed25519_dalek::SigningKey::from_bytes(&peer_sk.to_bytes())),
        );

        let result = session.process_proof(&proof, real_verify);
        assert!(result.is_ok(), "generate_proof output must verify with real crypto");
    }
}
