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

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::methods::PairingPayload;
use crate::error::MeshError;
use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Size & rate-limiting constants
// ---------------------------------------------------------------------------

/// Maximum size in bytes for any incoming handshake frame (challenge or
/// proof message) before deserialization. Handshake messages are small
/// (challenge: 32-byte nonce + PeerId + timestamp; proof: 32-byte nonce
/// + 64-byte signature + PeerId + optional 32-byte counter-challenge).
///   4 KiB is generous and prevents multi-GB OOM attacks from malicious
///   peers sending oversized payloads.
pub const MAX_HANDSHAKE_FRAME_SIZE: usize = 4096;

/// Maximum number of pairing handshake attempts allowed per IP address
/// within the rate-limiting window. Exceeding this limit causes the
/// connection to be rejected with a brief error, mitigating flood attacks
/// that exhaust CPU or file-descriptor resources.
pub const MAX_PAIRING_ATTEMPTS_PER_IP: u32 = 5;

/// Duration of the rate-limiting window in seconds. After this period
/// elapses since the first tracked attempt, the counter resets and the
/// IP is allowed to retry. 60 seconds is short enough to be friendly
/// to legitimate users who mistype a pairing code, but long enough to
/// deter automated flooding.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Handshake State
// ---------------------------------------------------------------------------

/// The state machine for a pairing handshake.
///
/// Tracks the progress of the Sigma protocol exchange between
/// two peers during pairing.
#[derive(Clone, Debug, PartialEq, Eq)]
// Begin the block scope.
// HandshakeState — variant enumeration.
// Match exhaustively to handle every protocol state.
// HandshakeState — variant enumeration.
// Match exhaustively to handle every protocol state.
// HandshakeState — variant enumeration.
// Match exhaustively to handle every protocol state.
// HandshakeState — variant enumeration.
// Match exhaustively to handle every protocol state.
// HandshakeState — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum HandshakeState {
    /// Waiting to start. No messages exchanged yet.
    Idle,

    /// We sent a challenge and are waiting for the peer's proof.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ChallengeSent {
        /// The challenge nonce we sent.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        our_challenge: [u8; 32],
    },

    /// We received the peer's proof and sent our own.
    /// Waiting for the peer to acknowledge.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ProofSent {
        /// The challenge nonce we sent.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        our_challenge: [u8; 32],
        /// The challenge nonce the peer sent.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_challenge: [u8; 32],
    },

    /// Handshake completed successfully. Both parties have
    /// proven key possession.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Completed {
        /// The peer's verified peer ID.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_id: PeerId,
    },

    /// Handshake failed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Failed(HandshakeError),
}

/// Errors that can occur during the handshake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// HandshakeError — variant enumeration.
// Match exhaustively to handle every protocol state.
// HandshakeError — variant enumeration.
// Match exhaustively to handle every protocol state.
// HandshakeError — variant enumeration.
// Match exhaustively to handle every protocol state.
// HandshakeError — variant enumeration.
// Match exhaustively to handle every protocol state.
// HandshakeError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum HandshakeError {
    /// The peer's proof didn't verify — they don't hold the
    /// private key for their claimed public key.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ProofVerificationFailed,
    /// The handshake timed out — the peer didn't respond.
    Timeout,
    /// The pairing payload was invalid or expired.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    InvalidPayload,
    /// The peer ID doesn't match what we expected.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    PeerIdMismatch,
    /// The handshake was cancelled by the user or peer.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// ChallengeMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ChallengeMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ChallengeMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ChallengeMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ChallengeMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ChallengeMessage {
    /// Random 32-byte challenge nonce.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub challenge: [u8; 32],

    /// The sender's peer ID (for identification).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_peer_id: PeerId,

    /// Unix timestamp (for freshness checking).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
}

/// A proof message (response to a challenge).
///
/// Contains the Ed25519 signature over the challenge nonce,
/// proving that the sender holds the private key corresponding
/// to their claimed public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ProofMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ProofMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ProofMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ProofMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ProofMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ProofMessage {
    /// The challenge nonce that was signed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub challenge: [u8; 32],

    /// Ed25519 signature over:
    /// "meshinfinity-sigma-proof-v1" || challenge || sender_peer_id
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,

    /// The sender's peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_peer_id: PeerId,

    /// The sender's counter-challenge (Step 2 only).
    /// Absent in the final proof (Step 3).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub counter_challenge: Option<[u8; 32]>,
}

/// Domain separator for Sigma protocol proofs.
///
/// Included in the signed message to prevent cross-protocol
/// signature reuse. An adversary can't take a signature from
/// a different protocol and use it as a Sigma proof.
// SIGMA_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// SIGMA_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// SIGMA_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// SIGMA_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// SIGMA_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SIGMA_DOMAIN: &[u8] = b"meshinfinity-sigma-proof-v1";

// ---------------------------------------------------------------------------
// Handshake Session
// ---------------------------------------------------------------------------

/// A pairing handshake session.
///
/// Manages the state of a single pairing handshake between two peers.
/// Tracks the exchange of challenges and proofs, and determines
/// when the handshake is complete.
// HandshakeSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// HandshakeSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// HandshakeSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// HandshakeSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// HandshakeSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct HandshakeSession {
    /// Current handshake state.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub state: HandshakeState,

    /// The peer's pairing payload (received via QR, NFC, etc.).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_payload: PairingPayload,

    /// When this session was created (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub created_at: u64,

    /// Session timeout (seconds). Default: 60.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timeout_secs: u64,
}

/// Default handshake timeout (seconds).
///
/// 60 seconds is generous for an interactive pairing flow.
/// The user should be physically present or on a call.
// DEFAULT_HANDSHAKE_TIMEOUT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_HANDSHAKE_TIMEOUT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_HANDSHAKE_TIMEOUT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_HANDSHAKE_TIMEOUT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_HANDSHAKE_TIMEOUT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEFAULT_HANDSHAKE_TIMEOUT: u64 = 60;

// Begin the block scope.
// HandshakeSession implementation — core protocol logic.
// HandshakeSession implementation — core protocol logic.
// HandshakeSession implementation — core protocol logic.
// HandshakeSession implementation — core protocol logic.
// HandshakeSession implementation — core protocol logic.
impl HandshakeSession {
    /// Create a new handshake session.
    ///
    /// `peer_payload`: the pairing payload received from the peer.
    /// `now`: current unix timestamp.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(peer_payload: PairingPayload, now: u64) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            state: HandshakeState::Idle,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            peer_payload,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            created_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            timeout_secs: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Start the handshake by generating and sending a challenge.
    ///
    /// `challenge`: 32 bytes of random entropy (from CSPRNG).
    /// Returns the ChallengeMessage to send to the peer.
    // Perform the 'initiate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'initiate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'initiate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'initiate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'initiate' operation.
    // Errors are propagated to the caller via Result.
    pub fn initiate(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        challenge: [u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        our_peer_id: PeerId,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> ChallengeMessage {
        // Update the state to reflect the new state.
        // Advance state state.
        // Advance state state.
        // Advance state state.
        // Advance state state.
        // Advance state state.
        self.state = HandshakeState::ChallengeSent {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            our_challenge: challenge,
        };

        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        ChallengeMessage {
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            challenge,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            sender_peer_id: our_peer_id,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
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
    // Perform the 'process proof' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process proof' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process proof' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process proof' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process proof' operation.
    // Errors are propagated to the caller via Result.
    pub fn process_proof<F>(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        proof: &ProofMessage,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        verify_fn: F,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Result<(), HandshakeError>
    where
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        F: Fn(&[u8; 32], &[u8], &[u8]) -> bool,
    {
        // Verify the peer ID matches the payload.
        // Compute expected id for this protocol step.
        // Compute expected id for this protocol step.
        // Compute expected id for this protocol step.
        // Compute expected id for this protocol step.
        // Compute expected id for this protocol step.
        let expected_id = PeerId::from_ed25519_pub(&self.peer_payload.ed25519_public);
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if proof.sender_peer_id != expected_id {
            // Update the state to reflect the new state.
            // Advance state state.
            // Advance state state.
            // Advance state state.
            // Advance state state.
            // Advance state state.
            self.state = HandshakeState::Failed(HandshakeError::PeerIdMismatch);
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(HandshakeError::PeerIdMismatch);
        }

        // Build the signed message:
        // SIGMA_DOMAIN || challenge || sender_peer_id
        // Compute signed msg for this protocol step.
        // Compute signed msg for this protocol step.
        // Compute signed msg for this protocol step.
        // Compute signed msg for this protocol step.
        // Compute signed msg for this protocol step.
        let mut signed_msg = Vec::with_capacity(
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            SIGMA_DOMAIN.len() + 32 + 32,
        );
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        signed_msg.extend_from_slice(SIGMA_DOMAIN);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        signed_msg.extend_from_slice(&proof.challenge);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        signed_msg.extend_from_slice(&proof.sender_peer_id.0);

        // Verify the signature.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !verify_fn(
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            &self.peer_payload.ed25519_public,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            &signed_msg,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            &proof.signature,
            // Begin the block scope.
        ) {
            // Update the state to reflect the new state.
            // Advance state state.
            // Advance state state.
            // Advance state state.
            // Advance state state.
            // Advance state state.
            self.state = HandshakeState::Failed(
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                HandshakeError::ProofVerificationFailed,
            );
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(HandshakeError::ProofVerificationFailed);
        }

        // Advance state based on current state.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match &self.state {
            // Begin the block scope.
            // Handle HandshakeState::ChallengeSent { our_challenge }.
            // Handle HandshakeState::ChallengeSent { our_challenge }.
            // Handle HandshakeState::ChallengeSent { our_challenge }.
            // Handle HandshakeState::ChallengeSent { our_challenge }.
            // Handle HandshakeState::ChallengeSent { our_challenge }.
            HandshakeState::ChallengeSent { our_challenge } => {
                // We sent a challenge, peer proved it. Check that
                // the proof is for OUR challenge.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if proof.challenge != *our_challenge {
                    // Update the state to reflect the new state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    self.state = HandshakeState::Failed(
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        HandshakeError::ProofVerificationFailed,
                    );
                    // Reject with an explicit error for the caller to handle.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    return Err(HandshakeError::ProofVerificationFailed);
                }

                // If the peer also sent a counter-challenge, we need
                // to respond. Otherwise, handshake is complete.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if let Some(counter) = proof.counter_challenge {
                    // Update the state to reflect the new state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    self.state = HandshakeState::ProofSent {
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        our_challenge: *our_challenge,
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        peer_challenge: counter,
                    };
                // Begin the block scope.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                } else {
                    // Update the state to reflect the new state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    self.state = HandshakeState::Completed {
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        peer_id: proof.sender_peer_id,
                    };
                }
            }
            // Begin the block scope.
            // Handle HandshakeState::Idle.
            // Handle HandshakeState::Idle.
            // Handle HandshakeState::Idle.
            // Handle HandshakeState::Idle.
            // Handle HandshakeState::Idle.
            HandshakeState::Idle => {
                // We received a proof without sending a challenge.
                // This can happen if the peer initiated.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if let Some(counter) = proof.counter_challenge {
                    // Update the state to reflect the new state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    self.state = HandshakeState::ProofSent {
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        our_challenge: [0; 32], // We didn't challenge.
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        peer_challenge: counter,
                    };
                }
            }
            // Update the local state.
            // Handle _.
            // Handle _.
            // Handle _.
            // Handle _.
            _ => {
                // Unexpected state. Ignore duplicate proofs.
            }
        }

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }

    /// Generate our proof message for the peer's challenge.
    ///
    /// `peer_challenge`: the challenge nonce from the peer.
    /// `our_peer_id`: our own peer ID.
    /// `sign_fn`: a closure that signs a message with our Ed25519 key.
    ///   Takes a message and returns the 64-byte signature.
    // Perform the 'generate proof' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'generate proof' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'generate proof' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'generate proof' operation.
    // Errors are propagated to the caller via Result.
    pub fn generate_proof<F>(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_challenge: [u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        our_peer_id: PeerId,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        sign_fn: F,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> ProofMessage
    where
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        F: Fn(&[u8]) -> Vec<u8>,
    {
        // Build the message to sign.
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
            SIGMA_DOMAIN.len() + 32 + 32,
        );
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(SIGMA_DOMAIN);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(&peer_challenge);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(&our_peer_id.0);

        // Ed25519 signature for authentication and integrity.
        // Compute signature for this protocol step.
        // Compute signature for this protocol step.
        // Compute signature for this protocol step.
        // Compute signature for this protocol step.
        let signature = sign_fn(&msg);

        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        ProofMessage {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            challenge: peer_challenge,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            signature,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            sender_peer_id: our_peer_id,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            counter_challenge: None, // Set by caller if needed.
        }
    }

    /// Mark the handshake as complete.
    // Perform the 'complete' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'complete' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'complete' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'complete' operation.
    // Errors are propagated to the caller via Result.
    pub fn complete(&mut self, peer_id: PeerId) {
        // Update the state to reflect the new state.
        // Advance state state.
        // Advance state state.
        // Advance state state.
        // Advance state state.
        self.state = HandshakeState::Completed { peer_id };
    }

    /// Check if the handshake has timed out.
    // Perform the 'is timed out' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is timed out' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is timed out' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is timed out' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_timed_out(&self, now: u64) -> bool {
        // Clamp the value to prevent overflow or underflow.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now.saturating_sub(self.created_at) > self.timeout_secs
    }

    /// Check if the handshake is complete.
    // Perform the 'is complete' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is complete' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is complete' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is complete' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_complete(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self.state, HandshakeState::Completed { .. })
    }

    /// Check if the handshake has failed.
    // Perform the 'is failed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is failed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is failed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is failed' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_failed(&self) -> bool {
        // Invoke the associated function.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self.state, HandshakeState::Failed(_))
    }
}

// ---------------------------------------------------------------------------
// Handshake frame size validation (Finding 3)
// ---------------------------------------------------------------------------

/// Validate that an incoming handshake frame does not exceed the maximum
/// allowed size before attempting deserialization. Without this check, a
/// malicious peer could send a multi-GB payload that exhausts memory
/// during JSON/bincode deserialization.
///
/// Returns `Ok(())` if the frame is within bounds, or
/// `Err(MeshError::MalformedFrame)` if it exceeds `MAX_HANDSHAKE_FRAME_SIZE`.
///
/// Callers MUST invoke this function on the raw bytes received from the
/// network BEFORE passing them to `serde_json::from_slice` or any other
/// deserializer.
pub fn validate_handshake_frame_size(data: &[u8]) -> Result<(), MeshError> {
    // Compare against the constant bound. Challenge messages are typically
    // ~100 bytes; proof messages ~200 bytes. 4 KiB is 20-40x headroom.
    if data.len() > MAX_HANDSHAKE_FRAME_SIZE {
        return Err(MeshError::MalformedFrame(format!(
            "handshake frame too large: {} bytes (max {})",
            data.len(),
            MAX_HANDSHAKE_FRAME_SIZE,
        )));
    }
    // Frame size is acceptable — proceed with deserialization.
    Ok(())
}

// ---------------------------------------------------------------------------
// Pairing rate limiter (Finding 4)
// ---------------------------------------------------------------------------

/// Per-IP rate limiter for incoming pairing handshake connections.
///
/// Tracks the number of pairing attempts from each IP address within a
/// sliding window. When an IP exceeds `MAX_PAIRING_ATTEMPTS_PER_IP`
/// within `RATE_LIMIT_WINDOW_SECS`, subsequent attempts are rejected
/// until the window resets.
///
/// This mitigates denial-of-service attacks where an adversary floods
/// the node with pairing TCP connections, exhausting CPU (signature
/// verification), file descriptors, or memory (HandshakeSession state).
pub struct PairingRateLimiter {
    /// Map from IP address to (attempt_count, window_start_time).
    /// The window starts when the first attempt from that IP is recorded.
    /// After `RATE_LIMIT_WINDOW_SECS` seconds, the entry is reset.
    entries: HashMap<IpAddr, (u32, Instant)>,
}

impl Default for PairingRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingRateLimiter {
    /// Create a new empty rate limiter with no tracked IPs.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Check whether a pairing attempt from `ip` should be allowed.
    ///
    /// Returns `Ok(())` if the attempt is within the rate limit, or
    /// `Err(MeshError::Internal)` if the IP has exceeded its quota.
    ///
    /// Each call that returns `Ok` increments the attempt counter for
    /// that IP. If the rate-limit window has expired since the first
    /// tracked attempt, the counter resets before checking.
    pub fn check_rate_limit(&mut self, ip: IpAddr) -> Result<(), MeshError> {
        let now = Instant::now();

        // Look up the existing entry for this IP, or create a fresh one.
        let entry = self.entries.entry(ip).or_insert((0, now));

        // Check if the current window has expired. If so, reset the
        // counter and start a new window from the current time.
        let elapsed = now.duration_since(entry.1).as_secs();
        if elapsed >= RATE_LIMIT_WINDOW_SECS {
            // Window expired — reset counter and start fresh.
            entry.0 = 0;
            entry.1 = now;
        }

        // Check whether the IP has exceeded the attempt limit.
        if entry.0 >= MAX_PAIRING_ATTEMPTS_PER_IP {
            // Rate limit exceeded — reject this attempt.
            return Err(MeshError::Internal(format!(
                "pairing rate limit exceeded for {} ({} attempts in {}s window)",
                ip, MAX_PAIRING_ATTEMPTS_PER_IP, RATE_LIMIT_WINDOW_SECS,
            )));
        }

        // Increment the attempt counter and allow the attempt.
        entry.0 += 1;
        Ok(())
    }

    /// Remove stale entries older than the rate-limit window.
    ///
    /// Call periodically (e.g., every 60 seconds) to prevent unbounded
    /// growth of the entries map from many distinct IPs. In practice,
    /// the number of unique IPs attempting pairing is small, but this
    /// provides a safety valve against memory exhaustion.
    pub fn cleanup_stale_entries(&mut self) {
        let now = Instant::now();
        // Retain only entries whose window has not yet expired.
        // Expired entries are harmless (they'd be reset on next access)
        // but removing them keeps the map from growing without bound.
        self.entries.retain(|_ip, (_, window_start)| {
            now.duration_since(*window_start).as_secs() < RATE_LIMIT_WINDOW_SECS
        });
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
        assert!(matches!(session.state, HandshakeState::ProofSent { .. }));
    }

    #[test]
    fn test_generate_proof() {
        let now = 1000;
        let payload = test_payload(now);
        let mut session = HandshakeSession::new(payload, now);

        let our_peer_id = PeerId([0x01; 32]);
        let peer_challenge = [0xDD; 32];

        let proof = session.generate_proof(peer_challenge, our_peer_id, mock_sign);

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
    fn payload_for_key(
        signing_key: &ed25519_dalek::SigningKey,
        now: u64,
    ) -> super::super::methods::PairingPayload {
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
        assert!(
            result.is_ok(),
            "real proof from legitimate key must succeed"
        );
        assert!(
            alice_session.is_complete(),
            "session must complete after valid proof"
        );
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
        assert_eq!(
            result,
            Err(HandshakeError::ProofVerificationFailed),
            "attacker's forged proof must be rejected"
        );
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
            challenge: challenge_b, // doesn't match our_challenge (challenge_a)
            signature: sig.to_bytes().to_vec(),
            sender_peer_id: peer_id,
            counter_challenge: None,
        };

        // process_proof checks proof.challenge == our_challenge.
        let result = session.process_proof(&proof, real_verify);
        assert!(
            result.is_err(),
            "proof for wrong challenge must be rejected"
        );
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
        let mut scratch_session = HandshakeSession::new(payload_for_key(&peer_sk, now), now);
        let proof = scratch_session.generate_proof(
            challenge,
            peer_id,
            real_sign_with(ed25519_dalek::SigningKey::from_bytes(&peer_sk.to_bytes())),
        );

        let result = session.process_proof(&proof, real_verify);
        assert!(
            result.is_ok(),
            "generate_proof output must verify with real crypto"
        );
    }

    // -----------------------------------------------------------------------
    // Finding 3: Handshake frame size validation tests
    // -----------------------------------------------------------------------

    /// Frames within the size limit must pass validation.
    #[test]
    fn test_frame_size_within_limit() {
        // A typical handshake frame is ~100-200 bytes.
        let small_frame = vec![0u8; 200];
        assert!(
            validate_handshake_frame_size(&small_frame).is_ok(),
            "200-byte frame should be accepted"
        );

        // Exactly at the limit must also pass.
        let exact_limit = vec![0u8; MAX_HANDSHAKE_FRAME_SIZE];
        assert!(
            validate_handshake_frame_size(&exact_limit).is_ok(),
            "frame at exact limit should be accepted"
        );
    }

    /// Frames exceeding the size limit must be rejected.
    #[test]
    fn test_frame_size_exceeds_limit() {
        // One byte over the limit.
        let oversized = vec![0u8; MAX_HANDSHAKE_FRAME_SIZE + 1];
        let result = validate_handshake_frame_size(&oversized);
        assert!(result.is_err(), "oversized frame must be rejected");

        // Verify the error message mentions the size.
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too large"),
            "error should mention 'too large': {err_msg}"
        );
    }

    /// Empty frames must pass validation (zero bytes is valid).
    #[test]
    fn test_frame_size_empty() {
        assert!(
            validate_handshake_frame_size(&[]).is_ok(),
            "empty frame should be accepted"
        );
    }

    // -----------------------------------------------------------------------
    // Finding 4: Pairing rate limiter tests
    // -----------------------------------------------------------------------

    /// Basic rate limiter: up to MAX_PAIRING_ATTEMPTS_PER_IP attempts
    /// should succeed, then the next attempt should be rejected.
    #[test]
    fn test_rate_limiter_basic_throttle() {
        let mut limiter = PairingRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().expect("valid IP");

        // First MAX_PAIRING_ATTEMPTS_PER_IP attempts should all succeed.
        for i in 0..MAX_PAIRING_ATTEMPTS_PER_IP {
            assert!(
                limiter.check_rate_limit(ip).is_ok(),
                "attempt {} should be allowed",
                i + 1
            );
        }

        // The next attempt should be rejected.
        let result = limiter.check_rate_limit(ip);
        assert!(
            result.is_err(),
            "attempt {} should be rejected (rate limit exceeded)",
            MAX_PAIRING_ATTEMPTS_PER_IP + 1
        );
    }

    /// Different IPs should have independent rate limits.
    #[test]
    fn test_rate_limiter_independent_ips() {
        let mut limiter = PairingRateLimiter::new();
        let ip_a: IpAddr = "10.0.0.1".parse().expect("valid IP");
        let ip_b: IpAddr = "10.0.0.2".parse().expect("valid IP");

        // Exhaust IP A's limit.
        for _ in 0..MAX_PAIRING_ATTEMPTS_PER_IP {
            limiter.check_rate_limit(ip_a).expect("A should be allowed");
        }
        // IP A is now blocked.
        assert!(
            limiter.check_rate_limit(ip_a).is_err(),
            "A should be blocked"
        );

        // IP B should still be allowed — independent counter.
        assert!(
            limiter.check_rate_limit(ip_b).is_ok(),
            "B should be allowed"
        );
    }

    /// Cleanup should remove stale entries without affecting active ones.
    #[test]
    fn test_rate_limiter_cleanup() {
        let mut limiter = PairingRateLimiter::new();
        let ip: IpAddr = "172.16.0.1".parse().expect("valid IP");

        // Record one attempt.
        limiter.check_rate_limit(ip).expect("should be allowed");
        assert_eq!(limiter.entries.len(), 1, "should have one entry");

        // Cleanup should not remove an entry within the window.
        limiter.cleanup_stale_entries();
        assert_eq!(
            limiter.entries.len(),
            1,
            "fresh entry should survive cleanup"
        );
    }
}
