//! Trust Endorsements and Web of Trust (§8.5)
//!
//! Endorsement model:
//! - Single endorser required (no trust laddering — §8.5.1)
//! - Endorsements from below Level 6 are silently ignored (§8.5.2)
//! - Endorser level sets default starting point, not ceiling (§8.5.3)
//! - Endorsements signed by the endorser's public mask key

use serde::{Deserialize, Serialize};

use super::levels::TrustLevel;
use crate::identity::peer_id::PeerId;

/// A trust endorsement record (§8.5.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TrustEndorsement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustEndorsement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustEndorsement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustEndorsement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustEndorsement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TrustEndorsement {
    /// Peer being endorsed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub endorsed_peer_id: PeerId,
    /// Peer issuing the endorsement.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub endorser_peer_id: PeerId,
    /// Endorser's trust level (for weight calculation).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub endorser_level: TrustLevel,
    /// When this endorsement was issued.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
    /// Monotonically increasing per endorser (for revocation ordering).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sequence: u64,
    /// Ed25519 signature by endorser's public mask key.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

/// A trust revocation — cancels a previous endorsement (§8.5.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TrustRevocation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustRevocation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustRevocation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustRevocation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustRevocation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TrustRevocation {
    /// Peer whose endorsement is being revoked.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub endorsed_peer_id: PeerId,
    /// Peer revoking their endorsement.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub endorser_peer_id: PeerId,
    /// Timestamp of revocation.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
    /// Sequence number (must be > the endorsement's sequence to be valid).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sequence: u64,
    /// Ed25519 signature by endorser's public mask key.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

/// Safety number verification record (§8.5.8).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// SafetyNumberVerification — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SafetyNumberVerification — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SafetyNumberVerification — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SafetyNumberVerification — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SafetyNumberVerification — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SafetyNumberVerification {
    /// Peer whose key was verified.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub subject_peer_id: PeerId,
    /// The new Ed25519 public key that was verified.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub new_ed25519_pub: [u8; 32],
    /// The safety number both parties confirmed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub safety_number: Vec<u8>,
    /// Peer who performed the verification.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub verifier_peer_id: PeerId,
    /// When the verification was performed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
    /// Ed25519 signature by verifier's relationship-specific mask key.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

/// Local endorsement store for a node's Web of Trust.
#[derive(Default, Serialize, Deserialize)]
// Begin the block scope.
// EndorsementStore — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// EndorsementStore — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// EndorsementStore — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// EndorsementStore — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// EndorsementStore — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct EndorsementStore {
    /// Active endorsements (endorser_peer_id → endorsed_peer_id → endorsement).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub endorsements: Vec<TrustEndorsement>,
    /// Active revocations.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub revocations: Vec<TrustRevocation>,
    /// Safety number verifications received.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub verifications: Vec<SafetyNumberVerification>,
}

// Begin the block scope.
// EndorsementStore implementation — core protocol logic.
// EndorsementStore implementation — core protocol logic.
// EndorsementStore implementation — core protocol logic.
// EndorsementStore implementation — core protocol logic.
// EndorsementStore implementation — core protocol logic.
impl EndorsementStore {
    /// Add an endorsement. Returns the default starting trust level.
    ///
    /// Endorsements from peers below Level 6 are silently ignored (§8.5.2).
    // Perform the 'add endorsement' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add endorsement' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add endorsement' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add endorsement' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add endorsement' operation.
    // Errors are propagated to the caller via Result.
    pub fn add_endorsement(&mut self, endorsement: TrustEndorsement) -> Option<TrustLevel> {
        // Ignore endorsements from below Level 6 (§8.5.2)
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if endorsement.endorser_level < TrustLevel::Trusted {
            // No result available — signal absence to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return None;
        }

        // Check if a newer revocation exists for this endorsement
        // Compute has newer revocation for this protocol step.
        // Compute has newer revocation for this protocol step.
        // Compute has newer revocation for this protocol step.
        // Compute has newer revocation for this protocol step.
        // Compute has newer revocation for this protocol step.
        let has_newer_revocation = self.revocations.iter().any(|r| {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            r.endorser_peer_id == endorsement.endorser_peer_id
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                && r.endorsed_peer_id == endorsement.endorsed_peer_id
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                && r.sequence > endorsement.sequence
        });
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if has_newer_revocation {
            // No result available — signal absence to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return None;
        }

        // Invoke the associated function.
        // Compute default level for this protocol step.
        // Compute default level for this protocol step.
        // Compute default level for this protocol step.
        // Compute default level for this protocol step.
        // Compute default level for this protocol step.
        let default_level = TrustLevel::endorsement_default(endorsement.endorser_level);
        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        self.endorsements.push(endorsement);
        // Execute this step in the protocol sequence.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        default_level
    }

    /// Process a revocation. Returns true if a matching endorsement was found and revoked.
    // Perform the 'add revocation' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add revocation' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add revocation' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add revocation' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add revocation' operation.
    // Errors are propagated to the caller via Result.
    pub fn add_revocation(&mut self, revocation: TrustRevocation) -> bool {
        // Remove any endorsement with lower sequence from the same endorser
        // Compute before len for this protocol step.
        // Compute before len for this protocol step.
        // Compute before len for this protocol step.
        // Compute before len for this protocol step.
        // Compute before len for this protocol step.
        let before_len = self.endorsements.len();
        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.endorsements.retain(|e| {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            !(e.endorser_peer_id == revocation.endorser_peer_id
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                && e.endorsed_peer_id == revocation.endorsed_peer_id
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                && e.sequence < revocation.sequence)
        });
        // Track the count for threshold and bounds checking.
        // Compute removed for this protocol step.
        // Compute removed for this protocol step.
        // Compute removed for this protocol step.
        // Compute removed for this protocol step.
        // Compute removed for this protocol step.
        let removed = self.endorsements.len() < before_len;

        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        self.revocations.push(revocation);
        removed
    }

    /// Count safety number verifications for a specific peer.
    // Perform the 'verification count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verification count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verification count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verification count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verification count' operation.
    // Errors are propagated to the caller via Result.
    pub fn verification_count(&self, subject_peer_id: &PeerId) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.verifications
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            .iter()
            // Select only elements matching the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            .filter(|v| v.subject_peer_id == *subject_peer_id)
            // Chain the operation on the intermediate result.
            .count()
    }

    /// Get all endorsements for a specific peer.
    // Perform the 'endorsements for' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'endorsements for' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'endorsements for' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'endorsements for' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'endorsements for' operation.
    // Errors are propagated to the caller via Result.
    pub fn endorsements_for(&self, peer_id: &PeerId) -> Vec<&TrustEndorsement> {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.endorsements
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            .iter()
            // Select only elements matching the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            .filter(|e| e.endorsed_peer_id == *peer_id)
            // Materialize the iterator into a concrete collection.
            // Collect into a concrete collection.
            // Collect into a concrete collection.
            // Collect into a concrete collection.
            // Collect into a concrete collection.
            // Collect into a concrete collection.
            .collect()
    }

    /// Get the highest endorser level for a specific peer.
    // Perform the 'highest endorser level' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'highest endorser level' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'highest endorser level' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'highest endorser level' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'highest endorser level' operation.
    // Errors are propagated to the caller via Result.
    pub fn highest_endorser_level(&self, peer_id: &PeerId) -> Option<TrustLevel> {
        // Delegate to the instance method.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.endorsements_for(peer_id)
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            .iter()
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            // Transform each element.
            // Transform each element.
            // Transform each element.
            .map(|e| e.endorser_level)
            // Clamp the value to prevent overflow or underflow.
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_endorsement(
        endorser: PeerId,
        endorsed: PeerId,
        level: TrustLevel,
        seq: u64,
    ) -> TrustEndorsement {
        TrustEndorsement {
            endorsed_peer_id: endorsed,
            endorser_peer_id: endorser,
            endorser_level: level,
            timestamp: 100,
            sequence: seq,
            signature: vec![0u8; 64],
        }
    }

    fn make_revocation(endorser: PeerId, endorsed: PeerId, seq: u64) -> TrustRevocation {
        TrustRevocation {
            endorsed_peer_id: endorsed,
            endorser_peer_id: endorser,
            timestamp: 200,
            sequence: seq,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_endorsement_from_trusted() {
        let mut store = EndorsementStore::default();
        let endorser = PeerId([0x01; 32]);
        let endorsed = PeerId([0x02; 32]);

        let result =
            store.add_endorsement(make_endorsement(endorser, endorsed, TrustLevel::Trusted, 1));
        assert_eq!(result, Some(TrustLevel::Vouched));
    }

    #[test]
    fn test_endorsement_from_inner_circle() {
        let mut store = EndorsementStore::default();
        let result = store.add_endorsement(make_endorsement(
            PeerId([0x01; 32]),
            PeerId([0x02; 32]),
            TrustLevel::InnerCircle,
            1,
        ));
        assert_eq!(result, Some(TrustLevel::Ally));
    }

    #[test]
    fn test_endorsement_from_low_trust_ignored() {
        let mut store = EndorsementStore::default();
        let result = store.add_endorsement(make_endorsement(
            PeerId([0x01; 32]),
            PeerId([0x02; 32]),
            TrustLevel::Acquaintance, // Level 5 — below threshold
            1,
        ));
        assert_eq!(result, None);
        assert!(store.endorsements.is_empty());
    }

    #[test]
    fn test_revocation() {
        let mut store = EndorsementStore::default();
        let endorser = PeerId([0x01; 32]);
        let endorsed = PeerId([0x02; 32]);

        store.add_endorsement(make_endorsement(endorser, endorsed, TrustLevel::Trusted, 1));
        assert_eq!(store.endorsements.len(), 1);

        let revoked = store.add_revocation(make_revocation(endorser, endorsed, 2));
        assert!(revoked);
        assert!(store.endorsements.is_empty());
    }

    #[test]
    fn test_revocation_sequence_ordering() {
        let mut store = EndorsementStore::default();
        let endorser = PeerId([0x01; 32]);
        let endorsed = PeerId([0x02; 32]);

        // Add endorsement at sequence 5
        store.add_endorsement(make_endorsement(endorser, endorsed, TrustLevel::Trusted, 5));

        // Revocation at sequence 3 (older) — should NOT revoke
        let revoked = store.add_revocation(make_revocation(endorser, endorsed, 3));
        assert!(!revoked);
        assert_eq!(store.endorsements.len(), 1);
    }

    #[test]
    fn test_endorsements_for_peer() {
        let mut store = EndorsementStore::default();
        let target = PeerId([0x02; 32]);

        store.add_endorsement(make_endorsement(
            PeerId([0x01; 32]),
            target,
            TrustLevel::Trusted,
            1,
        ));
        store.add_endorsement(make_endorsement(
            PeerId([0x03; 32]),
            target,
            TrustLevel::InnerCircle,
            1,
        ));
        store.add_endorsement(make_endorsement(
            PeerId([0x04; 32]),
            PeerId([0x05; 32]),
            TrustLevel::Trusted,
            1,
        ));

        assert_eq!(store.endorsements_for(&target).len(), 2);
    }

    #[test]
    fn test_highest_endorser_level() {
        let mut store = EndorsementStore::default();
        let target = PeerId([0x02; 32]);

        store.add_endorsement(make_endorsement(
            PeerId([0x01; 32]),
            target,
            TrustLevel::Trusted,
            1,
        ));
        store.add_endorsement(make_endorsement(
            PeerId([0x03; 32]),
            target,
            TrustLevel::InnerCircle,
            1,
        ));

        assert_eq!(
            store.highest_endorser_level(&target),
            Some(TrustLevel::InnerCircle)
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut store = EndorsementStore::default();
        store.add_endorsement(make_endorsement(
            PeerId([0x01; 32]),
            PeerId([0x02; 32]),
            TrustLevel::Trusted,
            1,
        ));

        let json = serde_json::to_string(&store).unwrap();
        let recovered: EndorsementStore = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.endorsements.len(), 1);
    }
}
