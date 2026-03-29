//! Trust Endorsements and Web of Trust (§8.5)
//!
//! Endorsement model:
//! - Single endorser required (no trust laddering — §8.5.1)
//! - Endorsements from below Level 6 are silently ignored (§8.5.2)
//! - Endorser level sets default starting point, not ceiling (§8.5.3)
//! - Endorsements signed by the endorser's public mask key

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;
use super::levels::TrustLevel;

/// A trust endorsement record (§8.5.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustEndorsement {
    /// Peer being endorsed.
    pub endorsed_peer_id: PeerId,
    /// Peer issuing the endorsement.
    pub endorser_peer_id: PeerId,
    /// Endorser's trust level (for weight calculation).
    pub endorser_level: TrustLevel,
    /// When this endorsement was issued.
    pub timestamp: u64,
    /// Monotonically increasing per endorser (for revocation ordering).
    pub sequence: u64,
    /// Ed25519 signature by endorser's public mask key.
    pub signature: Vec<u8>,
}

/// A trust revocation — cancels a previous endorsement (§8.5.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRevocation {
    /// Peer whose endorsement is being revoked.
    pub endorsed_peer_id: PeerId,
    /// Peer revoking their endorsement.
    pub endorser_peer_id: PeerId,
    /// Timestamp of revocation.
    pub timestamp: u64,
    /// Sequence number (must be > the endorsement's sequence to be valid).
    pub sequence: u64,
    /// Ed25519 signature by endorser's public mask key.
    pub signature: Vec<u8>,
}

/// Safety number verification record (§8.5.8).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SafetyNumberVerification {
    /// Peer whose key was verified.
    pub subject_peer_id: PeerId,
    /// The new Ed25519 public key that was verified.
    pub new_ed25519_pub: [u8; 32],
    /// The safety number both parties confirmed.
    pub safety_number: Vec<u8>,
    /// Peer who performed the verification.
    pub verifier_peer_id: PeerId,
    /// When the verification was performed.
    pub timestamp: u64,
    /// Ed25519 signature by verifier's relationship-specific mask key.
    pub signature: Vec<u8>,
}

/// Local endorsement store for a node's Web of Trust.
#[derive(Default, Serialize, Deserialize)]
pub struct EndorsementStore {
    /// Active endorsements (endorser_peer_id → endorsed_peer_id → endorsement).
    pub endorsements: Vec<TrustEndorsement>,
    /// Active revocations.
    pub revocations: Vec<TrustRevocation>,
    /// Safety number verifications received.
    pub verifications: Vec<SafetyNumberVerification>,
}

impl EndorsementStore {
    /// Add an endorsement. Returns the default starting trust level.
    ///
    /// Endorsements from peers below Level 6 are silently ignored (§8.5.2).
    pub fn add_endorsement(&mut self, endorsement: TrustEndorsement) -> Option<TrustLevel> {
        // Ignore endorsements from below Level 6 (§8.5.2)
        if endorsement.endorser_level < TrustLevel::Trusted {
            return None;
        }

        // Check if a newer revocation exists for this endorsement
        let has_newer_revocation = self.revocations.iter().any(|r| {
            r.endorser_peer_id == endorsement.endorser_peer_id
                && r.endorsed_peer_id == endorsement.endorsed_peer_id
                && r.sequence > endorsement.sequence
        });
        if has_newer_revocation {
            return None;
        }

        let default_level = TrustLevel::endorsement_default(endorsement.endorser_level);
        self.endorsements.push(endorsement);
        default_level
    }

    /// Process a revocation. Returns true if a matching endorsement was found and revoked.
    pub fn add_revocation(&mut self, revocation: TrustRevocation) -> bool {
        // Remove any endorsement with lower sequence from the same endorser
        let before_len = self.endorsements.len();
        self.endorsements.retain(|e| {
            !(e.endorser_peer_id == revocation.endorser_peer_id
                && e.endorsed_peer_id == revocation.endorsed_peer_id
                && e.sequence < revocation.sequence)
        });
        let removed = self.endorsements.len() < before_len;

        self.revocations.push(revocation);
        removed
    }

    /// Count safety number verifications for a specific peer.
    pub fn verification_count(&self, subject_peer_id: &PeerId) -> usize {
        self.verifications
            .iter()
            .filter(|v| v.subject_peer_id == *subject_peer_id)
            .count()
    }

    /// Get all endorsements for a specific peer.
    pub fn endorsements_for(&self, peer_id: &PeerId) -> Vec<&TrustEndorsement> {
        self.endorsements
            .iter()
            .filter(|e| e.endorsed_peer_id == *peer_id)
            .collect()
    }

    /// Get the highest endorser level for a specific peer.
    pub fn highest_endorser_level(&self, peer_id: &PeerId) -> Option<TrustLevel> {
        self.endorsements_for(peer_id)
            .iter()
            .map(|e| e.endorser_level)
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

        let result = store.add_endorsement(make_endorsement(
            endorser, endorsed, TrustLevel::Trusted, 1,
        ));
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
            PeerId([0x01; 32]), target, TrustLevel::Trusted, 1,
        ));
        store.add_endorsement(make_endorsement(
            PeerId([0x03; 32]), target, TrustLevel::InnerCircle, 1,
        ));
        store.add_endorsement(make_endorsement(
            PeerId([0x04; 32]), PeerId([0x05; 32]), TrustLevel::Trusted, 1,
        ));

        assert_eq!(store.endorsements_for(&target).len(), 2);
    }

    #[test]
    fn test_highest_endorser_level() {
        let mut store = EndorsementStore::default();
        let target = PeerId([0x02; 32]);

        store.add_endorsement(make_endorsement(
            PeerId([0x01; 32]), target, TrustLevel::Trusted, 1,
        ));
        store.add_endorsement(make_endorsement(
            PeerId([0x03; 32]), target, TrustLevel::InnerCircle, 1,
        ));

        assert_eq!(store.highest_endorser_level(&target), Some(TrustLevel::InnerCircle));
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
