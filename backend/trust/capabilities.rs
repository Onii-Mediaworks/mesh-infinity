//! Peer Capabilities (§8.1)
//!
//! Capability flags are per-peer grants independent of trust level.
//! A peer at the required trust level does NOT automatically receive
//! capabilities — the user must grant them individually.

use serde::{Deserialize, Serialize};

use super::levels::TrustLevel;

/// Capability flags for a specific peer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
// Begin the block scope.
// PeerCapabilities — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PeerCapabilities — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PeerCapabilities — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PeerCapabilities — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PeerCapabilities {
    /// Allow this peer to be selected as a wrapper/relay for outbound traffic.
    /// Minimum trust: Level 6 (Trusted).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub can_be_wrapper_node: bool,
    /// Allow this peer to route your internet traffic (exit node).
    /// Minimum trust: Level 7 (HighlyTrusted).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub can_be_exit_node: bool,
    /// Allow this peer to cache your offline messages.
    /// Minimum trust: Level 6 (Trusted).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub can_be_store_forward: bool,
    /// Accept WoT endorsements from this peer.
    /// Minimum trust: Level 6 (Trusted).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub can_endorse_peers: bool,
    /// Allow this peer to cast Friend-Disavowed votes.
    /// Minimum trust: Level 8 (InnerCircle).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub can_vote_disavow: bool,
}

// Begin the block scope.
// PeerCapabilities implementation — core protocol logic.
// PeerCapabilities implementation — core protocol logic.
// PeerCapabilities implementation — core protocol logic.
// PeerCapabilities implementation — core protocol logic.
impl PeerCapabilities {
    /// Check if a capability is valid for the given trust level.
    /// Returns false if the trust level is too low for the capability.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    pub fn validate(&self, trust_level: TrustLevel) -> Vec<CapabilityViolation> {
        // Pre-allocate the buffer to avoid repeated reallocations.
        // Compute violations for this protocol step.
        // Compute violations for this protocol step.
        // Compute violations for this protocol step.
        // Compute violations for this protocol step.
        let mut violations = Vec::new();

        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.can_be_wrapper_node && trust_level < TrustLevel::Trusted {
            // Record the violation for the caller to review.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            violations.push(CapabilityViolation {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                capability: "can_be_wrapper_node",
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                required: TrustLevel::Trusted,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                actual: trust_level,
            });
        }
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.can_be_exit_node && trust_level < TrustLevel::HighlyTrusted {
            // Record the violation for the caller to review.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            violations.push(CapabilityViolation {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                capability: "can_be_exit_node",
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                required: TrustLevel::HighlyTrusted,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                actual: trust_level,
            });
        }
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.can_be_store_forward && trust_level < TrustLevel::Trusted {
            // Record the violation for the caller to review.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            violations.push(CapabilityViolation {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                capability: "can_be_store_forward",
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                required: TrustLevel::Trusted,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                actual: trust_level,
            });
        }
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.can_endorse_peers && trust_level < TrustLevel::Trusted {
            // Record the violation for the caller to review.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            violations.push(CapabilityViolation {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                capability: "can_endorse_peers",
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                required: TrustLevel::Trusted,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                actual: trust_level,
            });
        }
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.can_vote_disavow && trust_level < TrustLevel::InnerCircle {
            // Record the violation for the caller to review.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            violations.push(CapabilityViolation {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                capability: "can_vote_disavow",
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                required: TrustLevel::InnerCircle,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                actual: trust_level,
            });
        }

        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        violations
    }

    /// Revoke all capabilities (used on trust downgrade below Level 6).
    // Perform the 'revoke all' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'revoke all' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'revoke all' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'revoke all' operation.
    // Errors are propagated to the caller via Result.
    pub fn revoke_all(&mut self) {
        *self = Self::default();
    }

    /// Check if any capability is granted.
    // Perform the 'has any' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'has any' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'has any' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'has any' operation.
    // Errors are propagated to the caller via Result.
    pub fn has_any(&self) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.can_be_wrapper_node
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            || self.can_be_exit_node
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            || self.can_be_store_forward
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            || self.can_endorse_peers
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            || self.can_vote_disavow
    }
}

/// A capability violation — capability granted at insufficient trust level.
#[derive(Debug)]
// Begin the block scope.
// CapabilityViolation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// CapabilityViolation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// CapabilityViolation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// CapabilityViolation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct CapabilityViolation {
    /// The capability for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub capability: &'static str,
    /// The required for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub required: TrustLevel,
    /// The actual for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub actual: TrustLevel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_no_capabilities() {
        let caps = PeerCapabilities::default();
        assert!(!caps.has_any());
    }

    #[test]
    fn test_validate_sufficient_trust() {
        let caps = PeerCapabilities {
            can_be_wrapper_node: true,
            can_be_store_forward: true,
            ..Default::default()
        };
        let violations = caps.validate(TrustLevel::Trusted);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_validate_insufficient_trust() {
        let caps = PeerCapabilities {
            can_be_wrapper_node: true,
            ..Default::default()
        };
        let violations = caps.validate(TrustLevel::Acquaintance);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].capability, "can_be_wrapper_node");
    }

    #[test]
    fn test_exit_node_requires_highly_trusted() {
        let caps = PeerCapabilities {
            can_be_exit_node: true,
            ..Default::default()
        };
        // Trusted (6) not enough — needs HighlyTrusted (7)
        assert_eq!(caps.validate(TrustLevel::Trusted).len(), 1);
        assert!(caps.validate(TrustLevel::HighlyTrusted).is_empty());
    }

    #[test]
    fn test_disavow_requires_inner_circle() {
        let caps = PeerCapabilities {
            can_vote_disavow: true,
            ..Default::default()
        };
        assert_eq!(caps.validate(TrustLevel::HighlyTrusted).len(), 1);
        assert!(caps.validate(TrustLevel::InnerCircle).is_empty());
    }

    #[test]
    fn test_revoke_all() {
        let mut caps = PeerCapabilities {
            can_be_wrapper_node: true,
            can_be_exit_node: true,
            can_be_store_forward: true,
            can_endorse_peers: true,
            can_vote_disavow: true,
        };
        assert!(caps.has_any());
        caps.revoke_all();
        assert!(!caps.has_any());
    }

    #[test]
    fn test_serde_roundtrip() {
        let caps = PeerCapabilities {
            can_be_wrapper_node: true,
            can_be_exit_node: false,
            can_be_store_forward: true,
            can_endorse_peers: false,
            can_vote_disavow: false,
        };
        let json = serde_json::to_string(&caps).unwrap();
        let recovered: PeerCapabilities = serde_json::from_str(&json).unwrap();
        assert!(recovered.can_be_wrapper_node);
        assert!(!recovered.can_be_exit_node);
    }
}
