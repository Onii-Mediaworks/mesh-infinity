//! Peer Capabilities (§8.1)
//!
//! Capability flags are per-peer grants independent of trust level.
//! A peer at the required trust level does NOT automatically receive
//! capabilities — the user must grant them individually.

use serde::{Deserialize, Serialize};

use super::levels::TrustLevel;

/// Capability flags for a specific peer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Allow this peer to be selected as a wrapper/relay for outbound traffic.
    /// Minimum trust: Level 6 (Trusted).
    pub can_be_wrapper_node: bool,
    /// Allow this peer to route your internet traffic (exit node).
    /// Minimum trust: Level 7 (HighlyTrusted).
    pub can_be_exit_node: bool,
    /// Allow this peer to cache your offline messages.
    /// Minimum trust: Level 6 (Trusted).
    pub can_be_store_forward: bool,
    /// Accept WoT endorsements from this peer.
    /// Minimum trust: Level 6 (Trusted).
    pub can_endorse_peers: bool,
    /// Allow this peer to cast Friend-Disavowed votes.
    /// Minimum trust: Level 8 (InnerCircle).
    pub can_vote_disavow: bool,
}

impl PeerCapabilities {
    /// Check if a capability is valid for the given trust level.
    /// Returns false if the trust level is too low for the capability.
    pub fn validate(&self, trust_level: TrustLevel) -> Vec<CapabilityViolation> {
        let mut violations = Vec::new();

        if self.can_be_wrapper_node && trust_level < TrustLevel::Trusted {
            violations.push(CapabilityViolation {
                capability: "can_be_wrapper_node",
                required: TrustLevel::Trusted,
                actual: trust_level,
            });
        }
        if self.can_be_exit_node && trust_level < TrustLevel::HighlyTrusted {
            violations.push(CapabilityViolation {
                capability: "can_be_exit_node",
                required: TrustLevel::HighlyTrusted,
                actual: trust_level,
            });
        }
        if self.can_be_store_forward && trust_level < TrustLevel::Trusted {
            violations.push(CapabilityViolation {
                capability: "can_be_store_forward",
                required: TrustLevel::Trusted,
                actual: trust_level,
            });
        }
        if self.can_endorse_peers && trust_level < TrustLevel::Trusted {
            violations.push(CapabilityViolation {
                capability: "can_endorse_peers",
                required: TrustLevel::Trusted,
                actual: trust_level,
            });
        }
        if self.can_vote_disavow && trust_level < TrustLevel::InnerCircle {
            violations.push(CapabilityViolation {
                capability: "can_vote_disavow",
                required: TrustLevel::InnerCircle,
                actual: trust_level,
            });
        }

        violations
    }

    /// Revoke all capabilities (used on trust downgrade below Level 6).
    pub fn revoke_all(&mut self) {
        *self = Self::default();
    }

    /// Check if any capability is granted.
    pub fn has_any(&self) -> bool {
        self.can_be_wrapper_node
            || self.can_be_exit_node
            || self.can_be_store_forward
            || self.can_endorse_peers
            || self.can_vote_disavow
    }
}

/// A capability violation — capability granted at insufficient trust level.
#[derive(Debug)]
pub struct CapabilityViolation {
    pub capability: &'static str,
    pub required: TrustLevel,
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
        assert_eq!(recovered.can_be_wrapper_node, true);
        assert_eq!(recovered.can_be_exit_node, false);
    }
}
