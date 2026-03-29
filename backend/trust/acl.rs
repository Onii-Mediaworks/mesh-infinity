//! Access Control List / Firewall Model (§8.8)
//!
//! # What is the ACL System?
//!
//! The ACL system provides fine-grained access control for services,
//! resources, and capabilities. It separates ACCESS from IDENTITY:
//! granting access to a resource does NOT require granting identity.
//!
//! # Rule Syntax (§8.8)
//!
//! Rules follow a ALLOW/DENY subject-target pattern:
//! ```text
//! ALLOW  service:<name>  TO  trust:Level6+
//! ALLOW  service:<name>  TO  peer:<hex_peer_id>
//! DENY   service:*       TO  *
//! ```
//!
//! # Evaluation Order
//!
//! Rules are evaluated in order. First match wins.
//! The implicit default is DENY — if no rule matches, access is denied.
//!
//! # Subjects
//!
//! Who the rule applies to:
//! - `trust:LevelN+` — anyone at or above trust level N
//! - `trust:LevelN-LevelM` — anyone in the trust range N–M
//! - `peer:<id>` — a specific peer by peer ID
//! - `group:<id>` — members of a specific group
//! - `ANY` — anyone (use carefully)
//!
//! # Targets
//!
//! What the rule protects:
//! - `service:<name>` — a specific hosted service
//! - `service:*` — all services
//! - `port:<number>` — a specific mesh port
//! - `resource:<path>` — a specific file or resource path

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;
use crate::trust::levels::TrustLevel;

// ---------------------------------------------------------------------------
// ACL Permission
// ---------------------------------------------------------------------------

/// Whether a rule allows or denies access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclPermission {
    /// Allow the matched subject to access the target.
    Allow,
    /// Deny the matched subject access to the target.
    Deny,
}

// ---------------------------------------------------------------------------
// ACL Subject
// ---------------------------------------------------------------------------

/// Who an ACL rule applies to (§8.8).
///
/// Subjects are matched in order of specificity:
/// peer > group > trust range > ANY.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclSubject {
    /// A specific peer by peer ID.
    Peer(PeerId),

    /// Members of a specific group.
    Group([u8; 32]),

    /// Anyone at or above a specific trust level.
    /// e.g., `TrustFloor(TrustLevel::Trusted)` = Level 6+.
    TrustFloor(TrustLevel),

    /// Anyone in a trust level range (inclusive).
    /// e.g., `TrustRange(Vouched, Acquaintance)` = Levels 2–5.
    TrustRange(TrustLevel, TrustLevel),

    /// Anyone at all. Use with extreme caution.
    Any,
}

impl AclSubject {
    /// Check if a peer matches this subject.
    ///
    /// `peer_id`: the peer to check.
    /// `peer_trust`: the peer's trust level with us.
    /// `peer_groups`: groups the peer belongs to.
    pub fn matches(
        &self,
        peer_id: &PeerId,
        peer_trust: TrustLevel,
        peer_groups: &[[u8; 32]],
    ) -> bool {
        match self {
            // Exact peer match.
            Self::Peer(id) => *id == *peer_id,

            // Group membership match.
            Self::Group(gid) => peer_groups.contains(gid),

            // Trust floor: peer must be at or above the floor.
            Self::TrustFloor(floor) => peer_trust >= *floor,

            // Trust range: peer must be within the range (inclusive).
            Self::TrustRange(low, high) => {
                peer_trust >= *low && peer_trust <= *high
            }

            // Match anyone.
            Self::Any => true,
        }
    }

    /// Specificity score for conflict resolution.
    /// More specific subjects win ties between rules at the same position.
    pub fn specificity(&self) -> u8 {
        match self {
            Self::Peer(_) => 4,
            Self::Group(_) => 3,
            Self::TrustRange(_, _) => 2,
            Self::TrustFloor(_) => 1,
            Self::Any => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ACL Target
// ---------------------------------------------------------------------------

/// What an ACL rule protects (§8.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclTarget {
    /// A specific service by name.
    Service(String),

    /// All services (wildcard).
    AllServices,

    /// A specific mesh port.
    Port(u32),

    /// A specific resource path.
    Resource(String),

    /// Everything (wildcard — use for default deny).
    Everything,
}

impl AclTarget {
    /// Check if a request matches this target.
    pub fn matches_service(&self, service_name: &str) -> bool {
        match self {
            Self::Service(name) => name == service_name,
            Self::AllServices | Self::Everything => true,
            _ => false,
        }
    }

    /// Check if a port matches this target.
    pub fn matches_port(&self, port: u32) -> bool {
        match self {
            Self::Port(p) => *p == port,
            Self::Everything => true,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// ACL Rule
// ---------------------------------------------------------------------------

/// A single ACL rule (§8.8).
///
/// Rules are evaluated in order. The first rule whose subject
/// and target both match determines the outcome. If no rule
/// matches, the implicit default is Deny.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AclRule {
    /// What this rule does (Allow or Deny).
    pub permission: AclPermission,

    /// Who this rule applies to.
    pub subject: AclSubject,

    /// What this rule protects.
    pub target: AclTarget,

    /// Optional human-readable description.
    pub description: Option<String>,

    /// Whether this rule is active.
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// ACL Engine
// ---------------------------------------------------------------------------

/// Evaluates ACL rules to determine access (§8.8).
///
/// Rules are stored in order and evaluated sequentially.
/// First match wins. No match = implicit Deny.
pub struct AclEngine {
    /// Ordered list of ACL rules.
    rules: Vec<AclRule>,
}

impl AclEngine {
    /// Create a new ACL engine with the given rules.
    pub fn new(rules: Vec<AclRule>) -> Self {
        Self { rules }
    }

    /// Create an empty engine (everything denied by default).
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Evaluate whether a peer can access a service.
    ///
    /// `peer_id`: who is requesting access.
    /// `peer_trust`: our trust level for this peer.
    /// `peer_groups`: groups this peer belongs to.
    /// `service_name`: which service they want to access.
    ///
    /// Returns Allow if a matching Allow rule is found,
    /// Deny if a matching Deny rule is found or no rule matches.
    pub fn check_service(
        &self,
        peer_id: &PeerId,
        peer_trust: TrustLevel,
        peer_groups: &[[u8; 32]],
        service_name: &str,
    ) -> AclPermission {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            // Check if both subject and target match.
            let subject_match =
                rule.subject.matches(peer_id, peer_trust, peer_groups);
            let target_match = rule.target.matches_service(service_name);

            if subject_match && target_match {
                return rule.permission;
            }
        }

        // No rule matched → implicit Deny.
        AclPermission::Deny
    }

    /// Evaluate whether a peer can access a port.
    pub fn check_port(
        &self,
        peer_id: &PeerId,
        peer_trust: TrustLevel,
        peer_groups: &[[u8; 32]],
        port: u32,
    ) -> AclPermission {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let subject_match =
                rule.subject.matches(peer_id, peer_trust, peer_groups);
            let target_match = rule.target.matches_port(port);

            if subject_match && target_match {
                return rule.permission;
            }
        }

        AclPermission::Deny
    }

    /// Add a rule to the end of the list.
    pub fn add_rule(&mut self, rule: AclRule) {
        self.rules.push(rule);
    }

    /// Insert a rule at a specific position.
    pub fn insert_rule(&mut self, index: usize, rule: AclRule) {
        if index <= self.rules.len() {
            self.rules.insert(index, rule);
        }
    }

    /// Remove a rule by index.
    pub fn remove_rule(&mut self, index: usize) -> Option<AclRule> {
        if index < self.rules.len() {
            Some(self.rules.remove(index))
        } else {
            None
        }
    }

    /// Number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn test_empty_engine_denies() {
        let engine = AclEngine::empty();
        let result = engine.check_service(
            &pid(0x01),
            TrustLevel::InnerCircle,
            &[],
            "any-service",
        );
        assert_eq!(result, AclPermission::Deny);
    }

    #[test]
    fn test_trust_floor_allow() {
        let engine = AclEngine::new(vec![AclRule {
            permission: AclPermission::Allow,
            subject: AclSubject::TrustFloor(TrustLevel::Trusted),
            target: AclTarget::Service("chat".to_string()),
            description: None,
            enabled: true,
        }]);

        // Trusted peer: allowed.
        assert_eq!(
            engine.check_service(&pid(0x01), TrustLevel::Trusted, &[], "chat"),
            AclPermission::Allow
        );

        // Unknown peer: denied (below floor).
        assert_eq!(
            engine.check_service(&pid(0x02), TrustLevel::Unknown, &[], "chat"),
            AclPermission::Deny
        );
    }

    #[test]
    fn test_specific_peer_override() {
        let engine = AclEngine::new(vec![
            // Deny a specific peer.
            AclRule {
                permission: AclPermission::Deny,
                subject: AclSubject::Peer(pid(0xBB)),
                target: AclTarget::AllServices,
                description: Some("Blocked user".to_string()),
                enabled: true,
            },
            // Allow all trusted peers.
            AclRule {
                permission: AclPermission::Allow,
                subject: AclSubject::TrustFloor(TrustLevel::Trusted),
                target: AclTarget::AllServices,
                description: None,
                enabled: true,
            },
        ]);

        // Blocked peer is denied even though they're trusted.
        assert_eq!(
            engine.check_service(&pid(0xBB), TrustLevel::InnerCircle, &[], "chat"),
            AclPermission::Deny
        );

        // Other trusted peers are allowed.
        assert_eq!(
            engine.check_service(&pid(0xCC), TrustLevel::Trusted, &[], "chat"),
            AclPermission::Allow
        );
    }

    #[test]
    fn test_group_subject() {
        let group_id = [0xFF; 32];
        let engine = AclEngine::new(vec![AclRule {
            permission: AclPermission::Allow,
            subject: AclSubject::Group(group_id),
            target: AclTarget::Service("files".to_string()),
            description: None,
            enabled: true,
        }]);

        // In the group: allowed.
        assert_eq!(
            engine.check_service(&pid(0x01), TrustLevel::Unknown, &[group_id], "files"),
            AclPermission::Allow
        );

        // Not in the group: denied.
        assert_eq!(
            engine.check_service(&pid(0x01), TrustLevel::Unknown, &[], "files"),
            AclPermission::Deny
        );
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let engine = AclEngine::new(vec![AclRule {
            permission: AclPermission::Allow,
            subject: AclSubject::Any,
            target: AclTarget::Everything,
            description: None,
            enabled: false, // Disabled!
        }]);

        // Rule is disabled — implicit deny.
        assert_eq!(
            engine.check_service(&pid(0x01), TrustLevel::InnerCircle, &[], "chat"),
            AclPermission::Deny
        );
    }

    #[test]
    fn test_port_check() {
        let engine = AclEngine::new(vec![AclRule {
            permission: AclPermission::Allow,
            subject: AclSubject::TrustFloor(TrustLevel::Acquaintance),
            target: AclTarget::Port(443),
            description: None,
            enabled: true,
        }]);

        assert_eq!(
            engine.check_port(&pid(0x01), TrustLevel::Trusted, &[], 443),
            AclPermission::Allow
        );
        assert_eq!(
            engine.check_port(&pid(0x01), TrustLevel::Trusted, &[], 80),
            AclPermission::Deny
        );
    }

    #[test]
    fn test_subject_specificity() {
        assert!(AclSubject::Peer(pid(0x01)).specificity() > AclSubject::Any.specificity());
        assert!(
            AclSubject::Group([0; 32]).specificity()
                > AclSubject::TrustFloor(TrustLevel::Unknown).specificity()
        );
    }
}
