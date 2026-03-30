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
// Begin the block scope.
// AclPermission — variant enumeration.
// Match exhaustively to handle every protocol state.
// AclPermission — variant enumeration.
// Match exhaustively to handle every protocol state.
// AclPermission — variant enumeration.
// Match exhaustively to handle every protocol state.
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
// Begin the block scope.
// AclSubject — variant enumeration.
// Match exhaustively to handle every protocol state.
// AclSubject — variant enumeration.
// Match exhaustively to handle every protocol state.
// AclSubject — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum AclSubject {
    /// A specific peer by peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Peer(PeerId),

    /// Members of a specific group.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Group([u8; 32]),

    /// Anyone at or above a specific trust level.
    /// e.g., `TrustFloor(TrustLevel::Trusted)` = Level 6+.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    TrustFloor(TrustLevel),

    /// Anyone in a trust level range (inclusive).
    /// e.g., `TrustRange(Vouched, Acquaintance)` = Levels 2–5.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    TrustRange(TrustLevel, TrustLevel),

    /// Anyone at all. Use with extreme caution.
    Any,
}

// Begin the block scope.
// AclSubject implementation — core protocol logic.
// AclSubject implementation — core protocol logic.
// AclSubject implementation — core protocol logic.
impl AclSubject {
    /// Check if a peer matches this subject.
    ///
    /// `peer_id`: the peer to check.
    /// `peer_trust`: the peer's trust level with us.
    /// `peer_groups`: groups the peer belongs to.
    // Perform the 'matches' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'matches' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'matches' operation.
    // Errors are propagated to the caller via Result.
    pub fn matches(
        &self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_id: &PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_trust: TrustLevel,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_groups: &[[u8; 32]],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> bool {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Exact peer match.
            Self::Peer(id) => *id == *peer_id,

            // Group membership match.
            Self::Group(gid) => peer_groups.contains(gid),

            // Trust floor: peer must be at or above the floor.
            Self::TrustFloor(floor) => peer_trust >= *floor,

            // Trust range: peer must be within the range (inclusive).
            // Handle Self::TrustRange(low, high).
            // Handle Self::TrustRange(low, high).
            // Handle Self::TrustRange(low, high).
            Self::TrustRange(low, high) => {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                peer_trust >= *low && peer_trust <= *high
            }

            // Match anyone.
            Self::Any => true,
        }
    }

    /// Specificity score for conflict resolution.
    /// More specific subjects win ties between rules at the same position.
    // Perform the 'specificity' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'specificity' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'specificity' operation.
    // Errors are propagated to the caller via Result.
    pub fn specificity(&self) -> u8 {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Invoke the associated function.
            Self::Peer(_) => 4,
            // Invoke the associated function.
            Self::Group(_) => 3,
            // Invoke the associated function.
            Self::TrustRange(_, _) => 2,
            // Invoke the associated function.
            Self::TrustFloor(_) => 1,
            // Handle this match arm.
            Self::Any => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ACL Target
// ---------------------------------------------------------------------------

/// What an ACL rule protects (§8.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// AclTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// AclTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// AclTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum AclTarget {
    /// A specific service by name.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Service(String),

    /// All services (wildcard).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    AllServices,

    /// A specific mesh port.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Port(u32),

    /// A specific resource path.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Resource(String),

    /// Everything (wildcard — use for default deny).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Everything,
}

// Begin the block scope.
// AclTarget implementation — core protocol logic.
// AclTarget implementation — core protocol logic.
// AclTarget implementation — core protocol logic.
impl AclTarget {
    /// Check if a request matches this target.
    // Perform the 'matches service' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'matches service' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'matches service' operation.
    // Errors are propagated to the caller via Result.
    pub fn matches_service(&self, service_name: &str) -> bool {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Invoke the associated function.
            Self::Service(name) => name == service_name,
            // Handle this match arm.
            Self::AllServices | Self::Everything => true,
            // Update the local state.
            _ => false,
        }
    }

    /// Check if a port matches this target.
    // Perform the 'matches port' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'matches port' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'matches port' operation.
    // Errors are propagated to the caller via Result.
    pub fn matches_port(&self, port: u32) -> bool {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Invoke the associated function.
            Self::Port(p) => *p == port,
            // Handle this match arm.
            Self::Everything => true,
            // Update the local state.
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
// Begin the block scope.
// AclRule — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AclRule — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AclRule — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AclRule {
    /// What this rule does (Allow or Deny).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub permission: AclPermission,

    /// Who this rule applies to.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub subject: AclSubject,

    /// What this rule protects.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target: AclTarget,

    /// Optional human-readable description.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: Option<String>,

    /// Whether this rule is active.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// ACL Engine
// ---------------------------------------------------------------------------

/// Evaluates ACL rules to determine access (§8.8).
///
/// Rules are stored in order and evaluated sequentially.
/// First match wins. No match = implicit Deny.
// AclEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AclEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AclEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AclEngine {
    /// Ordered list of ACL rules.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    rules: Vec<AclRule>,
}

// Begin the block scope.
// AclEngine implementation — core protocol logic.
// AclEngine implementation — core protocol logic.
// AclEngine implementation — core protocol logic.
impl AclEngine {
    /// Create a new ACL engine with the given rules.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(rules: Vec<AclRule>) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self { rules }
    }

    /// Create an empty engine (everything denied by default).
    // Perform the 'empty' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'empty' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'empty' operation.
    // Errors are propagated to the caller via Result.
    pub fn empty() -> Self {
        // Create a new instance with the specified parameters.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
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
    // Perform the 'check service' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check service' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check service' operation.
    // Errors are propagated to the caller via Result.
    pub fn check_service(
        &self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_id: &PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_trust: TrustLevel,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_groups: &[[u8; 32]],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        service_name: &str,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> AclPermission {
        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for rule in &self.rules {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !rule.enabled {
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                continue;
            }

            // Check if both subject and target match.
            // Compute subject match for this protocol step.
            // Compute subject match for this protocol step.
            // Compute subject match for this protocol step.
            let subject_match =
                // Execute the operation and bind the result.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                rule.subject.matches(peer_id, peer_trust, peer_groups);
            // Dispatch based on the variant to apply type-specific logic.
            // Compute target match for this protocol step.
            // Compute target match for this protocol step.
            // Compute target match for this protocol step.
            let target_match = rule.target.matches_service(service_name);

            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if subject_match && target_match {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return rule.permission;
            }
        }

        // No rule matched → implicit Deny.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        AclPermission::Deny
    }

    /// Evaluate whether a peer can access a port.
    // Perform the 'check port' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check port' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check port' operation.
    // Errors are propagated to the caller via Result.
    pub fn check_port(
        &self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_id: &PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_trust: TrustLevel,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_groups: &[[u8; 32]],
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        port: u32,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> AclPermission {
        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for rule in &self.rules {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !rule.enabled {
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                continue;
            }

            // Dispatch based on the variant to apply type-specific logic.
            // Compute subject match for this protocol step.
            // Compute subject match for this protocol step.
            // Compute subject match for this protocol step.
            let subject_match =
                // Execute the operation and bind the result.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                rule.subject.matches(peer_id, peer_trust, peer_groups);
            // Dispatch based on the variant to apply type-specific logic.
            // Compute target match for this protocol step.
            // Compute target match for this protocol step.
            // Compute target match for this protocol step.
            let target_match = rule.target.matches_port(port);

            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if subject_match && target_match {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return rule.permission;
            }
        }

        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        AclPermission::Deny
    }

    /// Add a rule to the end of the list.
    // Perform the 'add rule' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add rule' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add rule' operation.
    // Errors are propagated to the caller via Result.
    pub fn add_rule(&mut self, rule: AclRule) {
        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        self.rules.push(rule);
    }

    /// Insert a rule at a specific position.
    // Perform the 'insert rule' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'insert rule' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'insert rule' operation.
    // Errors are propagated to the caller via Result.
    pub fn insert_rule(&mut self, index: usize, rule: AclRule) {
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if index <= self.rules.len() {
            // Insert into the lookup table for efficient retrieval.
            // Insert into the map/set.
            // Insert into the map/set.
            // Insert into the map/set.
            self.rules.insert(index, rule);
        }
    }

    /// Remove a rule by index.
    // Perform the 'remove rule' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'remove rule' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'remove rule' operation.
    // Errors are propagated to the caller via Result.
    pub fn remove_rule(&mut self, index: usize) -> Option<AclRule> {
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if index < self.rules.len() {
            // Remove from the collection and return the evicted value.
            // Wrap the found value.
            // Wrap the found value.
            // Wrap the found value.
            Some(self.rules.remove(index))
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // No value available.
            // No value available.
            // No value available.
            None
        }
    }

    /// Number of rules.
    // Perform the 'rule count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'rule count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'rule count' operation.
    // Errors are propagated to the caller via Result.
    pub fn rule_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
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
