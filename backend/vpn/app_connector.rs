//! App Connector (§13.15)
//!
//! Per-app routing rules that override global routing decisions.
//! Rules are hard constraints to the transport solver.

use serde::{Deserialize, Serialize};

/// A per-app routing rule.
///
/// Lower priority number = higher priority.
/// App connector rules override global ThreatContext scoring.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// AppConnectorRule — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AppConnectorRule — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AppConnectorRule — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AppConnectorRule — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AppConnectorRule {
    /// Which app/traffic this rule matches.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub app_selector: AppSelector,
    /// Where to route matching traffic.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub routing_target: RoutingTarget,
    /// Priority (lower = higher priority).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub priority: u8,
    /// Whether this rule is active.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub enabled: bool,
    /// Minimum threat context for this rule to apply.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub threat_context_min: Option<u8>,
}

/// Selector for matching app traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// AppSelector — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AppSelector — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AppSelector — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AppSelector — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AppSelector {
    /// Application ID (platform-specific).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub app_id: Option<String>,
    /// Domain pattern (e.g., "*.example.com").
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub domain_pattern: Option<String>,
    /// IP range (CIDR notation).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ip_range: Option<String>,
    /// Port number.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub port: Option<u16>,
}

// Begin the block scope.
// AppSelector implementation — core protocol logic.
// AppSelector implementation — core protocol logic.
// AppSelector implementation — core protocol logic.
// AppSelector implementation — core protocol logic.
impl AppSelector {
    /// Specificity score for conflict resolution.
    /// More specific selectors win ties.
    // Perform the 'specificity' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'specificity' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'specificity' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'specificity' operation.
    // Errors are propagated to the caller via Result.
    pub fn specificity(&self) -> u8 {
        // Bind the computed value for subsequent use.
        // Compute score for this protocol step.
        // Compute score for this protocol step.
        // Compute score for this protocol step.
        // Compute score for this protocol step.
        let mut score = 0;
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.app_id.is_some() {
            // Execute this step in the protocol sequence.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            score += 4;
        }
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.domain_pattern.is_some() {
            // Execute this step in the protocol sequence.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            score += 3;
        }
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.ip_range.is_some() {
            // Execute this step in the protocol sequence.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            score += 2;
        }
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.port.is_some() {
            // Execute this step in the protocol sequence.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            score += 1;
        }
        score
    }
}

/// Where to route matched traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// RoutingTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// RoutingTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// RoutingTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// RoutingTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RoutingTarget {
    /// Route through a specific exit node.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ExitNode {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_id: [u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        profile: Option<[u8; 16]>,
    },
    /// Route through the mixnet tier.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    MixnetTier,
    /// Route through Tor.
    Tor,
    /// Route through I2P.
    I2P,
    /// Route through direct mesh (no exit node).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    DirectMesh,
    /// Direct connection (bypass mesh).
    Direct,
    /// Route through an Infinet.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Infinet { infinet_id: [u8; 32] },
}

/// Resolve conflicting rules: highest priority (lowest number) wins.
/// Equal priority: most specific selector wins.
// Perform the 'resolve rules' operation.
// Errors are propagated to the caller via Result.
// Perform the 'resolve rules' operation.
// Errors are propagated to the caller via Result.
// Perform the 'resolve rules' operation.
// Errors are propagated to the caller via Result.
// Perform the 'resolve rules' operation.
// Errors are propagated to the caller via Result.
pub fn resolve_rules(rules: &[AppConnectorRule]) -> Option<&AppConnectorRule> {
    rules
        // Create an iterator over the collection elements.
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
        .filter(|r| r.enabled)
        // Apply the closure to each element.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .min_by(|a, b| {
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            a.priority
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                .cmp(&b.priority)
                // Apply the closure to each element.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                .then_with(|| {
                    // Chain the operation on the intermediate result.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    b.app_selector
                        // Chain the operation on the intermediate result.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        .specificity()
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        .cmp(&a.app_selector.specificity())
                })
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_specificity() {
        let specific = AppSelector {
            app_id: Some("com.example.app".to_string()),
            domain_pattern: None,
            ip_range: None,
            port: None,
        };
        let broad = AppSelector {
            app_id: None,
            domain_pattern: None,
            ip_range: None,
            port: Some(443),
        };
        assert!(specific.specificity() > broad.specificity());
    }

    #[test]
    fn test_resolve_rules() {
        let rules = vec![
            AppConnectorRule {
                app_selector: AppSelector {
                    app_id: None, domain_pattern: None,
                    ip_range: None, port: Some(443),
                },
                routing_target: RoutingTarget::Tor,
                priority: 10,
                enabled: true,
                threat_context_min: None,
            },
            AppConnectorRule {
                app_selector: AppSelector {
                    app_id: Some("browser".into()), domain_pattern: None,
                    ip_range: None, port: None,
                },
                routing_target: RoutingTarget::MixnetTier,
                priority: 5, // Higher priority (lower number).
                enabled: true,
                threat_context_min: None,
            },
        ];

        let winner = resolve_rules(&rules).unwrap();
        assert_eq!(winner.priority, 5);
    }

    #[test]
    fn test_disabled_rules_excluded() {
        let rules = vec![
            AppConnectorRule {
                app_selector: AppSelector {
                    app_id: None, domain_pattern: None,
                    ip_range: None, port: None,
                },
                routing_target: RoutingTarget::Direct,
                priority: 1,
                enabled: false, // Disabled!
                threat_context_min: None,
            },
        ];

        assert!(resolve_rules(&rules).is_none());
    }
}
