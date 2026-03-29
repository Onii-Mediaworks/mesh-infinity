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
pub struct AppConnectorRule {
    /// Which app/traffic this rule matches.
    pub app_selector: AppSelector,
    /// Where to route matching traffic.
    pub routing_target: RoutingTarget,
    /// Priority (lower = higher priority).
    pub priority: u8,
    /// Whether this rule is active.
    pub enabled: bool,
    /// Minimum threat context for this rule to apply.
    pub threat_context_min: Option<u8>,
}

/// Selector for matching app traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppSelector {
    /// Application ID (platform-specific).
    pub app_id: Option<String>,
    /// Domain pattern (e.g., "*.example.com").
    pub domain_pattern: Option<String>,
    /// IP range (CIDR notation).
    pub ip_range: Option<String>,
    /// Port number.
    pub port: Option<u16>,
}

impl AppSelector {
    /// Specificity score for conflict resolution.
    /// More specific selectors win ties.
    pub fn specificity(&self) -> u8 {
        let mut score = 0;
        if self.app_id.is_some() {
            score += 4;
        }
        if self.domain_pattern.is_some() {
            score += 3;
        }
        if self.ip_range.is_some() {
            score += 2;
        }
        if self.port.is_some() {
            score += 1;
        }
        score
    }
}

/// Where to route matched traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RoutingTarget {
    /// Route through a specific exit node.
    ExitNode {
        peer_id: [u8; 32],
        profile: Option<[u8; 16]>,
    },
    /// Route through the mixnet tier.
    MixnetTier,
    /// Route through Tor.
    Tor,
    /// Route through I2P.
    I2P,
    /// Route through direct mesh (no exit node).
    DirectMesh,
    /// Direct connection (bypass mesh).
    Direct,
    /// Route through an Infinet.
    Infinet { infinet_id: [u8; 32] },
}

/// Resolve conflicting rules: highest priority (lowest number) wins.
/// Equal priority: most specific selector wins.
pub fn resolve_rules(rules: &[AppConnectorRule]) -> Option<&AppConnectorRule> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .min_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| {
                    b.app_selector
                        .specificity()
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
