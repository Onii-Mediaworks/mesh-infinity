//! App Connector (§13.15)
//!
//! Per-app routing rules that override global routing decisions.
//! Rules are hard constraints to the transport solver.

use serde::{Deserialize, Serialize};

/// How the configured app list should be interpreted.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppConnectorMode {
    #[default]
    Allowlist,
    Denylist,
}

/// One configured application entry exposed to the UI.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConnectorApp {
    /// Stable app identifier such as Android package name or bundle ID.
    pub app_id: String,
    /// Human-friendly label shown in the UI.
    pub name: String,
}

/// Persisted App Connector configuration owned by the backend.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConnectorConfig {
    /// Whether the listed apps are opt-in or opt-out.
    pub mode: AppConnectorMode,
    /// Ordered list of configured applications.
    #[serde(default)]
    pub apps: Vec<AppConnectorApp>,
    /// Explicit selector-based rules.
    #[serde(default)]
    pub rules: Vec<AppConnectorRule>,
}

/// A per-app routing rule.
///
/// Lower priority number = higher priority.
/// App connector rules override global ThreatContext scoring.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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

    /// Whether the selector has no match criteria at all.
    pub fn is_empty(&self) -> bool {
        self.app_id.is_none()
            && self.domain_pattern.is_none()
            && self.ip_range.is_none()
            && self.port.is_none()
    }
}

/// Where to route matched traffic.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RoutingTarget {
    /// Route through a specific exit node.
    ExitNode {
        peer_id: String,
        profile: Option<String>,
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
    Infinet { infinet_id: String },
}

/// Resolve conflicting rules: highest priority (lowest number) wins.
/// Equal priority: most specific selector wins.
pub fn resolve_rules(rules: &[AppConnectorRule]) -> Option<&AppConnectorRule> {
    rules.iter().filter(|r| r.enabled).min_by(|a, b| {
        a.priority.cmp(&b.priority).then_with(|| {
            b.app_selector
                .specificity()
                .cmp(&a.app_selector.specificity())
        })
    })
}

impl AppConnectorConfig {
    /// Convert the UI-facing config into solver-facing routing rules.
    pub fn to_rules(&self) -> Vec<AppConnectorRule> {
        let mut rules = self.rules.clone();
        rules.extend(self.apps.iter().enumerate().map(|(index, app)| {
            let routing_target = match self.mode {
                AppConnectorMode::Allowlist => RoutingTarget::DirectMesh,
                AppConnectorMode::Denylist => RoutingTarget::Direct,
            };
            AppConnectorRule {
                app_selector: AppSelector {
                    app_id: Some(app.app_id.clone()),
                    domain_pattern: None,
                    ip_range: None,
                    port: None,
                },
                routing_target,
                priority: index.min(u8::MAX as usize) as u8,
                enabled: true,
                threat_context_min: None,
            }
        }));
        rules.sort_by(|a, b| {
            a.priority.cmp(&b.priority).then_with(|| {
                b.app_selector
                    .specificity()
                    .cmp(&a.app_selector.specificity())
            })
        });
        rules
    }
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
                    app_id: None,
                    domain_pattern: None,
                    ip_range: None,
                    port: Some(443),
                },
                routing_target: RoutingTarget::Tor,
                priority: 10,
                enabled: true,
                threat_context_min: None,
            },
            AppConnectorRule {
                app_selector: AppSelector {
                    app_id: Some("browser".into()),
                    domain_pattern: None,
                    ip_range: None,
                    port: None,
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
        let rules = vec![AppConnectorRule {
            app_selector: AppSelector {
                app_id: None,
                domain_pattern: None,
                ip_range: None,
                port: None,
            },
            routing_target: RoutingTarget::Direct,
            priority: 1,
            enabled: false, // Disabled!
            threat_context_min: None,
        }];

        assert!(resolve_rules(&rules).is_none());
    }
}
