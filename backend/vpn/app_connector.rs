//! App Connector (§13.15)
//!
//! Per-app routing rules that override global routing decisions.
//! Rules are hard constraints to the transport solver.
//!
//! # Selector matching (§13.15 configuration model)
//!
//! Each `AppConnectorRule` carries an `AppSelector` that can name up to four
//! independent match criteria.  A connection matches a rule only when ALL
//! non-None criteria match simultaneously:
//!
//! | Selector field   | Match semantics                                        |
//! |------------------|--------------------------------------------------------|
//! | `app_id`         | Exact string equality against the calling package name |
//! | `domain_pattern` | Glob suffix: `"*.example.com"` → ends_with suffix      |
//! | `ip_range`       | CIDR containment: manual bit-mask, no external crate   |
//! | `port`           | Exact `u16` equality                                   |
//!
//! A `None` field is a wildcard — it matches any value for that dimension.
//! An empty `AppSelector` (all None) is therefore a catch-all.
//!
//! Rules are evaluated in ascending priority order (lower number = higher
//! priority).  At equal priority the more specific selector wins (see
//! `AppSelector::specificity`).  The first matching rule determines the
//! `ConnectorAction`.  If no rule matches the global default is
//! `ConnectorAction::AllowDirect`.

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

// ---------------------------------------------------------------------------
// Connection evaluation — the data-plane decision function
// ---------------------------------------------------------------------------

/// The routing action returned by `AppConnectorConfig::evaluate_connection`.
///
/// These values are mapped to integers in the FFI layer:
///   0 = Block  (drop the packet; the connection must not be forwarded)
///   1 = AllowDirect  (bypass the mesh; send through the device's normal IP stack)
///   2 = RouteViaMesh (forward through the mesh tunnel — the default for allowed apps)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorAction {
    /// Drop the packet.  Used when the matching rule targets a blocking target
    /// or when the connector is in denylist mode for this app.
    Block,
    /// Let the packet bypass the VPN tunnel and travel the normal IP path.
    AllowDirect,
    /// Forward the packet through the mesh tunnel (exit node, mixnet, etc.).
    RouteViaMesh,
}

impl ConnectorAction {
    /// Encode as the integer returned across the FFI boundary.
    ///
    /// Callers: 0 = block, 1 = allow_direct, 2 = route_via_mesh.
    pub fn as_ffi_int(self) -> i32 {
        match self {
            ConnectorAction::Block => 0,
            ConnectorAction::AllowDirect => 1,
            ConnectorAction::RouteViaMesh => 2,
        }
    }
}

/// Map a `RoutingTarget` to the coarse `ConnectorAction` needed by the data plane.
///
/// Any mesh-routed target (exit node, mixnet, Tor, I2P, DirectMesh, Infinet)
/// becomes `RouteViaMesh`.  `Direct` becomes `AllowDirect`.  There is no
/// explicit block target in `RoutingTarget`; block is reserved for future
/// denylist-mode expansion.
fn routing_target_to_action(target: &RoutingTarget) -> ConnectorAction {
    match target {
        // Direct bypass — packet should leave the VPN tunnel.
        RoutingTarget::Direct => ConnectorAction::AllowDirect,
        // All other targets use the mesh data path.
        RoutingTarget::ExitNode { .. }
        | RoutingTarget::MixnetTier
        | RoutingTarget::Tor
        | RoutingTarget::I2P
        | RoutingTarget::DirectMesh
        | RoutingTarget::Infinet { .. } => ConnectorAction::RouteViaMesh,
    }
}

// ---------------------------------------------------------------------------
// CIDR containment check — implemented with std::net::IpAddr only
// ---------------------------------------------------------------------------

/// Parse a CIDR string such as `"10.0.0.0/8"` or `"fd00::/16"` and report
/// whether `addr` falls within the described network.
///
/// # How the bit-mask check works (IPv4 example)
///
/// Given `"10.0.0.0/8"`:
/// - Network address = 10.0.0.0  →  `u32` = 0x0A000000
/// - Prefix length   = 8
/// - Mask            = 0xFFFFFFFF << (32 - 8)  =  0xFF000000
/// - A candidate `addr` matches iff `(addr_u32 & mask) == (network_u32 & mask)`
///
/// IPv6 uses the same logic on the 128-bit address split into two `u64` words.
///
/// Returns `false` on any parse error so a bad CIDR string never silently
/// allows traffic — it simply fails to match.
fn ip_in_cidr(addr: std::net::IpAddr, cidr: &str) -> bool {
    // Split on the first '/'.  Both halves must be present.
    let slash = match cidr.find('/') {
        Some(pos) => pos,
        None => return false,
    };
    let addr_part = &cidr[..slash];
    let prefix_str = &cidr[slash + 1..];

    // Parse the prefix length as a plain integer.
    let prefix_len: u32 = match prefix_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Parse the network base address and attempt to match address family.
    let network_addr: std::net::IpAddr = match addr_part.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    match (addr, network_addr) {
        // ---------------------------------------------------------------
        // IPv4 path
        // ---------------------------------------------------------------
        (std::net::IpAddr::V4(candidate), std::net::IpAddr::V4(network)) => {
            if prefix_len > 32 {
                // Invalid prefix; fail closed.
                return false;
            }
            let candidate_u32 = u32::from(candidate);
            let network_u32 = u32::from(network);
            if prefix_len == 0 {
                // /0 matches the entire IPv4 space.
                return true;
            }
            // Build the host-order mask: shift 0xFFFF_FFFF left by (32 - prefix_len).
            let mask: u32 = u32::MAX << (32 - prefix_len);
            (candidate_u32 & mask) == (network_u32 & mask)
        }

        // ---------------------------------------------------------------
        // IPv6 path
        // ---------------------------------------------------------------
        (std::net::IpAddr::V6(candidate), std::net::IpAddr::V6(network)) => {
            if prefix_len > 128 {
                return false;
            }
            // Represent both addresses as two u64 words (high 64 bits, low 64 bits).
            let cand_bytes = candidate.octets();
            let net_bytes = network.octets();
            let cand_hi = u64::from_be_bytes(cand_bytes[0..8].try_into().unwrap());
            let cand_lo = u64::from_be_bytes(cand_bytes[8..16].try_into().unwrap());
            let net_hi = u64::from_be_bytes(net_bytes[0..8].try_into().unwrap());
            let net_lo = u64::from_be_bytes(net_bytes[8..16].try_into().unwrap());

            if prefix_len == 0 {
                return true;
            }
            if prefix_len <= 64 {
                // The entire match is decided by the high word.
                let mask_hi: u64 = u64::MAX << (64 - prefix_len);
                (cand_hi & mask_hi) == (net_hi & mask_hi)
            } else {
                // High word must match fully; low word is masked.
                let low_bits = prefix_len - 64;
                let mask_lo: u64 = u64::MAX << (64 - low_bits);
                cand_hi == net_hi && (cand_lo & mask_lo) == (net_lo & mask_lo)
            }
        }

        // Mismatched address families never match.
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Domain glob matching
// ---------------------------------------------------------------------------

/// Check whether `domain` matches `pattern`.
///
/// The only wildcard supported is a leading `*` as in `"*.example.com"`.
/// This is the full extent of the spec's domain_pattern language (§13.15).
///
/// # Matching rules
///
/// - `"*.example.com"` matches `"foo.example.com"` and `"bar.example.com"`
///   but NOT `"example.com"` (no label to replace the `*`).
/// - A pattern without a `*` prefix is an exact hostname match.
/// - An empty pattern never matches.
fn domain_matches(pattern: &str, domain: &str) -> bool {
    if pattern.is_empty() || domain.is_empty() {
        return false;
    }
    if let Some(glob_rest) = pattern.strip_prefix('*') {
        // `glob_rest` is everything after the `*`, e.g. `".example.com"`.
        // The candidate must end with `glob_rest` AND have at least one
        // additional character before it (the label that replaced the `*`).
        if glob_rest.is_empty() {
            // Pattern is just `"*"` — matches everything.
            return true;
        }
        domain.ends_with(glob_rest) && domain.len() > glob_rest.len()
    } else {
        // No wildcard — exact equality.
        domain == pattern
    }
}

// ---------------------------------------------------------------------------
// AppSelector: per-connection matching
// ---------------------------------------------------------------------------

impl AppSelector {
    /// Return true if all non-None fields match the supplied connection attributes.
    ///
    /// A None field is a wildcard for that dimension — it always matches.
    /// All non-None fields must match simultaneously for the rule to fire.
    ///
    /// # Parameters
    ///
    /// - `package`    — the calling app's package / bundle ID (exact match vs `app_id`)
    /// - `dst_ip`     — the packet's destination IP address (checked against `ip_range`)
    /// - `dst_port`   — the packet's destination port (exact match vs `port`)
    /// - `dst_domain` — optional resolved domain from DNS (checked against `domain_pattern`)
    pub fn matches_connection(
        &self,
        package: &str,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        dst_domain: Option<&str>,
    ) -> bool {
        // --- app_id -----------------------------------------------------------
        // Exact package name match.  A None app_id means "any application".
        if let Some(app_id) = &self.app_id {
            if app_id != package {
                return false;
            }
        }

        // --- domain_pattern ---------------------------------------------------
        // Glob suffix check as described in domain_matches().
        // If no domain is available for the connection the field is skipped
        // (treated as wildcard) only when the field is None.  When the rule
        // has a domain_pattern but no domain was resolved we cannot match.
        if let Some(pattern) = &self.domain_pattern {
            match dst_domain {
                Some(dom) => {
                    if !domain_matches(pattern, dom) {
                        return false;
                    }
                }
                // Domain pattern present but we have no domain for this packet
                // — this rule cannot fire.
                None => return false,
            }
        }

        // --- ip_range ---------------------------------------------------------
        // CIDR containment check implemented with std::net bit-masking.
        if let Some(cidr) = &self.ip_range {
            if !ip_in_cidr(dst_ip, cidr) {
                return false;
            }
        }

        // --- port -------------------------------------------------------------
        // Exact port number match.
        if let Some(rule_port) = self.port {
            if rule_port != dst_port {
                return false;
            }
        }

        // All non-None criteria matched (or were wildcards).
        true
    }
}

impl AppConnectorConfig {
    /// Evaluate all active rules against a connection 4-tuple and return the
    /// routing decision.
    ///
    /// Rules are tested in priority order (lower `priority` number = higher
    /// precedence).  At equal priority the more specific selector wins (via
    /// `AppSelector::specificity`).  The list is assumed to be pre-sorted by
    /// `set_app_connector_config`; we re-sort defensively here so the function
    /// is correct even with an unsorted list.
    ///
    /// The default when no rule matches is `ConnectorAction::AllowDirect` —
    /// unmatched traffic is not captured by the mesh.
    ///
    /// # Parameters
    ///
    /// - `package`    — Android package name (or iOS bundle ID) of the app
    ///   that originated the packet.
    /// - `dst_ip`     — destination IP parsed from the raw IP header.
    /// - `dst_port`   — destination port parsed from the TCP/UDP header.
    /// - `dst_domain` — optional domain name extracted from a DNS question or
    ///   SNI field; `None` when not available (most packets).
    pub fn evaluate_connection(
        &self,
        package: &str,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        dst_domain: Option<&str>,
    ) -> ConnectorAction {
        // Collect enabled rules and sort by (priority ASC, specificity DESC).
        // Sorting is O(n log n) but rule lists are expected to be tiny (<100).
        let mut candidates: Vec<&AppConnectorRule> =
            self.rules.iter().filter(|r| r.enabled).collect();
        candidates.sort_by(|a, b| {
            a.priority.cmp(&b.priority).then_with(|| {
                // Higher specificity wins at equal priority (sort DESC).
                b.app_selector
                    .specificity()
                    .cmp(&a.app_selector.specificity())
            })
        });

        // Walk rules in priority order; return on the first match.
        for rule in &candidates {
            if rule
                .app_selector
                .matches_connection(package, dst_ip, dst_port, dst_domain)
            {
                return routing_target_to_action(&rule.routing_target);
            }
        }

        // No rule matched — default: allow direct (do not capture).
        ConnectorAction::AllowDirect
    }
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

    // Helper: build a minimal AppConnectorConfig with a single rule.
    fn single_rule_config(selector: AppSelector, target: RoutingTarget, priority: u8) -> AppConnectorConfig {
        AppConnectorConfig {
            mode: AppConnectorMode::Allowlist,
            apps: vec![],
            rules: vec![AppConnectorRule {
                app_selector: selector,
                routing_target: target,
                priority,
                enabled: true,
                threat_context_min: None,
            }],
        }
    }

    // Helper: parse an IP address from a string literal.
    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().expect("bad IP in test")
    }

    // -----------------------------------------------------------------
    // Selector matching unit tests
    // -----------------------------------------------------------------

    /// An exact package match routes via mesh; a non-matching package uses the
    /// default allow-direct action.
    #[test]
    fn test_evaluate_package_match() {
        let config = single_rule_config(
            AppSelector {
                app_id: Some("com.example.browser".into()),
                domain_pattern: None,
                ip_range: None,
                port: None,
            },
            RoutingTarget::DirectMesh,
            10,
        );

        // Matching package → RouteViaMesh.
        let action = config.evaluate_connection(
            "com.example.browser",
            ip("1.2.3.4"),
            443,
            None,
        );
        assert_eq!(action, ConnectorAction::RouteViaMesh,
            "Matching package name must route via mesh");

        // Different package → default AllowDirect.
        let action2 = config.evaluate_connection(
            "com.other.app",
            ip("1.2.3.4"),
            443,
            None,
        );
        assert_eq!(action2, ConnectorAction::AllowDirect,
            "Non-matching package must fall through to default");
    }

    /// Domain glob pattern `*.example.com` should match `sub.example.com` but
    /// not `example.com` itself (no label to replace the wildcard).
    #[test]
    fn test_evaluate_domain_glob() {
        let config = single_rule_config(
            AppSelector {
                app_id: None,
                domain_pattern: Some("*.example.com".into()),
                ip_range: None,
                port: None,
            },
            RoutingTarget::Tor,
            5,
        );

        // Subdomain matches.
        let hit = config.evaluate_connection(
            "any.app",
            ip("93.184.216.34"),
            443,
            Some("sub.example.com"),
        );
        assert_eq!(hit, ConnectorAction::RouteViaMesh,
            "*.example.com must match sub.example.com");

        // Second-level subdomain also matches.
        let hit2 = config.evaluate_connection(
            "any.app",
            ip("93.184.216.34"),
            80,
            Some("a.b.example.com"),
        );
        assert_eq!(hit2, ConnectorAction::RouteViaMesh,
            "*.example.com must match a.b.example.com");

        // The bare domain itself does not match (no label replacing *).
        let miss = config.evaluate_connection(
            "any.app",
            ip("93.184.216.34"),
            443,
            Some("example.com"),
        );
        assert_eq!(miss, ConnectorAction::AllowDirect,
            "*.example.com must NOT match example.com directly");

        // Completely different domain does not match.
        let miss2 = config.evaluate_connection(
            "any.app",
            ip("1.1.1.1"),
            53,
            Some("other.com"),
        );
        assert_eq!(miss2, ConnectorAction::AllowDirect,
            "*.example.com must NOT match other.com");
    }

    /// CIDR `10.0.0.0/8` must include `10.1.2.3` and exclude `11.0.0.0`.
    #[test]
    fn test_evaluate_cidr() {
        let config = single_rule_config(
            AppSelector {
                app_id: None,
                domain_pattern: None,
                ip_range: Some("10.0.0.0/8".into()),
                port: None,
            },
            RoutingTarget::MixnetTier,
            3,
        );

        // Address inside the /8 → RouteViaMesh.
        let inside = config.evaluate_connection("pkg", ip("10.1.2.3"), 80, None);
        assert_eq!(inside, ConnectorAction::RouteViaMesh,
            "10.1.2.3 must be inside 10.0.0.0/8");

        // Address outside the /8 → default AllowDirect.
        let outside = config.evaluate_connection("pkg", ip("11.0.0.0"), 80, None);
        assert_eq!(outside, ConnectorAction::AllowDirect,
            "11.0.0.0 must be outside 10.0.0.0/8");

        // Edge: network address itself is inside.
        let network_addr = config.evaluate_connection("pkg", ip("10.0.0.0"), 80, None);
        assert_eq!(network_addr, ConnectorAction::RouteViaMesh,
            "10.0.0.0 (network address) must be inside 10.0.0.0/8");

        // Edge: broadcast-like address at end of range is inside.
        let end = config.evaluate_connection("pkg", ip("10.255.255.255"), 80, None);
        assert_eq!(end, ConnectorAction::RouteViaMesh,
            "10.255.255.255 must be inside 10.0.0.0/8");
    }

    /// Port 443 rule fires only on port 443, not 80 or 8443.
    #[test]
    fn test_evaluate_port() {
        let config = single_rule_config(
            AppSelector {
                app_id: None,
                domain_pattern: None,
                ip_range: None,
                port: Some(443),
            },
            RoutingTarget::I2P,
            20,
        );

        // Exact match.
        let hit = config.evaluate_connection("any", ip("8.8.8.8"), 443, None);
        assert_eq!(hit, ConnectorAction::RouteViaMesh,
            "Port 443 rule must fire on port 443");

        // Different port — falls through to default.
        let miss = config.evaluate_connection("any", ip("8.8.8.8"), 80, None);
        assert_eq!(miss, ConnectorAction::AllowDirect,
            "Port 443 rule must NOT fire on port 80");

        let miss2 = config.evaluate_connection("any", ip("8.8.8.8"), 8443, None);
        assert_eq!(miss2, ConnectorAction::AllowDirect,
            "Port 443 rule must NOT fire on port 8443");
    }

    /// When no rule matches the default policy is AllowDirect.
    #[test]
    fn test_evaluate_no_match_uses_default() {
        // Config with a rule that will never fire for our probe.
        let config = single_rule_config(
            AppSelector {
                app_id: Some("com.specific.app".into()),
                domain_pattern: None,
                ip_range: None,
                port: None,
            },
            RoutingTarget::DirectMesh,
            1,
        );

        // Our package does not match — must get the default.
        let action = config.evaluate_connection(
            "com.completely.different",
            ip("5.5.5.5"),
            80,
            None,
        );
        assert_eq!(action, ConnectorAction::AllowDirect,
            "Unmatched connection must return AllowDirect default");

        // Empty rule list — always defaults.
        let empty_config = AppConnectorConfig::default();
        let default_action = empty_config.evaluate_connection("any.pkg", ip("1.1.1.1"), 53, None);
        assert_eq!(default_action, ConnectorAction::AllowDirect,
            "Empty config must always return AllowDirect");
    }

    /// A rule with lower priority number (= higher precedence) wins over a
    /// higher-numbered rule even when the higher-numbered rule also matches.
    #[test]
    fn test_evaluate_priority_order() {
        // Two rules both match "com.example.app":
        //   priority 1  → Tor (should win)
        //   priority 10 → Direct (lower precedence)
        let config = AppConnectorConfig {
            mode: AppConnectorMode::Allowlist,
            apps: vec![],
            rules: vec![
                AppConnectorRule {
                    app_selector: AppSelector {
                        app_id: Some("com.example.app".into()),
                        domain_pattern: None,
                        ip_range: None,
                        port: None,
                    },
                    routing_target: RoutingTarget::Direct, // lower precedence
                    priority: 10,
                    enabled: true,
                    threat_context_min: None,
                },
                AppConnectorRule {
                    app_selector: AppSelector {
                        app_id: Some("com.example.app".into()),
                        domain_pattern: None,
                        ip_range: None,
                        port: None,
                    },
                    routing_target: RoutingTarget::Tor, // higher precedence (priority 1)
                    priority: 1,
                    enabled: true,
                    threat_context_min: None,
                },
            ],
        };

        // Priority 1 rule (Tor → RouteViaMesh) must win.
        let action = config.evaluate_connection("com.example.app", ip("9.9.9.9"), 443, None);
        assert_eq!(action, ConnectorAction::RouteViaMesh,
            "Lower priority number must win — Tor (priority 1) beats Direct (priority 10)");
    }

    // -----------------------------------------------------------------
    // Existing tests — preserved in full
    // -----------------------------------------------------------------

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
