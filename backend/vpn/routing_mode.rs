//! VPN Traffic Routing Modes (§13.4, §13.11)
//!
//! # Four Routing Modes (§13.4)
//!
//! - **Off**: no VPN; messaging/services only. Default.
//! - **MeshOnly**: only mesh-addressed traffic goes through mesh.
//!   Internet traffic goes direct (or is blocked).
//! - **ExitNode**: ALL internet traffic routed via a selected
//!   exit node. Maximum privacy for internet browsing.
//! - **PolicyBased**: per-destination/app rules from the App Connector.
//!
//! # Kill Switch (§13.11)
//!
//! - **Strict** (default): traffic halts if exit node drops.
//!   User must reconnect or change mode. This prevents accidental
//!   IP exposure when the tunnel drops.
//! - **Permissive**: internet traffic falls back to direct on
//!   exit node disconnect. Less private but more reliable.
//!
//! # Mode Switching State Machine
//!
//! Mode changes are validated:
//! - ExitNode requires an exit_peer_id to be set
//! - PolicyBased requires at least one App Connector rule
//! - Switching to a more restrictive mode is always allowed
//! - Mesh tunnel maintenance (§16.3 minimum 2 tunnels) is
//!   UNAFFECTED by kill switch mode

use serde::{Deserialize, Serialize};

use crate::network::threat_context::ThreatContext;

// ---------------------------------------------------------------------------
// Routing Mode
// ---------------------------------------------------------------------------

/// VPN traffic routing mode (§13.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingMode {
    /// No VPN; messaging/service only.
    Off,
    /// Only mesh-addressed traffic through mesh.
    MeshOnly,
    /// All internet traffic via selected exit node.
    ExitNode,
    /// User-defined rules per destination/app/service.
    PolicyBased,
}

// ---------------------------------------------------------------------------
// Kill Switch Mode
// ---------------------------------------------------------------------------

/// Kill switch mode (§13.11).
///
/// Controls what happens when the exit node disconnects.
/// Mesh tunnels (§16.3) are unaffected by kill switch mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum KillSwitchMode {
    /// Traffic halts if exit drops. Reconnect or change mode.
    #[default]
    Strict,
    /// Internet traffic falls back to direct on disconnect.
    Permissive,
}


// ---------------------------------------------------------------------------
// VPN State
// ---------------------------------------------------------------------------

/// VPN operating state (runtime, not configuration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpnState {
    /// VPN is inactive (mode is Off).
    Inactive,
    /// VPN is connecting to exit node.
    Connecting,
    /// VPN is active and routing traffic.
    Active,
    /// Exit node disconnected, kill switch engaged.
    /// Traffic is halted (Strict mode) or falling back (Permissive).
    KillSwitchEngaged,
    /// VPN is disconnecting.
    Disconnecting,
}

// ---------------------------------------------------------------------------
// VPN Configuration
// ---------------------------------------------------------------------------

/// VPN configuration (§13.4, §13.11).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnConfig {
    /// Current routing mode.
    pub mode: RoutingMode,
    /// Selected exit node (for ExitNode mode).
    pub exit_peer_id: Option<[u8; 32]>,
    /// Selected network profile on the exit node.
    pub exit_profile_id: Option<[u8; 16]>,
    /// Kill switch mode.
    pub kill_switch: KillSwitchMode,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            mode: RoutingMode::Off,
            exit_peer_id: None,
            exit_profile_id: None,
            kill_switch: KillSwitchMode::Strict,
        }
    }
}

// ---------------------------------------------------------------------------
// VPN Manager
// ---------------------------------------------------------------------------

/// Manages VPN state and mode transitions.
///
/// Validates mode changes, enforces kill switch policy,
/// and tracks the current VPN operating state.
pub struct VpnManager {
    /// Current VPN configuration.
    pub config: VpnConfig,
    /// Current operating state.
    pub state: VpnState,
    /// Whether the exit node is currently reachable.
    pub exit_reachable: bool,
}

impl VpnManager {
    /// Create a new VPN manager with default config.
    pub fn new() -> Self {
        Self {
            config: VpnConfig::default(),
            state: VpnState::Inactive,
            exit_reachable: false,
        }
    }

    /// Attempt to change the routing mode.
    ///
    /// Validates the mode change:
    /// - ExitNode requires exit_peer_id to be set
    /// - PolicyBased requires has_rules to be true
    /// - ThreatContext::Critical restricts to Off or MeshOnly
    ///
    /// Returns an error string if the mode change is invalid.
    pub fn set_mode(
        &mut self,
        mode: RoutingMode,
        threat: ThreatContext,
        has_policy_rules: bool,
    ) -> Result<(), &'static str> {
        // In Critical threat context, only Off and MeshOnly are allowed.
        if threat == ThreatContext::Critical
            && !matches!(mode, RoutingMode::Off | RoutingMode::MeshOnly)
        {
            return Err("ExitNode and PolicyBased modes unavailable in Critical threat context");
        }

        // ExitNode requires a selected exit node.
        if mode == RoutingMode::ExitNode && self.config.exit_peer_id.is_none() {
            return Err("ExitNode mode requires selecting an exit node first");
        }

        // PolicyBased requires at least one App Connector rule.
        if mode == RoutingMode::PolicyBased && !has_policy_rules {
            return Err("PolicyBased mode requires at least one routing rule");
        }

        // Apply the mode change.
        self.config.mode = mode;

        // Update operating state.
        match mode {
            RoutingMode::Off => {
                self.state = VpnState::Inactive;
            }
            RoutingMode::MeshOnly => {
                self.state = VpnState::Active;
            }
            RoutingMode::ExitNode => {
                self.state = VpnState::Connecting;
            }
            RoutingMode::PolicyBased => {
                self.state = VpnState::Active;
            }
        }

        Ok(())
    }

    /// Handle exit node disconnect.
    ///
    /// Called when the exit node becomes unreachable.
    /// Engages the kill switch based on the configured mode.
    pub fn on_exit_disconnected(&mut self) {
        self.exit_reachable = false;

        if self.config.mode == RoutingMode::ExitNode {
            self.state = VpnState::KillSwitchEngaged;
        }
    }

    /// Handle exit node reconnect.
    pub fn on_exit_reconnected(&mut self) {
        self.exit_reachable = true;

        if self.state == VpnState::KillSwitchEngaged {
            self.state = VpnState::Active;
        }
    }

    /// Whether internet traffic is currently allowed.
    ///
    /// In Strict kill switch mode, traffic is blocked when the
    /// kill switch is engaged. In Permissive mode, it falls back
    /// to direct.
    pub fn internet_traffic_allowed(&self) -> bool {
        match self.state {
            VpnState::Inactive => true, // No VPN, direct traffic.
            VpnState::Active => true,
            VpnState::Connecting => false, // Wait for connection.
            VpnState::Disconnecting => false,
            VpnState::KillSwitchEngaged => {
                // Strict: blocked. Permissive: falls back to direct.
                self.config.kill_switch == KillSwitchMode::Permissive
            }
        }
    }

    /// Whether traffic should be routed through the exit node.
    pub fn should_route_through_exit(&self) -> bool {
        self.config.mode == RoutingMode::ExitNode
            && self.state == VpnState::Active
            && self.exit_reachable
    }
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = VpnConfig::default();
        assert_eq!(config.mode, RoutingMode::Off);
        assert_eq!(config.kill_switch, KillSwitchMode::Strict);
        assert!(config.exit_peer_id.is_none());
    }

    #[test]
    fn test_exit_node_requires_peer_id() {
        let mut mgr = VpnManager::new();

        // No exit peer selected — should fail.
        let result = mgr.set_mode(RoutingMode::ExitNode, ThreatContext::Normal, false);
        assert!(result.is_err());

        // Set an exit peer and try again.
        mgr.config.exit_peer_id = Some([0x01; 32]);
        let result = mgr.set_mode(RoutingMode::ExitNode, ThreatContext::Normal, false);
        assert!(result.is_ok());
        assert_eq!(mgr.state, VpnState::Connecting);
    }

    #[test]
    fn test_critical_restricts_modes() {
        let mut mgr = VpnManager::new();
        mgr.config.exit_peer_id = Some([0x01; 32]);

        // ExitNode not allowed in Critical.
        let result = mgr.set_mode(RoutingMode::ExitNode, ThreatContext::Critical, false);
        assert!(result.is_err());

        // MeshOnly is allowed in Critical.
        let result = mgr.set_mode(RoutingMode::MeshOnly, ThreatContext::Critical, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_kill_switch_strict() {
        let mut mgr = VpnManager::new();
        mgr.config.exit_peer_id = Some([0x01; 32]);
        mgr.set_mode(RoutingMode::ExitNode, ThreatContext::Normal, false).unwrap();
        mgr.state = VpnState::Active;
        mgr.exit_reachable = true;

        // Exit disconnects — kill switch engages.
        mgr.on_exit_disconnected();
        assert_eq!(mgr.state, VpnState::KillSwitchEngaged);

        // In Strict mode, internet traffic is blocked.
        assert!(!mgr.internet_traffic_allowed());

        // Exit reconnects — traffic resumes.
        mgr.on_exit_reconnected();
        assert!(mgr.internet_traffic_allowed());
    }

    #[test]
    fn test_kill_switch_permissive() {
        let mut mgr = VpnManager::new();
        mgr.config.exit_peer_id = Some([0x01; 32]);
        mgr.config.kill_switch = KillSwitchMode::Permissive;
        mgr.set_mode(RoutingMode::ExitNode, ThreatContext::Normal, false).unwrap();
        mgr.state = VpnState::Active;

        mgr.on_exit_disconnected();
        assert_eq!(mgr.state, VpnState::KillSwitchEngaged);

        // In Permissive mode, traffic falls back to direct.
        assert!(mgr.internet_traffic_allowed());
    }

    #[test]
    fn test_policy_requires_rules() {
        let mut mgr = VpnManager::new();

        // No rules — should fail.
        let result = mgr.set_mode(RoutingMode::PolicyBased, ThreatContext::Normal, false);
        assert!(result.is_err());

        // With rules — should succeed.
        let result = mgr.set_mode(RoutingMode::PolicyBased, ThreatContext::Normal, true);
        assert!(result.is_ok());
    }
}
