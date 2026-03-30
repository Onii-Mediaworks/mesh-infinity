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
// Begin the block scope.
// RoutingMode — variant enumeration.
// Match exhaustively to handle every protocol state.
// RoutingMode — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RoutingMode {
    /// No VPN; messaging/service only.
    Off,
    /// Only mesh-addressed traffic through mesh.
    // Execute this protocol step.
    // Execute this protocol step.
    MeshOnly,
    /// All internet traffic via selected exit node.
    // Execute this protocol step.
    // Execute this protocol step.
    ExitNode,
    /// User-defined rules per destination/app/service.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// KillSwitchMode — variant enumeration.
// Match exhaustively to handle every protocol state.
// KillSwitchMode — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum KillSwitchMode {
    /// Traffic halts if exit drops. Reconnect or change mode.
    #[default]
    Strict,
    /// Internet traffic falls back to direct on disconnect.
    // Execute this protocol step.
    // Execute this protocol step.
    Permissive,
}


// ---------------------------------------------------------------------------
// VPN State
// ---------------------------------------------------------------------------

/// VPN operating state (runtime, not configuration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Begin the block scope.
// VpnState — variant enumeration.
// Match exhaustively to handle every protocol state.
// VpnState — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum VpnState {
    /// VPN is inactive (mode is Off).
    // Execute this protocol step.
    // Execute this protocol step.
    Inactive,
    /// VPN is connecting to exit node.
    // Execute this protocol step.
    // Execute this protocol step.
    Connecting,
    /// VPN is active and routing traffic.
    Active,
    /// Exit node disconnected, kill switch engaged.
    /// Traffic is halted (Strict mode) or falling back (Permissive).
    // Execute this protocol step.
    // Execute this protocol step.
    KillSwitchEngaged,
    /// VPN is disconnecting.
    // Execute this protocol step.
    // Execute this protocol step.
    Disconnecting,
}

// ---------------------------------------------------------------------------
// VPN Configuration
// ---------------------------------------------------------------------------

/// VPN configuration (§13.4, §13.11).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// VpnConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// VpnConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct VpnConfig {
    /// Current routing mode.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mode: RoutingMode,
    /// Selected exit node (for ExitNode mode).
    // Execute this protocol step.
    // Execute this protocol step.
    pub exit_peer_id: Option<[u8; 32]>,
    /// Selected network profile on the exit node.
    // Execute this protocol step.
    // Execute this protocol step.
    pub exit_profile_id: Option<[u8; 16]>,
    /// Kill switch mode.
    // Execute this protocol step.
    // Execute this protocol step.
    pub kill_switch: KillSwitchMode,
}

// Trait implementation for protocol conformance.
// Implement Default for VpnConfig.
// Implement Default for VpnConfig.
impl Default for VpnConfig {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            mode: RoutingMode::Off,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            exit_peer_id: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            exit_profile_id: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
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
// VpnManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// VpnManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct VpnManager {
    /// Current VPN configuration.
    // Execute this protocol step.
    // Execute this protocol step.
    pub config: VpnConfig,
    /// Current operating state.
    // Execute this protocol step.
    // Execute this protocol step.
    pub state: VpnState,
    /// Whether the exit node is currently reachable.
    // Execute this protocol step.
    // Execute this protocol step.
    pub exit_reachable: bool,
}

// Begin the block scope.
// VpnManager implementation — core protocol logic.
// VpnManager implementation — core protocol logic.
impl VpnManager {
    /// Create a new VPN manager with default config.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            config: VpnConfig::default(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            state: VpnState::Inactive,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
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
    // Perform the 'set mode' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'set mode' operation.
    // Errors are propagated to the caller via Result.
    pub fn set_mode(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        mode: RoutingMode,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        threat: ThreatContext,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        has_policy_rules: bool,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> Result<(), &'static str> {
        // In Critical threat context, only Off and MeshOnly are allowed.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if threat == ThreatContext::Critical
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            && !matches!(mode, RoutingMode::Off | RoutingMode::MeshOnly)
        {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err("ExitNode and PolicyBased modes unavailable in Critical threat context");
        }

        // ExitNode requires a selected exit node.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if mode == RoutingMode::ExitNode && self.config.exit_peer_id.is_none() {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err("ExitNode mode requires selecting an exit node first");
        }

        // PolicyBased requires at least one App Connector rule.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if mode == RoutingMode::PolicyBased && !has_policy_rules {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err("PolicyBased mode requires at least one routing rule");
        }

        // Apply the mode change.
        // Execute this protocol step.
        // Execute this protocol step.
        self.config.mode = mode;

        // Update operating state.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match mode {
            // Begin the block scope.
            // Handle RoutingMode::Off.
            // Handle RoutingMode::Off.
            RoutingMode::Off => {
                // Update the state to reflect the new state.
                // Advance state state.
                // Advance state state.
                self.state = VpnState::Inactive;
            }
            // Begin the block scope.
            // Handle RoutingMode::MeshOnly.
            // Handle RoutingMode::MeshOnly.
            RoutingMode::MeshOnly => {
                // Update the state to reflect the new state.
                // Advance state state.
                // Advance state state.
                self.state = VpnState::Active;
            }
            // Begin the block scope.
            // Handle RoutingMode::ExitNode.
            // Handle RoutingMode::ExitNode.
            RoutingMode::ExitNode => {
                // Update the state to reflect the new state.
                // Advance state state.
                // Advance state state.
                self.state = VpnState::Connecting;
            }
            // Begin the block scope.
            // Handle RoutingMode::PolicyBased.
            // Handle RoutingMode::PolicyBased.
            RoutingMode::PolicyBased => {
                // Update the state to reflect the new state.
                // Advance state state.
                // Advance state state.
                self.state = VpnState::Active;
            }
        }

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }

    /// Handle exit node disconnect.
    ///
    /// Called when the exit node becomes unreachable.
    /// Engages the kill switch based on the configured mode.
    // Perform the 'on exit disconnected' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'on exit disconnected' operation.
    // Errors are propagated to the caller via Result.
    pub fn on_exit_disconnected(&mut self) {
        // Update the exit reachable to reflect the new state.
        // Advance exit reachable state.
        // Advance exit reachable state.
        self.exit_reachable = false;

        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.config.mode == RoutingMode::ExitNode {
            // Update the state to reflect the new state.
            // Advance state state.
            // Advance state state.
            self.state = VpnState::KillSwitchEngaged;
        }
    }

    /// Handle exit node reconnect.
    // Perform the 'on exit reconnected' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'on exit reconnected' operation.
    // Errors are propagated to the caller via Result.
    pub fn on_exit_reconnected(&mut self) {
        // Update the exit reachable to reflect the new state.
        // Advance exit reachable state.
        // Advance exit reachable state.
        self.exit_reachable = true;

        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.state == VpnState::KillSwitchEngaged {
            // Update the state to reflect the new state.
            // Advance state state.
            // Advance state state.
            self.state = VpnState::Active;
        }
    }

    /// Whether internet traffic is currently allowed.
    ///
    /// In Strict kill switch mode, traffic is blocked when the
    /// kill switch is engaged. In Permissive mode, it falls back
    /// to direct.
    // Perform the 'internet traffic allowed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'internet traffic allowed' operation.
    // Errors are propagated to the caller via Result.
    pub fn internet_traffic_allowed(&self) -> bool {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self.state {
            // Handle this match arm.
            VpnState::Inactive => true, // No VPN, direct traffic.
            // Handle this match arm.
            VpnState::Active => true,
            // Handle this match arm.
            VpnState::Connecting => false, // Wait for connection.
            // Handle this match arm.
            VpnState::Disconnecting => false,
            // Begin the block scope.
            // Handle VpnState::KillSwitchEngaged.
            // Handle VpnState::KillSwitchEngaged.
            VpnState::KillSwitchEngaged => {
                // Strict: blocked. Permissive: falls back to direct.
                // Execute this protocol step.
                // Execute this protocol step.
                self.config.kill_switch == KillSwitchMode::Permissive
            }
        }
    }

    /// Whether traffic should be routed through the exit node.
    // Perform the 'should route through exit' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'should route through exit' operation.
    // Errors are propagated to the caller via Result.
    pub fn should_route_through_exit(&self) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.config.mode == RoutingMode::ExitNode
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            && self.state == VpnState::Active
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            && self.exit_reachable
    }
}

// Trait implementation for protocol conformance.
// Implement Default for VpnManager.
// Implement Default for VpnManager.
impl Default for VpnManager {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
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
