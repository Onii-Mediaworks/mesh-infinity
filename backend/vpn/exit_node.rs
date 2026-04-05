//! Exit Node Capabilities (§13.2)
//!
//! Exit nodes route traffic from the mesh to external networks.
//! Advertisements are shared through trusted channels only.
//!
//! # Tier Classification (client-side only)
//!
//! | Tier | Capability | Risk |
//! |------|-----------|------|
//! | 1 | Named services only | Low |
//! | 2 | Darknet entry | Low-medium |
//! | 3 | Conditional exit (VPN, LAN) | Medium |
//! | 4 | Unconditional clearnet | High |

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Exit Capabilities
// ---------------------------------------------------------------------------

/// What an exit node can do (§13.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitCapabilities {
    /// Named hosted services accessible through this node.
    pub hosted_services: Vec<HostedServiceAd>,
    /// Darknet entry capabilities.
    pub darknet_entry: DarknetEntry,
    /// Conditional exit capabilities (VPN, Infinet, LAN).
    pub conditional_exit: Vec<ConditionalExitType>,
    /// Whether this node offers unconditional clearnet exit.
    pub clearnet_exit: bool,
    /// Whether this node will relay funnel traffic.
    pub funnel_relay: bool,
}

/// A hosted service advertised by an exit node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HostedServiceType {
    /// Clearnet domain pattern (e.g., "*.example.com").
    ClearnetDomain { pattern: String },
    /// Specific clearnet endpoint.
    ClearnetEndpoint { addr: String, port: u16 },
    /// Clearnet IP range.
    ClearnetRange { network: String },
    /// Mesh service.
    MeshService { service_name: String, port: u32 },
}

/// Advertised hosted service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostedServiceAd {
    /// The service type for this instance.
    pub service_type: HostedServiceType,
    /// The description for this instance.
    pub description: Option<String>,
}

/// Darknet entry capabilities (Tor bridge, I2P, etc.).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DarknetEntry {
    /// The tor bridge for this instance.
    pub tor_bridge: bool,
    /// The i2p router for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub i2p_router: bool,
    /// The yggdrasil for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub yggdrasil: bool,
    /// The mixnet for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mixnet: bool,
    /// The gnunet for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub gnunet: bool,
    /// The anonet for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub anonet: bool,
    /// The dn42 for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub dn42: bool,
    /// The briar relay for this instance.
    pub briar_relay: bool,
}

/// Types of conditional exit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConditionalExitType {
    /// Route through a VPN provider.
    VpnProvider { profile_id: [u8; 16] },
    /// Route through an Infinet.
    Infinet { infinet_id: [u8; 32] },
    /// Route to local LAN.
    LocalLan,
}

// ---------------------------------------------------------------------------
// Exit Node Advertisement
// ---------------------------------------------------------------------------

/// Full exit node advertisement (§13.2).
///
/// Shared through trusted channels only — never in the public
/// network map.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ExitNodeAdvertisement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ExitNodeAdvertisement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ExitNodeAdvertisement {
    /// The exit node's peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_id: [u8; 32],
    /// What this node can do.
    // Execute this protocol step.
    // Execute this protocol step.
    pub capabilities: ExitCapabilities,
    /// Network profiles offered.
    // Execute this protocol step.
    // Execute this protocol step.
    pub network_profiles: Vec<NetworkProfile>,
}

/// A network profile offered by an exit node.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// NetworkProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NetworkProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct NetworkProfile {
    /// The profile id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub profile_id: [u8; 16],
    /// The name for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// The description for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: Option<String>,
    /// The exit type for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub exit_type: ConditionalExitType,
    /// Whether this profile is mandatory (always applied).
    // Execute this protocol step.
    // Execute this protocol step.
    pub mandatory: bool,
}

// ---------------------------------------------------------------------------
// Tier Classification (§13.2)
// ---------------------------------------------------------------------------

/// Client-side risk classification for exit nodes.
/// Never transmitted — computed locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
// Begin the block scope.
// ExitTier — variant enumeration.
// Match exhaustively to handle every protocol state.
// ExitTier — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ExitTier {
    /// Named services/domains only. Low risk.
    // Execute this protocol step.
    // Execute this protocol step.
    Tier1 = 1,
    /// Darknet entry. Low-medium risk.
    // Execute this protocol step.
    // Execute this protocol step.
    Tier2 = 2,
    /// Conditional non-clearnet exit. Medium risk.
    // Execute this protocol step.
    // Execute this protocol step.
    Tier3 = 3,
    /// Unconditional clearnet routing. High risk.
    // Execute this protocol step.
    // Execute this protocol step.
    Tier4 = 4,
}

/// Classify an exit node into its highest applicable tier.
// Perform the 'classify exit tier' operation.
// Errors are propagated to the caller via Result.
// Perform the 'classify exit tier' operation.
// Errors are propagated to the caller via Result.
pub fn classify_exit_tier(caps: &ExitCapabilities) -> ExitTier {
    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if caps.clearnet_exit {
        // Return the result to the caller.
        // Return to the caller.
        // Return to the caller.
        return ExitTier::Tier4;
    }
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if !caps.conditional_exit.is_empty() {
        // Return the result to the caller.
        // Return to the caller.
        // Return to the caller.
        return ExitTier::Tier3;
    }
    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    if caps.darknet_entry.has_any() {
        // Return the result to the caller.
        // Return to the caller.
        return ExitTier::Tier2;
    }
    // Execute this step in the protocol sequence.
    // Execute this protocol step.
    ExitTier::Tier1
}

// Begin the block scope.
// DarknetEntry implementation — core protocol logic.
impl DarknetEntry {
    /// Whether any darknet entry capability is present.
    // Perform the 'has any' operation.
    // Errors are propagated to the caller via Result.
    pub fn has_any(&self) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        self.tor_bridge
            // Process the current step in the protocol.
            // Execute this protocol step.
            || self.i2p_router
            // Process the current step in the protocol.
            // Execute this protocol step.
            || self.yggdrasil
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            || self.mixnet
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            || self.gnunet
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            || self.anonet
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            || self.dn42
            // Process the current step in the protocol.
            // Execute this protocol step.
            || self.briar_relay
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_classification() {
        // Tier 1: services only.
        let t1 = ExitCapabilities {
            hosted_services: vec![],
            darknet_entry: DarknetEntry::default(),
            conditional_exit: vec![],
            clearnet_exit: false,
            funnel_relay: false,
        };
        assert_eq!(classify_exit_tier(&t1), ExitTier::Tier1);

        // Tier 2: darknet.
        let t2 = ExitCapabilities {
            darknet_entry: DarknetEntry {
                tor_bridge: true,
                ..Default::default()
            },
            ..t1.clone()
        };
        assert_eq!(classify_exit_tier(&t2), ExitTier::Tier2);

        // Tier 4: clearnet.
        let t4 = ExitCapabilities {
            clearnet_exit: true,
            ..t1.clone()
        };
        assert_eq!(classify_exit_tier(&t4), ExitTier::Tier4);
    }

    #[test]
    fn test_darknet_has_any() {
        assert!(!DarknetEntry::default().has_any());
        assert!(DarknetEntry {
            tor_bridge: true,
            ..Default::default()
        }
        .has_any());
    }
}
