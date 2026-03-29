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
    pub service_type: HostedServiceType,
    pub description: Option<String>,
}

/// Darknet entry capabilities (Tor bridge, I2P, etc.).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DarknetEntry {
    pub tor_bridge: bool,
    pub i2p_router: bool,
    pub yggdrasil: bool,
    pub mixnet: bool,
    pub gnunet: bool,
    pub anonet: bool,
    pub dn42: bool,
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
pub struct ExitNodeAdvertisement {
    /// The exit node's peer ID.
    pub peer_id: [u8; 32],
    /// What this node can do.
    pub capabilities: ExitCapabilities,
    /// Network profiles offered.
    pub network_profiles: Vec<NetworkProfile>,
}

/// A network profile offered by an exit node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkProfile {
    pub profile_id: [u8; 16],
    pub name: String,
    pub description: Option<String>,
    pub exit_type: ConditionalExitType,
    /// Whether this profile is mandatory (always applied).
    pub mandatory: bool,
}

// ---------------------------------------------------------------------------
// Tier Classification (§13.2)
// ---------------------------------------------------------------------------

/// Client-side risk classification for exit nodes.
/// Never transmitted — computed locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExitTier {
    /// Named services/domains only. Low risk.
    Tier1 = 1,
    /// Darknet entry. Low-medium risk.
    Tier2 = 2,
    /// Conditional non-clearnet exit. Medium risk.
    Tier3 = 3,
    /// Unconditional clearnet routing. High risk.
    Tier4 = 4,
}

/// Classify an exit node into its highest applicable tier.
pub fn classify_exit_tier(caps: &ExitCapabilities) -> ExitTier {
    if caps.clearnet_exit {
        return ExitTier::Tier4;
    }
    if !caps.conditional_exit.is_empty() {
        return ExitTier::Tier3;
    }
    if caps.darknet_entry.has_any() {
        return ExitTier::Tier2;
    }
    ExitTier::Tier1
}

impl DarknetEntry {
    /// Whether any darknet entry capability is present.
    pub fn has_any(&self) -> bool {
        self.tor_bridge
            || self.i2p_router
            || self.yggdrasil
            || self.mixnet
            || self.gnunet
            || self.anonet
            || self.dn42
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
            darknet_entry: DarknetEntry { tor_bridge: true, ..Default::default() },
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
        assert!(DarknetEntry { tor_bridge: true, ..Default::default() }.has_any());
    }
}
