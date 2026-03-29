//! Threat Context (§4.8, §5.10)
//!
//! The global security level that governs transport selection,
//! discovery mechanisms, and UI behavior.

use serde::{Deserialize, Serialize};

/// Global threat context level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ThreatContext {
    /// Normal: all mechanisms available, defaults reflect operational context.
    Normal = 0,
    /// Elevated: mDNS/SSDP disabled by default, direct IP disabled, warnings on clearnet.
    Elevated = 1,
    /// Critical: only anonymizing transports, network isolation mode forced,
    /// MeshAlways forced, push notifications suppressed.
    Critical = 2,
}

impl ThreatContext {
    /// From numeric value (FFI).
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Normal),
            1 => Some(Self::Elevated),
            2 => Some(Self::Critical),
            _ => None,
        }
    }

    /// Whether mDNS/SSDP local discovery is allowed.
    pub fn allows_mdns(self) -> bool {
        self == Self::Normal
    }

    /// Whether clearnet (direct IP) transport is allowed.
    pub fn allows_clearnet(self) -> bool {
        self == Self::Normal
    }

    /// Whether DHT participation is allowed.
    pub fn allows_dht(self) -> bool {
        self != Self::Critical
    }

    /// Whether direct mode (0-hop) is available.
    pub fn allows_direct_mode(self) -> bool {
        self != Self::Critical
    }

    /// Whether proximity direct (auto) is allowed.
    /// In Critical, MeshAlways is forced (§6.9.5).
    pub fn allows_proximity_direct(self) -> bool {
        self != Self::Critical
    }

    /// Whether push notifications (Tier 3/4) are allowed.
    /// Elevated or Critical → Tiers 3 and 4 suppressed (§14.7, §14.8).
    pub fn allows_push_notifications(self) -> bool {
        self == Self::Normal
    }

    /// Whether direct IP exposure (§13.17) is allowed.
    pub fn allows_direct_ip_exposure(self) -> bool {
        self == Self::Normal
    }

    /// Minimum hop count for routing.
    pub fn min_hops(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Elevated => 1,
            Self::Critical => 2,
        }
    }

    /// Plain-language description for UI (§22.9.1).
    pub fn description(self) -> &'static str {
        match self {
            Self::Normal => "Standard security. All transports available.",
            Self::Elevated => "Elevated security. Direct connections disabled. Prefer anonymizing transports.",
            Self::Critical => "Maximum security. Only anonymizing transports. Network isolation active.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering() {
        assert!(ThreatContext::Normal < ThreatContext::Elevated);
        assert!(ThreatContext::Elevated < ThreatContext::Critical);
    }

    #[test]
    fn test_normal_allows_everything() {
        let tc = ThreatContext::Normal;
        assert!(tc.allows_mdns());
        assert!(tc.allows_clearnet());
        assert!(tc.allows_dht());
        assert!(tc.allows_direct_mode());
        assert!(tc.allows_proximity_direct());
        assert!(tc.allows_push_notifications());
        assert!(tc.allows_direct_ip_exposure());
    }

    #[test]
    fn test_critical_restricts_everything() {
        let tc = ThreatContext::Critical;
        assert!(!tc.allows_mdns());
        assert!(!tc.allows_clearnet());
        assert!(!tc.allows_dht());
        assert!(!tc.allows_direct_mode());
        assert!(!tc.allows_proximity_direct());
        assert!(!tc.allows_push_notifications());
        assert!(!tc.allows_direct_ip_exposure());
    }

    #[test]
    fn test_min_hops() {
        assert_eq!(ThreatContext::Normal.min_hops(), 0);
        assert_eq!(ThreatContext::Elevated.min_hops(), 1);
        assert_eq!(ThreatContext::Critical.min_hops(), 2);
    }

    #[test]
    fn test_from_u8() {
        assert_eq!(ThreatContext::from_u8(0), Some(ThreatContext::Normal));
        assert_eq!(ThreatContext::from_u8(2), Some(ThreatContext::Critical));
        assert_eq!(ThreatContext::from_u8(3), None);
    }

    #[test]
    fn test_serde_roundtrip() {
        let tc = ThreatContext::Elevated;
        let json = serde_json::to_string(&tc).unwrap();
        let recovered: ThreatContext = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, recovered);
    }
}
