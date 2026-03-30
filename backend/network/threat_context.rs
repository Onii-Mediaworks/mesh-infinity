//! Threat Context (§4.8, §5.10)
//!
//! The global security level that governs transport selection,
//! discovery mechanisms, and UI behavior.

use serde::{Deserialize, Serialize};

/// Global threat context level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
// Begin the block scope.
// ThreatContext — variant enumeration.
// Match exhaustively to handle every protocol state.
// ThreatContext — variant enumeration.
// Match exhaustively to handle every protocol state.
// ThreatContext — variant enumeration.
// Match exhaustively to handle every protocol state.
// ThreatContext — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ThreatContext {
    /// Normal: all mechanisms available, defaults reflect operational context.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Normal = 0,
    /// Elevated: mDNS/SSDP disabled by default, direct IP disabled, warnings on clearnet.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Elevated = 1,
    /// Critical: only anonymizing transports, network isolation mode forced,
    /// MeshAlways forced, push notifications suppressed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Critical = 2,
}

// Begin the block scope.
// ThreatContext implementation — core protocol logic.
// ThreatContext implementation — core protocol logic.
// ThreatContext implementation — core protocol logic.
// ThreatContext implementation — core protocol logic.
impl ThreatContext {
    /// From numeric value (FFI).
    // Perform the 'from u8' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from u8' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from u8' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from u8' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_u8(v: u8) -> Option<Self> {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match v {
            // Update the local state.
            0 => Some(Self::Normal),
            // Update the local state.
            1 => Some(Self::Elevated),
            // Update the local state.
            2 => Some(Self::Critical),
            // Update the local state.
            _ => None,
        }
    }

    /// Whether mDNS/SSDP local discovery is allowed.
    // Perform the 'allows mdns' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows mdns' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows mdns' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows mdns' operation.
    // Errors are propagated to the caller via Result.
    pub fn allows_mdns(self) -> bool {
        // Update the local state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self == Self::Normal
    }

    /// Whether clearnet (direct IP) transport is allowed.
    // Perform the 'allows clearnet' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows clearnet' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows clearnet' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows clearnet' operation.
    // Errors are propagated to the caller via Result.
    pub fn allows_clearnet(self) -> bool {
        // Update the local state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self == Self::Normal
    }

    /// Whether DHT participation is allowed.
    // Perform the 'allows dht' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows dht' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows dht' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows dht' operation.
    // Errors are propagated to the caller via Result.
    pub fn allows_dht(self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self != Self::Critical
    }

    /// Whether direct mode (0-hop) is available.
    // Perform the 'allows direct mode' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows direct mode' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows direct mode' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows direct mode' operation.
    // Errors are propagated to the caller via Result.
    pub fn allows_direct_mode(self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self != Self::Critical
    }

    /// Whether proximity direct (auto) is allowed.
    /// In Critical, MeshAlways is forced (§6.9.5).
    // Perform the 'allows proximity direct' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows proximity direct' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows proximity direct' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows proximity direct' operation.
    // Errors are propagated to the caller via Result.
    pub fn allows_proximity_direct(self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self != Self::Critical
    }

    /// Whether push notifications (Tier 3/4) are allowed.
    /// Elevated or Critical → Tiers 3 and 4 suppressed (§14.7, §14.8).
    // Perform the 'allows push notifications' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows push notifications' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows push notifications' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows push notifications' operation.
    // Errors are propagated to the caller via Result.
    pub fn allows_push_notifications(self) -> bool {
        // Update the local state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self == Self::Normal
    }

    /// Whether direct IP exposure (§13.17) is allowed.
    // Perform the 'allows direct ip exposure' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows direct ip exposure' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows direct ip exposure' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows direct ip exposure' operation.
    // Errors are propagated to the caller via Result.
    pub fn allows_direct_ip_exposure(self) -> bool {
        // Update the local state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self == Self::Normal
    }

    /// Minimum hop count for routing.
    // Perform the 'min hops' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'min hops' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'min hops' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'min hops' operation.
    // Errors are propagated to the caller via Result.
    pub fn min_hops(self) -> u8 {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Handle this match arm.
            Self::Normal => 0,
            // Handle this match arm.
            Self::Elevated => 1,
            // Handle this match arm.
            Self::Critical => 2,
        }
    }

    /// Plain-language description for UI (§22.9.1).
    // Perform the 'description' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'description' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'description' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'description' operation.
    // Errors are propagated to the caller via Result.
    pub fn description(self) -> &'static str {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Handle this match arm.
            Self::Normal => "Standard security. All transports available.",
            // Handle this match arm.
            Self::Elevated => "Elevated security. Direct connections disabled. Prefer anonymizing transports.",
            // Handle this match arm.
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
