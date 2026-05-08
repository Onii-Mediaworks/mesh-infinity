//! Mesh Port Space (§12.1)
//!
//! # Port Addressing
//!
//! Mesh Infinity uses a 32-bit port space:
//! - Bit 31 clear (0x00000000–0x7FFFFFFF): addressed/service ports
//! - Bit 31 set (0x80000000–0xFFFFFFFF): ephemeral/connection-tracking
//!
//! # Port Ranges
//!
//! | Range | Purpose |
//! |-------|---------|
//! | 0–65535 | IANA-compatible |
//! | 65536–66999 | Reserved critical zone (honeypot) |
//! | 67000–133999 | Mesh Infinity native service blocks |
//! | 134000–2,147,483,647 | Free application/operator space |

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Port Range Constants
// ---------------------------------------------------------------------------

/// Start of IANA-compatible range.
// IANA_START — protocol constant.
// Defined by the spec; must not change without a version bump.
// IANA_START — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const IANA_START: u32 = 0;
/// End of IANA-compatible range (inclusive).
// IANA_END — protocol constant.
// Defined by the spec; must not change without a version bump.
// IANA_END — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const IANA_END: u32 = 65_535;

/// Start of reserved critical zone (honeypot).
// CRITICAL_ZONE_START — protocol constant.
// Defined by the spec; must not change without a version bump.
// CRITICAL_ZONE_START — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const CRITICAL_ZONE_START: u32 = 65_536;
/// End of reserved critical zone (inclusive).
// CRITICAL_ZONE_END — protocol constant.
// Defined by the spec; must not change without a version bump.
// CRITICAL_ZONE_END — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const CRITICAL_ZONE_END: u32 = 66_999;

/// Start of native service blocks.
// NATIVE_START — protocol constant.
// Defined by the spec; must not change without a version bump.
// NATIVE_START — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const NATIVE_START: u32 = 67_000;
/// End of native service blocks (inclusive).
// NATIVE_END — protocol constant.
// Defined by the spec; must not change without a version bump.
// NATIVE_END — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const NATIVE_END: u32 = 133_999;

/// Start of free application space.
// APP_SPACE_START — protocol constant.
// Defined by the spec; must not change without a version bump.
// APP_SPACE_START — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const APP_SPACE_START: u32 = 134_000;

/// Ephemeral port bit (bit 31).
// EPHEMERAL_BIT — protocol constant.
// Defined by the spec; must not change without a version bump.
// EPHEMERAL_BIT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const EPHEMERAL_BIT: u32 = 0x80000000;

// ---------------------------------------------------------------------------
// Native Service Port Blocks (§12.1.1)
// ---------------------------------------------------------------------------

/// Well-known native service port blocks.
///
/// Each block is 1000 ports assigned to a specific first-party service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// NativeService — variant enumeration.
// Match exhaustively to handle every protocol state.
// NativeService — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum NativeService {
    Garden,
    Infinet,
    Relay,
    NodeManagement,
    Chat,
    AgenticDistribution,
    Mnrdp,
    Mnsp,
    Mnfp,
    ApiGateway,
    ScreenShare,
    ClipboardSync,
    PrintServices,
}

// NativeService implementation — core protocol logic.
// NativeService implementation — core protocol logic.
impl NativeService {
    /// Get the port range for this native service.
    pub fn port_range(self) -> (u32, u32) {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            Self::Garden => (67_000, 67_999),
            Self::Infinet => (68_000, 68_999),
            Self::Relay => (69_000, 69_999),
            Self::NodeManagement => (70_000, 70_999),
            Self::Chat => (71_000, 71_999),
            Self::AgenticDistribution => (72_000, 72_999),
            Self::Mnrdp => (73_000, 73_999),
            Self::Mnsp => (74_000, 74_999),
            Self::Mnfp => (75_000, 75_999),
            Self::ApiGateway => (76_000, 76_999),
            Self::ScreenShare => (77_000, 77_999),
            Self::ClipboardSync => (78_000, 78_999),
            Self::PrintServices => (79_000, 79_999),
        }
    }

    /// Get the base port for this native service.
    pub fn base_port(self) -> u32 {
        // Delegate to the instance method.
        self.port_range().0
    }
}

/// Classify a port number into its range category.
pub fn classify_port(port: u32) -> PortClass {
    if port & EPHEMERAL_BIT != 0 {
        PortClass::Ephemeral
    // Bounds check to enforce protocol constraints.
    } else if port <= IANA_END {
        // Execute this step in the protocol sequence.
        PortClass::Iana
    // Bounds check to enforce protocol constraints.
    } else if port <= CRITICAL_ZONE_END {
        PortClass::CriticalZone
    // Bounds check to enforce protocol constraints.
    } else if port <= NATIVE_END {
        PortClass::NativeService
    } else {
        PortClass::Application
    }
}

/// Classification of a port number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// PortClass — variant enumeration.
// Match exhaustively to handle every protocol state.
// PortClass — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PortClass {
    /// IANA-compatible (0–65535).
    Iana,
    /// Reserved critical zone / honeypot (65536–66999).
    CriticalZone,
    /// Mesh Infinity native service (67000–133999).
    NativeService,
    /// Free application/operator space (134000+).
    Application,
    /// Ephemeral/connection-tracking (bit 31 set).
    Ephemeral,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_classification() {
        assert_eq!(classify_port(80), PortClass::Iana);
        assert_eq!(classify_port(443), PortClass::Iana);
        assert_eq!(classify_port(66_000), PortClass::CriticalZone);
        assert_eq!(classify_port(67_000), PortClass::NativeService);
        assert_eq!(classify_port(200_000), PortClass::Application);
        assert_eq!(classify_port(EPHEMERAL_BIT | 1), PortClass::Ephemeral);
    }

    #[test]
    fn test_native_service_ranges() {
        let (start, end) = NativeService::Garden.port_range();
        assert_eq!(start, 67_000);
        assert_eq!(end, 67_999);

        let (start, end) = NativeService::Chat.port_range();
        assert_eq!(start, 71_000);
        assert_eq!(end, 71_999);
    }
}
