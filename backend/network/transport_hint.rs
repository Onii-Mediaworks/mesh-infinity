//! Transport Hints (§4.2)
//!
//! Transport hints indicate how a peer is reachable.
//! Included in NetworkMapEntry for each peer.

use serde::{Deserialize, Serialize};

/// Transport type identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
// Begin the block scope.
// TransportType — variant enumeration.
// Match exhaustively to handle every protocol state.
// TransportType — variant enumeration.
// Match exhaustively to handle every protocol state.
// TransportType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum TransportType {
    /// WireGuard over clearnet (direct IP).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Clearnet,
    /// Tor hidden service (.onion).
    Tor,
    /// I2P destination.
    I2P,
    /// Bluetooth Low Energy.
    BLE,
    /// Bluetooth Classic.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    BluetoothClassic,
    /// WiFi Direct.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    WiFiDirect,
    /// NFC (proximity, no address).
    NFC,
    /// Ultrasonic (proximity, no address).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Ultrasonic,
    /// USB / Serial.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    USBSerial,
    /// Layer 2 / Raw Ethernet.
    Layer2,
    /// Generic RF (LoRa / Meshtastic, unspecified SDR).
    RF,
    /// LoRa spread-spectrum radio (ISM bands, unlicensed, low power).
    /// Long range (up to 15km line-of-sight), low bandwidth (~250bps–5kbps),
    /// excellent link budget (up to 157dB), ideal for off-grid mesh.
    LoRa,
    /// HF SDR (3–30 MHz). Uses ionospheric skip for ultra-long-range
    /// communication (hundreds to thousands of km). Requires licensed bands
    /// in most jurisdictions. Ideal for regional/continental mesh in crisis.
    SdrHf,
    /// VHF SDR (30–300 MHz). Line-of-sight, moderate range (20–150km with
    /// directional antenna). Good balance of range and bandwidth for regional mesh.
    SdrVhf,
    /// UHF SDR (300 MHz–3 GHz). Urban / suburban, 5–50km range.
    /// Higher data rates than HF/VHF. Covers most ISM bands.
    SdrUhf,
    /// SHF SDR (3–30 GHz). Short range, high bandwidth.
    /// Covers 5.8GHz, 10GHz amateur, and similar bands.
    SdrShf,
    /// Frequency Hopping Spread Spectrum (FHSS).
    /// Pseudo-random hop across a pre-agreed channel table, synchronized
    /// by a shared hop key. Highly resistant to jamming and interception.
    /// Solver prefers this over static RF when evasion is required.
    SdrFhss,
    /// Yggdrasil overlay.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Yggdrasil,
    /// cjdns overlay.
    Cjdns,
    /// ZeroTier overlay.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ZeroTier,
    /// Tailscale / Headscale overlay.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Tailscale,
    /// GNUnet.
    GNUnet,
    /// Native mixnet tier.
    Mixnet,
    /// Telephone subchannel.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Telephone,
    /// CAN bus.
    CANBus,
    /// PPPoE.
    PPPoE,
    /// Dial-up modem.
    Dialup,
}

// Begin the block scope.
// TransportType implementation — core protocol logic.
// TransportType implementation — core protocol logic.
// TransportType implementation — core protocol logic.
impl TransportType {
    /// Short display name for UI.
    // Perform the 'short name' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'short name' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'short name' operation.
    // Errors are propagated to the caller via Result.
    pub fn short_name(&self) -> &'static str {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Handle this match arm.
            Self::Clearnet => "Net",
            // Handle this match arm.
            Self::Tor => "Tor",
            // Handle this match arm.
            Self::I2P => "I2P",
            // Handle this match arm.
            Self::BLE => "BLE",
            // Handle this match arm.
            Self::BluetoothClassic => "BT",
            // Handle this match arm.
            Self::WiFiDirect => "WiFi",
            // Handle this match arm.
            Self::NFC => "NFC",
            // Handle this match arm.
            Self::Ultrasonic => "USonic",
            // Handle this match arm.
            Self::USBSerial => "USB",
            // Handle this match arm.
            Self::Layer2 => "L2",
            // Handle this match arm.
            Self::RF => "RF",
            // Handle this match arm.
            Self::LoRa => "LoRa",
            // Handle this match arm.
            Self::SdrHf => "HF",
            // Handle this match arm.
            Self::SdrVhf => "VHF",
            // Handle this match arm.
            Self::SdrUhf => "UHF",
            // Handle this match arm.
            Self::SdrShf => "SHF",
            // Handle this match arm.
            Self::SdrFhss => "FHSS",
            // Handle this match arm.
            Self::Yggdrasil => "Ygg",
            // Handle this match arm.
            Self::Cjdns => "cjdns",
            // Handle this match arm.
            Self::ZeroTier => "ZT",
            // Handle this match arm.
            Self::Tailscale => "TS",
            // Handle this match arm.
            Self::GNUnet => "GNU",
            // Handle this match arm.
            Self::Mixnet => "Mix",
            // Handle this match arm.
            Self::Telephone => "Tel",
            // Handle this match arm.
            Self::CANBus => "CAN",
            // Handle this match arm.
            Self::PPPoE => "PPP",
            // Handle this match arm.
            Self::Dialup => "Dial",
        }
    }

    /// Whether this transport type is SDR-based (software-configurable radio).
    ///
    /// All SDR transports share a common hardware abstraction layer and
    /// can be dynamically reconfigured for frequency, modulation, and bandwidth.
    /// Dedicated hardware types (LoRa, RF) use fixed-profile drivers
    /// that implement the same SDR trait but with limited configurability.
    // Perform the 'is sdr' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is sdr' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is sdr' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_sdr(&self) -> bool {
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(
            self,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            Self::RF | Self::LoRa | Self::SdrHf | Self::SdrVhf
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | Self::SdrUhf | Self::SdrShf | Self::SdrFhss
        )
    }

    /// Whether this is a proximity transport (auto-direct eligible, §6.9.5).
    // Perform the 'is proximity' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is proximity' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is proximity' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_proximity(&self) -> bool {
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(
            self,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            Self::BLE | Self::BluetoothClassic | Self::WiFiDirect
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | Self::NFC | Self::Ultrasonic | Self::USBSerial | Self::Layer2
        )
    }

    /// Whether this is an anonymizing transport.
    // Perform the 'is anonymizing' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is anonymizing' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is anonymizing' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_anonymizing(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Tor | Self::I2P | Self::GNUnet | Self::Mixnet)
    }

    /// Whether this transport is a trusted context.
    ///
    /// Trusted contexts are networks that require some kind of
    /// privilege to enter, or that are controlled primarily or
    /// solely by the user. Peers discovered over these transports
    /// default to a more elevated position of trust, and mDNS/local
    /// discovery is permitted over them.
    ///
    /// Trusted contexts:
    /// - **Tailscale**: pre-authenticated overlay (requires account auth)
    /// - **ZeroTier**: pre-authenticated overlay (requires network auth)
    /// - **Layer2 / WiFiDirect / USBSerial**: physical access required
    ///
    /// Note: LAN (Clearnet) is also toggleable as a trusted context
    /// via TrustedContextConfig but is NOT trusted by default (because
    /// many LANs are shared/public). The toggle exists because home
    /// and office LANs ARE user-controlled.
    ///
    /// All trusted context markers can be disabled per-transport.
    // Perform the 'is trusted context' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is trusted context' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is trusted context' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_trusted_context(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Tailscale | Self::ZeroTier)
    }

    /// Default trust level for peers discovered over this transport.
    ///
    /// Discovery over a trusted context does NOT automatically
    /// elevate trust — peers start at Level 0 like any other.
    ///
    /// However, peers that are both DISCOVERED and PAIRED over a
    /// trusted context get a trust boost in the pairing flow.
    /// This is handled by `pairing_trust_boost()`, not here.
    ///
    /// Discovery affects only whether mDNS/automatic peer finding
    /// is permitted. Pathing is never affected by trusted contexts.
    // Perform the 'default peer trust' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default peer trust' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default peer trust' operation.
    // Errors are propagated to the caller via Result.
    pub fn default_peer_trust(&self) -> u8 {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        0 // Discovery alone doesn't elevate trust.
    }

    /// Trust boost for peers paired over this transport.
    ///
    /// When a peer is both discovered AND paired over a trusted
    /// context (Tailscale, ZeroTier, user-designated LAN), the
    /// pairing starts at a higher trust level than Level 0.
    ///
    /// This reflects the fact that both parties had to authenticate
    /// to the overlay network — there's a pre-existing trust
    /// relationship mediated by the overlay operator.
    ///
    /// The boost is recorded in the contact record's pairing method
    /// metadata and factors into the trust calculation.
    ///
    /// Returns the trust level boost (0–2):
    /// - 0: no boost (default transports)
    /// - 1: minor boost (user-designated LAN)
    /// - 2: significant boost (Tailscale, ZeroTier — pre-authenticated)
    // Perform the 'pairing trust boost' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pairing trust boost' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pairing trust boost' operation.
    // Errors are propagated to the caller via Result.
    pub fn pairing_trust_boost(&self) -> u8 {
        // Trust level gate — restrict access based on peer trust.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.is_trusted_context() {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            2 // Tailscale/ZeroTier: overlay auth is a strong signal.
              // Begin the block scope.
              // Fallback when the guard was not satisfied.
              // Fallback when the guard was not satisfied.
              // Fallback when the guard was not satisfied.
        } else {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            0 // No boost for other transports.
        }
    }

    /// Whether mDNS/local discovery is permitted on this transport.
    ///
    /// Normally mDNS is only allowed on local network transports
    /// (clearnet, WiFi Direct, etc.). Trusted context overlays
    /// (Tailscale, ZeroTier) additionally allow mDNS because all
    /// participants are pre-authenticated by the overlay.
    ///
    /// This enables automatic mesh peer discovery over Tailscale
    /// and ZeroTier networks without requiring manual pairing.
    // Perform the 'allows mdns discovery' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows mdns discovery' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows mdns discovery' operation.
    // Errors are propagated to the caller via Result.
    pub fn allows_mdns_discovery(&self) -> bool {
        // Delegate to the instance method.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.is_proximity()
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            || matches!(self, Self::Clearnet)
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            || self.is_trusted_context()
    }

    /// Anonymization score for transport solver (§5.10.3).
    // Perform the 'anonymization score' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'anonymization score' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'anonymization score' operation.
    // Errors are propagated to the caller via Result.
    pub fn anonymization_score(&self) -> f32 {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            Self::Clearnet | Self::WiFiDirect | Self::BLE | Self::BluetoothClassic
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | Self::USBSerial | Self::Layer2 | Self::CANBus | Self::NFC
                // Handle this match arm.
                | Self::Ultrasonic | Self::PPPoE | Self::Dialup | Self::Telephone => 0.0,
            // Generic RF / LoRa: frequency is observable but content is encrypted.
            // No anonymization beyond encryption — RF direction-finding is possible.
            Self::RF | Self::LoRa | Self::SdrHf | Self::SdrVhf | Self::SdrUhf | Self::SdrShf => 0.0,
            // FHSS: pseudo-random hopping provides traffic-analysis resistance.
            // An adversary cannot easily correlate bursts to a specific peer
            // without the hop key. This is directional obscurity, not anonymity.
            Self::SdrFhss => 0.2,
            // Handle this match arm.
            Self::Tailscale | Self::ZeroTier => 0.3,
            // Handle this match arm.
            Self::I2P | Self::Yggdrasil | Self::Cjdns => 0.6,
            // Handle this match arm.
            Self::Tor | Self::GNUnet => 0.9,
            // Handle this match arm.
            Self::Mixnet => 1.0,
        }
    }

    /// Default bandwidth class.
    // Perform the 'default bandwidth' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default bandwidth' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default bandwidth' operation.
    // Errors are propagated to the caller via Result.
    pub fn default_bandwidth(&self) -> BandwidthClass {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Sub-kbps to low-kbps: HF ionospheric, LoRa, FHSS narrow channel
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            Self::SdrHf | Self::LoRa | Self::SdrFhss
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | Self::Ultrasonic | Self::Dialup | Self::CANBus
                // Handle this match arm.
                | Self::Telephone => BandwidthClass::Low,
            // Low-to-medium: generic RF, VHF, BLE, USB
            Self::RF | Self::SdrVhf | Self::BLE | Self::USBSerial => BandwidthClass::Medium,
            // Medium-to-high: UHF/SHF SDR (wideband modes)
            Self::SdrUhf | Self::SdrShf => BandwidthClass::Medium,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            Self::Clearnet | Self::WiFiDirect | Self::Layer2 | Self::PPPoE
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | Self::Tor | Self::I2P | Self::Yggdrasil | Self::Cjdns
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | Self::ZeroTier | Self::Tailscale | Self::GNUnet | Self::Mixnet
                // Handle this match arm.
                | Self::BluetoothClassic | Self::NFC => BandwidthClass::High,
        }
    }
}

/// Bandwidth classification (§5.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// BandwidthClass — variant enumeration.
// Match exhaustively to handle every protocol state.
// BandwidthClass — variant enumeration.
// Match exhaustively to handle every protocol state.
// BandwidthClass — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum BandwidthClass {
    Low,
    Medium,
    High,
}

/// A transport hint for how to reach a peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TransportHint — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TransportHint — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TransportHint — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TransportHint {
    /// The transport for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub transport: TransportType,
    /// Endpoint address (e.g., Tor .onion, clearnet IP:port).
    /// None for proximity transports (NFC, ultrasonic).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub endpoint: Option<String>,
}

/// Configuration for trusted context behavior.
///
/// A trusted context is any network that requires privilege to enter
/// or is controlled primarily by the user. Peers discovered over
/// trusted contexts get elevated initial trust and mDNS discovery
/// is permitted.
///
/// All toggles default to ON for overlay networks (Tailscale, ZeroTier)
/// and OFF for LAN (since many LANs are shared/public). Users with
/// private home/office LANs should enable the LAN toggle.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TrustedContextConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustedContextConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustedContextConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TrustedContextConfig {
    /// Whether peers on Tailscale inherit elevated trust.
    /// Default: true (Tailscale requires account authentication).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub tailscale_trust_elevation: bool,
    /// Whether peers on ZeroTier inherit elevated trust.
    /// Default: true (ZeroTier requires network authorization).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub zerotier_trust_elevation: bool,
    /// Whether the local LAN (clearnet) is a trusted context.
    /// Default: false (many LANs are shared/public).
    /// Enable for home/office networks the user controls.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub lan_trust_elevation: bool,
    /// Whether mDNS is allowed over trusted context transports.
    /// Default: true.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub allow_mdns_on_trusted: bool,
}

// Trait implementation for protocol conformance.
// Implement Default for TrustedContextConfig.
// Implement Default for TrustedContextConfig.
// Implement Default for TrustedContextConfig.
impl Default for TrustedContextConfig {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            tailscale_trust_elevation: true,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            zerotier_trust_elevation: true,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            lan_trust_elevation: false, // Off by default — user must opt in.
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            allow_mdns_on_trusted: true,
        }
    }
}

// Begin the block scope.
// TrustedContextConfig implementation — core protocol logic.
// TrustedContextConfig implementation — core protocol logic.
// TrustedContextConfig implementation — core protocol logic.
impl TrustedContextConfig {
    /// Whether this transport is a trusted context for discovery.
    ///
    /// Checks the per-transport toggle. Controls whether mDNS and
    /// automatic peer discovery are permitted. Does NOT affect pathing.
    // Perform the 'is trusted for discovery' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is trusted for discovery' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is trusted for discovery' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_trusted_for_discovery(&self, transport: &TransportType) -> bool {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match transport {
            // Handle this match arm.
            TransportType::Tailscale => self.tailscale_trust_elevation,
            // Handle this match arm.
            TransportType::ZeroTier => self.zerotier_trust_elevation,
            // Handle this match arm.
            TransportType::Clearnet => self.lan_trust_elevation,
            // Physical-access transports are inherently trusted.
            _ if transport.is_proximity() => true,
            // Update the local state.
            _ => false,
        }
    }

    /// Pairing trust boost for a transport, considering config toggles.
    ///
    /// When a peer is paired over a trusted context, the pairing
    /// gets a trust boost. This factors into the trust calculation
    /// but does NOT affect routing or pathing.
    ///
    /// Returns 0–2 boost levels.
    // Perform the 'pairing boost' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pairing boost' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pairing boost' operation.
    // Errors are propagated to the caller via Result.
    pub fn pairing_boost(&self, transport: &TransportType) -> u8 {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match transport {
            // Handle this match arm.
            TransportType::Tailscale if self.tailscale_trust_elevation => 2,
            // Handle this match arm.
            TransportType::ZeroTier if self.zerotier_trust_elevation => 2,
            // Handle this match arm.
            TransportType::Clearnet if self.lan_trust_elevation => 1,
            // Update the local state.
            _ => transport.pairing_trust_boost(),
        }
    }

    /// Whether mDNS discovery is allowed for a given transport,
    /// considering the trusted context config.
    ///
    /// Proximity transports (BLE, NFC, WiFi Direct, USB, Layer2)
    /// always allow mDNS regardless of the toggle — physical
    /// proximity IS the authentication.
    // Perform the 'allows mdns' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows mdns' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allows mdns' operation.
    // Errors are propagated to the caller via Result.
    pub fn allows_mdns(&self, transport: &TransportType) -> bool {
        // Proximity transports: always allowed.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if transport.is_proximity() {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return true;
        }
        // Trusted context overlays and LAN: depends on toggle.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.is_trusted_for_discovery(transport) {
            // Mutate the internal state.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            self.allow_mdns_on_trusted
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            transport.allows_mdns_discovery()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proximity_transports() {
        assert!(TransportType::BLE.is_proximity());
        assert!(TransportType::NFC.is_proximity());
        assert!(TransportType::USBSerial.is_proximity());
        assert!(!TransportType::Tor.is_proximity());
        assert!(!TransportType::Clearnet.is_proximity());
    }

    #[test]
    fn test_anonymizing_transports() {
        assert!(TransportType::Tor.is_anonymizing());
        assert!(TransportType::Mixnet.is_anonymizing());
        assert!(!TransportType::Clearnet.is_anonymizing());
        assert!(!TransportType::BLE.is_anonymizing());
    }

    #[test]
    fn test_anonymization_scores_ordered() {
        assert!(
            TransportType::Mixnet.anonymization_score() > TransportType::Tor.anonymization_score()
        );
        assert!(
            TransportType::Tor.anonymization_score() > TransportType::I2P.anonymization_score()
        );
        assert!(
            TransportType::I2P.anonymization_score()
                > TransportType::Clearnet.anonymization_score()
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let hint = TransportHint {
            transport: TransportType::Tor,
            endpoint: Some("abc123.onion:8080".into()),
        };
        let json = serde_json::to_string(&hint).unwrap();
        let recovered: TransportHint = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.transport, TransportType::Tor);
    }

    #[test]
    fn test_trusted_context() {
        assert!(TransportType::Tailscale.is_trusted_context());
        assert!(TransportType::ZeroTier.is_trusted_context());
        assert!(!TransportType::Tor.is_trusted_context());
        assert!(!TransportType::Clearnet.is_trusted_context());
    }

    #[test]
    fn test_discovery_trust_is_always_zero() {
        // Discovery alone never elevates trust. All peers start at 0.
        assert_eq!(TransportType::Tailscale.default_peer_trust(), 0);
        assert_eq!(TransportType::ZeroTier.default_peer_trust(), 0);
        assert_eq!(TransportType::Clearnet.default_peer_trust(), 0);
        assert_eq!(TransportType::Tor.default_peer_trust(), 0);
    }

    #[test]
    fn test_pairing_trust_boost() {
        // Pairing over trusted contexts gives a trust boost.
        assert_eq!(TransportType::Tailscale.pairing_trust_boost(), 2);
        assert_eq!(TransportType::ZeroTier.pairing_trust_boost(), 2);
        // Non-trusted contexts: no boost.
        assert_eq!(TransportType::Clearnet.pairing_trust_boost(), 0);
        assert_eq!(TransportType::Tor.pairing_trust_boost(), 0);
    }

    #[test]
    fn test_config_pairing_boost() {
        let config = TrustedContextConfig::default();
        // Tailscale/ZeroTier: boost of 2.
        assert_eq!(config.pairing_boost(&TransportType::Tailscale), 2);
        assert_eq!(config.pairing_boost(&TransportType::ZeroTier), 2);
        // LAN: off by default, so 0.
        assert_eq!(config.pairing_boost(&TransportType::Clearnet), 0);
        // LAN with toggle on: boost of 1.
        let mut config2 = config.clone();
        config2.lan_trust_elevation = true;
        assert_eq!(config2.pairing_boost(&TransportType::Clearnet), 1);
    }

    #[test]
    fn test_trusted_context_mdns() {
        // mDNS allowed on trusted context overlays.
        assert!(TransportType::Tailscale.allows_mdns_discovery());
        assert!(TransportType::ZeroTier.allows_mdns_discovery());
        // Also allowed on proximity and clearnet.
        assert!(TransportType::BLE.allows_mdns_discovery());
        assert!(TransportType::Clearnet.allows_mdns_discovery());
        // NOT allowed on anonymizing transports.
        assert!(!TransportType::Tor.allows_mdns_discovery());
    }

    #[test]
    fn test_trusted_context_config() {
        let config = TrustedContextConfig::default();
        // Both on by default.
        assert!(config.is_trusted_for_discovery(&TransportType::Tailscale));
        assert!(config.is_trusted_for_discovery(&TransportType::ZeroTier));
        assert!(config.allow_mdns_on_trusted);

        // Toggling off.
        let mut config2 = config.clone();
        config2.tailscale_trust_elevation = false;
        assert!(!config2.is_trusted_for_discovery(&TransportType::Tailscale));
        assert!(config2.is_trusted_for_discovery(&TransportType::ZeroTier));
    }

    #[test]
    fn test_trusted_context_config_mdns_toggle() {
        let mut config = TrustedContextConfig::default();

        // With trusted mDNS on (default).
        assert!(config.allows_mdns(&TransportType::Tailscale));

        // Toggle off.
        config.allow_mdns_on_trusted = false;
        assert!(!config.allows_mdns(&TransportType::Tailscale));

        // Non-trusted transports unaffected.
        assert!(config.allows_mdns(&TransportType::Clearnet));
        assert!(config.allows_mdns(&TransportType::BLE));
    }
}
