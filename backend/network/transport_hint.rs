//! Transport Hints (§4.2)
//!
//! Transport hints indicate how a peer is reachable.
//! Included in NetworkMapEntry for each peer.

use serde::{Deserialize, Serialize};

/// Transport type identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportType {
    /// WireGuard over clearnet (direct IP).
    Clearnet,
    /// Tor hidden service (.onion).
    Tor,
    /// I2P destination.
    I2P,
    /// Bluetooth Low Energy.
    BLE,
    /// Bluetooth Classic.
    BluetoothClassic,
    /// WiFi Direct.
    WiFiDirect,
    /// NFC (proximity, no address).
    NFC,
    /// Ultrasonic (proximity, no address).
    Ultrasonic,
    /// USB / Serial.
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
    Yggdrasil,
    /// cjdns overlay.
    Cjdns,
    /// ZeroTier overlay.
    ZeroTier,
    /// Tailscale / Headscale overlay.
    Tailscale,
    /// GNUnet.
    GNUnet,
    /// Native mixnet tier.
    Mixnet,
    /// Telephone subchannel.
    Telephone,
    /// CAN bus.
    CANBus,
    /// PPPoE.
    PPPoE,
    /// Dial-up modem.
    Dialup,
}

impl TransportType {
    /// Short display name for UI.
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Clearnet => "Net",
            Self::Tor => "Tor",
            Self::I2P => "I2P",
            Self::BLE => "BLE",
            Self::BluetoothClassic => "BT",
            Self::WiFiDirect => "WiFi",
            Self::NFC => "NFC",
            Self::Ultrasonic => "USonic",
            Self::USBSerial => "USB",
            Self::Layer2 => "L2",
            Self::RF => "RF",
            Self::LoRa => "LoRa",
            Self::SdrHf => "HF",
            Self::SdrVhf => "VHF",
            Self::SdrUhf => "UHF",
            Self::SdrShf => "SHF",
            Self::SdrFhss => "FHSS",
            Self::Yggdrasil => "Ygg",
            Self::Cjdns => "cjdns",
            Self::ZeroTier => "ZT",
            Self::Tailscale => "TS",
            Self::GNUnet => "GNU",
            Self::Mixnet => "Mix",
            Self::Telephone => "Tel",
            Self::CANBus => "CAN",
            Self::PPPoE => "PPP",
            Self::Dialup => "Dial",
        }
    }

    /// Whether this transport type is SDR-based (software-configurable radio).
    ///
    /// All SDR transports share a common hardware abstraction layer and
    /// can be dynamically reconfigured for frequency, modulation, and bandwidth.
    /// Dedicated hardware types (LoRa, RF) use fixed-profile drivers
    /// that implement the same SDR trait but with limited configurability.
    pub fn is_sdr(&self) -> bool {
        matches!(
            self,
            Self::RF | Self::LoRa | Self::SdrHf | Self::SdrVhf
                | Self::SdrUhf | Self::SdrShf | Self::SdrFhss
        )
    }

    /// Whether this is a proximity transport (auto-direct eligible, §6.9.5).
    pub fn is_proximity(&self) -> bool {
        matches!(
            self,
            Self::BLE | Self::BluetoothClassic | Self::WiFiDirect
                | Self::NFC | Self::Ultrasonic | Self::USBSerial | Self::Layer2
        )
    }

    /// Whether this is an anonymizing transport.
    pub fn is_anonymizing(&self) -> bool {
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
    pub fn is_trusted_context(&self) -> bool {
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
    pub fn default_peer_trust(&self) -> u8 {
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
    pub fn pairing_trust_boost(&self) -> u8 {
        if self.is_trusted_context() {
            2 // Tailscale/ZeroTier: overlay auth is a strong signal.
        } else {
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
    pub fn allows_mdns_discovery(&self) -> bool {
        self.is_proximity()
            || matches!(self, Self::Clearnet)
            || self.is_trusted_context()
    }

    /// Anonymization score for transport solver (§5.10.3).
    pub fn anonymization_score(&self) -> f32 {
        match self {
            Self::Clearnet | Self::WiFiDirect | Self::BLE | Self::BluetoothClassic
                | Self::USBSerial | Self::Layer2 | Self::CANBus | Self::NFC
                | Self::Ultrasonic | Self::PPPoE | Self::Dialup | Self::Telephone => 0.0,
            // Generic RF / LoRa: frequency is observable but content is encrypted.
            // No anonymization beyond encryption — RF direction-finding is possible.
            Self::RF | Self::LoRa | Self::SdrHf | Self::SdrVhf | Self::SdrUhf | Self::SdrShf => 0.0,
            // FHSS: pseudo-random hopping provides traffic-analysis resistance.
            // An adversary cannot easily correlate bursts to a specific peer
            // without the hop key. This is directional obscurity, not anonymity.
            Self::SdrFhss => 0.2,
            Self::Tailscale | Self::ZeroTier => 0.3,
            Self::I2P | Self::Yggdrasil | Self::Cjdns => 0.6,
            Self::Tor | Self::GNUnet => 0.9,
            Self::Mixnet => 1.0,
        }
    }

    /// Default bandwidth class.
    pub fn default_bandwidth(&self) -> BandwidthClass {
        match self {
            // Sub-kbps to low-kbps: HF ionospheric, LoRa, FHSS narrow channel
            Self::SdrHf | Self::LoRa | Self::SdrFhss
                | Self::Ultrasonic | Self::Dialup | Self::CANBus
                | Self::Telephone => BandwidthClass::Low,
            // Low-to-medium: generic RF, VHF, BLE, USB
            Self::RF | Self::SdrVhf | Self::BLE | Self::USBSerial => BandwidthClass::Medium,
            // Medium-to-high: UHF/SHF SDR (wideband modes)
            Self::SdrUhf | Self::SdrShf => BandwidthClass::Medium,
            Self::Clearnet | Self::WiFiDirect | Self::Layer2 | Self::PPPoE
                | Self::Tor | Self::I2P | Self::Yggdrasil | Self::Cjdns
                | Self::ZeroTier | Self::Tailscale | Self::GNUnet | Self::Mixnet
                | Self::BluetoothClassic | Self::NFC => BandwidthClass::High,
        }
    }
}

/// Bandwidth classification (§5.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BandwidthClass {
    Low,
    Medium,
    High,
}

/// A transport hint for how to reach a peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportHint {
    pub transport: TransportType,
    /// Endpoint address (e.g., Tor .onion, clearnet IP:port).
    /// None for proximity transports (NFC, ultrasonic).
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
pub struct TrustedContextConfig {
    /// Whether peers on Tailscale inherit elevated trust.
    /// Default: true (Tailscale requires account authentication).
    pub tailscale_trust_elevation: bool,
    /// Whether peers on ZeroTier inherit elevated trust.
    /// Default: true (ZeroTier requires network authorization).
    pub zerotier_trust_elevation: bool,
    /// Whether the local LAN (clearnet) is a trusted context.
    /// Default: false (many LANs are shared/public).
    /// Enable for home/office networks the user controls.
    pub lan_trust_elevation: bool,
    /// Whether mDNS is allowed over trusted context transports.
    /// Default: true.
    pub allow_mdns_on_trusted: bool,
}

impl Default for TrustedContextConfig {
    fn default() -> Self {
        Self {
            tailscale_trust_elevation: true,
            zerotier_trust_elevation: true,
            lan_trust_elevation: false, // Off by default — user must opt in.
            allow_mdns_on_trusted: true,
        }
    }
}

impl TrustedContextConfig {
    /// Whether this transport is a trusted context for discovery.
    ///
    /// Checks the per-transport toggle. Controls whether mDNS and
    /// automatic peer discovery are permitted. Does NOT affect pathing.
    pub fn is_trusted_for_discovery(&self, transport: &TransportType) -> bool {
        match transport {
            TransportType::Tailscale => self.tailscale_trust_elevation,
            TransportType::ZeroTier => self.zerotier_trust_elevation,
            TransportType::Clearnet => self.lan_trust_elevation,
            // Physical-access transports are inherently trusted.
            _ if transport.is_proximity() => true,
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
    pub fn pairing_boost(&self, transport: &TransportType) -> u8 {
        match transport {
            TransportType::Tailscale if self.tailscale_trust_elevation => 2,
            TransportType::ZeroTier if self.zerotier_trust_elevation => 2,
            TransportType::Clearnet if self.lan_trust_elevation => 1,
            _ => transport.pairing_trust_boost(),
        }
    }

    /// Whether mDNS discovery is allowed for a given transport,
    /// considering the trusted context config.
    ///
    /// Proximity transports (BLE, NFC, WiFi Direct, USB, Layer2)
    /// always allow mDNS regardless of the toggle — physical
    /// proximity IS the authentication.
    pub fn allows_mdns(&self, transport: &TransportType) -> bool {
        // Proximity transports: always allowed.
        if transport.is_proximity() {
            return true;
        }
        // Trusted context overlays and LAN: depends on toggle.
        if self.is_trusted_for_discovery(transport) {
            self.allow_mdns_on_trusted
        } else {
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
        assert!(TransportType::Mixnet.anonymization_score() > TransportType::Tor.anonymization_score());
        assert!(TransportType::Tor.anonymization_score() > TransportType::I2P.anonymization_score());
        assert!(TransportType::I2P.anonymization_score() > TransportType::Clearnet.anonymization_score());
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
