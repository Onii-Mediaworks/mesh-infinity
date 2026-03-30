//! Overlay Transport Clients — Tailscale and ZeroTier (§5.22, §5.23)
//!
//! Mesh Infinity is a first-class client for overlay networks. It does not
//! depend on an external Tailscale daemon or ZeroTier service — it manages
//! the overlay connection itself.
//!
//! # Mobile VPN Slot
//!
//! iOS and Android permit exactly one active VPN extension. Mesh Infinity's
//! extension handles mesh routing, Tailscale, ZeroTier, and Infinet in a
//! single slot. Users do not install separate overlay apps.
//!
//! # Architecture
//!
//! Each overlay client (`TailscaleClient`, `ZeroTierClient`) holds:
//! - Auth credentials (stored encrypted in vault; only decrypted in memory
//!   when the client is active)
//! - Connection state
//! - Network membership list
//! - Relay preference (mesh relay preferred over vendor relay — §5.30.4)
//!
//! The `OverlayManager` owns both clients and exposes a unified status
//! interface to the FFI layer and the transport solver.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Connection Status
// ---------------------------------------------------------------------------

/// Connection state of a Mesh Infinity-managed overlay client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum OverlayClientStatus {
    /// No credentials stored — client has never been configured.
    #[default]
    NotConfigured,
    /// Credentials stored; actively attempting to connect / authenticate.
    Connecting,
    /// Authenticated and connected to the overlay network.
    Connected,
    /// Credentials stored but transport is disabled or intentionally down.
    Disconnected,
    /// Authentication or connection error.
    Error,
}

impl OverlayClientStatus {
    /// Whether the client is usable as a transport path right now.
    pub fn is_active(&self) -> bool {
        *self == Self::Connected
    }

    /// Short label for UI display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotConfigured => "Not configured",
            Self::Connecting    => "Connecting",
            Self::Connected     => "Connected",
            Self::Disconnected  => "Disconnected",
            Self::Error         => "Error",
        }
    }
}

// ---------------------------------------------------------------------------
// Tailscale Client (§5.23)
// ---------------------------------------------------------------------------

/// Which coordination server the Tailscale client authenticates against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TailscaleController {
    /// Official Tailscale coordination server (login.tailscale.com).
    Vendor,
    /// Self-hosted Headscale instance.
    Headscale {
        /// Base URL of the Headscale server, e.g. "https://hs.example.com".
        url: String,
    },
}

impl TailscaleController {
    /// Base URL of the coordination server.
    pub fn base_url(&self) -> &str {
        match self {
            Self::Vendor => "https://login.tailscale.com",
            Self::Headscale { url } => url.as_str(),
        }
    }

    /// Whether this controller eliminates a third-party trust dependency.
    /// Self-hosted Headscale scores 0.5 anonymization instead of 0.3.
    pub fn is_self_hosted(&self) -> bool {
        matches!(self, Self::Headscale { .. })
    }
}

/// Tailscale device info after successful enrollment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TailscaleDeviceInfo {
    /// This device's Tailscale IP (e.g. 100.x.y.z).
    pub tailscale_ip: String,
    /// This device's name on the tailnet.
    pub device_name: String,
    /// The tailnet name.
    pub tailnet_name: String,
    /// Whether this device can act as an exit node.
    pub can_be_exit_node: bool,
}

/// A peer device on the tailnet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TailscalePeer {
    /// Display name.
    pub name: String,
    /// Tailscale virtual IP.
    pub ip: String,
    /// Whether the peer is currently online.
    pub online: bool,
    /// Whether this peer advertises exit node capability.
    pub is_exit_node: bool,
    /// OS identifier string.
    pub os: String,
    /// Unix timestamp of last seen time.
    pub last_seen: u64,
}

/// Stored credentials for a Tailscale client instance.
/// Kept encrypted in vault; only held in memory when client is active.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TailscaleCredentials {
    /// Which coordination server to authenticate against.
    pub controller: TailscaleController,
    /// The auth key (tskey-auth-...) or OAuth token. Encrypted at rest.
    pub auth_token: String,
    /// Whether the auth_token is a one-time auth key (used at enrollment)
    /// or a long-lived OAuth/session token (persisted after first auth).
    pub is_auth_key: bool,
}

/// State of the Mesh Infinity Tailscale client.
#[derive(Clone, Debug, Default)]
pub struct TailscaleClient {
    /// Current connection status.
    pub status: OverlayClientStatus,
    /// Stored credentials (None when not configured).
    pub credentials: Option<TailscaleCredentials>,
    /// Device info after successful enrollment.
    pub device_info: Option<TailscaleDeviceInfo>,
    /// Currently visible tailnet peers.
    pub peers: Vec<TailscalePeer>,
    /// Active exit node (peer name), if clearnet is routing via Tailscale.
    pub active_exit_node: Option<String>,
    /// Whether to prefer mesh relay over Tailscale DERP relay (§5.30.4).
    /// Default: true (mesh relay preferred).
    pub prefer_mesh_relay: bool,
}


impl TailscaleClient {
    pub fn new() -> Self {
        Self {
            prefer_mesh_relay: true,
            ..Default::default()
        }
    }

    /// Whether this client is configured and connected.
    pub fn is_connected(&self) -> bool {
        self.status.is_active()
    }

    /// Anonymization score for the transport solver (§5.23, §5.30).
    ///
    /// Vendor Tailscale (0.3): the coordination server sees which nodes
    /// connect and when, creating a metadata trail.  Self-hosted Headscale
    /// (0.5) eliminates the third-party trust dependency but still reveals
    /// the node's IP to whoever runs the server.  Neither achieves the
    /// anonymity of Tor (1.0) or I2P (0.9), but both provide better
    /// reachability behind corporate firewalls.
    pub fn anonymization_score(&self) -> f32 {
        match self.credentials.as_ref().map(|c| c.controller.is_self_hosted()) {
            Some(true)  => 0.5,
            Some(false) => 0.3,
            None        => 0.0,
        }
    }

    /// Available Tailscale exit nodes from the current tailnet peer list.
    pub fn available_exit_nodes(&self) -> Vec<&TailscalePeer> {
        self.peers.iter().filter(|p| p.is_exit_node).collect()
    }
}

// ---------------------------------------------------------------------------
// ZeroTier Client (§5.22)
// ---------------------------------------------------------------------------

/// Which controller the ZeroTier client uses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZeroTierController {
    /// ZeroTier Central (my.zerotier.com).
    Central,
    /// Self-hosted ZeroTier network controller.
    SelfHosted {
        /// Controller API base URL.
        url: String,
    },
}

impl ZeroTierController {
    pub fn api_base_url(&self) -> &str {
        match self {
            Self::Central                 => "https://api.zerotier.com/api/v1",
            Self::SelfHosted { url } => url.as_str(),
        }
    }

    pub fn is_self_hosted(&self) -> bool {
        matches!(self, Self::SelfHosted { .. })
    }
}

/// Authorization status of this device on a ZeroTier network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZeroTierNetworkAuthStatus {
    /// Authorized and connected.
    Authorized,
    /// Joined but waiting for network admin to approve.
    AwaitingAuthorization,
    /// Authorization was revoked.
    Unauthorized,
}

/// A ZeroTier network this device has joined.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeroTierNetwork {
    /// 16-character hex network ID.
    pub network_id: String,
    /// Network display name (from controller).
    pub name: String,
    /// Assigned virtual IP on this network.
    pub assigned_ip: Option<String>,
    /// Authorization status.
    pub auth_status: ZeroTierNetworkAuthStatus,
    /// Number of authorized members visible from this device.
    pub member_count: usize,
}

/// A member of a ZeroTier network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeroTierMember {
    /// ZeroTier Node ID (10-char hex).
    pub node_id: String,
    /// Display name (if set in controller).
    pub name: String,
    /// Assigned virtual IPs.
    pub ips: Vec<String>,
    /// Whether this member is currently authorized.
    pub authorized: bool,
    /// Unix timestamp of last seen.
    pub last_seen: u64,
}

/// Stored credentials for a ZeroTier client instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeroTierCredentials {
    /// Which controller to use.
    pub controller: ZeroTierController,
    /// API key. Encrypted at rest.
    pub api_key: String,
    /// Network IDs to join.
    pub network_ids: Vec<String>,
}

/// State of the Mesh Infinity ZeroTier client.
#[derive(Clone, Debug, Default)]
pub struct ZeroTierClient {
    /// Current connection status.
    pub status: OverlayClientStatus,
    /// Stored credentials (None when not configured).
    pub credentials: Option<ZeroTierCredentials>,
    /// This device's ZeroTier Node ID (10-char hex), assigned at first join.
    pub node_id: Option<String>,
    /// Networks this device has joined.
    pub networks: Vec<ZeroTierNetwork>,
    /// Whether to prefer mesh relay over ZeroTier PLANET/MOON relay (§5.30.4).
    /// Default: true.
    pub prefer_mesh_relay: bool,
}

impl ZeroTierClient {
    pub fn new() -> Self {
        Self {
            prefer_mesh_relay: true,
            ..Default::default()
        }
    }

    pub fn is_connected(&self) -> bool {
        self.status.is_active()
    }

    /// Anonymization score. 0.3 vendor; 0.5 self-hosted.
    pub fn anonymization_score(&self) -> f32 {
        match self.credentials.as_ref().map(|c| c.controller.is_self_hosted()) {
            Some(true)  => 0.5,
            Some(false) => 0.3,
            None        => 0.0,
        }
    }

    /// Networks awaiting admin authorization.
    pub fn awaiting_auth_networks(&self) -> Vec<&ZeroTierNetwork> {
        self.networks.iter()
            .filter(|n| n.auth_status == ZeroTierNetworkAuthStatus::AwaitingAuthorization)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Overlay Manager
// ---------------------------------------------------------------------------

/// Owns both overlay clients and provides unified status to the FFI and
/// transport solver.
#[derive(Default)]
pub struct OverlayManager {
    pub tailscale: TailscaleClient,
    pub zerotier: ZeroTierClient,
}

impl OverlayManager {
    pub fn new() -> Self {
        Self {
            tailscale: TailscaleClient::new(),
            zerotier: ZeroTierClient::new(),
        }
    }

    /// Whether any overlay is currently connected and usable as a transport.
    pub fn any_overlay_active(&self) -> bool {
        self.tailscale.is_connected() || self.zerotier.is_connected()
    }

    /// List of active exit nodes across all connected overlays.
    /// Used by the VPN screen exit node selector.
    pub fn available_exit_nodes(&self) -> Vec<ExitNodeOption> {
        let mut nodes = Vec::new();

        if self.tailscale.is_connected() {
            for peer in self.tailscale.available_exit_nodes() {
                nodes.push(ExitNodeOption::Tailscale {
                    peer_name: peer.name.clone(),
                    ip: peer.ip.clone(),
                });
            }
        }

        nodes
    }
}

/// An available exit node option for clearnet traffic routing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExitNodeOption {
    /// Mesh exit node (§13.2) — decentralized, preferred.
    Mesh {
        peer_id: String,
        display_name: String,
        trust_level: u8,
        hop_count: u8,
    },
    /// Tailscale exit node — routes through tailnet peer.
    /// Amber indicator (§5.30.5): coordination server visible.
    Tailscale {
        peer_name: String,
        ip: String,
    },
}

impl ExitNodeOption {
    /// Whether this is a mesh-native exit (green indicator) or an
    /// overlay exit (amber indicator). Used by VPN screen and status bar.
    pub fn is_mesh_native(&self) -> bool {
        matches!(self, Self::Mesh { .. })
    }

    /// Short label for UI display.
    pub fn display_label(&self) -> String {
        match self {
            Self::Mesh { display_name, .. } =>
                format!("Mesh: {display_name}"),
            Self::Tailscale { peer_name, .. } =>
                format!("Tailscale: {peer_name}"),
        }
    }

    /// Amber warning text for non-mesh exits. None for mesh exits.
    pub fn security_warning(&self) -> Option<&'static str> {
        match self {
            Self::Mesh { .. } => None,
            Self::Tailscale { .. } =>
                Some("Internet traffic exits through a Tailscale node. \
                      The exit node operator and Tailscale's coordination \
                      server can observe your clearnet traffic. \
                      Mesh traffic is unaffected."),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tailscale_client_defaults() {
        let c = TailscaleClient::new();
        assert_eq!(c.status, OverlayClientStatus::NotConfigured);
        assert!(c.prefer_mesh_relay);
        assert!(!c.is_connected());
        assert_eq!(c.anonymization_score(), 0.0); // no credentials
    }

    #[test]
    fn test_tailscale_anonymization_score() {
        let mut c = TailscaleClient::new();
        c.credentials = Some(TailscaleCredentials {
            controller: TailscaleController::Vendor,
            auth_token: "tskey-test".into(),
            is_auth_key: true,
        });
        assert_eq!(c.anonymization_score(), 0.3);

        c.credentials = Some(TailscaleCredentials {
            controller: TailscaleController::Headscale {
                url: "https://hs.example.com".into(),
            },
            auth_token: "test-token".into(),
            is_auth_key: false,
        });
        assert_eq!(c.anonymization_score(), 0.5);
    }

    #[test]
    fn test_zerotier_client_defaults() {
        let c = ZeroTierClient::new();
        assert_eq!(c.status, OverlayClientStatus::NotConfigured);
        assert!(c.prefer_mesh_relay);
        assert!(!c.is_connected());
    }

    #[test]
    fn test_zerotier_anonymization_score() {
        let mut c = ZeroTierClient::new();
        c.credentials = Some(ZeroTierCredentials {
            controller: ZeroTierController::Central,
            api_key: "testkey".into(),
            network_ids: vec!["8056c2e21c000001".into()],
        });
        assert_eq!(c.anonymization_score(), 0.3);

        c.credentials = Some(ZeroTierCredentials {
            controller: ZeroTierController::SelfHosted {
                url: "https://zt.example.com".into(),
            },
            api_key: "testkey".into(),
            network_ids: vec![],
        });
        assert_eq!(c.anonymization_score(), 0.5);
    }

    #[test]
    fn test_overlay_manager_exit_nodes() {
        let mut mgr = OverlayManager::new();
        assert!(!mgr.any_overlay_active());
        assert!(mgr.available_exit_nodes().is_empty());

        // Connect Tailscale with an exit node peer.
        mgr.tailscale.status = OverlayClientStatus::Connected;
        mgr.tailscale.peers = vec![TailscalePeer {
            name: "home-server".into(),
            ip: "100.90.1.5".into(),
            online: true,
            is_exit_node: true,
            os: "linux".into(),
            last_seen: 1_000_000,
        }];

        assert!(mgr.any_overlay_active());
        let exits = mgr.available_exit_nodes();
        assert_eq!(exits.len(), 1);
        assert!(!exits[0].is_mesh_native());
        assert!(exits[0].security_warning().is_some());
    }

    #[test]
    fn test_exit_node_option_labels() {
        let mesh = ExitNodeOption::Mesh {
            peer_id: "aabbcc".into(),
            display_name: "relay-1".into(),
            trust_level: 6,
            hop_count: 2,
        };
        assert!(mesh.is_mesh_native());
        assert!(mesh.security_warning().is_none());
        assert!(mesh.display_label().starts_with("Mesh:"));

        let ts = ExitNodeOption::Tailscale {
            peer_name: "home-server".into(),
            ip: "100.90.1.5".into(),
        };
        assert!(!ts.is_mesh_native());
        assert!(ts.security_warning().is_some());
        assert!(ts.display_label().starts_with("Tailscale:"));
    }

    #[test]
    fn test_status_label() {
        assert_eq!(OverlayClientStatus::Connected.label(), "Connected");
        assert_eq!(OverlayClientStatus::NotConfigured.label(), "Not configured");
        assert_eq!(OverlayClientStatus::Error.label(), "Error");
    }

    #[test]
    fn test_zerotier_awaiting_auth() {
        let mut c = ZeroTierClient::new();
        c.networks = vec![
            ZeroTierNetwork {
                network_id: "8056c2e21c000001".into(),
                name: "my-net".into(),
                assigned_ip: None,
                auth_status: ZeroTierNetworkAuthStatus::AwaitingAuthorization,
                member_count: 0,
            },
            ZeroTierNetwork {
                network_id: "8056c2e21c000002".into(),
                name: "other-net".into(),
                assigned_ip: Some("192.168.10.5".into()),
                auth_status: ZeroTierNetworkAuthStatus::Authorized,
                member_count: 3,
            },
        ];
        let pending = c.awaiting_auth_networks();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].network_id, "8056c2e21c000001");
    }
}
