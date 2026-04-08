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
//! - A stable UUID (`id`) generated at creation time for unambiguous instance
//!   identification across add/remove operations.
//! - A user-assigned `label` for display in the UI (e.g. "Work tailnet").
//! - Auth credentials (stored encrypted in vault; only decrypted in memory
//!   when the client is active)
//! - Connection state
//! - Network membership list
//! - Relay preference (mesh relay preferred over vendor relay — §5.30.4)
//!
//! The `OverlayManager` owns `Vec<TailscaleClient>` and `Vec<ZeroTierClient>`
//! so that multiple simultaneous tailnets / zeronets are supported.  A
//! priority ID on each Vec selects which instance wins routing conflicts.
//!
//! # Priority conflict resolution
//!
//! When multiple tailnets or zeronets are active simultaneously, the transport
//! solver needs a single winner for:
//!   - Exit node selection (which tailnet's exit nodes are offered first)
//!   - Split-tunnel routing preference
//!   - The anonymization score passed to the transport solver
//!
//! The priority instance is identified by `OverlayManager::priority_tailnet_id`
//! / `priority_zeronet_id`.  If None (or the ID no longer exists in the Vec),
//! the first connected instance in insertion order is used.  This "first
//! connected" fallback means the policy degrades gracefully if the priority
//! instance disconnects — there is always at most one winner.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

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
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Disconnected => "Disconnected",
            Self::Error => "Error",
        }
    }
}

// ---------------------------------------------------------------------------
// Instance ID generation
// ---------------------------------------------------------------------------

/// Generate a unique instance ID for a new overlay client.
///
/// Uses `SystemTime` as a seed combined with a thread-local counter to
/// ensure uniqueness within a session without requiring additional crates.
/// The result is a 32-character lowercase hex string.
fn generate_instance_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Seed the hasher with the current time in nanoseconds.  This gives
    // good entropy across process restarts and within a session.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Mix two DefaultHasher passes with different seeds to produce 128 bits
    // of output — sufficient for session-unique IDs.
    let mut h1 = DefaultHasher::new();
    secs.hash(&mut h1);
    nanos.hash(&mut h1);
    // Fold in a static counter for uniqueness within the same nanosecond
    // (e.g. two instances created back-to-back in a test).
    static COUNTER: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    count.hash(&mut h1);
    let a = h1.finish();

    let mut h2 = DefaultHasher::new();
    a.hash(&mut h2);
    count.wrapping_add(1).hash(&mut h2);
    nanos.wrapping_add(1).hash(&mut h2);
    let b = h2.finish();

    // Produce a 32-character hex string from the two 64-bit values.
    format!("{a:016x}{b:016x}")
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
    /// OS identifier string reported by the control plane when available.
    #[serde(default)]
    pub os: String,
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

/// State of the Mesh Infinity Tailscale client for one tailnet instance.
///
/// Multiple `TailscaleClient` instances may exist simultaneously in
/// `OverlayManager::tailnets`.  Each is independently authenticated and
/// tracked; the priority system selects which one wins routing conflicts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TailscaleClient {
    /// Stable UUID for this tailnet instance, generated at creation time.
    ///
    /// Used by the FFI and transport_ops layers to address specific instances
    /// in a multi-tailnet setup.  Never changes after construction.
    pub id: String,
    /// User-assigned label, e.g. "Work tailnet" or "Home Headscale".
    ///
    /// Defaults to empty string; may be updated once connected to reflect
    /// the tailnet name returned by the coordination server.
    pub label: String,
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
    /// Current relay posture for the overlay path.
    #[serde(default)]
    pub relay_mode: String,
    /// Key expiry timestamp in Unix milliseconds, 0 when not available.
    #[serde(default)]
    pub key_expiry_ms: u64,
    /// Whether to prefer mesh relay over Tailscale DERP relay (§5.30.4).
    /// Default: true (mesh relay preferred).
    pub prefer_mesh_relay: bool,
}

impl Default for TailscaleClient {
    fn default() -> Self {
        Self {
            id: generate_instance_id(),
            label: String::new(),
            status: OverlayClientStatus::default(),
            credentials: None,
            device_info: None,
            peers: Vec::new(),
            active_exit_node: None,
            relay_mode: String::new(),
            key_expiry_ms: 0,
            prefer_mesh_relay: true,
        }
    }
}

impl TailscaleClient {
    /// Create a new unconfigured Tailscale client with a fresh UUID.
    pub fn new() -> Self {
        // `Default::default()` calls `generate_instance_id()` for `id`.
        Self::default()
    }

    /// Create a new Tailscale client with a specific label.
    pub fn with_label(label: &str) -> Self {
        Self {
            label: label.to_string(),
            ..Self::default()
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
        match self
            .credentials
            .as_ref()
            .map(|c| c.controller.is_self_hosted())
        {
            Some(true) => 0.5,
            Some(false) => 0.3,
            None => 0.0,
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
            Self::Central => "https://api.zerotier.com/api/v1",
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
    /// Network ID this member belongs to.
    #[serde(default)]
    pub network_id: String,
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

/// State of the Mesh Infinity ZeroTier client for one zeronet instance.
///
/// Multiple `ZeroTierClient` instances may exist simultaneously in
/// `OverlayManager::zeronets`.  Each is independently authenticated and
/// tracked; the priority system selects which one wins routing conflicts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeroTierClient {
    /// Stable UUID for this zeronet instance, generated at creation time.
    ///
    /// Used by the FFI and transport_ops layers to address specific instances
    /// in a multi-zeronet setup.  Never changes after construction.
    pub id: String,
    /// User-assigned label.
    ///
    /// Defaults to empty string; may be updated once connected to reflect
    /// network names returned by the controller.
    pub label: String,
    /// Current connection status.
    pub status: OverlayClientStatus,
    /// Stored credentials (None when not configured).
    pub credentials: Option<ZeroTierCredentials>,
    /// This device's ZeroTier Node ID (10-char hex), assigned at first join.
    pub node_id: Option<String>,
    /// Networks this device has joined.
    pub networks: Vec<ZeroTierNetwork>,
    /// Members visible from the configured ZeroTier networks.
    pub members: Vec<ZeroTierMember>,
    /// Current relay posture for the overlay path.
    #[serde(default)]
    pub relay_mode: String,
    /// Whether to prefer mesh relay over ZeroTier PLANET/MOON relay (§5.30.4).
    /// Default: true.
    pub prefer_mesh_relay: bool,
}

impl Default for ZeroTierClient {
    fn default() -> Self {
        Self {
            id: generate_instance_id(),
            label: String::new(),
            status: OverlayClientStatus::default(),
            credentials: None,
            node_id: None,
            networks: Vec::new(),
            members: Vec::new(),
            relay_mode: String::new(),
            prefer_mesh_relay: true,
        }
    }
}

impl ZeroTierClient {
    /// Create a new unconfigured ZeroTier client with a fresh UUID.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new ZeroTier client with a specific label.
    pub fn with_label(label: &str) -> Self {
        Self {
            label: label.to_string(),
            ..Self::default()
        }
    }

    pub fn is_connected(&self) -> bool {
        self.status.is_active()
    }

    /// Anonymization score. 0.3 vendor; 0.5 self-hosted.
    pub fn anonymization_score(&self) -> f32 {
        match self
            .credentials
            .as_ref()
            .map(|c| c.controller.is_self_hosted())
        {
            Some(true) => 0.5,
            Some(false) => 0.3,
            None => 0.0,
        }
    }

    /// Networks awaiting admin authorization.
    pub fn awaiting_auth_networks(&self) -> Vec<&ZeroTierNetwork> {
        self.networks
            .iter()
            .filter(|n| n.auth_status == ZeroTierNetworkAuthStatus::AwaitingAuthorization)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Overlay Manager
// ---------------------------------------------------------------------------

/// Owns all overlay clients and provides unified status to the FFI and
/// transport solver.
///
/// Supports multiple simultaneous Tailscale tailnets and ZeroTier zeronets.
/// Each is independently connected and tracked.  Priority IDs determine which
/// instance wins routing conflicts when multiple are active.
///
/// # Priority conflict resolution
///
/// `priority_tailnet_id` and `priority_zeronet_id` are set explicitly by the
/// user (e.g. via `mi_tailscale_set_priority`).  When multiple instances of
/// the same type are connected, the priority instance wins for:
///   - Exit node selection (its exit nodes are offered first by the transport
///     solver and the VPN screen exit node selector)
///   - Split-tunnel routing preference
///   - The anonymization score used in transport path ranking
///
/// If the priority ID is None, or points to an instance that no longer exists
/// or is not connected, the fallback is the first connected instance in
/// insertion order.  If no instance is connected, the result is None.
///
/// This fallback-first-connected policy ensures the routing solver always has
/// a clear answer without requiring explicit user intervention when the
/// priority instance temporarily disconnects.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OverlayManager {
    /// All configured Tailscale tailnets.  Supports multiple simultaneous
    /// connections.  Empty = no Tailscale configured.
    pub tailnets: Vec<TailscaleClient>,
    /// ID of the prioritized tailnet for routing conflict resolution.
    ///
    /// When multiple tailnets are connected, the priority one wins for exit
    /// node selection, split-tunnel routing preference, and the anonymization
    /// score used by the transport solver.
    ///
    /// None = the first connected tailnet is used (or none if all disconnected).
    pub priority_tailnet_id: Option<String>,
    /// All configured ZeroTier zeronets.  Supports multiple simultaneous
    /// connections.  Empty = no ZeroTier configured.
    pub zeronets: Vec<ZeroTierClient>,
    /// ID of the prioritized zeronet for routing conflict resolution.
    ///
    /// Same semantics as `priority_tailnet_id`.
    /// None = the first connected zeronet is used.
    pub priority_zeronet_id: Option<String>,
}

impl OverlayManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether any overlay is currently connected and usable as a transport.
    pub fn any_overlay_active(&self) -> bool {
        self.tailnets.iter().any(|t| t.is_connected())
            || self.zeronets.iter().any(|z| z.is_connected())
    }

    /// List of active exit nodes across all connected overlays.
    ///
    /// Exit nodes from the priority tailnet appear first; remaining tailnets
    /// follow in insertion order.  Used by the VPN screen exit node selector.
    pub fn available_exit_nodes(&self) -> Vec<ExitNodeOption> {
        let mut nodes = Vec::new();

        // Build the ordered iterator: priority tailnet first, then the rest.
        // This ensures that when a priority instance is set, its exit nodes
        // are offered at the top of the UI list.
        let mut tailnet_order: Vec<&TailscaleClient> = Vec::new();
        if let Some(priority) = self.active_tailnet() {
            tailnet_order.push(priority);
        }
        for tailnet in &self.tailnets {
            // Skip the priority instance — already added above.
            if tailnet_order.iter().any(|t| t.id == tailnet.id) {
                continue;
            }
            if tailnet.is_connected() {
                tailnet_order.push(tailnet);
            }
        }

        for tailnet in tailnet_order {
            for peer in tailnet.available_exit_nodes() {
                nodes.push(ExitNodeOption::Tailscale {
                    peer_name: peer.name.clone(),
                    ip: peer.ip.clone(),
                });
            }
        }

        nodes
    }

    // -----------------------------------------------------------------------
    // Priority selection helpers
    // -----------------------------------------------------------------------

    /// The prioritized tailnet, or the first connected one, or None.
    ///
    /// Selection order:
    ///   1. The instance whose `id` matches `priority_tailnet_id` (if connected).
    ///   2. The first connected instance in insertion order.
    ///   3. None if no instance is connected.
    pub fn active_tailnet(&self) -> Option<&TailscaleClient> {
        // Try the explicit priority instance first.
        if let Some(ref priority_id) = self.priority_tailnet_id {
            if let Some(t) = self.tailnets.iter().find(|t| &t.id == priority_id) {
                if t.is_connected() {
                    return Some(t);
                }
            }
        }
        // Fall back to the first connected instance.
        self.tailnets.iter().find(|t| t.is_connected())
    }

    /// The prioritized zeronet, or the first connected one, or None.
    ///
    /// Same selection semantics as `active_tailnet`.
    pub fn active_zeronet(&self) -> Option<&ZeroTierClient> {
        // Try the explicit priority instance first.
        if let Some(ref priority_id) = self.priority_zeronet_id {
            if let Some(z) = self.zeronets.iter().find(|z| &z.id == priority_id) {
                if z.is_connected() {
                    return Some(z);
                }
            }
        }
        // Fall back to the first connected instance.
        self.zeronets.iter().find(|z| z.is_connected())
    }

    // -----------------------------------------------------------------------
    // Instance lookup
    // -----------------------------------------------------------------------

    /// Find a tailnet by its stable ID (immutable borrow).
    pub fn tailnet_by_id(&self, id: &str) -> Option<&TailscaleClient> {
        self.tailnets.iter().find(|t| t.id == id)
    }

    /// Find a tailnet by its stable ID (mutable borrow).
    pub fn tailnet_by_id_mut(&mut self, id: &str) -> Option<&mut TailscaleClient> {
        self.tailnets.iter_mut().find(|t| t.id == id)
    }

    /// Find a zeronet by its stable ID (immutable borrow).
    pub fn zeronet_by_id(&self, id: &str) -> Option<&ZeroTierClient> {
        self.zeronets.iter().find(|z| z.id == id)
    }

    /// Find a zeronet by its stable ID (mutable borrow).
    pub fn zeronet_by_id_mut(&mut self, id: &str) -> Option<&mut ZeroTierClient> {
        self.zeronets.iter_mut().find(|z| z.id == id)
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
    Tailscale { peer_name: String, ip: String },
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
            Self::Mesh { display_name, .. } => format!("Mesh: {display_name}"),
            Self::Tailscale { peer_name, .. } => format!("Tailscale: {peer_name}"),
        }
    }

    /// Amber warning text for non-mesh exits. None for mesh exits.
    pub fn security_warning(&self) -> Option<&'static str> {
        match self {
            Self::Mesh { .. } => None,
            Self::Tailscale { .. } => Some(
                "Internet traffic exits through a Tailscale node. \
                      The exit node operator and Tailscale's coordination \
                      server can observe your clearnet traffic. \
                      Mesh traffic is unaffected.",
            ),
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
        // id must be a non-empty hex string.
        assert!(!c.id.is_empty());
        assert!(c.id.chars().all(|ch| ch.is_ascii_hexdigit()));
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
        // id must be a non-empty hex string.
        assert!(!c.id.is_empty());
        assert!(c.id.chars().all(|ch| ch.is_ascii_hexdigit()));
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

        // Connect one Tailscale instance with an exit node peer.
        let mut ts = TailscaleClient::new();
        ts.status = OverlayClientStatus::Connected;
        ts.peers = vec![TailscalePeer {
            name: "home-server".into(),
            ip: "100.90.1.5".into(),
            online: true,
            is_exit_node: true,
            os: "linux".into(),
            last_seen: 1_000_000,
        }];
        mgr.tailnets.push(ts);

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

    // -----------------------------------------------------------------------
    // New multi-instance tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_tailnets_active() {
        // Two connected tailnets: any_overlay_active() must be true.
        let mut mgr = OverlayManager::new();

        let mut ts1 = TailscaleClient::new();
        ts1.status = OverlayClientStatus::Connected;

        let mut ts2 = TailscaleClient::new();
        ts2.status = OverlayClientStatus::Connected;

        mgr.tailnets.push(ts1);
        mgr.tailnets.push(ts2);

        assert!(mgr.any_overlay_active());
        // Both instances should be reachable.
        assert_eq!(mgr.tailnets.len(), 2);
    }

    #[test]
    fn test_priority_tailnet_selection() {
        // Two connected tailnets; priority ID should select the correct one.
        let mut mgr = OverlayManager::new();

        let mut ts1 = TailscaleClient::new();
        ts1.status = OverlayClientStatus::Connected;
        ts1.label = "Work".into();
        let ts1_id = ts1.id.clone();

        let mut ts2 = TailscaleClient::new();
        ts2.status = OverlayClientStatus::Connected;
        ts2.label = "Home".into();
        let ts2_id = ts2.id.clone();

        mgr.tailnets.push(ts1);
        mgr.tailnets.push(ts2);

        // Without a priority set, the first connected instance wins.
        assert_eq!(mgr.active_tailnet().map(|t| t.id.as_str()), Some(ts1_id.as_str()));

        // Set priority to the second instance.
        mgr.priority_tailnet_id = Some(ts2_id.clone());
        assert_eq!(mgr.active_tailnet().map(|t| t.id.as_str()), Some(ts2_id.as_str()));

        // Disconnect the priority instance; fallback to first connected.
        mgr.tailnet_by_id_mut(&ts2_id).unwrap().status = OverlayClientStatus::Disconnected;
        assert_eq!(mgr.active_tailnet().map(|t| t.id.as_str()), Some(ts1_id.as_str()));
    }

    #[test]
    fn test_tailnet_by_id() {
        // Lookup by stable ID must return the correct instance.
        let mut mgr = OverlayManager::new();

        let ts1 = TailscaleClient::new();
        let ts2 = TailscaleClient::new();
        let ts1_id = ts1.id.clone();
        let ts2_id = ts2.id.clone();

        // IDs must be distinct (uniqueness guarantee).
        assert_ne!(ts1_id, ts2_id);

        mgr.tailnets.push(ts1);
        mgr.tailnets.push(ts2);

        assert!(mgr.tailnet_by_id(&ts1_id).is_some());
        assert!(mgr.tailnet_by_id(&ts2_id).is_some());
        assert!(mgr.tailnet_by_id("nonexistent-id").is_none());

        // Mutable lookup allows field mutation.
        mgr.tailnet_by_id_mut(&ts1_id).unwrap().label = "Updated".into();
        assert_eq!(mgr.tailnet_by_id(&ts1_id).unwrap().label, "Updated");
    }

    #[test]
    fn test_add_remove_instance() {
        // Add then remove instances; Vec length must track correctly.
        let mut mgr = OverlayManager::new();
        assert_eq!(mgr.tailnets.len(), 0);
        assert_eq!(mgr.zeronets.len(), 0);

        // Add two tailnet instances.
        let ts1 = TailscaleClient::new();
        let ts2 = TailscaleClient::new();
        let ts1_id = ts1.id.clone();
        mgr.tailnets.push(ts1);
        mgr.tailnets.push(ts2);
        assert_eq!(mgr.tailnets.len(), 2);

        // Remove the first one.
        mgr.tailnets.retain(|t| t.id != ts1_id);
        assert_eq!(mgr.tailnets.len(), 1);

        // Add two zeronet instances.
        let zt1 = ZeroTierClient::new();
        let zt2 = ZeroTierClient::new();
        let zt1_id = zt1.id.clone();
        mgr.zeronets.push(zt1);
        mgr.zeronets.push(zt2);
        assert_eq!(mgr.zeronets.len(), 2);

        // Remove the first zeronet.
        mgr.zeronets.retain(|z| z.id != zt1_id);
        assert_eq!(mgr.zeronets.len(), 1);
    }

    #[test]
    fn test_priority_zeronet_selection() {
        // Two connected zeronets; priority ID selects the correct one.
        let mut mgr = OverlayManager::new();

        let mut zt1 = ZeroTierClient::new();
        zt1.status = OverlayClientStatus::Connected;
        zt1.label = "Corp network".into();
        let zt1_id = zt1.id.clone();

        let mut zt2 = ZeroTierClient::new();
        zt2.status = OverlayClientStatus::Connected;
        zt2.label = "Home network".into();
        let zt2_id = zt2.id.clone();

        mgr.zeronets.push(zt1);
        mgr.zeronets.push(zt2);

        // Without a priority set, first connected wins.
        assert_eq!(mgr.active_zeronet().map(|z| z.id.as_str()), Some(zt1_id.as_str()));

        // Set priority to the second instance.
        mgr.priority_zeronet_id = Some(zt2_id.clone());
        assert_eq!(mgr.active_zeronet().map(|z| z.id.as_str()), Some(zt2_id.as_str()));
    }

    #[test]
    fn test_exit_nodes_priority_order() {
        // Priority tailnet's exit nodes appear before other tailnets' nodes.
        let mut mgr = OverlayManager::new();

        let mut ts1 = TailscaleClient::new();
        ts1.status = OverlayClientStatus::Connected;
        ts1.peers = vec![TailscalePeer {
            name: "first-server".into(),
            ip: "100.0.0.1".into(),
            online: true,
            is_exit_node: true,
            os: "linux".into(),
            last_seen: 0,
        }];
        let ts1_id = ts1.id.clone();

        let mut ts2 = TailscaleClient::new();
        ts2.status = OverlayClientStatus::Connected;
        ts2.peers = vec![TailscalePeer {
            name: "second-server".into(),
            ip: "100.0.0.2".into(),
            online: true,
            is_exit_node: true,
            os: "linux".into(),
            last_seen: 0,
        }];
        let ts2_id = ts2.id.clone();

        mgr.tailnets.push(ts1);
        mgr.tailnets.push(ts2);

        // Without priority, first tailnet's exit node appears first.
        let exits = mgr.available_exit_nodes();
        assert_eq!(exits.len(), 2);
        if let ExitNodeOption::Tailscale { peer_name, .. } = &exits[0] {
            assert_eq!(peer_name, "first-server");
        }

        // Set priority to second tailnet; its exit node should appear first.
        mgr.priority_tailnet_id = Some(ts2_id.clone());
        let exits = mgr.available_exit_nodes();
        assert_eq!(exits.len(), 2);
        if let ExitNodeOption::Tailscale { peer_name, .. } = &exits[0] {
            assert_eq!(peer_name, "second-server");
        }

        // Suppress unused variable warnings.
        let _ = ts1_id;
    }
}
