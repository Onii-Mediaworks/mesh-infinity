//! Federation (§19)
//!
//! # What is Federation?
//!
//! Federation allows Mesh Infinity to interoperate with external
//! communication platforms (Matrix, ActivityPub, XMPP, WebRTC)
//! through bridge services.
//!
//! # Federation Masks (§19.3)
//!
//! Each federated identity gets its own mask — a separate
//! cryptographic identity that prevents cross-platform linkage.
//! Linkage between federation masks and mesh identities is
//! NEVER automatic.
//!
//! # Security Boundaries (§19.4)
//!
//! - External users are capped at Level 5 (Acquaintance)
//! - Per-user rate limit: 60 messages/minute
//! - Per-channel aggregate: 300 messages/minute
//! - Bridge service identities use MLS HistoryAccess::None
//! - No trust propagation across federation bridges

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum trust level for federated external users.
pub const MAX_EXTERNAL_TRUST_LEVEL: u8 = 5; // Acquaintance.

/// Per-external-user message rate limit (messages/minute).
pub const EXTERNAL_USER_RATE_LIMIT: u32 = 60;

/// Per-bridged-channel aggregate rate limit (messages/minute).
pub const CHANNEL_AGGREGATE_RATE_LIMIT: u32 = 300;

// ---------------------------------------------------------------------------
// Federated Platform
// ---------------------------------------------------------------------------

/// Supported federation platforms (§19).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FederatedPlatform {
    /// Matrix (via Synapse/Dendrite bridges).
    Matrix,
    /// ActivityPub (Mastodon, Pleroma, etc.).
    ActivityPub,
    /// XMPP (Jabber).
    Xmpp,
    /// WebRTC (browser-based access to Gardens).
    WebRtc,
    /// AT Protocol (Bluesky).
    AtProtocol,
    /// Nostr.
    Nostr,
    /// Diaspora.
    Diaspora,
    /// Custom/other platform.
    Custom(String),
}

// ---------------------------------------------------------------------------
// Federation Mask (§19.3)
// ---------------------------------------------------------------------------

/// A federation mask — a separate identity for a federated platform.
///
/// Prevents cross-platform linkage. Each federated identity
/// gets its own mask with independent keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationMask {
    /// Unique mask identifier.
    pub mask_id: [u8; 32],
    /// Which platform this mask is for.
    pub platform: FederatedPlatform,
    /// The external ID on that platform.
    pub external_id: String,
    /// Whether linkage is one-way or bidirectional.
    pub linkage: LinkageType,
    /// When this mask was created.
    pub created_at: u64,
    /// When this mask was last used.
    pub last_used: u64,
}

/// Linkage type for federation masks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkageType {
    /// Only the local user knows the connection.
    OneWay,
    /// Both sides know (mutual verification completed).
    TwoWay,
}

// ---------------------------------------------------------------------------
// Bridge Configuration
// ---------------------------------------------------------------------------

/// Configuration for a federation bridge (§19.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Which platform to bridge.
    pub platform: FederatedPlatform,
    /// Whether the bridge is active.
    pub enabled: bool,
    /// Maximum external users allowed through this bridge.
    pub max_external_users: Option<u32>,
    /// Per-user rate limit override (default: EXTERNAL_USER_RATE_LIMIT).
    pub user_rate_limit: Option<u32>,
    /// Per-channel rate limit override.
    pub channel_rate_limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// WebRTC Gateway (§19.1)
// ---------------------------------------------------------------------------

/// WebRTC gateway configuration for browser-based Garden access.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebRtcGatewayConfig {
    /// Whether the WebRTC gateway is enabled.
    pub enabled: bool,
    /// Maximum simultaneous WebRTC connections.
    pub max_connections: u32,
    /// ICE policy for NAT traversal.
    pub ice_policy: IcePolicy,
    /// Which channels allow WebRTC access (None = all).
    pub allowed_channels: Option<Vec<[u8; 32]>>,
}

/// ICE policy for WebRTC NAT traversal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IcePolicy {
    /// Only use relay (TURN) servers. Most private.
    RelayOnly,
    /// Use mesh relay as STUN/TURN bridge.
    BridgeStunTurn,
    /// Use external STUN/TURN servers (least private).
    External {
        stun: Vec<String>,
        turn: Vec<TurnConfig>,
    },
}

/// TURN server configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TurnConfig {
    pub url: String,
    pub username: Option<String>,
    pub credential: Option<String>,
}

// ---------------------------------------------------------------------------
// OIDC Support (§18.5)
// ---------------------------------------------------------------------------

/// OIDC authentication configuration for plugins and services.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Whether OIDC is enabled for this service.
    pub enabled: bool,
    /// OIDC issuer URL.
    pub issuer: String,
    /// Client ID.
    pub client_id: String,
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// Privacy warning acknowledged by user.
    pub privacy_warning_accepted: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_mask_serde() {
        let mask = FederationMask {
            mask_id: [0xAA; 32],
            platform: FederatedPlatform::Matrix,
            external_id: "@alice:matrix.org".to_string(),
            linkage: LinkageType::OneWay,
            created_at: 1000,
            last_used: 2000,
        };
        let json = serde_json::to_string(&mask).unwrap();
        let recovered: FederationMask = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.platform, FederatedPlatform::Matrix);
    }

    #[test]
    fn test_bridge_config() {
        let config = BridgeConfig {
            platform: FederatedPlatform::ActivityPub,
            enabled: true,
            max_external_users: Some(100),
            user_rate_limit: None,
            channel_rate_limit: None,
        };
        assert!(config.enabled);
    }

    #[test]
    fn test_linkage_types() {
        assert_ne!(LinkageType::OneWay, LinkageType::TwoWay);
    }
}
