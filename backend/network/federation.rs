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
// MAX_EXTERNAL_TRUST_LEVEL — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_EXTERNAL_TRUST_LEVEL — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_EXTERNAL_TRUST_LEVEL: u8 = 5; // Acquaintance.

/// Per-external-user message rate limit (messages/minute).
// EXTERNAL_USER_RATE_LIMIT — protocol constant.
// Defined by the spec; must not change without a version bump.
// EXTERNAL_USER_RATE_LIMIT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const EXTERNAL_USER_RATE_LIMIT: u32 = 60;

/// Per-bridged-channel aggregate rate limit (messages/minute).
// CHANNEL_AGGREGATE_RATE_LIMIT — protocol constant.
// Defined by the spec; must not change without a version bump.
// CHANNEL_AGGREGATE_RATE_LIMIT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const CHANNEL_AGGREGATE_RATE_LIMIT: u32 = 300;

// ---------------------------------------------------------------------------
// Federated Platform
// ---------------------------------------------------------------------------

/// Supported federation platforms (§19).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// FederatedPlatform — variant enumeration.
// Match exhaustively to handle every protocol state.
// FederatedPlatform — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum FederatedPlatform {
    /// Matrix (via Synapse/Dendrite bridges).
    Matrix,
    /// ActivityPub (Mastodon, Pleroma, etc.).
    // Execute this protocol step.
    // Execute this protocol step.
    ActivityPub,
    /// XMPP (Jabber).
    Xmpp,
    /// WebRTC (browser-based access to Gardens).
    WebRtc,
    /// AT Protocol (Bluesky).
    // Execute this protocol step.
    // Execute this protocol step.
    AtProtocol,
    /// Nostr.
    Nostr,
    /// Diaspora.
    // Execute this protocol step.
    // Execute this protocol step.
    Diaspora,
    /// Custom/other platform.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// FederationMask — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FederationMask — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FederationMask {
    /// Unique mask identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mask_id: [u8; 32],
    /// Which platform this mask is for.
    // Execute this protocol step.
    // Execute this protocol step.
    pub platform: FederatedPlatform,
    /// The external ID on that platform.
    // Execute this protocol step.
    // Execute this protocol step.
    pub external_id: String,
    /// Whether linkage is one-way or bidirectional.
    // Execute this protocol step.
    // Execute this protocol step.
    pub linkage: LinkageType,
    /// When this mask was created.
    // Execute this protocol step.
    // Execute this protocol step.
    pub created_at: u64,
    /// When this mask was last used.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_used: u64,
}

/// Linkage type for federation masks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// LinkageType — variant enumeration.
// Match exhaustively to handle every protocol state.
// LinkageType — variant enumeration.
// Match exhaustively to handle every protocol state.
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
// Begin the block scope.
// BridgeConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// BridgeConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct BridgeConfig {
    /// Which platform to bridge.
    // Execute this protocol step.
    // Execute this protocol step.
    pub platform: FederatedPlatform,
    /// Whether the bridge is active.
    // Execute this protocol step.
    // Execute this protocol step.
    pub enabled: bool,
    /// Maximum external users allowed through this bridge.
    // Execute this protocol step.
    // Execute this protocol step.
    pub max_external_users: Option<u32>,
    /// Per-user rate limit override (default: EXTERNAL_USER_RATE_LIMIT).
    // Execute this protocol step.
    // Execute this protocol step.
    pub user_rate_limit: Option<u32>,
    /// Per-channel rate limit override.
    // Execute this protocol step.
    // Execute this protocol step.
    pub channel_rate_limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// WebRTC Gateway (§19.1)
// ---------------------------------------------------------------------------

/// WebRTC gateway configuration for browser-based Garden access.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// WebRtcGatewayConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// WebRtcGatewayConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct WebRtcGatewayConfig {
    /// Whether the WebRTC gateway is enabled.
    // Execute this protocol step.
    // Execute this protocol step.
    pub enabled: bool,
    /// Maximum simultaneous WebRTC connections.
    // Execute this protocol step.
    // Execute this protocol step.
    pub max_connections: u32,
    /// ICE policy for NAT traversal.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ice_policy: IcePolicy,
    /// Which channels allow WebRTC access (None = all).
    // Execute this protocol step.
    // Execute this protocol step.
    pub allowed_channels: Option<Vec<[u8; 32]>>,
}

/// ICE policy for WebRTC NAT traversal.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// IcePolicy — variant enumeration.
// Match exhaustively to handle every protocol state.
// IcePolicy — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum IcePolicy {
    /// Only use relay (TURN) servers. Most private.
    // Execute this protocol step.
    // Execute this protocol step.
    RelayOnly,
    /// Use mesh relay as STUN/TURN bridge.
    // Execute this protocol step.
    // Execute this protocol step.
    BridgeStunTurn,
    /// Use external STUN/TURN servers (least private).
    // Execute this protocol step.
    // Execute this protocol step.
    External {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        stun: Vec<String>,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        turn: Vec<TurnConfig>,
    },
}

/// TURN server configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TurnConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TurnConfig — protocol data structure (see field-level docs).
pub struct TurnConfig {
    /// The url for this instance.
    // Execute this protocol step.
    pub url: String,
    /// The username for this instance.
    // Execute this protocol step.
    pub username: Option<String>,
    /// The credential for this instance.
    // Execute this protocol step.
    pub credential: Option<String>,
}

// ---------------------------------------------------------------------------
// OIDC Support (§18.5)
// ---------------------------------------------------------------------------

/// OIDC authentication configuration for plugins and services.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// OidcConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct OidcConfig {
    /// Whether OIDC is enabled for this service.
    // Execute this protocol step.
    pub enabled: bool,
    /// OIDC issuer URL.
    // Execute this protocol step.
    pub issuer: String,
    /// Client ID.
    // Execute this protocol step.
    pub client_id: String,
    /// Scopes to request.
    // Execute this protocol step.
    pub scopes: Vec<String>,
    /// Privacy warning acknowledged by user.
    // Execute this protocol step.
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
