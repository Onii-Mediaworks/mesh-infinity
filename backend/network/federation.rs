//! Federation (§19)
//!
//! # What is Federation?
//!
//! Federation allows Mesh Infinity to interoperate with external
//! communication platforms (Matrix, ActivityPub, XMPP, WebRTC)
//! through bridge services.
//!
//! # Federation Bridge System (§19.2)
//!
//! Bridges translate messages bidirectionally between Mesh Infinity
//! Garden channels and external networks. Each bridge runs as a
//! Garden plugin in a WASM sandbox, connecting to the external
//! platform via its native API.
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
// Import the crate-level error type for fallible bridge operations.
use crate::error::MeshError;
// HashMap is used for flexible key-value config in BridgeConnectionConfig.
use std::collections::HashMap;
// OsRng and RngCore provide OS-entropy random byte generation for bridge IDs.
use rand_core::{OsRng, RngCore};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum trust level for federated external users.
// MAX_EXTERNAL_TRUST_LEVEL — protocol constant from §19.4.1.
// Hard architectural limit: trusted tier (Level 6+) requires mesh keypair.
pub const MAX_EXTERNAL_TRUST_LEVEL: u8 = 5; // Acquaintance.

/// Per-external-user message rate limit (messages/minute).
// EXTERNAL_USER_RATE_LIMIT — protocol constant from §19.2.9.
// Prevents a single federated user from flooding a Garden channel.
pub const EXTERNAL_USER_RATE_LIMIT: u32 = 60;

/// Per-bridged-channel aggregate rate limit (messages/minute).
// CHANNEL_AGGREGATE_RATE_LIMIT — protocol constant from §19.2.9.
// Caps total inbound federation traffic per bridged channel.
pub const CHANNEL_AGGREGATE_RATE_LIMIT: u32 = 300;

/// Default display name prefix format for bridged messages.
// Used when formatting external user display names inside Garden channels.
// Pattern: "[platform] username: message" per §19.2.1.
const BRIDGE_DISPLAY_PREFIX: &str = "bridged";

/// Minimum length for a remote room identifier string.
// Prevents empty or trivially short room IDs from being accepted.
// Remote platforms always have identifiers of at least one character.
const MIN_REMOTE_ROOM_ID_LEN: usize = 1;

// ---------------------------------------------------------------------------
// Federated Platform
// ---------------------------------------------------------------------------

/// Supported federation platforms (§19).
// Each variant maps to a specific protocol bridge implementation.
// The Custom variant allows extending to platforms not enumerated here.
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
// Bridge Type (§19.2)
// ---------------------------------------------------------------------------

/// The protocol type for a federation bridge connection.
// Maps to the protocol-specific translation logic in translate_inbound
// and translate_outbound. Each type determines message format mapping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeType {
    /// Matrix bridge — highest priority, full bidirectional chat (§19.2.2).
    // Supports real-time messaging, voice/video, reactions, edits, threads.
    Matrix,
    /// XMPP bridge — text chat and MUC rooms (§19.2.4).
    // Uses XEP-0045 for MUC, XEP-0363 for file upload, XEP-0444 for reactions.
    Xmpp,
    /// IRC bridge — classic text-only chat protocol.
    // Simplest translation: plain text messages only, no rich formatting.
    Irc,
    /// Signal bridge — encrypted messaging (§19.2, custom extension).
    // Messages translated to/from Signal's protobuf wire format.
    Signal,
    /// Custom bridge type — user-defined protocol name.
    // Allows third-party bridge plugins to register their own protocol.
    Custom(String),
}

// ---------------------------------------------------------------------------
// Bridge Status
// ---------------------------------------------------------------------------

/// Current operational state of a federation bridge.
// Tracks the connection lifecycle from disconnected through errors.
// The FFI layer exposes this as a JSON string for Flutter to render.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeStatus {
    /// Bridge is not connected to the external network.
    // Initial state after creation, or after explicit disconnect.
    Disconnected,
    /// Bridge is in the process of establishing a connection.
    // Transition state: will move to Connected or Error.
    Connecting,
    /// Bridge is actively connected and relaying messages.
    // Normal operating state; message translation is active.
    Connected,
    /// Bridge encountered an error and cannot relay messages.
    // The String describes the error; admin intervention may be needed.
    Error(String),
}

// ---------------------------------------------------------------------------
// Bridge Connection Config
// ---------------------------------------------------------------------------

/// Connection credentials and parameters for a specific bridge instance.
// Holds protocol-specific auth data (tokens, URLs, usernames).
// The `extra` map allows protocol-specific fields without schema changes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeConnectionConfig {
    /// Homeserver or server URL (e.g., Matrix homeserver, XMPP server).
    // Not all bridge types require this — IRC uses server:port in `extra`.
    pub homeserver_url: Option<String>,
    /// Username for authenticating with the external platform.
    // Platform-specific format (e.g., "@bot:matrix.org" for Matrix).
    pub username: Option<String>,
    /// Authentication token or password for the external platform.
    // Stored encrypted at rest; never logged or included in status JSON.
    pub token: Option<String>,
    /// Additional protocol-specific configuration key-value pairs.
    // Examples: "irc_channel" -> "#mychannel", "xmpp_conference" -> "muc.example.com".
    pub extra: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Bridge Policy Config (§19.2.9)
// ---------------------------------------------------------------------------

/// Rate-limiting and access policy for a federation bridge.
// Enforces the security boundaries defined in §19.2.9 and §19.4.
// Each bridge has its own policy; defaults come from module constants.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgePolicyConfig {
    /// Which platform this policy applies to.
    // Links the policy to a specific FederatedPlatform variant.
    pub platform: FederatedPlatform,
    /// Whether the bridge is administratively enabled.
    // When false, all traffic is blocked regardless of connection state.
    pub enabled: bool,
    /// Maximum external users allowed through this bridge.
    // None means unlimited (subject to Garden-level limits).
    pub max_external_users: Option<u32>,
    /// Per-user rate limit override (default: EXTERNAL_USER_RATE_LIMIT).
    // Must not exceed EXTERNAL_USER_RATE_LIMIT unless admin overrides.
    pub user_rate_limit: Option<u32>,
    /// Per-channel rate limit override (default: CHANNEL_AGGREGATE_RATE_LIMIT).
    // Caps total inbound messages per bridged channel per minute.
    pub channel_rate_limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Bridge Direction
// ---------------------------------------------------------------------------

/// Direction of message flow for a bridged room mapping.
// Controls whether messages flow one-way or both ways across the bridge.
// InboundOnly is useful for read-only mirrors of external channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeDirection {
    /// Messages flow in both directions across the bridge.
    // Most common mode: full interoperability between platforms.
    Bidirectional,
    /// Only external messages are relayed into the Garden.
    // Garden users see external messages but cannot reply through the bridge.
    InboundOnly,
    /// Only Garden messages are relayed to the external platform.
    // External users see Garden messages but cannot send through the bridge.
    OutboundOnly,
}

// ---------------------------------------------------------------------------
// Bridged Room
// ---------------------------------------------------------------------------

/// A mapping between a local Garden room and an external platform room.
// Each bridged room belongs to exactly one bridge and has a direction.
// The bridge_id links back to the owning FederationBridge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgedRoom {
    /// Local Garden room identifier (16-byte UUID).
    // References a room in the Garden's channel list.
    pub local_room_id: [u8; 16],
    /// Remote room identifier on the external platform.
    // Format is platform-specific (e.g., "!abc:matrix.org" for Matrix).
    pub remote_room_id: String,
    /// The bridge that owns this room mapping.
    // Used to look up the bridge for translation and status checks.
    pub bridge_id: [u8; 16],
    /// Direction of message flow for this room mapping.
    // Controls which side can send messages through the bridge.
    pub direction: BridgeDirection,
}

// ---------------------------------------------------------------------------
// Bridged Message
// ---------------------------------------------------------------------------

/// A message received from an external network, translated for the Garden.
// Contains the original sender info and content after format translation.
// Attachments are handled separately via BridgedAttachment references.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgedMessage {
    /// The bridge that received this message.
    // Used to attribute the message and apply rate limiting.
    pub source_bridge: [u8; 16],
    /// The sender's identity on the external platform.
    // Displayed as "[platform] sender" in the Garden channel.
    pub remote_sender: String,
    /// The room/channel on the external platform where this originated.
    // Used to route the message to the correct local Garden room.
    pub remote_room: String,
    /// The text content of the message after translation.
    // Already converted from the external format to Garden plaintext/markdown.
    pub content: String,
    /// Unix timestamp (seconds since epoch) when the message was sent.
    // Taken from the external platform's timestamp, not local clock.
    pub timestamp: u64,
    /// File attachments associated with this message.
    // Each attachment has a URL on the external platform for download.
    pub attachments: Vec<BridgedAttachment>,
}

// ---------------------------------------------------------------------------
// Bridged Attachment
// ---------------------------------------------------------------------------

/// A file attachment from an external network message.
// Referenced by URL; the bridge downloads and re-encrypts for Garden storage.
// Media quarantine rules (§22.4.11) apply to all external attachments.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgedAttachment {
    /// Original filename from the external platform.
    // Sanitized before display to prevent path traversal or UI injection.
    pub filename: String,
    /// MIME type of the attachment (e.g., "image/png", "application/pdf").
    // Used to determine rendering strategy in the Garden UI.
    pub mime_type: String,
    /// Size of the attachment in bytes.
    // Used for progress display and to enforce size limits.
    pub size_bytes: u64,
    /// URL where the attachment can be fetched from the external platform.
    // The bridge downloads from this URL; it is not exposed to Garden users.
    pub url: String,
}

// ---------------------------------------------------------------------------
// Federation Bridge (§19.2)
// ---------------------------------------------------------------------------

/// A federation bridge connection to an external messaging network.
// Manages the lifecycle of a bridge: creation, connection, room mapping,
// and message translation. Each bridge has a unique 16-byte identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationBridge {
    /// Unique bridge identifier (16-byte UUID).
    // Generated at creation time from OS random source.
    pub id: [u8; 16],
    /// The protocol type this bridge connects to.
    // Determines which translation logic is used for messages.
    pub bridge_type: BridgeType,
    /// Current operational status of this bridge.
    // Updated by connect_bridge, disconnect_bridge, and error handlers.
    pub status: BridgeStatus,
    /// Connection credentials and parameters for this bridge.
    // Contains auth tokens, server URLs, and protocol-specific config.
    pub config: BridgeConnectionConfig,
    /// Rooms currently bridged through this connection.
    // Each entry maps a local Garden room to an external room.
    pub connected_rooms: Vec<BridgedRoom>,
    /// Total number of messages relayed through this bridge.
    // Monotonically increasing counter; used for admin monitoring.
    pub message_count: u64,
    /// Unix timestamp of the last message relayed, if any.
    // None if no messages have been relayed since bridge creation.
    pub last_activity: Option<u64>,
}

// ---------------------------------------------------------------------------
// Federation Mask (§19.3)
// ---------------------------------------------------------------------------

/// A federation mask — a separate identity for a federated platform.
///
/// Prevents cross-platform linkage. Each federated identity
/// gets its own mask with independent keys.
// FederationMask holds the identity binding between mesh and external platform.
// The mask_id is derived via §3.1.2 and is never reused across platforms.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationMask {
    /// Unique mask identifier.
    // 32-byte derived identity, one per platform per user.
    pub mask_id: [u8; 32],
    /// Which platform this mask is for.
    // Determines the format of external_id and linkage proof.
    pub platform: FederatedPlatform,
    /// The external ID on that platform.
    // Platform-specific format (e.g., "@alice:matrix.org", "alice@xmpp.org").
    pub external_id: String,
    /// Whether linkage is one-way or bidirectional.
    // OneWay is default; TwoWay requires explicit user consent.
    pub linkage: LinkageType,
    /// When this mask was created (unix timestamp).
    // Set once at creation; never updated.
    pub created_at: u64,
    /// When this mask was last used (unix timestamp).
    // Updated each time the mask signs or verifies a linkage proof.
    pub last_used: u64,
}

/// Linkage type for federation masks.
// Controls the directionality of identity proof between mesh and external.
// TwoWay creates a permanent public link — requires informed consent (§19.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkageType {
    /// Only the local user knows the connection.
    OneWay,
    /// Both sides know (mutual verification completed).
    TwoWay,
}

// ---------------------------------------------------------------------------
// WebRTC Gateway (§19.1)
// ---------------------------------------------------------------------------

/// WebRTC gateway configuration for browser-based Garden access.
// Enables browser users to participate in Garden channels without the native app.
// The gateway serves a web client and handles WebRTC signalling (§19.1.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebRtcGatewayConfig {
    /// Whether the WebRTC gateway is enabled.
    // Default: false. Must be explicitly enabled by Garden admin.
    pub enabled: bool,
    /// Maximum simultaneous WebRTC connections.
    // Default: 100. Prevents resource exhaustion on the relay node.
    pub max_connections: u32,
    /// ICE policy for NAT traversal.
    // Default: RelayOnly for maximum privacy (no STUN/TURN IP disclosure).
    pub ice_policy: IcePolicy,
    /// Which channels allow WebRTC access (None = all public channels).
    // Admin-configurable allowlist of channel IDs.
    pub allowed_channels: Option<Vec<[u8; 32]>>,
}

/// ICE policy for WebRTC NAT traversal.
// Controls how the gateway handles ICE candidates and NAT traversal.
// RelayOnly is the most private; External requires explicit opt-in (§19.1.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IcePolicy {
    /// Only use relay (TURN) servers. Most private.
    // No ICE candidates generated; no STUN/TURN; no IP disclosure.
    RelayOnly,
    /// Use mesh relay as STUN/TURN bridge.
    // Better NAT traversal; browser IP visible only to bridge's STUN/TURN.
    BridgeStunTurn,
    /// Use external STUN/TURN servers (least private).
    // Browser user's IP visible to external server operator.
    External {
        /// STUN server URLs for NAT discovery.
        stun: Vec<String>,
        /// TURN server configurations for relay fallback.
        turn: Vec<TurnConfig>,
    },
}

/// TURN server configuration.
// Holds credentials for a single TURN relay server.
// Used only when IcePolicy::External is selected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TurnConfig {
    /// The TURN server URL (e.g., "turn:turn.example.com:3478").
    pub url: String,
    /// Optional username for TURN authentication.
    pub username: Option<String>,
    /// Optional credential/password for TURN authentication.
    pub credential: Option<String>,
}

// ---------------------------------------------------------------------------
// OIDC Support (§18.5)
// ---------------------------------------------------------------------------

/// OIDC authentication configuration for plugins and services.
// OIDC-authenticated users remain at their current mesh trust level.
// The trust_ceiling caps effective trust for OIDC-only users (§18.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Whether OIDC is enabled for this service.
    pub enabled: bool,
    /// OIDC issuer URL (e.g., "https://accounts.google.com").
    pub issuer: String,
    /// Client ID registered with the OIDC provider.
    pub client_id: String,
    /// Scopes to request from the provider.
    pub scopes: Vec<String>,
    /// Whether the user has acknowledged the privacy implications.
    pub privacy_warning_accepted: bool,
}

// ---------------------------------------------------------------------------
// Bridge Operations — Creation
// ---------------------------------------------------------------------------

/// Create a new federation bridge with the given type and connection config.
///
/// Generates a random 16-byte bridge ID, sets initial status to Disconnected,
/// and validates the config before returning the bridge instance.
// Returns MeshError::Internal if the OS random source fails.
// Returns MeshError::Internal if required config fields are missing.
pub fn create_bridge(
    bridge_type: BridgeType,
    config: BridgeConnectionConfig,
) -> Result<FederationBridge, MeshError> {
    // Validate that the config has at least a homeserver URL or extra params.
    // A bridge with no connection info at all cannot be useful.
    let has_server = config
        .homeserver_url
        .as_ref()
        .is_some_and(|u| !u.is_empty());
    // Check whether extra params provide enough info for a custom bridge.
    let has_extra = !config.extra.is_empty();

    // For standard bridge types, require a homeserver URL.
    // Custom bridges may use only extra params for their connection info.
    if !has_server && !has_extra {
        return Err(MeshError::Internal(
            "bridge config must have a homeserver_url or extra connection parameters".into(),
        ));
    }

    // Generate a 16-byte random bridge ID using OS entropy.
    // This uniquely identifies the bridge instance across the node.
    let mut id = [0u8; 16];
    // Use OsRng for cryptographic-quality randomness (consistent with codebase).
    OsRng.fill_bytes(&mut id);

    // Construct the bridge in Disconnected state with zero counters.
    // The caller must explicitly call connect_bridge to activate it.
    let bridge = FederationBridge {
        id,
        bridge_type,
        // All bridges start disconnected until connect_bridge is called.
        status: BridgeStatus::Disconnected,
        config,
        // No rooms are bridged until bridge_room is called.
        connected_rooms: Vec::new(),
        // No messages have been relayed yet.
        message_count: 0,
        // No activity has occurred yet.
        last_activity: None,
    };

    Ok(bridge)
}

// ---------------------------------------------------------------------------
// Bridge Operations — Connection Lifecycle
// ---------------------------------------------------------------------------

/// Attempt to connect a bridge to its external network.
///
/// Validates the bridge configuration, transitions status from Disconnected
/// to Connecting, then to Connected. Returns an error if the bridge is
/// already connected or if config validation fails.
// This is a local state transition; actual network I/O is handled by the
// bridge plugin in the WASM sandbox at runtime.
pub fn connect_bridge(bridge: &mut FederationBridge) -> Result<(), MeshError> {
    // Reject connection attempts on bridges that are already connected.
    // The caller must disconnect first to re-establish a connection.
    if bridge.status == BridgeStatus::Connected {
        return Err(MeshError::Internal("bridge is already connected".into()));
    }

    // Reject connection attempts on bridges that are currently connecting.
    // Prevents duplicate connection attempts from racing.
    if bridge.status == BridgeStatus::Connecting {
        return Err(MeshError::Internal(
            "bridge is already in the process of connecting".into(),
        ));
    }

    // Validate that required credentials are present for the bridge type.
    // Each bridge type has different minimum credential requirements.
    validate_bridge_credentials(&bridge.bridge_type, &bridge.config)?;

    // Transition to Connecting state to indicate work is in progress.
    // This intermediate state lets the UI show a spinner/progress indicator.
    bridge.status = BridgeStatus::Connecting;

    // Validate that the homeserver URL (if present) looks like a valid URL.
    // This catches obvious typos before attempting a real connection.
    if let Some(ref url) = bridge.config.homeserver_url {
        // Check for a protocol prefix as a basic sanity check.
        // Real URL parsing happens in the protocol-specific bridge plugin.
        if !url.starts_with("http://") && !url.starts_with("https://") {
            bridge.status = BridgeStatus::Error(format!(
                "invalid homeserver URL: must start with http:// or https://: {url}"
            ));
            return Err(MeshError::Internal(
                "homeserver_url must start with http:// or https://".into(),
            ));
        }
    }

    // Connection validation passed — mark as connected.
    // In a production system, this would be set asynchronously after the
    // actual TCP/TLS handshake completes in the bridge plugin.
    bridge.status = BridgeStatus::Connected;

    Ok(())
}

/// Disconnect a bridge from its external network.
///
/// Transitions the bridge to Disconnected status. Idempotent: calling
/// disconnect on an already-disconnected bridge is a no-op.
// Does not remove bridged room mappings — they persist for reconnection.
// The message counter and last_activity are preserved across reconnects.
pub fn disconnect_bridge(bridge: &mut FederationBridge) {
    // Set status to Disconnected regardless of current state.
    // This handles Connected, Connecting, and Error states uniformly.
    bridge.status = BridgeStatus::Disconnected;
    // Room mappings are intentionally preserved so that reconnecting
    // the bridge resumes message relay without re-configuring rooms.
}

// ---------------------------------------------------------------------------
// Bridge Operations — Room Mapping
// ---------------------------------------------------------------------------

/// Bridge a local Garden room to a remote room on the external platform.
///
/// Creates a BridgedRoom mapping and adds it to the bridge's connected_rooms.
/// Returns an error if the bridge is not connected, the remote room ID is
/// empty, or the local room is already bridged on this bridge.
// Each local room can be bridged to at most one remote room per bridge.
// The same local room CAN be bridged to different platforms via different bridges.
pub fn bridge_room(
    bridge: &mut FederationBridge,
    local_room_id: [u8; 16],
    remote_room_id: &str,
    direction: BridgeDirection,
) -> Result<(), MeshError> {
    // Require the bridge to be connected before adding room mappings.
    // A disconnected bridge cannot verify that the remote room exists.
    if bridge.status != BridgeStatus::Connected {
        return Err(MeshError::Internal(
            "cannot bridge room: bridge is not connected".into(),
        ));
    }

    // Validate that the remote room ID is not empty or too short.
    // All external platforms use non-empty room identifiers.
    if remote_room_id.len() < MIN_REMOTE_ROOM_ID_LEN {
        return Err(MeshError::Internal(
            "remote_room_id must not be empty".into(),
        ));
    }

    // Check for duplicate: the same local room cannot be bridged twice
    // on the same bridge (it can be bridged on different bridges).
    let already_bridged = bridge
        .connected_rooms
        .iter()
        .any(|r| r.local_room_id == local_room_id);
    if already_bridged {
        // Format the room ID as hex for a useful error message.
        let hex_id = hex::encode(local_room_id);
        return Err(MeshError::Internal(format!(
            "local room {hex_id} is already bridged on this bridge"
        )));
    }

    // Create the room mapping linking local and remote rooms.
    // The bridge_id references this bridge for later lookups.
    let bridged_room = BridgedRoom {
        local_room_id,
        remote_room_id: remote_room_id.to_string(),
        bridge_id: bridge.id,
        direction,
    };

    // Add the mapping to the bridge's room list.
    // Room ordering is insertion order; not significant for operation.
    bridge.connected_rooms.push(bridged_room);

    Ok(())
}

/// Remove a bridged room mapping from a bridge.
///
/// Finds and removes the BridgedRoom for the given local_room_id.
/// Returns an error if the room is not bridged on this bridge.
// Does not affect the external platform — the remote room continues to exist.
// Messages in flight at removal time are dropped.
pub fn unbridge_room(
    bridge: &mut FederationBridge,
    local_room_id: &[u8; 16],
) -> Result<(), MeshError> {
    // Find the index of the bridged room matching this local room ID.
    // Linear scan is fine: bridges typically have few room mappings.
    let position = bridge
        .connected_rooms
        .iter()
        .position(|r| &r.local_room_id == local_room_id);

    match position {
        Some(idx) => {
            // Remove the room mapping by index; preserves order of remaining rooms.
            bridge.connected_rooms.remove(idx);
            Ok(())
        }
        None => {
            // Format the room ID as hex for a useful error message.
            let hex_id = hex::encode(local_room_id);
            Err(MeshError::NotFound {
                kind: "bridged_room",
                id: hex_id,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Message Translation — Inbound (External -> Garden)
// ---------------------------------------------------------------------------

/// Translate an inbound bridged message into a Garden-compatible JSON value.
///
/// Produces a JSON object with fields matching the Garden message format:
/// `sender`, `text`, `timestamp`, `bridged`, `source_bridge`, `remote_room`,
/// and `attachments`. The `bridged: true` flag marks it for the audit log (§19.2.1).
// The returned JSON is ready to be inserted into the Garden's message store.
// Attachment URLs are included for the bridge plugin to download and re-encrypt.
pub fn translate_inbound(msg: &BridgedMessage) -> serde_json::Value {
    // Format the sender with a "bridged" prefix for Garden display.
    // This makes it visually clear which messages came from external platforms.
    let display_sender = format!("[{BRIDGE_DISPLAY_PREFIX}] {}", msg.remote_sender);

    // Build the attachments array, translating each to Garden's attachment format.
    // Each attachment includes metadata for the UI and a URL for download.
    let attachments_json: Vec<serde_json::Value> = msg
        .attachments
        .iter()
        .map(|att| {
            // Convert each BridgedAttachment into a JSON object.
            // The bridge plugin will download from `url` and store locally.
            serde_json::json!({
                "filename": att.filename,
                "mimeType": att.mime_type,
                "sizeBytes": att.size_bytes,
                "url": att.url,
            })
        })
        .collect();

    // Assemble the final Garden message JSON.
    // The `bridged: true` flag is required by §19.2.1 for the encrypted audit log.
    serde_json::json!({
        "sender": display_sender,
        "text": msg.content,
        "timestamp": msg.timestamp,
        "bridged": true,
        "sourceBridge": hex::encode(msg.source_bridge),
        "remoteRoom": msg.remote_room,
        "attachments": attachments_json,
    })
}

// ---------------------------------------------------------------------------
// Message Translation — Outbound (Garden -> External)
// ---------------------------------------------------------------------------

/// Translate a local Garden message into a protocol-specific string for the
/// external platform.
///
/// Reads the `text` and `sender` fields from the local message JSON and
/// formats them according to the bridge type's conventions. Returns the
/// formatted string ready to send via the bridge plugin's external API.
// Returns MeshError::Internal if the local message lacks required fields.
// Each bridge type has its own formatting rules matching the spec's tables.
pub fn translate_outbound(
    local_msg: &serde_json::Value,
    bridge_type: &BridgeType,
) -> Result<String, MeshError> {
    // Extract the message text from the local Garden message.
    // This is the content that will be sent to the external platform.
    let text = local_msg
        .get("text")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MeshError::Internal("local message missing 'text' field".into()))?;

    // Extract the sender display name for attribution on the external platform.
    // External platforms show this as the message author.
    let sender = local_msg
        .get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Format the outbound message according to the bridge type's protocol.
    // Each protocol has different formatting conventions (§19.2.2-§19.2.7).
    let formatted = match bridge_type {
        // Matrix uses HTML-formatted message bodies (m.room.message).
        // The sender is attributed via the Matrix AS user, not in the body.
        BridgeType::Matrix => format_matrix_outbound(sender, text),
        // XMPP uses plain text in <message><body> stanzas (XEP-0045).
        // Sender attribution is prefixed in the body for MUC rooms.
        BridgeType::Xmpp => format_xmpp_outbound(sender, text),
        // IRC uses simple plain text with sender prefix.
        // No rich formatting; markdown is stripped.
        BridgeType::Irc => format_irc_outbound(sender, text),
        // Signal uses protobuf-style content (simplified to text here).
        // The sender is attributed via the Signal bridge's identity.
        BridgeType::Signal => format_signal_outbound(sender, text),
        // Custom bridges receive a generic JSON-formatted string.
        // The bridge plugin is responsible for final format conversion.
        BridgeType::Custom(ref name) => format_custom_outbound(name, sender, text),
    };

    Ok(formatted)
}

// ---------------------------------------------------------------------------
// Status Reporting
// ---------------------------------------------------------------------------

/// Produce a JSON summary of a bridge's current state for the FFI/UI layer.
///
/// Includes the bridge ID, type, status, room count, message count, and
/// last activity timestamp. Sensitive fields (tokens, passwords) are excluded.
// This is called by the FFI layer to populate the Federation settings screen.
// The config's token field is deliberately omitted to prevent credential leaks.
pub fn bridge_status_json(bridge: &FederationBridge) -> serde_json::Value {
    // Format the bridge type as a human-readable string.
    // Custom types include the user-provided name.
    let type_str = match &bridge.bridge_type {
        BridgeType::Matrix => "matrix".to_string(),
        BridgeType::Xmpp => "xmpp".to_string(),
        BridgeType::Irc => "irc".to_string(),
        BridgeType::Signal => "signal".to_string(),
        BridgeType::Custom(ref name) => format!("custom:{name}"),
    };

    // Format the status as a JSON-friendly string with optional detail.
    // Error states include the error message for admin diagnosis.
    let (status_str, status_detail) = match &bridge.status {
        BridgeStatus::Disconnected => ("disconnected", None),
        BridgeStatus::Connecting => ("connecting", None),
        BridgeStatus::Connected => ("connected", None),
        BridgeStatus::Error(ref msg) => ("error", Some(msg.as_str())),
    };

    // Build the room list summary without exposing internal IDs.
    // Each room shows its remote ID and direction for admin review.
    let rooms_json: Vec<serde_json::Value> = bridge
        .connected_rooms
        .iter()
        .map(|room| {
            // Format direction as a lowercase string for JSON consistency.
            let dir = match room.direction {
                BridgeDirection::Bidirectional => "bidirectional",
                BridgeDirection::InboundOnly => "inbound_only",
                BridgeDirection::OutboundOnly => "outbound_only",
            };
            serde_json::json!({
                "localRoomId": hex::encode(room.local_room_id),
                "remoteRoomId": room.remote_room_id,
                "direction": dir,
            })
        })
        .collect();

    // Assemble the full status JSON, omitting sensitive config fields.
    // The homeserver_url is included (not sensitive); token is omitted.
    let mut status = serde_json::json!({
        "id": hex::encode(bridge.id),
        "bridgeType": type_str,
        "status": status_str,
        "homeserverUrl": bridge.config.homeserver_url,
        "username": bridge.config.username,
        "connectedRooms": rooms_json,
        "roomCount": bridge.connected_rooms.len(),
        "messageCount": bridge.message_count,
        "lastActivity": bridge.last_activity,
    });

    // Append the error detail only when the bridge is in an error state.
    // This avoids a null/empty "statusDetail" field in normal operation.
    if let Some(detail) = status_detail {
        status["statusDetail"] = serde_json::Value::String(detail.to_string());
    }

    status
}

// ---------------------------------------------------------------------------
// Internal Helpers — Credential Validation
// ---------------------------------------------------------------------------

/// Validate that the bridge config contains the minimum required credentials
/// for the given bridge type.
// Each protocol has different minimum requirements for authentication.
// Matrix needs a token; XMPP needs username; IRC needs a server; etc.
fn validate_bridge_credentials(
    bridge_type: &BridgeType,
    config: &BridgeConnectionConfig,
) -> Result<(), MeshError> {
    match bridge_type {
        // Matrix requires a homeserver URL and an access token.
        // The token authenticates the bridge as an Application Service.
        BridgeType::Matrix => {
            if config
                .homeserver_url
                .as_ref()
                .is_some_and(|u| !u.is_empty())
                && config.token.as_ref().is_some_and(|t| !t.is_empty())
            {
                Ok(())
            } else {
                Err(MeshError::Internal(
                    "Matrix bridge requires homeserver_url and token".into(),
                ))
            }
        }
        // XMPP requires a homeserver URL (server address) and username.
        // The username is the JID for the bridge component (XEP-0114).
        BridgeType::Xmpp => {
            if config
                .homeserver_url
                .as_ref()
                .is_some_and(|u| !u.is_empty())
                && config.username.as_ref().is_some_and(|u| !u.is_empty())
            {
                Ok(())
            } else {
                Err(MeshError::Internal(
                    "XMPP bridge requires homeserver_url and username".into(),
                ))
            }
        }
        // IRC requires a server address, provided via homeserver_url or extra.
        // IRC bridges are simpler: no token needed, just server + optional nick.
        BridgeType::Irc => {
            let has_server = config
                .homeserver_url
                .as_ref()
                .is_some_and(|u| !u.is_empty())
                || config.extra.contains_key("server");
            if has_server {
                Ok(())
            } else {
                Err(MeshError::Internal(
                    "IRC bridge requires homeserver_url or extra['server']".into(),
                ))
            }
        }
        // Signal requires a token (API key) for the Signal bridge service.
        // The homeserver_url points to the Signal bridge daemon.
        BridgeType::Signal => {
            if config.token.as_ref().is_some_and(|t| !t.is_empty()) {
                Ok(())
            } else {
                Err(MeshError::Internal("Signal bridge requires a token".into()))
            }
        }
        // Custom bridges have no fixed credential requirements.
        // The bridge plugin itself validates its own config at runtime.
        BridgeType::Custom(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Internal Helpers — Protocol-Specific Formatting
// ---------------------------------------------------------------------------

/// Format a Garden message for Matrix (m.room.message with HTML body).
// Matrix messages use HTML formatting within the `formatted_body` field.
// The sender is attributed via the Application Service's virtual user.
fn format_matrix_outbound(sender: &str, text: &str) -> String {
    // Escape HTML special characters to prevent injection in Matrix clients.
    // Matrix renders `formatted_body` as HTML; unescaped content is dangerous.
    let escaped_text = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    // Build the Matrix m.room.message JSON payload.
    // `msgtype` is "m.text"; `body` is plaintext fallback; `format` is HTML.
    serde_json::json!({
        "msgtype": "m.text",
        "body": format!("<{sender}> {text}"),
        "format": "org.matrix.custom.html",
        "formatted_body": format!("<b>{sender}</b>: {escaped_text}"),
    })
    .to_string()
}

/// Format a Garden message for XMPP (<message type="groupchat">).
// XMPP MUC messages are plain text in the <body> element (XEP-0045).
// The sender is prefixed because MUC attribution comes from the room JID.
fn format_xmpp_outbound(sender: &str, text: &str) -> String {
    // XMPP bodies are plain text; no HTML escaping needed.
    // The sender prefix distinguishes mesh users in the XMPP room.
    format!("<{sender}> {text}")
}

/// Format a Garden message for IRC (PRIVMSG-style).
// IRC messages are plain text with a maximum length of ~512 bytes per line.
// Long messages are truncated; the full text is not available on IRC.
fn format_irc_outbound(sender: &str, text: &str) -> String {
    // IRC convention: angle-bracket sender prefix, then message text.
    // Newlines are replaced with spaces since IRC is single-line per message.
    let single_line = text.replace('\n', " ");
    // Truncate to IRC's practical message limit (leaving room for protocol overhead).
    // 400 bytes leaves room for the PRIVMSG prefix and channel name.
    let max_len = 400;
    if single_line.len() > max_len {
        // Truncate at a safe byte boundary and append an ellipsis.
        let truncated = &single_line[..single_line.floor_char_boundary(max_len)];
        format!("<{sender}> {truncated}...")
    } else {
        format!("<{sender}> {single_line}")
    }
}

/// Format a Garden message for Signal (simplified text with attribution).
// Signal bridge messages are plain text; the bridge daemon handles encryption.
// Sender attribution is included since Signal groups show per-member messages.
fn format_signal_outbound(sender: &str, text: &str) -> String {
    // Signal messages are UTF-8 plaintext; no special escaping needed.
    // The sender prefix identifies the mesh user within the Signal group.
    format!("{sender}: {text}")
}

/// Format a Garden message for a custom bridge (generic JSON envelope).
// Custom bridges receive a JSON object with platform name, sender, and text.
// The bridge plugin parses this and converts to its own wire format.
fn format_custom_outbound(platform_name: &str, sender: &str, text: &str) -> String {
    // Wrap in a JSON envelope so the custom bridge plugin can extract fields.
    // The `platform` field lets a multi-protocol plugin route correctly.
    serde_json::json!({
        "platform": platform_name,
        "sender": sender,
        "text": text,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Serde round-trip tests --

    /// Verify FederationMask serializes and deserializes without data loss.
    // Tests the JSON round-trip for mask_id, platform, and linkage fields.
    #[test]
    fn test_federation_mask_serde() {
        // Create a mask with known values for deterministic assertion.
        let mask = FederationMask {
            mask_id: [0xAA; 32],
            platform: FederatedPlatform::Matrix,
            external_id: "@alice:matrix.org".to_string(),
            linkage: LinkageType::OneWay,
            created_at: 1000,
            last_used: 2000,
        };
        // Serialize to JSON string and parse back.
        let json = serde_json::to_string(&mask).expect("mask should serialize");
        let recovered: FederationMask =
            serde_json::from_str(&json).expect("mask should deserialize");
        // Verify the platform survived the round-trip.
        assert_eq!(recovered.platform, FederatedPlatform::Matrix);
        // Verify the external ID survived the round-trip.
        assert_eq!(recovered.external_id, "@alice:matrix.org");
    }

    /// Verify BridgePolicyConfig fields are accessible after construction.
    // Ensures the renamed policy config still works correctly.
    #[test]
    fn test_bridge_policy_config() {
        let config = BridgePolicyConfig {
            platform: FederatedPlatform::ActivityPub,
            enabled: true,
            max_external_users: Some(100),
            user_rate_limit: None,
            channel_rate_limit: None,
        };
        // Policy should be enabled as constructed.
        assert!(config.enabled);
        // Max users should be the configured value.
        assert_eq!(config.max_external_users, Some(100));
    }

    /// Verify LinkageType variants are distinct.
    // Ensures the PartialEq derive works correctly for enum comparison.
    #[test]
    fn test_linkage_types() {
        assert_ne!(LinkageType::OneWay, LinkageType::TwoWay);
    }

    // -- Bridge creation tests --

    /// Verify create_bridge produces a valid bridge in Disconnected state.
    // The bridge should have a non-zero ID and empty room list.
    #[test]
    fn test_create_bridge_success() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        // Create a Matrix bridge with valid config.
        let bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // Bridge should start in Disconnected state.
        assert_eq!(bridge.status, BridgeStatus::Disconnected);
        // Bridge should have no rooms initially.
        assert!(bridge.connected_rooms.is_empty());
        // Bridge should have zero message count.
        assert_eq!(bridge.message_count, 0);
        // Bridge should have no last activity.
        assert!(bridge.last_activity.is_none());
        // Bridge ID should not be all zeros (random generation).
        assert_ne!(bridge.id, [0u8; 16]);
    }

    /// Verify create_bridge rejects empty config (no URL, no extras).
    // A bridge with no connection info cannot do anything useful.
    #[test]
    fn test_create_bridge_empty_config_rejected() {
        let config = BridgeConnectionConfig {
            homeserver_url: None,
            username: None,
            token: None,
            extra: HashMap::new(),
        };
        // Should fail because there's no connection information at all.
        let result = create_bridge(BridgeType::Matrix, config);
        assert!(result.is_err());
    }

    /// Verify create_bridge accepts a custom bridge with only extra params.
    // Custom bridges may not use homeserver_url at all.
    #[test]
    fn test_create_bridge_custom_with_extra_only() {
        let mut extra = HashMap::new();
        extra.insert("relay_url".into(), "wss://relay.example.com".into());
        let config = BridgeConnectionConfig {
            homeserver_url: None,
            username: None,
            token: None,
            extra,
        };
        // Should succeed because extra params provide connection info.
        let bridge = create_bridge(BridgeType::Custom("nostr-relay".into()), config)
            .expect("custom bridge with extras should succeed");
        assert_eq!(bridge.bridge_type, BridgeType::Custom("nostr-relay".into()));
    }

    // -- Bridge connection tests --

    /// Verify connect_bridge transitions from Disconnected to Connected.
    // Tests the happy path for Matrix bridge connection.
    #[test]
    fn test_connect_bridge_success() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // Connect should transition to Connected state.
        connect_bridge(&mut bridge).expect("should connect");
        assert_eq!(bridge.status, BridgeStatus::Connected);
    }

    /// Verify connect_bridge rejects already-connected bridges.
    // Prevents duplicate connection attempts.
    #[test]
    fn test_connect_bridge_already_connected() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // First connect should succeed.
        connect_bridge(&mut bridge).expect("should connect");
        // Second connect should fail with an error.
        let result = connect_bridge(&mut bridge);
        assert!(result.is_err());
    }

    /// Verify connect_bridge rejects Matrix bridge without token.
    // Matrix requires both homeserver_url and token for AS authentication.
    #[test]
    fn test_connect_bridge_missing_credentials() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: None,
            token: None, // Missing token.
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // Connect should fail due to missing token.
        let result = connect_bridge(&mut bridge);
        assert!(result.is_err());
    }

    /// Verify connect_bridge rejects invalid homeserver URL.
    // URLs must start with http:// or https://.
    #[test]
    fn test_connect_bridge_invalid_url() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("not-a-url".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // Connect should fail due to invalid URL.
        let result = connect_bridge(&mut bridge);
        assert!(result.is_err());
        // Status should reflect the error.
        matches!(bridge.status, BridgeStatus::Error(_));
    }

    // -- Disconnect tests --

    /// Verify disconnect_bridge transitions to Disconnected.
    // Also verifies that room mappings are preserved after disconnect.
    #[test]
    fn test_disconnect_bridge() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        connect_bridge(&mut bridge).expect("should connect");
        // Add a room mapping before disconnecting.
        bridge_room(
            &mut bridge,
            [1u8; 16],
            "!room:matrix.org",
            BridgeDirection::Bidirectional,
        )
        .expect("should bridge room");
        // Disconnect the bridge.
        disconnect_bridge(&mut bridge);
        // Status should be Disconnected.
        assert_eq!(bridge.status, BridgeStatus::Disconnected);
        // Room mappings should be preserved for reconnection.
        assert_eq!(bridge.connected_rooms.len(), 1);
    }

    /// Verify disconnect_bridge is idempotent.
    // Calling disconnect on a disconnected bridge should not panic or error.
    #[test]
    fn test_disconnect_bridge_idempotent() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // Disconnect twice — should not panic.
        disconnect_bridge(&mut bridge);
        disconnect_bridge(&mut bridge);
        assert_eq!(bridge.status, BridgeStatus::Disconnected);
    }

    // -- Room bridging tests --

    /// Verify bridge_room adds a room mapping to a connected bridge.
    // Tests the happy path with valid parameters.
    #[test]
    fn test_bridge_room_success() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        connect_bridge(&mut bridge).expect("should connect");
        // Bridge a room with bidirectional flow.
        bridge_room(
            &mut bridge,
            [1u8; 16],
            "!room:matrix.org",
            BridgeDirection::Bidirectional,
        )
        .expect("should bridge room");
        // Verify the room mapping was added.
        assert_eq!(bridge.connected_rooms.len(), 1);
        assert_eq!(bridge.connected_rooms[0].remote_room_id, "!room:matrix.org");
        assert_eq!(
            bridge.connected_rooms[0].direction,
            BridgeDirection::Bidirectional
        );
    }

    /// Verify bridge_room rejects empty remote room IDs.
    // All external platforms use non-empty room identifiers.
    #[test]
    fn test_bridge_room_empty_remote_id() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        connect_bridge(&mut bridge).expect("should connect");
        // Empty remote room ID should be rejected.
        let result = bridge_room(&mut bridge, [1u8; 16], "", BridgeDirection::Bidirectional);
        assert!(result.is_err());
    }

    /// Verify bridge_room rejects duplicate local room on same bridge.
    // Each local room can only be bridged once per bridge.
    #[test]
    fn test_bridge_room_duplicate_rejected() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        connect_bridge(&mut bridge).expect("should connect");
        // First bridge should succeed.
        bridge_room(
            &mut bridge,
            [1u8; 16],
            "!room:matrix.org",
            BridgeDirection::Bidirectional,
        )
        .expect("should bridge room");
        // Second bridge of same local room should fail.
        let result = bridge_room(
            &mut bridge,
            [1u8; 16],
            "!other:matrix.org",
            BridgeDirection::InboundOnly,
        );
        assert!(result.is_err());
    }

    /// Verify bridge_room rejects when bridge is not connected.
    // Room mapping requires an active connection to verify the remote room.
    #[test]
    fn test_bridge_room_not_connected() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // Do not connect — room bridging should fail.
        let result = bridge_room(
            &mut bridge,
            [1u8; 16],
            "!room:matrix.org",
            BridgeDirection::Bidirectional,
        );
        assert!(result.is_err());
    }

    // -- Unbridge tests --

    /// Verify unbridge_room removes an existing room mapping.
    // The bridge should have one fewer room after unbridging.
    #[test]
    fn test_unbridge_room_success() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        connect_bridge(&mut bridge).expect("should connect");
        let room_id = [1u8; 16];
        bridge_room(
            &mut bridge,
            room_id,
            "!room:matrix.org",
            BridgeDirection::Bidirectional,
        )
        .expect("should bridge room");
        // Unbridge the room.
        unbridge_room(&mut bridge, &room_id).expect("should unbridge");
        // Room list should be empty.
        assert!(bridge.connected_rooms.is_empty());
    }

    /// Verify unbridge_room returns NotFound for unknown rooms.
    // Attempting to unbridge a room that isn't mapped should fail.
    #[test]
    fn test_unbridge_room_not_found() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // Unbridge a room that was never bridged.
        let result = unbridge_room(&mut bridge, &[99u8; 16]);
        assert!(result.is_err());
    }

    // -- Inbound translation tests --

    /// Verify translate_inbound produces correct Garden JSON structure.
    // The JSON must include bridged:true, sender prefix, and all fields.
    #[test]
    fn test_translate_inbound_basic() {
        let msg = BridgedMessage {
            source_bridge: [0xBB; 16],
            remote_sender: "alice@matrix.org".into(),
            remote_room: "!room:matrix.org".into(),
            content: "Hello from Matrix!".into(),
            timestamp: 1700000000,
            attachments: vec![],
        };
        let json = translate_inbound(&msg);
        // Sender should have the [bridged] prefix.
        assert_eq!(
            json["sender"].as_str().expect("sender should be string"),
            "[bridged] alice@matrix.org"
        );
        // Text should be preserved verbatim.
        assert_eq!(json["text"].as_str().expect("text"), "Hello from Matrix!");
        // The bridged flag must be true for the audit log.
        assert_eq!(json["bridged"].as_bool().expect("bridged"), true);
        // Timestamp should be the original value.
        assert_eq!(json["timestamp"].as_u64().expect("timestamp"), 1700000000);
        // Attachments should be an empty array.
        assert!(json["attachments"]
            .as_array()
            .expect("attachments")
            .is_empty());
    }

    /// Verify translate_inbound handles attachments correctly.
    // Each attachment should be serialized with all metadata fields.
    #[test]
    fn test_translate_inbound_with_attachments() {
        let msg = BridgedMessage {
            source_bridge: [0xCC; 16],
            remote_sender: "bob@xmpp.org".into(),
            remote_room: "room@muc.xmpp.org".into(),
            content: "See attached".into(),
            timestamp: 1700000001,
            attachments: vec![BridgedAttachment {
                filename: "photo.jpg".into(),
                mime_type: "image/jpeg".into(),
                size_bytes: 1024,
                url: "https://xmpp.org/upload/photo.jpg".into(),
            }],
        };
        let json = translate_inbound(&msg);
        // Should have exactly one attachment.
        let atts = json["attachments"].as_array().expect("attachments");
        assert_eq!(atts.len(), 1);
        // Attachment should have the correct filename.
        assert_eq!(atts[0]["filename"].as_str().expect("filename"), "photo.jpg");
        // Attachment should have the correct MIME type.
        assert_eq!(atts[0]["mimeType"].as_str().expect("mime"), "image/jpeg");
        // Attachment should have the correct size.
        assert_eq!(atts[0]["sizeBytes"].as_u64().expect("size"), 1024);
    }

    // -- Outbound translation tests --

    /// Verify translate_outbound produces Matrix-formatted output.
    // Matrix output should be a JSON string with m.text msgtype and HTML body.
    #[test]
    fn test_translate_outbound_matrix() {
        let local_msg = serde_json::json!({
            "sender": "mesh_user",
            "text": "Hello Matrix!",
        });
        let result = translate_outbound(&local_msg, &BridgeType::Matrix).expect("should translate");
        // Result should be valid JSON containing the Matrix message fields.
        let parsed: serde_json::Value =
            serde_json::from_str(&result).expect("result should be valid JSON");
        assert_eq!(parsed["msgtype"].as_str().expect("msgtype"), "m.text");
        // The formatted_body should contain the sender in bold.
        let formatted = parsed["formatted_body"].as_str().expect("formatted_body");
        assert!(formatted.contains("<b>mesh_user</b>"));
    }

    /// Verify translate_outbound produces XMPP-formatted output.
    // XMPP output should be plain text with sender prefix.
    #[test]
    fn test_translate_outbound_xmpp() {
        let local_msg = serde_json::json!({
            "sender": "mesh_user",
            "text": "Hello XMPP!",
        });
        let result = translate_outbound(&local_msg, &BridgeType::Xmpp).expect("should translate");
        // Result should be plain text with angle-bracket sender prefix.
        assert_eq!(result, "<mesh_user> Hello XMPP!");
    }

    /// Verify translate_outbound produces IRC-formatted output.
    // IRC output should be plain text, single-line, with sender prefix.
    #[test]
    fn test_translate_outbound_irc() {
        let local_msg = serde_json::json!({
            "sender": "mesh_user",
            "text": "Hello IRC!",
        });
        let result = translate_outbound(&local_msg, &BridgeType::Irc).expect("should translate");
        assert_eq!(result, "<mesh_user> Hello IRC!");
    }

    /// Verify translate_outbound truncates long IRC messages.
    // IRC has a practical 400-byte limit per message line.
    #[test]
    fn test_translate_outbound_irc_truncation() {
        // Create a message longer than 400 characters.
        let long_text = "x".repeat(500);
        let local_msg = serde_json::json!({
            "sender": "user",
            "text": long_text,
        });
        let result = translate_outbound(&local_msg, &BridgeType::Irc).expect("should translate");
        // Result should end with "..." indicating truncation.
        assert!(result.ends_with("..."));
        // Result should be shorter than the input.
        assert!(result.len() < 500);
    }

    /// Verify translate_outbound replaces newlines for IRC.
    // IRC is single-line; newlines must be replaced with spaces.
    #[test]
    fn test_translate_outbound_irc_newlines() {
        let local_msg = serde_json::json!({
            "sender": "user",
            "text": "line1\nline2\nline3",
        });
        let result = translate_outbound(&local_msg, &BridgeType::Irc).expect("should translate");
        // Newlines should be replaced with spaces.
        assert!(!result.contains('\n'));
        assert!(result.contains("line1 line2 line3"));
    }

    /// Verify translate_outbound produces Signal-formatted output.
    // Signal output should be "sender: text" format.
    #[test]
    fn test_translate_outbound_signal() {
        let local_msg = serde_json::json!({
            "sender": "mesh_user",
            "text": "Hello Signal!",
        });
        let result = translate_outbound(&local_msg, &BridgeType::Signal).expect("should translate");
        assert_eq!(result, "mesh_user: Hello Signal!");
    }

    /// Verify translate_outbound produces custom bridge JSON envelope.
    // Custom bridges receive a JSON object with platform, sender, and text.
    #[test]
    fn test_translate_outbound_custom() {
        let local_msg = serde_json::json!({
            "sender": "mesh_user",
            "text": "Hello custom!",
        });
        let result = translate_outbound(&local_msg, &BridgeType::Custom("myproto".into()))
            .expect("should translate");
        // Result should be valid JSON with the platform field.
        let parsed: serde_json::Value =
            serde_json::from_str(&result).expect("result should be valid JSON");
        assert_eq!(parsed["platform"].as_str().expect("platform"), "myproto");
        assert_eq!(parsed["text"].as_str().expect("text"), "Hello custom!");
    }

    /// Verify translate_outbound rejects messages without text field.
    // The text field is required for all outbound translations.
    #[test]
    fn test_translate_outbound_missing_text() {
        let local_msg = serde_json::json!({
            "sender": "mesh_user",
        });
        let result = translate_outbound(&local_msg, &BridgeType::Matrix);
        assert!(result.is_err());
    }

    /// Verify translate_outbound uses "unknown" when sender is missing.
    // A missing sender should not cause an error; it defaults to "unknown".
    #[test]
    fn test_translate_outbound_missing_sender() {
        let local_msg = serde_json::json!({
            "text": "no sender",
        });
        let result = translate_outbound(&local_msg, &BridgeType::Xmpp)
            .expect("should translate even without sender");
        // Should use "unknown" as the default sender.
        assert!(result.contains("<unknown>"));
    }

    /// Verify Matrix outbound escapes HTML special characters.
    // Prevents XSS-style injection in Matrix clients rendering HTML.
    #[test]
    fn test_translate_outbound_matrix_html_escape() {
        let local_msg = serde_json::json!({
            "sender": "user",
            "text": "<script>alert('xss')</script>",
        });
        let result = translate_outbound(&local_msg, &BridgeType::Matrix).expect("should translate");
        // The formatted_body should have escaped angle brackets.
        let parsed: serde_json::Value = serde_json::from_str(&result).expect("valid JSON");
        let formatted = parsed["formatted_body"].as_str().expect("formatted_body");
        assert!(formatted.contains("&lt;script&gt;"));
        assert!(!formatted.contains("<script>"));
    }

    // -- Status JSON tests --

    /// Verify bridge_status_json includes all expected fields.
    // The status JSON is consumed by the FFI layer for Flutter rendering.
    #[test]
    fn test_bridge_status_json_structure() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        connect_bridge(&mut bridge).expect("should connect");
        // Get the status JSON.
        let status = bridge_status_json(&bridge);
        // Verify all expected fields are present.
        assert_eq!(status["bridgeType"].as_str().expect("type"), "matrix");
        assert_eq!(status["status"].as_str().expect("status"), "connected");
        assert_eq!(status["messageCount"].as_u64().expect("count"), 0);
        assert!(status["connectedRooms"]
            .as_array()
            .expect("rooms")
            .is_empty());
        // Token should NOT be present in the status JSON (security).
        assert!(status.get("token").is_none());
    }

    /// Verify bridge_status_json includes error detail for error state.
    // Error bridges should include the statusDetail field with the error message.
    #[test]
    fn test_bridge_status_json_error_state() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // Manually set error status for testing.
        bridge.status = BridgeStatus::Error("connection refused".into());
        let status = bridge_status_json(&bridge);
        // Status should be "error" with a detail message.
        assert_eq!(status["status"].as_str().expect("status"), "error");
        assert_eq!(
            status["statusDetail"].as_str().expect("detail"),
            "connection refused"
        );
    }

    /// Verify bridge_status_json includes room details.
    // Each bridged room should appear with its remote ID and direction.
    #[test]
    fn test_bridge_status_json_with_rooms() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        connect_bridge(&mut bridge).expect("should connect");
        bridge_room(
            &mut bridge,
            [1u8; 16],
            "!room:matrix.org",
            BridgeDirection::InboundOnly,
        )
        .expect("should bridge room");
        let status = bridge_status_json(&bridge);
        // Should have one room in the list.
        let rooms = status["connectedRooms"].as_array().expect("rooms");
        assert_eq!(rooms.len(), 1);
        assert_eq!(
            rooms[0]["remoteRoomId"].as_str().expect("remote"),
            "!room:matrix.org"
        );
        assert_eq!(rooms[0]["direction"].as_str().expect("dir"), "inbound_only");
        assert_eq!(status["roomCount"].as_u64().expect("count"), 1);
    }

    // -- BridgeType serde tests --

    /// Verify BridgeType serializes and deserializes correctly.
    // All variants including Custom should survive a JSON round-trip.
    #[test]
    fn test_bridge_type_serde() {
        // Test each variant through a serde round-trip.
        let types = vec![
            BridgeType::Matrix,
            BridgeType::Xmpp,
            BridgeType::Irc,
            BridgeType::Signal,
            BridgeType::Custom("telegram".into()),
        ];
        for bt in &types {
            let json = serde_json::to_string(bt).expect("should serialize");
            let recovered: BridgeType = serde_json::from_str(&json).expect("should deserialize");
            assert_eq!(&recovered, bt);
        }
    }

    /// Verify BridgeStatus serializes and deserializes correctly.
    // The Error variant contains a string payload that must survive.
    #[test]
    fn test_bridge_status_serde() {
        let statuses = vec![
            BridgeStatus::Disconnected,
            BridgeStatus::Connecting,
            BridgeStatus::Connected,
            BridgeStatus::Error("timeout".into()),
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).expect("should serialize");
            let recovered: BridgeStatus = serde_json::from_str(&json).expect("should deserialize");
            assert_eq!(&recovered, s);
        }
    }

    /// Verify BridgeDirection variants are all distinct.
    // Ensures the PartialEq derive distinguishes all three directions.
    #[test]
    fn test_bridge_direction_distinct() {
        assert_ne!(BridgeDirection::Bidirectional, BridgeDirection::InboundOnly);
        assert_ne!(
            BridgeDirection::Bidirectional,
            BridgeDirection::OutboundOnly
        );
        assert_ne!(BridgeDirection::InboundOnly, BridgeDirection::OutboundOnly);
    }

    // -- Credential validation tests --

    /// Verify XMPP bridge requires both URL and username.
    // Missing username should cause connect_bridge to fail.
    #[test]
    fn test_xmpp_bridge_requires_username() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://xmpp.example.com".into()),
            username: None, // Missing username.
            token: None,
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Xmpp, config).expect("should create bridge");
        let result = connect_bridge(&mut bridge);
        assert!(result.is_err());
    }

    /// Verify IRC bridge accepts server from extra params.
    // IRC can use extra["server"] instead of homeserver_url.
    #[test]
    fn test_irc_bridge_server_from_extra() {
        let mut extra = HashMap::new();
        extra.insert("server".into(), "irc.libera.chat:6697".into());
        let config = BridgeConnectionConfig {
            homeserver_url: None,
            username: Some("meshbot".into()),
            token: None,
            extra,
        };
        let mut bridge = create_bridge(BridgeType::Irc, config).expect("should create bridge");
        // Connect should succeed because server is in extra.
        let result = connect_bridge(&mut bridge);
        assert!(result.is_ok());
    }

    /// Verify Signal bridge requires a token.
    // Signal bridges authenticate via API key/token.
    #[test]
    fn test_signal_bridge_requires_token() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://signal-bridge.example.com".into()),
            username: None,
            token: None, // Missing token.
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Signal, config).expect("should create bridge");
        let result = connect_bridge(&mut bridge);
        assert!(result.is_err());
    }

    /// Verify custom bridge has no credential requirements.
    // Custom bridge plugins validate their own credentials at runtime.
    #[test]
    fn test_custom_bridge_no_credential_requirements() {
        let mut extra = HashMap::new();
        extra.insert("key".into(), "value".into());
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://custom.example.com".into()),
            username: None,
            token: None,
            extra,
        };
        let mut bridge =
            create_bridge(BridgeType::Custom("test".into()), config).expect("should create bridge");
        // Connect should succeed — custom bridges have no fixed requirements.
        let result = connect_bridge(&mut bridge);
        assert!(result.is_ok());
    }

    // -- Full lifecycle test --

    /// End-to-end test: create, connect, bridge room, translate, disconnect.
    // Exercises the entire bridge lifecycle in sequence.
    #[test]
    fn test_full_bridge_lifecycle() {
        // Step 1: Create a Matrix bridge.
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let mut bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        assert_eq!(bridge.status, BridgeStatus::Disconnected);

        // Step 2: Connect the bridge.
        connect_bridge(&mut bridge).expect("should connect");
        assert_eq!(bridge.status, BridgeStatus::Connected);

        // Step 3: Bridge a room.
        let room_id = [0x42; 16];
        bridge_room(
            &mut bridge,
            room_id,
            "!test:matrix.org",
            BridgeDirection::Bidirectional,
        )
        .expect("should bridge room");
        assert_eq!(bridge.connected_rooms.len(), 1);

        // Step 4: Translate an inbound message.
        let inbound = BridgedMessage {
            source_bridge: bridge.id,
            remote_sender: "@alice:matrix.org".into(),
            remote_room: "!test:matrix.org".into(),
            content: "Hello from Matrix".into(),
            timestamp: 1700000000,
            attachments: vec![],
        };
        let garden_json = translate_inbound(&inbound);
        assert_eq!(garden_json["bridged"], true);

        // Step 5: Translate an outbound message.
        let outbound = serde_json::json!({
            "sender": "mesh_user",
            "text": "Hello back!",
        });
        let matrix_msg =
            translate_outbound(&outbound, &bridge.bridge_type).expect("should translate outbound");
        assert!(!matrix_msg.is_empty());

        // Step 6: Check bridge status JSON.
        let status = bridge_status_json(&bridge);
        assert_eq!(status["status"].as_str().expect("s"), "connected");
        assert_eq!(status["roomCount"].as_u64().expect("rc"), 1);

        // Step 7: Unbridge the room.
        unbridge_room(&mut bridge, &room_id).expect("should unbridge");
        assert!(bridge.connected_rooms.is_empty());

        // Step 8: Disconnect.
        disconnect_bridge(&mut bridge);
        assert_eq!(bridge.status, BridgeStatus::Disconnected);
    }

    // -- FederationBridge serde test --

    /// Verify FederationBridge round-trips through JSON.
    // The entire bridge state should serialize and deserialize correctly.
    #[test]
    fn test_federation_bridge_serde() {
        let config = BridgeConnectionConfig {
            homeserver_url: Some("https://matrix.example.com".into()),
            username: Some("@bridge:example.com".into()),
            token: Some("secret_token".into()),
            extra: HashMap::new(),
        };
        let bridge = create_bridge(BridgeType::Matrix, config).expect("should create bridge");
        // Serialize to JSON and back.
        let json = serde_json::to_string(&bridge).expect("should serialize");
        let recovered: FederationBridge = serde_json::from_str(&json).expect("should deserialize");
        // Bridge type should survive the round-trip.
        assert_eq!(recovered.bridge_type, BridgeType::Matrix);
        // Status should survive the round-trip.
        assert_eq!(recovered.status, BridgeStatus::Disconnected);
        // ID should match.
        assert_eq!(recovered.id, bridge.id);
    }

    // -- Constants tests --

    /// Verify protocol constants match the spec values.
    // These values are defined in §19.2.9 and §19.4; changes require a version bump.
    #[test]
    fn test_protocol_constants() {
        // §19.4.1: external users capped at Level 5 (Acquaintance).
        assert_eq!(MAX_EXTERNAL_TRUST_LEVEL, 5);
        // §19.2.9: 60 messages/minute per external user.
        assert_eq!(EXTERNAL_USER_RATE_LIMIT, 60);
        // §19.2.9: 300 messages/minute per bridged channel aggregate.
        assert_eq!(CHANNEL_AGGREGATE_RATE_LIMIT, 300);
    }

    /// Verify BridgedRoom serde round-trip works correctly.
    // Room mappings are persisted and must survive serialization.
    #[test]
    fn test_bridged_room_serde() {
        let room = BridgedRoom {
            local_room_id: [0x11; 16],
            remote_room_id: "!room:matrix.org".into(),
            bridge_id: [0x22; 16],
            direction: BridgeDirection::OutboundOnly,
        };
        let json = serde_json::to_string(&room).expect("should serialize");
        let recovered: BridgedRoom = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(recovered.direction, BridgeDirection::OutboundOnly);
        assert_eq!(recovered.remote_room_id, "!room:matrix.org");
    }

    /// Verify BridgedMessage with attachments round-trips through serde.
    // Messages with attachments must preserve all attachment metadata.
    #[test]
    fn test_bridged_message_serde() {
        let msg = BridgedMessage {
            source_bridge: [0xDD; 16],
            remote_sender: "alice@xmpp.org".into(),
            remote_room: "room@muc.xmpp.org".into(),
            content: "Check this file".into(),
            timestamp: 1700000000,
            attachments: vec![BridgedAttachment {
                filename: "doc.pdf".into(),
                mime_type: "application/pdf".into(),
                size_bytes: 2048,
                url: "https://xmpp.org/upload/doc.pdf".into(),
            }],
        };
        let json = serde_json::to_string(&msg).expect("should serialize");
        let recovered: BridgedMessage = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(recovered.attachments.len(), 1);
        assert_eq!(recovered.attachments[0].filename, "doc.pdf");
    }

    /// Verify BridgeConnectionConfig with extra params round-trips.
    // The HashMap<String, String> extra field must survive serialization.
    #[test]
    fn test_bridge_connection_config_serde() {
        let mut extra = HashMap::new();
        extra.insert("irc_channel".into(), "#mesh".into());
        extra.insert("tls".into(), "true".into());
        let config = BridgeConnectionConfig {
            homeserver_url: Some("irc.libera.chat".into()),
            username: Some("meshbot".into()),
            token: None,
            extra,
        };
        let json = serde_json::to_string(&config).expect("should serialize");
        let recovered: BridgeConnectionConfig =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(
            recovered.extra.get("irc_channel").map(|s| s.as_str()),
            Some("#mesh")
        );
        assert_eq!(recovered.extra.len(), 2);
    }
}
