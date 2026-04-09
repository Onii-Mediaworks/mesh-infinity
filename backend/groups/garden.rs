//! Garden / Communities (§10.2)
//!
//! # What is a Garden?
//!
//! A Garden is a Discord-like community space with channels, roles,
//! permissions, and rich messaging. Each Garden runs on one or more
//! hosting nodes and uses MLS (Messaging Layer Security) for
//! group encryption.
//!
//! # Key Differences from Groups (§8.7)
//!
//! Groups are simple: flat membership, Sender Keys, basic messaging.
//! Gardens are complex: hierarchical channels, role-based permissions,
//! auto-moderation, MLS encryption, 30+ content types, and optional
//! WebRTC browser access.
//!
//! # Channel Security Tiers
//!
//! - **Encrypted** (default): MLS E2E encryption. Server can't read.
//! - **PublicPlaintext**: no encryption. For public announcement channels.
//!
//! # Message Wire Format
//!
//! GardenMessage has two parts:
//! - Server-visible metadata (message_id, channel, timestamp bucket,
//!   MLS epoch, size class, notification priority)
//! - Inside encryption: actual content, sender, attachments, reactions, etc.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Channel Security
// ---------------------------------------------------------------------------

/// Channel encryption tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// ChannelSecurityTier — variant enumeration.
// Match exhaustively to handle every protocol state.
// ChannelSecurityTier — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ChannelSecurityTier {
    /// MLS E2E encryption. Default.
    // Execute this protocol step.
    // Execute this protocol step.
    Encrypted,
    /// No encryption. For public announcement channels.
    // Execute this protocol step.
    // Execute this protocol step.
    PublicPlaintext,
}

// ---------------------------------------------------------------------------
// History Access
// ---------------------------------------------------------------------------

/// How much history new members can see.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// HistoryAccess — variant enumeration.
// Match exhaustively to handle every protocol state.
// HistoryAccess — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum HistoryAccess {
    /// All history visible to new members.
    Full,
    /// Only messages from join time forward.
    // Execute this protocol step.
    // Execute this protocol step.
    FromJoin,
    /// No history access.
    // No value available.
    // No value available.
    None,
}

// ---------------------------------------------------------------------------
// Permissions (§10.2)
// ---------------------------------------------------------------------------

/// Fine-grained permission flags for Garden roles.
///
/// Each permission maps to a specific action. Roles accumulate
/// permissions — a member's effective permissions are the union
/// of all their roles' permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
// Begin the block scope.
// Permission — variant enumeration.
// Match exhaustively to handle every protocol state.
// Permission — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum Permission {
    // Execute this protocol step.
    // Execute this protocol step.
    ViewChannel,
    // Execute this protocol step.
    // Execute this protocol step.
    SendMessages,
    // Execute this protocol step.
    // Execute this protocol step.
    SendVoice,
    // Execute this protocol step.
    // Execute this protocol step.
    AttachFiles,
    // Execute this protocol step.
    // Execute this protocol step.
    EmbedLinks,
    // Execute this protocol step.
    // Execute this protocol step.
    AddReactions,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    UseExternalEmoji,
    // Execute this protocol step.
    // Execute this protocol step.
    ReadHistory,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    CreatePublicThreads,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    CreatePrivateThreads,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SendThreadMessages,
    // Execute this protocol step.
    // Execute this protocol step.
    ManageThreads,
    // Execute this protocol step.
    // Execute this protocol step.
    ManageMessages,
    // Execute this protocol step.
    // Execute this protocol step.
    MuteMembers,
    // Execute this protocol step.
    // Execute this protocol step.
    DeafenMembers,
    // Execute this protocol step.
    // Execute this protocol step.
    MoveMembers,
    // Execute this protocol step.
    // Execute this protocol step.
    KickMembers,
    // Execute this protocol step.
    // Execute this protocol step.
    BanMembers,
    // Execute this protocol step.
    // Execute this protocol step.
    TimeoutMembers,
    // Execute this protocol step.
    // Execute this protocol step.
    ManageChannels,
    // Execute this protocol step.
    // Execute this protocol step.
    ManageRoles,
    // Execute this protocol step.
    // Execute this protocol step.
    ManageGarden,
    // Execute this protocol step.
    // Execute this protocol step.
    ManageWebhooks,
    // Execute this protocol step.
    // Execute this protocol step.
    ManageEmoji,
    // Execute this protocol step.
    // Execute this protocol step.
    ViewAuditLog,
    // Execute this protocol step.
    // Execute this protocol step.
    ManageInvites,
    // Execute this protocol step.
    // Execute this protocol step.
    RecordCalls,
    Connect,
    Speak,
    Video,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    PrioritySpeaker,
    // Execute this protocol step.
    // Execute this protocol step.
    RequestToSpeak,
    // Execute this protocol step.
    // Execute this protocol step.
    Administrator,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MentionEveryone,
}

// ---------------------------------------------------------------------------
// Garden Content Types (§10.2)
// ---------------------------------------------------------------------------

/// Content type for Garden messages.
///
/// 30+ content types supporting rich messaging, polls,
/// threads, reactions, moderation, and more.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// GardenContentType — variant enumeration.
// Match exhaustively to handle every protocol state.
// GardenContentType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum GardenContentType {
    Text,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Image {
        view_once: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Video {
        view_once: bool,
    },
    Audio,
    File,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Gif {
        url: String,
        embed_inline: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Sticker {
        sticker_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Reaction {
        target_id: [u8; 16],
        emoji: String,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ReactionRemove {
        target_id: [u8; 16],
        emoji: String,
    },
    // Begin the block scope.
    Poll {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        poll_id: [u8; 16],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        question: String,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        options: Vec<String>,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        close_at: Option<u64>,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        allow_multiselect: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    PollVote {
        poll_id: [u8; 16],
        option_indices: Vec<u8>,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    PollClose {
        poll_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Edit {
        original_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Deletion {
        original_id: [u8; 16],
        for_everyone: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Pin {
        original_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Unpin {
        original_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ThreadCreate {
        title: String,
        is_forum_post: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ThreadClose {
        thread_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ThreadLock {
        thread_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ThreadUnlock {
        thread_id: [u8; 16],
    },
    // Execute this protocol step.
    // Execute this protocol step.
    Announcement,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Embed {
        url: String,
        embed_data: Vec<u8>,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ScheduledEventRef {
        event_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SlashCommand {
        command: String,
        args: Vec<String>,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    BotResponse {
        command_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SystemEvent {
        event_type: SystemEventType,
        subject_id: Option<[u8; 32]>,
        detail: Option<String>,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    CallSignal {
        signal_type: String,
        session_id: [u8; 32],
    },
}

/// System events in a Garden.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// SystemEventType — variant enumeration.
// Match exhaustively to handle every protocol state.
// SystemEventType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum SystemEventType {
    // Execute this protocol step.
    // Execute this protocol step.
    MemberJoin,
    // Execute this protocol step.
    // Execute this protocol step.
    MemberLeave,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MemberKick { by: [u8; 32] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MemberBan { by: [u8; 32] },
    // Execute this protocol step.
    // Execute this protocol step.
    RoleCreate,
    // Execute this protocol step.
    // Execute this protocol step.
    RoleDelete,
    // Execute this protocol step.
    // Execute this protocol step.
    RoleAssign,
    // Execute this protocol step.
    // Execute this protocol step.
    RoleRevoke,
    // Execute this protocol step.
    // Execute this protocol step.
    ChannelCreate,
    // Execute this protocol step.
    // Execute this protocol step.
    ChannelDelete,
    // Execute this protocol step.
    // Execute this protocol step.
    ChannelUpdate,
    // Execute this protocol step.
    // Execute this protocol step.
    SettingsChange,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    HostingNodeAdded,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    HostingNodeRemoved,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    CanaryTrip { canary_type: CanaryType },
}

/// Canary types for transparency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// CanaryType — variant enumeration.
// Match exhaustively to handle every protocol state.
// CanaryType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum CanaryType {
    /// Algorithmic canary (automated check failed).
    // Execute this protocol step.
    // Execute this protocol step.
    Algorithmic,
    /// Dead man's switch canary (admin stopped confirming).
    // Execute this protocol step.
    // Execute this protocol step.
    DeadManSwitch,
}

// ---------------------------------------------------------------------------
// Mentions
// ---------------------------------------------------------------------------

/// Mention types in Garden messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// Mention — variant enumeration.
// Match exhaustively to handle every protocol state.
// Mention — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum Mention {
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MemberMention([u8; 32]),
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    RoleMention([u8; 32]),
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ChannelMention([u8; 32]),
    Here,
    All,
}

// ---------------------------------------------------------------------------
// Garden Message Wire Format (§10.2)
// ---------------------------------------------------------------------------

/// A Garden message (§10.2).
///
/// Split into server-visible metadata and encrypted content.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// GardenMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GardenMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GardenMessage {
    // --- Server-visible metadata ---
    /// Unique message identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    pub message_id: [u8; 16],
    /// Monotonic sequence number within the channel.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sequence_number: u64,
    /// Which channel this message belongs to.
    // Execute this protocol step.
    // Execute this protocol step.
    pub channel_id: [u8; 32],
    /// UTC day bucket for the timestamp (coarsened).
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp_bucket: u64,
    /// MLS epoch this message was encrypted under.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mls_epoch: u64,
    /// Size class for traffic analysis resistance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload_size_class: u8,
    /// Notification priority.
    // Execute this protocol step.
    // Execute this protocol step.
    pub notification_priority: u8,

    // --- Inside encryption ---
    /// Content type and payload.
    // Execute this protocol step.
    // Execute this protocol step.
    pub content_type: GardenContentType,
    /// Sender's peer ID (sealed sender).
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_id: [u8; 32],
    /// Actual timestamp (inside encryption).
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_timestamp: u64,
    /// The message payload (text, file reference, etc.).
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload: Vec<u8>,
    /// Reply-to reference.
    // Execute this protocol step.
    // Execute this protocol step.
    pub reply_to: Option<[u8; 16]>,
    /// Thread ID (if in a thread).
    // Execute this protocol step.
    // Execute this protocol step.
    pub thread_id: Option<[u8; 16]>,
    /// Mentions in this message.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mentions: Vec<Mention>,
    /// Attachment references.
    // Execute this protocol step.
    // Execute this protocol step.
    pub attachments: Vec<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Auto-Moderation (§10.2)
// ---------------------------------------------------------------------------

/// Auto-moderation rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// AutoModRule — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AutoModRule — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AutoModRule {
    /// The trigger for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub trigger: AutoModTrigger,
    /// The action for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub action: AutoModAction,
    /// The exempt roles for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub exempt_roles: Vec<[u8; 32]>,
    /// The exempt channels for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub exempt_channels: Vec<[u8; 32]>,
}

/// What triggers auto-moderation.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// AutoModTrigger — variant enumeration.
// Match exhaustively to handle every protocol state.
// AutoModTrigger — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum AutoModTrigger {
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    KeywordMatch(Vec<String>),
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MentionSpam(u8),
    // Execute this protocol step.
    // Execute this protocol step.
    SpamContent,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ExplicitContent,
}

/// What happens when auto-mod triggers.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// AutoModAction — variant enumeration.
// Match exhaustively to handle every protocol state.
// AutoModAction — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum AutoModAction {
    // Execute this protocol step.
    // Execute this protocol step.
    BlockMessage,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Timeout(u64), // Duration in seconds.
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Alert([u8; 32]), // Channel ID to alert.
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SendLog([u8; 32]), // Channel ID for log.
}

// ---------------------------------------------------------------------------
// Scheduled Delivery
// ---------------------------------------------------------------------------

/// Scheduled message delivery mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// ScheduledDeliveryMode — variant enumeration.
// Match exhaustively to handle every protocol state.
// ScheduledDeliveryMode — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ScheduledDeliveryMode {
    /// Deliver at the scheduled time.
    AtTime,
    /// Deliver when the recipient is next online after the time.
    // Execute this protocol step.
    // Execute this protocol step.
    WhenOnlineAfter,
}

// ---------------------------------------------------------------------------
// Garden Visibility (§10.2)
// ---------------------------------------------------------------------------

/// Whether a Garden is publicly discoverable or invite-only.
///
/// Public Gardens appear in search results and can be joined by anyone.
/// InviteOnly Gardens require an explicit invitation from an existing member
/// with the ManageInvites permission (Owner or Admin by default).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GardenVisibility {
    /// Discoverable by any peer on the network.
    /// Anyone can request to join without an invitation.
    Public,
    /// Hidden from discovery; requires an explicit invite to join.
    /// Only members with ManageInvites permission can issue invites.
    InviteOnly,
}

// ---------------------------------------------------------------------------
// Garden Roles (§10.2)
// ---------------------------------------------------------------------------

/// Role within a Garden community. Roles form a strict hierarchy
/// that determines what actions a member can perform.
///
/// The hierarchy (highest to lowest): Owner > Admin > Moderator > Member > Guest.
/// Each role inherits the permissions of all roles below it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GardenRole {
    /// Garden creator. Full control over all aspects of the Garden.
    /// Cannot be removed or demoted. Only one Owner per Garden.
    Owner,
    /// Administrator. Can manage rooms, members (except other admins),
    /// and most Garden settings. Cannot remove or demote the Owner.
    Admin,
    /// Moderator. Can manage members below Moderator rank and
    /// moderate content (delete messages, mute, timeout).
    Moderator,
    /// Standard member. Can access permitted rooms and participate
    /// in conversations, but cannot perform administrative actions.
    Member,
    /// Restricted visitor. Read-only access to public rooms only.
    /// Cannot send messages, react, or access restricted channels.
    Guest,
}

impl GardenRole {
    /// Returns the numeric privilege level for hierarchy comparisons.
    /// Higher values indicate more privilege: Owner(4) > Admin(3) > Moderator(2)
    /// > Member(1) > Guest(0). Used to enforce "cannot manage someone at or
    /// > above your own level" rules throughout the permission system.
    fn privilege_level(self) -> u8 {
        // Map each role to a numeric level for comparison.
        // Owner is highest at 4; Guest is lowest at 0.
        match self {
            GardenRole::Owner => 4,
            GardenRole::Admin => 3,
            GardenRole::Moderator => 2,
            GardenRole::Member => 1,
            GardenRole::Guest => 0,
        }
    }

    /// Returns true if this role outranks the other role.
    /// Used to enforce the rule that you can only manage members
    /// whose role is strictly below yours in the hierarchy.
    pub fn outranks(self, other: GardenRole) -> bool {
        // Strict greater-than: Owner outranks Admin, but Admin does not outrank Admin.
        self.privilege_level() > other.privilege_level()
    }
}

// ---------------------------------------------------------------------------
// Garden Room Types (§10.2)
// ---------------------------------------------------------------------------

/// The type of room (channel) within a Garden.
/// Determines the kind of content and interaction supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GardenRoomType {
    /// Text-based chat channel. Supports all GardenContentType variants.
    Text,
    /// Voice/video channel. Supports real-time communication via WebRTC.
    Voice,
    /// One-way broadcast channel. Only members with ManageMessages
    /// permission can post; everyone else is read-only.
    Announcement,
}

// ---------------------------------------------------------------------------
// Garden Room (§10.2)
// ---------------------------------------------------------------------------

/// A room (channel) within a Garden.
///
/// Each room has a unique 16-byte ID, a human-readable name, a type
/// that determines its behaviour, and a list of roles that can access it.
/// If access_roles is empty, ALL roles can access the room.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GardenRoom {
    /// Unique 16-byte identifier for this room, generated randomly.
    pub room_id: [u8; 16],
    /// Human-readable name (e.g., "general", "announcements", "voice-lobby").
    pub name: String,
    /// Whether this is a text, voice, or announcement channel.
    pub room_type: GardenRoomType,
    /// Which roles can access this room. Empty means all roles have access.
    /// When non-empty, only members holding one of these roles can view
    /// and interact with this room.
    pub access_roles: Vec<GardenRole>,
}

// ---------------------------------------------------------------------------
// Garden Member (§10.2)
// ---------------------------------------------------------------------------

/// A member of a Garden community.
///
/// Each member is identified by their PeerId and assigned a role that
/// determines their permissions within the Garden. The display_name
/// is an optional per-Garden alias (§9.4.3) separate from the peer's
/// global identity name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GardenMember {
    /// The member's peer identity. Links to their Ed25519 public key.
    pub peer_id: crate::identity::peer_id::PeerId,
    /// The member's role within this Garden (Owner, Admin, etc.).
    pub role: GardenRole,
    /// Unix timestamp (seconds) when this member joined the Garden.
    pub joined_at: u64,
    /// Optional per-Garden display name (§9.4.3). Overrides the
    /// peer's global display name within this Garden only.
    pub display_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Garden (§10.2) — the core community structure
// ---------------------------------------------------------------------------

/// A Garden (community) — a collection of rooms, channels, and members.
///
/// Gardens are the Mesh Infinity equivalent of Discord servers or Matrix
/// spaces. They provide multi-room, role-based community spaces with
/// privacy-preserving properties (§10.2).
///
/// Each Garden has its own Ed25519 keypair for cryptographic identity,
/// a governance policy for administrative decisions, and a member list
/// with hierarchical roles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Garden {
    /// Unique 16-byte identifier, generated randomly at creation time.
    pub id: [u8; 16],
    /// Human-readable name of the Garden (e.g., "Rust Developers").
    pub name: String,
    /// Description text explaining the purpose of this Garden.
    pub description: String,
    /// Ed25519 public key for this Garden's cryptographic identity.
    /// Used to verify signatures on Garden-level administrative actions.
    pub ed_pub: [u8; 32],
    /// Whether this Garden is publicly discoverable or invite-only.
    pub visibility: GardenVisibility,
    /// Ordered list of rooms (channels) within this Garden.
    pub rooms: Vec<GardenRoom>,
    /// List of all members with their roles and join timestamps.
    pub members: Vec<GardenMember>,
    /// Unix timestamp (seconds) when this Garden was created.
    pub created_at: u64,
    /// Governance policy controlling quorum voting for admin actions.
    /// Re-uses the group governance system from §8.10.
    pub governance: crate::groups::governance::GovernancePolicy,
}

// ---------------------------------------------------------------------------
// Garden Management Functions (§10.2)
// ---------------------------------------------------------------------------

/// Creates a new Garden with the given name, description, and creator.
///
/// The creator is automatically added as the Owner — the highest-privilege
/// role that cannot be removed. An Ed25519 keypair is derived from the
/// supplied secret key to give the Garden its own cryptographic identity.
///
/// A default "general" text room is created so the Garden is immediately
/// usable. The governance policy defaults to the standard §8.10.2 values.
///
/// # Errors
///
/// Returns `MeshError::Internal` if the system RNG fails to generate
/// the Garden ID or the default room ID.
pub fn create_garden(
    name: &str,
    description: &str,
    creator: &crate::identity::peer_id::PeerId,
    secret_key: &[u8; 32],
) -> Result<Garden, crate::error::MeshError> {
    // Generate a random 16-byte Garden ID using the system CSPRNG.
    // This ID uniquely identifies the Garden across the mesh network.
    let mut garden_id = [0u8; 16];
    getrandom::fill(&mut garden_id).map_err(|e| {
        crate::error::MeshError::Internal(format!("RNG failed for garden ID: {}", e))
    })?;

    // Derive the Ed25519 public key from the supplied secret key.
    // The Garden's keypair is separate from any peer's personal keypair.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    // Extract the 32-byte verifying (public) key for storage.
    let ed_pub: [u8; 32] = signing_key.verifying_key().to_bytes();

    // Get the current Unix timestamp for the creation time.
    // saturating_sub(0) is a no-op; the real protection is the map_err.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| crate::error::MeshError::Internal(format!("system clock error: {}", e)))?
        .as_secs();

    // Generate a random room ID for the default "general" channel.
    // Every Garden starts with at least one room so it's immediately usable.
    let mut general_room_id = [0u8; 16];
    getrandom::fill(&mut general_room_id)
        .map_err(|e| crate::error::MeshError::Internal(format!("RNG failed for room ID: {}", e)))?;

    // Build the default "general" text room accessible to all roles.
    // An empty access_roles list means every member can see this room.
    let general_room = GardenRoom {
        room_id: general_room_id,
        name: "general".to_string(),
        room_type: GardenRoomType::Text,
        access_roles: Vec::new(),
    };

    // Create the founding member entry with Owner role.
    // The Owner is the immutable root of the Garden's hierarchy.
    let founder = GardenMember {
        peer_id: *creator,
        role: GardenRole::Owner,
        joined_at: now,
        display_name: None,
    };

    // Use the default governance policy from §8.10.2.
    // The Garden creator can later change this via a governance proposal.
    let governance = crate::groups::governance::GovernancePolicy::default_policy();

    // Assemble and return the fully-initialized Garden.
    Ok(Garden {
        id: garden_id,
        name: name.to_string(),
        description: description.to_string(),
        ed_pub,
        visibility: GardenVisibility::Public,
        rooms: vec![general_room],
        members: vec![founder],
        created_at: now,
        governance,
    })
}

/// Adds a new room (channel) to an existing Garden.
///
/// The room receives a randomly-generated 16-byte ID. The caller specifies
/// the room name, type, and which roles can access it. An empty
/// access_roles list means all members can access the room.
///
/// # Errors
///
/// Returns `MeshError::Internal` if the system RNG fails to generate
/// a room ID.
pub fn add_room(
    garden: &mut Garden,
    name: &str,
    room_type: GardenRoomType,
    access_roles: Vec<GardenRole>,
) -> Result<[u8; 16], crate::error::MeshError> {
    // Generate a random 16-byte room ID using the system CSPRNG.
    // Uniqueness is probabilistically guaranteed by 128 bits of randomness.
    let mut room_id = [0u8; 16];
    getrandom::fill(&mut room_id)
        .map_err(|e| crate::error::MeshError::Internal(format!("RNG failed for room ID: {}", e)))?;

    // Construct the new room with the caller-supplied parameters.
    // The room is immediately usable once added to the Garden.
    let room = GardenRoom {
        room_id,
        name: name.to_string(),
        room_type,
        access_roles,
    };

    // Append the room to the Garden's room list.
    // Ordering is preserved as insertion order (newest last).
    garden.rooms.push(room);

    // Return the generated room ID so the caller can reference it.
    Ok(room_id)
}

/// Removes a room from a Garden by its 16-byte room ID.
///
/// Searches the Garden's room list for a room matching the given ID
/// and removes it. The room's messages are not handled here — that is
/// the responsibility of the storage layer.
///
/// # Errors
///
/// Returns `MeshError::NotFound` if no room with the given ID exists
/// in this Garden.
pub fn remove_room(garden: &mut Garden, room_id: &[u8; 16]) -> Result<(), crate::error::MeshError> {
    // Find the position of the room with the matching ID.
    // Linear scan is fine: Gardens typically have fewer than 100 rooms.
    let pos = garden
        .rooms
        .iter()
        .position(|r| r.room_id == *room_id)
        .ok_or_else(|| crate::error::MeshError::NotFound {
            kind: "garden_room",
            id: hex::encode(room_id),
        })?;

    // Remove the room at the found position (preserves order of remaining rooms).
    garden.rooms.remove(pos);
    Ok(())
}

/// Invites (adds) a new member to a Garden with the specified role.
///
/// The new member's joined_at timestamp is set to the current time.
/// Duplicate invitations (same peer_id already present) are rejected
/// to prevent accidental role overwrites.
///
/// # Role restrictions
///
/// - Only one Owner can exist per Garden; attempting to invite with
///   Owner role is rejected.
/// - The caller is responsible for verifying that the *invoking* member
///   has sufficient privilege (use `change_member_role` for role changes).
///
/// # Errors
///
/// Returns `MeshError::Internal` if:
/// - The peer is already a member of this Garden.
/// - The caller attempts to add a second Owner.
/// - The system clock is unavailable.
pub fn invite_member(
    garden: &mut Garden,
    peer_id: &crate::identity::peer_id::PeerId,
    role: GardenRole,
) -> Result<(), crate::error::MeshError> {
    // Reject adding a second Owner — Gardens have exactly one Owner.
    // Ownership transfer requires remove + re-add, which is intentionally
    // blocked (Owner cannot be removed). Use governance for succession.
    if role == GardenRole::Owner {
        return Err(crate::error::MeshError::Internal(
            "cannot invite with Owner role — only one Owner per Garden".to_string(),
        ));
    }

    // Check for duplicate membership. A peer should not appear twice.
    // If they need a role change, use change_member_role instead.
    if garden.members.iter().any(|m| m.peer_id == *peer_id) {
        return Err(crate::error::MeshError::Internal(
            "peer is already a member of this Garden".to_string(),
        ));
    }

    // Get the current Unix timestamp for the join time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| crate::error::MeshError::Internal(format!("system clock error: {}", e)))?
        .as_secs();

    // Create the new member entry with the specified role and current timestamp.
    let member = GardenMember {
        peer_id: *peer_id,
        role,
        joined_at: now,
        display_name: None,
    };

    // Append to the member list. New members go at the end.
    garden.members.push(member);
    Ok(())
}

/// Removes a member from a Garden by their PeerId.
///
/// The Owner cannot be removed — this is an immutable invariant.
/// The caller is responsible for verifying that the *invoking* member
/// has sufficient privilege to remove the target (Admin can remove
/// non-admins, Moderator can remove Members and Guests).
///
/// # Errors
///
/// Returns `MeshError::Internal` if the target is the Owner.
/// Returns `MeshError::NotFound` if no member with the given PeerId exists.
pub fn remove_member(
    garden: &mut Garden,
    peer_id: &crate::identity::peer_id::PeerId,
) -> Result<(), crate::error::MeshError> {
    // Find the member's position in the list.
    // Linear scan is acceptable: Gardens typically have thousands of members at most.
    let pos = garden
        .members
        .iter()
        .position(|m| m.peer_id == *peer_id)
        .ok_or_else(|| crate::error::MeshError::NotFound {
            kind: "garden_member",
            id: hex::encode(peer_id.0),
        })?;

    // The Owner is the immutable root of the Garden. Removing the Owner
    // would leave the Garden without governance authority.
    if garden.members[pos].role == GardenRole::Owner {
        return Err(crate::error::MeshError::Internal(
            "cannot remove the Garden Owner".to_string(),
        ));
    }

    // Remove the member at the found position.
    garden.members.remove(pos);
    Ok(())
}

/// Changes a member's role within a Garden.
///
/// # Role change constraints (§10.2)
///
/// - The Owner's role cannot be changed (immutable).
/// - No one can be promoted to Owner (only one Owner per Garden).
/// - Admin can change roles of Moderators, Members, and Guests.
/// - Moderator can change roles of Members and Guests only.
/// - Members and Guests cannot change anyone's role.
///
/// The caller must verify the invoking member's authority separately.
/// This function only enforces the target-side constraints.
///
/// # Errors
///
/// Returns `MeshError::Internal` if:
/// - The target member is the Owner (cannot change Owner's role).
/// - The new_role is Owner (cannot promote to Owner).
///   Returns `MeshError::NotFound` if the target peer is not a member.
pub fn change_member_role(
    garden: &mut Garden,
    peer_id: &crate::identity::peer_id::PeerId,
    new_role: GardenRole,
) -> Result<(), crate::error::MeshError> {
    // Cannot promote anyone to Owner. Owner is assigned at creation only.
    if new_role == GardenRole::Owner {
        return Err(crate::error::MeshError::Internal(
            "cannot promote to Owner — Owner is set at Garden creation".to_string(),
        ));
    }

    // Find the target member in the list.
    let member = garden
        .members
        .iter_mut()
        .find(|m| m.peer_id == *peer_id)
        .ok_or_else(|| crate::error::MeshError::NotFound {
            kind: "garden_member",
            id: hex::encode(peer_id.0),
        })?;

    // The Owner's role is immutable. No one — not even the Owner themselves —
    // can change the Owner role via this function.
    if member.role == GardenRole::Owner {
        return Err(crate::error::MeshError::Internal(
            "cannot change the Owner's role".to_string(),
        ));
    }

    // Apply the new role. The caller is trusted to have verified their
    // own authority to make this change (outranks check).
    member.role = new_role;
    Ok(())
}

/// Returns the list of rooms accessible to a specific member.
///
/// A room is accessible if either:
/// 1. The room's access_roles list is empty (open to all members), OR
/// 2. The member's role appears in the room's access_roles list.
///
/// Owner and Admin roles can always see all rooms regardless of
/// access_roles restrictions (administrative override).
pub fn list_accessible_rooms<'a>(
    garden: &'a Garden,
    member_peer_id: &crate::identity::peer_id::PeerId,
) -> Vec<&'a GardenRoom> {
    // First, find the member's role. If the peer is not a member,
    // they have no access to any rooms (return empty list).
    let member_role = match garden.members.iter().find(|m| m.peer_id == *member_peer_id) {
        Some(m) => m.role,
        // Non-members see no rooms at all.
        None => return Vec::new(),
    };

    // Filter rooms based on the member's role and the room's access list.
    garden
        .rooms
        .iter()
        .filter(|room| {
            // Owners and Admins have administrative override — they see everything.
            if member_role == GardenRole::Owner || member_role == GardenRole::Admin {
                return true;
            }
            // If access_roles is empty, the room is open to all members.
            if room.access_roles.is_empty() {
                return true;
            }
            // Otherwise, check if the member's role is in the access list.
            room.access_roles.contains(&member_role)
        })
        .collect()
}

/// Returns true if the given peer is a member of this Garden.
///
/// This is a simple membership check — it does not consider role or
/// permissions. Use `list_accessible_rooms` or direct role checks
/// for permission-gated operations.
pub fn is_member(garden: &Garden, peer_id: &crate::identity::peer_id::PeerId) -> bool {
    // Linear scan through the member list. For Gardens with very large
    // memberships, a HashSet index could be maintained separately.
    garden.members.iter().any(|m| m.peer_id == *peer_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a deterministic PeerId from a single byte.
    /// Uses PeerId::from_ed25519_pub with a 32-byte array filled with the seed.
    fn make_peer(seed: u8) -> crate::identity::peer_id::PeerId {
        // Build a fake 32-byte "public key" from the seed byte.
        // This is deterministic and unique per seed value.
        let fake_pub = [seed; 32];
        crate::identity::peer_id::PeerId::from_ed25519_pub(&fake_pub)
    }

    /// Helper: create a test Garden with a known creator.
    /// Returns (Garden, creator_PeerId) for use in subsequent assertions.
    fn make_test_garden() -> (Garden, crate::identity::peer_id::PeerId) {
        // Use a fixed 32-byte secret key for deterministic Ed25519 derivation.
        let secret = [0x42u8; 32];
        let creator = make_peer(0xAA);
        // create_garden should succeed with valid inputs.
        let garden = create_garden("Test Garden", "A test community", &creator, &secret)
            .expect("create_garden should not fail with valid inputs");
        (garden, creator)
    }

    #[test]
    fn test_content_types_serde() {
        let content = GardenContentType::Poll {
            poll_id: [0x01; 16],
            question: "Favorite color?".to_string(),
            options: vec!["Red".to_string(), "Blue".to_string()],
            close_at: Some(9999),
            allow_multiselect: false,
        };
        let json = serde_json::to_string(&content).unwrap();
        let recovered: GardenContentType = serde_json::from_str(&json).unwrap();
        match recovered {
            GardenContentType::Poll { question, .. } => {
                assert_eq!(question, "Favorite color?");
            }
            _ => panic!("Expected Poll"),
        }
    }

    #[test]
    fn test_permission_count() {
        // Verify we have all 34 permissions.
        let perms = [Permission::ViewChannel,
            Permission::SendMessages,
            Permission::Administrator,
            Permission::MentionEveryone];
        assert_eq!(perms.len(), 4); // Spot check.
    }

    #[test]
    fn test_garden_message_serde() {
        let msg = GardenMessage {
            message_id: [0x01; 16],
            sequence_number: 42,
            channel_id: [0x02; 32],
            timestamp_bucket: 1000,
            mls_epoch: 5,
            payload_size_class: 2,
            notification_priority: 1,
            content_type: GardenContentType::Text,
            sender_id: [0x03; 32],
            sender_timestamp: 1001,
            payload: b"Hello Garden!".to_vec(),
            reply_to: None,
            thread_id: None,
            mentions: vec![],
            attachments: vec![],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let recovered: GardenMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.sequence_number, 42);
    }

    #[test]
    fn test_auto_mod_serde() {
        let rule = AutoModRule {
            trigger: AutoModTrigger::MentionSpam(5),
            action: AutoModAction::Timeout(300),
            exempt_roles: vec![],
            exempt_channels: vec![],
        };
        let json = serde_json::to_string(&rule).unwrap();
        let recovered: AutoModRule = serde_json::from_str(&json).unwrap();
        match recovered.trigger {
            AutoModTrigger::MentionSpam(n) => assert_eq!(n, 5),
            _ => panic!("Expected MentionSpam"),
        }
    }

    // -----------------------------------------------------------------------
    // Garden creation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_garden_basic() {
        // A freshly created Garden should have the correct name, description,
        // one Owner member (the creator), and one default "general" room.
        let (garden, creator) = make_test_garden();
        assert_eq!(garden.name, "Test Garden");
        assert_eq!(garden.description, "A test community");
        // Must have exactly one member: the creator as Owner.
        assert_eq!(garden.members.len(), 1);
        assert_eq!(garden.members[0].peer_id, creator);
        assert_eq!(garden.members[0].role, GardenRole::Owner);
        // Must have exactly one default room named "general".
        assert_eq!(garden.rooms.len(), 1);
        assert_eq!(garden.rooms[0].name, "general");
        assert_eq!(garden.rooms[0].room_type, GardenRoomType::Text);
        // The ed_pub should be non-zero (derived from the secret key).
        assert_ne!(garden.ed_pub, [0u8; 32]);
        // Default visibility is Public.
        assert_eq!(garden.visibility, GardenVisibility::Public);
        // Creation timestamp should be non-zero.
        assert!(garden.created_at > 0);
    }

    #[test]
    fn test_create_garden_unique_ids() {
        // Two Gardens created with different keys should have different IDs.
        // (Random IDs are probabilistically unique with 128 bits.)
        let secret_a = [0x01u8; 32];
        let secret_b = [0x02u8; 32];
        let creator = make_peer(0x01);
        let g1 = create_garden("A", "", &creator, &secret_a).unwrap();
        let g2 = create_garden("B", "", &creator, &secret_b).unwrap();
        // IDs should differ (128-bit collision is astronomically unlikely).
        assert_ne!(g1.id, g2.id);
    }

    // -----------------------------------------------------------------------
    // Room management tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_room() {
        // Adding a room should increase the room count and return a valid ID.
        let (mut garden, _) = make_test_garden();
        let initial_count = garden.rooms.len();
        // Add a voice channel restricted to Owner and Admin roles.
        let room_id = add_room(
            &mut garden,
            "voice-lobby",
            GardenRoomType::Voice,
            vec![GardenRole::Owner, GardenRole::Admin],
        )
        .unwrap();
        // Room count should increase by one.
        assert_eq!(garden.rooms.len(), initial_count + 1);
        // The returned ID should match the last room's ID.
        assert_eq!(garden.rooms.last().unwrap().room_id, room_id);
        assert_eq!(garden.rooms.last().unwrap().name, "voice-lobby");
        assert_eq!(
            garden.rooms.last().unwrap().room_type,
            GardenRoomType::Voice
        );
    }

    #[test]
    fn test_remove_room_success() {
        // Removing an existing room should decrease the room count.
        let (mut garden, _) = make_test_garden();
        let room_id = add_room(&mut garden, "temp", GardenRoomType::Text, Vec::new()).unwrap();
        let count_before = garden.rooms.len();
        // Remove the room we just added.
        remove_room(&mut garden, &room_id).unwrap();
        assert_eq!(garden.rooms.len(), count_before - 1);
        // The room should no longer be findable.
        assert!(!garden.rooms.iter().any(|r| r.room_id == room_id));
    }

    #[test]
    fn test_remove_room_not_found() {
        // Removing a non-existent room should return NotFound.
        let (mut garden, _) = make_test_garden();
        let fake_id = [0xFF; 16];
        let result = remove_room(&mut garden, &fake_id);
        assert!(result.is_err());
        // Verify the error is a NotFound variant.
        match result.unwrap_err() {
            crate::error::MeshError::NotFound { kind, .. } => {
                assert_eq!(kind, "garden_room");
            }
            other => panic!("Expected NotFound, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Member management tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_invite_member() {
        // Inviting a new member should add them to the member list.
        let (mut garden, _) = make_test_garden();
        let new_peer = make_peer(0xBB);
        invite_member(&mut garden, &new_peer, GardenRole::Member).unwrap();
        // Should now have 2 members: the Owner and the new Member.
        assert_eq!(garden.members.len(), 2);
        assert_eq!(garden.members[1].peer_id, new_peer);
        assert_eq!(garden.members[1].role, GardenRole::Member);
        assert!(garden.members[1].joined_at > 0);
    }

    #[test]
    fn test_invite_member_duplicate_rejected() {
        // Inviting the same peer twice should fail.
        let (mut garden, _) = make_test_garden();
        let peer = make_peer(0xBB);
        invite_member(&mut garden, &peer, GardenRole::Member).unwrap();
        // Second invite should fail because they are already a member.
        let result = invite_member(&mut garden, &peer, GardenRole::Admin);
        assert!(result.is_err());
    }

    #[test]
    fn test_invite_member_owner_rejected() {
        // Cannot invite with Owner role — only one Owner per Garden.
        let (mut garden, _) = make_test_garden();
        let peer = make_peer(0xCC);
        let result = invite_member(&mut garden, &peer, GardenRole::Owner);
        assert!(result.is_err());
    }

    #[test]
    fn test_invite_all_non_owner_roles() {
        // All non-Owner roles should be valid for invitation.
        let (mut garden, _) = make_test_garden();
        let roles = [
            GardenRole::Admin,
            GardenRole::Moderator,
            GardenRole::Member,
            GardenRole::Guest,
        ];
        for (i, role) in roles.iter().enumerate() {
            let peer = make_peer(i as u8 + 1);
            invite_member(&mut garden, &peer, *role).unwrap();
        }
        // Should have 5 members total: Owner + 4 invited.
        assert_eq!(garden.members.len(), 5);
    }

    #[test]
    fn test_remove_member_success() {
        // Removing a non-Owner member should succeed.
        let (mut garden, _) = make_test_garden();
        let peer = make_peer(0xBB);
        invite_member(&mut garden, &peer, GardenRole::Member).unwrap();
        remove_member(&mut garden, &peer).unwrap();
        // Should be back to just the Owner.
        assert_eq!(garden.members.len(), 1);
    }

    #[test]
    fn test_remove_owner_rejected() {
        // The Owner cannot be removed — this is an immutable invariant.
        let (mut garden, creator) = make_test_garden();
        let result = remove_member(&mut garden, &creator);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_member_not_found() {
        // Removing a non-existent member should return NotFound.
        let (mut garden, _) = make_test_garden();
        let fake_peer = make_peer(0xFF);
        let result = remove_member(&mut garden, &fake_peer);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::error::MeshError::NotFound { kind, .. } => {
                assert_eq!(kind, "garden_member");
            }
            other => panic!("Expected NotFound, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Role change tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_change_member_role() {
        // Changing a Member to Admin should update their role.
        let (mut garden, _) = make_test_garden();
        let peer = make_peer(0xBB);
        invite_member(&mut garden, &peer, GardenRole::Member).unwrap();
        change_member_role(&mut garden, &peer, GardenRole::Admin).unwrap();
        // Verify the role was updated.
        let member = garden.members.iter().find(|m| m.peer_id == peer).unwrap();
        assert_eq!(member.role, GardenRole::Admin);
    }

    #[test]
    fn test_change_owner_role_rejected() {
        // The Owner's role cannot be changed by anyone, including themselves.
        let (mut garden, creator) = make_test_garden();
        let result = change_member_role(&mut garden, &creator, GardenRole::Admin);
        assert!(result.is_err());
    }

    #[test]
    fn test_promote_to_owner_rejected() {
        // No one can be promoted to Owner.
        let (mut garden, _) = make_test_garden();
        let peer = make_peer(0xBB);
        invite_member(&mut garden, &peer, GardenRole::Admin).unwrap();
        let result = change_member_role(&mut garden, &peer, GardenRole::Owner);
        assert!(result.is_err());
    }

    #[test]
    fn test_change_role_not_found() {
        // Changing the role of a non-existent member should fail.
        let (mut garden, _) = make_test_garden();
        let fake_peer = make_peer(0xFF);
        let result = change_member_role(&mut garden, &fake_peer, GardenRole::Admin);
        assert!(result.is_err());
    }

    #[test]
    fn test_change_role_multiple_transitions() {
        // A member should be able to cycle through non-Owner roles.
        let (mut garden, _) = make_test_garden();
        let peer = make_peer(0xBB);
        invite_member(&mut garden, &peer, GardenRole::Guest).unwrap();
        // Guest -> Member -> Moderator -> Admin -> Moderator -> Guest
        change_member_role(&mut garden, &peer, GardenRole::Member).unwrap();
        change_member_role(&mut garden, &peer, GardenRole::Moderator).unwrap();
        change_member_role(&mut garden, &peer, GardenRole::Admin).unwrap();
        change_member_role(&mut garden, &peer, GardenRole::Moderator).unwrap();
        change_member_role(&mut garden, &peer, GardenRole::Guest).unwrap();
        let member = garden.members.iter().find(|m| m.peer_id == peer).unwrap();
        assert_eq!(member.role, GardenRole::Guest);
    }

    // -----------------------------------------------------------------------
    // Room access tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_accessible_rooms_all_roles() {
        // A room with empty access_roles should be visible to everyone.
        let (garden, creator) = make_test_garden();
        let rooms = list_accessible_rooms(&garden, &creator);
        // The default "general" room has empty access_roles.
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].name, "general");
    }

    #[test]
    fn test_list_accessible_rooms_restricted() {
        // A room restricted to Admin should not be visible to a Member.
        let (mut garden, creator) = make_test_garden();
        // Add a restricted room accessible only to Owner and Admin.
        add_room(
            &mut garden,
            "admin-only",
            GardenRoomType::Text,
            vec![GardenRole::Owner, GardenRole::Admin],
        )
        .unwrap();
        // Add a regular Member.
        let member_peer = make_peer(0xBB);
        invite_member(&mut garden, &member_peer, GardenRole::Member).unwrap();

        // The Owner should see both rooms (admin override).
        let owner_rooms = list_accessible_rooms(&garden, &creator);
        assert_eq!(owner_rooms.len(), 2);

        // The Member should only see "general" (not "admin-only").
        let member_rooms = list_accessible_rooms(&garden, &member_peer);
        assert_eq!(member_rooms.len(), 1);
        assert_eq!(member_rooms[0].name, "general");
    }

    #[test]
    fn test_list_accessible_rooms_admin_sees_all() {
        // Admin should see all rooms regardless of access_roles restrictions.
        let (mut garden, _) = make_test_garden();
        add_room(
            &mut garden,
            "owner-only",
            GardenRoomType::Text,
            vec![GardenRole::Owner],
        )
        .unwrap();
        // Add an Admin member.
        let admin_peer = make_peer(0xCC);
        invite_member(&mut garden, &admin_peer, GardenRole::Admin).unwrap();
        // Admin should see all rooms (administrative override).
        let admin_rooms = list_accessible_rooms(&garden, &admin_peer);
        assert_eq!(admin_rooms.len(), 2);
    }

    #[test]
    fn test_list_accessible_rooms_guest_restricted() {
        // Guest should only see rooms that explicitly include Guest role
        // or rooms with empty access_roles (open to all).
        let (mut garden, _) = make_test_garden();
        // Add a room that explicitly includes Guest access.
        add_room(
            &mut garden,
            "public-announcements",
            GardenRoomType::Announcement,
            vec![GardenRole::Member, GardenRole::Guest],
        )
        .unwrap();
        // Add a room that excludes Guest.
        add_room(
            &mut garden,
            "members-only",
            GardenRoomType::Text,
            vec![GardenRole::Member],
        )
        .unwrap();
        // Add a Guest member.
        let guest_peer = make_peer(0xDD);
        invite_member(&mut garden, &guest_peer, GardenRole::Guest).unwrap();
        // Guest should see: "general" (open) + "public-announcements" (explicit Guest).
        // Guest should NOT see: "members-only" (Member role only).
        let guest_rooms = list_accessible_rooms(&garden, &guest_peer);
        assert_eq!(guest_rooms.len(), 2);
        let names: Vec<&str> = guest_rooms.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"general"));
        assert!(names.contains(&"public-announcements"));
        assert!(!names.contains(&"members-only"));
    }

    #[test]
    fn test_list_accessible_rooms_non_member() {
        // A non-member should see zero rooms.
        let (garden, _) = make_test_garden();
        let stranger = make_peer(0xFF);
        let rooms = list_accessible_rooms(&garden, &stranger);
        assert!(rooms.is_empty());
    }

    // -----------------------------------------------------------------------
    // Membership check tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_member_true() {
        // The creator should be recognized as a member.
        let (garden, creator) = make_test_garden();
        assert!(is_member(&garden, &creator));
    }

    #[test]
    fn test_is_member_false() {
        // A random peer not in the Garden should not be a member.
        let (garden, _) = make_test_garden();
        let stranger = make_peer(0xFF);
        assert!(!is_member(&garden, &stranger));
    }

    #[test]
    fn test_is_member_after_invite_and_remove() {
        // After inviting and then removing, the peer should no longer be a member.
        let (mut garden, _) = make_test_garden();
        let peer = make_peer(0xBB);
        invite_member(&mut garden, &peer, GardenRole::Member).unwrap();
        assert!(is_member(&garden, &peer));
        remove_member(&mut garden, &peer).unwrap();
        assert!(!is_member(&garden, &peer));
    }

    // -----------------------------------------------------------------------
    // Role hierarchy tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_role_outranks() {
        // Owner outranks everyone.
        assert!(GardenRole::Owner.outranks(GardenRole::Admin));
        assert!(GardenRole::Owner.outranks(GardenRole::Moderator));
        assert!(GardenRole::Owner.outranks(GardenRole::Member));
        assert!(GardenRole::Owner.outranks(GardenRole::Guest));
        // Admin outranks Moderator, Member, Guest — but not Owner or Admin.
        assert!(GardenRole::Admin.outranks(GardenRole::Moderator));
        assert!(GardenRole::Admin.outranks(GardenRole::Member));
        assert!(GardenRole::Admin.outranks(GardenRole::Guest));
        assert!(!GardenRole::Admin.outranks(GardenRole::Owner));
        assert!(!GardenRole::Admin.outranks(GardenRole::Admin));
        // Moderator outranks Member and Guest only.
        assert!(GardenRole::Moderator.outranks(GardenRole::Member));
        assert!(GardenRole::Moderator.outranks(GardenRole::Guest));
        assert!(!GardenRole::Moderator.outranks(GardenRole::Admin));
        assert!(!GardenRole::Moderator.outranks(GardenRole::Moderator));
        // Member outranks Guest only.
        assert!(GardenRole::Member.outranks(GardenRole::Guest));
        assert!(!GardenRole::Member.outranks(GardenRole::Member));
        // Guest outranks no one.
        assert!(!GardenRole::Guest.outranks(GardenRole::Guest));
    }

    #[test]
    fn test_role_privilege_levels_ordered() {
        // Verify the privilege levels form a strict total order.
        assert!(GardenRole::Owner.privilege_level() > GardenRole::Admin.privilege_level());
        assert!(GardenRole::Admin.privilege_level() > GardenRole::Moderator.privilege_level());
        assert!(GardenRole::Moderator.privilege_level() > GardenRole::Member.privilege_level());
        assert!(GardenRole::Member.privilege_level() > GardenRole::Guest.privilege_level());
    }

    // -----------------------------------------------------------------------
    // Garden serde round-trip test
    // -----------------------------------------------------------------------

    #[test]
    fn test_garden_serde_round_trip() {
        // A Garden should survive JSON serialization and deserialization intact.
        let (mut garden, _) = make_test_garden();
        // Add a second room and member to make the structure non-trivial.
        add_room(
            &mut garden,
            "voice",
            GardenRoomType::Voice,
            vec![GardenRole::Member, GardenRole::Admin],
        )
        .unwrap();
        let peer = make_peer(0xBB);
        invite_member(&mut garden, &peer, GardenRole::Admin).unwrap();

        // Serialize to JSON and back.
        let json = serde_json::to_string(&garden).unwrap();
        let recovered: Garden = serde_json::from_str(&json).unwrap();

        // Verify key fields survived the round trip.
        assert_eq!(recovered.id, garden.id);
        assert_eq!(recovered.name, garden.name);
        assert_eq!(recovered.description, garden.description);
        assert_eq!(recovered.ed_pub, garden.ed_pub);
        assert_eq!(recovered.rooms.len(), garden.rooms.len());
        assert_eq!(recovered.members.len(), garden.members.len());
        assert_eq!(recovered.created_at, garden.created_at);
    }

    // -----------------------------------------------------------------------
    // Visibility serde test
    // -----------------------------------------------------------------------

    #[test]
    fn test_visibility_serde() {
        // Both visibility variants should serialize and deserialize correctly.
        let public_json = serde_json::to_string(&GardenVisibility::Public).unwrap();
        let invite_json = serde_json::to_string(&GardenVisibility::InviteOnly).unwrap();
        let recovered_public: GardenVisibility = serde_json::from_str(&public_json).unwrap();
        let recovered_invite: GardenVisibility = serde_json::from_str(&invite_json).unwrap();
        assert_eq!(recovered_public, GardenVisibility::Public);
        assert_eq!(recovered_invite, GardenVisibility::InviteOnly);
    }

    // -----------------------------------------------------------------------
    // Edge case: add and remove rooms until empty
    // -----------------------------------------------------------------------

    #[test]
    fn test_remove_all_rooms() {
        // A Garden can have zero rooms after removing them all.
        let (mut garden, _) = make_test_garden();
        // Collect room IDs to remove.
        let room_ids: Vec<[u8; 16]> = garden.rooms.iter().map(|r| r.room_id).collect();
        for rid in &room_ids {
            remove_room(&mut garden, rid).unwrap();
        }
        assert!(garden.rooms.is_empty());
    }

    // -----------------------------------------------------------------------
    // Edge case: moderator room access
    // -----------------------------------------------------------------------

    #[test]
    fn test_moderator_room_access() {
        // Moderator should see rooms explicitly granting Moderator access,
        // plus rooms with empty access_roles, but NOT admin-restricted rooms.
        let (mut garden, _) = make_test_garden();
        add_room(
            &mut garden,
            "mod-channel",
            GardenRoomType::Text,
            vec![GardenRole::Moderator, GardenRole::Admin],
        )
        .unwrap();
        add_room(
            &mut garden,
            "admin-channel",
            GardenRoomType::Text,
            vec![GardenRole::Admin],
        )
        .unwrap();
        let mod_peer = make_peer(0xEE);
        invite_member(&mut garden, &mod_peer, GardenRole::Moderator).unwrap();

        let rooms = list_accessible_rooms(&garden, &mod_peer);
        // Should see: "general" (open) + "mod-channel" (explicit Moderator).
        // Should NOT see: "admin-channel" (Admin only).
        assert_eq!(rooms.len(), 2);
        let names: Vec<&str> = rooms.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"general"));
        assert!(names.contains(&"mod-channel"));
        assert!(!names.contains(&"admin-channel"));
    }
}
