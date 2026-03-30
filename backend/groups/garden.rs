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
    Image { view_once: bool },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Video { view_once: bool },
    Audio,
    File,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Gif { url: String, embed_inline: bool },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Sticker { sticker_id: [u8; 16] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Reaction { target_id: [u8; 16], emoji: String },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ReactionRemove { target_id: [u8; 16], emoji: String },
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
    PollVote { poll_id: [u8; 16], option_indices: Vec<u8> },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    PollClose { poll_id: [u8; 16] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Edit { original_id: [u8; 16] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Deletion { original_id: [u8; 16], for_everyone: bool },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Pin { original_id: [u8; 16] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Unpin { original_id: [u8; 16] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ThreadCreate { title: String, is_forum_post: bool },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ThreadClose { thread_id: [u8; 16] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ThreadLock { thread_id: [u8; 16] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ThreadUnlock { thread_id: [u8; 16] },
    // Execute this protocol step.
    // Execute this protocol step.
    Announcement,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Embed { url: String, embed_data: Vec<u8> },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ScheduledEventRef { event_id: [u8; 16] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SlashCommand { command: String, args: Vec<String> },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    BotResponse { command_id: [u8; 16] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SystemEvent { event_type: SystemEventType, subject_id: Option<[u8; 32]>, detail: Option<String> },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    CallSignal { signal_type: String, session_id: [u8; 32] },
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        let perms = vec![
            Permission::ViewChannel,
            Permission::SendMessages,
            Permission::Administrator,
            Permission::MentionEveryone,
        ];
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
}
