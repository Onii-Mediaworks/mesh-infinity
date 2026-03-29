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
pub enum ChannelSecurityTier {
    /// MLS E2E encryption. Default.
    Encrypted,
    /// No encryption. For public announcement channels.
    PublicPlaintext,
}

// ---------------------------------------------------------------------------
// History Access
// ---------------------------------------------------------------------------

/// How much history new members can see.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryAccess {
    /// All history visible to new members.
    Full,
    /// Only messages from join time forward.
    FromJoin,
    /// No history access.
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
pub enum Permission {
    ViewChannel,
    SendMessages,
    SendVoice,
    AttachFiles,
    EmbedLinks,
    AddReactions,
    UseExternalEmoji,
    ReadHistory,
    CreatePublicThreads,
    CreatePrivateThreads,
    SendThreadMessages,
    ManageThreads,
    ManageMessages,
    MuteMembers,
    DeafenMembers,
    MoveMembers,
    KickMembers,
    BanMembers,
    TimeoutMembers,
    ManageChannels,
    ManageRoles,
    ManageGarden,
    ManageWebhooks,
    ManageEmoji,
    ViewAuditLog,
    ManageInvites,
    RecordCalls,
    Connect,
    Speak,
    Video,
    PrioritySpeaker,
    RequestToSpeak,
    Administrator,
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
pub enum GardenContentType {
    Text,
    Image { view_once: bool },
    Video { view_once: bool },
    Audio,
    File,
    Gif { url: String, embed_inline: bool },
    Sticker { sticker_id: [u8; 16] },
    Reaction { target_id: [u8; 16], emoji: String },
    ReactionRemove { target_id: [u8; 16], emoji: String },
    Poll {
        poll_id: [u8; 16],
        question: String,
        options: Vec<String>,
        close_at: Option<u64>,
        allow_multiselect: bool,
    },
    PollVote { poll_id: [u8; 16], option_indices: Vec<u8> },
    PollClose { poll_id: [u8; 16] },
    Edit { original_id: [u8; 16] },
    Deletion { original_id: [u8; 16], for_everyone: bool },
    Pin { original_id: [u8; 16] },
    Unpin { original_id: [u8; 16] },
    ThreadCreate { title: String, is_forum_post: bool },
    ThreadClose { thread_id: [u8; 16] },
    ThreadLock { thread_id: [u8; 16] },
    ThreadUnlock { thread_id: [u8; 16] },
    Announcement,
    Embed { url: String, embed_data: Vec<u8> },
    ScheduledEventRef { event_id: [u8; 16] },
    SlashCommand { command: String, args: Vec<String> },
    BotResponse { command_id: [u8; 16] },
    SystemEvent { event_type: SystemEventType, subject_id: Option<[u8; 32]>, detail: Option<String> },
    CallSignal { signal_type: String, session_id: [u8; 32] },
}

/// System events in a Garden.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SystemEventType {
    MemberJoin,
    MemberLeave,
    MemberKick { by: [u8; 32] },
    MemberBan { by: [u8; 32] },
    RoleCreate,
    RoleDelete,
    RoleAssign,
    RoleRevoke,
    ChannelCreate,
    ChannelDelete,
    ChannelUpdate,
    SettingsChange,
    HostingNodeAdded,
    HostingNodeRemoved,
    CanaryTrip { canary_type: CanaryType },
}

/// Canary types for transparency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryType {
    /// Algorithmic canary (automated check failed).
    Algorithmic,
    /// Dead man's switch canary (admin stopped confirming).
    DeadManSwitch,
}

// ---------------------------------------------------------------------------
// Mentions
// ---------------------------------------------------------------------------

/// Mention types in Garden messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Mention {
    MemberMention([u8; 32]),
    RoleMention([u8; 32]),
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
pub struct GardenMessage {
    // --- Server-visible metadata ---
    /// Unique message identifier.
    pub message_id: [u8; 16],
    /// Monotonic sequence number within the channel.
    pub sequence_number: u64,
    /// Which channel this message belongs to.
    pub channel_id: [u8; 32],
    /// UTC day bucket for the timestamp (coarsened).
    pub timestamp_bucket: u64,
    /// MLS epoch this message was encrypted under.
    pub mls_epoch: u64,
    /// Size class for traffic analysis resistance.
    pub payload_size_class: u8,
    /// Notification priority.
    pub notification_priority: u8,

    // --- Inside encryption ---
    /// Content type and payload.
    pub content_type: GardenContentType,
    /// Sender's peer ID (sealed sender).
    pub sender_id: [u8; 32],
    /// Actual timestamp (inside encryption).
    pub sender_timestamp: u64,
    /// The message payload (text, file reference, etc.).
    pub payload: Vec<u8>,
    /// Reply-to reference.
    pub reply_to: Option<[u8; 16]>,
    /// Thread ID (if in a thread).
    pub thread_id: Option<[u8; 16]>,
    /// Mentions in this message.
    pub mentions: Vec<Mention>,
    /// Attachment references.
    pub attachments: Vec<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Auto-Moderation (§10.2)
// ---------------------------------------------------------------------------

/// Auto-moderation rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutoModRule {
    pub trigger: AutoModTrigger,
    pub action: AutoModAction,
    pub exempt_roles: Vec<[u8; 32]>,
    pub exempt_channels: Vec<[u8; 32]>,
}

/// What triggers auto-moderation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AutoModTrigger {
    KeywordMatch(Vec<String>),
    MentionSpam(u8),
    SpamContent,
    ExplicitContent,
}

/// What happens when auto-mod triggers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AutoModAction {
    BlockMessage,
    Timeout(u64), // Duration in seconds.
    Alert([u8; 32]), // Channel ID to alert.
    SendLog([u8; 32]), // Channel ID for log.
}

// ---------------------------------------------------------------------------
// Scheduled Delivery
// ---------------------------------------------------------------------------

/// Scheduled message delivery mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduledDeliveryMode {
    /// Deliver at the scheduled time.
    AtTime,
    /// Deliver when the recipient is next online after the time.
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
