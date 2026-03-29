//! Message types (§10.0.1, §10.1.3)
//!
//! Common message envelope and Chat-specific message format.

use serde::{Deserialize, Serialize};
use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Notification Priority (§10.0.1)
// ---------------------------------------------------------------------------

/// Notification priority hint for the notification router (§14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationPriority {
    /// No notification (receipts, typing indicators, presence updates).
    Silent,
    /// Batched; never triggers standalone wake.
    Low,
    /// Standard notification; may be batched.
    Normal,
    /// Prompt delivery; direct messages from trusted peers.
    High,
    /// High-priority alert (calls, pairing requests, direct mentions).
    Urgent,
}

// ---------------------------------------------------------------------------
// Message Security Mode (§22.5.2, §6.9)
// ---------------------------------------------------------------------------

/// Per-conversation message security mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum MessageSecurityMode {
    /// Mixnet routing + S&F + maximum cover.
    MaxSecurity = 0,
    /// Standard mesh + extra hops + tighter jitter.
    Reinforced = 1,
    /// Standard mesh routing (default).
    #[default]
    Standard = 2,
    /// 1-2 relay hops, obfuscated (LoSec).
    Fast = 3,
    /// Peer-to-peer, no mesh routing.
    Direct = 4,
}


impl MessageSecurityMode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::MaxSecurity),
            1 => Some(Self::Reinforced),
            2 => Some(Self::Standard),
            3 => Some(Self::Fast),
            4 => Some(Self::Direct),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Content types (§10.1.3)
// ---------------------------------------------------------------------------

/// Chat content type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChatContentType {
    Text,
    Image { view_once: bool },
    Video { view_once: bool },
    Audio { playback_speeds: bool },
    VoiceMessage { duration_ms: u32 },
    File,
    Reaction { target_id: [u8; 16], emoji: String },
    ReactionRemove { target_id: [u8; 16], emoji: String },
    Edit { original_id: [u8; 16] },
    Deletion { original_id: [u8; 16], for_everyone: bool },
    Pin { target_id: [u8; 16] },
    Unpin { target_id: [u8; 16] },
    Delivered,
    Read { message_ids: Vec<[u8; 16]> },
    Typing { active: bool },
    LinkPreview { url: String, title: Option<String>, description: Option<String> },
    CallSignal { signal_type: CallSignalType, session_id: [u8; 32] },
    CallEnd { session_id: [u8; 32], duration_secs: u32 },
    SystemEvent { event: ChatSystemEvent },
}

/// Call signal types.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CallSignalType {
    Offer,
    Answer,
    IceCandidate,
    Hangup,
    Decline,
    Busy,
    LoSecRequest,
    LoSecResponse,
    Invite,
    ScreenShare { active: bool },
}

/// Chat system events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChatSystemEvent {
    GroupCreated,
    MemberAdded(PeerId),
    MemberRemoved(PeerId),
    MemberLeft,
    GroupRenamed(String),
    AvatarChanged,
    MissedCall { session_id: [u8; 32] },
    DisappearingMessagesChanged(Option<u64>),
}

// ---------------------------------------------------------------------------
// Chat Message (§10.1.3)
// ---------------------------------------------------------------------------

/// A single chat message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Random per-conversation ID (128-bit).
    pub id: [u8; 16],
    /// Monotonically increasing per conversation. Primary sort key.
    pub sequence_number: u64,
    /// Conversation this message belongs to.
    pub conversation_id: [u8; 16],
    /// DM or Group.
    pub conversation_type: ConversationType,
    /// Sender's peer ID.
    pub sender_peer_id: PeerId,
    /// Sender's clock (display-only, not for ordering).
    pub sender_timestamp: u64,
    /// Content type and type-specific data.
    pub content_type: ChatContentType,
    /// Application-specific payload.
    pub payload: Vec<u8>,
    /// Message being replied to (if any).
    pub reply_to: Option<[u8; 16]>,
    /// Thread this message belongs to.
    pub thread_id: Option<[u8; 16]>,
    /// Disappearing message expiry (Unix timestamp).
    pub expires_at: Option<u64>,
    /// Mentioned peer IDs.
    pub mentions: Vec<PeerId>,
    /// File attachments.
    pub attachments: Vec<AttachmentRef>,
    /// Whether this message was forwarded.
    pub is_forwarded: bool,
    /// Original sender attribution (for forwarded messages).
    pub forward_attribution: Option<String>,
    /// Edit timestamp (if edited).
    pub edited_at: Option<u64>,
}

/// Conversation type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversationType {
    DirectMessage,
    Group,
}

/// Attachment reference (§11).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// Content-addressed hash.
    pub file_id: [u8; 32],
    /// Original filename.
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// MIME type.
    pub mime_type: String,
}

impl ChatMessage {
    /// Create a new text message.
    pub fn new_text(
        conversation_id: [u8; 16],
        conversation_type: ConversationType,
        sender: PeerId,
        sequence: u64,
        text: &str,
    ) -> Self {
        let mut id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut id);

        Self {
            id,
            sequence_number: sequence,
            conversation_id,
            conversation_type,
            sender_peer_id: sender,
            sender_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            content_type: ChatContentType::Text,
            payload: text.as_bytes().to_vec(),
            reply_to: None,
            thread_id: None,
            expires_at: None,
            mentions: vec![],
            attachments: vec![],
            is_forwarded: false,
            forward_attribution: None,
            edited_at: None,
        }
    }

    /// Get the text content (if this is a text message).
    pub fn text(&self) -> Option<&str> {
        if matches!(self.content_type, ChatContentType::Text) {
            std::str::from_utf8(&self.payload).ok()
        } else {
            None
        }
    }

    /// Notification priority for this message type (§16.9.3).
    pub fn notification_priority(&self) -> NotificationPriority {
        match &self.content_type {
            ChatContentType::Delivered | ChatContentType::Typing { .. } => NotificationPriority::Silent,
            ChatContentType::Read { .. } => NotificationPriority::Silent,
            ChatContentType::CallSignal { .. } => NotificationPriority::Urgent,
            ChatContentType::SystemEvent { .. } => NotificationPriority::Low,
            _ => NotificationPriority::Normal, // Escalated to High by active conversation detection (§16.9.3)
        }
    }
}

use rand_core::RngCore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_text_message() {
        let pid = PeerId([0x01; 32]);
        let msg = ChatMessage::new_text([0x02; 16], ConversationType::DirectMessage, pid, 1, "Hello!");
        assert_eq!(msg.text(), Some("Hello!"));
        assert_eq!(msg.sequence_number, 1);
        assert!(matches!(msg.content_type, ChatContentType::Text));
    }

    #[test]
    fn test_unique_message_ids() {
        let pid = PeerId([0x01; 32]);
        let msg1 = ChatMessage::new_text([0x02; 16], ConversationType::DirectMessage, pid, 1, "a");
        let msg2 = ChatMessage::new_text([0x02; 16], ConversationType::DirectMessage, pid, 2, "b");
        assert_ne!(msg1.id, msg2.id);
    }

    #[test]
    fn test_notification_priority() {
        let pid = PeerId([0x01; 32]);
        let text = ChatMessage::new_text([0x02; 16], ConversationType::DirectMessage, pid, 1, "hi");
        assert_eq!(text.notification_priority(), NotificationPriority::Normal);
    }

    #[test]
    fn test_security_mode_default() {
        assert_eq!(MessageSecurityMode::default(), MessageSecurityMode::Standard);
    }

    #[test]
    fn test_security_mode_from_u8() {
        assert_eq!(MessageSecurityMode::from_u8(0), Some(MessageSecurityMode::MaxSecurity));
        assert_eq!(MessageSecurityMode::from_u8(4), Some(MessageSecurityMode::Direct));
        assert_eq!(MessageSecurityMode::from_u8(5), None);
    }

    #[test]
    fn test_serde_roundtrip() {
        let pid = PeerId([0x01; 32]);
        let msg = ChatMessage::new_text([0x02; 16], ConversationType::Group, pid, 42, "test");
        let json = serde_json::to_string(&msg).unwrap();
        let recovered: ChatMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.text(), Some("test"));
        assert_eq!(recovered.sequence_number, 42);
    }
}
