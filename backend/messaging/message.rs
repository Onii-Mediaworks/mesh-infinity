//! Message types (§10.0.1, §10.1.3)
//!
//! Common message envelope and Chat-specific message format.

use crate::identity::peer_id::PeerId;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Notification Priority (§10.0.1)
// ---------------------------------------------------------------------------

/// Notification priority hint for the notification router (§14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// NotificationPriority — variant enumeration.
// Match exhaustively to handle every protocol state.
// NotificationPriority — variant enumeration.
// Match exhaustively to handle every protocol state.
// NotificationPriority — variant enumeration.
// Match exhaustively to handle every protocol state.
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
// Begin the block scope.
// MessageSecurityMode — variant enumeration.
// Match exhaustively to handle every protocol state.
// MessageSecurityMode — variant enumeration.
// Match exhaustively to handle every protocol state.
// MessageSecurityMode — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MessageSecurityMode {
    /// Mixnet routing + S&F + maximum cover.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    MaxSecurity = 0,
    /// Standard mesh + extra hops + tighter jitter.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Reinforced = 1,
    /// Standard mesh routing (default).
    #[default]
    // Update the local state.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Standard = 2,
    /// 1-2 relay hops, obfuscated (LoSec).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Fast = 3,
    /// Peer-to-peer, no mesh routing.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Direct = 4,
}

// Begin the block scope.
// MessageSecurityMode implementation — core protocol logic.
// MessageSecurityMode implementation — core protocol logic.
// MessageSecurityMode implementation — core protocol logic.
impl MessageSecurityMode {
    // Begin the block scope.
    // Perform the 'from u8' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from u8' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from u8' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_u8(v: u8) -> Option<Self> {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match v {
            // Update the local state.
            0 => Some(Self::MaxSecurity),
            // Update the local state.
            1 => Some(Self::Reinforced),
            // Update the local state.
            2 => Some(Self::Standard),
            // Update the local state.
            3 => Some(Self::Fast),
            // Update the local state.
            4 => Some(Self::Direct),
            // Update the local state.
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Content types (§10.1.3)
// ---------------------------------------------------------------------------

/// Chat content type.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ChatContentType — variant enumeration.
// Match exhaustively to handle every protocol state.
// ChatContentType — variant enumeration.
// Match exhaustively to handle every protocol state.
// ChatContentType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ChatContentType {
    Text,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Image {
        view_once: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Video {
        view_once: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Audio {
        playback_speeds: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    VoiceMessage {
        duration_ms: u32,
    },
    File,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Reaction {
        target_id: [u8; 16],
        emoji: String,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ReactionRemove {
        target_id: [u8; 16],
        emoji: String,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Edit {
        original_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Deletion {
        original_id: [u8; 16],
        for_everyone: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Pin {
        target_id: [u8; 16],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Unpin {
        target_id: [u8; 16],
    },
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Delivered,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Read {
        message_ids: Vec<[u8; 16]>,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Typing {
        active: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    LinkPreview {
        url: String,
        title: Option<String>,
        description: Option<String>,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    CallSignal {
        signal_type: CallSignalType,
        session_id: [u8; 32],
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    CallEnd {
        session_id: [u8; 32],
        duration_secs: u32,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    SystemEvent {
        event: ChatSystemEvent,
    },
}

/// Call signal types.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// CallSignalType — variant enumeration.
// Match exhaustively to handle every protocol state.
// CallSignalType — variant enumeration.
// Match exhaustively to handle every protocol state.
// CallSignalType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum CallSignalType {
    Offer,
    Answer,
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    IceCandidate,
    Hangup,
    Decline,
    Busy,
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    LoSecRequest,
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    LoSecResponse,
    Invite,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ScreenShare { active: bool },
}

/// Chat system events.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ChatSystemEvent — variant enumeration.
// Match exhaustively to handle every protocol state.
// ChatSystemEvent — variant enumeration.
// Match exhaustively to handle every protocol state.
// ChatSystemEvent — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ChatSystemEvent {
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    GroupCreated,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    MemberAdded(PeerId),
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    MemberRemoved(PeerId),
    // Execute this protocol step.
    // Execute this protocol step.
    MemberLeft,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    GroupRenamed(String),
    // Execute this protocol step.
    // Execute this protocol step.
    AvatarChanged,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MissedCall { session_id: [u8; 32] },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    DisappearingMessagesChanged(Option<u64>),
}

// ---------------------------------------------------------------------------
// Chat Message (§10.1.3)
// ---------------------------------------------------------------------------

/// A single chat message.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ChatMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ChatMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ChatMessage {
    /// Random per-conversation ID (128-bit).
    // Execute this protocol step.
    // Execute this protocol step.
    pub id: [u8; 16],
    /// Monotonically increasing per conversation. Primary sort key.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sequence_number: u64,
    /// Conversation this message belongs to.
    // Execute this protocol step.
    // Execute this protocol step.
    pub conversation_id: [u8; 16],
    /// DM or Group.
    // Execute this protocol step.
    // Execute this protocol step.
    pub conversation_type: ConversationType,
    /// Sender's peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_peer_id: PeerId,
    /// Sender's clock (display-only, not for ordering).
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_timestamp: u64,
    /// Content type and type-specific data.
    // Execute this protocol step.
    // Execute this protocol step.
    pub content_type: ChatContentType,
    /// Application-specific payload.
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload: Vec<u8>,
    /// Message being replied to (if any).
    // Execute this protocol step.
    // Execute this protocol step.
    pub reply_to: Option<[u8; 16]>,
    /// Thread this message belongs to.
    // Execute this protocol step.
    // Execute this protocol step.
    pub thread_id: Option<[u8; 16]>,
    /// Disappearing message expiry (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    pub expires_at: Option<u64>,
    /// Mentioned peer IDs.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mentions: Vec<PeerId>,
    /// File attachments.
    // Execute this protocol step.
    // Execute this protocol step.
    pub attachments: Vec<AttachmentRef>,
    /// Whether this message was forwarded.
    // Execute this protocol step.
    // Execute this protocol step.
    pub is_forwarded: bool,
    /// Original sender attribution (for forwarded messages).
    // Execute this protocol step.
    // Execute this protocol step.
    pub forward_attribution: Option<String>,
    /// Edit timestamp (if edited).
    // Execute this protocol step.
    // Execute this protocol step.
    pub edited_at: Option<u64>,
}

/// Conversation type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// ConversationType — variant enumeration.
// Match exhaustively to handle every protocol state.
// ConversationType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ConversationType {
    // Execute this protocol step.
    // Execute this protocol step.
    DirectMessage,
    Group,
}

/// Attachment reference (§11).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// AttachmentRef — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AttachmentRef — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AttachmentRef {
    /// Content-addressed hash.
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_id: [u8; 32],
    /// Original filename.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// File size in bytes.
    // Execute this protocol step.
    // Execute this protocol step.
    pub size: u64,
    /// MIME type.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mime_type: String,
}

// Begin the block scope.
// ChatMessage implementation — core protocol logic.
// ChatMessage implementation — core protocol logic.
impl ChatMessage {
    /// Create a new text message.
    // Perform the 'new text' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new text' operation.
    // Errors are propagated to the caller via Result.
    pub fn new_text(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        conversation_id: [u8; 16],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        conversation_type: ConversationType,
        // Execute this protocol step.
        // Execute this protocol step.
        sender: PeerId,
        // Execute this protocol step.
        // Execute this protocol step.
        sequence: u64,
        // Execute this protocol step.
        // Execute this protocol step.
        text: &str,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Self {
        // Unique identifier for lookup and deduplication.
        // Compute id for this protocol step.
        // Compute id for this protocol step.
        let mut id = [0u8; 16];
        // OS-provided cryptographic random number generator.
        // Execute this protocol step.
        // Execute this protocol step.
        rand_core::OsRng.fill_bytes(&mut id);

        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            id,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            sequence_number: sequence,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            conversation_id,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            conversation_type,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            sender_peer_id: sender,
            // Invoke the associated function.
            // Execute this protocol step.
            // Execute this protocol step.
            sender_timestamp: std::time::SystemTime::now()
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                .duration_since(std::time::UNIX_EPOCH)
                // Fall back to the default value on failure.
                // Execute this protocol step.
                // Execute this protocol step.
                .unwrap_or_default()
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                .as_millis() as u64,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            content_type: ChatContentType::Text,
            // Extract the raw byte representation for wire encoding.
            // Execute this protocol step.
            // Execute this protocol step.
            payload: text.as_bytes().to_vec(),
            // Execute this protocol step.
            // Execute this protocol step.
            reply_to: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            thread_id: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            expires_at: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            mentions: vec![],
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            attachments: vec![],
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            is_forwarded: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            forward_attribution: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            edited_at: None,
        }
    }

    /// Get the text content (if this is a text message).
    // Perform the 'text' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'text' operation.
    // Errors are propagated to the caller via Result.
    pub fn text(&self) -> Option<&str> {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if matches!(self.content_type, ChatContentType::Text) {
            // Check the operation outcome without consuming the error.
            // Execute this protocol step.
            // Execute this protocol step.
            std::str::from_utf8(&self.payload).ok()
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // No value available.
            // No value available.
            None
        }
    }

    /// Notification priority for this message type (§16.9.3).
    // Perform the 'notification priority' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'notification priority' operation.
    // Errors are propagated to the caller via Result.
    pub fn notification_priority(&self) -> NotificationPriority {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match &self.content_type {
            // Handle this match arm.
            // Handle ChatContentType::Delivered | ChatContentType::Typing { .. }.
            // Handle ChatContentType::Delivered | ChatContentType::Typing { .. }.
            ChatContentType::Delivered | ChatContentType::Typing { .. } => {
                NotificationPriority::Silent
            }
            // Handle this match arm.
            // Handle ChatContentType::Read { .. }.
            // Handle ChatContentType::Read { .. }.
            ChatContentType::Read { .. } => NotificationPriority::Silent,
            // Handle this match arm.
            // Handle ChatContentType::CallSignal { .. }.
            // Handle ChatContentType::CallSignal { .. }.
            ChatContentType::CallSignal { .. } => NotificationPriority::Urgent,
            // Handle this match arm.
            // Handle ChatContentType::SystemEvent { .. }.
            // Handle ChatContentType::SystemEvent { .. }.
            ChatContentType::SystemEvent { .. } => NotificationPriority::Low,
            // Update the local state.
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
        let msg = ChatMessage::new_text(
            [0x02; 16],
            ConversationType::DirectMessage,
            pid,
            1,
            "Hello!",
        );
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
        assert_eq!(
            MessageSecurityMode::default(),
            MessageSecurityMode::Standard
        );
    }

    #[test]
    fn test_security_mode_from_u8() {
        assert_eq!(
            MessageSecurityMode::from_u8(0),
            Some(MessageSecurityMode::MaxSecurity)
        );
        assert_eq!(
            MessageSecurityMode::from_u8(4),
            Some(MessageSecurityMode::Direct)
        );
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
