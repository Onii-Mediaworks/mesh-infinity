//! Rooms / Conversations (§10.1.1, §10.1.2)
//!
//! A room represents a conversation — either a 1:1 DM or a group chat.

use serde::{Deserialize, Serialize};
use crate::identity::peer_id::PeerId;
use super::message::{ConversationType, MessageSecurityMode};

/// A conversation room.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Room {
    /// Unique room identifier.
    pub id: [u8; 16],
    /// Human-readable name (peer name for DM, group name for group).
    pub name: String,
    /// DM or Group.
    pub conversation_type: ConversationType,
    /// Participants (peer IDs). For DM: exactly 2 (self + other).
    pub participants: Vec<PeerId>,
    /// Last message preview text.
    pub last_message_preview: Option<String>,
    /// Last message timestamp (for sort order).
    pub last_message_at: Option<u64>,
    /// Unread message count.
    pub unread_count: u32,
    /// Whether the room is muted.
    pub is_muted: bool,
    /// Mute expiry (None = muted forever, Some = muted until timestamp).
    pub mute_until: Option<u64>,
    /// Whether the room is archived.
    pub is_archived: bool,
    /// Whether the room is pinned to the top of the list.
    pub is_pinned: bool,
    /// Per-conversation security mode (§22.5.2).
    pub security_mode: MessageSecurityMode,
    /// Disappearing message timer (None = disabled).
    pub disappearing_timer: Option<u64>,
    /// Next sequence number for outgoing messages.
    pub next_sequence: u64,
    /// User-defined labels/folders.
    pub labels: Vec<String>,
    /// Draft message text (device-local).
    pub draft: Option<String>,
}

impl Room {
    /// Create a new DM room.
    pub fn new_dm(self_peer_id: PeerId, other_peer_id: PeerId, other_name: &str) -> Self {
        let mut id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut id);

        Self {
            id,
            name: other_name.to_string(),
            conversation_type: ConversationType::DirectMessage,
            participants: vec![self_peer_id, other_peer_id],
            last_message_preview: None,
            last_message_at: None,
            unread_count: 0,
            is_muted: false,
            mute_until: None,
            is_archived: false,
            is_pinned: false,
            security_mode: MessageSecurityMode::Standard,
            disappearing_timer: None,
            next_sequence: 0,
            labels: vec![],
            draft: None,
        }
    }

    /// Create a new group room.
    pub fn new_group(name: &str, members: Vec<PeerId>) -> Self {
        let mut id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut id);

        Self {
            id,
            name: name.to_string(),
            conversation_type: ConversationType::Group,
            participants: members,
            last_message_preview: None,
            last_message_at: None,
            unread_count: 0,
            is_muted: false,
            mute_until: None,
            is_archived: false,
            is_pinned: false,
            security_mode: MessageSecurityMode::Standard,
            disappearing_timer: None,
            next_sequence: 0,
            labels: vec![],
            draft: None,
        }
    }

    /// Get the other peer in a DM (returns None for group rooms).
    pub fn dm_peer(&self, self_peer_id: &PeerId) -> Option<&PeerId> {
        if self.conversation_type != ConversationType::DirectMessage {
            return None;
        }
        self.participants.iter().find(|p| *p != self_peer_id)
    }

    /// Increment and return the next sequence number.
    pub fn next_seq(&mut self) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        seq
    }

    /// Update last message info.
    pub fn update_last_message(&mut self, preview: &str, timestamp: u64) {
        self.last_message_preview = Some(preview.chars().take(100).collect());
        self.last_message_at = Some(timestamp);
    }

    /// Mark all messages as read.
    pub fn mark_read(&mut self) {
        self.unread_count = 0;
    }

    /// Increment unread count.
    pub fn increment_unread(&mut self) {
        if !self.is_muted {
            self.unread_count += 1;
        }
    }
}

use rand_core::RngCore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_dm() {
        let me = PeerId([0x01; 32]);
        let them = PeerId([0x02; 32]);
        let room = Room::new_dm(me, them, "Alice");
        assert_eq!(room.name, "Alice");
        assert_eq!(room.conversation_type, ConversationType::DirectMessage);
        assert_eq!(room.participants.len(), 2);
    }

    #[test]
    fn test_create_group() {
        let members = vec![PeerId([0x01; 32]), PeerId([0x02; 32]), PeerId([0x03; 32])];
        let room = Room::new_group("Team", members);
        assert_eq!(room.name, "Team");
        assert_eq!(room.conversation_type, ConversationType::Group);
        assert_eq!(room.participants.len(), 3);
    }

    #[test]
    fn test_dm_peer() {
        let me = PeerId([0x01; 32]);
        let them = PeerId([0x02; 32]);
        let room = Room::new_dm(me, them, "Bob");
        assert_eq!(room.dm_peer(&me), Some(&them));
    }

    #[test]
    fn test_sequence_numbering() {
        let mut room = Room::new_group("Test", vec![]);
        assert_eq!(room.next_seq(), 0);
        assert_eq!(room.next_seq(), 1);
        assert_eq!(room.next_seq(), 2);
    }

    #[test]
    fn test_unread_count() {
        let mut room = Room::new_group("Test", vec![]);
        room.increment_unread();
        room.increment_unread();
        assert_eq!(room.unread_count, 2);
        room.mark_read();
        assert_eq!(room.unread_count, 0);
    }

    #[test]
    fn test_muted_no_unread() {
        let mut room = Room::new_group("Test", vec![]);
        room.is_muted = true;
        room.increment_unread();
        assert_eq!(room.unread_count, 0);
    }

    #[test]
    fn test_last_message_truncation() {
        let mut room = Room::new_group("Test", vec![]);
        let long_msg = "a".repeat(200);
        room.update_last_message(&long_msg, 100);
        assert!(room.last_message_preview.as_ref().unwrap().len() <= 100);
    }

    #[test]
    fn test_serde_roundtrip() {
        let room = Room::new_group("Test Group", vec![PeerId([0x01; 32])]);
        let json = serde_json::to_string(&room).unwrap();
        let recovered: Room = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.name, "Test Group");
    }
}
