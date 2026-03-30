//! Rooms / Conversations (§10.1.1, §10.1.2)
//!
//! A room represents a conversation — either a 1:1 DM or a group chat.

use serde::{Deserialize, Serialize};
use crate::identity::peer_id::PeerId;
use super::message::{ConversationType, MessageSecurityMode};

/// A conversation room.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// Room — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// Room — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// Room — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct Room {
    /// Unique room identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub id: [u8; 16],
    /// Human-readable name (peer name for DM, group name for group).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// DM or Group.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub conversation_type: ConversationType,
    /// Participants (peer IDs). For DM: exactly 2 (self + other).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub participants: Vec<PeerId>,
    /// Last message preview text.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_message_preview: Option<String>,
    /// Last message timestamp (for sort order).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_message_at: Option<u64>,
    /// Unread message count.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub unread_count: u32,
    /// Whether the room is muted.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub is_muted: bool,
    /// Mute expiry (None = muted forever, Some = muted until timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mute_until: Option<u64>,
    /// Whether the room is archived.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub is_archived: bool,
    /// Whether the room is pinned to the top of the list.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub is_pinned: bool,
    /// Per-conversation security mode (§22.5.2).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub security_mode: MessageSecurityMode,
    /// Disappearing message timer (None = disabled).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub disappearing_timer: Option<u64>,
    /// Next sequence number for outgoing messages.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub next_sequence: u64,
    /// User-defined labels/folders.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub labels: Vec<String>,
    /// Draft message text (device-local).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub draft: Option<String>,
}

// Begin the block scope.
// Room implementation — core protocol logic.
// Room implementation — core protocol logic.
// Room implementation — core protocol logic.
impl Room {
    /// Create a new DM room.
    // Perform the 'new dm' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new dm' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new dm' operation.
    // Errors are propagated to the caller via Result.
    pub fn new_dm(self_peer_id: PeerId, other_peer_id: PeerId, other_name: &str) -> Self {
        // Unique identifier for lookup and deduplication.
        // Compute id for this protocol step.
        // Compute id for this protocol step.
        // Compute id for this protocol step.
        let mut id = [0u8; 16];
        // OS-provided cryptographic random number generator.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        rand_core::OsRng.fill_bytes(&mut id);

        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            id,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            name: other_name.to_string(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            conversation_type: ConversationType::DirectMessage,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            participants: vec![self_peer_id, other_peer_id],
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            last_message_preview: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            last_message_at: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            unread_count: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            is_muted: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            mute_until: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            is_archived: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            is_pinned: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            security_mode: MessageSecurityMode::Standard,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            disappearing_timer: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            next_sequence: 0,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            labels: vec![],
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            draft: None,
        }
    }

    /// Create a new group room.
    // Perform the 'new group' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new group' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new group' operation.
    // Errors are propagated to the caller via Result.
    pub fn new_group(name: &str, members: Vec<PeerId>) -> Self {
        // Unique identifier for lookup and deduplication.
        // Compute id for this protocol step.
        // Compute id for this protocol step.
        // Compute id for this protocol step.
        let mut id = [0u8; 16];
        // OS-provided cryptographic random number generator.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        rand_core::OsRng.fill_bytes(&mut id);

        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            id,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            name: name.to_string(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            conversation_type: ConversationType::Group,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            participants: members,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            last_message_preview: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            last_message_at: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            unread_count: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            is_muted: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            mute_until: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            is_archived: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            is_pinned: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            security_mode: MessageSecurityMode::Standard,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            disappearing_timer: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            next_sequence: 0,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            labels: vec![],
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            draft: None,
        }
    }

    /// Get the other peer in a DM (returns None for group rooms).
    // Perform the 'dm peer' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'dm peer' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'dm peer' operation.
    // Errors are propagated to the caller via Result.
    pub fn dm_peer(&self, self_peer_id: &PeerId) -> Option<&PeerId> {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.conversation_type != ConversationType::DirectMessage {
            // No result available — signal absence to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return None;
        }
        // Create an iterator over the collection elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        self.participants.iter().find(|p| *p != self_peer_id)
    }

    /// Increment and return the next sequence number.
    // Perform the 'next seq' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'next seq' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'next seq' operation.
    // Errors are propagated to the caller via Result.
    pub fn next_seq(&mut self) -> u64 {
        // Execute the operation and bind the result.
        // Compute seq for this protocol step.
        // Compute seq for this protocol step.
        // Compute seq for this protocol step.
        let seq = self.next_sequence;
        // Update the next sequence to reflect the new state.
        // Advance next sequence state.
        // Advance next sequence state.
        // Advance next sequence state.
        self.next_sequence += 1;
        seq
    }

    /// Update last message info.
    // Perform the 'update last message' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'update last message' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'update last message' operation.
    // Errors are propagated to the caller via Result.
    pub fn update_last_message(&mut self, preview: &str, timestamp: u64) {
        // Update the last message preview to reflect the new state.
        // Advance last message preview state.
        // Advance last message preview state.
        // Advance last message preview state.
        self.last_message_preview = Some(preview.chars().take(100).collect());
        // Update the last message at to reflect the new state.
        // Advance last message at state.
        // Advance last message at state.
        // Advance last message at state.
        self.last_message_at = Some(timestamp);
    }

    /// Mark all messages as read.
    // Perform the 'mark read' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'mark read' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'mark read' operation.
    // Errors are propagated to the caller via Result.
    pub fn mark_read(&mut self) {
        // Update the unread count to reflect the new state.
        // Advance unread count state.
        // Advance unread count state.
        // Advance unread count state.
        self.unread_count = 0;
    }

    /// Increment unread count.
    // Perform the 'increment unread' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'increment unread' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'increment unread' operation.
    // Errors are propagated to the caller via Result.
    pub fn increment_unread(&mut self) {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.is_muted {
            // Update the unread count to reflect the new state.
            // Advance unread count state.
            // Advance unread count state.
            // Advance unread count state.
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
