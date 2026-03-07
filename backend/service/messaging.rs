//! Room and message operations.
//!
//! This module owns chat-room lifecycle, message ingress/egress, and listener
//! fanout for message and transfer updates.

use crossbeam_channel::{unbounded, Receiver};

use crate::core::error::{MeshInfinityError, Result};
use crate::core::PeerId;

use super::{
    dm_room_id, ensure_room_exists, now_label, peer_id_string, random_id, trust_label,
    CoreTrustLevel, FileTransferSummary, MeshInfinityService, Message, NodeMode, PeerSummary,
    RoomSummary,
};

impl MeshInfinityService {
    /// Return currently selected room id, if one is active.
    pub fn active_room_id(&self) -> Option<String> {
        self.state.read().unwrap().active_room_id.clone()
    }

    /// Return active room display title or fallback label.
    pub fn active_room_title(&self) -> String {
        let state = self.state.read().unwrap();
        let active_id = state.active_room_id.as_deref().unwrap_or_default();
        state
            .rooms
            .iter()
            .find(|room| room.id == active_id)
            .map(|room| room.name.clone())
            .unwrap_or_default()
    }

    /// Return messages for current active room.
    pub fn messages_for_active_room(&self) -> Vec<Message> {
        let state = self.state.read().unwrap();
        let active_id = match &state.active_room_id {
            Some(id) => id.clone(),
            None => return Vec::new(),
        };
        state.messages.get(&active_id).cloned().unwrap_or_default()
    }

    /// Return messages for an explicit room id.
    pub fn messages_for_room(&self, room_id: &str) -> Vec<Message> {
        let state = self.state.read().unwrap();
        state.messages.get(room_id).cloned().unwrap_or_default()
    }

    /// Return room messages newer than `cursor_message_id`.
    pub fn sync_room_messages_since(
        &self,
        room_id: &str,
        after_message_id: Option<&str>,
    ) -> Result<Vec<Message>> {
        let state = self.state.read().unwrap();
        ensure_room_exists(&state.rooms, room_id)?;
        let messages = state
            .messages
            .get(room_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let synced = match after_message_id {
            Some(cursor) => {
                if let Some(index) = messages.iter().position(|m| m.id == cursor) {
                    messages.iter().skip(index + 1).cloned().collect()
                } else {
                    // Unknown cursor: return full room to self-heal diverged clients.
                    messages.to_vec()
                }
            }
            None => messages.to_vec(),
        };

        Ok(synced)
    }

    /// Create a new room and return generated room id.
    pub fn create_room(&self, name: &str) -> Result<String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(MeshInfinityError::InvalidConfiguration(
                "room name required".to_string(),
            ));
        }

        let mut state = self.state.write().unwrap();
        if state.settings.node_mode == NodeMode::Server {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        let room_id = random_id("room");
        state.rooms.insert(
            0,
            RoomSummary {
                id: room_id.clone(),
                name: trimmed.to_string(),
                last_message: String::new(),
                unread_count: 0,
                timestamp: String::new(),
            },
        );
        state.messages.insert(room_id.clone(), Vec::new());
        state.active_room_id = Some(room_id.clone());
        Ok(room_id)
    }

    /// Select active room by id.
    pub fn select_room(&self, room_id: &str) -> Result<()> {
        let mut state = self.state.write().unwrap();
        if state.settings.node_mode == NodeMode::Server {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        ensure_room_exists(&state.rooms, room_id)?;

        state.active_room_id = Some(room_id.to_string());
        if let Some(room) = state.rooms.iter_mut().find(|room| room.id == room_id) {
            room.unread_count = 0;
        }
        Ok(())
    }

    /// Delete a room and associated messages.
    pub fn delete_room(&self, room_id: &str) -> Result<()> {
        let mut state = self.state.write().unwrap();
        if state.settings.node_mode == NodeMode::Server {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        ensure_room_exists(&state.rooms, room_id)?;

        let index = state
            .rooms
            .iter()
            .position(|room| room.id == room_id)
            .expect("validated room existence");

        state.rooms.remove(index);
        state.messages.remove(room_id);

        if state.active_room_id.as_deref() == Some(room_id) {
            state.active_room_id = state.rooms.first().map(|room| room.id.clone());
        }

        Ok(())
    }

    /// Clear active-room selection.
    pub fn clear_active_room(&self) {
        self.state.write().unwrap().active_room_id = None;
    }

    /// Register message listener channel for push updates.
    pub fn register_message_listener(&self) -> Receiver<Message> {
        let (sender, receiver) = unbounded();
        self.state.write().unwrap().message_listeners.push(sender);
        receiver
    }

    /// Register transfer listener channel for push updates.
    pub fn register_transfer_listener(&self) -> Receiver<FileTransferSummary> {
        let (sender, receiver) = unbounded();
        self.state.write().unwrap().transfer_listeners.push(sender);
        receiver
    }

    /// Broadcast message update to all subscribers.
    pub(super) fn notify_message_listeners(&self, message: &Message) {
        let state = self.state.read().unwrap();
        for sender in &state.message_listeners {
            let _ = sender.send(message.clone());
        }
    }

    /// Broadcast transfer update to all subscribers.
    pub(super) fn notify_transfer_listeners(&self, transfer: &FileTransferSummary) {
        let state = self.state.read().unwrap();
        for sender in &state.transfer_listeners {
            let _ = sender.send(transfer.clone());
        }
    }

    /// Send text message to currently active room.
    pub fn send_message(&self, text: &str) -> Result<()> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let room_id = match self.state.read().unwrap().active_room_id.clone() {
            Some(id) => id,
            None => return Ok(()),
        };

        self.send_message_to_room(&room_id, trimmed)
    }

    /// Send text message to a specific room id.
    pub fn send_message_to_room(&self, room_id: &str, text: &str) -> Result<()> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(());
        }

        ensure_room_exists(&self.state.read().unwrap().rooms, room_id)?;

        let outbound_message = {
            let mut state = self.state.write().unwrap();
            if state.settings.node_mode == NodeMode::Server {
                return Err(MeshInfinityError::OperationNotSupported);
            }

            let message = Message {
                id: random_id("msg"),
                room_id: room_id.to_string(),
                sender: "You".to_string(),
                text: trimmed.to_string(),
                timestamp: now_label(),
                is_outgoing: true,
            };

            state
                .messages
                .entry(room_id.to_string())
                .or_default()
                .push(message.clone());

            if let Some(room) = state.rooms.iter_mut().find(|room| room.id == room_id) {
                room.last_message = message.text.clone();
                room.timestamp = message.timestamp.clone();
            }

            message
        };

        self.notify_message_listeners(&outbound_message);

        for peer in self.peers.get_all_peers() {
            let _ = self.route_outbound_message(peer.peer_id, trimmed.as_bytes());
        }

        Ok(())
    }

    /// Delete message by id and return containing room id.
    pub fn delete_message(&self, message_id: &str) -> Result<String> {
        let mut state = self.state.write().unwrap();
        if state.settings.node_mode == NodeMode::Server {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        let mut found_room_id: Option<String> = None;
        for (room_id, messages) in state.messages.iter_mut() {
            if let Some(index) = messages.iter().position(|message| message.id == message_id) {
                messages.remove(index);
                found_room_id = Some(room_id.clone());
                break;
            }
        }

        let room_id = found_room_id.ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("message not found".to_string())
        })?;

        let last_message_info = state
            .messages
            .get(&room_id)
            .and_then(|messages| messages.last())
            .map(|msg| (msg.text.clone(), msg.timestamp.clone()));

        if let Some(room) = state.rooms.iter_mut().find(|room| room.id == room_id) {
            if let Some((text, timestamp)) = last_message_info {
                room.last_message = text;
                room.timestamp = timestamp;
            } else {
                room.last_message.clear();
                room.timestamp.clear();
            }
        }

        Ok(room_id)
    }

    /// Receive and ingest an inbound message from peer transport.
    pub fn receive_message(
        &self,
        peer_id: PeerId,
        room_id: Option<&str>,
        text: &str,
    ) -> Result<()> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(());
        }

        let short_code: String = peer_id_string(&peer_id).chars().take(6).collect();
        let sender = format!("Peer {}", short_code);
        let resolved_room_id = room_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| dm_room_id(&peer_id));

        let inbound_message = {
            let mut state = self.state.write().unwrap();
            if state.rooms.iter().all(|room| room.id != resolved_room_id) {
                state.rooms.push(RoomSummary {
                    id: resolved_room_id.clone(),
                    name: sender.clone(),
                    last_message: String::new(),
                    unread_count: 0,
                    timestamp: String::new(),
                });
            }

            let message = Message {
                id: random_id("msg"),
                room_id: resolved_room_id.clone(),
                sender: sender.clone(),
                text: trimmed.to_string(),
                timestamp: now_label(),
                is_outgoing: false,
            };

            state
                .messages
                .entry(resolved_room_id.clone())
                .or_default()
                .push(message.clone());

            let is_active = state.active_room_id.as_deref() == Some(&resolved_room_id);
            if let Some(room) = state
                .rooms
                .iter_mut()
                .find(|room| room.id == resolved_room_id)
            {
                room.last_message = message.text.clone();
                room.timestamp = message.timestamp.clone();
                if !is_active {
                    room.unread_count = room.unread_count.saturating_add(1);
                }
            }

            if state
                .peers
                .iter()
                .all(|peer| peer.id != peer_id_string(&peer_id))
            {
                let trust_level = self
                    .peers
                    .get_trust_level(&peer_id)
                    .unwrap_or(CoreTrustLevel::Caution);
                state.peers.push(PeerSummary {
                    id: peer_id_string(&peer_id),
                    name: sender,
                    trust_level: trust_level as i32,
                    status: trust_label(trust_level),
                });
            }

            state.bytes_received = state.bytes_received.saturating_add(trimmed.len() as u64);
            message
        };

        self.notify_message_listeners(&inbound_message);

        Ok(())
    }
}
