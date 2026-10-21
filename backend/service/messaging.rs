//! Messaging operations for `MeshRuntime`.
//!
//! This module implements the inbound frame dispatcher (`process_inbound_frame`)
//! and all outbound messaging operations: send text, reactions, read receipts,
//! typing indicators, reply, edit, delete, forward, pin, disappearing timers,
//! search, and prune.
//!
//! ## Frame types handled by process_inbound_frame
//! All frame-type dispatch is done in this method; specialist handlers for
//! non-message frames (calls, WireGuard, pairing, gossip, etc.) are called
//! from here and defined in their respective service sub-modules.
//!
//! ## Error policy
//! All inbound-frame methods return `bool`: `true` = accepted, `false` =
//! rejected/ignored.  Rejection is always silent — we never send an error
//! response to a peer; doing so would leak state to a potential adversary.

use crate::crypto::double_ratchet::{DoubleRatchetSession, RatchetHeader};
use crate::crypto::message_encrypt::{decrypt_message, MessageContext};
use crate::identity::peer_id::PeerId;
use crate::messaging::room::Room;
use crate::service::runtime::{bootstrap_ratchet_session, MeshRuntime};
use ed25519_dalek::{Signature, Signer, Verifier};
use x25519_dalek::StaticSecret as X25519Secret;

const GROUP_MESSAGE_INNER_SIG_DOMAIN: &[u8] = b"meshinfinity-group-inner-sender-v1";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct GroupSenderKeySeedWire {
    chain_key: String,
    iteration: u32,
    verifying_key: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct GroupMessageSkWire {
    iteration: u32,
    ciphertext: String,
    signature: String,
    sender_key_seed: GroupSenderKeySeedWire,
    sender: String,
    room_id: String,
    msg_id: String,
    text: String,
    timestamp: u64,
    sender_sig: String,
}

fn build_group_inner_signature_message(
    group_id: &[u8; 32],
    room_id: &str,
    msg_id: &str,
    text: &str,
    timestamp: u64,
    sender: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        GROUP_MESSAGE_INNER_SIG_DOMAIN.len()
            + group_id.len()
            + sender.len()
            + room_id.len()
            + msg_id.len()
            + text.len()
            + 64,
    );
    message.extend_from_slice(GROUP_MESSAGE_INNER_SIG_DOMAIN);
    message.extend_from_slice(group_id);
    message.extend_from_slice(&(room_id.len() as u64).to_le_bytes());
    message.extend_from_slice(room_id.as_bytes());
    message.extend_from_slice(&(msg_id.len() as u64).to_le_bytes());
    message.extend_from_slice(msg_id.as_bytes());
    message.extend_from_slice(&(text.len() as u64).to_le_bytes());
    message.extend_from_slice(text.as_bytes());
    message.extend_from_slice(&timestamp.to_le_bytes());
    message.extend_from_slice(sender);
    message
}

/// The canonical `group_message_sk` envelope the ring signature covers.
///
/// SPEC §3.5.2: "The ciphertext is the entire canonical group envelope
/// being authenticated, including its authenticated header."  For the
/// Sender Key frame that is the outer AEAD nonce followed by the wrapped
/// ciphertext.  The group id and epoch are *not* repeated here because the
/// ring transcript already binds them from the verifier's own record; the
/// frame's copies are only used to find that record.
fn group_sk_envelope_bytes(nonce: &[u8; 12], wrapped: &[u8]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(nonce.len() + wrapped.len());
    envelope.extend_from_slice(nonce);
    envelope.extend_from_slice(wrapped);
    envelope
}

/// Why a group control payload could not be opened with the ratchet.
///
/// Every variant is a silent rejection on the wire (we never answer a peer
/// with an error); the distinction exists so callers can decide whether to
/// request re-inclusion (§8.7.6) without parsing strings.
#[derive(Debug)]
enum GroupRatchetError {
    /// No installed session and no usable candidate from the frame.
    NoSession,
    /// The ratchet refused the header (duplicate, gap too large, exhausted).
    Ratchet,
    /// The ciphertext did not authenticate under the derived message key.
    Aead,
}

/// Parse the classical X3DH init header (`x3dh_eph_pub`, `x3dh_encrypted_ik`)
/// from an inbound frame.
///
/// Both fields must be present, hex-encoded and exactly the protocol sizes
/// (32 and `ENCRYPTED_IK_SIZE` bytes); anything else yields `None`.  Parsing
/// says nothing about who sent the header — the responder binds it to the
/// contact's identity key in `x3dh_respond`.
fn parse_x3dh_init_header(
    envelope: &serde_json::Value,
) -> Option<crate::crypto::x3dh::X3dhInitHeader> {
    use crate::crypto::x3dh::{X3dhInitHeader, ENCRYPTED_IK_SIZE};

    // Alice's ephemeral X25519 public key (32 bytes).
    let eph_pub: [u8; 32] = envelope
        .get("x3dh_eph_pub")
        .and_then(|v| v.as_str())
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| b.as_slice().try_into().ok())?;
    // Alice's identity key, AEAD-encrypted (32-byte key + 16-byte tag).
    let encrypted_ik_pub: [u8; ENCRYPTED_IK_SIZE] = envelope
        .get("x3dh_encrypted_ik")
        .and_then(|v| v.as_str())
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| b.as_slice().try_into().ok())?;
    Some(X3dhInitHeader {
        eph_pub,
        encrypted_ik_pub,
    })
}

/// Extract the message text from a decrypted direct-message payload.
///
/// New-format payloads are JSON `{"hdr": {...}, "text": "..."}`.  The inner
/// header is AEAD-authenticated and must match the outer header the key was
/// derived from; a mismatch means the encrypted outer header blob was
/// substituted and the frame is rejected.  Legacy payloads are bare UTF-8
/// text.  Returns `None` for a mismatch or a malformed payload.
fn extract_direct_message_text(plaintext: &[u8], header: &RatchetHeader) -> Option<String> {
    // Try the structured format first; fall back to bare text.
    let Ok(inner) = serde_json::from_slice::<serde_json::Value>(plaintext) else {
        return String::from_utf8(plaintext.to_vec()).ok();
    };
    if let Some(inner_hdr) = inner.get("hdr") {
        // Each field of the authenticated inner header must equal the outer.
        let inner_rp = inner_hdr
            .get("ratchet_pub")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let inner_pcl = inner_hdr
            .get("prev_chain_len")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let inner_mn = inner_hdr
            .get("msg_num")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        if inner_rp != hex::encode(header.ratchet_pub)
            || inner_pcl != header.prev_chain_len
            || inner_mn != header.msg_num
        {
            return None;
        }
    }
    // The text field is mandatory in the structured format.
    inner
        .get("text")
        .and_then(|v| v.as_str())
        .map(|t| t.to_string())
}

fn room_preview_text(text: &str) -> String {
    if text.len() > 80 {
        format!("{}…", &text[..80])
    } else {
        text.to_string()
    }
}

impl MeshRuntime {
    fn group_for_room(&self, room_id_hex: &str) -> Option<(crate::groups::group::Group, Room)> {
        use crate::messaging::message::ConversationType;

        let room = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms
                .iter()
                .find(|room| {
                    room.conversation_type == ConversationType::Group
                        && hex::encode(room.id) == room_id_hex
                })
                .cloned()?
        };

        let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        groups
            .iter()
            .find(|group| {
                group.profile.display_name == room.name
                    && group.members.len() == room.participants.len()
                    && group
                        .members
                        .iter()
                        .all(|member| room.participants.contains(member))
            })
            .cloned()
            .map(|group| (group, room))
    }

    /// Seal a group control payload for one member under their ratchet session.
    ///
    /// Group control frames (`group_invite`, `group_rekey`,
    /// `group_ring_commit`) encrypt `payload` directly under the next
    /// ratchet message key with ChaCha20-Poly1305 and an all-zero nonce (the
    /// key is single-use), carry the ratchet header as a top-level field,
    /// and attach our pending X3DH init header while the peer has not yet
    /// replied.  Returns `None` when we hold no session for `member` — the
    /// caller cannot reach them until a session exists.  The sessions lock
    /// is held for the whole step so two frames cannot race one send key.
    fn seal_group_control_frame(
        &self,
        member: PeerId,
        frame_type: &str,
        payload: &[u8],
    ) -> Option<serde_json::Value> {
        use chacha20poly1305::{
            aead::{Aead, Nonce},
            ChaCha20Poly1305, Key, KeyInit,
        };

        let our_peer_id = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|identity| identity.peer_id())?;

        let mut sessions = self
            .ratchet_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let session = sessions.get_mut(&member)?;
        let (header, msg_key) = session.next_send_msg_key().ok()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let nonce = Nonce::<ChaCha20Poly1305>::default();
        let ciphertext = cipher.encrypt(&nonce, payload).ok()?;

        let mut frame = serde_json::json!({
            "type":           frame_type,
            "sender":         hex::encode(our_peer_id.0),
            "ratchet_header": serde_json::to_value(&header).ok()?,
            "ciphertext":     hex::encode(&ciphertext),
        });
        // First contact: the peer needs our X3DH init header to derive the
        // session this frame was sealed under.
        let x3dh_fields = self
            .x3dh_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&member)
            .copied();
        if let Some((eph, ik)) = x3dh_fields {
            if let Some(obj) = frame.as_object_mut() {
                obj.insert(
                    "x3dh_eph_pub".into(),
                    serde_json::Value::String(hex::encode(eph)),
                );
                obj.insert(
                    "x3dh_encrypted_ik".into(),
                    serde_json::Value::String(hex::encode(ik)),
                );
            }
        }
        Some(frame)
    }

    /// Announce our ring public key for `group` to every other member.
    ///
    /// This is the "authenticated membership commit" of SPEC §3.5.2: the
    /// key travels inside each member's ratchet session, so the recipient
    /// knows exactly which authenticated peer it belongs to.  Members we
    /// have no session with yet are skipped; they learn the key from the
    /// admin's next invite snapshot or our next commit.
    fn broadcast_ring_key_commit(
        &self,
        group: &crate::groups::group::Group,
        ring_public: &[u8; 32],
    ) {
        let payload = serde_json::json!({
            "type":    "group_ring_commit",
            "groupId": hex::encode(group.group_id),
            "ringPub": hex::encode(ring_public),
        });
        let Ok(payload_bytes) = serde_json::to_vec(&payload) else {
            return;
        };
        for member in &group.members {
            if *member == group.our_peer_id {
                continue;
            }
            if let Some(frame) =
                self.seal_group_control_frame(*member, "group_ring_commit", &payload_bytes)
            {
                self.send_raw_frame(&member.to_hex(), &frame);
            }
        }
        self.save_ratchet_sessions();
    }

    #[allow(clippy::too_many_arguments)] // All params are distinct message metadata fields
    fn persist_room_message(
        &self,
        room_id_hex: &str,
        sender_hex: &str,
        text: &str,
        timestamp: u64,
        msg_id_hex: &str,
        is_outgoing: bool,
        auth_status: Option<&str>,
    ) {
        let mut message = serde_json::json!({
            "id":         msg_id_hex,
            "roomId":     room_id_hex,
            "sender":     sender_hex,
            "text":       text,
            "timestamp":  timestamp,
            "isOutgoing": is_outgoing,
        });
        if let Some(status) = auth_status {
            message["authStatus"] = serde_json::Value::String(status.to_string());
        }

        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.to_string())
            .or_default()
            .push(message.clone());

        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms
                .iter_mut()
                .find(|room| hex::encode(room.id) == room_id_hex)
            {
                room.last_message_preview = Some(room_preview_text(text));
                room.last_message_at = Some(timestamp);
                if is_outgoing {
                    room.next_sequence += 1;
                } else if !room.is_muted {
                    room.unread_count += 1;
                }
            }
        }

        self.push_event("MessageAdded", message);
        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms
                .iter()
                .find(|room| hex::encode(room.id) == room_id_hex)
                .map(|room| {
                    serde_json::json!({
                        "id":          hex::encode(room.id),
                        "name":        room.name,
                        "lastMessage": room.last_message_preview,
                        "unreadCount": room.unread_count,
                        "timestamp":   room.last_message_at,
                    })
                })
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }
    }

    /// Send a Sender Key group message authenticated by a ring signature.
    ///
    /// The outer envelope is signed with our dedicated ring key for the
    /// group under profile `MI-AOS-R255-1` (§3.5.2), so recipients can
    /// check it came from a current member without the outer layer naming
    /// us.  Under the spec's release gate an unreviewed build cannot sign:
    /// Private/Closed groups have no attributable fallback (only Open and
    /// Public groups keep attributable outer authentication), so the error
    /// is surfaced as an `Error` event and nothing is sent.
    fn send_ring_group_message(&mut self, room_id_hex: &str, text: &str) -> bool {
        use crate::crypto::ring_sig::{ring_sign, RingContextType};
        use crate::crypto::sender_keys::SenderKey;
        use crate::service::runtime::try_random_fill;

        if !self.identity_unlocked || text.is_empty() {
            return false;
        }

        let (mut group, room) = match self.group_for_room(room_id_hex) {
            Some(value) => value,
            None => return false,
        };
        if !group.profile.network_type.uses_ring_signatures() {
            return false;
        }

        let (our_peer_id, identity_signing_key) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(identity) => (identity.peer_id(), identity.ed25519_signing.clone()),
                None => return false,
            }
        };

        let mut msg_id_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        if !try_random_fill(&mut msg_id_bytes) || !try_random_fill(&mut nonce_bytes) {
            return false;
        }
        let msg_id_hex = hex::encode(msg_id_bytes);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        let sender_chain_key = match group.my_sender_chain_key {
            Some(value) => value,
            None => return false,
        };
        let sender_signing_key = match group.my_sender_signing_key {
            Some(value) => value,
            None => return false,
        };
        let sender_iteration = group.my_sender_iteration;

        let mut sender_key =
            match SenderKey::from_parts(sender_chain_key, sender_iteration, &sender_signing_key) {
                Ok(value) => value,
                Err(_) => return false,
            };
        let sender_key_seed = GroupSenderKeySeedWire {
            chain_key: hex::encode(sender_chain_key),
            iteration: sender_iteration,
            verifying_key: hex::encode(sender_key.verifying_key().to_bytes()),
        };

        let sender_sig_message = build_group_inner_signature_message(
            &group.group_id,
            room_id_hex,
            &msg_id_hex,
            text,
            timestamp,
            &our_peer_id.0,
        );
        let sender_sig = identity_signing_key.sign(&sender_sig_message);

        let sk_plaintext = GroupMessageSkWire {
            iteration: sender_iteration,
            ciphertext: String::new(),
            signature: String::new(),
            sender_key_seed,
            sender: our_peer_id.to_hex(),
            room_id: room_id_hex.to_string(),
            msg_id: msg_id_hex.clone(),
            text: text.to_string(),
            timestamp,
            sender_sig: hex::encode(sender_sig.to_bytes()),
        };
        let sk_plaintext_bytes = match serde_json::to_vec(&sk_plaintext) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let sk_message = match sender_key.encrypt(&sk_plaintext_bytes) {
            Ok(value) => value,
            Err(_) => return false,
        };

        let wrapped_inner = serde_json::json!({
            "iteration":       sk_message.iteration,
            "ciphertext":      hex::encode(&sk_message.ciphertext),
            "signature":       hex::encode(&sk_message.signature),
            "sender_key_seed": {
                "chain_key":     sk_plaintext.sender_key_seed.chain_key,
                "iteration":     sk_plaintext.sender_key_seed.iteration,
                "verifying_key": sk_plaintext.sender_key_seed.verifying_key,
            }
        });
        let wrapped_inner_bytes = match serde_json::to_vec(&wrapped_inner) {
            Ok(value) => value,
            Err(_) => return false,
        };

        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
        let symmetric_cipher = match ChaCha20Poly1305::new_from_slice(&group.symmetric_key) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let wrapped = match symmetric_cipher.encrypt(
            chacha20poly1305::Nonce::from_slice(&nonce_bytes),
            wrapped_inner_bytes.as_ref(),
        ) {
            Ok(value) => value,
            Err(_) => return false,
        };

        // The ring is every member's committed ring key; a member we have
        // no key for cannot be represented, so the message cannot be sent
        // until their commit arrives.
        let Some(ring) = group.sorted_ring() else {
            self.push_event(
                "Error",
                serde_json::json!({
                    "message": "group ring is incomplete: a member has not committed a ring key"
                }),
            );
            return false;
        };
        // Our own ring scalar — dedicated to this group, never the identity key.
        let Some(ring_secret) = group.my_ring_secret else {
            self.push_event(
                "Error",
                serde_json::json!({ "message": "no ring key for this group yet" }),
            );
            return false;
        };
        let context = group.ring_context(RingContextType::Application);
        let envelope_bytes = group_sk_envelope_bytes(&nonce_bytes, &wrapped);
        let ring_sig = match ring_sign(&ring_secret, &ring, &context, &envelope_bytes) {
            Ok(value) => value,
            // Includes `ProfileNotEnabled` under the §3.5.2 release gate.
            Err(error) => {
                self.push_event(
                    "Error",
                    serde_json::json!({ "message": format!("ring signing failed: {error}") }),
                );
                return false;
            }
        };

        let frame = serde_json::json!({
            "type":      "group_message_sk",
            "groupId":   hex::encode(group.group_id),
            "epoch":     group.sender_key_epoch,
            "nonce":     hex::encode(nonce_bytes),
            "wrapped":   hex::encode(&wrapped),
            "ring_sig":  ring_sig,
        });

        for participant in &room.participants {
            if *participant == our_peer_id {
                continue;
            }
            self.send_raw_frame(&participant.to_hex(), &frame);
        }

        group.my_sender_chain_key = Some(*sender_key.chain_key_bytes());
        group.my_sender_iteration = sender_key.iteration;
        if let Some(group_mut) = self
            .groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter_mut()
            .find(|candidate| candidate.group_id == group.group_id)
        {
            group_mut.my_sender_chain_key = group.my_sender_chain_key;
            group_mut.my_sender_iteration = group.my_sender_iteration;
        }

        self.persist_room_message(
            room_id_hex,
            &our_peer_id.to_hex(),
            text,
            timestamp,
            &msg_id_hex,
            true,
            None,
        );
        self.save_groups();
        self.save_messages();
        self.save_rooms();
        true
    }

    // -----------------------------------------------------------------------
    // Inbound frame dispatcher
    // -----------------------------------------------------------------------

    /// Decrypt an inbound message frame and push events for the Flutter UI.
    ///
    /// Called from the poll loop for every complete TCP frame received from an
    /// identified peer.  Dispatches non-message frame types (call signalling,
    /// WireGuard, pairing, gossip, etc.) to their specialist handlers.
    ///
    /// Returns `true` if the frame was accepted and processed, `false` if it
    /// was malformed, cryptographically invalid, or from an unknown sender.
    pub fn process_inbound_frame(&self, envelope: &serde_json::Value) -> bool {
        // Pairing hello must be dispatched before the "unknown sender" check
        // because the sender is not yet in our contact store.
        if envelope.get("type").and_then(|t| t.as_str()) == Some("pairing_hello") {
            return self.process_pairing_hello(envelope);
        }

        // Message request from an unpaired sender — dispatched before the
        // "unknown sender" gate for the same reason as pairing_hello.
        // The frame carries the sender's public keys so we can verify the
        // signature without a pre-existing contact record (§10.1.1).
        if envelope.get("type").and_then(|t| t.as_str()) == Some("message_request") {
            return self.process_message_request_frame(envelope);
        }

        let frame_type = envelope.get("type").and_then(|t| t.as_str()).unwrap_or("");

        // LoSec negotiation — carry their own Ed25519 signatures.
        if frame_type == "losec_request" {
            return self.process_losec_request_frame(envelope);
        }
        if frame_type == "losec_response" {
            return self.process_losec_response_frame(envelope);
        }

        // Gossip map entry.
        if frame_type == "gossip_map_entry" {
            return self.process_gossip_map_entry_frame(envelope);
        }
        if frame_type == "service_record" {
            return self.process_service_record_frame(envelope);
        }

        // Call signalling.
        if frame_type == "call_offer" {
            return self.process_call_offer_frame(envelope);
        }
        if frame_type == "call_answer" {
            return self.process_call_answer_frame(envelope);
        }
        if frame_type == "call_hangup" {
            return self.process_call_hangup_frame(envelope);
        }

        // WireGuard handshake.
        if frame_type == "wg_init" {
            return self.process_wg_init_frame(envelope);
        }
        if frame_type == "wg_response" {
            return self.process_wg_response_frame(envelope);
        }

        // Routing.
        if frame_type == "route_announcement" {
            return self.process_route_announcement_frame(envelope);
        }
        if frame_type == "mesh_packet" {
            return self.process_mesh_packet_frame(envelope);
        }

        // File transfers.
        if frame_type == "file_offer" {
            return self.process_file_offer_frame(envelope);
        }
        if frame_type == "file_chunk" {
            return self.process_file_chunk_frame(envelope);
        }
        if frame_type == "file_complete" {
            return self.process_file_complete_frame(envelope);
        }

        // Group messaging.
        if frame_type == "group_rekey" {
            return self.process_group_rekey_frame(envelope);
        }
        if frame_type == "group_invite" {
            return self.process_group_invite_frame(envelope);
        }
        if frame_type == "group_message" {
            return self.process_group_message_frame(envelope);
        }
        if frame_type == "group_message_sk" {
            return self.process_group_message_sk_frame(envelope);
        }
        if frame_type == "group_reinclusion_request" {
            return self.process_group_reinclusion_request_frame(envelope);
        }
        if frame_type == "group_ring_commit" {
            return self.process_group_ring_commit_frame(envelope);
        }

        // Store-and-forward.
        if frame_type == "sf_deposit" {
            return self.process_sf_deposit_frame(envelope);
        }
        if frame_type == "sf_deliver" {
            return self.process_sf_deliver_frame(envelope);
        }

        // Delivery receipt.
        if frame_type == "delivery_receipt" {
            return self.process_delivery_receipt_frame(envelope);
        }

        // Remote killswitch (§3.9, §8.3) — Level 8 (InnerCircle) gate.
        if frame_type == "remote_wipe" {
            return self.process_remote_wipe_frame(envelope);
        }

        // Keepalive probes.
        if frame_type == "keepalive" {
            let our_hex = self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|id| id.peer_id().to_hex())
                .unwrap_or_default();
            if let Some(peer_hex) = envelope.get("sender").and_then(|v| v.as_str()) {
                self.send_raw_frame(
                    peer_hex,
                    &serde_json::json!({
                        "type": "keepalive_ack",
                        "sender": our_hex,
                    }),
                );
            }
            return true;
        }
        // Keepalive ack — no action needed; last_rx already updated.
        if frame_type == "keepalive_ack" {
            return true;
        }

        // Typing indicator.
        if frame_type == "typing_indicator" {
            if let (Some(sender), Some(room_id)) = (
                envelope.get("sender").and_then(|v| v.as_str()),
                envelope.get("roomId").and_then(|v| v.as_str()),
            ) {
                let is_active = envelope
                    .get("active")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.push_event(
                    "TypingIndicator",
                    serde_json::json!({
                        "roomId": room_id,
                        "peerId": sender,
                        "active": is_active,
                    }),
                );
            }
            return true;
        }

        // Emoji reaction.
        if frame_type == "reaction" {
            if let (Some(sender), Some(room_id), Some(msg_id), Some(emoji)) = (
                envelope.get("sender").and_then(|v| v.as_str()),
                envelope.get("roomId").and_then(|v| v.as_str()),
                envelope.get("msgId").and_then(|v| v.as_str()),
                envelope.get("emoji").and_then(|v| v.as_str()),
            ) {
                if !emoji.is_empty() {
                    self.push_event(
                        "ReactionAdded",
                        serde_json::json!({
                            "roomId": room_id,
                            "msgId":  msg_id,
                            "peerId": sender,
                            "emoji":  emoji,
                        }),
                    );
                }
            }
            return true;
        }

        // ---- Direct encrypted message (Double Ratchet path) ----
        // All other frame types that carry a "ciphertext" field are treated as
        // direct encrypted messages.  Unknown frame types that lack a ciphertext
        // field are silently discarded.

        macro_rules! field_str {
            ($key:expr) => {
                match envelope.get($key).and_then(|v| v.as_str()) {
                    Some(s) => s.to_string(),
                    None => return false,
                }
            };
        }

        let sender_hex = field_str!("sender");
        let room_id_hex = field_str!("room");
        let msg_id = field_str!("msg_id");
        let ts = envelope.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
        let ciphertext_hex = field_str!("ciphertext");

        // SECURITY (HIGH-4): Check the deduplication cache BEFORE any
        // expensive cryptographic work.  If the message ID has already been
        // processed in this room, silently drop it.  This prevents replay
        // attacks where an attacker re-delivers a previously processed
        // message, potentially causing duplicate notifications or state
        // corruption after session reload.
        {
            let mut dedup = self
                .dedup_msg_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if dedup.is_duplicate(&room_id_hex, &msg_id) {
                // Duplicate detected — silently discard the frame.
                eprintln!(
                    "[messaging] DEBUG: duplicate message {} in room {} — dropped",
                    msg_id, room_id_hex
                );
                return false;
            }
        }

        // Decode the ciphertext; a non-hex payload is a malformed frame.
        let ciphertext = match hex::decode(&ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sender_id_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let sender_peer_id = PeerId(sender_id_bytes);

        // Reject frames from unknown senders.
        let contact = match self
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&sender_peer_id)
            .cloned()
        {
            Some(c) => c,
            None => return false,
        };

        // A blocked contact (§22.8.2 "Block contact") is dropped here, before
        // any session or decrypt work: the block costs nothing to enforce and
        // nothing is sent back, so the sender cannot tell a block from an
        // offline peer.
        if contact.blocked {
            return false;
        }

        // Resolve a session for this sender.  An existing one is used as-is.
        // If none exists, build a *candidate* from the frame's X3DH material
        // (or static DH for an explicitly legacy contact) but do not install
        // it: nothing in the frame has been authenticated yet, and a session
        // installed from unverified material would let any network peer
        // wedge this contact's session.  SPEC §7.0.1 commits session creation
        // together with message acceptance, never before, so the candidate
        // is installed below only once the four-layer decrypt succeeds.
        let has_session = self
            .ratchet_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&sender_peer_id);
        let candidate = if has_session {
            None
        } else {
            match self.bootstrap_session_from_frame(envelope, &contact, sender_peer_id) {
                Some(session) => Some(session),
                None => return false,
            }
        };

        // SECURITY (CRIT-2): the ratchet header arrives encrypted under a key
        // derived from the static DH between us and the sender, so an
        // observer cannot track ratchet key changes or counters.
        //
        // The encrypted header is *required*.  The former plaintext
        // `ratchet_pub` / `prev_chain_len` / `msg_num` fallback was removed:
        // those fields were attacker-controlled and let an unauthenticated
        // peer choose the DH input for a contact's session.  No shipping
        // sender emits plaintext headers (`send_text_message` always encrypts).
        let enc_header_hex = match envelope.get("enc_header").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return false,
        };
        let enc_bytes = match hex::decode(enc_header_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        // Our X25519 secret: used for the header key here and for Step 4
        // of the four-layer decrypt below.
        let our_x25519_secret = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => X25519Secret::from(id.x25519_secret.to_bytes()),
                None => return false,
            }
        };
        // Header key = HKDF(DH(our static secret, sender's static public)).
        let their_x25519_pub_for_hdr = x25519_dalek::PublicKey::from(contact.x25519_public);
        let dh_shared = our_x25519_secret.diffie_hellman(&their_x25519_pub_for_hdr);
        let hdr_key = match DoubleRatchetSession::derive_header_key_from_dh(dh_shared.as_bytes()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let header = match DoubleRatchetSession::decrypt_header_with_key(&enc_bytes, &hdr_key) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Sender's Ed25519 verifying key for the Step 3 signature check.
        let sender_verifying_key =
            match ed25519_dalek::VerifyingKey::from_bytes(&contact.ed25519_public) {
                Ok(k) => k,
                Err(_) => return false,
            };

        // Derive the message key, authenticate the payload, and only then
        // commit the ratchet step (and install the candidate session).  The
        // whole sequence runs under the sessions lock so the commit replaces
        // exactly the state the pending step was computed from — no send or
        // other receive can interleave.  This is SPEC §7.0.3 "Invalid
        // ciphertext cannot commit state" and §7.0.2 "persist session state
        // and message deduplication atomically" at the in-memory level; the
        // vault write happens once at the end of this function.
        let text = {
            let mut sessions = self
                .ratchet_sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Prefer a session installed since our check above (a concurrent
            // frame may have won the race); otherwise use the candidate.
            let session = match sessions.get(&sender_peer_id) {
                Some(existing) => existing,
                None => match candidate.as_ref() {
                    Some(fresh) => fresh,
                    None => return false,
                },
            };
            // Speculative receive step: `session` is not modified here.  A
            // duplicate, an oversized gap or an exhausted counter is rejected
            // before any AEAD work.
            let pending = match session.prepare_recv(&header) {
                Ok(p) => p,
                Err(_) => return false,
            };
            let (cipher_key, session_nonce, ratchet_msg_key) =
                match DoubleRatchetSession::expand_msg_key(pending.msg_key()) {
                    Ok(keys) => keys,
                    Err(_) => return false,
                };

            // Decrypt via the four-layer scheme (§7.1).  This is the only
            // authentication of the payload: Step 3 verifies the contact's
            // Ed25519 signature and Step 2 the AEAD tag under the ratchet key.
            // On failure the pending state is dropped and nothing changes.
            let plaintext = match decrypt_message(
                &ciphertext,
                &our_x25519_secret,
                &sender_verifying_key,
                &cipher_key,
                &session_nonce,
                &ratchet_msg_key,
                MessageContext::Direct,
            ) {
                Ok(p) => p,
                Err(_) => return false,
            };

            // Extract the text, checking the authenticated inner header
            // against the outer one.  This runs before the commit so a
            // mismatch also leaves the session untouched.
            let text = match extract_direct_message_text(&plaintext, &header) {
                Some(t) => t,
                None => return false,
            };

            // Authenticated: commit the ratchet step.  A first message from
            // this contact installs the candidate session at the same time.
            match sessions.get_mut(&sender_peer_id) {
                Some(existing) => existing.commit_recv(pending),
                None => {
                    if let Some(mut fresh) = candidate {
                        fresh.commit_recv(pending);
                        sessions.insert(sender_peer_id, fresh);
                    }
                }
            }
            text
        };

        // The sender demonstrably shares a session with us, so any X3DH /
        // PQXDH init material we were still attaching to our outgoing
        // messages for them is no longer needed.  This is cleared only after
        // authentication: previously any unauthenticated frame naming the
        // contact could strip the init header from our next message and
        // stop the peer from ever bootstrapping its side.
        self.x3dh_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&sender_peer_id);
        self.pqxdh_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&sender_peer_id);

        // Auto-create a DM room if one doesn't exist for this conversation.
        let room_exists = self
            .rooms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|r| hex::encode(r.id) == room_id_hex);
        if !room_exists {
            let our_peer_id = self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|id| id.peer_id())
                .unwrap_or(PeerId([0u8; 32]));
            let peer_name = contact
                .display_name
                .as_deref()
                .or(contact.local_nickname.as_deref())
                .unwrap_or(&contact.peer_id.short_hex())
                .to_string();
            let mut room = Room::new_dm(our_peer_id, sender_peer_id, &peer_name);
            // Use the sender's room ID so both sides share the same identifier.
            if let Ok(id_bytes) = hex::decode(&room_id_hex) {
                if id_bytes.len() == 16 {
                    room.id.copy_from_slice(&id_bytes);
                }
            }
            self.rooms
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(room);
            self.save_rooms();
        }

        // Build and store the message JSON.
        let msg = serde_json::json!({
            "id":         msg_id,
            "roomId":     room_id_hex,
            "sender":     sender_hex,
            "text":       text,
            "timestamp":  ts,
            "isOutgoing": false,
            "authStatus": "authenticated",
        });
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.clone())
            .or_default()
            .push(msg.clone());

        // Update room last-message preview and unread count.
        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                room.last_message_preview = Some(if text.len() > 80 {
                    format!("{}…", &text[..80])
                } else {
                    text.clone()
                });
                room.last_message_at = Some(ts);
                if !room.is_muted {
                    room.unread_count += 1;
                }
            }
        }

        // Emit events.
        self.push_event("MessageAdded", msg);
        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms
                .iter()
                .find(|r| hex::encode(r.id) == room_id_hex)
                .map(|r| {
                    serde_json::json!({
                        "id":           hex::encode(r.id),
                        "name":         r.name,
                        "lastMessage":  r.last_message_preview,
                        "unreadCount":  r.unread_count,
                        "timestamp":    r.last_message_at,
                    })
                })
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }

        // Send a delivery receipt to the sender (§7.3).
        {
            let our_hex = self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|id| id.peer_id().to_hex())
                .unwrap_or_default();
            let ts_now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.send_raw_frame(
                &sender_hex,
                &serde_json::json!({
                    "type":   "delivery_receipt",
                    "sender": our_hex,
                    "msg_id": msg_id,
                    "room":   room_id_hex,
                    "ts":     ts_now,
                }),
            );
        }

        // Submit notification (§14) — dispatcher applies jitter/suppression.
        if self
            .module_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .social
            .notifications
        {
            let conv_id_padded: Option<[u8; 32]> = hex::decode(&room_id_hex)
                .ok()
                .filter(|b| b.len() == 16)
                .map(|b| {
                    let mut a = [0u8; 32];
                    a[..16].copy_from_slice(&b);
                    a
                });
            let sender_name = self
                .contacts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&sender_peer_id)
                .and_then(|c| c.display_name.clone())
                .unwrap_or_else(|| sender_peer_id.short_hex());
            let notif_event = crate::notifications::NotificationEvent {
                priority: crate::notifications::NotificationPriority::Normal,
                title: format!("New message from {}", sender_name),
                body: Some(if text.len() > 60 {
                    format!("{}…", &text[..60])
                } else {
                    text.clone()
                }),
                sender_id: Some(sender_peer_id.0),
                conversation_id: conv_id_padded,
                created_at: ts,
            };
            self.notifications
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .submit(notif_event);
        }

        // SECURITY (HIGH-4): Record this message ID in the deduplication cache
        // so any future replay of the same message will be silently dropped.
        {
            let mut dedup = self
                .dedup_msg_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            dedup.mark_delivered(&room_id_hex, &msg_id);
        }

        self.save_messages();
        self.save_rooms();
        self.save_ratchet_sessions();
        self.save_dedup_cache();
        true
    }

    /// Build (but do not install) a Double Ratchet session for an inbound
    /// direct-message frame from a contact we have no session with.
    ///
    /// Tries X3DH/PQXDH if the frame carries the init header fields, binding
    /// the header to the contact's known identity key; falls back to static
    /// DH only for explicitly legacy contacts.  Returns `None` if
    /// bootstrapping fails (caller should return `false` to discard the
    /// frame).  The caller installs the returned candidate only after the
    /// frame's payload has authenticated under it.
    fn bootstrap_session_from_frame(
        &self,
        envelope: &serde_json::Value,
        contact: &crate::pairing::contact::ContactRecord,
        _sender_peer_id: PeerId,
    ) -> Option<DoubleRatchetSession> {
        // Classical X3DH init header, if the frame carries one.
        let init_header = parse_x3dh_init_header(envelope);

        let pqxdh_kem_ct = envelope
            .get("pqxdh_kem_ct")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == crate::crypto::x3dh::KEM_CT_SIZE);

        let pqxdh_kem_binding: Option<[u8; 32]> = envelope
            .get("pqxdh_kem_binding")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            });

        if let Some(header) = init_header {
            // X3DH/PQXDH response path: we are Bob receiving Alice's init header.
            use crate::crypto::x3dh::{pqxdh_decapsulate, x3dh_respond};
            use hkdf::Hkdf;
            use zeroize::Zeroizing;

            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = guard.as_ref()?;

            // Alice's ephemeral key, reused by the PQXDH binding below.
            let eph_pub = header.eph_pub;
            // Identity binding (§7.0.2): the IK recovered from the header must
            // be this contact's IK.  Any sender can produce a header that
            // decrypts, so without this check a stranger's init would be
            // accepted as Alice's.  `x3dh_respond` compares in constant time.
            let mut output = x3dh_respond(
                &id.x25519_secret,
                &id.preauth_x25519_secret,
                &header,
                &contact.x25519_public,
            )
            .ok()?;

            // PQXDH: mix in post-quantum shared secret if both fields are present.
            if let (Some(ref kem_ct), Some(ref kem_binding)) = (&pqxdh_kem_ct, &pqxdh_kem_binding) {
                let dh3 = id
                    .preauth_x25519_secret
                    .diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub));
                if let Ok(pq_ss) = pqxdh_decapsulate(
                    &id.kem_decapsulation_key,
                    kem_ct,
                    kem_binding,
                    dh3.as_bytes(),
                ) {
                    let dh1 = id
                        .preauth_x25519_secret
                        .diffie_hellman(&x25519_dalek::PublicKey::from(contact.x25519_public));
                    let dh2 = id
                        .x25519_secret
                        .diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub));
                    let dh3_inner = id
                        .preauth_x25519_secret
                        .diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub));
                    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 32 * 4));
                    ikm.extend_from_slice(&[0xFF; 32]);
                    ikm.extend_from_slice(dh1.as_bytes());
                    ikm.extend_from_slice(dh2.as_bytes());
                    ikm.extend_from_slice(dh3_inner.as_bytes());
                    ikm.extend_from_slice(&pq_ss);
                    let hk = Hkdf::<sha2::Sha256>::new(Some(&[0u8; 32]), &ikm);
                    let mut master = Zeroizing::new([0u8; 32]);
                    if hk.expand(b"MeshInfinity_PQXDH_v1", &mut *master).is_ok() {
                        output = crate::crypto::x3dh::X3dhSessionOutput {
                            master_secret: crate::crypto::secmem::SecureKey32::new(*master).ok()?,
                            is_post_quantum: true,
                            header: None,
                            pqxdh_header: None,
                        };
                    }
                }
            }

            let master = output.master_secret.as_bytes();
            // Bob is the DR receiver; initial ratchet key = his own preauth keypair.
            let preauth_secret = X25519Secret::from(id.preauth_x25519_secret.to_bytes());
            let preauth_pub = *id.preauth_x25519_pub.as_bytes();
            Some(DoubleRatchetSession::init_receiver(
                master,
                preauth_secret,
                &preauth_pub,
            ))
        } else {
            // Only explicitly legacy contacts may omit the authenticated
            // X3DH init header. A prekey-capable contact without that header
            // is a downgrade attempt or malformed frame.
            if contact.preauth_key.is_some() {
                return None;
            }
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().and_then(|id| {
                bootstrap_ratchet_session(id, contact)
                    .ok()
                    .map(|(s, _, _)| s)
            })
        }
    }

    /// Build (but do not install) a candidate ratchet session for a group
    /// control frame (`group_rekey`, `group_invite`, `group_message`) from a
    /// peer we have no session with yet.
    ///
    /// Returns `None` when a session already exists (the existing one must be
    /// used), when the sender is not a contact (there is no identity key to
    /// bind the init header to), or when the frame carries no valid X3DH init
    /// header.  Group frames never fall back to static DH.  The caller passes
    /// the candidate to `open_group_ratchet_payload`, which installs it only
    /// once the payload authenticates.
    fn group_frame_candidate_session(
        &self,
        envelope: &serde_json::Value,
        sender_peer_id: PeerId,
    ) -> Option<DoubleRatchetSession> {
        // An existing session is authoritative; never replace it from a frame.
        if self
            .ratchet_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&sender_peer_id)
        {
            return None;
        }
        // Only contacts have a known identity key to bind the header to.
        let contact = self
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&sender_peer_id)
            .cloned()?;
        let header = parse_x3dh_init_header(envelope)?;

        // Bob-side X3DH: derive the master secret, bound to the contact's IK.
        use crate::crypto::x3dh::x3dh_respond;
        let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let id = guard.as_ref()?;
        let output = x3dh_respond(
            &id.x25519_secret,
            &id.preauth_x25519_secret,
            &header,
            &contact.x25519_public,
        )
        .ok()?;

        // Bob is always the receiver in X3DH — our preauth keypair is the
        // initial ratchet keypair.
        let master = output.master_secret.as_bytes();
        let preauth_secret = X25519Secret::from(id.preauth_x25519_secret.to_bytes());
        let preauth_pub = *id.preauth_x25519_pub.as_bytes();
        Some(DoubleRatchetSession::init_receiver(
            master,
            preauth_secret,
            &preauth_pub,
        ))
    }

    /// Decrypt a group control payload with the sender's ratchet session,
    /// committing the ratchet step only on success.
    ///
    /// Group control frames (`group_rekey`, `group_invite`, `group_message`)
    /// encrypt their payload directly under the raw ratchet message key with
    /// ChaCha20-Poly1305 and an all-zero nonce (the key is single-use).  The
    /// receive step is prepared on a working copy, the AEAD tag is checked,
    /// and only then is the step committed — installing `candidate` if this
    /// was the peer's first frame.  A forged header or bad ciphertext leaves
    /// the live session (and the session map) untouched.  Runs entirely
    /// under the sessions lock so the commit cannot race another frame.
    fn open_group_ratchet_payload(
        &self,
        sender_peer_id: PeerId,
        candidate: Option<DoubleRatchetSession>,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, GroupRatchetError> {
        use chacha20poly1305::{
            aead::{Aead, Nonce},
            ChaCha20Poly1305, Key, KeyInit,
        };

        let mut sessions = self
            .ratchet_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Prefer an installed session (another frame may have raced us);
        // otherwise use the unverified candidate.
        let session = match sessions.get(&sender_peer_id) {
            Some(existing) => existing,
            None => candidate.as_ref().ok_or(GroupRatchetError::NoSession)?,
        };
        // Speculative receive step; `session` is untouched.
        let pending = session
            .prepare_recv(header)
            .map_err(|_| GroupRatchetError::Ratchet)?;

        // Authenticate and decrypt under the pending key.
        let cipher = ChaCha20Poly1305::new(Key::from_slice(pending.msg_key()));
        let nonce = Nonce::<ChaCha20Poly1305>::default();
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| GroupRatchetError::Aead)?;

        // Authenticated: commit, installing the candidate on a first frame.
        match sessions.get_mut(&sender_peer_id) {
            Some(existing) => existing.commit_recv(pending),
            None => {
                if let Some(mut fresh) = candidate {
                    fresh.commit_recv(pending);
                    sessions.insert(sender_peer_id, fresh);
                }
            }
        }
        Ok(plaintext)
    }

    // -----------------------------------------------------------------------
    // Outbound messaging
    // -----------------------------------------------------------------------

    /// Send an encrypted text message to all participants of a room.
    ///
    /// Encrypts with the Double Ratchet session for each peer in the room,
    /// appending X3DH/PQXDH headers when required.  Stores the message
    /// locally and emits `MessageAdded` + `RoomUpdated` events.
    ///
    /// Returns `true` on success, `false` if identity is not unlocked or the
    /// room does not exist.
    pub fn send_text_message(&self, room_id_hex: &str, text: &str) -> bool {
        use crate::crypto::message_encrypt::encrypt_message;
        use crate::service::runtime::try_random_fill;

        if !self.identity_unlocked {
            return false;
        }
        if text.is_empty() {
            return false;
        }

        // Resolve the room and its participants.
        let (_room_id, participants) = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            match rooms.iter().find(|r| hex::encode(r.id) == room_id_hex) {
                Some(r) => (r.id, r.participants.clone()),
                None => return false,
            }
        };

        // Our identity.
        let (our_peer_id, our_ed25519) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => (id.peer_id(), id.ed25519_signing.clone()),
                None => return false,
            }
        };

        // Generate a unique message ID.
        let mut msg_id_bytes = [0u8; 16];
        if !try_random_fill(&mut msg_id_bytes) {
            return false;
        }
        let msg_id_hex = hex::encode(msg_id_bytes);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Send to each non-self participant.
        for peer_id in &participants {
            if *peer_id == our_peer_id {
                continue;
            }

            let peer_hex = peer_id.to_hex();
            let contact = match self
                .contacts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(peer_id)
                .cloned()
            {
                Some(c) => c,
                None => continue,
            };

            // Ensure a ratchet session exists for this peer.
            if !self
                .ratchet_sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(peer_id)
            {
                let id_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref id) = *id_guard {
                    match bootstrap_ratchet_session(id, &contact) {
                        Ok((session, x3dh_hdr, pq_ext)) => {
                            if let Some(h) = x3dh_hdr {
                                self.x3dh_pending
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(*peer_id, h);
                            }
                            if let Some(e) = pq_ext {
                                self.pqxdh_pending
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(*peer_id, e);
                            }
                            self.ratchet_sessions
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(*peer_id, session);
                        }
                        Err(_) => continue,
                    }
                }
            }

            // Advance ratchet for the next send message key.
            let (ratchet_header, msg_key) = {
                let mut sessions = self
                    .ratchet_sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                match sessions.get_mut(peer_id) {
                    Some(s) => match s.next_send_msg_key() {
                        Ok(k) => k,
                        Err(_) => continue,
                    },
                    None => continue,
                }
            };

            // SECURITY (CRIT-2): Encrypt the ratchet header using a key
            // derived from the static DH shared secret between us and the
            // peer.  Both sides can independently derive this key from
            // their long-term X25519 keypairs, so neither needs to know the
            // other's ratchet state to decrypt the header.
            let our_x25519_for_hdr = {
                let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                match guard.as_ref() {
                    Some(id) => x25519_dalek::StaticSecret::from(id.x25519_secret.to_bytes()),
                    None => continue,
                }
            };
            let their_x25519_pub_for_hdr = x25519_dalek::PublicKey::from(contact.x25519_public);
            let dh_shared = our_x25519_for_hdr.diffie_hellman(&their_x25519_pub_for_hdr);
            let hdr_key =
                match DoubleRatchetSession::derive_header_key_from_dh(dh_shared.as_bytes()) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
            let enc_header =
                match DoubleRatchetSession::encrypt_header_with_key(&ratchet_header, &hdr_key) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
            let (cipher_key, session_nonce, ratchet_msg_key) =
                match DoubleRatchetSession::expand_msg_key(&msg_key) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

            // Build the inner plaintext: ratchet header + message text.
            //
            // SECURITY (CRIT-2): The ratchet header fields (ratchet_pub,
            // prev_chain_len, msg_num) are placed INSIDE the AEAD ciphertext
            // so an observer cannot correlate messages by tracking ratchet key
            // changes and counters.  The outer envelope carries only an opaque
            // encrypted header blob for the receiver to derive the decryption
            // key, and the full header inside the ciphertext for tamper
            // verification after decryption.
            let inner_payload = serde_json::json!({
                "hdr": {
                    "ratchet_pub":    hex::encode(ratchet_header.ratchet_pub),
                    "prev_chain_len": ratchet_header.prev_chain_len,
                    "msg_num":        ratchet_header.msg_num,
                },
                "text": text,
            });
            // Serialise the inner payload to bytes for encryption.
            let inner_bytes = match serde_json::to_vec(&inner_payload) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Four-layer encrypt the inner payload (header + text).
            let their_x25519_pub = x25519_dalek::PublicKey::from(contact.x25519_public);
            let ciphertext = match encrypt_message(
                &inner_bytes,
                &ratchet_msg_key,
                &cipher_key,
                &session_nonce,
                &our_ed25519,
                &their_x25519_pub,
                MessageContext::Direct,
            ) {
                Ok(ct) => ct,
                Err(_) => continue,
            };

            // Build wire frame — no plaintext header fields.
            //
            // The outer envelope contains only opaque blobs: the encrypted
            // header (for ratchet key derivation) and the full ciphertext
            // (which itself contains the header for verification).
            let mut frame = serde_json::json!({
                "sender":     our_peer_id.to_hex(),
                "room":       room_id_hex,
                "msg_id":     msg_id_hex,
                "ts":         ts,
                "enc_header": hex::encode(&enc_header),
                "ciphertext": hex::encode(&ciphertext),
            });

            // Attach X3DH init header if this is our first message to this peer.
            if let Some((eph, ik)) = self
                .x3dh_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(peer_id)
                .copied()
            {
                if let Some(obj) = frame.as_object_mut() {
                    obj.insert(
                        "x3dh_eph_pub".into(),
                        serde_json::Value::String(hex::encode(eph)),
                    );
                    obj.insert(
                        "x3dh_encrypted_ik".into(),
                        serde_json::Value::String(hex::encode(ik)),
                    );
                }
            }
            // Attach PQXDH extension if present.
            if let Some((kem_ct, kem_binding)) = self
                .pqxdh_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(peer_id)
                .cloned()
            {
                if let Some(obj) = frame.as_object_mut() {
                    obj.insert(
                        "pqxdh_kem_ct".into(),
                        serde_json::Value::String(hex::encode(&kem_ct)),
                    );
                    obj.insert(
                        "pqxdh_kem_binding".into(),
                        serde_json::Value::String(hex::encode(kem_binding)),
                    );
                }
            }

            self.send_raw_frame(&peer_hex, &frame);
        }

        // Store locally.
        let msg = serde_json::json!({
            "id":        msg_id_hex,
            "roomId":    room_id_hex,
            "sender":    our_peer_id.to_hex(),
            "text":      text,
            "timestamp": ts,
            "isOutgoing": true,
        });
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.to_string())
            .or_default()
            .push(msg.clone());

        // Update room preview.
        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                room.last_message_preview = Some(if text.len() > 80 {
                    format!("{}…", &text[..80])
                } else {
                    text.to_string()
                });
                room.last_message_at = Some(ts);
                room.next_sequence += 1;
            }
        }

        self.push_event("MessageAdded", msg);
        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms
                .iter()
                .find(|r| hex::encode(r.id) == room_id_hex)
                .map(|r| {
                    serde_json::json!({
                        "id":          hex::encode(r.id),
                        "name":        r.name,
                        "lastMessage": r.last_message_preview,
                        "unreadCount": r.unread_count,
                        "timestamp":   r.last_message_at,
                    })
                })
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }

        // Persist all three interdependent collections atomically.
        // Ratchet sessions MUST be saved after every send because the chain
        // state has advanced — failing to persist would cause out-of-sync
        // ratchets on crash-recovery.
        self.save_messages();
        self.save_rooms();
        self.save_ratchet_sessions();
        true
    }

    // -----------------------------------------------------------------------
    // send_raw_frame — internal transport helper
    //
    // This is the single chokepoint for all outbound frame transmission.
    // Every operation that needs to send data to a peer (messaging, call
    // signalling, file transfers, keepalives, pairing, routing, etc.)
    // routes through this method.  It handles optional WireGuard encryption
    // and the TCP length-prefix framing transparently.
    // -----------------------------------------------------------------------

    /// Serialise `frame` and send it to `peer_id_hex` over the clearnet connection.
    ///
    /// If a WireGuard session exists for the peer, the payload is encrypted
    /// before transmission.  Falls back to plaintext if encryption fails.
    /// Failure to write is logged but not propagated (best-effort delivery;
    /// the retransmit path is `clearnet_flush_outbox`).
    pub fn send_raw_frame(&self, peer_id_hex: &str, frame: &serde_json::Value) {
        use std::io::Write;

        let frame_bytes = match serde_json::to_vec(frame) {
            Ok(b) => b,
            Err(_) => return,
        };

        // Encrypt with WireGuard session if one exists.
        let payload = if let Ok(peer_bytes) = hex::decode(peer_id_hex) {
            if peer_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&peer_bytes);
                let peer_id = PeerId(arr);
                let mut wg = self
                    .wireguard_sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(session) = wg.get_mut(&peer_id) {
                    match session.encrypt(&frame_bytes) {
                        Ok(ct) => {
                            let envelope = serde_json::json!({ "wg_ct": hex::encode(&ct) });
                            match serde_json::to_vec(&envelope) {
                                Ok(bytes) => bytes,
                                // Cannot happen for a hex string, but never
                                // fall back to the plaintext frame.
                                Err(_) => return,
                            }
                        }
                        // Fail closed (§5.1: no fallback to plaintext under
                        // any circumstances).  A nonce overflow means the
                        // session is exhausted: drop it so the next frame
                        // goes out only after a fresh handshake.
                        Err(e) => {
                            if matches!(
                                e,
                                crate::transport::wireguard::WireGuardError::NonceOverflow
                            ) {
                                wg.remove(&peer_id);
                            }
                            self.push_event(
                                "Error",
                                serde_json::json!({
                                    "message": format!("link encryption failed, frame dropped: {e}")
                                }),
                            );
                            return;
                        }
                    }
                } else {
                    frame_bytes
                }
            } else {
                frame_bytes
            }
        } else {
            frame_bytes
        };

        // Write to the established TCP connection.
        let mut conns = self
            .clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(stream) = conns.get_mut(peer_id_hex) {
            let len = payload.len() as u32;
            if let Err(e) = stream
                .write_all(&len.to_be_bytes())
                .and_then(|_| stream.write_all(&payload))
            {
                eprintln!("[transport] WARNING: failed to write frame to peer {peer_id_hex}: {e}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Group frame handlers — delivery receipt, rekey, invite, message,
    // Sender Key message, re-inclusion request (§8.7, §7.0.4)
    // -----------------------------------------------------------------------

    /// Handle an incoming `delivery_receipt` frame.
    ///
    /// Updates the in-memory delivery status of the referenced message from
    /// `"sent"` to `"delivered"` and emits `MessageStatusUpdated` to Flutter.
    /// The status is only promoted forward (sent → delivered) and never
    /// demoted to prevent replay attacks that could confuse the UI.
    fn process_delivery_receipt_frame(&self, envelope: &serde_json::Value) -> bool {
        let msg_id = match envelope.get("msg_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let room_id = match envelope.get("room").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };

        // Update in-memory message status.
        {
            let mut messages = self.messages.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room_msgs) = messages.get_mut(&room_id) {
                if let Some(msg) = room_msgs
                    .iter_mut()
                    .find(|m| m.get("id").and_then(|v| v.as_str()) == Some(&msg_id))
                {
                    // Only promote forward: sent → delivered.
                    let current = msg
                        .get("deliveryStatus")
                        .and_then(|v| v.as_str())
                        .unwrap_or("sent");
                    if current == "sent" {
                        msg["deliveryStatus"] = serde_json::json!("delivered");
                    }
                }
            }
        }

        // Emit event so the UI can update the message's delivery indicator.
        self.push_event(
            "MessageStatusUpdated",
            serde_json::json!({
                "msgId":          msg_id,
                "roomId":         room_id,
                "deliveryStatus": "delivered",
            }),
        );

        true
    }

    /// Handle an incoming `group_rekey` frame (§8.7.4, §8.7.5).
    ///
    /// The group admin has rotated the Sender Key and is distributing new
    /// key material to all members.  We decrypt the ciphertext using our
    /// ratchet session with the admin, update the group's `symmetric_key` and
    /// `sender_key_epoch`.  Future messages will use the new key.
    fn process_group_rekey_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let ciphertext_hex = match envelope.get("ciphertext").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let sender_peer_id = crate::identity::peer_id::PeerId(sender_bytes);

        // Deserialise the ratchet header.
        let header_val = match envelope.get("ratchet_header") {
            Some(v) => v.clone(),
            None => return false,
        };
        let ratchet_header: RatchetHeader = match serde_json::from_value(header_val) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Build a candidate session from the frame's X3DH header if we have
        // none for this sender; it is installed only once the payload below
        // authenticates, so an unverified frame can never plant a session.
        let candidate = self.group_frame_candidate_session(envelope, sender_peer_id);

        // Decrypt the rekey payload; the ratchet step (and any candidate
        // session) is committed only on AEAD success.
        let plaintext = match self.open_group_ratchet_payload(
            sender_peer_id,
            candidate,
            &ratchet_header,
            &ct,
        ) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        // The receive chain advanced: persist it so a crash cannot replay
        // this position against the vault copy.
        self.save_ratchet_sessions();

        // Parse the inner rekey payload.
        let inner: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let group_id_hex = match inner.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let new_epoch = match inner.get("epoch").and_then(|v| v.as_u64()) {
            Some(e) => e,
            None => return false,
        };
        let new_key_hex = match inner.get("symmetricKey").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let new_key_bytes = match hex::decode(&new_key_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let gid_bytes = match hex::decode(&group_id_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        // Apply the new key — only if this is a newer epoch (prevents replay of old rekeys).
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(group) = groups.iter_mut().find(|g| g.group_id == gid_bytes) {
            if new_epoch > group.sender_key_epoch {
                group.symmetric_key = new_key_bytes;
                group.sender_key_epoch = new_epoch;
                group.last_rekey_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                drop(groups);
                self.save_groups();
                return true;
            }
        }

        true
    }

    /// Handle an incoming `group_invite` frame (§8.7).
    ///
    /// The sender (an admin) is sharing group credentials with us.  Decrypt
    /// the payload, reconstruct the `Group` struct, persist it, and create
    /// the shared conversation room so the UI can display it immediately.
    fn process_group_invite_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let ciphertext_hex = match envelope.get("ciphertext").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let sender_peer_id = crate::identity::peer_id::PeerId(sender_bytes);

        // Group invites often come from a peer we have not yet exchanged
        // direct messages with, so the frame may carry an X3DH init header.
        // Build a candidate session from it when we have none; the candidate
        // is installed only once the invite payload authenticates below.
        let candidate = self.group_frame_candidate_session(envelope, sender_peer_id);

        // The ratchet header is carried in a top-level "ratchet_header" JSON
        // field (not inline with the ciphertext as in direct messages).
        let header_val = match envelope.get("ratchet_header") {
            Some(v) => v.clone(),
            None => return false,
        };
        let ratchet_header: RatchetHeader = match serde_json::from_value(header_val) {
            Ok(h) => h,
            Err(_) => return false,
        };
        // Decrypt the invite payload; the ratchet step (and any candidate
        // session) is committed only on AEAD success.
        let plaintext = match self.open_group_ratchet_payload(
            sender_peer_id,
            candidate,
            &ratchet_header,
            &ct,
        ) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        // The receive chain advanced: persist it so a crash cannot replay
        // this position against the vault copy.
        self.save_ratchet_sessions();

        // Parse the outer wrapper then the inner invite JSON.
        let outer: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let inv = match outer.get("invite") {
            Some(v) => v,
            None => return false,
        };

        // Extract group credentials from the invite.
        let group_id_hex = match inv.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let ed25519_pub_hex = match inv.get("ed25519Pub").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let x25519_pub_hex = match inv.get("x25519Pub").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let sym_key_hex = match inv.get("symmetricKey").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let sender_key_epoch = inv
            .get("senderKeyEpoch")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        let name = inv
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Group")
            .to_string();

        let gid_bytes = match hex::decode(&group_id_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let ed25519_pub_bytes = match hex::decode(&ed25519_pub_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let x25519_pub_bytes = match hex::decode(&x25519_pub_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let sym_key_bytes = match hex::decode(&sym_key_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let members: Vec<crate::identity::peer_id::PeerId> = inv
            .get("members")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m.as_str())
                    .filter_map(|s| hex::decode(s).ok())
                    .filter(|b| b.len() == 32)
                    .map(|b| {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        crate::identity::peer_id::PeerId(a)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let admins: Vec<crate::identity::peer_id::PeerId> = inv
            .get("admins")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m.as_str())
                    .filter_map(|s| hex::decode(s).ok())
                    .filter(|b| b.len() == 32)
                    .map(|b| {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        crate::identity::peer_id::PeerId(a)
                    })
                    .collect()
            })
            .unwrap_or_default();

        let our_peer_id = match self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|id| id.peer_id())
        {
            Some(p) => p,
            None => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Skip if we are already a member of this group (idempotent).
        let already_member = self
            .groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|g| g.group_id == gid_bytes);
        if already_member {
            return true;
        }

        // Build and store the Group record.
        use crate::groups::group::{Group, GroupPublicProfile, NetworkType};
        let description_str = inv
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let profile = GroupPublicProfile {
            group_id: gid_bytes,
            display_name: name.clone(),
            description: description_str,
            avatar_hash: None,
            network_type: NetworkType::Private,
            member_count: None,
            created_at: now,
            signed_by: sender_bytes,
            signature: vec![],
        };
        let mut group = Group::new_as_member(
            gid_bytes,
            profile,
            crate::groups::group::GroupKeys {
                ed25519_public: ed25519_pub_bytes,
                ed25519_private: None,
                x25519_public: x25519_pub_bytes,
                symmetric_key: sym_key_bytes,
            },
            our_peer_id,
            (members.clone(), admins),
            sender_key_epoch,
            now,
        );

        // Ring keys the admin already knows (§3.5.2).  The invite arrived
        // over the admin's authenticated session, so this is the admin's
        // attestation of each member's key; `commit_member_ring_key` still
        // drops non-members and invalid points individually rather than
        // rejecting the whole invite.
        if let Some(ring_keys) = inv.get("memberRingKeys").and_then(|v| v.as_object()) {
            for (peer_hex, key_value) in ring_keys {
                let Some(peer) = hex::decode(peer_hex)
                    .ok()
                    .filter(|b| b.len() == 32)
                    .map(|b| {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        PeerId(a)
                    })
                else {
                    continue;
                };
                let Some(key) = key_value
                    .as_str()
                    .and_then(|s| hex::decode(s).ok())
                    .filter(|b| b.len() == 32)
                    .map(|b| {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        a
                    })
                else {
                    continue;
                };
                // Our own slot is always minted locally below, never imported.
                if peer == our_peer_id {
                    continue;
                }
                let _ = group.commit_member_ring_key(&peer, key);
            }
        }

        // Mint our own dedicated ring key for this group.  An RNG failure
        // leaves it unset; sending will surface that, and a later send can
        // retry.  Membership itself does not depend on it.
        let our_ring_public = if group.profile.network_type.uses_ring_signatures() {
            group.ensure_ring_keypair().ok()
        } else {
            None
        };

        let group_snapshot = group.clone();
        self.groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(group);
        self.save_groups();

        // Commit our ring key to the members we already have sessions with.
        if let Some(ring_public) = our_ring_public {
            self.broadcast_ring_key_commit(&group_snapshot, &ring_public);
        }

        // Create a conversation room for this group so the UI shows it immediately.
        let mut room = crate::messaging::room::Room::new_group(&name, members);
        let room_id_hex = hex::encode(room.id);
        room.last_message_at = Some(now);

        let room_summary = serde_json::json!({
            "id":          room_id_hex.clone(),
            "name":        name,
            "lastMessage": "",
            "unreadCount": 0,
            "timestamp":   now,
        });
        self.rooms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(room);
        self.save_rooms();

        self.push_event("RoomUpdated", room_summary);

        true
    }

    /// Handle an incoming `group_message` frame (§8.7).
    ///
    /// A group member has sent a message to the group.  Decrypt the payload
    /// using the sender's ratchet session (same ChaCha20-Poly1305 scheme
    /// used for `group_invite`/`group_rekey`), then store it and emit
    /// `MessageAdded`.
    fn process_group_message_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        // groupId is carried unencrypted so we can request re-inclusion on failure.
        let outer_group_id_hex = envelope
            .get("groupId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let ciphertext_hex = match envelope.get("ciphertext").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let sender_peer_id = crate::identity::peer_id::PeerId(sender_bytes);

        // Build a candidate session from the frame's X3DH header if we have
        // none for this sender (and the sender is a contact); it is installed
        // only once the payload below authenticates.
        let candidate = self.group_frame_candidate_session(envelope, sender_peer_id);

        // Decrypt using the ratchet message key.
        let header_val = match envelope.get("ratchet_header") {
            Some(v) => v.clone(),
            None => return false,
        };
        let ratchet_header: RatchetHeader = match serde_json::from_value(header_val) {
            Ok(h) => h,
            Err(_) => return false,
        };
        // The ratchet step (and any candidate session) is committed only on
        // AEAD success.  Every failure mode — no session, ratchet out of
        // sync, bad ciphertext — asks the sender for re-inclusion (§8.7.6);
        // the live session is unchanged, so a stray or forged frame cannot
        // break a working session.
        let plaintext = match self.open_group_ratchet_payload(
            sender_peer_id,
            candidate,
            &ratchet_header,
            &ct,
        ) {
            Ok(pt) => pt,
            Err(_) => {
                if let Some(ref gid) = outer_group_id_hex {
                    self.send_group_reinclusion_request(&sender_hex, gid);
                }
                return false;
            }
        };

        // Parse the inner message payload.
        let inner: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let room_id_hex = match inner.get("roomId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let text = match inner.get("text").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let msg_id = inner
            .get("msgId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ts = inner
            .get("timestamp")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });

        let msg = serde_json::json!({
            "id":         msg_id,
            "roomId":     room_id_hex,
            "sender":     sender_hex,
            "text":       text,
            "timestamp":  ts,
            "isOutgoing": false,
            "authStatus": "authenticated",
        });

        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.clone())
            .or_default()
            .push(msg.clone());

        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                room.last_message_preview = Some(if text.len() > 80 {
                    format!("{}…", &text[..80])
                } else {
                    text.clone()
                });
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                room.last_message_at = Some(now);
                if !room.is_muted {
                    room.unread_count += 1;
                }
            }
        }

        self.push_event("MessageAdded", msg);

        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms
                .iter()
                .find(|r| hex::encode(r.id) == room_id_hex)
                .map(|r| {
                    serde_json::json!({
                        "id":          hex::encode(r.id),
                        "name":        r.name,
                        "lastMessage": r.last_message_preview,
                        "unreadCount": r.unread_count,
                        "timestamp":   r.last_message_at,
                    })
                })
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }

        self.save_messages();
        self.save_rooms();
        self.save_ratchet_sessions();
        true
    }

    /// Handle an incoming `group_message_sk` frame (Sender Key path, §7.0.4).
    ///
    /// Wire format:
    /// ```json
    /// { "type": "group_message_sk", "groupId": "<hex>", "epoch": <u64>,
    ///   "nonce": "<hex-12>", "wrapped": "<hex>", "ring_sig": { ... } }
    /// ```
    ///
    /// For private and closed groups the sender is not carried in plaintext.
    /// Instead:
    /// - `nonce || wrapped` is authenticated by an `MI-AOS-R255-1` ring
    ///   signature over the members' committed ring keys, under a context
    ///   (group, epoch, roster) taken from our own record (§3.5.2)
    /// - the sender identity and its attributable Ed25519 signature live only
    ///   inside the encrypted Sender Key plaintext
    ///
    /// The frame's `epoch` must equal our current epoch: old-epoch traffic is
    /// never accepted as current content, and checking it first avoids O(n)
    /// ring arithmetic on a frame that cannot verify.
    fn process_group_message_sk_frame(&self, envelope: &serde_json::Value) -> bool {
        let outer_group_id_hex = match envelope.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let epoch = match envelope.get("epoch").and_then(|value| value.as_u64()) {
            Some(value) => value,
            None => return false,
        };
        let nonce_hex = match envelope.get("nonce").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let wrapped_hex = match envelope.get("wrapped").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ring_sig: crate::crypto::ring_sig::RingSignature =
            match envelope.get("ring_sig").cloned() {
                Some(value) => match serde_json::from_value(value) {
                    Ok(value) => value,
                    Err(_) => return false,
                },
                None => return false,
            };

        let nonce_bytes: [u8; 12] = match hex::decode(nonce_hex) {
            Ok(b) if b.len() == 12 => {
                let mut a = [0u8; 12];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let wrapped = match hex::decode(wrapped_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let gid_bytes: [u8; 32] = match hex::decode(&outer_group_id_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        let group_snapshot = {
            let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            match groups
                .iter()
                .find(|candidate| candidate.group_id == gid_bytes)
            {
                Some(value) => value.clone(),
                None => return false,
            }
        };
        // Cheap checks before the O(n) ring walk (§3.5.2 "rate-limit before
        // expensive work"): the epoch must be current and the ring complete.
        if epoch != group_snapshot.sender_key_epoch {
            return false;
        }
        let Some(ring) = group_snapshot.sorted_ring() else {
            return false;
        };
        // Everything in the context is ours, not the frame's: an attacker
        // cannot choose the roster or epoch their signature is checked under.
        let context =
            group_snapshot.ring_context(crate::crypto::ring_sig::RingContextType::Application);
        let envelope_bytes = group_sk_envelope_bytes(&nonce_bytes, &wrapped);
        // Any error — forged, malformed, or `ProfileNotEnabled` under the
        // release gate — is a silent drop (§16.1 error policy).
        if crate::crypto::ring_sig::ring_verify(&ring, &context, &envelope_bytes, &ring_sig)
            .is_err()
        {
            return false;
        }

        // Step 1: Unwrap the outer ChaCha20-Poly1305 layer (group symmetric key).
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
        let sym_cipher = ChaCha20Poly1305::new_from_slice(&group_snapshot.symmetric_key)
            .expect("symmetric_key is always 32 bytes");
        let sk_wire_bytes = match sym_cipher.decrypt(
            chacha20poly1305::Nonce::from_slice(&nonce_bytes),
            wrapped.as_ref(),
        ) {
            Ok(value) => value,
            Err(_) => return false,
        };

        // Step 2: Parse the inner Sender Key wrapper and recover the sender key seed.
        let sk_wire: serde_json::Value = match serde_json::from_slice(&sk_wire_bytes) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let iteration = match sk_wire.get("iteration").and_then(|value| value.as_u64()) {
            Some(value) => value as u32,
            None => return false,
        };
        let inner_ct = match sk_wire
            .get("ciphertext")
            .and_then(|value| value.as_str())
            .and_then(|value| hex::decode(value).ok())
        {
            Some(value) => value,
            None => return false,
        };
        let sig_bytes = match sk_wire
            .get("signature")
            .and_then(|value| value.as_str())
            .and_then(|value| hex::decode(value).ok())
        {
            Some(value) => value,
            None => return false,
        };
        let sender_key_seed: GroupSenderKeySeedWire = match sk_wire.get("sender_key_seed").cloned()
        {
            Some(value) => match serde_json::from_value(value) {
                Ok(value) => value,
                Err(_) => return false,
            },
            None => return false,
        };
        let seed_chain_key: [u8; 32] = match hex::decode(&sender_key_seed.chain_key) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut value = [0u8; 32];
                value.copy_from_slice(&bytes);
                value
            }
            _ => return false,
        };
        let seed_verifying_key: [u8; 32] = match hex::decode(&sender_key_seed.verifying_key) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut value = [0u8; 32];
                value.copy_from_slice(&bytes);
                value
            }
            _ => return false,
        };

        use crate::crypto::sender_keys::{SenderKeyMessage, SenderKeyReceiver};
        use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;

        let verifying_key = match Ed25519VerifyingKey::from_bytes(&seed_verifying_key) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let mut receiver =
            SenderKeyReceiver::from_state(seed_chain_key, sender_key_seed.iteration, verifying_key);
        let sk_msg = SenderKeyMessage {
            iteration,
            ciphertext: inner_ct,
            signature: sig_bytes,
        };

        // Step 3: Decrypt the Sender Key payload and validate the claimed sender.
        let plaintext_bytes = match receiver.decrypt(&sk_msg) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let inner: GroupMessageSkWire = match serde_json::from_slice(&plaintext_bytes) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let sender_bytes: [u8; 32] = match hex::decode(&inner.sender) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut value = [0u8; 32];
                value.copy_from_slice(&bytes);
                value
            }
            _ => return false,
        };
        let sender_peer_id = PeerId(sender_bytes);
        if !group_snapshot.members.contains(&sender_peer_id) {
            return false;
        }

        let sender_identity_pub = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(identity) = guard.as_ref() {
                if identity.peer_id() == sender_peer_id {
                    Some(identity.ed25519_pub)
                } else {
                    None
                }
            } else {
                None
            }
        }
        .or_else(|| {
            self.contacts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&sender_peer_id)
                .map(|contact| contact.ed25519_public)
        });
        let sender_identity_pub = match sender_identity_pub {
            Some(value) => value,
            None => return false,
        };
        let sender_sig = match hex::decode(&inner.sender_sig) {
            Ok(bytes) if bytes.len() == 64 => {
                let mut value = [0u8; 64];
                value.copy_from_slice(&bytes);
                Signature::from_bytes(&value)
            }
            _ => return false,
        };
        let sender_sig_message = build_group_inner_signature_message(
            &gid_bytes,
            &inner.room_id,
            &inner.msg_id,
            &inner.text,
            inner.timestamp,
            &sender_bytes,
        );
        let sender_identity_key = match Ed25519VerifyingKey::from_bytes(&sender_identity_pub) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if sender_identity_key
            .verify(&sender_sig_message, &sender_sig)
            .is_err()
        {
            return false;
        }

        // Step 4: Persist the advanced Sender Key receiver state under the recovered sender.
        {
            let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(group) = groups
                .iter_mut()
                .find(|candidate| candidate.group_id == gid_bytes)
            {
                use crate::groups::group::PeerSenderKeyState;
                group.peer_sender_keys.insert(
                    sender_bytes,
                    PeerSenderKeyState {
                        chain_key: *receiver.chain_key_bytes(),
                        next_iteration: receiver.next_iter(),
                        verifying_key: seed_verifying_key,
                    },
                );
            }
        }

        self.persist_room_message(
            &inner.room_id,
            &inner.sender,
            &inner.text,
            inner.timestamp,
            &inner.msg_id,
            false,
            Some("authenticated"),
        );
        self.save_messages();
        self.save_rooms();
        self.save_groups();
        true
    }

    /// Send a `group_reinclusion_request` to a peer whose `group_message` we
    /// could not decrypt (§8.7.6).
    ///
    /// The frame is sent in plaintext because by definition our ratchet session
    /// with that peer is broken.  The only information disclosed is our own
    /// peer-ID and the group-ID, both of which the sender already knows.
    fn send_group_reinclusion_request(&self, peer_hex: &str, group_id_hex: &str) {
        let our_hex = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => hex::encode(id.peer_id().0),
                None => return,
            }
        };
        let frame = serde_json::json!({
            "type":    "group_reinclusion_request",
            "sender":  our_hex,
            "groupId": group_id_hex,
        });
        self.send_raw_frame(peer_hex, &frame);
    }

    /// Handle an incoming `group_reinclusion_request` frame (§8.7.6).
    ///
    /// The requester's ratchet session with us is out of sync.  If we are an
    /// admin of the named group **and** the requester is already a member, we
    /// re-send them a `group_invite` so they can re-join.
    ///
    /// The membership check prevents a non-member from obtaining group
    /// credentials by forging a re-inclusion request.
    fn process_group_reinclusion_request_frame(&self, envelope: &serde_json::Value) -> bool {
        let requester_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let group_id_hex = match envelope.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let gid_bytes: [u8; 32] = match hex::decode(&group_id_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let requester_bytes: [u8; 32] = match hex::decode(&requester_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let requester_peer_id = crate::identity::peer_id::PeerId(requester_bytes);

        let our_peer_id = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => id.peer_id(),
                None => return false,
            }
        };

        // Build the invite payload only if we are an admin and the requester is
        // already a member (prevents credential-harvesting via forged requests).
        let invite_payload_bytes: Vec<u8> = {
            let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            let group = match groups.iter().find(|g| g.group_id == gid_bytes) {
                Some(g) => g,
                None => return false,
            };
            // We must be an admin.
            if !group.admins.contains(&our_peer_id) {
                return false;
            }
            // Requester must already be a member.
            if !group.members.contains(&requester_peer_id) {
                return false;
            }

            let snap = serde_json::json!({
                "groupId":        hex::encode(group.group_id),
                "ed25519Pub":     hex::encode(group.ed25519_public),
                "x25519Pub":      hex::encode(group.x25519_public),
                "symmetricKey":   hex::encode(group.symmetric_key),
                "senderKeyEpoch": group.sender_key_epoch,
                "members": group.members.iter()
                    .map(|m| hex::encode(m.0)).collect::<Vec<_>>(),
                "admins": group.admins.iter()
                    .map(|m| hex::encode(m.0)).collect::<Vec<_>>(),
                "name":        group.profile.display_name.clone(),
                "description": group.profile.description.clone(),
                // Every ring key we know, so the re-joiner can rebuild the
                // ring without waiting for each member to re-commit.
                "memberRingKeys": group.member_ring_keys.iter()
                    .map(|(peer, key)| {
                        (hex::encode(peer), serde_json::Value::String(hex::encode(key)))
                    })
                    .collect::<serde_json::Map<String, serde_json::Value>>(),
            });
            match serde_json::to_vec(&serde_json::json!({
                "type":   "group_invite",
                "invite": snap,
            })) {
                Ok(b) => b,
                Err(_) => return false,
            }
        };

        // Encrypt with the requester's ratchet session.
        // If the ratchet session is missing we cannot help — the admin would
        // need to trigger a full re-pair out-of-band.
        if let Some(frame) =
            self.seal_group_control_frame(requester_peer_id, "group_invite", &invite_payload_bytes)
        {
            self.send_raw_frame(&requester_hex, &frame);
            self.save_ratchet_sessions();
        }
        true
    }

    /// Handle an incoming `group_ring_commit` frame (§3.5.2).
    ///
    /// A member is committing the ring public key they will sign group
    /// envelopes with.  The payload is sealed under the sender's ratchet
    /// session, so the key is bound to an authenticated peer; we then
    /// require that peer to be a current member and the key to be a valid
    /// non-identity ristretto255 point before recording it.  Everything
    /// else is a silent drop.
    fn process_group_ring_commit_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let ciphertext_hex = match envelope.get("ciphertext").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let sender_peer_id = PeerId(sender_bytes);

        // Same session handling as the other group control frames: a
        // candidate session from an X3DH header is installed only once the
        // payload authenticates.
        let candidate = self.group_frame_candidate_session(envelope, sender_peer_id);
        let header_val = match envelope.get("ratchet_header") {
            Some(v) => v.clone(),
            None => return false,
        };
        let ratchet_header: RatchetHeader = match serde_json::from_value(header_val) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let plaintext = match self.open_group_ratchet_payload(
            sender_peer_id,
            candidate,
            &ratchet_header,
            &ct,
        ) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        // The receive chain advanced: persist it so a crash cannot replay
        // this position against the vault copy.
        self.save_ratchet_sessions();

        let inner: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let gid_bytes: [u8; 32] = match inner
            .get("groupId")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
        {
            Some(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let ring_public: [u8; 32] = match inner
            .get("ringPub")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
        {
            Some(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        // Record the key only for a current member of a group we are in;
        // `commit_member_ring_key` also rejects invalid points.
        let committed = {
            let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            match groups.iter_mut().find(|g| g.group_id == gid_bytes) {
                Some(group) => group
                    .commit_member_ring_key(&sender_peer_id, ring_public)
                    .is_ok(),
                None => false,
            }
        };
        if !committed {
            return false;
        }
        self.save_groups();
        true
    }
}

// ---------------------------------------------------------------------------
// Room and message management operations
// ---------------------------------------------------------------------------

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Room operations
    // -----------------------------------------------------------------------

    /// Return the full room list as a JSON string.
    ///
    /// Each entry includes group/DM metadata: `id`, `name`, `lastMessage`,
    /// `unreadCount`, `timestamp`, `isArchived`, `isPinned`, `isMuted`,
    /// `securityMode`, `conversationType`, `groupId`, `otherPeerId`.
    pub fn get_room_list(&self) -> String {
        use crate::identity::peer_id::PeerId;
        use crate::messaging::message::ConversationType;

        let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        // Build group-id lookup keyed by group peer_id for annotation.
        let groups_guard = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group_lookup: std::collections::HashMap<PeerId, String> = groups_guard
            .iter()
            .map(|g| {
                (
                    PeerId::from_ed25519_pub(&g.ed25519_public),
                    hex::encode(g.group_id),
                )
            })
            .collect();
        drop(groups_guard);

        let json: Vec<serde_json::Value> = rooms
            .iter()
            .map(|r| {
                let is_group = r.conversation_type == ConversationType::Group;
                let group_id = if is_group {
                    r.participants
                        .first()
                        .and_then(|pid| group_lookup.get(pid))
                        .cloned()
                } else {
                    None
                };
                // For DM rooms expose the other peer's ID.
                let other_peer_id = if !is_group && r.participants.len() >= 2 {
                    Some(hex::encode(r.participants[1].0))
                } else {
                    None
                };
                serde_json::json!({
                    "id":               hex::encode(r.id),
                    "name":             r.name,
                    "lastMessage":      r.last_message_preview,
                    "unreadCount":      r.unread_count,
                    "timestamp":        r.last_message_at,
                    "isArchived":       r.is_archived,
                    "isPinned":         r.is_pinned,
                    "isMuted":          r.is_muted,
                    "securityMode":     r.security_mode,
                    "conversationType": if is_group { "group" } else { "dm" },
                    "groupId":          group_id,
                    "otherPeerId":      other_peer_id,
                })
            })
            .collect();

        serde_json::to_string(&json).unwrap_or_else(|_| "[]".into())
    }

    /// Create a new room (DM or standalone).
    ///
    /// If `peer_id_hex` is `Some`, creates a DM room with the named peer.
    /// If `peer_id_hex` is `None`, creates a standalone group room.
    ///
    /// Returns `Ok(room_id_hex)` on success, `Err(reason)` on failure.
    pub fn create_room(&mut self, name: &str, peer_id_hex: Option<&str>) -> Result<String, String> {
        use crate::identity::peer_id::PeerId;

        let room = if let Some(pid_hex) = peer_id_hex {
            // DM room — look up the contact.
            let peer_bytes: [u8; 32] = hex::decode(pid_hex)
                .ok()
                .filter(|b| b.len() == 32)
                .map(|b| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                })
                .ok_or("invalid peer_id_hex")?;
            let peer_id = PeerId(peer_bytes);

            let our_peer_id = self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|id| id.peer_id())
                .unwrap_or(PeerId([0u8; 32]));

            let room_name = if name.is_empty() {
                // Fall back to peer's display name.
                self.contacts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&peer_id)
                    .and_then(|c| c.display_name.clone())
                    .unwrap_or_else(|| pid_hex[..8].to_string())
            } else {
                name.to_string()
            };

            crate::messaging::room::Room::new_dm(our_peer_id, peer_id, &room_name)
        } else {
            // Standalone group room.
            let room_name = if name.is_empty() {
                "New Chat".to_string()
            } else {
                name.to_string()
            };
            crate::messaging::room::Room::new_group(&room_name, vec![])
        };

        let id_hex = hex::encode(room.id);
        self.rooms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(room.clone());
        self.save_rooms();

        self.push_event(
            "RoomCreated",
            serde_json::json!({
                "id":   id_hex,
                "name": room.name,
            }),
        );

        Ok(id_hex)
    }

    /// Delete a room and its messages.
    ///
    /// Returns `true` if the room was found and removed.
    pub fn delete_room(&self, room_id_hex: &str) -> bool {
        let before = self.rooms.lock().unwrap_or_else(|e| e.into_inner()).len();
        self.rooms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|r| hex::encode(r.id) != room_id_hex);
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(room_id_hex);
        let after = self.rooms.lock().unwrap_or_else(|e| e.into_inner()).len();

        if after < before {
            self.push_event("RoomDeleted", serde_json::json!({ "roomId": room_id_hex }));
            self.save_rooms();
            self.save_messages();
            true
        } else {
            false
        }
    }

    /// Return messages for a room as a JSON array string.
    pub fn get_messages(&self, room_id_hex: &str) -> String {
        let msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
        match msgs.get(room_id_hex) {
            Some(m) => serde_json::to_string(m).unwrap_or_else(|_| "[]".into()),
            None => "[]".into(),
        }
    }

    /// Return the active conversation room ID as a JSON string (`"null"` if none).
    pub fn active_room_id(&self) -> String {
        let active = self
            .active_conversation
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match *active {
            Some(id) => format!("\"{}\"", hex::encode(id)),
            None => "null".into(),
        }
    }

    /// Return the current file transfers as a JSON array string.
    pub fn get_file_transfers(&self) -> String {
        let transfers = self
            .file_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        serde_json::to_string(&*transfers).unwrap_or_else(|_| "[]".into())
    }

    // -----------------------------------------------------------------------
    // Message operations
    // -----------------------------------------------------------------------

    /// Delete a message from local storage (local-only; not broadcast).
    pub fn delete_message(&self, msg_id: &str) {
        let mut msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
        for room_msgs in msgs.values_mut() {
            room_msgs.retain(|m| m.get("id").and_then(|v| v.as_str()) != Some(msg_id));
        }
    }

    /// Send a reaction to a message and broadcast it to room participants.
    ///
    /// Emits `ReactionAdded` and sends a `reaction` frame to each connected peer.
    pub fn send_reaction(&self, room_id_hex: &str, msg_id: &str, emoji: &str) -> bool {
        if emoji.is_empty() {
            return false;
        }

        self.push_event(
            "ReactionAdded",
            serde_json::json!({
                "roomId": room_id_hex,
                "msgId":  msg_id,
                "emoji":  emoji,
            }),
        );

        let (recipients, our_hex) = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            let room_id_bytes = match hex::decode(room_id_hex) {
                Ok(b) if b.len() == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&b);
                    a
                }
                _ => return true, // event emitted; wire-send best-effort
            };
            let room = match rooms.iter().find(|r| r.id == room_id_bytes) {
                Some(r) => r,
                None => return true,
            };
            let our = self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|id| id.peer_id().to_hex())
                .unwrap_or_default();
            let peers: Vec<String> = room
                .participants
                .iter()
                .map(|p| hex::encode(p.0))
                .filter(|h| *h != our)
                .collect();
            (peers, our)
        };

        let frame = serde_json::json!({
            "type":   "reaction",
            "sender": our_hex,
            "roomId": room_id_hex,
            "msgId":  msg_id,
            "emoji":  emoji,
        });
        for peer_hex in &recipients {
            self.send_raw_frame(peer_hex, &frame);
        }
        true
    }

    /// Mark a room as read and emit a `ReadReceipt` event.
    pub fn send_read_receipt(&self, room_id_hex: &str, msg_id: &str) {
        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                room.mark_read();
            }
        }
        self.push_event(
            "ReadReceipt",
            serde_json::json!({"roomId": room_id_hex, "msgId": msg_id}),
        );
        self.save_rooms();
    }

    /// Emit a typing indicator event and broadcast to room participants.
    pub fn send_typing_indicator(&self, room_id_hex: &str, active: bool) {
        self.push_event(
            "TypingIndicator",
            serde_json::json!({
                "roomId": room_id_hex,
                "active": active,
            }),
        );

        let (recipients, our_hex) = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            let room_id_bytes = match hex::decode(room_id_hex) {
                Ok(b) if b.len() == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&b);
                    a
                }
                _ => return,
            };
            let room = match rooms.iter().find(|r| r.id == room_id_bytes) {
                Some(r) => r,
                None => return,
            };
            let our = self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|id| hex::encode(id.peer_id().0))
                .unwrap_or_default();
            let peers: Vec<String> = room
                .participants
                .iter()
                .map(|p| hex::encode(p.0))
                .filter(|h| *h != our)
                .collect();
            (peers, our)
        };

        let frame = serde_json::json!({
            "type":   "typing_indicator",
            "sender": our_hex,
            "roomId": room_id_hex,
            "active": active,
        });
        for peer_hex in &recipients {
            self.send_raw_frame(peer_hex, &frame);
        }
    }

    /// Send a reply message that quotes an earlier message.
    ///
    /// Returns `true` on success.
    pub fn reply_to_message(&mut self, room_id_hex: &str, reply_to_id: &str, text: &str) -> bool {
        use crate::service::runtime::try_random_fill;
        if text.is_empty() {
            return false;
        }

        let mut msg_id_bytes = [0u8; 16];
        if !try_random_fill(&mut msg_id_bytes) {
            return false;
        }
        let msg_id = hex::encode(msg_id_bytes);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let sender = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|id| id.peer_id().to_hex())
            .unwrap_or_else(|| "local".into());

        let msg = serde_json::json!({
            "id":         msg_id,
            "roomId":     room_id_hex,
            "sender":     sender,
            "text":       text,
            "timestamp":  timestamp,
            "isOutgoing": true,
            "authStatus": "outgoing",
            "replyTo":    reply_to_id,
        });

        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.to_string())
            .or_default()
            .push(msg.clone());
        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                let preview = if text.len() > 80 {
                    format!("\u{21a9} {}…", &text[..77])
                } else {
                    format!("\u{21a9} {text}")
                };
                room.last_message_preview = Some(preview);
                room.last_message_at = Some(timestamp);
            }
        }
        self.push_event("MessageAdded", msg);
        self.save_messages();
        self.save_rooms();
        true
    }

    /// Edit the text of a previously sent message (own messages only).
    ///
    /// Returns `true` if the message was found and updated.
    pub fn edit_message(&self, msg_id: &str, new_text: &str) -> bool {
        if new_text.is_empty() {
            return false;
        }
        let edited_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut found = false;
        {
            let mut all_msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
            for msgs in all_msgs.values_mut() {
                for msg in msgs.iter_mut() {
                    if msg.get("id").and_then(|v| v.as_str()) == Some(msg_id) {
                        if msg.get("isOutgoing").and_then(|v| v.as_bool()) == Some(true) {
                            if let Some(obj) = msg.as_object_mut() {
                                obj.insert("text".into(), serde_json::json!(new_text));
                                obj.insert("editedAt".into(), serde_json::json!(edited_at));
                            }
                            found = true;
                        }
                        break;
                    }
                }
                if found {
                    break;
                }
            }
        }

        if found {
            self.push_event(
                "MessageEdited",
                serde_json::json!({
                    "msgId":    msg_id,
                    "newText":  new_text,
                    "editedAt": edited_at,
                }),
            );
            self.save_messages();
        }
        found
    }

    /// Delete a message for all participants (marks it deleted in place).
    ///
    /// Returns `Some(room_id_hex)` of the containing room, or `None` if not found.
    pub fn delete_for_everyone(&self, msg_id: &str) -> Option<String> {
        let mut found_room: Option<String> = None;
        {
            let mut all_msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
            for (room_id, msgs) in all_msgs.iter_mut() {
                for msg in msgs.iter_mut() {
                    if msg.get("id").and_then(|v| v.as_str()) == Some(msg_id) {
                        if let Some(obj) = msg.as_object_mut() {
                            obj.insert("text".into(), serde_json::json!(""));
                            obj.insert("deleted".into(), serde_json::json!(true));
                        }
                        found_room = Some(room_id.clone());
                        break;
                    }
                }
                if found_room.is_some() {
                    break;
                }
            }
        }

        if let Some(ref room_id) = found_room {
            self.push_event(
                "MessageDeleted",
                serde_json::json!({"msgId": msg_id, "roomId": room_id}),
            );
            self.save_messages();
        }
        found_room
    }

    /// Forward a message to a different room.
    ///
    /// Returns `true` on success.
    pub fn forward_message(&mut self, msg_id: &str, target_room_hex: &str) -> bool {
        use crate::service::runtime::try_random_fill;

        let original_text = {
            let all_msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
            all_msgs
                .values()
                .flat_map(|msgs| msgs.iter())
                .find(|msg| msg.get("id").and_then(|v| v.as_str()) == Some(msg_id))
                .and_then(|msg| {
                    msg.get("text")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
        };

        let text = match original_text {
            Some(t) if !t.is_empty() => t,
            _ => return false,
        };

        let mut new_id_bytes = [0u8; 16];
        if !try_random_fill(&mut new_id_bytes) {
            return false;
        }
        let new_id = hex::encode(new_id_bytes);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let sender = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|id| id.peer_id().to_hex())
            .unwrap_or_else(|| "local".into());

        let fwd = serde_json::json!({
            "id":          new_id,
            "roomId":      target_room_hex,
            "sender":      sender,
            "text":        text,
            "timestamp":   timestamp,
            "isOutgoing":  true,
            "authStatus":  "outgoing",
            "isForwarded": true,
        });

        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(target_room_hex.to_string())
            .or_default()
            .push(fwd.clone());
        self.push_event("MessageAdded", fwd);
        self.save_messages();
        true
    }

    /// Pin a message (marks `pinned = true`).
    ///
    /// Returns `true` if the message was found.
    pub fn pin_message(&self, msg_id: &str) -> bool {
        self.set_message_pin(msg_id, true)
    }

    /// Unpin a previously pinned message.
    ///
    /// Returns `true` if the message was found.
    pub fn unpin_message(&self, msg_id: &str) -> bool {
        self.set_message_pin(msg_id, false)
    }

    /// Internal helper: set the `pinned` flag on a message.
    fn set_message_pin(&self, msg_id: &str, pinned: bool) -> bool {
        let mut found = false;
        {
            let mut all_msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
            for msgs in all_msgs.values_mut() {
                for msg in msgs.iter_mut() {
                    if msg.get("id").and_then(|v| v.as_str()) == Some(msg_id) {
                        if let Some(obj) = msg.as_object_mut() {
                            obj.insert("pinned".into(), serde_json::json!(pinned));
                        }
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
            }
        }

        if found {
            let event = if pinned {
                "MessagePinned"
            } else {
                "MessageUnpinned"
            };
            self.push_event(event, serde_json::json!({"msgId": msg_id}));
            self.save_messages();
        }
        found
    }

    /// Set the disappearing-message timer for a room.
    ///
    /// Pass `secs = 0` to disable. Returns `true` if the room was found.
    pub fn set_disappearing_timer(&self, room_id_hex: &str, secs: u64) -> bool {
        let mut found = false;
        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                room.disappearing_timer = if secs == 0 { None } else { Some(secs) };
                found = true;
            }
        }

        if found {
            self.push_event(
                "DisappearingTimerChanged",
                serde_json::json!({
                    "roomId": room_id_hex,
                    "secs":   secs,
                }),
            );
            self.save_rooms();
        }
        found
    }

    /// Full-text search across all in-memory messages (case-insensitive).
    ///
    /// Returns a JSON array of matching message objects.
    pub fn search_messages(&self, query: &str) -> String {
        if query.is_empty() {
            return "[]".into();
        }
        let lower = query.to_lowercase();
        let all_msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
        let results: Vec<&serde_json::Value> = all_msgs
            .values()
            .flat_map(|msgs| msgs.iter())
            .filter(|msg| {
                msg.get("text")
                    .and_then(|v| v.as_str())
                    .map(|t| t.to_lowercase().contains(&lower))
                    .unwrap_or(false)
            })
            .collect();
        serde_json::to_string(&results).unwrap_or_else(|_| "[]".into())
    }

    /// Remove messages whose `expiresAt` timestamp is in the past.
    ///
    /// Should be called periodically to enforce disappearing-message timers.
    /// Emits `MessagesExpired` if any were pruned.
    pub fn prune_expired_messages(&self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut pruned = 0usize;
        {
            let mut all_msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
            for msgs in all_msgs.values_mut() {
                let before = msgs.len();
                msgs.retain(|msg| {
                    if let Some(exp) = msg.get("expiresAt").and_then(|v| v.as_u64()) {
                        exp > now
                    } else {
                        true
                    }
                });
                pruned += before - msgs.len();
            }
        }

        if pruned > 0 {
            self.push_event("MessagesExpired", serde_json::json!({"count": pruned}));
            self.save_messages();
        }
        pruned
    }
}

impl crate::service::runtime::MeshRuntime {
    // -----------------------------------------------------------------------
    // Group-specific helpers (§10.1.2)
    // -----------------------------------------------------------------------

    /// Create a named group room with an initial member list.
    ///
    /// `members_json` is a JSON array of hex-encoded peer IDs, e.g. `["aabb…","ccdd…"]`.
    /// Returns `Ok(room_id_hex)` on success, `Err(reason)` on failure.
    pub fn create_group(&mut self, name: &str, members_json: &str) -> Result<String, String> {
        use crate::identity::peer_id::PeerId;

        // Parse the optional member list; tolerate an empty or absent array.
        let member_hexes: Vec<String> = if members_json.is_empty() || members_json == "[]" {
            vec![]
        } else {
            serde_json::from_str(members_json).map_err(|e| e.to_string())?
        };

        let mut members: Vec<PeerId> = Vec::with_capacity(member_hexes.len() + 1);

        // Always include ourselves.
        let our_peer_id = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|id| id.peer_id())
            .unwrap_or(PeerId([0u8; 32]));
        members.push(our_peer_id);

        for hex_str in &member_hexes {
            let bytes: [u8; 32] = hex::decode(hex_str)
                .ok()
                .filter(|b| b.len() == 32)
                .map(|b| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                })
                .ok_or_else(|| format!("invalid peer_id_hex: {hex_str}"))?;
            members.push(PeerId(bytes));
        }

        let group_name = if name.is_empty() { "New Group" } else { name };
        let room = crate::messaging::room::Room::new_group(group_name, members);
        let id_hex = hex::encode(room.id);

        self.rooms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(room.clone());
        self.save_rooms();

        self.push_event(
            "GroupCreated",
            serde_json::json!({
                "id":   id_hex,
                "name": room.name,
            }),
        );

        Ok(id_hex)
    }

    /// Return a JSON array of all group rooms (conversation_type == Group).
    pub fn list_groups(&self) -> String {
        use crate::messaging::message::ConversationType;
        let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let groups: Vec<serde_json::Value> = rooms
            .iter()
            .filter(|r| r.conversation_type == ConversationType::Group)
            .map(|r| {
                serde_json::json!({
                    "id":           hex::encode(r.id),
                    "name":         r.name,
                    "memberCount":  r.participants.len(),
                    "unreadCount":  r.unread_count,
                    "lastMessage":  r.last_message_preview,
                    "timestamp":    r.last_message_at,
                })
            })
            .collect();
        serde_json::to_string(&groups).unwrap_or_else(|_| "[]".into())
    }

    /// Return the member list for a group room as a JSON array of hex peer IDs.
    pub fn group_members(&self, group_id_hex: &str) -> String {
        let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(room) = rooms.iter().find(|r| hex::encode(r.id) == group_id_hex) {
            let members: Vec<String> = room.participants.iter().map(|p| hex::encode(p.0)).collect();
            serde_json::to_string(&members).unwrap_or_else(|_| "[]".into())
        } else {
            "[]".into()
        }
    }

    /// Remove ourselves from a group room and notify other members.
    ///
    /// Returns `Ok(())` if found, `Err(reason)` if the room does not exist.
    pub fn leave_group(&mut self, group_id_hex: &str) -> Result<(), String> {
        use crate::messaging::message::ConversationType;

        let our_peer_id = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|id| id.peer_id())
            .ok_or("no identity")?;

        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let room = rooms
            .iter_mut()
            .find(|r| {
                hex::encode(r.id) == group_id_hex && r.conversation_type == ConversationType::Group
            })
            .ok_or_else(|| format!("group not found: {group_id_hex}"))?;

        // Remove self from participant list.
        room.participants.retain(|p| p != &our_peer_id);
        drop(rooms);

        self.save_rooms();
        self.push_event("GroupLeft", serde_json::json!({ "groupId": group_id_hex }));
        Ok(())
    }

    /// Send a text message to a group room.
    ///
    /// Returns `true` if the message was queued successfully.
    pub fn group_send_message(&mut self, group_id_hex: &str, text: &str) -> bool {
        if let Some((group, _room)) = self.group_for_room(group_id_hex) {
            if group.profile.network_type.uses_ring_signatures() {
                return self.send_ring_group_message(group_id_hex, text);
            }
        }
        self.send_text_message(group_id_hex, text)
    }

    /// Invite a peer to an existing group room.
    ///
    /// Returns `true` if the peer was added (or was already a member).
    pub fn group_invite_peer(&mut self, group_id_hex: &str, peer_id_hex: &str) -> bool {
        use crate::identity::peer_id::PeerId;

        let peer_bytes: [u8; 32] = match hex::decode(peer_id_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }) {
            Some(arr) => arr,
            None => return false,
        };
        let new_member = PeerId(peer_bytes);

        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == group_id_hex) {
            // Idempotent: skip if already a member.
            if room.participants.contains(&new_member) {
                return true;
            }
            room.participants.push(new_member);
            drop(rooms);
            self.save_rooms();
            self.push_event(
                "GroupMemberAdded",
                serde_json::json!({
                    "groupId": group_id_hex,
                    "peerId":  peer_id_hex,
                }),
            );
            true
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Remote killswitch (§3.9, §8.3)
    // -----------------------------------------------------------------------

    /// Processes a `remote_wipe` frame received over the mesh.
    ///
    /// Security requirements (§8.3):
    /// 1. Sender must be a known contact at InnerCircle (Level 8).
    /// 2. `remote_wipe_enabled` runtime flag must be `true`.
    /// 3. Frame must carry a valid Ed25519 signature over the canonical
    ///    killswitch payload, preventing replay of arbitrary JSON objects
    ///    as wipe commands.
    ///
    /// On success: erases all on-disk identity data via the standard killswitch
    /// path (§3.9.1), pushes a `RemoteWiped` event so the UI can notify the
    /// user, and returns `true`.  All failures are silent (§16.1 error policy).
    fn process_remote_wipe_frame(&self, envelope: &serde_json::Value) -> bool {
        // --- 1. Sender identity resolution ---
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let sender_id_bytes: [u8; 32] = match hex::decode(sender_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let sender_peer_id = crate::identity::peer_id::PeerId(sender_id_bytes);

        // --- 2. Trust gate: sender must be InnerCircle (Level 8, §8.3) ---
        let contact = match self
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&sender_peer_id)
            .cloned()
        {
            Some(c) => c,
            None => return false, // Unknown sender — silent drop.
        };
        if contact.trust_level < crate::trust::levels::TrustLevel::InnerCircle {
            // Insufficient trust — silent drop, no feedback to sender.
            return false;
        }

        // --- 3. Remote-wipe feature gate (user must have opted in) ---
        let enabled = *self
            .remote_wipe_enabled
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !enabled {
            return false;
        }

        // --- 4. Signature verification over canonical killswitch payload ---
        // Payload: `<domain> || sender_id_bytes || "remote_wipe"`.
        // The nonce field (if present) is mixed in to prevent cross-device replay.
        let nonce = envelope.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
        let sig_hex = match envelope.get("sig").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        // Canonical message: sender peer-id bytes || ASCII "remote_wipe" || nonce bytes.
        let mut canonical_msg = Vec::with_capacity(32 + 11 + nonce.len());
        canonical_msg.extend_from_slice(&sender_id_bytes);
        canonical_msg.extend_from_slice(b"remote_wipe");
        canonical_msg.extend_from_slice(nonce.as_bytes());
        if !crate::crypto::signing::verify(
            &contact.ed25519_public,
            crate::crypto::signing::DOMAIN_KILLSWITCH,
            &canonical_msg,
            &sig_bytes,
        ) {
            // Bad signature — silent drop.
            return false;
        }

        // --- 5. Execute: erase all on-disk identity data (§3.9.1) ---
        // `standard_erase` overwrites and unlinks vault files.  In-memory state
        // becomes stale but harmless; the OS reclaims process memory on exit.
        // Per-spec: process termination is the recommended post-erase action for
        // high-assurance scenarios (§3.9 security note).
        let data_dir = std::path::Path::new(&self.data_dir);
        crate::identity::killswitch::standard_erase(data_dir);

        // Push a RemoteWiped event so the UI can display a notification and
        // guide the user through recovery before the process exits.
        self.push_event(
            "RemoteWiped",
            serde_json::json!({ "senderPeerId": sender_hex }),
        );

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ring_sig::{generate_ring_keypair, ring_sign, RingContextType};
    use crate::crypto::sender_keys::SenderKey;
    use crate::groups::group::{Group, GroupKeys, GroupPublicProfile, NetworkType};
    use crate::pairing::contact::{ContactRecord, ContactStore};
    use crate::pairing::methods::PairingMethod;
    use crate::service::runtime::MeshRuntime;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
    use tempfile::TempDir;

    #[test]
    fn test_private_group_message_sk_hides_sender_in_outer_frame() {
        let temp_dir = TempDir::new().unwrap();
        let mut runtime = MeshRuntime::new(temp_dir.path().to_string_lossy().into_owned());
        {
            let mut flags = runtime
                .transport_flags
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            flags.clearnet = false;
            flags.mesh_discovery = false;
        }
        runtime
            .create_identity(Some("Recipient".to_string()))
            .unwrap();

        let (recipient_peer_id, recipient_ed25519_pub) = {
            let guard = runtime
                .identity
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let identity = guard.as_ref().unwrap();
            (identity.peer_id(), identity.ed25519_pub)
        };
        let sender_identity =
            crate::identity::self_identity::SelfIdentity::generate(Some("Sender".to_string()));

        let mut contacts = ContactStore::new();
        contacts.upsert(ContactRecord::new(
            sender_identity.peer_id(),
            sender_identity.ed25519_pub,
            sender_identity.x25519_pub.to_bytes(),
            PairingMethod::QrCode,
            1,
        ));
        *runtime
            .contacts
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = contacts;

        let group_id = [0x33; 32];
        let symmetric_key = [0x44; 32];
        let members = vec![sender_identity.peer_id(), recipient_peer_id];
        let mut group = Group::new_as_member(
            group_id,
            GroupPublicProfile {
                group_id,
                display_name: "Secret Group".to_string(),
                description: String::new(),
                avatar_hash: None,
                network_type: NetworkType::Private,
                member_count: None,
                created_at: 1,
                signed_by: sender_identity.peer_id().0,
                signature: vec![],
            },
            GroupKeys {
                ed25519_public: [0x55; 32],
                ed25519_private: None,
                x25519_public: [0x66; 32],
                symmetric_key,
            },
            recipient_peer_id,
            (members.clone(), vec![sender_identity.peer_id()]),
            1,
            1,
        );
        // Both members have committed dedicated ring keys (§3.5.2); the
        // sender's is what the outer envelope will be signed with.
        let sender_ring = generate_ring_keypair().unwrap();
        group
            .commit_member_ring_key(&sender_identity.peer_id(), sender_ring.public)
            .unwrap();
        group.ensure_ring_keypair().unwrap();
        let ring = group.sorted_ring().unwrap();
        let ring_context = group.ring_context(RingContextType::Application);
        runtime
            .groups
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(group);

        let room = Room::new_group("Secret Group", members.clone());
        let room_id_hex = hex::encode(room.id);
        runtime
            .rooms
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(room);

        let sender_key = SenderKey::generate();
        let sender_key_chain = *sender_key.chain_key_bytes();
        let sender_key_signing_key = sender_key.signing_key_bytes();
        let sender_key_seed = GroupSenderKeySeedWire {
            chain_key: hex::encode(sender_key_chain),
            iteration: sender_key.iteration,
            verifying_key: hex::encode(sender_key.verifying_key().to_bytes()),
        };
        let sender_sig_message = build_group_inner_signature_message(
            &group_id,
            &room_id_hex,
            "msg-1",
            "hidden sender message",
            100,
            &sender_identity.peer_id().0,
        );
        let sender_sig = sender_identity.ed25519_signing.sign(&sender_sig_message);
        let plaintext = GroupMessageSkWire {
            iteration: 0,
            ciphertext: String::new(),
            signature: String::new(),
            sender_key_seed: sender_key_seed.clone(),
            sender: sender_identity.peer_id().to_hex(),
            room_id: room_id_hex.clone(),
            msg_id: "msg-1".to_string(),
            text: "hidden sender message".to_string(),
            timestamp: 100,
            sender_sig: hex::encode(sender_sig.to_bytes()),
        };
        let plaintext_bytes = serde_json::to_vec(&plaintext).unwrap();
        let mut sender_key = SenderKey::from_parts(
            sender_key_chain,
            sender_key_seed.iteration,
            &sender_key_signing_key,
        )
        .unwrap();
        let sender_key_message = sender_key.encrypt(&plaintext_bytes).unwrap();

        let wrapped_inner = serde_json::json!({
            "iteration": sender_key_message.iteration,
            "ciphertext": hex::encode(&sender_key_message.ciphertext),
            "signature": hex::encode(&sender_key_message.signature),
            "sender_key_seed": sender_key_seed,
        });
        let wrapped_inner_bytes = serde_json::to_vec(&wrapped_inner).unwrap();
        let nonce_bytes = [0x77; 12];
        let symmetric_cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key).unwrap();
        let wrapped = symmetric_cipher
            .encrypt(
                chacha20poly1305::Nonce::from_slice(&nonce_bytes),
                wrapped_inner_bytes.as_ref(),
            )
            .unwrap();
        let envelope_bytes = group_sk_envelope_bytes(&nonce_bytes, &wrapped);
        let ring_sig =
            ring_sign(&sender_ring.secret, &ring, &ring_context, &envelope_bytes).unwrap();

        let frame = serde_json::json!({
            "type": "group_message_sk",
            "groupId": hex::encode(group_id),
            "epoch": 1,
            "nonce": hex::encode(nonce_bytes),
            "wrapped": hex::encode(&wrapped),
            "ring_sig": ring_sig,
        });

        assert!(frame.get("sender").is_none());
        // The identity key never signs the outer layer: the ring key is not
        // derived from it, and the frame carries only the ring proof.
        let _ = recipient_ed25519_pub;

        // Negative vectors at the service boundary before the real frame:
        // a stale epoch, a tampered envelope and a malformed proof are all
        // dropped silently.
        let mut stale = frame.clone();
        stale["epoch"] = serde_json::json!(2);
        assert!(!runtime.process_group_message_sk_frame(&stale));
        let mut tampered = frame.clone();
        tampered["nonce"] = serde_json::json!(hex::encode([0x78; 12]));
        assert!(!runtime.process_group_message_sk_frame(&tampered));
        let mut malformed = frame.clone();
        malformed["ring_sig"] = serde_json::json!("00");
        assert!(!runtime.process_group_message_sk_frame(&malformed));

        assert!(runtime.process_group_message_sk_frame(&frame));

        let stored_messages = runtime
            .messages
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let room_messages = stored_messages.get(&room_id_hex).unwrap();
        assert_eq!(room_messages.len(), 1);
        assert_eq!(
            room_messages[0]["sender"],
            sender_identity.peer_id().to_hex()
        );
        assert_eq!(room_messages[0]["authStatus"], "authenticated");
        drop(stored_messages);

        let groups = runtime
            .groups
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let stored_group = groups
            .iter()
            .find(|group| group.group_id == group_id)
            .unwrap();
        assert!(stored_group
            .peer_sender_keys
            .contains_key(&sender_identity.peer_id().0));
    }

    // -----------------------------------------------------------------------
    // Direct-message session hardening tests
    //
    // These exercise the inbound direct-message path end to end with frames
    // built exactly as `send_text_message` builds them, so the session-
    // installation and commit-after-verify guarantees are tested at the
    // service boundary, not just in the crypto modules.
    // -----------------------------------------------------------------------

    use crate::crypto::message_encrypt::encrypt_message;
    use crate::crypto::x3dh::{x3dh_initiate, PreauthBundle, X3dhInitHeader};
    use crate::identity::self_identity::SelfIdentity;
    use x25519_dalek::PublicKey as X25519Public;

    /// Room id shared by every direct-message test frame.
    const TEST_ROOM_HEX: &str = "11111111111111111111111111111111";

    /// A runtime ("Bob") with a fresh identity and all transports disabled.
    fn test_runtime() -> (TempDir, MeshRuntime) {
        let temp_dir = TempDir::new().unwrap();
        let mut runtime = MeshRuntime::new(temp_dir.path().to_string_lossy().into_owned());
        {
            let mut flags = runtime
                .transport_flags
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            flags.clearnet = false;
            flags.mesh_discovery = false;
        }
        runtime.create_identity(Some("Bob".to_string())).unwrap();
        (temp_dir, runtime)
    }

    /// Register `peer` as a paired contact of the runtime.
    fn add_contact(runtime: &MeshRuntime, peer: &SelfIdentity) {
        let mut contacts = runtime
            .contacts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        contacts.upsert(ContactRecord::new(
            peer.peer_id(),
            peer.ed25519_pub,
            peer.x25519_pub.to_bytes(),
            PairingMethod::QrCode,
            1,
        ));
    }

    /// The runtime's X25519 identity public key (what a contact record holds).
    fn runtime_x25519_pub(runtime: &MeshRuntime) -> X25519Public {
        let guard = runtime
            .identity
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        guard.as_ref().unwrap().x25519_pub
    }

    /// The runtime's preauth bundle as an initiator would fetch it, with the
    /// preauth key signed by the runtime's Ed25519 identity key.
    fn runtime_bundle(runtime: &MeshRuntime) -> PreauthBundle {
        let guard = runtime
            .identity
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let id = guard.as_ref().unwrap();
        let preauth_sig = id
            .ed25519_signing
            .sign(&PreauthBundle::signed_message(&id.preauth_x25519_pub));
        PreauthBundle {
            identity_ed25519_pub: id.ed25519_pub,
            identity_x25519_pub: id.x25519_pub,
            preauth_x25519_pub: id.preauth_x25519_pub,
            preauth_kem_pub: None,
            preauth_sig: Some(preauth_sig.to_bytes().to_vec()),
            kem_sig: None,
        }
    }

    /// Initiator side: run X3DH against the runtime's bundle using
    /// `ik_secret` for DH1 and `ik_pub_bytes` as the identity key carried in
    /// the header, and start the sender-side ratchet.  Splitting the two
    /// lets a test build a header that names one identity key while the DH
    /// was done with another (what a forger must do).
    fn initiate_session(
        runtime: &MeshRuntime,
        ik_secret: &X25519Secret,
        ik_pub_bytes: &[u8; 32],
    ) -> (DoubleRatchetSession, X3dhInitHeader) {
        let bundle = runtime_bundle(runtime);
        let output = x3dh_initiate(ik_secret, ik_pub_bytes, &bundle).unwrap();
        let header = output.header.unwrap();
        let session = DoubleRatchetSession::init_sender(
            output.master_secret.as_bytes(),
            bundle.preauth_x25519_pub.as_bytes(),
        )
        .unwrap();
        (session, header)
    }

    /// Build a direct-message frame from `sender` to the runtime exactly as
    /// `send_text_message` does: encrypted ratchet header, four-layer
    /// ciphertext over `{"hdr", "text"}`, optional X3DH init fields.
    fn direct_frame(
        sender: &SelfIdentity,
        recipient_x25519_pub: &X25519Public,
        session: &mut DoubleRatchetSession,
        init: Option<&X3dhInitHeader>,
        msg_id: &str,
        text: &str,
    ) -> serde_json::Value {
        let (ratchet_header, msg_key) = session.next_send_msg_key().unwrap();
        let dh_shared = sender.x25519_secret.diffie_hellman(recipient_x25519_pub);
        let hdr_key =
            DoubleRatchetSession::derive_header_key_from_dh(dh_shared.as_bytes()).unwrap();
        let enc_header =
            DoubleRatchetSession::encrypt_header_with_key(&ratchet_header, &hdr_key).unwrap();
        let (cipher_key, session_nonce, ratchet_msg_key) =
            DoubleRatchetSession::expand_msg_key(&msg_key).unwrap();
        let inner = serde_json::json!({
            "hdr": {
                "ratchet_pub":    hex::encode(ratchet_header.ratchet_pub),
                "prev_chain_len": ratchet_header.prev_chain_len,
                "msg_num":        ratchet_header.msg_num,
            },
            "text": text,
        });
        let ciphertext = encrypt_message(
            &serde_json::to_vec(&inner).unwrap(),
            &ratchet_msg_key,
            &cipher_key,
            &session_nonce,
            &sender.ed25519_signing,
            recipient_x25519_pub,
            MessageContext::Direct,
        )
        .unwrap();
        let mut frame = serde_json::json!({
            "sender":     sender.peer_id().to_hex(),
            "room":       TEST_ROOM_HEX,
            "msg_id":     msg_id,
            "ts":         100,
            "enc_header": hex::encode(&enc_header),
            "ciphertext": hex::encode(&ciphertext),
        });
        if let Some(h) = init {
            let obj = frame.as_object_mut().unwrap();
            obj.insert("x3dh_eph_pub".into(), hex::encode(h.eph_pub).into());
            obj.insert(
                "x3dh_encrypted_ik".into(),
                hex::encode(h.encrypted_ik_pub).into(),
            );
        }
        frame
    }

    /// Whether the runtime holds a ratchet session for `peer`.
    fn has_session(runtime: &MeshRuntime, peer: &SelfIdentity) -> bool {
        runtime
            .ratchet_sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains_key(&peer.peer_id())
    }

    /// Serialised snapshot of the runtime's session with `peer`, for
    /// before/after comparison of every field including the root key.
    fn session_fingerprint(runtime: &MeshRuntime, peer: &SelfIdentity) -> Vec<u8> {
        let sessions = runtime
            .ratchet_sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        serde_json::to_vec(&sessions.get(&peer.peer_id()).unwrap().to_snapshot()).unwrap()
    }

    /// Number of stored messages in the test room.
    fn stored_count(runtime: &MeshRuntime) -> usize {
        runtime
            .messages
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(TEST_ROOM_HEX)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Regression test (finding: unauthenticated X3DH init installs a
    /// session): a frame naming Alice as sender whose init header carries a
    /// third party's identity key, with garbage ciphertext, must be dropped
    /// without installing any session for Alice.  Alice's genuine first
    /// message must then still bootstrap and decrypt.
    #[test]
    fn test_bogus_x3dh_init_with_wrong_identity_key_installs_no_session() {
        let (_dir, runtime) = test_runtime();
        let alice = SelfIdentity::generate(Some("Alice".to_string()));
        add_contact(&runtime, &alice);
        let bob_x25519 = runtime_x25519_pub(&runtime);

        // A third party runs a well-formed X3DH against Bob's public bundle
        // with its own identity key and names Alice as the sender.
        let other = SelfIdentity::generate(None);
        let (mut other_session, other_init) =
            initiate_session(&runtime, &other.x25519_secret, other.x25519_pub.as_bytes());
        let mut bogus = direct_frame(
            &other,
            &bob_x25519,
            &mut other_session,
            Some(&other_init),
            "bogus-1",
            "x",
        );
        bogus["sender"] = alice.peer_id().to_hex().into();

        assert!(
            !runtime.process_inbound_frame(&bogus),
            "bogus init accepted"
        );
        assert!(
            !has_session(&runtime, &alice),
            "session installed for Alice"
        );
        assert_eq!(stored_count(&runtime), 0);

        // Alice's genuine first message bootstraps and decrypts.
        let (mut alice_session, alice_init) =
            initiate_session(&runtime, &alice.x25519_secret, alice.x25519_pub.as_bytes());
        let genuine = direct_frame(
            &alice,
            &bob_x25519,
            &mut alice_session,
            Some(&alice_init),
            "alice-1",
            "hello",
        );
        assert!(
            runtime.process_inbound_frame(&genuine),
            "genuine init rejected"
        );
        assert!(has_session(&runtime, &alice));
        assert_eq!(stored_count(&runtime), 1);
    }

    /// Regression test (same finding, stronger forger): the init header
    /// carries Alice's *real* identity key (it is public), so the identity
    /// check passes, but the forger cannot complete DH1 and its ciphertext
    /// cannot authenticate.  The candidate session must not be installed.
    #[test]
    fn test_x3dh_init_with_contact_identity_key_but_bad_payload_installs_no_session() {
        let (_dir, runtime) = test_runtime();
        let alice = SelfIdentity::generate(Some("Alice".to_string()));
        add_contact(&runtime, &alice);
        let bob_x25519 = runtime_x25519_pub(&runtime);

        // Forger: own DH secret, Alice's public identity key in the header.
        let forger = SelfIdentity::generate(None);
        let (mut forger_session, forged_init) =
            initiate_session(&runtime, &forger.x25519_secret, alice.x25519_pub.as_bytes());
        let mut forged = direct_frame(
            &forger,
            &bob_x25519,
            &mut forger_session,
            Some(&forged_init),
            "forged-1",
            "x",
        );
        forged["sender"] = alice.peer_id().to_hex().into();

        assert!(
            !runtime.process_inbound_frame(&forged),
            "forged init accepted"
        );
        assert!(
            !has_session(&runtime, &alice),
            "session installed for Alice"
        );

        // Alice's genuine first message still works afterwards.
        let (mut alice_session, alice_init) =
            initiate_session(&runtime, &alice.x25519_secret, alice.x25519_pub.as_bytes());
        let genuine = direct_frame(
            &alice,
            &bob_x25519,
            &mut alice_session,
            Some(&alice_init),
            "alice-1",
            "hello",
        );
        assert!(runtime.process_inbound_frame(&genuine));
        assert!(has_session(&runtime, &alice));
    }

    /// Regression test (finding: ratchet state committed before
    /// authentication): replaying a delivered frame under a fresh `msg_id`
    /// (so the dedup cache does not catch it) must be rejected and must leave
    /// the session able to decrypt Alice's next genuine message.
    #[test]
    fn test_replayed_direct_message_keeps_session_working() {
        let (_dir, runtime) = test_runtime();
        let alice = SelfIdentity::generate(Some("Alice".to_string()));
        add_contact(&runtime, &alice);
        let bob_x25519 = runtime_x25519_pub(&runtime);
        let (mut alice_session, alice_init) =
            initiate_session(&runtime, &alice.x25519_secret, alice.x25519_pub.as_bytes());

        // Two genuine messages.
        let m1 = direct_frame(
            &alice,
            &bob_x25519,
            &mut alice_session,
            Some(&alice_init),
            "m1",
            "one",
        );
        let m2 = direct_frame(
            &alice,
            &bob_x25519,
            &mut alice_session,
            Some(&alice_init),
            "m2",
            "two",
        );
        assert!(runtime.process_inbound_frame(&m1));
        assert!(runtime.process_inbound_frame(&m2));
        let before = session_fingerprint(&runtime, &alice);

        // Replay m1 with a new message id: duplicate ratchet position.
        let mut replay = m1.clone();
        replay["msg_id"] = "m1-replay".into();
        assert!(!runtime.process_inbound_frame(&replay), "replay accepted");
        assert_eq!(
            session_fingerprint(&runtime, &alice),
            before,
            "replay changed session"
        );
        assert_eq!(stored_count(&runtime), 2, "replay was stored");

        // The next genuine message still decrypts.
        let m3 = direct_frame(&alice, &bob_x25519, &mut alice_session, None, "m3", "three");
        assert!(
            runtime.process_inbound_frame(&m3),
            "session broken after replay"
        );
        assert_eq!(stored_count(&runtime), 3);
    }

    /// Regression test (same finding): a captured frame from an *earlier
    /// ratchet chain* replayed after a DH step carries a ratchet key the
    /// session no longer tracks.  Before the fix Bob performed a DH step on
    /// the stale key and committed it; the session must instead be unchanged
    /// and keep working in both directions.
    #[test]
    fn test_stale_chain_replay_leaves_direct_session_unchanged() {
        let (_dir, runtime) = test_runtime();
        let alice = SelfIdentity::generate(Some("Alice".to_string()));
        add_contact(&runtime, &alice);
        let bob_x25519 = runtime_x25519_pub(&runtime);
        let (mut alice_session, alice_init) =
            initiate_session(&runtime, &alice.x25519_secret, alice.x25519_pub.as_bytes());

        // Chain 1: Alice's first message establishes Bob's session.
        let m1 = direct_frame(
            &alice,
            &bob_x25519,
            &mut alice_session,
            Some(&alice_init),
            "m1",
            "one",
        );
        assert!(runtime.process_inbound_frame(&m1));

        // Bob replies (taken straight from his session, since the test has
        // no transport) and Alice receives it, performing her DH step.
        let (bob_hdr, bob_ct) = {
            let mut sessions = runtime
                .ratchet_sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            sessions
                .get_mut(&alice.peer_id())
                .unwrap()
                .encrypt(b"reply")
                .unwrap()
        };
        assert_eq!(alice_session.decrypt(&bob_hdr, &bob_ct).unwrap(), b"reply");

        // Chain 2: Alice's next message carries a new ratchet key; Bob steps.
        let m2 = direct_frame(&alice, &bob_x25519, &mut alice_session, None, "m2", "two");
        assert!(runtime.process_inbound_frame(&m2));
        let before = session_fingerprint(&runtime, &alice);

        // Replay the chain-1 frame under a fresh id: stale ratchet key.
        let mut stale = m1.clone();
        stale["msg_id"] = "m1-stale".into();
        assert!(
            !runtime.process_inbound_frame(&stale),
            "stale replay accepted"
        );
        assert_eq!(
            session_fingerprint(&runtime, &alice),
            before,
            "stale replay changed session"
        );

        // Both directions still work.
        let m3 = direct_frame(&alice, &bob_x25519, &mut alice_session, None, "m3", "three");
        assert!(
            runtime.process_inbound_frame(&m3),
            "session broken after stale replay"
        );
        let (bob_hdr2, bob_ct2) = {
            let mut sessions = runtime
                .ratchet_sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            sessions
                .get_mut(&alice.peer_id())
                .unwrap()
                .encrypt(b"reply 2")
                .unwrap()
        };
        assert_eq!(
            alice_session.decrypt(&bob_hdr2, &bob_ct2).unwrap(),
            b"reply 2"
        );
    }

    /// Regression test: the plaintext legacy header fallback is gone.  A
    /// frame with plaintext `ratchet_pub`/`msg_num` fields and no
    /// `enc_header` must be rejected without touching the session, even
    /// when the sender is a known contact with an installed session.
    #[test]
    fn test_plaintext_legacy_header_is_rejected() {
        let (_dir, runtime) = test_runtime();
        let alice = SelfIdentity::generate(Some("Alice".to_string()));
        add_contact(&runtime, &alice);
        let bob_x25519 = runtime_x25519_pub(&runtime);
        let (mut alice_session, alice_init) =
            initiate_session(&runtime, &alice.x25519_secret, alice.x25519_pub.as_bytes());
        let m1 = direct_frame(
            &alice,
            &bob_x25519,
            &mut alice_session,
            Some(&alice_init),
            "m1",
            "one",
        );
        assert!(runtime.process_inbound_frame(&m1));
        let before = session_fingerprint(&runtime, &alice);

        // Attacker-chosen plaintext header naming an arbitrary ratchet key.
        let legacy = serde_json::json!({
            "sender":         alice.peer_id().to_hex(),
            "room":           TEST_ROOM_HEX,
            "msg_id":         "legacy-1",
            "ts":             100,
            "ratchet_pub":    hex::encode([0x42u8; 32]),
            "prev_chain_len": 0,
            "msg_num":        0,
            "ciphertext":     hex::encode([0u8; 64]),
        });
        assert!(
            !runtime.process_inbound_frame(&legacy),
            "legacy header accepted"
        );
        assert_eq!(
            session_fingerprint(&runtime, &alice),
            before,
            "legacy frame changed session"
        );
    }

    /// §22.8.2 block gate: a genuine, decryptable first message from a
    /// blocked contact is dropped before any session is installed, and the
    /// same message is accepted once the block is lifted.  The frame is
    /// cryptographically valid, so the only thing standing between it and
    /// the message store is the block flag.
    #[test]
    fn test_blocked_contact_direct_message_is_dropped_until_unblocked() {
        let (_dir, runtime) = test_runtime();
        let alice = SelfIdentity::generate(Some("Alice".to_string()));
        add_contact(&runtime, &alice);
        let bob_x25519 = runtime_x25519_pub(&runtime);
        let alice_hex = alice.peer_id().to_hex();

        // Alice's genuine first message, built exactly as send_text_message does.
        let (mut alice_session, alice_init) =
            initiate_session(&runtime, &alice.x25519_secret, alice.x25519_pub.as_bytes());
        let genuine = direct_frame(
            &alice,
            &bob_x25519,
            &mut alice_session,
            Some(&alice_init),
            "alice-blocked-1",
            "hello",
        );

        // Blocked: dropped, no session, nothing stored.
        runtime.set_peer_blocked(&alice_hex, true).unwrap();
        assert!(
            !runtime.process_inbound_frame(&genuine),
            "blocked contact's message accepted"
        );
        assert!(
            !has_session(&runtime, &alice),
            "session installed for blocked contact"
        );
        assert_eq!(stored_count(&runtime), 0);

        // Unblocked: the very same frame bootstraps the session and lands.
        runtime.set_peer_blocked(&alice_hex, false).unwrap();
        assert!(
            runtime.process_inbound_frame(&genuine),
            "unblocked contact's message rejected"
        );
        assert!(has_session(&runtime, &alice));
        assert_eq!(stored_count(&runtime), 1);
    }

    // -----------------------------------------------------------------------
    // Ring key commit tests (§3.5.2 "authenticated membership commit")
    // -----------------------------------------------------------------------

    /// Build a group control frame from `sender` exactly as
    /// `seal_group_control_frame` does on the sending side: payload sealed
    /// under the next ratchet message key, header top-level, optional X3DH
    /// init fields for a first contact.
    fn group_control_frame(
        sender: &SelfIdentity,
        session: &mut DoubleRatchetSession,
        init: Option<&X3dhInitHeader>,
        frame_type: &str,
        payload: &serde_json::Value,
    ) -> serde_json::Value {
        use chacha20poly1305::{
            aead::{Aead, Nonce},
            ChaCha20Poly1305, Key, KeyInit,
        };
        let (ratchet_header, msg_key) = session.next_send_msg_key().unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let nonce = Nonce::<ChaCha20Poly1305>::default();
        let ciphertext = cipher
            .encrypt(&nonce, serde_json::to_vec(payload).unwrap().as_ref())
            .unwrap();
        let mut frame = serde_json::json!({
            "type":           frame_type,
            "sender":         sender.peer_id().to_hex(),
            "ratchet_header": serde_json::to_value(&ratchet_header).unwrap(),
            "ciphertext":     hex::encode(&ciphertext),
        });
        if let Some(h) = init {
            let obj = frame.as_object_mut().unwrap();
            obj.insert("x3dh_eph_pub".into(), hex::encode(h.eph_pub).into());
            obj.insert(
                "x3dh_encrypted_ik".into(),
                hex::encode(h.encrypted_ik_pub).into(),
            );
        }
        frame
    }

    /// Install a Private group on the runtime with `members`, returning its id.
    fn install_private_group(
        runtime: &MeshRuntime,
        members: Vec<PeerId>,
        admin: PeerId,
    ) -> [u8; 32] {
        let group_id = [0x36; 32];
        let our_peer_id = runtime
            .identity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .unwrap()
            .peer_id();
        let group = Group::new_as_member(
            group_id,
            GroupPublicProfile {
                group_id,
                display_name: "Commit Group".to_string(),
                description: String::new(),
                avatar_hash: None,
                network_type: NetworkType::Private,
                member_count: None,
                created_at: 1,
                signed_by: admin.0,
                signature: vec![],
            },
            GroupKeys {
                ed25519_public: [0x55; 32],
                ed25519_private: None,
                x25519_public: [0x66; 32],
                symmetric_key: [0x44; 32],
            },
            our_peer_id,
            (members, vec![admin]),
            1,
            1,
        );
        runtime
            .groups
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(group);
        group_id
    }

    /// The recorded ring key for `peer` in the runtime's group, if any.
    fn recorded_ring_key(
        runtime: &MeshRuntime,
        group_id: &[u8; 32],
        peer: &PeerId,
    ) -> Option<[u8; 32]> {
        runtime
            .groups
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .find(|g| g.group_id == *group_id)
            .and_then(|g| g.member_ring_keys.get(&peer.0).copied())
    }

    /// A member's authenticated `group_ring_commit` records their key, after
    /// which the runtime can assemble the full ring.
    #[test]
    fn test_group_ring_commit_records_member_key() {
        let (_dir, runtime) = test_runtime();
        let alice = SelfIdentity::generate(Some("Alice".to_string()));
        add_contact(&runtime, &alice);
        let bob = runtime
            .identity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .unwrap()
            .peer_id();
        let group_id = install_private_group(&runtime, vec![alice.peer_id(), bob], alice.peer_id());

        // Alice bootstraps a session and commits her ring key in one frame.
        let (mut session, init) =
            initiate_session(&runtime, &alice.x25519_secret, alice.x25519_pub.as_bytes());
        let alice_ring = generate_ring_keypair().unwrap();
        let payload = serde_json::json!({
            "type":    "group_ring_commit",
            "groupId": hex::encode(group_id),
            "ringPub": hex::encode(alice_ring.public),
        });
        let frame = group_control_frame(
            &alice,
            &mut session,
            Some(&init),
            "group_ring_commit",
            &payload,
        );
        assert!(runtime.process_inbound_frame(&frame));
        assert_eq!(
            recorded_ring_key(&runtime, &group_id, &alice.peer_id()),
            Some(alice_ring.public)
        );

        // With Bob's own key minted, the ring is complete and sorted.
        let mut groups = runtime
            .groups
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let group = groups.iter_mut().find(|g| g.group_id == group_id).unwrap();
        let bob_ring = group.ensure_ring_keypair().unwrap();
        let ring = group.sorted_ring().unwrap();
        let mut expected = vec![alice_ring.public, bob_ring];
        expected.sort_unstable();
        assert_eq!(ring, expected);
    }

    /// Commits from non-members and commits of invalid points are dropped,
    /// leaving the ring incomplete rather than poisoned.
    #[test]
    fn test_group_ring_commit_rejects_non_member_and_invalid_point() {
        let (_dir, runtime) = test_runtime();
        let alice = SelfIdentity::generate(Some("Alice".to_string()));
        let mallory = SelfIdentity::generate(Some("Mallory".to_string()));
        add_contact(&runtime, &alice);
        add_contact(&runtime, &mallory);
        let bob = runtime
            .identity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .unwrap()
            .peer_id();
        let group_id = install_private_group(&runtime, vec![alice.peer_id(), bob], alice.peer_id());

        // Mallory is a contact but not a member: authenticated, still refused.
        let (mut m_session, m_init) = initiate_session(
            &runtime,
            &mallory.x25519_secret,
            mallory.x25519_pub.as_bytes(),
        );
        let mallory_ring = generate_ring_keypair().unwrap();
        let frame = group_control_frame(
            &mallory,
            &mut m_session,
            Some(&m_init),
            "group_ring_commit",
            &serde_json::json!({
                "type":    "group_ring_commit",
                "groupId": hex::encode(group_id),
                "ringPub": hex::encode(mallory_ring.public),
            }),
        );
        assert!(!runtime.process_inbound_frame(&frame));
        assert_eq!(
            recorded_ring_key(&runtime, &group_id, &mallory.peer_id()),
            None
        );

        // Alice is a member but commits the identity point: refused.
        let (mut a_session, a_init) =
            initiate_session(&runtime, &alice.x25519_secret, alice.x25519_pub.as_bytes());
        let frame = group_control_frame(
            &alice,
            &mut a_session,
            Some(&a_init),
            "group_ring_commit",
            &serde_json::json!({
                "type":    "group_ring_commit",
                "groupId": hex::encode(group_id),
                "ringPub": hex::encode([0u8; 32]),
            }),
        );
        assert!(!runtime.process_inbound_frame(&frame));
        assert_eq!(
            recorded_ring_key(&runtime, &group_id, &alice.peer_id()),
            None
        );
        // The ring cannot be assembled while a member's key is missing.
        let groups = runtime
            .groups
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let group = groups.iter().find(|g| g.group_id == group_id).unwrap();
        assert!(group.sorted_ring().is_none());
    }
}
