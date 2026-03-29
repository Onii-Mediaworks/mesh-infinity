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
use crate::service::runtime::{MeshRuntime, bootstrap_ratchet_session};
use x25519_dalek::StaticSecret as X25519Secret;

impl MeshRuntime {
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

        let frame_type = envelope.get("type").and_then(|t| t.as_str()).unwrap_or("");

        // LoSec negotiation — carry their own Ed25519 signatures.
        if frame_type == "losec_request"  { return self.process_losec_request_frame(envelope); }
        if frame_type == "losec_response" { return self.process_losec_response_frame(envelope); }

        // Gossip map entry.
        if frame_type == "gossip_map_entry" { return self.process_gossip_map_entry_frame(envelope); }

        // Call signalling.
        if frame_type == "call_offer"   { return self.process_call_offer_frame(envelope); }
        if frame_type == "call_answer"  { return self.process_call_answer_frame(envelope); }
        if frame_type == "call_hangup"  { return self.process_call_hangup_frame(envelope); }

        // WireGuard handshake.
        if frame_type == "wg_init"      { return self.process_wg_init_frame(envelope); }
        if frame_type == "wg_response"  { return self.process_wg_response_frame(envelope); }

        // Routing.
        if frame_type == "route_announcement" { return self.process_route_announcement_frame(envelope); }
        if frame_type == "mesh_packet"        { return self.process_mesh_packet_frame(envelope); }

        // File transfers.
        if frame_type == "file_offer"    { return self.process_file_offer_frame(envelope); }
        if frame_type == "file_chunk"    { return self.process_file_chunk_frame(envelope); }
        if frame_type == "file_complete" { return self.process_file_complete_frame(envelope); }

        // Group messaging.
        if frame_type == "group_rekey"                  { return self.process_group_rekey_frame(envelope); }
        if frame_type == "group_invite"                 { return self.process_group_invite_frame(envelope); }
        if frame_type == "group_message"                { return self.process_group_message_frame(envelope); }
        if frame_type == "group_message_sk"             { return self.process_group_message_sk_frame(envelope); }
        if frame_type == "group_reinclusion_request"    { return self.process_group_reinclusion_request_frame(envelope); }

        // Store-and-forward.
        if frame_type == "sf_deposit"   { return self.process_sf_deposit_frame(envelope); }
        if frame_type == "sf_deliver"   { return self.process_sf_deliver_frame(envelope); }

        // Delivery receipt.
        if frame_type == "delivery_receipt" { return self.process_delivery_receipt_frame(envelope); }

        // Keepalive probes.
        if frame_type == "keepalive" {
            let our_hex = self.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default();
            if let Some(peer_hex) = envelope.get("sender").and_then(|v| v.as_str()) {
                self.send_raw_frame(peer_hex, &serde_json::json!({
                    "type": "keepalive_ack",
                    "sender": our_hex,
                }));
            }
            return true;
        }
        // Keepalive ack — no action needed; last_rx already updated.
        if frame_type == "keepalive_ack" { return true; }

        // Typing indicator.
        if frame_type == "typing_indicator" {
            if let (Some(sender), Some(room_id)) = (
                envelope.get("sender").and_then(|v| v.as_str()),
                envelope.get("roomId").and_then(|v| v.as_str()),
            ) {
                let is_active = envelope.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                self.push_event("TypingIndicator", serde_json::json!({
                    "roomId": room_id,
                    "peerId": sender,
                    "active": is_active,
                }));
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
                    self.push_event("ReactionAdded", serde_json::json!({
                        "roomId": room_id,
                        "msgId":  msg_id,
                        "peerId": sender,
                        "emoji":  emoji,
                    }));
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

        let sender_hex      = field_str!("sender");
        let room_id_hex     = field_str!("room");
        let msg_id          = field_str!("msg_id");
        let ts              = envelope.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
        let ciphertext_hex  = field_str!("ciphertext");
        let ratchet_pub_hex = field_str!("ratchet_pub");
        let prev_chain_len  = envelope.get("prev_chain_len").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let msg_num         = envelope.get("msg_num").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        // Decode binary fields.
        let ciphertext = match hex::decode(&ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ratchet_pub_bytes: [u8; 32] = match hex::decode(&ratchet_pub_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sender_id_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sender_peer_id = PeerId(sender_id_bytes);

        // Reject frames from unknown senders.
        let contact = match self.contacts.lock().unwrap_or_else(|e| e.into_inner())
            .get(&sender_peer_id).cloned()
        {
            Some(c) => c,
            None => return false,
        };

        // Bootstrap a ratchet session if we don't have one for this sender yet.
        if !self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
            .contains_key(&sender_peer_id)
        {
            if let Some(session) = self.bootstrap_session_from_frame(envelope, &contact, sender_peer_id) {
                self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                    .insert(sender_peer_id, session);
            }
        } else {
            // Existing session — clear any pending X3DH/PQXDH headers for this peer
            // (receipt of a reply means Bob has established his matching session).
            self.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&sender_peer_id);
            self.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&sender_peer_id);
        }

        // Advance the ratchet and derive message keys.
        let header = RatchetHeader { ratchet_pub: ratchet_pub_bytes, prev_chain_len, msg_num };
        let (cipher_key, session_nonce, ratchet_msg_key) = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            let session = match sessions.get_mut(&sender_peer_id) {
                Some(s) => s,
                None => return false,
            };
            let msg_key = match session.recv_msg_key(&header) {
                Ok(k) => k,
                Err(_) => return false,
            };
            match DoubleRatchetSession::expand_msg_key(&msg_key) {
                Ok(keys) => keys,
                Err(_) => return false,
            }
        };

        // Our X25519 secret and sender's Ed25519 verifying key for decryption.
        let our_x25519_secret = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => X25519Secret::from(id.x25519_secret.to_bytes()),
                None => return false,
            }
        };
        let sender_verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&contact.ed25519_public) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Decrypt via the four-layer scheme (§7.1).
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

        let text = match String::from_utf8(plaintext) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Auto-create a DM room if one doesn't exist for this conversation.
        let room_exists = self.rooms.lock().unwrap_or_else(|e| e.into_inner())
            .iter().any(|r| hex::encode(r.id) == room_id_hex);
        if !room_exists {
            let our_peer_id = self.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| id.peer_id()).unwrap_or(PeerId([0u8; 32]));
            let peer_name = contact.display_name.as_deref()
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
            self.rooms.lock().unwrap_or_else(|e| e.into_inner()).push(room);
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
        self.messages.lock().unwrap_or_else(|e| e.into_inner())
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
            rooms.iter().find(|r| hex::encode(r.id) == room_id_hex).map(|r| serde_json::json!({
                "id":           hex::encode(r.id),
                "name":         r.name,
                "lastMessage":  r.last_message_preview,
                "unreadCount":  r.unread_count,
                "timestamp":    r.last_message_at,
            }))
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }

        // Send a delivery receipt to the sender (§7.3).
        {
            let our_hex = self.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default();
            let ts_now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);
            self.send_raw_frame(&sender_hex, &serde_json::json!({
                "type":   "delivery_receipt",
                "sender": our_hex,
                "msg_id": msg_id,
                "room":   room_id_hex,
                "ts":     ts_now,
            }));
        }

        // Submit notification (§14) — dispatcher applies jitter/suppression.
        if self.module_config.lock().unwrap_or_else(|e| e.into_inner()).social.notifications {
            let conv_id_padded: Option<[u8; 32]> = hex::decode(&room_id_hex)
                .ok()
                .filter(|b| b.len() == 16)
                .map(|b| {
                    let mut a = [0u8; 32];
                    a[..16].copy_from_slice(&b);
                    a
                });
            let sender_name = self.contacts.lock().unwrap_or_else(|e| e.into_inner())
                .get(&sender_peer_id)
                .and_then(|c| c.display_name.clone())
                .unwrap_or_else(|| sender_peer_id.short_hex());
            let notif_event = crate::notifications::NotificationEvent {
                priority:        crate::notifications::NotificationPriority::Normal,
                title:           format!("New message from {}", sender_name),
                body:            Some(if text.len() > 60 { format!("{}…", &text[..60]) } else { text.clone() }),
                sender_id:       Some(sender_peer_id.0),
                conversation_id: conv_id_padded,
                created_at:      ts,
            };
            self.notifications.lock().unwrap_or_else(|e| e.into_inner()).submit(notif_event);
        }

        self.save_messages();
        self.save_rooms();
        self.save_ratchet_sessions();
        true
    }

    /// Bootstrap a Double Ratchet session from an inbound message frame.
    ///
    /// Tries X3DH/PQXDH if the frame carries the init header fields;
    /// falls back to static DH otherwise.  Returns `None` if bootstrapping
    /// fails (caller should return `false` to discard the frame).
    fn bootstrap_session_from_frame(
        &self,
        envelope: &serde_json::Value,
        contact: &crate::pairing::contact::ContactRecord,
        _sender_peer_id: PeerId,
    ) -> Option<DoubleRatchetSession> {
        let eph_pub_opt: Option<[u8; 32]> = envelope.get("x3dh_eph_pub")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });

        let enc_ik_opt = envelope.get("x3dh_encrypted_ik")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == crate::crypto::x3dh::ENCRYPTED_IK_SIZE)
            .map(|b| { let mut a = [0u8; crate::crypto::x3dh::ENCRYPTED_IK_SIZE]; a.copy_from_slice(&b); a });

        let pqxdh_kem_ct = envelope.get("pqxdh_kem_ct")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == crate::crypto::x3dh::KEM_CT_SIZE);

        let pqxdh_kem_binding: Option<[u8; 32]> = envelope.get("pqxdh_kem_binding")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });

        if let (Some(eph_pub), Some(enc_ik)) = (eph_pub_opt, enc_ik_opt) {
            // X3DH/PQXDH response path: we are Bob receiving Alice's init header.
            use crate::crypto::x3dh::{x3dh_respond, pqxdh_decapsulate, X3dhInitHeader};
            use hkdf::Hkdf;
            use zeroize::Zeroizing;

            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = guard.as_ref()?;

            let header = X3dhInitHeader { eph_pub, encrypted_ik_pub: enc_ik };
            let mut output = x3dh_respond(&id.x25519_secret, &id.preauth_x25519_secret, &header).ok()?;

            // PQXDH: mix in post-quantum shared secret if both fields are present.
            if let (Some(ref kem_ct), Some(ref kem_binding)) = (&pqxdh_kem_ct, &pqxdh_kem_binding) {
                let dh3 = id.preauth_x25519_secret.diffie_hellman(
                    &x25519_dalek::PublicKey::from(eph_pub),
                );
                if let Ok(pq_ss) = pqxdh_decapsulate(
                    &id.kem_decapsulation_key,
                    kem_ct,
                    kem_binding,
                    dh3.as_bytes(),
                ) {
                    let dh1 = id.preauth_x25519_secret.diffie_hellman(
                        &x25519_dalek::PublicKey::from(contact.x25519_public),
                    );
                    let dh2 = id.x25519_secret.diffie_hellman(
                        &x25519_dalek::PublicKey::from(eph_pub),
                    );
                    let dh3_inner = id.preauth_x25519_secret.diffie_hellman(
                        &x25519_dalek::PublicKey::from(eph_pub),
                    );
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
            let preauth_pub    = *id.preauth_x25519_pub.as_bytes();
            Some(DoubleRatchetSession::init_receiver(master, preauth_secret, &preauth_pub))
        } else {
            // Static DH fallback.
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().and_then(|id| {
                bootstrap_ratchet_session(id, contact).ok().map(|(s, _, _)| s)
            })
        }
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
        use crate::service::runtime::try_random_fill;
        use crate::crypto::message_encrypt::encrypt_message;

        if !self.identity_unlocked { return false; }
        if text.is_empty() { return false; }

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
                Some(id) => (
                    id.peer_id(),
                    id.ed25519_signing.clone(),
                ),
                None => return false,
            }
        };

        // Generate a unique message ID.
        let mut msg_id_bytes = [0u8; 16];
        if !try_random_fill(&mut msg_id_bytes) { return false; }
        let msg_id_hex = hex::encode(msg_id_bytes);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        // Send to each non-self participant.
        for peer_id in &participants {
            if *peer_id == our_peer_id { continue; }

            let peer_hex = peer_id.to_hex();
            let contact = match self.contacts.lock().unwrap_or_else(|e| e.into_inner())
                .get(peer_id).cloned()
            {
                Some(c) => c,
                None => continue,
            };

            // Ensure a ratchet session exists for this peer.
            if !self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                .contains_key(peer_id)
            {
                let id_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref id) = *id_guard {
                    match bootstrap_ratchet_session(id, &contact) {
                        Ok((session, x3dh_hdr, pq_ext)) => {
                            if let Some(h) = x3dh_hdr {
                                self.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner())
                                    .insert(*peer_id, h);
                            }
                            if let Some(e) = pq_ext {
                                self.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner())
                                    .insert(*peer_id, e);
                            }
                            self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                                .insert(*peer_id, session);
                        }
                        Err(_) => continue,
                    }
                }
            }

            // Advance ratchet for the next send message key.
            let (ratchet_header, msg_key) = {
                let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
                match sessions.get_mut(peer_id) {
                    Some(s) => match s.next_send_msg_key() {
                        Ok(k) => k,
                        Err(_) => continue,
                    },
                    None => continue,
                }
            };
            let (cipher_key, session_nonce, ratchet_msg_key) =
                match DoubleRatchetSession::expand_msg_key(&msg_key) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

            // Four-layer encrypt.
            let their_x25519_pub = x25519_dalek::PublicKey::from(contact.x25519_public);
            let ciphertext = match encrypt_message(
                text.as_bytes(),
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

            // Build wire frame.
            let mut frame = serde_json::json!({
                "sender":         our_peer_id.to_hex(),
                "room":           room_id_hex,
                "msg_id":         msg_id_hex,
                "ts":             ts,
                "ratchet_pub":    hex::encode(ratchet_header.ratchet_pub),
                "prev_chain_len": ratchet_header.prev_chain_len,
                "msg_num":        ratchet_header.msg_num,
                "ciphertext":     hex::encode(&ciphertext),
            });

            // Attach X3DH init header if this is our first message to this peer.
            if let Some((eph, ik)) = self.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner())
                .get(peer_id).copied()
            {
                if let Some(obj) = frame.as_object_mut() {
                    obj.insert("x3dh_eph_pub".into(), serde_json::Value::String(hex::encode(eph)));
                    obj.insert("x3dh_encrypted_ik".into(), serde_json::Value::String(hex::encode(ik)));
                }
            }
            // Attach PQXDH extension if present.
            if let Some((kem_ct, kem_binding)) = self.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner())
                .get(peer_id).cloned()
            {
                if let Some(obj) = frame.as_object_mut() {
                    obj.insert("pqxdh_kem_ct".into(), serde_json::Value::String(hex::encode(&kem_ct)));
                    obj.insert("pqxdh_kem_binding".into(), serde_json::Value::String(hex::encode(kem_binding)));
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
        self.messages.lock().unwrap_or_else(|e| e.into_inner())
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
                room.next_sequence   += 1;
            }
        }

        self.push_event("MessageAdded", msg);
        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms.iter().find(|r| hex::encode(r.id) == room_id_hex).map(|r| serde_json::json!({
                "id":          hex::encode(r.id),
                "name":        r.name,
                "lastMessage": r.last_message_preview,
                "unreadCount": r.unread_count,
                "timestamp":   r.last_message_at,
            }))
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }

        self.save_messages();
        self.save_rooms();
        self.save_ratchet_sessions();
        true
    }

    // -----------------------------------------------------------------------
    // send_raw_frame — internal transport helper
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
                let mut wg = self.wireguard_sessions.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(session) = wg.get_mut(&peer_id) {
                    match session.encrypt(&frame_bytes) {
                        Ok(ct) => {
                            let envelope = serde_json::json!({ "wg_ct": hex::encode(&ct) });
                            serde_json::to_vec(&envelope).unwrap_or(frame_bytes)
                        }
                        Err(_) => frame_bytes, // Encrypt error — send plaintext.
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
        let mut conns = self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(stream) = conns.get_mut(peer_id_hex) {
            let len = payload.len() as u32;
            if let Err(e) = stream.write_all(&len.to_be_bytes())
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
                if let Some(msg) = room_msgs.iter_mut()
                    .find(|m| m.get("id").and_then(|v| v.as_str()) == Some(&msg_id))
                {
                    // Only promote forward: sent → delivered.
                    let current = msg.get("deliveryStatus")
                        .and_then(|v| v.as_str()).unwrap_or("sent");
                    if current == "sent" {
                        msg["deliveryStatus"] = serde_json::json!("delivered");
                    }
                }
            }
        }

        // Emit event so the UI can update the message's delivery indicator.
        self.push_event("MessageStatusUpdated", serde_json::json!({
            "msgId":          msg_id,
            "roomId":         room_id,
            "deliveryStatus": "delivered",
        }));

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
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
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

        // Bootstrap ratchet session from X3DH header if the session is missing.
        {
            let contact = self.contacts.lock().unwrap_or_else(|e| e.into_inner())
                .get(&sender_peer_id).cloned();
            if let Some(ref contact) = contact {
                if !self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                    .contains_key(&sender_peer_id)
                {
                    let eph_pub_opt = envelope.get("x3dh_eph_pub")
                        .and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .filter(|b| b.len() == 32)
                        .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
                    let enc_ik_opt = envelope.get("x3dh_encrypted_ik")
                        .and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .filter(|b| b.len() == crate::crypto::x3dh::ENCRYPTED_IK_SIZE)
                        .map(|b| {
                            let mut a = [0u8; crate::crypto::x3dh::ENCRYPTED_IK_SIZE];
                            a.copy_from_slice(&b); a
                        });
                    if let (Some(eph_pub), Some(enc_ik)) = (eph_pub_opt, enc_ik_opt) {
                        use crate::crypto::x3dh::{x3dh_respond, X3dhInitHeader};
                        let session_result: Option<DoubleRatchetSession> = {
                            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                            guard.as_ref().and_then(|id| {
                                let header = X3dhInitHeader { eph_pub, encrypted_ik_pub: enc_ik };
                                x3dh_respond(&id.x25519_secret, &id.preauth_x25519_secret, &header)
                                    .ok()
                                    .map(|out| {
                                        let master = out.master_secret.as_bytes();
                                        let preauth_secret = x25519_dalek::StaticSecret::from(
                                            id.preauth_x25519_secret.to_bytes());
                                        let preauth_pub = *id.preauth_x25519_pub.as_bytes();
                                        DoubleRatchetSession::init_receiver(
                                            master, preauth_secret, &preauth_pub)
                                    })
                            })
                        };
                        if let Some(session) = session_result {
                            self.ratchet_sessions.lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(sender_peer_id, session);
                        }
                    }
                    let _ = contact;
                }
            }
        }

        // Decrypt the rekey payload using the ratchet message key.
        let plaintext = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            let session = match sessions.get_mut(&sender_peer_id) {
                Some(s) => s,
                None => return false,
            };
            let msg_key = match session.recv_msg_key(&ratchet_header) {
                Ok(k) => k,
                Err(_) => return false,
            };
            // Decrypt using ChaCha20-Poly1305; nonce = all-zero 12 bytes.
            use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
            let nonce = Nonce::<ChaCha20Poly1305>::default();
            match cipher.decrypt(&nonce, ct.as_ref()) {
                Ok(pt) => pt,
                Err(_) => return false,
            }
        };

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
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let gid_bytes = match hex::decode(&group_id_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
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
                    .map(|d| d.as_secs()).unwrap_or(0);
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
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sender_peer_id = crate::identity::peer_id::PeerId(sender_bytes);

        // Bootstrap ratchet session if X3DH header is present.
        {
            let contact = self.contacts.lock().unwrap_or_else(|e| e.into_inner())
                .get(&sender_peer_id).cloned();
            if let Some(ref _contact) = contact {
                if !self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                    .contains_key(&sender_peer_id)
                {
                    let eph_pub_opt = envelope.get("x3dh_eph_pub")
                        .and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .filter(|b| b.len() == 32)
                        .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
                    let enc_ik_opt = envelope.get("x3dh_encrypted_ik")
                        .and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .filter(|b| b.len() == crate::crypto::x3dh::ENCRYPTED_IK_SIZE)
                        .map(|b| {
                            let mut a = [0u8; crate::crypto::x3dh::ENCRYPTED_IK_SIZE];
                            a.copy_from_slice(&b); a
                        });
                    if let (Some(eph_pub), Some(enc_ik)) = (eph_pub_opt, enc_ik_opt) {
                        use crate::crypto::x3dh::{x3dh_respond, X3dhInitHeader};
                        let session_result: Option<DoubleRatchetSession> = {
                            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                            guard.as_ref().and_then(|id| {
                                let header = X3dhInitHeader { eph_pub, encrypted_ik_pub: enc_ik };
                                x3dh_respond(&id.x25519_secret, &id.preauth_x25519_secret, &header)
                                    .ok()
                                    .map(|out| {
                                        let master = out.master_secret.as_bytes();
                                        let preauth_secret = x25519_dalek::StaticSecret::from(
                                            id.preauth_x25519_secret.to_bytes());
                                        let preauth_pub = *id.preauth_x25519_pub.as_bytes();
                                        DoubleRatchetSession::init_receiver(
                                            master, preauth_secret, &preauth_pub)
                                    })
                            })
                        };
                        if let Some(session) = session_result {
                            self.ratchet_sessions.lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(sender_peer_id, session);
                        }
                    }
                }
            }
        }

        // Decrypt the invite payload using the ratchet session.
        let header_val = match envelope.get("ratchet_header") {
            Some(v) => v.clone(),
            None => return false,
        };
        let ratchet_header: RatchetHeader = match serde_json::from_value(header_val) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let plaintext = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            let session = match sessions.get_mut(&sender_peer_id) {
                Some(s) => s,
                None => return false,
            };
            let msg_key = match session.recv_msg_key(&ratchet_header) {
                Ok(k) => k,
                Err(_) => return false,
            };
            use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
            let nonce = Nonce::<ChaCha20Poly1305>::default();
            match cipher.decrypt(&nonce, ct.as_ref()) {
                Ok(pt) => pt,
                Err(_) => return false,
            }
        };

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
        let group_id_hex    = match inv.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let ed25519_pub_hex = match inv.get("ed25519Pub").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let x25519_pub_hex  = match inv.get("x25519Pub").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let sym_key_hex     = match inv.get("symmetricKey").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let sender_key_epoch = inv.get("senderKeyEpoch").and_then(|v| v.as_u64()).unwrap_or(1);
        let name = inv.get("name").and_then(|v| v.as_str()).unwrap_or("Group").to_string();

        let gid_bytes = match hex::decode(&group_id_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let ed25519_pub_bytes = match hex::decode(&ed25519_pub_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let x25519_pub_bytes = match hex::decode(&x25519_pub_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sym_key_bytes = match hex::decode(&sym_key_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let members: Vec<crate::identity::peer_id::PeerId> = inv.get("members")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|m| m.as_str())
                .filter_map(|s| hex::decode(s).ok())
                .filter(|b| b.len() == 32)
                .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b);
                    crate::identity::peer_id::PeerId(a) })
                .collect())
            .unwrap_or_default();
        let admins: Vec<crate::identity::peer_id::PeerId> = inv.get("admins")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|m| m.as_str())
                .filter_map(|s| hex::decode(s).ok())
                .filter(|b| b.len() == 32)
                .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b);
                    crate::identity::peer_id::PeerId(a) })
                .collect())
            .unwrap_or_default();

        let our_peer_id = match self.identity.lock().unwrap_or_else(|e| e.into_inner())
            .as_ref().map(|id| id.peer_id())
        {
            Some(p) => p,
            None => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        // Skip if we are already a member of this group (idempotent).
        let already_member = self.groups.lock().unwrap_or_else(|e| e.into_inner())
            .iter().any(|g| g.group_id == gid_bytes);
        if already_member {
            return true;
        }

        // Build and store the Group record.
        use crate::groups::group::{Group, GroupPublicProfile, NetworkType};
        let description_str = inv.get("description").and_then(|v| v.as_str())
            .unwrap_or("").to_string();
        let profile = GroupPublicProfile {
            group_id:     gid_bytes,
            display_name: name.clone(),
            description:  description_str,
            avatar_hash:  None,
            network_type: NetworkType::Private,
            member_count: None,
            created_at:   now,
            signed_by:    sender_bytes,
            signature:    vec![],
        };
        let group = Group::new_as_member(
            gid_bytes,
            profile,
            crate::groups::group::GroupKeys {
                ed25519_public:  ed25519_pub_bytes,
                ed25519_private: None,
                x25519_public:   x25519_pub_bytes,
                symmetric_key:   sym_key_bytes,
            },
            our_peer_id,
            (members.clone(), admins),
            sender_key_epoch,
            now,
        );
        self.groups.lock().unwrap_or_else(|e| e.into_inner()).push(group);
        self.save_groups();

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
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).push(room);
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
        let outer_group_id_hex = envelope.get("groupId")
            .and_then(|v| v.as_str()).map(|s| s.to_string());
        let ciphertext_hex = match envelope.get("ciphertext").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sender_peer_id = crate::identity::peer_id::PeerId(sender_bytes);

        // Bootstrap ratchet from X3DH header if the session is missing.
        {
            if !self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                .contains_key(&sender_peer_id)
            {
                let eph_pub_opt = envelope.get("x3dh_eph_pub")
                    .and_then(|v| v.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .filter(|b| b.len() == 32)
                    .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
                let enc_ik_opt = envelope.get("x3dh_encrypted_ik")
                    .and_then(|v| v.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .filter(|b| b.len() == crate::crypto::x3dh::ENCRYPTED_IK_SIZE)
                    .map(|b| {
                        let mut a = [0u8; crate::crypto::x3dh::ENCRYPTED_IK_SIZE];
                        a.copy_from_slice(&b); a
                    });
                if let (Some(eph_pub), Some(enc_ik)) = (eph_pub_opt, enc_ik_opt) {
                    use crate::crypto::x3dh::{x3dh_respond, X3dhInitHeader};
                    let session_result: Option<DoubleRatchetSession> = {
                        let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                        guard.as_ref().and_then(|id| {
                            let header = X3dhInitHeader { eph_pub, encrypted_ik_pub: enc_ik };
                            x3dh_respond(&id.x25519_secret, &id.preauth_x25519_secret, &header)
                                .ok()
                                .map(|out| {
                                    let master = out.master_secret.as_bytes();
                                    let preauth_secret = x25519_dalek::StaticSecret::from(
                                        id.preauth_x25519_secret.to_bytes());
                                    let preauth_pub = *id.preauth_x25519_pub.as_bytes();
                                    DoubleRatchetSession::init_receiver(
                                        master, preauth_secret, &preauth_pub)
                                })
                        })
                    };
                    if let Some(session) = session_result {
                        self.ratchet_sessions.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(sender_peer_id, session);
                    }
                }
            }
        }

        // Decrypt using ratchet message key.
        let header_val = match envelope.get("ratchet_header") {
            Some(v) => v.clone(),
            None => return false,
        };
        let ratchet_header: RatchetHeader = match serde_json::from_value(header_val) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let plaintext = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            let session = match sessions.get_mut(&sender_peer_id) {
                Some(s) => s,
                None => {
                    // No ratchet session — request re-inclusion from the sender (§8.7.6).
                    drop(sessions);
                    if let Some(ref gid) = outer_group_id_hex {
                        self.send_group_reinclusion_request(&sender_hex, gid);
                    }
                    return false;
                }
            };
            let msg_key = match session.recv_msg_key(&ratchet_header) {
                Ok(k) => k,
                Err(_) => {
                    // Ratchet out of sync — request re-inclusion from the sender.
                    drop(sessions);
                    if let Some(ref gid) = outer_group_id_hex {
                        self.send_group_reinclusion_request(&sender_hex, gid);
                    }
                    return false;
                }
            };
            use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
            let nonce = Nonce::<ChaCha20Poly1305>::default();
            match cipher.decrypt(&nonce, ct.as_ref()) {
                Ok(pt) => pt,
                Err(_) => {
                    if let Some(ref gid) = outer_group_id_hex {
                        self.send_group_reinclusion_request(&sender_hex, gid);
                    }
                    return false;
                }
            }
        };

        // Parse the inner message payload.
        let inner: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let room_id_hex = match inner.get("roomId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let text = match inner.get("text").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let msg_id = inner.get("msgId").and_then(|v| v.as_str())
            .unwrap_or("").to_string();
        let ts = inner.get("timestamp").and_then(|v| v.as_u64())
            .unwrap_or_else(|| std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0));

        let msg = serde_json::json!({
            "id":         msg_id,
            "roomId":     room_id_hex,
            "sender":     sender_hex,
            "text":       text,
            "timestamp":  ts,
            "isOutgoing": false,
            "authStatus": "authenticated",
        });

        self.messages.lock().unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.clone())
            .or_default()
            .push(msg.clone());

        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut()
                .find(|r| hex::encode(r.id) == room_id_hex)
            {
                room.last_message_preview = Some(if text.len() > 80 {
                    format!("{}…", &text[..80])
                } else {
                    text.clone()
                });
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0);
                room.last_message_at = Some(now);
                if !room.is_muted {
                    room.unread_count += 1;
                }
            }
        }

        self.push_event("MessageAdded", msg);

        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms.iter().find(|r| hex::encode(r.id) == room_id_hex)
                .map(|r| serde_json::json!({
                    "id":          hex::encode(r.id),
                    "name":        r.name,
                    "lastMessage": r.last_message_preview,
                    "unreadCount": r.unread_count,
                    "timestamp":   r.last_message_at,
                }))
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
    /// { "type": "group_message_sk", "groupId": "<hex>", "sender": "<hex>",
    ///   "epoch": <u32>, "nonce": "<hex-12>", "wrapped": "<hex>" }
    /// ```
    ///
    /// The `wrapped` bytes are `ChaCha20Poly1305(symmetric_key, nonce)` over a
    /// JSON blob `{"iteration":<u32>,"ciphertext":"<hex>","signature":"<hex>"}`.
    /// That inner layer is a `SenderKeyMessage` encrypted with the sender's
    /// per-group Sender Key and signed with their Sender Key Ed25519 key.
    fn process_group_message_sk_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let outer_group_id_hex = match envelope.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
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

        let nonce_bytes: [u8; 12] = match hex::decode(nonce_hex) {
            Ok(b) if b.len() == 12 => { let mut a = [0u8; 12]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let wrapped = match hex::decode(wrapped_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let gid_bytes: [u8; 32] = match hex::decode(&outer_group_id_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };

        // Step 1: Find the group and extract symmetric_key + peer_sender_keys.
        let (symmetric_key, peer_state_opt) = {
            let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            let g = match groups.iter().find(|g| g.group_id == gid_bytes) {
                Some(g) => g,
                None => return false,
            };
            let psk = g.peer_sender_keys.get(&sender_bytes).cloned();
            (g.symmetric_key, psk)
        };

        // Step 2: Unwrap the outer ChaCha20-Poly1305 layer (group symmetric key).
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        let sym_cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .expect("symmetric_key is always 32 bytes");
        let sk_wire_bytes = match sym_cipher.decrypt(
            chacha20poly1305::Nonce::from_slice(&nonce_bytes),
            wrapped.as_ref(),
        ) {
            Ok(b) => b,
            Err(_) => {
                // Group symmetric key mismatch — request re-inclusion.
                self.send_group_reinclusion_request(&sender_hex, &outer_group_id_hex);
                return false;
            }
        };

        // Step 3: Parse the inner SenderKeyMessage wire blob.
        let sk_wire: serde_json::Value = match serde_json::from_slice(&sk_wire_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let iteration = match sk_wire.get("iteration").and_then(|v| v.as_u64()) {
            Some(n) => n as u32,
            None => return false,
        };
        let inner_ct = match sk_wire.get("ciphertext").and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok()) {
            Some(b) => b,
            None => return false,
        };
        let sig_bytes = match sk_wire.get("signature").and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok()) {
            Some(b) => b,
            None => return false,
        };

        use crate::crypto::sender_keys::{SenderKeyMessage, SenderKeyReceiver};
        use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;

        // Step 4: Reconstruct SenderKeyReceiver from persisted state (if any).
        let peer_state = match peer_state_opt {
            Some(s) => s,
            None => {
                // No Sender Key for this peer — request re-inclusion.
                self.send_group_reinclusion_request(&sender_hex, &outer_group_id_hex);
                return false;
            }
        };

        let verifying_key = match Ed25519VerifyingKey::from_bytes(&peer_state.verifying_key) {
            Ok(vk) => vk,
            Err(_) => return false,
        };

        let mut receiver = SenderKeyReceiver::from_state(
            peer_state.chain_key,
            peer_state.next_iteration,
            verifying_key,
        );

        let sk_msg = SenderKeyMessage {
            iteration,
            ciphertext: inner_ct,
            signature:  sig_bytes,
        };

        // Step 5: Decrypt using Sender Key (verifies signature + decrypts).
        let plaintext_bytes = match receiver.decrypt(&sk_msg) {
            Ok(pt) => pt,
            Err(_) => {
                self.send_group_reinclusion_request(&sender_hex, &outer_group_id_hex);
                return false;
            }
        };

        // Step 6: Persist the advanced receiver state back to the group.
        {
            let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(g) = groups.iter_mut().find(|g| g.group_id == gid_bytes) {
                use crate::groups::group::PeerSenderKeyState;
                g.peer_sender_keys.insert(sender_bytes, PeerSenderKeyState {
                    chain_key:      *receiver.chain_key_bytes(),
                    next_iteration: receiver.next_iter(),
                    verifying_key:  peer_state.verifying_key,
                });
            }
        }

        // Step 7: Parse the inner plaintext message JSON.
        let inner: serde_json::Value = match serde_json::from_slice(&plaintext_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let room_id_hex = match inner.get("roomId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let text = match inner.get("text").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let msg_id = inner.get("msgId").and_then(|v| v.as_str())
            .unwrap_or("").to_string();
        let ts = inner.get("timestamp").and_then(|v| v.as_u64())
            .unwrap_or_else(|| std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0));

        let msg = serde_json::json!({
            "id":         msg_id,
            "roomId":     room_id_hex,
            "sender":     sender_hex,
            "text":       text,
            "timestamp":  ts,
            "isOutgoing": false,
            "authStatus": "authenticated",
        });

        self.messages.lock().unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.clone())
            .or_default()
            .push(msg.clone());

        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut()
                .find(|r| hex::encode(r.id) == room_id_hex)
            {
                room.last_message_preview = Some(if text.len() > 80 {
                    format!("{}…", &text[..80])
                } else {
                    text.clone()
                });
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0);
                room.last_message_at = Some(now);
                if !room.is_muted {
                    room.unread_count += 1;
                }
            }
        }

        self.push_event("MessageAdded", msg);

        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms.iter().find(|r| hex::encode(r.id) == room_id_hex)
                .map(|r| serde_json::json!({
                    "id":          hex::encode(r.id),
                    "name":        r.name,
                    "lastMessage": r.last_message_preview,
                    "unreadCount": r.unread_count,
                    "timestamp":   r.last_message_at,
                }))
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }

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
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let requester_bytes: [u8; 32] = match hex::decode(&requester_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let requester_peer_id = crate::identity::peer_id::PeerId(requester_bytes);

        let our_peer_id = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() { Some(id) => id.peer_id(), None => return false }
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
            if !group.admins.contains(&our_peer_id) { return false; }
            // Requester must already be a member.
            if !group.members.contains(&requester_peer_id) { return false; }

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
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
        let frame_opt = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = sessions.get_mut(&requester_peer_id) {
                if let Ok((header, msg_key)) = session.next_send_msg_key() {
                    let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
                    let nonce = Nonce::<ChaCha20Poly1305>::default();
                    cipher.encrypt(&nonce, invite_payload_bytes.as_ref()).ok().map(|ct| {
                        let x3dh_fields = self.x3dh_pending.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&requester_peer_id).copied();
                        let mut f = serde_json::json!({
                            "type":           "group_invite",
                            "sender":         hex::encode(our_peer_id.0),
                            "ratchet_header": serde_json::to_value(&header)
                                .unwrap_or(serde_json::Value::Null),
                            "ciphertext":     hex::encode(&ct),
                        });
                        if let Some((eph, ik)) = x3dh_fields {
                            if let Some(obj) = f.as_object_mut() {
                                obj.insert("x3dh_eph_pub".into(),
                                    serde_json::Value::String(hex::encode(eph)));
                                obj.insert("x3dh_encrypted_ik".into(),
                                    serde_json::Value::String(hex::encode(ik)));
                            }
                        }
                        f
                    })
                } else { None }
            } else { None }
        };

        if let Some(frame) = frame_opt {
            self.send_raw_frame(&requester_hex, &frame);
            self.save_ratchet_sessions();
        }
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
            .map(|g| (PeerId::from_ed25519_pub(&g.ed25519_public), hex::encode(g.group_id)))
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
    pub fn create_room(
        &mut self,
        name: &str,
        peer_id_hex: Option<&str>,
    ) -> Result<String, String> {
        use crate::identity::peer_id::PeerId;

        let room = if let Some(pid_hex) = peer_id_hex {
            // DM room — look up the contact.
            let peer_bytes: [u8; 32] = hex::decode(pid_hex)
                .ok()
                .filter(|b| b.len() == 32)
                .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a })
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
            let room_name = if name.is_empty() { "New Chat".to_string() } else { name.to_string() };
            crate::messaging::room::Room::new_group(&room_name, vec![])
        };

        let id_hex = hex::encode(room.id);
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).push(room.clone());
        self.save_rooms();

        self.push_event("RoomCreated", serde_json::json!({
            "id":   id_hex,
            "name": room.name,
        }));

        Ok(id_hex)
    }

    /// Delete a room and its messages.
    ///
    /// Returns `true` if the room was found and removed.
    pub fn delete_room(&self, room_id_hex: &str) -> bool {
        let before = self.rooms.lock().unwrap_or_else(|e| e.into_inner()).len();
        self.rooms.lock().unwrap_or_else(|e| e.into_inner())
            .retain(|r| hex::encode(r.id) != room_id_hex);
        self.messages.lock().unwrap_or_else(|e| e.into_inner())
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
        let active = self.active_conversation.lock().unwrap_or_else(|e| e.into_inner());
        match *active {
            Some(id) => format!("\"{}\"", hex::encode(id)),
            None => "null".into(),
        }
    }

    /// Return the current file transfers as a JSON array string.
    pub fn get_file_transfers(&self) -> String {
        let transfers = self.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
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
        if emoji.is_empty() { return false; }

        self.push_event("ReactionAdded", serde_json::json!({
            "roomId": room_id_hex,
            "msgId":  msg_id,
            "emoji":  emoji,
        }));

        let (recipients, our_hex) = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            let room_id_bytes = match hex::decode(room_id_hex) {
                Ok(b) if b.len() == 16 => { let mut a = [0u8; 16]; a.copy_from_slice(&b); a }
                _ => return true, // event emitted; wire-send best-effort
            };
            let room = match rooms.iter().find(|r| r.id == room_id_bytes) {
                Some(r) => r,
                None => return true,
            };
            let our = self.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default();
            let peers: Vec<String> = room.participants.iter()
                .map(|p| hex::encode(p.0)).filter(|h| *h != our).collect();
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
        self.push_event("ReadReceipt", serde_json::json!({"roomId": room_id_hex, "msgId": msg_id}));
        self.save_rooms();
    }

    /// Emit a typing indicator event and broadcast to room participants.
    pub fn send_typing_indicator(&self, room_id_hex: &str, active: bool) {
        self.push_event("TypingIndicator", serde_json::json!({
            "roomId": room_id_hex,
            "active": active,
        }));

        let (recipients, our_hex) = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            let room_id_bytes = match hex::decode(room_id_hex) {
                Ok(b) if b.len() == 16 => { let mut a = [0u8; 16]; a.copy_from_slice(&b); a }
                _ => return,
            };
            let room = match rooms.iter().find(|r| r.id == room_id_bytes) {
                Some(r) => r,
                None => return,
            };
            let our = self.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| hex::encode(id.peer_id().0)).unwrap_or_default();
            let peers: Vec<String> = room.participants.iter()
                .map(|p| hex::encode(p.0)).filter(|h| *h != our).collect();
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
    pub fn reply_to_message(
        &mut self,
        room_id_hex: &str,
        reply_to_id: &str,
        text: &str,
    ) -> bool {
        use crate::service::runtime::try_random_fill;
        if text.is_empty() { return false; }

        let mut msg_id_bytes = [0u8; 16];
        if !try_random_fill(&mut msg_id_bytes) { return false; }
        let msg_id = hex::encode(msg_id_bytes);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let sender = self.identity.lock().unwrap_or_else(|e| e.into_inner())
            .as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_else(|| "local".into());

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

        self.messages.lock().unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.to_string()).or_default().push(msg.clone());
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
        if new_text.is_empty() { return false; }
        let edited_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

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
                if found { break; }
            }
        }

        if found {
            self.push_event("MessageEdited", serde_json::json!({
                "msgId":    msg_id,
                "newText":  new_text,
                "editedAt": edited_at,
            }));
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
                if found_room.is_some() { break; }
            }
        }

        if let Some(ref room_id) = found_room {
            self.push_event("MessageDeleted", serde_json::json!({"msgId": msg_id, "roomId": room_id}));
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
            all_msgs.values().flat_map(|msgs| msgs.iter()).find(|msg| {
                msg.get("id").and_then(|v| v.as_str()) == Some(msg_id)
            }).and_then(|msg| msg.get("text").and_then(|v| v.as_str()).map(|s| s.to_string()))
        };

        let text = match original_text { Some(t) if !t.is_empty() => t, _ => return false };

        let mut new_id_bytes = [0u8; 16];
        if !try_random_fill(&mut new_id_bytes) { return false; }
        let new_id = hex::encode(new_id_bytes);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let sender = self.identity.lock().unwrap_or_else(|e| e.into_inner())
            .as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_else(|| "local".into());

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

        self.messages.lock().unwrap_or_else(|e| e.into_inner())
            .entry(target_room_hex.to_string()).or_default().push(fwd.clone());
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
                if found { break; }
            }
        }

        if found {
            let event = if pinned { "MessagePinned" } else { "MessageUnpinned" };
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
            self.push_event("DisappearingTimerChanged", serde_json::json!({
                "roomId": room_id_hex,
                "secs":   secs,
            }));
            self.save_rooms();
        }
        found
    }

    /// Full-text search across all in-memory messages (case-insensitive).
    ///
    /// Returns a JSON array of matching message objects.
    pub fn search_messages(&self, query: &str) -> String {
        if query.is_empty() { return "[]".into(); }
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
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

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
                .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a })
                .ok_or_else(|| format!("invalid peer_id_hex: {hex_str}"))?;
            members.push(PeerId(bytes));
        }

        let group_name = if name.is_empty() { "New Group" } else { name };
        let room = crate::messaging::room::Room::new_group(group_name, members);
        let id_hex = hex::encode(room.id);

        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).push(room.clone());
        self.save_rooms();

        self.push_event("GroupCreated", serde_json::json!({
            "id":   id_hex,
            "name": room.name,
        }));

        Ok(id_hex)
    }

    /// Return a JSON array of all group rooms (conversation_type == Group).
    pub fn list_groups(&self) -> String {
        use crate::messaging::message::ConversationType;
        let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let groups: Vec<serde_json::Value> = rooms
            .iter()
            .filter(|r| r.conversation_type == ConversationType::Group)
            .map(|r| serde_json::json!({
                "id":           hex::encode(r.id),
                "name":         r.name,
                "memberCount":  r.participants.len(),
                "unreadCount":  r.unread_count,
                "lastMessage":  r.last_message_preview,
                "timestamp":    r.last_message_at,
            }))
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
            .find(|r| hex::encode(r.id) == group_id_hex
                && r.conversation_type == ConversationType::Group)
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
        // Groups are ordinary rooms — delegate to send_text_message.
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
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a })
        {
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
            self.push_event("GroupMemberAdded", serde_json::json!({
                "groupId": group_id_hex,
                "peerId":  peer_id_hex,
            }));
            true
        } else {
            false
        }
    }
}
