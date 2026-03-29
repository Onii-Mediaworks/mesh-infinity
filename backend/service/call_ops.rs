//! Voice/video call operations and WireGuard per-hop handshake handlers for
//! `MeshRuntime` (§5.2).
//!
//! ## Call lifecycle
//! 1. Caller: `call_offer` → serialises a `CallSignal::Offer` and sends a
//!    `call_offer` frame to the remote peer.
//! 2. Callee: `process_call_offer_frame` — emits `CallIncoming` to Flutter.
//! 3. Callee: `call_answer` → serialises a `CallSignal::Answer` and sends it.
//! 4. Caller: `process_call_answer_frame` — emits `CallAnswered` or
//!    `CallHungUp`.
//! 5. Either: `call_hangup` → `send_call_hangup` → remote receives
//!    `process_call_hangup_frame` → emits `CallHungUp`.
//!
//! ## WireGuard handshakes (§5.2)
//! The initiator calls `wg_initiate_handshake` to generate an ephemeral key
//! pair and produce a `HandshakeInit` message.  The responder's reply is
//! handled by `process_wg_response_frame`, completing the session.
//!
//! The responder side is handled by `process_wg_init_frame` (called by the
//! inbound frame dispatcher in `messaging.rs`) and also exposed directly as
//! `wg_respond_to_handshake` for synchronous API callers.
//!
//! ## Error policy
//! All methods return `Err(String)` for user-visible failures.  Internal
//! logic errors (missing state, decode failures) return `false` from the
//! frame handlers without panicking.

use crate::identity::peer_id::PeerId;
use crate::service::runtime::MeshRuntime;

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Outbound call control (Flutter-facing)
    // -----------------------------------------------------------------------

    /// Initiate an outgoing call to a peer (§12).
    ///
    /// Builds a `CallSignal::Offer` with the given codec lists, serialises it,
    /// and sends a `call_offer` frame via the standard TCP transport.  Also
    /// records the call state in `active_call` so subsequent hangup / answer
    /// handlers can reference it.
    ///
    /// # Parameters
    /// - `peer_id_hex`: 64-hex destination peer.
    /// - `is_video`:     whether to include video codecs in the offer.
    /// - `session_desc`: SDP-compatible session description (may be empty).
    ///
    /// Returns `Ok(call_id_hex)` on success, `Err(String)` on failure.
    pub fn call_offer(
        &self,
        peer_id_hex: &str,
        is_video: bool,
        session_desc: &str,
    ) -> Result<String, String> {
        // Require identity for the sender field.
        let our_hex = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .as_ref()
                .map(|id| id.peer_id().to_hex())
                .ok_or("identity not unlocked")?
        };

        // Reject if another call is already active to prevent duplicate state.
        if self
            .active_call
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err("a call is already active".into());
        }

        // Generate a random 32-byte call ID.
        let mut call_id_bytes = [0u8; 32];
        crate::service::runtime::try_random_fill(&mut call_id_bytes);
        let call_id_hex = hex::encode(call_id_bytes);

        // Parse the destination peer ID.
        let peer_bytes = hex::decode(peer_id_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or("invalid peer_id_hex")?;
        let mut peer_arr = [0u8; 32];
        peer_arr.copy_from_slice(&peer_bytes);
        let callee_peer_id = PeerId(peer_arr);

        // Build codec lists (minimal — the real SDP negotiation is UI-side).
        let audio_codecs = vec![crate::calls::AudioCodec::Opus];
        let video_codecs: Vec<crate::calls::VideoCodec> = if is_video {
            vec![crate::calls::VideoCodec::VP8]
        } else {
            Vec::new()
        };

        let signal = crate::calls::CallSignal::Offer {
            call_id: call_id_bytes,
            audio_codecs,
            video_codecs,
            session_desc: session_desc.to_string(),
            losec_requested: false,
        };

        let payload = serde_json::to_string(&signal).map_err(|e| e.to_string())?;

        // Record in active_call before sending so a fast response can match it.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let call_state =
            crate::calls::CallState::new_outgoing(call_id_bytes, is_video, callee_peer_id, now);
        *self.active_call.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((call_state, peer_id_hex.to_string()));

        // Send the call_offer frame over the clearnet/WG transport.
        self.send_raw_frame(
            peer_id_hex,
            &serde_json::json!({
                "type":    "call_offer",
                "sender":  our_hex,
                "payload": payload,
            }),
        );

        Ok(call_id_hex)
    }

    /// Answer an incoming call (§12).
    ///
    /// Sends a `call_answer` frame back to the caller with our selected codec.
    /// Requires that `active_call` is set (by a prior `process_call_offer_frame`
    /// call).
    ///
    /// Returns `Ok(())` on success, `Err(String)` if there is no active call.
    pub fn call_answer(&self, session_desc: &str) -> Result<(), String> {
        // Snapshot the caller peer ID and call_id before sending.
        let (caller_hex, call_id_bytes) = {
            let guard = self.active_call.lock().unwrap_or_else(|e| e.into_inner());
            let (state, caller_hex) = guard.as_ref().ok_or("no active call")?;
            (caller_hex.clone(), state.call_id)
        };

        let signal = crate::calls::CallSignal::Answer {
            call_id: call_id_bytes,
            audio_codec: crate::calls::AudioCodec::Opus,
            video_codec: None,
            session_desc: session_desc.to_string(),
            losec_accepted: false,
        };
        let payload = serde_json::to_string(&signal).map_err(|e| e.to_string())?;

        self.send_raw_frame(
            &caller_hex,
            &serde_json::json!({
                "type":    "call_answer",
                "payload": payload,
            }),
        );
        Ok(())
    }

    /// Hang up the current active call (§12).
    ///
    /// Sends a `Hangup` signal to the remote peer, clears `active_call`, and
    /// emits `CallHungUp` to notify Flutter.  A no-op if there is no active
    /// call (returns `Ok(())`).
    pub fn call_hangup(&self) -> Result<(), String> {
        // Extract and clear active call in one lock acquisition.
        let (peer_hex, call_id_bytes) = {
            let mut guard = self.active_call.lock().unwrap_or_else(|e| e.into_inner());
            match guard.take() {
                Some((state, hex)) => (hex, state.call_id),
                None => return Ok(()), // already idle
            }
        };

        let call_id_hex = hex::encode(call_id_bytes);
        self.send_call_hangup(&peer_hex, &call_id_hex);
        self.push_event(
            "CallHungUp",
            serde_json::json!({
                "callId": call_id_hex,
                "reason": "UserHangup",
            }),
        );
        Ok(())
    }

    /// Get the current call status as a JSON string.
    ///
    /// Returns `{"active": true, "callId": "...", "peerId": "...", "isVideo": bool}`
    /// or `{"active": false}` if there is no active call.
    pub fn call_status(&self) -> String {
        let guard = self.active_call.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some((state, peer_hex)) => serde_json::json!({
                "active":  true,
                "callId":  hex::encode(state.call_id),
                "peerId":  peer_hex,
                "isVideo": state.is_video,
            })
            .to_string(),
            None => r#"{"active":false}"#.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Internal: send a call hangup signal to a peer
    // -----------------------------------------------------------------------

    /// Send a `call_hangup` signal frame to `peer_id_hex`.
    ///
    /// Called by `call_hangup` and by `process_call_offer_frame` when we are
    /// busy (already have an active call and must auto-decline).
    ///
    /// Non-blocking: if there is no TCP connection to the peer the frame is
    /// silently dropped.
    pub fn send_call_hangup(&self, peer_id_hex: &str, call_id_hex: &str) {
        let call_id_bytes = match hex::decode(call_id_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return, // malformed call_id — nothing to send
        };

        let signal = crate::calls::CallSignal::Hangup {
            call_id:   call_id_bytes,
            reason:    crate::calls::HangupReason::Declined,
        };
        let payload = match serde_json::to_string(&signal) {
            Ok(s) => s,
            Err(_) => return,
        };

        self.send_raw_frame(
            peer_id_hex,
            &serde_json::json!({
                "type":    "call_hangup",
                "payload": payload,
            }),
        );
    }

    // -----------------------------------------------------------------------
    // Inbound call frame handlers
    // -----------------------------------------------------------------------

    /// Handle an inbound `call_offer` frame.
    ///
    /// Validates the frame, rejects with a hangup if another call is already
    /// active, otherwise stores the call state and emits `CallIncoming` for
    /// the Flutter UI to ring.
    ///
    /// Returns `true` on success (even auto-declined), `false` if the frame
    /// is malformed.
    pub fn process_call_offer_frame(&self, envelope: &serde_json::Value) -> bool {
        // Extract sender field.
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };

        // Deserialise the CallSignal from the "payload" string field.
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signal: crate::calls::CallSignal = match serde_json::from_str(payload_str) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Extract call_id, video flag, and SDP description from the Offer variant.
        let (call_id, is_video, session_desc) = match &signal {
            crate::calls::CallSignal::Offer {
                call_id,
                video_codecs,
                session_desc,
                ..
            } => (*call_id, !video_codecs.is_empty(), session_desc.clone()),
            _ => return false, // unexpected variant in a call_offer frame
        };
        let call_id_hex = hex::encode(call_id);

        // Auto-decline if we are already on a call — preserve the current state.
        if self
            .active_call
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            self.send_call_hangup(&sender_hex, &call_id_hex);
            return true; // consumed — busy signal sent
        }

        // Parse the sender's peer ID bytes.
        let sender_id_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        // Timestamp for call state creation.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Store incoming call state (CallState::new_outgoing is reused here
        // because the caller is the *other* side; "outgoing" means the call
        // was initiated by the remote peer toward us).
        let call_state = crate::calls::CallState::new_outgoing(
            call_id,
            is_video,
            PeerId(sender_id_bytes),
            now,
        );
        *self.active_call.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((call_state, sender_hex.clone()));

        // Notify Flutter so the incoming call UI is shown.
        self.push_event(
            "CallIncoming",
            serde_json::json!({
                "callId":      call_id_hex,
                "peerId":      sender_hex,
                "isVideo":     is_video,
                "sessionDesc": session_desc,
            }),
        );
        true
    }

    /// Handle an inbound `call_answer` frame.
    ///
    /// Emits either `CallAnswered` (on a proper Answer signal) or `CallHungUp`
    /// (if the remote side immediately declined).
    ///
    /// Returns `true` on success, `false` if the payload is malformed.
    pub fn process_call_answer_frame(&self, envelope: &serde_json::Value) -> bool {
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signal: crate::calls::CallSignal = match serde_json::from_str(payload_str) {
            Ok(s) => s,
            Err(_) => return false,
        };

        match signal {
            crate::calls::CallSignal::Answer {
                call_id,
                audio_codec,
                video_codec,
                session_desc,
                ..
            } => {
                // Remote accepted — notify Flutter with negotiated codecs.
                self.push_event(
                    "CallAnswered",
                    serde_json::json!({
                        "callId":      hex::encode(call_id),
                        "audioCodec":  format!("{audio_codec:?}"),
                        "videoCodec":  video_codec.map(|c| format!("{c:?}")),
                        "sessionDesc": session_desc,
                    }),
                );
                true
            }
            crate::calls::CallSignal::Hangup { call_id, reason } => {
                // Remote declined immediately.
                *self.active_call.lock().unwrap_or_else(|e| e.into_inner()) = None;
                self.push_event(
                    "CallHungUp",
                    serde_json::json!({
                        "callId": hex::encode(call_id),
                        "reason": format!("{reason:?}"),
                    }),
                );
                true
            }
            _ => false, // unexpected signal type in a call_answer frame
        }
    }

    /// Handle an inbound `call_hangup` frame.
    ///
    /// Clears `active_call` and emits `CallHungUp`.  Returns `true` if the
    /// frame contained a valid `Hangup` signal, `false` otherwise.
    pub fn process_call_hangup_frame(&self, envelope: &serde_json::Value) -> bool {
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signal: crate::calls::CallSignal = match serde_json::from_str(payload_str) {
            Ok(s) => s,
            Err(_) => return false,
        };

        if let crate::calls::CallSignal::Hangup { call_id, reason } = signal {
            // Clear our end of the call before emitting the event.
            *self.active_call.lock().unwrap_or_else(|e| e.into_inner()) = None;
            self.push_event(
                "CallHungUp",
                serde_json::json!({
                    "callId": hex::encode(call_id),
                    "reason": format!("{reason:?}"),
                }),
            );
            return true;
        }
        false
    }

    // -----------------------------------------------------------------------
    // WireGuard per-hop handshake (§5.2) — inbound frame handlers
    // -----------------------------------------------------------------------

    /// Handle an inbound WireGuard handshake init frame (§5.2).
    ///
    /// Deserialises the `HandshakeInit`, responds with a `HandshakeResponse`,
    /// and stores the established `WireGuardSession` so subsequent frames from
    /// this peer are encrypted with WG keys.
    ///
    /// Returns `true` on success, `false` if the frame is malformed or the
    /// required keys cannot be retrieved.
    pub fn process_wg_init_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::crypto::channel_key::derive_channel_key;
        use crate::transport::wireguard::{HandshakeInit, respond_to_handshake};

        // Sender peer ID (64 hex chars = 32 bytes).
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) if s.len() == 64 => s.to_string(),
            _ => return false,
        };

        // Raw init message: 80 bytes (32 eph_pub + 48 enc_static).
        let init_hex = match envelope.get("init_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let init_bytes = match hex::decode(init_hex) {
            Ok(b) if b.len() == 80 => b,
            _ => return false,
        };

        // Decode the initiator's peer ID.
        let initiator_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let initiator_id = PeerId(initiator_bytes);

        // Retrieve our X25519 static secret and the initiator's X25519 pub.
        let (our_secret_bytes, our_peer_id, their_x25519) = {
            let id_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            match (id_guard.as_ref(), contacts.get(&initiator_id)) {
                (Some(id), Some(contact)) => (
                    id.x25519_secret.to_bytes(),
                    id.peer_id(),
                    x25519_dalek::PublicKey::from(contact.x25519_public),
                ),
                _ => return false, // identity not unlocked or peer unknown
            }
        };

        // Derive per-channel PSK from the DH shared secret (§5.2).
        let our_secret = x25519_dalek::StaticSecret::from(our_secret_bytes);
        let psk = match derive_channel_key(&our_secret, &their_x25519, &our_peer_id, &initiator_id)
        {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Reconstruct the HandshakeInit message from wire bytes.
        let init_msg = HandshakeInit {
            eph_i_pub: {
                let mut a = [0u8; 32];
                a.copy_from_slice(&init_bytes[..32]);
                a
            },
            enc_static: {
                let mut a = [0u8; 48];
                a.copy_from_slice(&init_bytes[32..]);
                a
            },
        };

        // Run the responder-side handshake to derive session keys.
        let (session, response) = match respond_to_handshake(
            &init_msg,
            &our_secret,
            &psk,
            our_peer_id,
            initiator_id,
        ) {
            Ok(r) => r,
            Err(_) => return false,
        };

        // Store the established session keyed by the initiator's peer ID.
        self.wireguard_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(initiator_id, session);

        // Send the handshake response back so the initiator can complete.
        let our_hex = our_peer_id.to_hex();
        let response_frame = serde_json::json!({
            "type":         "wg_response",
            "sender":       our_hex,
            "response_hex": hex::encode(response.eph_r_pub),
        });
        self.send_raw_frame(&sender_hex, &response_frame);
        true
    }

    /// Handle an inbound WireGuard handshake response frame (§5.2).
    ///
    /// Completes the initiator-side pending handshake and stores the session.
    /// Returns `true` on success, `false` if the frame is malformed or there
    /// is no matching pending handshake.
    pub fn process_wg_response_frame(&self, envelope: &serde_json::Value) -> bool {
        // Sender peer ID (responder).
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) if s.len() == 64 => s.to_string(),
            _ => return false,
        };

        // 32-byte ephemeral public key from the responder.
        let response_hex = match envelope.get("response_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let eph_r_pub: [u8; 32] = match hex::decode(response_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        // Decode the responder peer ID.
        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let responder_id = PeerId(sender_bytes);

        // Retrieve our peer ID from the identity.
        let our_peer_id = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => id.peer_id(),
                None => return false,
            }
        };

        // Consume the pending initiator handshake — if absent the response is
        // spurious (possibly a replay) and we discard it.
        let pending = {
            let mut map = self
                .pending_wg_handshakes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match map.remove(&responder_id) {
                Some(p) => p,
                None => return false,
            }
        };

        // Complete the handshake and derive the bidirectional session keys.
        let response = crate::transport::wireguard::HandshakeResponse { eph_r_pub };
        let session = match pending.complete(&response, our_peer_id, responder_id) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Store the established WireGuard session.
        self.wireguard_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(responder_id, session);
        true
    }

    // -----------------------------------------------------------------------
    // WireGuard handshake initiation (synchronous API)
    // -----------------------------------------------------------------------

    /// Initiate a WireGuard handshake with a peer (§5.2).
    ///
    /// Generates an ephemeral X25519 key pair, encrypts our static identity
    /// under DH(eph_i, static_r), and stores the pending state so that
    /// `process_wg_response_frame` can complete the session.
    ///
    /// Returns `Ok(init_hex)` where `init_hex` is 80 hex bytes
    /// (32-byte eph_pub + 48-byte enc_static), or `Err(String)` on failure.
    pub fn wg_initiate_handshake(&self, peer_id_hex: &str) -> Result<String, String> {
        use crate::crypto::channel_key::derive_channel_key;
        use crate::transport::wireguard::PendingInitiatorHandshake;

        // Parse the destination peer ID.
        let peer_bytes: [u8; 32] = hex::decode(peer_id_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .ok_or("invalid peer_id_hex")?;
        let target_peer_id = PeerId(peer_bytes);

        // Retrieve our X25519 static key and the peer's X25519 public key.
        let (our_secret_bytes, our_pub_id, their_x25519_pub) = {
            let id_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = id_guard.as_ref().ok_or("identity not unlocked")?;
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            let contact = contacts
                .get(&target_peer_id)
                .ok_or("peer not in contacts")?
                .clone();
            let their_pub = x25519_dalek::PublicKey::from(contact.x25519_public);
            let our_secret_bytes = id.x25519_secret.to_bytes();
            (our_secret_bytes, id.peer_id(), their_pub)
        };

        // Derive per-channel PSK.
        let our_secret = x25519_dalek::StaticSecret::from(our_secret_bytes);
        let psk =
            derive_channel_key(&our_secret, &their_x25519_pub, &our_pub_id, &target_peer_id)
                .map_err(|_| "PSK derivation failed")?;

        // Build the pending handshake and init message.
        let (pending, init_msg) = PendingInitiatorHandshake::new(
            x25519_dalek::StaticSecret::from(our_secret.to_bytes()),
            their_x25519_pub,
            psk,
        );

        // Serialise: eph_i_pub (32) + enc_static (48) = 80 bytes hex.
        let mut init_bytes = Vec::with_capacity(80);
        init_bytes.extend_from_slice(&init_msg.eph_i_pub);
        init_bytes.extend_from_slice(&init_msg.enc_static);
        let init_hex = hex::encode(&init_bytes);

        // Store the pending state so the response handler can finish the session.
        self.pending_wg_handshakes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(target_peer_id, pending);

        Ok(init_hex)
    }

    /// Respond to a WireGuard handshake init (synchronous API variant).
    ///
    /// Identical to `process_wg_init_frame` but takes raw arguments instead
    /// of a JSON envelope; used by `mi_wg_respond_to_handshake` in the thin
    /// FFI shim.
    ///
    /// Returns `Ok(response_hex)` (32 bytes hex) on success, `Err(String)`
    /// on failure.
    pub fn wg_respond_to_handshake(
        &self,
        peer_id_hex: &str,
        init_hex: &str,
    ) -> Result<String, String> {
        use crate::crypto::channel_key::derive_channel_key;
        use crate::transport::wireguard::{HandshakeInit, respond_to_handshake};

        // Parse the initiator's peer ID.
        let peer_bytes: [u8; 32] = hex::decode(peer_id_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .ok_or("invalid peer_id_hex")?;
        let initiator_peer_id = PeerId(peer_bytes);

        // Decode the 80-byte init message.
        let init_bytes: Vec<u8> = hex::decode(init_hex)
            .ok()
            .filter(|b| b.len() == 80)
            .ok_or("invalid init_hex (expected 80 bytes)")?;
        let mut eph_i_pub = [0u8; 32];
        let mut enc_static = [0u8; 48];
        eph_i_pub.copy_from_slice(&init_bytes[..32]);
        enc_static.copy_from_slice(&init_bytes[32..]);
        let init_msg = HandshakeInit {
            eph_i_pub,
            enc_static,
        };

        // Retrieve our X25519 secret and the initiator's X25519 pub.
        let (our_secret_bytes, our_peer_id, their_x25519_pub) = {
            let id_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = id_guard.as_ref().ok_or("identity not unlocked")?;
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            let contact = contacts
                .get(&initiator_peer_id)
                .ok_or("peer not in contacts")?
                .clone();
            let their_pub = x25519_dalek::PublicKey::from(contact.x25519_public);
            (id.x25519_secret.to_bytes(), id.peer_id(), their_pub)
        };

        let our_secret = x25519_dalek::StaticSecret::from(our_secret_bytes);
        let psk =
            derive_channel_key(&our_secret, &their_x25519_pub, &our_peer_id, &initiator_peer_id)
                .map_err(|_| "PSK derivation failed")?;

        let (session, response) = respond_to_handshake(
            &init_msg,
            &our_secret,
            &psk,
            our_peer_id,
            initiator_peer_id,
        )
        .map_err(|e| e.to_string())?;

        // Store the established session.
        self.wireguard_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(initiator_peer_id, session);

        Ok(hex::encode(response.eph_r_pub))
    }

    /// Complete an initiator-side WireGuard handshake after receiving the
    /// responder's reply (synchronous API variant).
    ///
    /// Consumes the pending handshake state created by `wg_initiate_handshake`
    /// and establishes the bidirectional WireGuard session.
    ///
    /// Returns `Ok(())` on success, `Err(String)` if there is no pending
    /// handshake or the response bytes are invalid.
    pub fn wg_complete_handshake(
        &self,
        peer_id_hex: &str,
        response_hex: &str,
    ) -> Result<(), String> {
        use crate::transport::wireguard::HandshakeResponse;

        // Parse responder peer ID.
        let peer_bytes: [u8; 32] = hex::decode(peer_id_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .ok_or("invalid peer_id_hex")?;
        let responder_peer_id = PeerId(peer_bytes);

        // Parse the 32-byte response.
        let resp_bytes: [u8; 32] = hex::decode(response_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .ok_or("response_hex must be 32 bytes")?;
        let response = HandshakeResponse { eph_r_pub: resp_bytes };

        // Retrieve our peer ID.
        let our_peer_id = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .as_ref()
                .map(|id| id.peer_id())
                .ok_or("identity not unlocked")?
        };

        // Consume the pending handshake state.
        let pending = {
            let mut map = self
                .pending_wg_handshakes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.remove(&responder_peer_id)
                .ok_or("no pending handshake for this peer")?
        };

        // Complete the handshake and derive bidirectional session keys.
        let session = pending
            .complete(&response, our_peer_id, responder_peer_id)
            .map_err(|e| e.to_string())?;

        // Store the established session.
        self.wireguard_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(responder_peer_id, session);

        Ok(())
    }
}
