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

        // Only one call at a time is supported.  Reject if another call is
        // active to prevent duplicate WebRTC sessions and confused UI state.
        // The caller should check call_status() before offering.
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

        // Record in active_call BEFORE sending the offer frame so a fast
        // response (answer or hangup arriving within the same tick) can find
        // the matching call state.  If we sent first and recorded second, a
        // race condition could cause the response handler to drop the reply.
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
            call_id: call_id_bytes,
            reason: crate::calls::HangupReason::Declined,
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
        let call_state =
            crate::calls::CallState::new_outgoing(call_id, is_video, PeerId(sender_id_bytes), now);
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
        // Sender peer ID (64 hex chars = 32 bytes).
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) if s.len() == 64 => s.to_string(),
            _ => return false,
        };
        let init_hex = match envelope.get("init_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        // The synchronous path does all parsing and verification.
        let response_hex = match self.wg_respond_to_handshake(&sender_hex, init_hex) {
            Ok(hex) => hex,
            Err(_) => return false,
        };
        let our_hex = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => id.peer_id().to_hex(),
                None => return false,
            }
        };

        // Send the handshake response back so the initiator can complete.
        let response_frame = serde_json::json!({
            "type":         "wg_response",
            "sender":       our_hex,
            "response_hex": response_hex,
        });
        self.send_raw_frame(&sender_hex, &response_frame);
        true
    }

    /// Current handshake timestamp: nanoseconds since the Unix epoch.
    ///
    /// The responder requires every Init from a given initiator to carry a
    /// strictly increasing timestamp (§5.2 replay rule), so the resolution
    /// must exceed the fastest legitimate re-handshake cadence; nanoseconds
    /// match WireGuard's TAI64N granularity.
    fn wg_handshake_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    /// The endpoint policy every new link session gets (§5.2, "Endpoint
    /// pinning").  The per-connection mode (LoSec/Direct) is not tracked on
    /// the runtime yet, so the policy is derived from the threat context
    /// alone with the connection treated as Standard; Elevated and Critical
    /// pin, Normal roams with a forced re-handshake.
    fn wg_endpoint_policy(&self) -> crate::transport::wireguard::EndpointPolicy {
        crate::transport::wireguard::EndpointPolicy::for_context(
            self.threat_context,
            crate::routing::losec::ConnectionMode::Standard,
            crate::transport::wireguard::DEFAULT_KEEPALIVE_SECS,
        )
    }

    /// Unwrap an inbound frame from `peer_hex` through its link session.
    ///
    /// Once a session exists for the peer, only two kinds of frame are
    /// accepted: `{"wg_ct": hex}` envelopes, which are decrypted and parsed,
    /// and plaintext handshake frames (`wg_init` / `wg_response`), which
    /// are self-authenticating and needed for re-handshakes.  Any other
    /// plaintext frame from a peer with a session is dropped: a peer that
    /// completed a handshake must not be able to bypass it.  Without a
    /// session, a `wg_ct` envelope cannot be opened and is dropped, and
    /// plaintext passes through (the pre-handshake baseline).
    ///
    /// Returns the frame to dispatch, or `None` to drop it.
    pub fn unwrap_inbound_wg_frame(
        &self,
        peer_hex: &str,
        frame: serde_json::Value,
    ) -> Option<serde_json::Value> {
        let peer_id = hex::decode(peer_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(PeerId)?;
        let wg_ct = frame
            .get("wg_ct")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let sessions = self
            .wireguard_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match (sessions.get(&peer_id), wg_ct) {
            // Encrypted envelope with a live session: decrypt and parse.
            (Some(session), Some(ct_hex)) => {
                let ct = hex::decode(ct_hex).ok()?;
                let plain = session.decrypt(&ct).ok()?;
                serde_json::from_slice(&plain).ok()
            }
            // Encrypted envelope, no session: undecryptable, drop.
            (None, Some(_)) => None,
            // Plaintext with a live session: only handshake frames pass.
            (Some(_), None) => {
                let frame_type = frame.get("type").and_then(|v| v.as_str()).unwrap_or("");
                matches!(frame_type, "wg_init" | "wg_response").then_some(frame)
            }
            // Plaintext, no session: pre-handshake baseline.
            (None, None) => Some(frame),
        }
    }

    /// Handle an inbound WireGuard handshake response frame (§5.2).
    ///
    /// Completes the initiator-side pending handshake and stores the session.
    /// Returns `true` on success, `false` if the frame is malformed or there
    /// is no matching pending handshake.
    pub fn process_wg_response_frame(&self, envelope: &serde_json::Value) -> bool {
        // Sender peer ID (responder).
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) if s.len() == 64 => s,
            _ => return false,
        };
        let response_hex = match envelope.get("response_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        // The synchronous path verifies the responder's confirmation before
        // installing anything.
        self.wg_complete_handshake(sender_hex, response_hex).is_ok()
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
        use crate::transport::wireguard::{PendingInitiatorHandshake, TunnelPsk};

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
        let (our_secret_bytes, their_x25519_pub) = {
            let id_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = id_guard.as_ref().ok_or("identity not unlocked")?;
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            let contact = contacts
                .get(&target_peer_id)
                .ok_or("peer not in contacts")?
                .clone();
            let their_pub = x25519_dalek::PublicKey::from(contact.x25519_public);
            let our_secret_bytes = id.x25519_secret.to_bytes();
            (our_secret_bytes, their_pub)
        };

        // No-PSK tunnel (§5.2).  The per-epoch trusted-tunnel PSK comes from
        // the hybrid agreement in `transport::tunnel_keys`; until that
        // agreement runs over the link, the tunnel stays a no-PSK tunnel and
        // trusted-tier features are withheld.  The static `channel_key` is
        // never installed as a PSK.
        let psk = TunnelPsk::None;

        // Build the pending handshake and init message.
        let (pending, init_msg) = PendingInitiatorHandshake::new(
            x25519_dalek::StaticSecret::from(our_secret_bytes),
            their_x25519_pub,
            psk,
            Self::wg_handshake_timestamp(),
        )
        .map_err(|e| e.to_string())?;

        // Serialise the fixed wire layout (header + fields) as hex.
        let init_hex = hex::encode(init_msg.to_bytes());

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
        use crate::transport::wireguard::{
            respond_to_handshake, HandshakeInit, StaticKeySource, TunnelPsk,
        };

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

        // Decode and parse the init message; the parser enforces the fixed
        // length and the `MI-LINK-1` header, so a peer declaring another
        // suite or version is rejected here with a typed error.
        let init_bytes: Vec<u8> = hex::decode(init_hex).map_err(|_| "invalid init_hex")?;
        let init_msg = HandshakeInit::from_bytes(&init_bytes).map_err(|e| e.to_string())?;

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
        // No-PSK tunnel until the §5.2 hybrid PSK agreement has run; see
        // `wg_initiate_handshake`.
        let psk = TunnelPsk::None;

        // Respond: the initiator's static key is checked against the
        // contact's known key and its key confirmation is verified before
        // any session is derived; a replayed Init (timestamp not newer than
        // the last accepted) is rejected.
        let last_ts = self
            .wireguard_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_init_timestamp(&initiator_peer_id);
        let (mut session, response, timestamp) = respond_to_handshake(
            &init_msg,
            &our_secret,
            &their_x25519_pub,
            &psk,
            our_peer_id,
            initiator_peer_id,
            last_ts,
        )
        .map_err(|e| e.to_string())?;
        // The identity X25519 key served as the static key: a bootstrap
        // tunnel that must be re-keyed once a role-scoped binding exists.
        session.set_key_source(StaticKeySource::IdentityBootstrap);
        session.set_endpoint_policy(self.wg_endpoint_policy());

        // Store the confirmed session and the accepted timestamp.
        let mut sessions = self
            .wireguard_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sessions.record_init_timestamp(initiator_peer_id, timestamp);
        sessions.insert(initiator_peer_id, session);

        Ok(hex::encode(response.to_bytes()))
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
        use crate::transport::wireguard::{HandshakeResponse, StaticKeySource};

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

        // Decode and parse the response (fixed length, `MI-LINK-1` header).
        let resp_bytes: Vec<u8> = hex::decode(response_hex).map_err(|_| "invalid response_hex")?;
        let response = HandshakeResponse::from_bytes(&resp_bytes).map_err(|e| e.to_string())?;

        // Retrieve our peer ID.
        let our_peer_id = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .as_ref()
                .map(|id| id.peer_id())
                .ok_or("identity not unlocked")?
        };

        // Complete against the pending state *without* consuming it: a
        // forged or tampered response fails the responder's key
        // confirmation and must leave the pending handshake in place for
        // the genuine reply.  Only a verified response removes it.
        let mut session = {
            let mut map = self
                .pending_wg_handshakes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let pending = map
                .get(&responder_peer_id)
                .ok_or("no pending handshake for this peer")?;
            let session = pending
                .complete(&response, our_peer_id, responder_peer_id)
                .map_err(|e| e.to_string())?;
            map.remove(&responder_peer_id);
            session
        };
        session.set_key_source(StaticKeySource::IdentityBootstrap);
        session.set_endpoint_policy(self.wg_endpoint_policy());

        // Store the confirmed session.
        self.wireguard_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(responder_peer_id, session);

        Ok(())
    }
}
