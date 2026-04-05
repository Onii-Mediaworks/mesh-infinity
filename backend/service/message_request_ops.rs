//! Message request operations for `MeshRuntime` (§10.1.1).
//!
//! Message requests are inbound first-contact messages from **unpaired** peers.
//! Because there is no prior shared secret, the sender includes their Ed25519
//! and X25519 public keys in a signed `message_request` frame.  We verify the
//! signature, rate-limit, and queue the request for the user to accept or decline.
//!
//! ## Wire format (`message_request` frame)
//!
//! ```json
//! {
//!   "type":           "message_request",
//!   "sender_ed25519": "<64-char hex — sender's Ed25519 public key>",
//!   "sender_x25519":  "<64-char hex — sender's X25519 public key>",
//!   "display_name":   "<optional UTF-8 string, max 64 chars>",
//!   "text":           "<plaintext message, max 2000 chars>",
//!   "msg_id":         "<32-char hex — random nonce; also the request ID>",
//!   "ts":             <u64 unix seconds>,
//!   "sig":            "<128-char hex — Ed25519 sig over canonical bytes>"
//! }
//! ```
//!
//! ## Signature canonical form
//!
//! The `sig` field covers the following bytes, in order, with no separator:
//!   `"message_request"` (UTF-8 literal) || `sender_ed25519` (raw 32 bytes)
//!   || `msg_id` (raw 16 bytes) || `ts` (big-endian u64) || `text` (UTF-8)
//!
//! This binds the frame type, sender identity, unique nonce, timestamp, and
//! message text into a single authenticated blob, preventing any field from
//! being substituted without invalidating the signature.
//!
//! ## Rate limits
//!
//! Enforced in `process_message_request_frame`:
//!   - Max 5 pending requests from any single sender (prevents spam campaigns).
//!   - Max 200 total pending requests (bounded memory / vault size).
//!   - Requests older than 30 days are pruned on `load_from_vault`.
//!
//! ## Accept flow
//!
//! `accept_message_request` creates a `ContactRecord` from the stored public
//! keys (trust level = `Acquaintance`, level 5), adds the stored message to
//! the new room, and emits `MessageAdded` + `RoomUpdated` events.  The sender
//! will infer acceptance when they receive a reply; no explicit accept signal
//! is sent (that would leak user activity to the sender).
//!
//! ## Decline flow
//!
//! `decline_message_request` silently removes the queue entry.  The sender
//! receives no notification — this is intentional.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::identity::peer_id::PeerId;
use crate::messaging::room::Room;
use crate::pairing::contact::ContactRecord;
use crate::pairing::methods::PairingMethod;
use crate::service::runtime::MeshRuntime;
use crate::trust::levels::TrustLevel;

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Inbound: process a message_request frame from an unpaired sender
    // -----------------------------------------------------------------------

    /// Handle an inbound `message_request` frame from an unpaired sender.
    ///
    /// Verifies the Ed25519 signature, applies rate limits, and queues the
    /// request for user action.  Emits a `MessageRequest` event so Flutter
    /// can update the badge immediately.
    ///
    /// Returns `true` if the frame was accepted (even if ultimately rate-limited,
    /// to avoid leaking presence), `false` only on cryptographic failure.
    pub fn process_message_request_frame(&self, envelope: &serde_json::Value) -> bool {
        // ---- Extract required fields ----------------------------------------

        // Sender's Ed25519 public key — 32 bytes / 64 hex chars.
        let ed_hex = match envelope.get("sender_ed25519").and_then(|v| v.as_str()) {
            Some(h) if h.len() == 64 => h,
            _ => return false,
        };
        let ed_bytes: [u8; 32] = match hex::decode(ed_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        // Sender's X25519 public key — 32 bytes / 64 hex chars.
        let x_hex = match envelope.get("sender_x25519").and_then(|v| v.as_str()) {
            Some(h) if h.len() == 64 => h,
            _ => return false,
        };
        let _x_bytes: [u8; 32] = match hex::decode(x_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        // Unique message nonce — 16 bytes / 32 hex chars.
        let msg_id = match envelope.get("msg_id").and_then(|v| v.as_str()) {
            Some(id) if !id.is_empty() => id,
            _ => return false,
        };

        // Unix timestamp (seconds).
        let ts = envelope.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);

        // Message text — capped at 2 000 chars to prevent abuse.
        let text_raw = match envelope.get("text").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return false,
        };
        // Truncate to 2 000 Unicode scalar values (not bytes) to bound frame size.
        let text: String = text_raw.chars().take(2_000).collect();

        // Ed25519 signature over the canonical bytes (see module doc).
        let sig_hex = match envelope.get("sig").and_then(|v| v.as_str()) {
            Some(s) if s.len() == 128 => s,
            _ => return false,
        };
        let sig_bytes: [u8; 64] = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => {
                let mut a = [0u8; 64];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        // ---- Timestamp freshness check (30-day window) ----------------------
        // Reject frames older than 30 days to prevent request-queue flooding
        // via stored/replayed frames.  We allow 60 s of clock skew.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        const THIRTY_DAYS_SECS: u64 = 30 * 24 * 3600;
        const CLOCK_SKEW_SECS: u64 = 60;
        if ts + THIRTY_DAYS_SECS < now_secs || ts > now_secs + CLOCK_SKEW_SECS {
            // Silently discard — stale or future-dated frame.
            return true;
        }

        // ---- Ed25519 signature verification ---------------------------------
        // Build the canonical byte string: frame-type literal || ed_pub (32) ||
        // msg_id bytes (raw) || ts (big-endian u64) || text (UTF-8).
        let verifying_key = match VerifyingKey::from_bytes(&ed_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let signature = match Signature::from_bytes(&sig_bytes) {
            sig => sig,
        };
        let msg_id_bytes = match hex::decode(msg_id) {
            Ok(b) if b.len() == 16 => b,
            // Non-16-byte msg_id: fall back to raw UTF-8 bytes of the id string.
            Ok(b) => b,
            Err(_) => msg_id.as_bytes().to_vec(),
        };
        let mut canonical: Vec<u8> = b"message_request".to_vec();
        canonical.extend_from_slice(&ed_bytes);
        canonical.extend_from_slice(&msg_id_bytes);
        canonical.extend_from_slice(&ts.to_be_bytes());
        canonical.extend_from_slice(text.as_bytes());

        if verifying_key.verify(&canonical, &signature).is_err() {
            // Cryptographic failure — drop silently (never error back to sender).
            return false;
        }

        // ---- Derive peer ID and check if already paired ---------------------
        // If the sender has since been paired (e.g. a race condition between
        // pairing on another device and this frame arriving), skip the request
        // queue and let the normal message delivery path handle it.
        let peer_id = PeerId::from_ed25519_pub(&ed_bytes);
        let already_paired = self
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer_id)
            .is_some();
        if already_paired {
            // Silently discard — paired peers use normal encrypted message flow.
            return true;
        }

        // ---- Rate limiting --------------------------------------------------
        let sender_hex = hex::encode(peer_id.0);
        {
            let queue = self
                .pending_message_requests
                .lock()
                .unwrap_or_else(|e| e.into_inner());

            // Max 5 pending requests per sender.
            let sender_count = queue
                .iter()
                .filter(|r| r.get("peerId").and_then(|v| v.as_str()) == Some(&sender_hex))
                .count();
            if sender_count >= 5 {
                return true; // Silently drop — flood protection.
            }

            // Max 200 total entries across all senders.
            if queue.len() >= 200 {
                return true; // Silently drop — total cap.
            }
        }

        // ---- Build and enqueue the request ----------------------------------
        let display_name = envelope
            .get("display_name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            // Cap display names at 64 chars to prevent oversized entries.
            .map(|s| s.chars().take(64).collect::<String>())
            .unwrap_or_else(|| peer_id.short_hex());

        // Build an ISO-8601 timestamp string for the Dart model.
        let ts_iso = format_unix_as_iso8601(ts);

        // Message preview: first 100 chars.
        let preview: String = text.chars().take(100).collect();
        let preview = if text.chars().count() > 100 {
            format!("{}…", preview)
        } else {
            preview
        };

        // The stored record includes internal `_ed25519` / `_x25519` fields so
        // `accept_message_request` can create a ContactRecord without the sender
        // needing to resend their keys.  The Dart side ignores unknown fields.
        let request = serde_json::json!({
            "id":             msg_id,
            "peerId":         sender_hex,
            "senderName":     display_name,
            "trustLevel":     0u8,          // unpaired = level 0
            "messagePreview": preview,
            "timestamp":      ts_iso,
            // Internal fields used by accept_message_request — not sent to Dart.
            "_ed25519":       ed_hex,
            "_x25519":        x_hex,
            "_text":          text,
            "_ts":            ts,
            "_msg_id":        msg_id,
        });

        self.pending_message_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.clone());

        self.save_message_requests();

        // Emit the public-facing fields only (strip internal _ keys).
        let public_request = serde_json::json!({
            "id":             msg_id,
            "peerId":         sender_hex,
            "senderName":     &request["senderName"],
            "trustLevel":     0u8,
            "messagePreview": preview,
            "timestamp":      ts_iso,
        });
        self.push_event("MessageRequest", public_request);

        true
    }

    // -----------------------------------------------------------------------
    // Query: return the pending request queue as JSON
    // -----------------------------------------------------------------------

    /// Serialise the pending message request queue to a JSON array.
    ///
    /// Each entry contains only the Dart-facing fields (`id`, `peerId`,
    /// `senderName`, `trustLevel`, `messagePreview`, `timestamp`).
    /// Internal `_*` fields are stripped before returning.
    pub fn message_requests_json(&self) -> String {
        let queue = self
            .pending_message_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let public: Vec<serde_json::Value> = queue
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id":             r["id"],
                    "peerId":         r["peerId"],
                    "senderName":     r["senderName"],
                    "trustLevel":     r["trustLevel"],
                    "messagePreview": r["messagePreview"],
                    "timestamp":      r["timestamp"],
                })
            })
            .collect();
        serde_json::to_string(&public).unwrap_or_else(|_| "[]".to_string())
    }

    // -----------------------------------------------------------------------
    // Accept: promote request to a room, create contact record
    // -----------------------------------------------------------------------

    /// Accept a pending message request by ID.
    ///
    /// 1. Creates a `ContactRecord` from the sender's stored public keys
    ///    at trust level `Acquaintance` (level 5).
    /// 2. Seeds a direct routing entry for the new contact.
    /// 3. Auto-creates a DM room for the conversation.
    /// 4. Drops the stored first message into the room's message cache.
    /// 5. Emits `MessageAdded` + `RoomUpdated` events so Flutter rebuilds.
    /// 6. Removes the request from the pending queue and persists.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` if the ID is not found.
    pub fn accept_message_request(&self, request_id: &str) -> Result<(), String> {
        // Find and remove the request from the queue atomically.
        let request = {
            let mut queue = self
                .pending_message_requests
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let pos = queue
                .iter()
                .position(|r| r.get("id").and_then(|v| v.as_str()) == Some(request_id))
                .ok_or_else(|| format!("message request '{}' not found", request_id))?;
            queue.remove(pos)
        };

        // Extract internal fields we stored at request-queue time.
        let ed_hex = request
            .get("_ed25519")
            .and_then(|v| v.as_str())
            .ok_or("request missing _ed25519")?;
        let x_hex = request
            .get("_x25519")
            .and_then(|v| v.as_str())
            .ok_or("request missing _x25519")?;
        let text = request
            .get("_text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ts = request.get("_ts").and_then(|v| v.as_u64()).unwrap_or(0);
        let msg_id = request
            .get("_msg_id")
            .and_then(|v| v.as_str())
            .unwrap_or(request_id)
            .to_string();
        let display_name_stored = request
            .get("senderName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Decode public key bytes.
        let ed_bytes: [u8; 32] = hex::decode(ed_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .ok_or("invalid _ed25519")?;
        let x_bytes: [u8; 32] = hex::decode(x_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .ok_or("invalid _x25519")?;

        let peer_id = PeerId::from_ed25519_pub(&ed_bytes);
        let sender_hex = hex::encode(peer_id.0);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // ---- Create ContactRecord -------------------------------------------
        // Trust level: Acquaintance (5) — they reached out but haven't been
        // vouched for.  The user can promote trust manually after accepting.
        let mut contact = ContactRecord::new(
            peer_id,
            ed_bytes,
            x_bytes,
            PairingMethod::LinkShare, // closest semantic: they shared their identity
            now,
        );
        contact.set_trust_level(TrustLevel::Acquaintance);
        if !display_name_stored.is_empty() {
            contact.display_name = Some(display_name_stored.clone());
        }

        // Persist the new contact.
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upsert(contact);
        self.save_contacts();
        // Seed a routing entry for the new contact.
        self.rebuild_routing_table_from_contacts();

        // ---- Auto-create DM room -------------------------------------------
        let our_peer_id = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|id| id.peer_id())
            .unwrap_or(PeerId([0u8; 32]));
        let peer_name = if display_name_stored.is_empty() {
            peer_id.short_hex()
        } else {
            display_name_stored
        };
        let room = Room::new_dm(our_peer_id, peer_id, &peer_name);
        let room_id_hex = hex::encode(room.id);

        let room_already_exists = self
            .rooms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|r| hex::encode(r.id) == room_id_hex);
        if !room_already_exists {
            self.rooms
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(room);
            self.save_rooms();
        }

        // ---- Insert the stored first message --------------------------------
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

        // Update room metadata.
        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                room.last_message_preview = Some(if text.len() > 80 {
                    format!("{}…", &text[..80])
                } else {
                    text.clone()
                });
                room.last_message_at = Some(ts);
                room.unread_count += 1;
            }
        }
        self.save_rooms();
        self.save_messages();

        // ---- Emit events ---------------------------------------------------
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

        // Also emit a PeerListUpdated so the contacts screen refreshes.
        self.push_event("PeerListUpdated", serde_json::json!({}));

        // Persist the queue (request was removed above).
        self.save_message_requests();

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Decline: silently remove request
    // -----------------------------------------------------------------------

    /// Decline a pending message request by ID.
    ///
    /// Removes the request from the queue without notifying the sender.
    /// Sender receives no signal — this is intentional to prevent the sender
    /// from using decline responses to infer user activity (§10.1.1).
    ///
    /// Returns `Ok(())` on success, `Err(reason)` if the ID is not found.
    pub fn decline_message_request(&self, request_id: &str) -> Result<(), String> {
        let mut queue = self
            .pending_message_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let pos = queue
            .iter()
            .position(|r| r.get("id").and_then(|v| v.as_str()) == Some(request_id))
            .ok_or_else(|| format!("message request '{}' not found", request_id))?;
        queue.remove(pos);
        drop(queue);
        self.save_message_requests();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper: format a Unix timestamp as ISO 8601 (UTC)
// ---------------------------------------------------------------------------

/// Format a Unix timestamp (seconds since epoch) as an ISO 8601 UTC string.
///
/// Produces `YYYY-MM-DDTHH:MM:SSZ` without a fractional seconds component.
/// Used for the `timestamp` field in `MessageRequest` JSON sent to Flutter.
///
/// Falls back to the decimal seconds string if the date arithmetic fails
/// (e.g. timestamp overflows year 9999).
fn format_unix_as_iso8601(ts: u64) -> String {
    // Days since the Unix epoch (1970-01-01).
    let secs_in_day: u64 = 86_400;
    let time_of_day = ts % secs_in_day;
    let days = ts / secs_in_day;

    // Convert days since epoch to (year, month, day) using the Gregorian
    // calendar algorithm (works for 1970-01-01 through at least 2100).
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let hh = time_of_day / 3_600;
    let mm = (time_of_day % 3_600) / 60;
    let ss = time_of_day % 60;

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}
