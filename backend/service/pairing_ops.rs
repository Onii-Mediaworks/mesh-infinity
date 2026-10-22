//! Peer pairing, pairing payload, peer list, and trust operations for
//! `MeshRuntime`.
//!
//! The pairing protocol (§8.3) is two-sided:
//!   - Alice shows a QR code containing her `PairingPayload`.
//!   - Bob scans it and calls `pair_peer`, which stores Alice's keys and
//!     immediately sends Alice a signed `pairing_hello` frame so she can add
//!     Bob without a second QR scan.
//!   - On receiving a `pairing_hello`, Alice calls `process_pairing_hello`
//!     which stores Bob's `ContactRecord`.
//!
//! All frame handlers (`process_pairing_hello`, `process_gossip_map_entry_frame`,
//! `process_route_announcement_frame`, `process_mesh_packet_frame`,
//! `process_losec_*_frame`, group frame handlers) live here or in messaging.rs.
//!
//! Trust operations (set_trust_level, trust_verify) are also here because they
//! operate directly on the `ContactStore`.

use crate::identity::peer_id::PeerId;
use crate::mesh::admin_command::{
    parse_admin_command, AdminCommand, AdminCommandError, RemoteKillswitchRequest,
};
use crate::mesh::{MeshPacket, PacketKind};
use crate::pairing::contact::ContactRecord;
use crate::pairing::methods::parse_pairing_qr_payload_json;
use crate::routing::announcement::ReachabilityAnnouncement;
use crate::routing::store_forward::{
    DepositResult, Priority, ReleaseCondition, StoreAndForwardRequest,
};
use crate::routing::table::{DeviceAddress, RoutingEntry};
use crate::service::runtime::{
    bootstrap_ratchet_session, local_clearnet_ip, write_tcp_frame, MeshRuntime, PendingPairing,
    DEFAULT_HS_PORT, MAX_PENDING_PAIRINGS,
};
use crate::trust::levels::TrustLevel;

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Pair peer (Bob side)
    // -----------------------------------------------------------------------

    /// Store a peer's pairing payload (scanned QR / received deep link) and
    /// initiate a two-way pairing handshake (§8.3).
    ///
    /// Parses the payload, creates a `ContactRecord`, bootstraps a Double Ratchet
    /// session, then sends a signed `pairing_hello` frame to Alice's clearnet
    /// endpoint so Alice can add Bob without scanning a second code.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` on malformed input.
    pub fn pair_peer(&self, payload_json: &str) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Parse and structurally validate the hostile QR/deep-link payload
        // before using any field semantically.
        let decoded = parse_pairing_qr_payload_json(payload_json.as_bytes(), now)
            .map_err(|error| error.safe_description())?;
        let payload = decoded.payload;
        let ed_bytes = payload.ed25519_public;
        let x_bytes = payload.x25519_public;
        let mesh_x_bytes = decoded.mesh_x25519_public;

        // Derive the canonical peer ID by hashing the Ed25519 public key.
        // This gives a stable identifier that does not change if the peer
        // rotates their X25519 preauth key (which happens weekly).
        let peer_id = payload.peer_id;
        let name = payload.display_name.clone();

        // Extract optional preauth X25519 public key (their SPK for X3DH).
        let preauth_pub_bytes = decoded.preauth_x25519_public;

        // Extract transport hints.
        let clearnet_endpoint = payload
            .transport_hints
            .iter()
            .find(|hint| hint.transport == "clearnet")
            .and_then(|hint| hint.endpoint.clone());
        let tor_endpoint = payload
            .transport_hints
            .iter()
            .find(|hint| hint.transport == "tor")
            .and_then(|hint| hint.endpoint.clone());

        let mut contact = ContactRecord::new(
            peer_id,
            ed_bytes,
            x_bytes,
            crate::pairing::methods::PairingMethod::LinkShare,
            now,
        );
        contact.mesh_x25519_public = mesh_x_bytes;
        contact.display_name = name.clone();
        contact.clearnet_endpoint = clearnet_endpoint;
        contact.tor_endpoint = tor_endpoint;

        // Store ML-KEM-768 encapsulation key if advertised (PQXDH §3.4.1).
        // This enables post-quantum key exchange with this peer; if absent,
        // the session will use classical X3DH only.
        contact.kem_encapsulation_key = decoded
            .kem_pub
            .filter(|bytes| bytes.len() == crate::crypto::x3dh::KEM_EK_SIZE);

        // Store their preauth pub — Alice uses it to initiate X3DH.
        if let Some(preauth_bytes) = preauth_pub_bytes {
            let preauth_sig_opt = decoded.preauth_sig.filter(|sig| sig.len() == 64);
            if let Some(sig) = preauth_sig_opt {
                contact.update_preauth_key_with_sig(preauth_bytes, sig, now);
            } else {
                contact.update_preauth_key(preauth_bytes, now);
            }
        }

        // Bootstrap a Double Ratchet session.
        {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref our_id) = *guard {
                if let Ok((session, x3dh_header, pq_ext)) =
                    bootstrap_ratchet_session(our_id, &contact)
                {
                    if let Some(header) = x3dh_header {
                        self.x3dh_pending
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(peer_id, header);
                    }
                    if let Some(pq) = pq_ext {
                        self.pqxdh_pending
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(peer_id, pq);
                    }
                    drop(guard);
                    self.ratchet_sessions
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(peer_id, session);
                }
            }
        }

        // Snapshot the clearnet endpoint before moving `contact` into the store.
        // We need this after the move to know where to send the pairing hello.
        let clearnet_ep = contact.clearnet_endpoint.clone();

        // Persist the contact.  upsert() is used instead of insert() because
        // the same peer could be paired multiple times (e.g. after a reinstall
        // where only one side lost state).
        let pairing_method_label = format!("{:?}", contact.pairing_method);
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upsert(contact);
        self.save_contacts();

        // Two-way pairing hello (§8.3): send our own keys back to Alice so
        // she can add Bob without needing to scan a second QR code.  This
        // completes the pairing in one scan rather than two.  The scanned
        // token is what proves to Alice that this hello answers a payload
        // she issued, and Alice's peer id is what the link handshake must
        // confirm before the hello is sent.
        if let Some(ref ep) = clearnet_ep {
            self.send_pairing_hello_to(&peer_id.to_hex(), ep, &payload.pairing_token);
        }

        // Announce our network map entry to the new peer.
        let peer_id_hex = hex::encode(peer_id.0);
        self.send_gossip_self_entry(&peer_id_hex);

        // Broadcast a fresh self-reachability announcement to all current peers.
        self.broadcast_self_route_announcement();

        // Emit PeerAdded event for the UI.
        self.push_event(
            "PeerAdded",
            serde_json::json!({
                "id":               hex::encode(peer_id.0),
                "name":             name.as_deref().unwrap_or(""),
                "trustLevel":       0,
                "pairingMethod":    pairing_method_label,
                "status":           "offline",
                "canBeExitNode":    false,
                "canBeWrapperNode": false,
                "canBeStoreForward": false,
                "canEndorsePeers":  false,
                "latencyMs":        serde_json::Value::Null,
            }),
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Pairing hello (Alice side — process Bob's unsolicited frame)
    // -----------------------------------------------------------------------

    /// Handle a `pairing_hello` frame from a peer who has scanned our QR code.
    ///
    /// This is the second half of the two-way pairing handshake (§8.3).  Bob
    /// scanned Alice's QR and called `pair_peer`, then immediately sent this
    /// frame to Alice so Alice can add Bob without a second scan.
    ///
    /// The frame signature covers
    /// `DOMAIN_PAIRING_HELLO | ed25519 | x25519 | pairing_token | BE32(kem_len) | kem_pub`
    /// (see `pairing_hello_preimage`; display_name is intentionally excluded —
    /// it is an untrusted display hint).
    ///
    /// A hello from a peer we do not already know creates a contact only if
    /// its `pairing_token` is one this device issued in a QR / link payload
    /// and that payload has not expired (§8.3).  Anyone else who can reach
    /// our socket gets nothing: no contact, no session, no route, no event.
    /// The token is single-use; a second hello with the same token is
    /// treated like a hello without one.
    ///
    /// On success: stores Bob's ContactRecord, bootstraps a ratchet session,
    /// and emits a `PeerAdded` event.
    pub fn process_pairing_hello(&self, envelope: &serde_json::Value) -> bool {
        use crate::crypto::signing;

        let ed_hex = match envelope.get("ed25519_public").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ed_bytes: [u8; 32] = match hex::decode(ed_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        let x_hex = match envelope.get("x25519_public").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let x_bytes: [u8; 32] = match hex::decode(x_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let mesh_x_bytes = envelope
            .get("mesh_x25519_public")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            });

        let sig_hex = match envelope.get("sig").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // ML-KEM encapsulation key, raw bytes exactly as sent (empty when the
        // peer has none). It is part of the signed preimage so a man in the
        // middle cannot swap it to downgrade PQXDH to classical X3DH
        // (§3.4.1, §7.0.1). Malformed hex is a malformed frame: drop it.
        let kem_bytes: Vec<u8> = match envelope.get("kem_pub").and_then(|v| v.as_str()) {
            Some(h) => match hex::decode(h) {
                Ok(b) => b,
                Err(_) => return false,
            },
            None => Vec::new(),
        };

        // The §8.3 pairing token Bob scanned from our payload.  Required and
        // signed: it is the only thing tying this hello to a pairing session
        // the local user actually started.
        let token: [u8; 32] = match envelope
            .get("pairing_token")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok())
        {
            Some(token) => token,
            None => return false,
        };

        // SECURITY: Verify the Ed25519 signature over
        // DOMAIN_PAIRING_HELLO || ed || x || token || BE32(kem_len) || kem.
        // The domain separator prevents cross-protocol signature reuse.
        // The display_name is intentionally NOT signed — it is an untrusted
        // display hint that the user can see and override via the contact's
        // local nickname setting.  An attacker cannot impersonate a different
        // peer because the peer_id is derived from the (signed) ed25519 key.
        let signed_msg = pairing_hello_preimage(&ed_bytes, &x_bytes, &token, &kem_bytes);
        if !signing::verify(
            &ed_bytes,
            signing::DOMAIN_PAIRING_HELLO,
            &signed_msg,
            &sig_bytes,
        ) {
            // Signature invalid — possibly corrupted or forged frame.
            // Silently discard (§7.2 error-silence rule).
            return false;
        }

        // Derive the canonical peer_id from the verified Ed25519 key.
        let peer_id = PeerId::from_ed25519_pub(&ed_bytes);

        // Idempotent: if we already have this peer in our contact store,
        // re-emit PeerAdded to synchronise the Flutter UI (the UI may have
        // been restarted or missed the original event).
        if self
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer_id)
            .is_some()
        {
            let name = envelope
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            self.push_event(
                "PeerAdded",
                serde_json::json!({
                    "id":               hex::encode(peer_id.0),
                    "name":             name,
                    "trustLevel":       0,
                    "status":           "online",
                    "canBeExitNode":    false,
                    "canBeWrapperNode": false,
                    "canBeStoreForward": false,
                    "canEndorsePeers":  false,
                    "latencyMs":        serde_json::Value::Null,
                }),
            );
            return true;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // SECURITY: an unknown peer becomes a contact only by presenting a
        // token we issued and that is still valid.  Everything above only
        // proved the sender holds *some* key; this proves the local user
        // invited that key holder (§8.3, §2.0).  Silent drop otherwise.
        if !self.consume_pairing_token(&token, now) {
            self.diagnostic_log("pairing", "hello_without_valid_token");
            return false;
        }

        let display_name = envelope
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Extract optional preauth and KEM keys.
        let preauth_pub_bytes: Option<[u8; 32]> = envelope
            .get("preauth_x25519_public")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            });
        let preauth_sig_opt: Option<Vec<u8>> = envelope
            .get("preauth_sig")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 64);

        let hints_arr = envelope
            .get("transport_hints")
            .and_then(|h| h.as_array())
            .cloned()
            .unwrap_or_default();
        let clearnet_endpoint = hints_arr
            .iter()
            .find(|h| h.get("transport").and_then(|t| t.as_str()) == Some("clearnet"))
            .and_then(|h| h.get("endpoint"))
            .and_then(|e| e.as_str())
            .map(|s| s.to_string());
        let tor_endpoint = hints_arr
            .iter()
            .find(|h| h.get("transport").and_then(|t| t.as_str()) == Some("tor"))
            .and_then(|h| h.get("endpoint"))
            .and_then(|e| e.as_str())
            .map(|s| s.to_string());

        let mut contact = ContactRecord::new(
            peer_id,
            ed_bytes,
            x_bytes,
            crate::pairing::methods::PairingMethod::LinkShare,
            now,
        );
        contact.mesh_x25519_public = mesh_x_bytes;
        contact.display_name = display_name.clone();
        contact.clearnet_endpoint = clearnet_endpoint;
        contact.tor_endpoint = tor_endpoint;
        // Signature-covered KEM key (verified above); only a full-size key is
        // usable for PQXDH, anything else means "no PQ key published".
        contact.kem_encapsulation_key =
            Some(kem_bytes).filter(|b| b.len() == crate::crypto::x3dh::KEM_EK_SIZE);
        if let Some(preauth_bytes) = preauth_pub_bytes {
            if let Some(sig) = preauth_sig_opt {
                contact.update_preauth_key_with_sig(preauth_bytes, sig, now);
            } else {
                contact.update_preauth_key(preauth_bytes, now);
            }
        }

        // Bootstrap a ratchet session.
        {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref our_id) = *guard {
                if let Ok((session, x3dh_header, pq_ext)) =
                    bootstrap_ratchet_session(our_id, &contact)
                {
                    if let Some(header) = x3dh_header {
                        self.x3dh_pending
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(peer_id, header);
                    }
                    if let Some(pq) = pq_ext {
                        self.pqxdh_pending
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(peer_id, pq);
                    }
                    drop(guard);
                    self.ratchet_sessions
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(peer_id, session);
                }
            }
        }

        let pairing_method_label = format!("{:?}", contact.pairing_method);
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upsert(contact);
        self.save_contacts();

        // Add a local-plane routing entry for the new peer.
        {
            let dest = DeviceAddress(peer_id.0);
            let entry = RoutingEntry {
                destination: dest,
                next_hop: dest,
                hop_count: 1,
                latency_ms: 10,
                next_hop_trust: TrustLevel::Unknown,
                last_updated: now,
                announcement_id: [0u8; 32],
            };
            self.routing_table
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .update_local(entry);
        }

        // Reply with our own network map entry so the new peer has our preauth key.
        let peer_id_hex = hex::encode(peer_id.0);
        self.send_gossip_self_entry(&peer_id_hex);

        self.push_event(
            "PeerAdded",
            serde_json::json!({
                "id":               hex::encode(peer_id.0),
                "name":             display_name.as_deref().unwrap_or(""),
                "trustLevel":       0,
                "pairingMethod":    pairing_method_label,
                "status":           "online",
                "canBeExitNode":    false,
                "canBeWrapperNode": false,
                "canBeStoreForward": false,
                "canEndorsePeers":  false,
                "latencyMs":        serde_json::Value::Null,
            }),
        );

        true
    }

    // -----------------------------------------------------------------------
    // Peer list
    // -----------------------------------------------------------------------

    /// Return a JSON array of all known peers from the contact store.
    pub fn get_peer_list(&self) -> String {
        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
        let peers: Vec<serde_json::Value> = contacts
            .all()
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id":               hex::encode(c.peer_id.0),
                    "name":             c.display_name.as_deref()
                        .or(c.local_nickname.as_deref())
                        .unwrap_or(&c.peer_id.short_hex()),
                    "trustLevel":       c.trust_level.value(),
                    "pairingMethod":    format!("{:?}", c.pairing_method),
                    "status":           if c.last_seen.is_some() { "online" } else { "offline" },
                    "canBeExitNode":    c.can_be_exit_node,
                    "canBeWrapperNode": c.can_be_wrapper_node,
                    "canBeStoreForward": c.can_be_store_forward,
                    "canEndorsePeers":  c.can_endorse_peers,
                    "latencyMs":        c.latency_ms,
                    // §22.8.2 block state, so the contact screen can offer
                    // "Unblock contact" instead of "Block contact".
                    "blocked":          c.blocked,
                })
            })
            .collect();
        serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string())
    }

    // -----------------------------------------------------------------------
    // Block list (§22.8.2 "Block contact")
    // -----------------------------------------------------------------------

    /// Block or unblock a contact.
    ///
    /// A blocked contact stays in the contact store — the block must survive
    /// a later trust downgrade and must be reversible — but every inbound
    /// direct message and message request from them is dropped at the
    /// inbound gate (`process_inbound_frame`, `process_message_request_frame`).
    /// The change is persisted to `peers.vault` immediately.
    pub fn set_peer_blocked(&self, peer_id_hex: &str, blocked: bool) -> Result<(), String> {
        let pid = parse_peer_id_hex(peer_id_hex)?;
        {
            let mut contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            // Only known contacts can be blocked: there is nothing to block
            // for a peer we have never paired with.
            let contact = contacts
                .get_mut(&pid)
                .ok_or_else(|| "Peer not found".to_string())?;
            if blocked {
                contact.block();
            } else {
                contact.unblock();
            }
        }
        // Write through so the block survives a restart.
        self.save_contacts();
        Ok(())
    }

    /// Whether a contact is blocked.  Unknown or malformed peer IDs are not
    /// blocked (there is no contact record to carry the flag).
    pub fn is_peer_blocked(&self, peer_id_hex: &str) -> bool {
        let Ok(pid) = parse_peer_id_hex(peer_id_hex) else {
            return false;
        };
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&pid)
            .is_some_and(|c| c.blocked)
    }

    // -----------------------------------------------------------------------
    // Trust operations
    // -----------------------------------------------------------------------

    /// Set the trust level for a peer.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` if the peer is not found or
    /// the level is invalid.
    pub fn set_trust_level(&self, peer_id_hex: &str, level: u8) -> Result<(), String> {
        let trust =
            TrustLevel::from_value(level).ok_or_else(|| "Invalid trust level".to_string())?;
        let pid_bytes: [u8; 32] = hex::decode(peer_id_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .ok_or_else(|| "Invalid peer id".to_string())?;
        let pid = PeerId(pid_bytes);
        {
            let mut contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            let contact = contacts
                .get_mut(&pid)
                .ok_or_else(|| "Peer not found".to_string())?;
            contact.set_trust_level(trust);
        }
        self.push_event(
            "TrustUpdated",
            serde_json::json!({
                "peerId":     peer_id_hex,
                "trustLevel": level,
            }),
        );
        self.save_contacts();
        Ok(())
    }

    /// Return a JSON object with the trust and verification status of a peer.
    pub fn trust_verify(&self, peer_id_hex: &str) -> String {
        let pid_bytes: [u8; 32] =
            match hex::decode(peer_id_hex)
                .ok()
                .filter(|b| b.len() == 32)
                .map(|b| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }) {
                Some(b) => b,
                None => return r#"{"verified": false, "error": "invalid peer id"}"#.to_string(),
            };
        let pid = PeerId(pid_bytes);
        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
        match contacts.get(&pid) {
            Some(contact) => serde_json::json!({
                "verified":       contact.safety_number_verified,
                "trustLevel":     contact.trust_level.value(),
                "safetyNumber":   contact.safety_number,
                "pairingMethod":  format!("{:?}", contact.pairing_method),
            })
            .to_string(),
            None => r#"{"verified": false, "error": "peer not found"}"#.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Gossip map entry handler (§4.1)
    // -----------------------------------------------------------------------

    /// Process an inbound `gossip_map_entry` frame (§4.1).
    ///
    /// Source attribution: the frame's top-level `sender` is the connection
    /// identity the poll loop keys this TCP link on (proven by the §5.1 link
    /// handshake and enforced by `frame_bound_to_link`), i.e. the peer that
    /// *delivered* the entry. That — never the entry's own
    /// `peer_id` — is what the §4.2 per-peer rate limit and the §4.1
    /// source-diversity quorum are charged to. Attributing to the entry owner
    /// would give every forged self-signed entry its own rate budget and make
    /// the quorum unreachable (every "source" for an entry would be the entry
    /// itself). A frame without a well-formed `sender` is dropped.
    ///
    /// Validates the Ed25519 signature, merges into the local network map, and
    /// updates the matching contact's preauth_key + transport hints if the peer
    /// is known. The KEM key copied into the contact is covered by the entry
    /// signature (`NetworkMapEntry::signing_payload`, wire v2), so a relay
    /// cannot substitute it.
    pub fn process_gossip_map_entry_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::network::map::NetworkMapEntry;

        // Delivering peer: the connection identity, parsed strictly (64 hex).
        let source = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(hex_id) => match PeerId::from_hex(hex_id) {
                Ok(pid) => pid,
                Err(_) => return false,
            },
            None => return false,
        };

        let entry_val = match envelope.get("entry") {
            Some(v) => v.clone(),
            None => return false,
        };
        // `NetworkMapEntry` is `deny_unknown_fields`: a v1 entry carrying
        // `last_seen`, or one smuggling a local-only field, fails here.
        let entry: NetworkMapEntry = match serde_json::from_value(entry_val) {
            Ok(e) => e,
            Err(_) => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry_peer_id = entry.peer_id;

        // Our trust in the *delivering* peer selects its rate budget (§4.2).
        // Unknown connections get the untrusted budget.
        let source_trust = self
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&source)
            .map(|c| c.trust_level)
            .unwrap_or(TrustLevel::Unknown);

        // Merge into the gossip engine's network map.  The gossip engine handles
        // deduplication (via sequence numbers), rate limiting per delivering
        // source, source-diversity staging, and signature verification
        // internally.  It returns false if the entry was stale, duplicate,
        // rate-limited, still awaiting quorum, or had an invalid signature.
        let accepted = {
            let mut gossip = self.gossip.lock().unwrap_or_else(|e| e.into_inner());
            gossip
                .receive_entry(entry.clone(), &source, source_trust, now)
                .unwrap_or(false)
        };

        if !accepted {
            return false;
        }

        // If we know this peer (they are in our contact store), update their
        // preauth key and transport hints from the gossip entry.  This is how
        // peers learn about each other's address changes and SPK rotations
        // without requiring a fresh pairing exchange.
        {
            let mut contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(contact) = contacts.get_mut(&entry_peer_id) {
                if let Some(pk) = entry.public_keys.first() {
                    if let Some(preauth) = pk.preauth_x25519_public {
                        if let Some(ref sig) = pk.preauth_sig {
                            contact.update_preauth_key_with_sig(preauth, sig.clone(), now);
                        } else {
                            contact.update_preauth_key(preauth, now);
                        }
                    }
                    if let Some(ref kem_ek) = pk.kem_encapsulation_key {
                        if kem_ek.len() == crate::crypto::x3dh::KEM_EK_SIZE {
                            contact.kem_encapsulation_key = Some(kem_ek.clone());
                        }
                    }
                }
                for hint in &entry.transport_hints {
                    match hint.transport {
                        crate::network::transport_hint::TransportType::Clearnet => {
                            if let Some(ref ep) = hint.endpoint {
                                contact.clearnet_endpoint = Some(ep.clone());
                            }
                        }
                        crate::network::transport_hint::TransportType::Tor => {
                            if let Some(ref ep) = hint.endpoint {
                                contact.tor_endpoint = Some(ep.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        true
    }

    /// Process an inbound `service_record` frame carrying a signed service
    /// advertisement.
    pub fn process_service_record_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender = envelope.get("sender").and_then(|value| value.as_str());
        let record_val = match envelope.get("record") {
            Some(value) => value.clone(),
            None => return false,
        };
        let record: crate::services::registry::ServiceRecord =
            match serde_json::from_value(record_val) {
                Ok(record) => record,
                Err(_) => return false,
            };
        self.receive_service_record(record, sender)
    }

    // -----------------------------------------------------------------------
    // Route announcement handler (§6.2)
    // -----------------------------------------------------------------------

    /// Process an inbound `route_announcement` frame (§6.2).
    ///
    /// Runs the announcement through the `AnnouncementProcessor` (dedup, age,
    /// hop-count, and signature checks), inserts the derived routing entry, and
    /// forwards to other clearnet peers when the scope permits.
    pub fn process_route_announcement_frame(&self, envelope: &serde_json::Value) -> bool {
        let ann_val = match envelope.get("announcement") {
            Some(v) => v.clone(),
            None => return false,
        };
        let announcement: ReachabilityAnnouncement = match serde_json::from_value(ann_val) {
            Ok(a) => a,
            Err(_) => return false,
        };

        let from_hex = match envelope.get("from").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let from_bytes: [u8; 32] = match hex::decode(&from_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };
        let from_addr = DeviceAddress(from_bytes);

        let neighbour_trust = {
            let from_peer_id = PeerId(from_bytes);
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            contacts
                .get(&from_peer_id)
                .map(|c| c.trust_level)
                .unwrap_or(TrustLevel::Unknown)
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let result = {
            let mut proc = self
                .announcement_processor
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            proc.process(&announcement, from_addr, neighbour_trust, now, None)
        };

        match result {
            crate::routing::announcement::ProcessResult::Accepted(r) => {
                // Insert into the routing table.
                {
                    let mut table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
                    table.update_public(r.entry, now);
                }

                // Forward to all identified clearnet peers if scope allows.
                if r.should_forward {
                    if let Some(fwd_ann) = r.forward_announcement {
                        let our_hex = self
                            .identity
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref()
                            .map(|id| hex::encode(id.peer_id().0))
                            .unwrap_or_default();
                        let fwd_frame = serde_json::json!({
                            "type": "route_announcement",
                            "from": our_hex,
                            "announcement": fwd_ann,
                        });
                        let peers: Vec<String> = self
                            .clearnet_connections
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .keys()
                            .cloned()
                            .collect();
                        for peer_hex in peers {
                            if peer_hex == from_hex {
                                continue;
                            }
                            self.send_raw_frame(&peer_hex, &fwd_frame);
                        }
                    }
                }

                true
            }
            crate::routing::announcement::ProcessResult::Rejected(_) => false,
        }
    }

    // -----------------------------------------------------------------------
    // Mesh packet handler (§6.5)
    // -----------------------------------------------------------------------

    /// Process an inbound `mesh_packet` frame (§6.5).
    ///
    /// Runs the packet through the `ForwardEngine` (dedup, TTL, routing lookup)
    /// then either delivers it locally or forwards to the next hop.
    pub fn process_mesh_packet_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::mesh::forwarder::{ForwardDecision, ForwardEngine};

        let pkt_val = match envelope.get("packet") {
            Some(v) => v.clone(),
            None => return false,
        };
        let mut pkt: MeshPacket = match serde_json::from_value(pkt_val) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let our_addr = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => DeviceAddress(id.peer_id().0),
                None => return false,
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let dest = pkt.dest_address();

        let route_entry = {
            let table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
            table.lookup(&dest, None, now).cloned()
        };

        let decision = {
            let mut dedup = self.dedup_cache.lock().unwrap_or_else(|e| e.into_inner());
            ForwardEngine::decide(
                &crate::mesh::forwarder::PacketHeader {
                    packet_id: pkt.packet_id,
                    destination: dest,
                    ttl: pkt.ttl,
                    timestamp: pkt.timestamp,
                },
                &our_addr,
                now,
                &mut dedup,
                route_entry.as_ref(),
            )
        };

        match decision {
            ForwardDecision::Deliver => {
                // Re-inject Message packets through the application pipeline.
                if pkt.kind == PacketKind::Message {
                    if let Some(payload) = pkt.payload_bytes() {
                        if let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&payload)
                        {
                            return self.process_inbound_frame(&envelope);
                        }
                    }
                }

                // Admin commands (§3.9.3) carry their own signature; the
                // unsigned packet envelope authorises nothing.
                if pkt.kind == PacketKind::AdminCommand {
                    return self.process_admin_command(&pkt, now);
                }

                self.push_event(
                    "MeshPacketDelivered",
                    serde_json::json!({
                        "source": hex::encode(pkt.source),
                        "kind":   format!("{:?}", pkt.kind),
                        "size":   pkt.payload_hex.len() / 2,
                    }),
                );
                true
            }
            ForwardDecision::Forward { next_hop } => {
                if !pkt.decrement_ttl() {
                    return false;
                }
                let next_hop_hex = hex::encode(next_hop.0);
                self.send_raw_frame(
                    &next_hop_hex,
                    &serde_json::json!({
                        "type":   "mesh_packet",
                        "packet": pkt,
                    }),
                );
                true
            }
            ForwardDecision::Drop(_) => false,
        }
    }

    // -----------------------------------------------------------------------
    // LoSec handlers (§6.9.6)
    // -----------------------------------------------------------------------

    /// Handle an inbound `losec_request` frame (§6.9.6).
    ///
    /// Verifies the signed request, runs the LoSec policy, sends a
    /// `losec_response` frame, and emits a `LoSecRequested` event.
    pub fn process_losec_request_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::routing::losec::{
            handle_losec_request, AmbientTrafficMonitor, ServiceLoSecConfig, SignedLoSecRequest,
        };
        use ed25519_dalek::SigningKey;

        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signed_req: SignedLoSecRequest = match serde_json::from_str(payload_str) {
            Ok(r) => r,
            Err(_) => return false,
        };

        let signing_key = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => SigningKey::from_bytes(&id.ed25519_signing.to_bytes()),
                None => return false,
            }
        };

        let mut monitor = AmbientTrafficMonitor::new();
        let active_tunnels = self
            .sdr
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .len();
        monitor.update(active_tunnels, active_tunnels as u64 * 1024);

        let service_config = ServiceLoSecConfig {
            allow_losec: true,
            allow_direct: true,
        };
        let signed_resp = handle_losec_request(
            &signed_req,
            &service_config,
            monitor.losec_available(),
            &signing_key,
        );

        let our_peer_id_hex = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .as_ref()
                .map(|id| id.peer_id().to_hex())
                .unwrap_or_default()
        };
        let session_id_hex = hex::encode(signed_req.request.session_id);

        if let Ok(resp_json) = serde_json::to_string(&signed_resp) {
            let frame = serde_json::json!({
                "type":       "losec_response",
                "sender":     our_peer_id_hex,
                "session_id": session_id_hex,
                "payload":    resp_json,
            });
            if let Ok(frame_bytes) = serde_json::to_vec(&frame) {
                let mut conns = self
                    .clearnet_connections
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(stream) = conns.get_mut(&sender_hex) {
                    use std::io::Write;
                    let len = (frame_bytes.len() as u32).to_be_bytes();
                    if let Err(e) = stream
                        .write_all(&len)
                        .and_then(|_| stream.write_all(&frame_bytes))
                    {
                        eprintln!("[transport] WARNING: failed to send losec_response to {sender_hex}: {e}");
                    }
                }
            }
        }

        self.push_event(
            "LoSecRequested",
            serde_json::json!({
                "peerId":           sender_hex,
                "sessionId":        session_id_hex,
                "accepted":         signed_resp.response.accepted,
                "rejectionReason":  signed_resp.response.rejection_reason,
            }),
        );
        true
    }

    /// Handle an inbound `losec_response` frame (§6.9.6).
    ///
    /// Parses the response and emits a `LoSecResponse` event so the Flutter UI
    /// can update the conversation's security mode indicator.
    pub fn process_losec_response_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::routing::losec::SignedLoSecResponse;

        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let session_id_hex = envelope
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signed_resp: SignedLoSecResponse = match serde_json::from_str(payload_str) {
            Ok(r) => r,
            Err(_) => return false,
        };

        self.push_event(
            "LoSecResponse",
            serde_json::json!({
                "peerId":           sender_hex,
                "sessionId":        session_id_hex,
                "accepted":         signed_resp.response.accepted,
                "rejectionReason":  signed_resp.response.rejection_reason,
            }),
        );
        true
    }

    // -----------------------------------------------------------------------
    // Store-and-forward frame handlers (§6.8)
    // -----------------------------------------------------------------------

    /// Handle an incoming `sf_deposit` frame (§6.8).
    ///
    /// Validates the request and, if S&F relay is enabled, buffers the message
    /// for delivery to the (currently offline) destination.
    pub fn process_sf_deposit_frame(&self, envelope: &serde_json::Value) -> bool {
        // Honour the S&F relay toggle (§17.13 module config).  When disabled,
        // this node silently consumes deposit requests without buffering them.
        // Returning true (not false) prevents the sender from retrying endlessly.
        let relay_enabled = {
            let mc = self.module_config.lock().unwrap_or_else(|e| e.into_inner());
            mc.social.store_forward
        };
        if !relay_enabled {
            // S&F disabled — silently consume the frame (not an error).
            return true;
        }

        let dest_hex = match envelope.get("destination").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let dest_bytes: [u8; 32] = match hex::decode(dest_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        let payload_hex = match envelope.get("payload_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let payload = match hex::decode(payload_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let expiry = envelope.get("expiry").and_then(|v| v.as_u64()).unwrap_or(0);
        let expiry_sig = hex::decode(
            envelope
                .get("expiry_sig")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )
        .unwrap_or_default();

        let priority = match envelope
            .get("priority")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
        {
            0 => Priority::Low,
            2 => Priority::High,
            3 => Priority::Critical,
            _ => Priority::Normal,
        };

        let request = StoreAndForwardRequest {
            destination: DeviceAddress(dest_bytes),
            payload,
            expiry,
            expiry_sig,
            priority,
            release_condition: ReleaseCondition::Immediate,
            application_id: None,
            cancellation_pubkey: None,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Derive a stable tunnel_id from the sender hex for per-sender rate
        // limiting.  A simple multiplicative hash is sufficient here — it only
        // needs to distinguish different senders, not be cryptographically secure.
        let sender_hex = envelope
            .get("sender")
            .and_then(|v| v.as_str())
            .unwrap_or("0");
        let tunnel_id = sender_hex
            .bytes()
            .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));

        let result = self
            .sf_server
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .deposit(request, tunnel_id, now);

        matches!(result, DepositResult::Accepted)
    }

    /// Handle an incoming `sf_deliver` frame (§6.8).
    ///
    /// A relay node is delivering a message that was stored for us.  The
    /// payload is the original application-layer encrypted frame, so we
    /// re-inject it through `process_inbound_frame` as if it arrived directly.
    pub fn process_sf_deliver_frame(&self, envelope: &serde_json::Value) -> bool {
        let payload_hex = match envelope.get("payload_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let payload = match hex::decode(payload_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        // Re-inject the payload as if it arrived directly from the network;
        // deserialise from JSON bytes first.
        match serde_json::from_slice::<serde_json::Value>(&payload) {
            Ok(envelope) => self.process_inbound_frame(&envelope),
            Err(_) => false,
        }
    }

    // -----------------------------------------------------------------------
    // Outbound gossip helper
    // -----------------------------------------------------------------------

    /// Broadcast our signed network map entry to a connected peer.
    ///
    /// Called after pairing or when a new clearnet connection is established.
    /// Gives the peer our preauth key so they can initiate X3DH (§7.0, H20).
    pub fn send_gossip_self_entry(&self, peer_id_hex: &str) {
        use crate::network::map::NetworkMapEntry;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Build transport hints from active services.
        let mut transport_hints: Vec<crate::network::transport_hint::TransportHint> = Vec::new();
        {
            let port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
            if self
                .clearnet_listener
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
            {
                if let Some(ip) = local_clearnet_ip() {
                    transport_hints.push(crate::network::transport_hint::TransportHint {
                        transport: crate::network::transport_hint::TransportType::Clearnet,
                        endpoint: Some(format!("{}:{}", ip, port)),
                    });
                }
            }
            let tor_guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref tor) = *tor_guard {
                transport_hints.push(crate::network::transport_hint::TransportHint {
                    transport: crate::network::transport_hint::TransportType::Tor,
                    endpoint: Some(format!("{}:{}", tor.onion_address, DEFAULT_HS_PORT)),
                });
            }
        }

        let self_entry = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                None => return,
                Some(id) => {
                    let kem_ek = if id.kem_encapsulation_key.is_empty() {
                        None
                    } else {
                        Some(id.kem_encapsulation_key.clone())
                    };

                    let preauth_sig = {
                        use crate::crypto::x3dh::PreauthBundle;
                        let msg = PreauthBundle::signed_message(&id.preauth_x25519_pub);
                        let secret = id.ed25519_signing.to_bytes();
                        Some(crate::crypto::signing::sign(
                            &secret,
                            crate::crypto::x3dh::PREAUTH_SIG_DOMAIN,
                            &msg,
                        ))
                    };

                    let mut entry = NetworkMapEntry {
                        peer_id: id.peer_id(),
                        public_keys: vec![crate::network::map::PublicKeyRecord {
                            ed25519_public: id.ed25519_pub,
                            x25519_public: *id.x25519_pub.as_bytes(),
                            preauth_x25519_public: Some(*id.preauth_x25519_pub.as_bytes()),
                            kem_encapsulation_key: kem_ek,
                            preauth_sig,
                        }],
                        version: crate::network::map::MAP_ENTRY_FORMAT_VERSION,
                        transport_hints,
                        prev_hash: None,
                        public_profile: None,
                        services: vec![],
                        sequence: now,
                        signature: vec![],
                        local_trust: TrustLevel::InnerCircle,
                    };
                    entry.sign(&id.ed25519_signing);
                    entry
                }
            }
        };

        // `sender` is our connection identity; the receiver charges its gossip
        // rate limit and source-diversity quorum to it (§4.1, §4.2) and drops
        // gossip frames that omit it.
        self.send_raw_frame(
            peer_id_hex,
            &serde_json::json!({
                "type":   "gossip_map_entry",
                "sender": self_entry.peer_id.to_hex(),
                "entry":  self_entry,
            }),
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(records) = self.local_garden_service_records(now) {
            for record in records {
                self.send_raw_frame(
                    peer_id_hex,
                    &serde_json::json!({
                        "type": "service_record",
                        "sender": self
                            .identity
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref()
                            .map(|identity| identity.peer_id().to_hex())
                            .unwrap_or_default(),
                        "record": record,
                    }),
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Two-way pairing hello helper
    // -----------------------------------------------------------------------

    /// Connect to `endpoint` (host:port), prove the far end is `peer_id_hex`
    /// via the link handshake (§5.1), and send a signed `pairing_hello`
    /// carrying the scanned `token`.
    ///
    /// The frame lets the remote peer learn our keys without scanning a second
    /// QR code.  If the connection or handshake fails (peer offline, NAT,
    /// wrong endpoint) we silently give up — the pairing will be completed
    /// next time they connect.
    fn send_pairing_hello_to(&self, peer_id_hex: &str, endpoint: &str, token: &[u8; 32]) {
        use crate::crypto::signing;
        use std::net::TcpStream;

        let (
            ed_bytes,
            x_bytes,
            mesh_x_bytes,
            display_name,
            our_peer_id_hex,
            signing_key_bytes,
            preauth_x25519_hex,
            kem_pub_bytes,
        ) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = match guard.as_ref() {
                Some(id) => id,
                None => return,
            };
            (
                id.ed25519_pub,
                *id.x25519_pub.as_bytes(),
                self.mesh_identity
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|identity| identity.public_bytes())
                    .unwrap_or([0u8; 32]),
                id.display_name.clone(),
                id.peer_id().to_hex(),
                id.ed25519_signing.to_bytes(),
                hex::encode(id.preauth_x25519_pub.as_bytes()),
                id.kem_encapsulation_key.clone(),
            )
        };
        // The hex form goes on the wire; the raw bytes go into the preimage,
        // and the receiver reconstructs the same bytes by decoding the hex.
        let kem_pub_hex = hex::encode(&kem_pub_bytes);

        // Sign: DOMAIN_PAIRING_HELLO | ed25519 | x25519 | token | BE32(kem_len) | kem_pub.
        let signed_msg = pairing_hello_preimage(&ed_bytes, &x_bytes, token, &kem_pub_bytes);
        let sig = signing::sign(
            &signing_key_bytes,
            signing::DOMAIN_PAIRING_HELLO,
            &signed_msg,
        );

        // Build transport hints.
        let port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let mut hints: Vec<serde_json::Value> = Vec::new();
        if self
            .clearnet_listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            let ip = local_clearnet_ip()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string());
            hints.push(serde_json::json!({
                "transport": "clearnet",
                "endpoint":  format!("{ip}:{port}"),
            }));
        }
        {
            let tor_guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref t) = *tor_guard {
                hints.push(serde_json::json!({
                    "transport": "tor",
                    "endpoint":  format!("{}:{}", t.onion_address, DEFAULT_HS_PORT),
                }));
            }
        }

        let frame_json = serde_json::json!({
            "type":                "pairing_hello",
            "sender":              our_peer_id_hex,
            "ed25519_public":      hex::encode(ed_bytes),
            "x25519_public":       hex::encode(x_bytes),
            "mesh_x25519_public":  hex::encode(mesh_x_bytes),
            "preauth_x25519_public": preauth_x25519_hex,
            "kem_pub":             kem_pub_hex,
            "pairing_token":       hex::encode(token),
            "display_name":        display_name,
            "transport_hints":     hints,
            "sig":                 hex::encode(&sig),
        });

        let payload = match serde_json::to_vec(&frame_json) {
            Ok(b) => b,
            Err(_) => return,
        };

        let addr: std::net::SocketAddr = match endpoint.parse() {
            Ok(a) => a,
            Err(_) => return,
        };

        let mut stream = match TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))
        {
            Ok(s) => s,
            Err(_) => return, // Peer offline — pairing completes on next connect.
        };

        // The scanned payload named a peer id; the endpoint is only a hint.
        // Prove we reached that peer before handing it our hello (§5.1).
        if let Err(e) = self.authenticate_outbound_link(&mut stream, peer_id_hex) {
            eprintln!("[transport] WARNING: pairing link to {endpoint} not authenticated: {e}");
            return;
        }

        // Best-effort write; log failure for diagnostics.
        if let Err(e) = write_tcp_frame(&mut stream, &payload) {
            eprintln!("[transport] WARNING: failed to send pairing frame to {endpoint}: {e}");
        }

        // Register the authenticated connection under the *peer's* id for reuse.
        if stream.set_nonblocking(true).is_ok() {
            self.clearnet_connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(peer_id_hex.to_string(), stream);
        }
    }

    // -----------------------------------------------------------------------
    // Pending pairing tokens (§8.3)
    // -----------------------------------------------------------------------

    /// Record a pairing token this device just embedded in a QR / link payload.
    ///
    /// Expired tokens are pruned first; the list is capped at
    /// `MAX_PENDING_PAIRINGS` with the oldest evicted, so a user mashing
    /// "regenerate" cannot grow it and a stranger cannot influence it at all
    /// (only local payload generation calls this).
    pub fn remember_pairing_token(&self, token: [u8; 32], expires_at: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut pending = self
            .pending_pairings
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pending.retain(|entry| entry.expires_at > now);
        while pending.len() >= MAX_PENDING_PAIRINGS {
            pending.remove(0);
        }
        pending.push(PendingPairing { token, expires_at });
    }

    /// Consume `token` if it is one we issued and has not expired.
    ///
    /// Single-use: a matching entry is removed whether or not the pairing
    /// then completes, so a captured hello cannot be replayed to re-add a
    /// peer the user has since removed.  Expired entries are pruned as a
    /// side effect.
    pub fn consume_pairing_token(&self, token: &[u8; 32], now: u64) -> bool {
        let mut pending = self
            .pending_pairings
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pending.retain(|entry| entry.expires_at > now);
        match pending.iter().position(|entry| entry.token == *token) {
            Some(index) => {
                pending.remove(index);
                true
            }
            None => false,
        }
    }

    // -----------------------------------------------------------------------
    // Admin commands (§3.9.3)
    // -----------------------------------------------------------------------

    /// Execute a delivered `AdminCommand` packet, or reject it.
    ///
    /// Returns `true` only if a command was verified and carried out.  Every
    /// rejection is reported to the local UI as `AdminCommandRejected` with a
    /// typed reason and never answered on the network.
    fn process_admin_command(&self, pkt: &MeshPacket, now: u64) -> bool {
        let source_hex = hex::encode(pkt.source);
        let outcome = pkt
            .payload_bytes()
            .ok_or(AdminCommandError::MalformedJson)
            .and_then(|payload| parse_admin_command(&payload))
            .and_then(|command| match command {
                AdminCommand::Killswitch(request) => {
                    self.authorise_remote_killswitch(pkt, &request, now)
                }
            });
        self.finish_remote_killswitch(&source_hex, outcome)
    }

    /// Carry out an authorised remote killswitch, or report why it was
    /// refused.
    ///
    /// Shared tail of every delivery path (`AdminCommand` packets and
    /// `remote_wipe` link frames): the only thing that erases the device is
    /// an `Ok` from the §3.9.3 verifier, and every `Err` becomes one local
    /// `AdminCommandRejected` event.  `source_hex` is the unauthenticated
    /// origin the rejection is reported under.  Returns `true` only if the
    /// device was erased.
    pub(crate) fn finish_remote_killswitch(
        &self,
        source_hex: &str,
        outcome: Result<String, AdminCommandError>,
    ) -> bool {
        match outcome {
            Ok(requester_hex) => match self.execute_remote_killswitch(&requester_hex) {
                Ok(()) => {
                    self.push_event(
                        "RemoteKillswitchExecuted",
                        serde_json::json!({ "sender": requester_hex }),
                    );
                    true
                }
                Err(reason) => {
                    // The executor re-checks trust; a disagreement here means
                    // the store changed between the two reads.  Drop.
                    self.push_event(
                        "AdminCommandRejected",
                        serde_json::json!({ "sender": source_hex, "reason": reason }),
                    );
                    false
                }
            },
            Err(error) => {
                self.push_event(
                    "AdminCommandRejected",
                    serde_json::json!({ "sender": source_hex, "reason": error.to_string() }),
                );
                false
            }
        }
    }

    /// Decide whether a remote killswitch packet may fire on this device.
    ///
    /// `MeshPacket::source` is checked for consistency with the signed
    /// requester id but grants nothing: a forged source with no valid
    /// signature is rejected the same as any other stranger.  Everything
    /// that actually authorises the erase lives in
    /// `authorise_killswitch_request`.  Returns the requester's peer id hex
    /// on success.
    fn authorise_remote_killswitch(
        &self,
        pkt: &MeshPacket,
        request: &RemoteKillswitchRequest,
        now: u64,
    ) -> Result<String, AdminCommandError> {
        if pkt.source != request.requester_id.0 {
            return Err(AdminCommandError::SourceMismatch);
        }
        self.authorise_killswitch_request(request, now)
    }

    /// The §3.9.3 verifier shared by every delivery path.
    ///
    /// The authority is the Ed25519 key the *local contact store* holds for
    /// the requester, and only if the user placed that contact at
    /// InnerCircle and enabled remote wipe.  In order, the request must:
    /// name this device as `target_peer_id` (one signature wipes one
    /// device), come from a known InnerCircle contact, arrive while remote
    /// wipe is enabled, sit inside the freshness window, verify under the
    /// stored key, and not have been presented before.  The replay cache is
    /// shared across paths, so a request captured from one carrier cannot
    /// be re-presented on another.  Returns the requester's peer id hex.
    pub(crate) fn authorise_killswitch_request(
        &self,
        request: &RemoteKillswitchRequest,
        now: u64,
    ) -> Result<String, AdminCommandError> {
        let our_id = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|id| id.peer_id())
        };
        if our_id != Some(request.target_peer_id) {
            return Err(AdminCommandError::WrongTarget);
        }
        // Trust and key both come from local state written by the user's
        // own pairing and trust decisions, never from the packet.
        let requester_key = {
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            let contact = contacts
                .get(&request.requester_id)
                .ok_or(AdminCommandError::UnknownRequester)?;
            if contact.trust_level != TrustLevel::InnerCircle {
                return Err(AdminCommandError::InsufficientTrust);
            }
            contact.ed25519_public
        };
        let enabled = *self
            .remote_wipe_enabled
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !enabled {
            return Err(AdminCommandError::RemoteWipeDisabled);
        }
        request.check_freshness(now)?;
        request.verify(&requester_key)?;
        // Recorded only after verification so garbage cannot churn the cache.
        let fresh = self
            .killswitch_replay
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(&request.signature);
        if !fresh {
            return Err(AdminCommandError::Replayed);
        }
        Ok(request.requester_id.to_hex())
    }
}

/// Bytes signed under `DOMAIN_PAIRING_HELLO` by both the hello sender and
/// its verifier:
/// `ed25519 (32) || x25519 (32) || pairing_token (32) || BE32(kem_len) || kem_pub`.
///
/// The token binds the hello to one payload the receiver issued (§8.3).  The
/// ML-KEM key is length-prefixed so an absent key (len 0) is itself
/// authenticated: a middlebox can neither strip nor replace it without
/// invalidating the signature (§3.4.1, §7.0.1). One shared helper keeps the
/// two sides from drifting apart.
fn pairing_hello_preimage(
    ed_bytes: &[u8; 32],
    x_bytes: &[u8; 32],
    token: &[u8; 32],
    kem_pub: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(96 + 4 + kem_pub.len());
    msg.extend_from_slice(ed_bytes);
    msg.extend_from_slice(x_bytes);
    msg.extend_from_slice(token);
    msg.extend_from_slice(&(kem_pub.len() as u32).to_be_bytes());
    msg.extend_from_slice(kem_pub);
    msg
}

/// Parse a 64-hex-char peer ID into a `PeerId`.
///
/// Rejects anything that is not exactly 32 bytes of hex so the caller never
/// looks up a truncated or padded ID by accident.
fn parse_peer_id_hex(peer_id_hex: &str) -> Result<PeerId, String> {
    let bytes = hex::decode(peer_id_hex).map_err(|_| "Invalid peer id".to_string())?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Invalid peer id".to_string())?;
    Ok(PeerId(array))
}

#[cfg(test)]
mod block_list_tests {
    use super::parse_peer_id_hex;
    use crate::identity::peer_id::PeerId;
    use crate::pairing::contact::ContactRecord;
    use crate::pairing::methods::PairingMethod;
    use crate::service::runtime::MeshRuntime;

    /// Insert a paired contact with a fixed peer ID; returns its hex ID.
    fn add_contact(runtime: &MeshRuntime) -> String {
        let pid = PeerId([0x5Au8; 32]);
        let contact = ContactRecord::new(pid, [0u8; 32], [0u8; 32], PairingMethod::QrCode, 0);
        runtime
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upsert(contact);
        pid.to_hex()
    }

    /// Block and unblock flip the contact flag and the peer list JSON mirrors
    /// it, which is what the contact screen's menu reads.
    #[test]
    fn block_and_unblock_round_trip_through_peer_list() {
        let runtime = MeshRuntime::new("target/test-block-round-trip".to_string());
        let peer_hex = add_contact(&runtime);
        assert!(!runtime.is_peer_blocked(&peer_hex));

        runtime.set_peer_blocked(&peer_hex, true).unwrap();
        assert!(runtime.is_peer_blocked(&peer_hex));
        let list: serde_json::Value = serde_json::from_str(&runtime.get_peer_list()).unwrap();
        assert_eq!(list[0]["blocked"], serde_json::Value::Bool(true));

        runtime.set_peer_blocked(&peer_hex, false).unwrap();
        assert!(!runtime.is_peer_blocked(&peer_hex));
        let list: serde_json::Value = serde_json::from_str(&runtime.get_peer_list()).unwrap();
        assert_eq!(list[0]["blocked"], serde_json::Value::Bool(false));
    }

    /// Unknown peers and malformed IDs can neither be blocked nor read as
    /// blocked; the error path must not panic or invent a record.
    #[test]
    fn block_rejects_unknown_and_malformed_peer_ids() {
        let runtime = MeshRuntime::new("target/test-block-unknown".to_string());
        let unknown = PeerId([0x01u8; 32]).to_hex();
        assert!(runtime.set_peer_blocked(&unknown, true).is_err());
        assert!(!runtime.is_peer_blocked(&unknown));
        assert!(runtime.set_peer_blocked("not-hex", true).is_err());
        assert!(!runtime.is_peer_blocked("abcd"));
        assert!(parse_peer_id_hex(&"ab".repeat(31)).is_err());
        assert!(parse_peer_id_hex(&"ab".repeat(32)).is_ok());
    }
}

#[cfg(test)]
mod gossip_attribution_tests {
    //! Service-level checks that `process_gossip_map_entry_frame` charges the
    //! §4.2 rate limit and the §4.1 source-diversity quorum to the frame's
    //! delivering `sender`, never to the entry owner, and that the v2 wire
    //! format (no peer-reported time) is enforced at the frame boundary.
    use crate::identity::peer_id::PeerId;
    use crate::network::map::{NetworkMapEntry, PublicKeyRecord, MAP_ENTRY_FORMAT_VERSION};
    use crate::service::runtime::MeshRuntime;
    use crate::trust::levels::TrustLevel;
    use ed25519_dalek::SigningKey;

    /// Self-signed v2 entry for a deterministic owner derived from `seed`.
    fn signed_entry(seed: u8, seq: u64) -> NetworkMapEntry {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let ed_pub = signing_key.verifying_key().to_bytes();
        let mut entry = NetworkMapEntry {
            version: MAP_ENTRY_FORMAT_VERSION,
            peer_id: PeerId::from_ed25519_pub(&ed_pub),
            public_keys: vec![PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: seq,
            signature: vec![],
            prev_hash: None,
            local_trust: TrustLevel::Unknown,
        };
        entry.sign(&signing_key);
        entry
    }

    /// A `gossip_map_entry` frame as the poll loop would hand it over,
    /// optionally without the connection-identifying `sender`.
    fn frame(sender: Option<&PeerId>, entry: &NetworkMapEntry) -> serde_json::Value {
        let mut v = serde_json::json!({ "type": "gossip_map_entry", "entry": entry });
        if let Some(s) = sender {
            v["sender"] = serde_json::Value::String(s.to_hex());
        }
        v
    }

    /// Seed the live map directly with `n` distinct owners so the quorum
    /// band under test is reached without going through the frame handler.
    fn seed_map(runtime: &MeshRuntime, n: u8) {
        let mut gossip = runtime.gossip.lock().unwrap_or_else(|e| e.into_inner());
        for i in 0..n {
            gossip
                .map
                .insert(signed_entry(0x10u8.wrapping_add(i), 1), 1_000)
                .unwrap();
        }
    }

    /// No `sender`, malformed `sender`: the frame is dropped before any
    /// attribution can happen, and nothing is merged.
    #[test]
    fn gossip_frame_without_valid_sender_is_dropped() {
        let runtime = MeshRuntime::new("target/test-gossip-no-sender".to_string());
        let entry = signed_entry(0x02, 1);
        assert!(!runtime.process_gossip_map_entry_frame(&frame(None, &entry)));
        let mut bad = frame(None, &entry);
        bad["sender"] = serde_json::Value::String("zz".repeat(32));
        assert!(!runtime.process_gossip_map_entry_frame(&bad));
        assert_eq!(
            runtime
                .gossip
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .map_size(),
            0
        );
    }

    /// At ≥100 live entries, 140 forged owners delivered by one connection
    /// are never promoted; a second, independent delivering connection
    /// completes the quorum for the same entry. This is exactly the case the
    /// owner-keyed attribution made impossible (quorum unreachable) and, had
    /// it been reachable, satisfiable by one attacker.
    #[test]
    fn gossip_quorum_is_charged_to_delivering_sender_not_entry_owner() {
        let runtime = MeshRuntime::new("target/test-gossip-quorum-sender".to_string());
        seed_map(&runtime, 100);
        let map_size = || {
            runtime
                .gossip
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .map_size()
        };
        assert_eq!(map_size(), 100);

        let attacker = PeerId([0xA0; 32]);
        for i in 0u8..140 {
            let entry = signed_entry(0x80u8.wrapping_add(i), 1);
            assert!(
                !runtime.process_gossip_map_entry_frame(&frame(Some(&attacker), &entry)),
                "entry from a single delivering connection must not be promoted"
            );
        }
        assert_eq!(
            map_size(),
            100,
            "one connection must not grow the map at ≥100"
        );

        // An independent second connection vouching for one of those entries
        // reaches the 2-source quorum and it is promoted.
        let honest = PeerId([0xB0; 32]);
        let entry = signed_entry(0x80, 1);
        assert!(runtime.process_gossip_map_entry_frame(&frame(Some(&honest), &entry)));
        assert_eq!(map_size(), 101);
    }

    /// A frame whose entry still carries the v1 self-reported `last_seen`
    /// is rejected at the deserialization boundary (CMR-005).
    #[test]
    fn gossip_frame_with_v1_last_seen_entry_is_dropped() {
        let runtime = MeshRuntime::new("target/test-gossip-v1-last-seen".to_string());
        let sender = PeerId([0x01; 32]);
        let mut v = frame(Some(&sender), &signed_entry(0x02, 1));
        v["entry"]["last_seen"] = serde_json::json!(1_700_000_000u64);
        assert!(!runtime.process_gossip_map_entry_frame(&v));
        assert_eq!(
            runtime
                .gossip
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .map_size(),
            0
        );
    }
}

#[cfg(test)]
mod admin_command_tests {
    use super::*;
    use crate::identity::self_identity::SelfIdentity;
    use crate::pairing::methods::PairingMethod;
    use tempfile::TempDir;

    /// A runtime with a fresh unlocked identity and all transports off.
    fn test_runtime() -> (TempDir, MeshRuntime) {
        let dir = TempDir::new().unwrap();
        let mut runtime = MeshRuntime::new(dir.path().to_string_lossy().into_owned());
        {
            let mut flags = runtime
                .transport_flags
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            flags.clearnet = false;
            flags.mesh_discovery = false;
        }
        runtime.create_identity(Some("Target".to_string())).unwrap();
        (dir, runtime)
    }

    /// The runtime's own peer id.
    fn our_peer_id(runtime: &MeshRuntime) -> PeerId {
        runtime
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .unwrap()
            .peer_id()
    }

    /// Register `peer` as a contact at `trust`, with its real identity key.
    fn add_contact(runtime: &MeshRuntime, peer: &SelfIdentity, trust: TrustLevel) {
        let mut contact = ContactRecord::new(
            peer.peer_id(),
            peer.ed25519_pub,
            peer.x25519_pub.to_bytes(),
            PairingMethod::QrCode,
            1,
        );
        contact.set_trust_level(trust);
        runtime
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upsert(contact);
    }

    /// Current unix seconds.
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Wrap `payload` in an `AdminCommand` packet addressed to the runtime,
    /// with the (unsigned, attacker-chosen) envelope source set to `source`.
    fn admin_packet(runtime: &MeshRuntime, source: &PeerId, payload: &[u8]) -> serde_json::Value {
        let pkt = MeshPacket::new(
            source.0,
            our_peer_id(runtime).0,
            PacketKind::AdminCommand,
            payload,
            now(),
        );
        serde_json::json!({ "type": "mesh_packet", "packet": pkt })
    }

    /// A properly signed request from `requester` targeting the runtime.
    fn signed_request(
        runtime: &MeshRuntime,
        requester: &SelfIdentity,
        timestamp: u64,
    ) -> RemoteKillswitchRequest {
        RemoteKillswitchRequest::sign(
            &our_peer_id(runtime),
            &requester.ed25519_pub,
            &requester.ed25519_signing.to_bytes(),
            timestamp,
        )
    }

    /// Whether the identity is still loaded (a wipe clears it).
    fn identity_intact(runtime: &MeshRuntime) -> bool {
        runtime
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Rejection reasons pushed to the UI, in order.
    fn rejection_reasons(runtime: &MeshRuntime) -> Vec<String> {
        runtime
            .event_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|event| event["type"] == "AdminCommandRejected")
            .map(|event| event["data"]["reason"].as_str().unwrap_or("").to_string())
            .collect()
    }

    /// Whether a `RemoteKillswitchExecuted` event was pushed.
    fn executed(runtime: &MeshRuntime) -> bool {
        runtime
            .event_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|event| event["type"] == "RemoteKillswitchExecuted")
    }

    /// Regression for the critical finding: an `AdminCommand` whose only
    /// "authority" is an envelope `source` naming an InnerCircle contact must
    /// not wipe anything, with or without a forged signature.
    #[test]
    fn unsigned_killswitch_with_forged_inner_circle_source_is_dropped() {
        let (_dir, runtime) = test_runtime();
        let requester = SelfIdentity::generate(Some("Inner".to_string()));
        add_contact(&runtime, &requester, TrustLevel::InnerCircle);
        *runtime.remote_wipe_enabled.lock().unwrap() = true;

        // The legacy unsigned command, exactly as the finding describes.
        let frame = admin_packet(&runtime, &requester.peer_id(), br#"{"type":"killswitch"}"#);
        assert!(!runtime.process_mesh_packet_frame(&frame));
        assert!(identity_intact(&runtime));
        assert_eq!(runtime.contacts.lock().unwrap().count(), 1);

        // A well-formed request naming the contact but signed by a stranger.
        let mallory = SelfIdentity::generate(None);
        let forged = RemoteKillswitchRequest::sign(
            &our_peer_id(&runtime),
            &requester.ed25519_pub,
            &mallory.ed25519_signing.to_bytes(),
            now(),
        );
        let bytes = serde_json::to_vec(&forged.to_json()).unwrap();
        let frame = admin_packet(&runtime, &requester.peer_id(), &bytes);
        assert!(!runtime.process_mesh_packet_frame(&frame));
        assert!(identity_intact(&runtime));
        assert_eq!(runtime.contacts.lock().unwrap().count(), 1);
        assert!(!executed(&runtime));
        assert_eq!(
            rejection_reasons(&runtime),
            vec![
                AdminCommandError::MissingField("target_peer_id").to_string(),
                AdminCommandError::BadSignature.to_string(),
            ]
        );
    }

    /// The genuine path still works: a request signed by an InnerCircle
    /// contact's own key, with remote wipe enabled, erases the device.
    #[test]
    fn signed_inner_circle_killswitch_wipes_device() {
        let (_dir, runtime) = test_runtime();
        let requester = SelfIdentity::generate(Some("Inner".to_string()));
        add_contact(&runtime, &requester, TrustLevel::InnerCircle);
        *runtime.remote_wipe_enabled.lock().unwrap() = true;

        let request = signed_request(&runtime, &requester, now());
        let bytes = serde_json::to_vec(&request.to_json()).unwrap();
        let frame = admin_packet(&runtime, &requester.peer_id(), &bytes);
        assert!(runtime.process_mesh_packet_frame(&frame));
        assert!(!identity_intact(&runtime));
        assert_eq!(runtime.contacts.lock().unwrap().count(), 0);
        assert!(executed(&runtime));
        assert!(rejection_reasons(&runtime).is_empty());
    }

    /// Every gate is checked from local state: the opt-in flag, InnerCircle
    /// trust, the target binding, freshness, source consistency and contact
    /// membership.  None of these failures touches the identity.
    #[test]
    fn signed_killswitch_requires_every_local_gate() {
        let (_dir, runtime) = test_runtime();
        let requester = SelfIdentity::generate(Some("Inner".to_string()));
        let our_id = our_peer_id(&runtime);
        let deliver = |payload: &RemoteKillswitchRequest, source: &PeerId| {
            let bytes = serde_json::to_vec(&payload.to_json()).unwrap();
            let frame = admin_packet(&runtime, source, &bytes);
            assert!(!runtime.process_mesh_packet_frame(&frame));
            assert!(identity_intact(&runtime));
        };
        let request = signed_request(&runtime, &requester, now());

        // Stranger: not a contact at all.
        deliver(&request, &requester.peer_id());
        // Contact below InnerCircle.
        add_contact(&runtime, &requester, TrustLevel::Ally);
        deliver(&request, &requester.peer_id());
        // InnerCircle but the user never enabled remote wipe.
        add_contact(&runtime, &requester, TrustLevel::InnerCircle);
        deliver(&request, &requester.peer_id());
        *runtime.remote_wipe_enabled.lock().unwrap() = true;
        // Envelope source disagrees with the signed requester.
        deliver(&request, &PeerId([0x99u8; 32]));
        // Signed for some other device.
        let other_target = RemoteKillswitchRequest::sign(
            &PeerId([0x42u8; 32]),
            &requester.ed25519_pub,
            &requester.ed25519_signing.to_bytes(),
            now(),
        );
        deliver(&other_target, &requester.peer_id());
        // Too old to honour.
        let stale = signed_request(
            &runtime,
            &requester,
            now() - crate::mesh::admin_command::KILLSWITCH_MAX_AGE_SECS - 60,
        );
        deliver(&stale, &requester.peer_id());

        assert_eq!(
            rejection_reasons(&runtime),
            vec![
                AdminCommandError::UnknownRequester.to_string(),
                AdminCommandError::InsufficientTrust.to_string(),
                AdminCommandError::RemoteWipeDisabled.to_string(),
                AdminCommandError::SourceMismatch.to_string(),
                AdminCommandError::WrongTarget.to_string(),
                AdminCommandError::StaleTimestamp.to_string(),
            ]
        );
        assert!(!executed(&runtime));
        assert_eq!(our_peer_id(&runtime), our_id);
    }

    /// A verified request is remembered: presenting the same signature again
    /// is refused before it reaches the executor.
    #[test]
    fn replayed_killswitch_signature_is_rejected() {
        let (_dir, runtime) = test_runtime();
        let requester = SelfIdentity::generate(Some("Inner".to_string()));
        add_contact(&runtime, &requester, TrustLevel::InnerCircle);
        *runtime.remote_wipe_enabled.lock().unwrap() = true;
        let request = signed_request(&runtime, &requester, now());
        let pkt = MeshPacket::new(
            requester.peer_id().0,
            our_peer_id(&runtime).0,
            PacketKind::AdminCommand,
            b"",
            now(),
        );
        assert_eq!(
            runtime.authorise_remote_killswitch(&pkt, &request, now()),
            Ok(requester.peer_id().to_hex())
        );
        assert_eq!(
            runtime.authorise_remote_killswitch(&pkt, &request, now()),
            Err(AdminCommandError::Replayed)
        );
        assert!(identity_intact(&runtime));
    }
}

#[cfg(test)]
mod pairing_hello_tests {
    use super::*;
    use crate::crypto::signing::{self, DOMAIN_PAIRING_HELLO};
    use crate::identity::self_identity::SelfIdentity;
    use tempfile::TempDir;

    /// A runtime ("Alice") with a fresh unlocked identity and transports off.
    fn test_runtime() -> (TempDir, MeshRuntime) {
        let dir = TempDir::new().unwrap();
        let mut runtime = MeshRuntime::new(dir.path().to_string_lossy().into_owned());
        {
            let mut flags = runtime
                .transport_flags
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            flags.clearnet = false;
            flags.mesh_discovery = false;
        }
        runtime.create_identity(Some("Alice".to_string())).unwrap();
        (dir, runtime)
    }

    /// Current unix seconds.
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Bob's `pairing_hello`, signed exactly as `send_pairing_hello_to`
    /// signs it.  `token == None` omits the field (and signs a zero token,
    /// which the receiver can never match).
    fn hello_frame(bob: &SelfIdentity, token: Option<&[u8; 32]>) -> serde_json::Value {
        let kem = bob.kem_encapsulation_key.clone();
        let signed_token = token.copied().unwrap_or([0u8; 32]);
        let msg = pairing_hello_preimage(
            &bob.ed25519_pub,
            &bob.x25519_pub.to_bytes(),
            &signed_token,
            &kem,
        );
        let sig = signing::sign(&bob.ed25519_signing.to_bytes(), DOMAIN_PAIRING_HELLO, &msg);
        let mut frame = serde_json::json!({
            "type":            "pairing_hello",
            "sender":          bob.peer_id().to_hex(),
            "ed25519_public":  hex::encode(bob.ed25519_pub),
            "x25519_public":   hex::encode(bob.x25519_pub.to_bytes()),
            "kem_pub":         hex::encode(&kem),
            "display_name":    "Bob",
            "transport_hints": [],
            "sig":             hex::encode(&sig),
        });
        if let Some(token) = token {
            frame["pairing_token"] = serde_json::json!(hex::encode(token));
        }
        frame
    }

    /// Everything a hello must not create for a stranger.
    fn assert_no_trace_of(runtime: &MeshRuntime, bob: &SelfIdentity) {
        assert!(runtime
            .contacts
            .lock()
            .unwrap()
            .get(&bob.peer_id())
            .is_none());
        assert!(!runtime
            .ratchet_sessions
            .lock()
            .unwrap()
            .contains_key(&bob.peer_id()));
        assert!(!runtime
            .event_queue
            .lock()
            .unwrap()
            .iter()
            .any(|event| event["type"] == "PeerAdded"));
    }

    /// A self-signed hello with no token is proof of a key, not of an
    /// invitation: it must leave no contact, session or event behind.
    #[test]
    fn hello_without_token_creates_no_contact() {
        let (_dir, runtime) = test_runtime();
        let bob = SelfIdentity::generate(Some("Bob".to_string()));
        assert!(!runtime.process_pairing_hello(&hello_frame(&bob, None)));
        assert_no_trace_of(&runtime, &bob);
    }

    /// A token Alice never issued, or one that has expired, is worthless.
    #[test]
    fn hello_with_unissued_or_expired_token_creates_no_contact() {
        let (_dir, runtime) = test_runtime();
        let bob = SelfIdentity::generate(Some("Bob".to_string()));
        let guessed = [0x33u8; 32];
        assert!(!runtime.process_pairing_hello(&hello_frame(&bob, Some(&guessed))));
        assert_no_trace_of(&runtime, &bob);

        let expired = [0x44u8; 32];
        runtime.remember_pairing_token(expired, now() - 1);
        assert!(!runtime.process_pairing_hello(&hello_frame(&bob, Some(&expired))));
        assert_no_trace_of(&runtime, &bob);
        // The expired record was pruned, not merely skipped.
        assert!(runtime.pending_pairings.lock().unwrap().is_empty());
    }

    /// A hello presenting a live issued token creates the contact; the token
    /// is then spent, so a second key holder cannot ride the same token.
    #[test]
    fn hello_with_issued_token_creates_contact_once() {
        let (_dir, runtime) = test_runtime();
        let bob = SelfIdentity::generate(Some("Bob".to_string()));
        let token = [0x55u8; 32];
        runtime.remember_pairing_token(token, now() + 30);

        assert!(runtime.process_pairing_hello(&hello_frame(&bob, Some(&token))));
        let contact = runtime
            .contacts
            .lock()
            .unwrap()
            .get(&bob.peer_id())
            .cloned()
            .expect("contact created");
        assert_eq!(contact.ed25519_public, bob.ed25519_pub);
        assert!(runtime
            .event_queue
            .lock()
            .unwrap()
            .iter()
            .any(|event| event["type"] == "PeerAdded"));
        assert!(
            !runtime.consume_pairing_token(&token, now()),
            "token must be spent"
        );

        // Carol replays the token with her own key: no second contact.
        let carol = SelfIdentity::generate(Some("Carol".to_string()));
        assert!(!runtime.process_pairing_hello(&hello_frame(&carol, Some(&token))));
        assert!(runtime
            .contacts
            .lock()
            .unwrap()
            .get(&carol.peer_id())
            .is_none());
        assert_eq!(runtime.contacts.lock().unwrap().count(), 1);
    }

    /// The issued-token list is bounded; the oldest entry is evicted first.
    #[test]
    fn pending_pairings_are_bounded() {
        let (_dir, runtime) = test_runtime();
        let expires = now() + 60;
        for i in 0..=MAX_PENDING_PAIRINGS {
            runtime.remember_pairing_token([i as u8; 32], expires);
        }
        assert_eq!(
            runtime.pending_pairings.lock().unwrap().len(),
            MAX_PENDING_PAIRINGS
        );
        assert!(!runtime.consume_pairing_token(&[0u8; 32], now()));
        assert!(runtime.consume_pairing_token(&[MAX_PENDING_PAIRINGS as u8; 32], now()));
    }

    /// Issuing a pairing payload records its token, so a hello answering a
    /// real QR scan is honoured.
    #[test]
    fn pairing_payload_token_admits_a_hello() {
        let (_dir, runtime) = test_runtime();
        let payload: serde_json::Value =
            serde_json::from_str(&runtime.get_pairing_payload().unwrap()).unwrap();
        let token: [u8; 32] = hex::decode(payload["pairing_token"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let bob = SelfIdentity::generate(Some("Bob".to_string()));
        assert!(runtime.process_pairing_hello(&hello_frame(&bob, Some(&token))));
        assert!(runtime
            .contacts
            .lock()
            .unwrap()
            .get(&bob.peer_id())
            .is_some());
    }
}
