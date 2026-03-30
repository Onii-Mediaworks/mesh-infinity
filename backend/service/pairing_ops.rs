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
use crate::pairing::contact::ContactRecord;
use crate::routing::announcement::ReachabilityAnnouncement;
use crate::routing::table::{DeviceAddress, RoutingEntry};
use crate::service::runtime::{MeshRuntime, bootstrap_ratchet_session, write_tcp_frame, local_clearnet_ip, DEFAULT_HS_PORT};
use crate::routing::store_forward::{StoreAndForwardRequest, ReleaseCondition, Priority, DepositResult};
use crate::mesh::{MeshPacket, PacketKind};
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
        // Parse the pairing payload — this was scanned from a QR code or received
        // as a deep link.  The payload is signed by Alice's identity key in the
        // QR generation step, but we verify the signature later during the
        // challenge-response handshake, not here (Bob's trust in the QR is
        // established by the physical proximity of scanning it).
        let payload: serde_json::Value = serde_json::from_str(payload_json)
            .map_err(|_| "Payload is not valid JSON".to_string())?;

        // Extract required Ed25519 public key — this is Alice's long-term
        // identity key from which her PeerId is derived.
        let ed_hex = payload.get("ed25519_public").and_then(|v| v.as_str())
            .ok_or("Missing ed25519_public")?;
        let ed_bytes: [u8; 32] = hex::decode(ed_hex)
            .ok().filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a })
            .ok_or("Invalid ed25519_public")?;

        // Extract required X25519 public key.
        let x_hex = payload.get("x25519_public").and_then(|v| v.as_str())
            .ok_or("Missing x25519_public")?;
        let x_bytes: [u8; 32] = hex::decode(x_hex)
            .ok().filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a })
            .ok_or("Invalid x25519_public")?;

        // Derive the canonical peer ID by hashing the Ed25519 public key.
        // This gives a stable identifier that does not change if the peer
        // rotates their X25519 preauth key (which happens weekly).
        let peer_id = PeerId::from_ed25519_pub(&ed_bytes);
        let name    = payload.get("display_name").and_then(|v| v.as_str()).map(|s| s.to_string());

        // Extract optional preauth X25519 public key (their SPK for X3DH).
        let preauth_pub_bytes: Option<[u8; 32]> = payload
            .get("preauth_x25519_public")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });

        // Extract transport hints.
        let hints = payload.get("transport_hints")
            .and_then(|h| h.as_array()).cloned().unwrap_or_default();
        let clearnet_endpoint = hints.iter().find(|h| {
            h.get("transport").and_then(|t| t.as_str()) == Some("clearnet")
        }).and_then(|h| h.get("endpoint")).and_then(|e| e.as_str()).map(|s| s.to_string());
        let tor_endpoint = hints.iter().find(|h| {
            h.get("transport").and_then(|t| t.as_str()) == Some("tor")
        }).and_then(|h| h.get("endpoint")).and_then(|e| e.as_str()).map(|s| s.to_string());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        let mut contact = ContactRecord::new(
            peer_id,
            ed_bytes,
            x_bytes,
            crate::pairing::methods::PairingMethod::LinkShare,
            now,
        );
        contact.display_name      = name.clone();
        contact.clearnet_endpoint = clearnet_endpoint;
        contact.tor_endpoint      = tor_endpoint;

        // Store ML-KEM-768 encapsulation key if advertised (PQXDH §3.4.1).
        // This enables post-quantum key exchange with this peer; if absent,
        // the session will use classical X3DH only.
        contact.kem_encapsulation_key = payload
            .get("kem_pub")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == crate::crypto::x3dh::KEM_EK_SIZE);

        // Store their preauth pub — Alice uses it to initiate X3DH.
        if let Some(preauth_bytes) = preauth_pub_bytes {
            let preauth_sig_opt: Option<Vec<u8>> = payload
                .get("preauth_sig")
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok())
                .filter(|b| b.len() == 64);
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
                        self.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner())
                            .insert(peer_id, header);
                    }
                    if let Some(pq) = pq_ext {
                        self.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner())
                            .insert(peer_id, pq);
                    }
                    drop(guard);
                    self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
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
        self.contacts.lock().unwrap_or_else(|e| e.into_inner()).upsert(contact);
        self.save_contacts();

        // Two-way pairing hello (§8.3): send our own keys back to Alice so
        // she can add Bob without needing to scan a second QR code.  This
        // completes the pairing in one scan rather than two.
        if let Some(ref ep) = clearnet_ep {
            self.send_pairing_hello_to(ep);
        }

        // Announce our network map entry to the new peer.
        let peer_id_hex = hex::encode(peer_id.0);
        self.send_gossip_self_entry(&peer_id_hex);

        // Broadcast a fresh self-reachability announcement to all current peers.
        self.broadcast_self_route_announcement();

        // Emit PeerAdded event for the UI.
        self.push_event("PeerAdded", serde_json::json!({
            "id":               hex::encode(peer_id.0),
            "name":             name.as_deref().unwrap_or(""),
            "trustLevel":       0,
            "status":           "offline",
            "canBeExitNode":    false,
            "canBeWrapperNode": false,
            "canBeStoreForward": false,
            "canEndorsePeers":  false,
            "latencyMs":        serde_json::Value::Null,
        }));

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
    /// The frame signature covers `DOMAIN_PAIRING_HELLO | ed25519_bytes | x25519_bytes`
    /// (display_name is intentionally excluded — it is an untrusted display hint).
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
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };

        let x_hex = match envelope.get("x25519_public").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let x_bytes: [u8; 32] = match hex::decode(x_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };

        let sig_hex = match envelope.get("sig").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // SECURITY: Verify the Ed25519 signature over DOMAIN_PAIRING_HELLO || ed_bytes || x_bytes.
        // The domain separator prevents cross-protocol signature reuse.
        // The display_name is intentionally NOT signed — it is an untrusted
        // display hint that the user can see and override via the contact's
        // local nickname setting.  An attacker cannot impersonate a different
        // peer because the peer_id is derived from the (signed) ed25519 key.
        let mut signed_msg = Vec::with_capacity(64);
        signed_msg.extend_from_slice(&ed_bytes);
        signed_msg.extend_from_slice(&x_bytes);
        if !signing::verify(&ed_bytes, signing::DOMAIN_PAIRING_HELLO, &signed_msg, &sig_bytes) {
            // Signature invalid — possibly corrupted or forged frame.
            // Silently discard (§7.2 error-silence rule).
            return false;
        }

        // Derive the canonical peer_id from the verified Ed25519 key.
        let peer_id = PeerId::from_ed25519_pub(&ed_bytes);

        // Idempotent: if we already have this peer in our contact store,
        // re-emit PeerAdded to synchronise the Flutter UI (the UI may have
        // been restarted or missed the original event).
        if self.contacts.lock().unwrap_or_else(|e| e.into_inner()).get(&peer_id).is_some() {
            let name = envelope.get("display_name").and_then(|v| v.as_str()).unwrap_or("");
            self.push_event("PeerAdded", serde_json::json!({
                "id":               hex::encode(peer_id.0),
                "name":             name,
                "trustLevel":       0,
                "status":           "online",
                "canBeExitNode":    false,
                "canBeWrapperNode": false,
                "canBeStoreForward": false,
                "canEndorsePeers":  false,
                "latencyMs":        serde_json::Value::Null,
            }));
            return true;
        }

        let display_name = envelope.get("display_name")
            .and_then(|v| v.as_str()).map(|s| s.to_string());

        // Extract optional preauth and KEM keys.
        let preauth_pub_bytes: Option<[u8; 32]> = envelope
            .get("preauth_x25519_public")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
        let preauth_sig_opt: Option<Vec<u8>> = envelope
            .get("preauth_sig")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 64);

        let hints_arr = envelope.get("transport_hints")
            .and_then(|h| h.as_array()).cloned().unwrap_or_default();
        let clearnet_endpoint = hints_arr.iter().find(|h| {
            h.get("transport").and_then(|t| t.as_str()) == Some("clearnet")
        }).and_then(|h| h.get("endpoint")).and_then(|e| e.as_str()).map(|s| s.to_string());
        let tor_endpoint = hints_arr.iter().find(|h| {
            h.get("transport").and_then(|t| t.as_str()) == Some("tor")
        }).and_then(|h| h.get("endpoint")).and_then(|e| e.as_str()).map(|s| s.to_string());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        let mut contact = ContactRecord::new(
            peer_id,
            ed_bytes,
            x_bytes,
            crate::pairing::methods::PairingMethod::LinkShare,
            now,
        );
        contact.display_name      = display_name.clone();
        contact.clearnet_endpoint = clearnet_endpoint;
        contact.tor_endpoint      = tor_endpoint;
        contact.kem_encapsulation_key = envelope
            .get("kem_pub")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == crate::crypto::x3dh::KEM_EK_SIZE);
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
                        self.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner())
                            .insert(peer_id, header);
                    }
                    if let Some(pq) = pq_ext {
                        self.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner())
                            .insert(peer_id, pq);
                    }
                    drop(guard);
                    self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                        .insert(peer_id, session);
                }
            }
        }

        self.contacts.lock().unwrap_or_else(|e| e.into_inner()).upsert(contact);
        self.save_contacts();

        // Add a local-plane routing entry for the new peer.
        {
            let dest  = DeviceAddress(peer_id.0);
            let entry = RoutingEntry {
                destination:     dest,
                next_hop:        dest,
                hop_count:       1,
                latency_ms:      10,
                next_hop_trust:  TrustLevel::Unknown,
                last_updated:    now,
                announcement_id: [0u8; 32],
            };
            self.routing_table.lock().unwrap_or_else(|e| e.into_inner()).update_local(entry);
        }

        // Reply with our own network map entry so the new peer has our preauth key.
        let peer_id_hex = hex::encode(peer_id.0);
        self.send_gossip_self_entry(&peer_id_hex);

        self.push_event("PeerAdded", serde_json::json!({
            "id":               hex::encode(peer_id.0),
            "name":             display_name.as_deref().unwrap_or(""),
            "trustLevel":       0,
            "status":           "online",
            "canBeExitNode":    false,
            "canBeWrapperNode": false,
            "canBeStoreForward": false,
            "canEndorsePeers":  false,
            "latencyMs":        serde_json::Value::Null,
        }));

        true
    }

    // -----------------------------------------------------------------------
    // Peer list
    // -----------------------------------------------------------------------

    /// Return a JSON array of all known peers from the contact store.
    pub fn get_peer_list(&self) -> String {
        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
        let peers: Vec<serde_json::Value> = contacts.all().iter().map(|c| {
            serde_json::json!({
                "id":               hex::encode(c.peer_id.0),
                "name":             c.display_name.as_deref()
                    .or(c.local_nickname.as_deref())
                    .unwrap_or(&c.peer_id.short_hex()),
                "trustLevel":       c.trust_level.value(),
                "status":           if c.last_seen.is_some() { "online" } else { "offline" },
                "canBeExitNode":    c.can_be_exit_node,
                "canBeWrapperNode": c.can_be_wrapper_node,
                "canBeStoreForward": c.can_be_store_forward,
                "canEndorsePeers":  c.can_endorse_peers,
                "latencyMs":        c.latency_ms,
            })
        }).collect();
        serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string())
    }

    // -----------------------------------------------------------------------
    // Trust operations
    // -----------------------------------------------------------------------

    /// Set the trust level for a peer.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` if the peer is not found or
    /// the level is invalid.
    pub fn set_trust_level(&self, peer_id_hex: &str, level: u8) -> Result<(), String> {
        let trust = TrustLevel::from_value(level)
            .ok_or_else(|| "Invalid trust level".to_string())?;
        let pid_bytes: [u8; 32] = hex::decode(peer_id_hex)
            .ok().filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a })
            .ok_or_else(|| "Invalid peer id".to_string())?;
        let pid = PeerId(pid_bytes);
        {
            let mut contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            let contact = contacts.get_mut(&pid)
                .ok_or_else(|| "Peer not found".to_string())?;
            contact.set_trust_level(trust);
        }
        self.push_event("TrustUpdated", serde_json::json!({
            "peerId":     peer_id_hex,
            "trustLevel": level,
        }));
        self.save_contacts();
        Ok(())
    }

    /// Return a JSON object with the trust and verification status of a peer.
    pub fn trust_verify(&self, peer_id_hex: &str) -> String {
        let pid_bytes: [u8; 32] = match hex::decode(peer_id_hex)
            .ok().filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a })
        {
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
            }).to_string(),
            None => r#"{"verified": false, "error": "peer not found"}"#.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Gossip map entry handler (§4.1)
    // -----------------------------------------------------------------------

    /// Process an inbound `gossip_map_entry` frame (§4.1).
    ///
    /// Validates the Ed25519 signature, merges into the local network map, and
    /// updates the matching contact's preauth_key + transport hints if the peer
    /// is known.
    pub fn process_gossip_map_entry_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::network::map::NetworkMapEntry;

        let entry_val = match envelope.get("entry") {
            Some(v) => v.clone(),
            None => return false,
        };
        let entry: NetworkMapEntry = match serde_json::from_value(entry_val) {
            Ok(e) => e,
            Err(_) => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        let entry_peer_id = entry.peer_id;

        // Merge into the gossip engine's network map.  The gossip engine handles
        // deduplication (via sequence numbers), age checks, and signature
        // verification internally.  It returns false if the entry was stale,
        // duplicate, or had an invalid signature.
        let accepted = {
            let mut gossip = self.gossip.lock().unwrap_or_else(|e| e.into_inner());
            gossip.receive_entry(entry.clone(), &entry_peer_id, TrustLevel::Unknown, now)
                .unwrap_or(false)
        };

        if !accepted { return false; }

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
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let from_addr = DeviceAddress(from_bytes);

        let neighbour_trust = {
            let from_peer_id = PeerId(from_bytes);
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            contacts.get(&from_peer_id)
                .map(|c| c.trust_level)
                .unwrap_or(TrustLevel::Unknown)
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        let result = {
            let mut proc = self.announcement_processor.lock().unwrap_or_else(|e| e.into_inner());
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
                        let our_hex = self.identity.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref().map(|id| hex::encode(id.peer_id().0))
                            .unwrap_or_default();
                        let fwd_frame = serde_json::json!({
                            "type": "route_announcement",
                            "from": our_hex,
                            "announcement": fwd_ann,
                        });
                        let peers: Vec<String> = self.clearnet_connections
                            .lock().unwrap_or_else(|e| e.into_inner())
                            .keys().cloned().collect();
                        for peer_hex in peers {
                            if peer_hex == from_hex { continue; }
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
        use crate::mesh::forwarder::{ForwardEngine, ForwardDecision};

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
            .map(|d| d.as_secs()).unwrap_or(0);

        let dest = pkt.dest_address();

        let route_entry = {
            let table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
            table.lookup(&dest, None, now).cloned()
        };

        let decision = {
            let mut dedup = self.dedup_cache.lock().unwrap_or_else(|e| e.into_inner());
            ForwardEngine::decide(
                &crate::mesh::forwarder::PacketHeader {
                    packet_id:   pkt.packet_id,
                    destination: dest,
                    ttl:         pkt.ttl,
                    timestamp:   pkt.timestamp,
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
                        // Deserialise from JSON bytes before re-injecting.
                        if let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&payload) {
                            return self.process_inbound_frame(&envelope);
                        }
                    }
                }
                self.push_event("MeshPacketDelivered", serde_json::json!({
                    "source": hex::encode(pkt.source),
                    "kind":   format!("{:?}", pkt.kind),
                    "size":   pkt.payload_hex.len() / 2,
                }));
                true
            }
            ForwardDecision::Forward { next_hop } => {
                if !pkt.decrement_ttl() { return false; }
                let next_hop_hex = hex::encode(next_hop.0);
                self.send_raw_frame(&next_hop_hex, &serde_json::json!({
                    "type":   "mesh_packet",
                    "packet": pkt,
                }));
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
            handle_losec_request, AmbientTrafficMonitor,
            ServiceLoSecConfig, SignedLoSecRequest,
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
        let active_tunnels = self.sdr.lock().unwrap_or_else(|e| e.into_inner()).sessions.len();
        monitor.update(active_tunnels, active_tunnels as u64 * 1024);

        let service_config = ServiceLoSecConfig { allow_losec: true, allow_direct: true };
        let signed_resp = handle_losec_request(
            &signed_req, &service_config, monitor.losec_available(), &signing_key,
        );

        let our_peer_id_hex = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default()
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
                let mut conns = self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(stream) = conns.get_mut(&sender_hex) {
                    use std::io::Write;
                    let len = (frame_bytes.len() as u32).to_be_bytes();
                    if let Err(e) = stream.write_all(&len)
                        .and_then(|_| stream.write_all(&frame_bytes))
                    {
                        eprintln!("[transport] WARNING: failed to send losec_response to {sender_hex}: {e}");
                    }
                }
            }
        }

        self.push_event("LoSecRequested", serde_json::json!({
            "peerId":           sender_hex,
            "sessionId":        session_id_hex,
            "accepted":         signed_resp.response.accepted,
            "rejectionReason":  signed_resp.response.rejection_reason,
        }));
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
        let session_id_hex = envelope.get("session_id")
            .and_then(|v| v.as_str()).unwrap_or("").to_string();
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signed_resp: SignedLoSecResponse = match serde_json::from_str(payload_str) {
            Ok(r) => r,
            Err(_) => return false,
        };

        self.push_event("LoSecResponse", serde_json::json!({
            "peerId":           sender_hex,
            "sessionId":        session_id_hex,
            "accepted":         signed_resp.response.accepted,
            "rejectionReason":  signed_resp.response.rejection_reason,
        }));
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
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
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

        let expiry     = envelope.get("expiry").and_then(|v| v.as_u64()).unwrap_or(0);
        let expiry_sig = hex::decode(
            envelope.get("expiry_sig").and_then(|v| v.as_str()).unwrap_or("")
        ).unwrap_or_default();

        let priority = match envelope.get("priority").and_then(|v| v.as_u64()).unwrap_or(1) {
            0 => Priority::Low,
            2 => Priority::High,
            3 => Priority::Critical,
            _ => Priority::Normal,
        };

        let request = StoreAndForwardRequest {
            destination:         DeviceAddress(dest_bytes),
            payload,
            expiry,
            expiry_sig,
            priority,
            release_condition:   ReleaseCondition::Immediate,
            application_id:      None,
            cancellation_pubkey: None,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        // Derive a stable tunnel_id from the sender hex for per-sender rate
        // limiting.  A simple multiplicative hash is sufficient here — it only
        // needs to distinguish different senders, not be cryptographically secure.
        let sender_hex = envelope.get("sender").and_then(|v| v.as_str()).unwrap_or("0");
        let tunnel_id  = sender_hex.bytes().fold(
            0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64),
        );

        let result = self.sf_server.lock().unwrap_or_else(|e| e.into_inner())
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
            .map(|d| d.as_secs()).unwrap_or(0);

        // Build transport hints from active services.
        let mut transport_hints: Vec<crate::network::transport_hint::TransportHint> = Vec::new();
        {
            let port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
            if self.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                if let Some(ip) = local_clearnet_ip() {
                    transport_hints.push(crate::network::transport_hint::TransportHint {
                        transport: crate::network::transport_hint::TransportType::Clearnet,
                        endpoint:  Some(format!("{}:{}", ip, port)),
                    });
                }
            }
            let tor_guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref tor) = *tor_guard {
                transport_hints.push(crate::network::transport_hint::TransportHint {
                    transport: crate::network::transport_hint::TransportType::Tor,
                    endpoint:  Some(format!("{}:{}", tor.onion_address, DEFAULT_HS_PORT)),
                });
            }
        }

        let self_entry = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                None => return,
                Some(id) => {
                    let kem_ek = if id.kem_encapsulation_key.is_empty() { None }
                        else { Some(id.kem_encapsulation_key.clone()) };

                    let preauth_sig = {
                        use crate::crypto::x3dh::PreauthBundle;
                        let msg    = PreauthBundle::signed_message(&id.preauth_x25519_pub);
                        let secret = id.ed25519_signing.to_bytes();
                        Some(crate::crypto::signing::sign(
                            &secret,
                            crate::crypto::x3dh::PREAUTH_SIG_DOMAIN,
                            &msg,
                        ))
                    };

                    let mut entry = NetworkMapEntry {
                        peer_id:         id.peer_id(),
                        public_keys:     vec![crate::network::map::PublicKeyRecord {
                            ed25519_public:        id.ed25519_pub,
                            x25519_public:         *id.x25519_pub.as_bytes(),
                            preauth_x25519_public: Some(*id.preauth_x25519_pub.as_bytes()),
                            kem_encapsulation_key: kem_ek,
                            preauth_sig,
                        }],
                        last_seen:        now,
                        transport_hints,
                        public_profile:   None,
                        services:         vec![],
                        sequence:         now,
                        signature:        vec![],
                        local_trust:      TrustLevel::InnerCircle,
                    };
                    entry.sign(&id.ed25519_signing);
                    entry
                }
            }
        };

        self.send_raw_frame(peer_id_hex, &serde_json::json!({
            "type":  "gossip_map_entry",
            "entry": self_entry,
        }));
    }

    // -----------------------------------------------------------------------
    // Two-way pairing hello helper
    // -----------------------------------------------------------------------

    /// Connect to `endpoint` (host:port) and send a signed `pairing_hello` frame.
    ///
    /// The frame lets the remote peer learn our keys without scanning a second
    /// QR code.  Non-blocking: if the connection fails (peer offline, NAT) we
    /// silently ignore — the pairing will be completed next time they connect.
    fn send_pairing_hello_to(&self, endpoint: &str) {
        use crate::crypto::signing;
        use std::net::TcpStream;

        let (ed_bytes, x_bytes, display_name, peer_id_hex, signing_key_bytes,
             preauth_x25519_hex, kem_pub_hex) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = match guard.as_ref() {
                Some(id) => id,
                None => return,
            };
            (
                id.ed25519_pub,
                *id.x25519_pub.as_bytes(),
                id.display_name.clone(),
                id.peer_id().to_hex(),
                id.ed25519_signing.to_bytes(),
                hex::encode(id.preauth_x25519_pub.as_bytes()),
                hex::encode(&id.kem_encapsulation_key),
            )
        };

        // Sign: DOMAIN_PAIRING_HELLO | ed25519_bytes | x25519_bytes.
        let mut signed_msg = Vec::with_capacity(64);
        signed_msg.extend_from_slice(&ed_bytes);
        signed_msg.extend_from_slice(&x_bytes);
        let sig = signing::sign(&signing_key_bytes, signing::DOMAIN_PAIRING_HELLO, &signed_msg);

        // Build transport hints.
        let port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let mut hints: Vec<serde_json::Value> = Vec::new();
        if self.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
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
            "sender":              peer_id_hex,
            "ed25519_public":      hex::encode(ed_bytes),
            "x25519_public":       hex::encode(x_bytes),
            "preauth_x25519_public": preauth_x25519_hex,
            "kem_pub":             kem_pub_hex,
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

        let mut stream = match TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)) {
            Ok(s) => s,
            Err(_) => return, // Peer offline — pairing completes on next connect.
        };

        // Best-effort write; log failure for diagnostics.
        if let Err(e) = write_tcp_frame(&mut stream, &payload) {
            eprintln!("[transport] WARNING: failed to send pairing frame to {endpoint}: {e}");
        }

        // Register the connection for reuse.
        let peer_id_hex_clone = peer_id_hex.clone();
        if let Ok(_) = stream.set_nonblocking(true) {
            self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner())
                .insert(peer_id_hex_clone, stream);
        }
    }
}
