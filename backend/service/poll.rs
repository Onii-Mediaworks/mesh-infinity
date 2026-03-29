//! Poll-cycle advance methods for `MeshRuntime`.
//!
//! `advance_clearnet_transport` is the master tick method called by
//! `mi_poll_events` on every poll cycle (~200 ms).  It dispatches to the
//! individual sub-system advance methods defined here and in `discovery.rs`.
//!
//! ## Keepalive policy (§5.1)
//! - If a peer has sent no data for > 30 s, send a `keepalive` frame.
//! - If a peer has sent no data for > 120 s, close the connection and mark
//!   them offline.
//! - At most one keepalive probe is sent per 10 s gap to avoid storms.

use crate::identity::peer_id::PeerId;
use crate::routing::table::DeviceAddress;
use crate::service::runtime::{MeshRuntime, FileDirection, CHUNKS_PER_TICK, FILE_CHUNK_SIZE};
use crate::service::runtime::{write_tcp_frame, try_read_frame, extract_frame_sender};
use crate::trust::levels::TrustLevel;
use crate::routing::table::RoutingEntry;

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Master tick
    // -----------------------------------------------------------------------

    /// Advance all transport sub-systems for one poll cycle.
    ///
    /// Called from `mi_poll_events` approximately every 200 ms.
    /// Returns after all non-blocking sub-system steps have been run.
    pub fn advance_clearnet_transport(&self) {
        // Accept new TCP connections and drain Tor inbound streams.
        self.clearnet_accept_new_connections();
        self.tor_drain_inbound();
        // Identify pending connections and process identified ones.
        self.clearnet_process_pending_incoming();
        self.clearnet_process_identified();
        // Retry any queued outbox messages.
        self.clearnet_flush_outbox();
        // LAN discovery ticks.
        self.advance_lan_discovery();
        self.advance_lan_discovery_handshakes();
        // File transfer chunks.
        self.advance_file_transfers();
        // S&F server GC, group rekeying, notifications, and gossip cleanup.
        self.advance_sf_gc();
        self.advance_group_rekeys();
        self.advance_notifications();
        self.advance_gossip_cleanup();
        // Keepalive probes and stale connection pruning.
        self.advance_keepalives();
    }

    // -----------------------------------------------------------------------
    // Keepalives
    // -----------------------------------------------------------------------

    /// Send keepalive probes to idle peers and close unresponsive ones.
    ///
    /// Policy (§5.1):
    /// - > 30 s no data received  → send keepalive frame (at most once per 10 s).
    /// - > 120 s no data received → close the connection; emit PeerUpdated(offline).
    pub fn advance_keepalives(&self) {
        /// Seconds of idle before we probe.
        const KEEPALIVE_INTERVAL_SECS: u64 = 30;
        /// Seconds of silence before declaring the peer dead.
        const KEEPALIVE_TIMEOUT_SECS: u64 = 120;
        /// Minimum gap between successive probes to the same peer.
        const KEEPALIVE_TX_MIN_GAP_SECS: u64 = 10;

        let now = std::time::Instant::now();

        // Snapshot the peer list without holding the lock across the loop body.
        let peer_ids: Vec<String> = self
            .clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();

        let mut to_drop: Vec<String> = Vec::new();

        for peer_hex in &peer_ids {
            // Read the last-received timestamp (None = never received data yet).
            let last_rx = {
                let map = self.clearnet_last_rx.lock().unwrap_or_else(|e| e.into_inner());
                map.get(peer_hex).copied()
            };
            let idle_secs = last_rx
                .map(|t| now.duration_since(t).as_secs())
                .unwrap_or(0);

            if idle_secs >= KEEPALIVE_TIMEOUT_SECS {
                // Peer has been silent too long — declare dead.
                to_drop.push(peer_hex.clone());
                continue;
            }

            if idle_secs >= KEEPALIVE_INTERVAL_SECS {
                // Check whether we sent a probe recently enough.
                let last_tx = {
                    let map = self
                        .clearnet_last_keepalive_tx
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    map.get(peer_hex).copied()
                };
                let tx_gap = last_tx
                    .map(|t| now.duration_since(t).as_secs())
                    .unwrap_or(u64::MAX);
                if tx_gap >= KEEPALIVE_TX_MIN_GAP_SECS {
                    // Send a lightweight probe frame and record the transmit time.
                    self.send_raw_frame(peer_hex, &serde_json::json!({"type": "keepalive"}));
                    self.clearnet_last_keepalive_tx
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(peer_hex.clone(), now);
                }
            }
        }

        // Close stale connections and update routing / Flutter state.
        for peer_hex in to_drop {
            // Remove all per-peer data structures atomically (best effort).
            self.clearnet_connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer_hex);
            self.clearnet_recv_buffers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer_hex);
            self.clearnet_last_rx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer_hex);
            self.clearnet_last_keepalive_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer_hex);

            // Remove the direct routing entry for this peer.
            if let Ok(bytes) = hex::decode(&peer_hex) {
                if bytes.len() == 32 {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&bytes);
                    self.routing_table
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove_local(&DeviceAddress(a));
                }
            }

            // Resolve display name and trust level for the event payload.
            let (display_name, trust_val) = {
                let peer_bytes_opt = hex::decode(&peer_hex)
                    .ok()
                    .filter(|b| b.len() == 32)
                    .map(|b| {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        a
                    });
                if let Some(pb) = peer_bytes_opt {
                    let pid = PeerId(pb);
                    let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                    contacts
                        .get(&pid)
                        .map(|c| (c.display_name.clone().unwrap_or_default(), c.trust_level as u8))
                        .unwrap_or_default()
                } else {
                    (String::new(), 0u8)
                }
            };

            // Emit PeerUpdated(offline) so Flutter removes the online badge.
            self.push_event(
                "PeerUpdated",
                serde_json::json!({
                    "id": peer_hex,
                    "name": display_name,
                    "trustLevel": trust_val,
                    "status": "offline",
                    "canBeExitNode": false,
                    "canBeWrapperNode": false,
                    "canBeStoreForward": false,
                    "canEndorsePeers": false,
                    "latencyMs": null,
                }),
            );
        }
    }

    // -----------------------------------------------------------------------
    // Route announcement
    // -----------------------------------------------------------------------

    /// Broadcast a signed reachability announcement for this node (§6.2).
    ///
    /// Called after successful pairing so all currently connected peers update
    /// their routing tables with a fresh direct route to us.
    pub fn broadcast_self_route_announcement(&self) {
        use crate::crypto::signing;
        use crate::routing::announcement::{AnnouncementScope, ReachabilityAnnouncement};
        use crate::service::runtime::try_random_fill;

        // Gather our peer ID and Ed25519 signing key.
        let (peer_id_bytes, signing_key_bytes) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => (id.peer_id().0, id.ed25519_signing.to_bytes()),
                None => return, // Identity not yet unlocked.
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Generate a unique announcement ID for deduplication.
        let mut announcement_id = [0u8; 32];
        if !try_random_fill(&mut announcement_id) {
            return;
        }

        // Sign: destination || announcement_id || timestamp.
        let mut signed_msg = Vec::with_capacity(72);
        signed_msg.extend_from_slice(&peer_id_bytes);
        signed_msg.extend_from_slice(&announcement_id);
        signed_msg.extend_from_slice(&now.to_be_bytes());
        let signature = signing::sign(
            &signing_key_bytes,
            signing::DOMAIN_ROUTING_ANNOUNCEMENT,
            &signed_msg,
        );

        let our_addr = DeviceAddress(peer_id_bytes);
        let announcement = ReachabilityAnnouncement {
            destination:     our_addr,
            hop_count:       0,
            latency_ms:      0,
            next_hop_trust:  TrustLevel::InnerCircle,
            announcement_id,
            timestamp:       now,
            scope:           AnnouncementScope::Public,
            signature,
        };

        let our_hex = hex::encode(peer_id_bytes);
        let ann_val = match serde_json::to_value(&announcement) {
            Ok(v) => v,
            Err(_) => return,
        };
        let frame = serde_json::json!({
            "type": "route_announcement",
            "from": our_hex,
            "announcement": ann_val,
        });

        // Broadcast to every currently identified clearnet peer.
        let peers: Vec<String> = self
            .clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        for peer_hex in peers {
            self.send_raw_frame(&peer_hex, &frame);
        }
    }

    /// Insert a direct local-plane routing entry for a freshly connected peer.
    ///
    /// `destination == next_hop` with `hop_count = 1` indicates a direct link.
    /// Trust level is read from the contact store.
    pub fn insert_local_route_for_peer(&self, peer_id_hex: &str) {
        let peer_bytes = match hex::decode(peer_id_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return,
        };
        let addr    = DeviceAddress(peer_bytes);
        let peer_id = PeerId(peer_bytes);

        let trust = {
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            contacts
                .get(&peer_id)
                .map(|c| c.trust_level)
                .unwrap_or(TrustLevel::Unknown)
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Zero announcement_id for direct entries — they are not gossip-originated.
        let entry = RoutingEntry {
            destination:     addr,
            next_hop:        addr,
            hop_count:       1,
            latency_ms:      0,
            next_hop_trust:  trust,
            last_updated:    now,
            announcement_id: [0u8; 32],
        };
        self.routing_table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .update_local(entry);
    }

    // -----------------------------------------------------------------------
    // Gossip / notifications / S&F GC
    // -----------------------------------------------------------------------

    /// Prune stale network-map entries from the gossip engine (§4.1, §4.5).
    pub fn advance_gossip_cleanup(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.gossip
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cleanup(now);
    }

    /// Drain coalesced notifications whose jitter window has closed (§14).
    ///
    /// Emits a `LocalNotification` event for each dispatched notification so
    /// Flutter can display a system notification or in-app badge.
    pub fn advance_notifications(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dispatched = self
            .notifications
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dispatch_ready(now);

        for notif in dispatched {
            let conv_id_hex = notif.conversation_id.map(hex::encode);
            self.push_event(
                "LocalNotification",
                serde_json::json!({
                    "title":          notif.title,
                    "body":           notif.body,
                    "conversationId": conv_id_hex,
                    "eventCount":     notif.event_count,
                    "priority":       format!("{:?}", notif.priority),
                    "tier":           format!("{:?}", notif.tier),
                }),
            );
        }
    }

    /// Garbage-collect the store-and-forward server (§6.8).
    ///
    /// Purges expired and already-delivered messages.  Cheap on most ticks.
    pub fn advance_sf_gc(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.sf_server
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .gc(now);
    }

    // -----------------------------------------------------------------------
    // Group Sender Key rekeying (§8.7.4, §8.7.5)
    // -----------------------------------------------------------------------

    /// Trigger scheduled Sender Key rekeying for groups we administer.
    ///
    /// For each admin group whose `rekey_interval_secs` has elapsed:
    /// 1. Generate a new 32-byte symmetric key.
    /// 2. Bump the epoch counter.
    /// 3. Distribute the new key to all currently-connected members via their
    ///    individual Double Ratchet sessions.
    /// 4. Persist updated group state to vault.
    pub fn advance_group_rekeys(&self) {
        use chacha20poly1305::{aead::{Aead, Nonce}, ChaCha20Poly1305, Key, KeyInit};
        use crate::service::runtime::try_random_fill;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Collect groups that need a rekey without holding the lock long.
        let rekey_targets: Vec<(usize, [u8; 32], Vec<[u8; 32]>)> = {
            let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            groups
                .iter()
                .enumerate()
                .filter(|(_, g)| g.is_admin && g.needs_rekey(now))
                .map(|(i, g)| {
                    let members: Vec<[u8; 32]> = g.members.iter().map(|m| m.0).collect();
                    (i, g.group_id, members)
                })
                .collect()
        };

        if rekey_targets.is_empty() {
            return;
        }

        for (idx, group_id, member_ids) in rekey_targets {
            // Generate fresh symmetric key material.
            let mut new_symmetric_key = [0u8; 32];
            if !try_random_fill(&mut new_symmetric_key) {
                continue;
            }

            // Update the group record and grab the new epoch.
            let new_epoch = {
                let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
                match groups.get_mut(idx) {
                    Some(group) => {
                        group.symmetric_key    = new_symmetric_key;
                        group.sender_key_epoch += 1;
                        group.last_rekey_at    = now;
                        group.sender_key_epoch
                    }
                    None => continue,
                }
            };

            let group_id_hex  = hex::encode(group_id);
            let new_key_hex   = hex::encode(new_symmetric_key);

            // Our own peer ID — skip when iterating members.
            let our_peer_id = self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|id| id.peer_id());

            for member_bytes in &member_ids {
                let member_id  = PeerId(*member_bytes);
                let member_hex = hex::encode(member_bytes);

                // Never send to ourselves.
                if Some(member_id) == our_peer_id {
                    continue;
                }

                // Build the rekey payload JSON.
                let rekey_payload = serde_json::json!({
                    "type":         "group_rekey",
                    "groupId":      group_id_hex,
                    "epoch":        new_epoch,
                    "symmetricKey": new_key_hex,
                });
                let payload_bytes = match serde_json::to_vec(&rekey_payload) {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                // Encrypt using this member's ratchet session.
                let encrypted_envelope: Option<serde_json::Value> = {
                    let mut sessions =
                        self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(session) = sessions.get_mut(&member_id) {
                        match session.next_send_msg_key() {
                            Ok((header, msg_key)) => {
                                let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
                                // All-zero 12-byte nonce — safe because msg_key is single-use.
                                let nonce = Nonce::<ChaCha20Poly1305>::default();
                                match cipher.encrypt(&nonce, payload_bytes.as_ref()) {
                                    Ok(ct) => {
                                        let x3dh_header = self
                                            .x3dh_pending
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .get(&member_id)
                                            .copied();
                                        let our_sender_hex = hex::encode(
                                            our_peer_id.map(|id| id.0).unwrap_or([0u8; 32]),
                                        );
                                        let mut envelope = serde_json::json!({
                                            "type":           "group_rekey",
                                            "sender":         our_sender_hex,
                                            "ratchet_header": serde_json::to_value(&header)
                                                .unwrap_or(serde_json::Value::Null),
                                            "ciphertext":     hex::encode(&ct),
                                        });
                                        // Attach X3DH init header if we haven't had a reply yet.
                                        if let Some((eph, ik)) = x3dh_header {
                                            if let Some(obj) = envelope.as_object_mut() {
                                                obj.insert(
                                                    "x3dh_eph_pub".to_string(),
                                                    serde_json::Value::String(hex::encode(eph)),
                                                );
                                                obj.insert(
                                                    "x3dh_encrypted_ik".to_string(),
                                                    serde_json::Value::String(hex::encode(ik)),
                                                );
                                            }
                                        }
                                        Some(envelope)
                                    }
                                    Err(_) => None,
                                }
                            }
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                };

                if let Some(frame) = encrypted_envelope {
                    self.send_raw_frame(&member_hex, &frame);
                }
            }
        }

        // Persist updated group state (new symmetric keys and epochs).
        self.save_groups();
    }

    // -----------------------------------------------------------------------
    // File transfer chunks
    // -----------------------------------------------------------------------

    /// Tick outgoing file transfers: send the next batch of chunks.
    ///
    /// Sends at most `CHUNKS_PER_TICK` chunks per active transfer per poll cycle
    /// to keep the event loop responsive.
    pub fn advance_file_transfers(&self) {
        use std::io::Read;

        let transfer_ids: Vec<String> = self
            .active_file_io
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();

        for tid in transfer_ids {
            // Snapshot direction and metadata without holding the lock over I/O.
            let (direction, peer_id, file_id, total_bytes) = {
                let map = self.active_file_io.lock().unwrap_or_else(|e| e.into_inner());
                match map.get(&tid) {
                    Some(s) => (
                        if s.direction == FileDirection::Send { "send" } else { "recv" },
                        s.peer_id.clone(),
                        s.file_id,
                        s.total_bytes,
                    ),
                    None => continue,
                }
            };

            if direction != "send" {
                continue; // Receive-side: data arrives via inbound frames.
            }

            for _ in 0..CHUNKS_PER_TICK {
                // Read the next chunk while holding the lock only for I/O.
                let chunk_data = {
                    let mut map = self.active_file_io.lock().unwrap_or_else(|e| e.into_inner());
                    let state = match map.get_mut(&tid) {
                        Some(s) => s,
                        None => break,
                    };
                    if state.transferred_bytes >= state.total_bytes {
                        break;
                    }
                    let mut buf = vec![0u8; FILE_CHUNK_SIZE];
                    let n = state.file.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.truncate(n);
                    let offset = state.transferred_bytes;
                    state.transferred_bytes += n as u64;
                    (buf, offset, state.file_id)
                };

                let (data, offset, fid) = chunk_data;
                let chunk_index = (offset / FILE_CHUNK_SIZE as u64) as u32;

                // Build and send the chunk frame.
                let frame = serde_json::json!({
                    "type":       "file_chunk",
                    "transferId": tid,
                    "fileId":     hex::encode(fid),
                    "chunkIndex": chunk_index,
                    "offset":     offset,
                    "data":       hex::encode(&data),
                });
                self.send_raw_frame(&peer_id, &frame);

                // Update the in-memory transfer record with new progress.
                let transferred = {
                    let map = self.active_file_io.lock().unwrap_or_else(|e| e.into_inner());
                    map.get(&tid).map(|s| s.transferred_bytes).unwrap_or(0)
                };
                {
                    let mut transfers =
                        self.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
                    for t in transfers.iter_mut() {
                        if t.get("id").and_then(|v| v.as_str()) == Some(&tid) {
                            if let Some(obj) = t.as_object_mut() {
                                obj.insert(
                                    "transferredBytes".to_string(),
                                    serde_json::Value::Number(transferred.into()),
                                );
                                if transferred >= total_bytes {
                                    obj.insert(
                                        "status".to_string(),
                                        serde_json::Value::String("completed".to_string()),
                                    );
                                }
                            }
                            break;
                        }
                    }
                }
                self.push_transfer_update(&tid);

                // When complete, remove from I/O map and notify the peer.
                if transferred >= total_bytes {
                    self.active_file_io
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&tid);
                    let complete_frame = serde_json::json!({
                        "type":       "file_complete",
                        "transferId": tid,
                        "fileId":     hex::encode(file_id),
                        "ok":         true,
                    });
                    self.send_raw_frame(&peer_id, &complete_frame);
                    break;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Clearnet TCP helpers
    // -----------------------------------------------------------------------

    /// Accept new TCP connections from the clearnet listener into the pending queue.
    pub fn clearnet_accept_new_connections(&self) {
        let new_streams: Vec<std::net::TcpStream> = {
            let guard = self.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner());
            let mut accepted = Vec::new();
            if let Some(ref listener) = *guard {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // Set non-blocking so the poll loop never stalls.
                            let _ = stream.set_nonblocking(true);
                            accepted.push(stream);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
            accepted
        };
        if !new_streams.is_empty() {
            let mut pending =
                self.clearnet_pending_incoming.lock().unwrap_or_else(|e| e.into_inner());
            for stream in new_streams {
                pending.push((stream, Vec::new()));
            }
        }
    }

    /// Drain inbound streams accepted by the Tor hidden-service transport.
    ///
    /// Inserts them into the same pending-incoming queue as clearnet
    /// connections so the normal identification path handles them.
    pub fn tor_drain_inbound(&self) {
        let new_streams: Vec<std::net::TcpStream> = {
            let guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(tor) => tor.drain_inbound(),
                None => Vec::new(),
            }
        };
        if !new_streams.is_empty() {
            let mut pending =
                self.clearnet_pending_incoming.lock().unwrap_or_else(|e| e.into_inner());
            for stream in new_streams {
                pending.push((stream, Vec::new()));
            }
        }
    }

    /// Read data from pending (unidentified) inbound connections.
    ///
    /// Once a complete frame arrives, extract the sender peer_id and promote
    /// the connection to the identified map.  LAN discovery probes are
    /// handled inline and the probe socket is immediately dropped.
    ///
    /// In Critical threat mode (isolation, §3.4), connections from unknown
    /// peers are silently dropped — the socket is closed without reply.
    pub fn clearnet_process_pending_incoming(&self) {
        use std::io::Read;

        let pending_conns: Vec<(std::net::TcpStream, Vec<u8>)> = {
            let mut guard =
                self.clearnet_pending_incoming.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };

        let mut still_pending: Vec<(std::net::TcpStream, Vec<u8>)> = Vec::new();
        let mut identified: Vec<(String, std::net::TcpStream, Vec<u8>)> = Vec::new();
        let mut ready_frames: Vec<Vec<u8>> = Vec::new();

        for (mut stream, mut buf) in pending_conns {
            // Non-blocking read until WouldBlock or EOF.
            let mut tmp = [0u8; 4096];
            let closed = loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break true,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break false,
                    Err(_) => break true,
                }
            };
            if closed {
                continue; // Peer disconnected before sending any data.
            }

            if let Some(frame) = try_read_frame(&mut buf) {
                // LAN discovery probes have no "sender" field — handle and close.
                let is_discover = serde_json::from_slice::<serde_json::Value>(&frame)
                    .ok()
                    .and_then(|v| {
                        v.get("type")
                            .and_then(|t| t.as_str())
                            .map(|s| s == "mi_discover")
                    })
                    .unwrap_or(false);
                if is_discover {
                    self.handle_lan_discover_request(&frame, &mut stream);
                    // Drop `stream` here — the probe connection is never kept alive.
                    continue;
                }
                if let Some(sender_hex) = extract_frame_sender(&frame) {
                    ready_frames.push(frame);
                    identified.push((sender_hex, stream, buf));
                    continue;
                }
            }
            still_pending.push((stream, buf));
        }

        // Re-queue connections that still haven't sent a full identifying frame.
        self.clearnet_pending_incoming
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(still_pending);

        // Enforce isolation mode (§3.4): Critical threat context → accept only known peers.
        let in_critical_mode = self.threat_context == crate::network::threat_context::ThreatContext::Critical;

        let mut newly_identified: Vec<String> = Vec::new();
        for (peer_id_hex, stream, buf) in identified {
            if in_critical_mode {
                let peer_bytes = match hex::decode(&peer_id_hex) {
                    Ok(b) if b.len() == 32 => {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        a
                    }
                    _ => continue, // Malformed ID — always drop.
                };
                let known = self
                    .contacts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&PeerId(peer_bytes))
                    .is_some();
                if !known {
                    drop(stream); // Close socket — no reply.
                    continue;
                }
            }
            self.clearnet_connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(peer_id_hex.clone(), stream);
            self.clearnet_recv_buffers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(peer_id_hex.clone(), buf);
            newly_identified.push(peer_id_hex);
        }

        // Process the first frames from newly identified connections immediately.
        for frame in ready_frames {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&frame) {
                self.process_inbound_frame(&v);
            }
        }

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        for peer_id_hex in &newly_identified {
            // Insert direct routing entry and seed last_rx timestamp.
            self.insert_local_route_for_peer(peer_id_hex);
            self.clearnet_last_rx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(peer_id_hex.clone(), std::time::Instant::now());

            // Emit PeerUpdated(online) so Flutter shows the connection immediately.
            {
                let peer_bytes_opt = hex::decode(peer_id_hex)
                    .ok()
                    .filter(|b| b.len() == 32)
                    .map(|b| {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        a
                    });
                if let Some(peer_bytes) = peer_bytes_opt {
                    let pid = PeerId(peer_bytes);
                    let (display_name, trust_val, cap_exit, cap_wrapper, cap_sf, cap_endorse) = {
                        let contacts =
                            self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(c) = contacts.get(&pid) {
                            (
                                c.display_name.clone().unwrap_or_default(),
                                c.trust_level as u8,
                                c.can_be_exit_node,
                                c.can_be_wrapper_node,
                                c.can_be_store_forward,
                                c.can_endorse_peers,
                            )
                        } else {
                            (String::new(), 0u8, false, false, false, false)
                        }
                    };
                    self.push_event(
                        "PeerUpdated",
                        serde_json::json!({
                            "id":               peer_id_hex,
                            "name":             display_name,
                            "trustLevel":       trust_val,
                            "status":           "online",
                            "canBeExitNode":    cap_exit,
                            "canBeWrapperNode": cap_wrapper,
                            "canBeStoreForward":cap_sf,
                            "canEndorsePeers":  cap_endorse,
                            "latencyMs":        null,
                        }),
                    );
                }
            }

            // Flush any S&F-buffered messages for this peer (§6.8).
            if let Ok(peer_bytes) = hex::decode(peer_id_hex) {
                if peer_bytes.len() == 32 {
                    let mut addr_bytes = [0u8; 32];
                    addr_bytes.copy_from_slice(&peer_bytes);
                    let dest = DeviceAddress(addr_bytes);
                    let queued = self
                        .sf_server
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .retrieve(&dest, now_secs);
                    for req in queued {
                        let deliver_frame = serde_json::json!({
                            "type":        "sf_deliver",
                            "payload_hex": hex::encode(&req.payload),
                        });
                        self.send_raw_frame(peer_id_hex, &deliver_frame);
                    }
                }
            }
        }
    }

    /// Read from and dispatch frames on all identified clearnet connections.
    ///
    /// Reads until `WouldBlock`; each complete frame is passed to
    /// `process_inbound_frame`.  Closed connections are removed.
    pub fn clearnet_process_identified(&self) {
        use std::io::Read;

        let peer_ids: Vec<String> = self
            .clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();

        let mut to_remove: Vec<String> = Vec::new();

        for peer_hex in peer_ids {
            // Read available bytes into the peer's receive buffer.
            let closed = {
                let mut tmp = [0u8; 4096];
                let mut conns = self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
                let stream = match conns.get_mut(&peer_hex) {
                    Some(s) => s,
                    None => continue,
                };
                let closed = loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break true,
                        Ok(n) => {
                            let mut bufs = self.clearnet_recv_buffers.lock().unwrap_or_else(|e| e.into_inner());
                            bufs.entry(peer_hex.clone()).or_default().extend_from_slice(&tmp[..n]);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break false,
                        Err(_) => break true,
                    }
                };
                // Update last_rx on any data received.
                if !closed {
                    self.clearnet_last_rx
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(peer_hex.clone(), std::time::Instant::now());
                }
                closed
            };

            if closed {
                to_remove.push(peer_hex.clone());
                continue;
            }

            // Drain complete frames from the receive buffer.
            loop {
                let frame = {
                    let mut bufs =
                        self.clearnet_recv_buffers.lock().unwrap_or_else(|e| e.into_inner());
                    match bufs.get_mut(&peer_hex) {
                        Some(buf) => try_read_frame(buf),
                        None => None,
                    }
                };
                match frame {
                    None => break,
                    Some(bytes) => {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            self.process_inbound_frame(&v);
                        }
                    }
                }
            }
        }

        // Clean up closed connections.
        for peer_hex in to_remove {
            self.clearnet_connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer_hex);
            self.clearnet_recv_buffers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer_hex);
        }
    }

    /// Attempt to deliver all queued outbox messages (§5.1 local S&F).
    ///
    /// For each entry:
    /// - If an identified connection to the peer already exists, use it.
    /// - Otherwise try clearnet (TCP connect + send).
    /// - Otherwise try Tor if enabled and the peer advertises an onion address.
    /// - Undeliverable entries remain in the outbox for the next cycle.
    pub fn clearnet_flush_outbox(&self) {
        use crate::service::runtime::DEFAULT_HS_PORT;

        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut outbox = self.outbox.lock().unwrap_or_else(|e| e.into_inner());
        if outbox.is_empty() {
            return;
        }

        let mut remaining = Vec::new();
        for (peer_hex, endpoint, frame) in outbox.drain(..) {
            // Try existing identified connection first.
            let sent = {
                let mut conns =
                    self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(stream) = conns.get_mut(&peer_hex) {
                    write_tcp_frame(stream, &frame).is_ok()
                } else {
                    false
                }
            };
            if sent {
                continue;
            }

            // Try clearnet TCP.
            let clearnet_ok = flags.clearnet
                && {
                    if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
                        if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
                            &addr,
                            std::time::Duration::from_secs(3),
                        ) {
                            let ok = write_tcp_frame(&mut stream, &frame).is_ok();
                            if ok {
                                let _ = stream.set_nonblocking(true);
                                self.clearnet_connections
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(peer_hex.clone(), stream);
                            }
                            ok
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };
            if clearnet_ok {
                continue;
            }

            // Try Tor if enabled and the peer has a known onion address.
            let tor_ok = flags.tor
                && {
                    let tor_endpoint = {
                        let peer_bytes = hex::decode(&peer_hex)
                            .ok()
                            .and_then(|b| {
                                if b.len() == 32 {
                                    let mut a = [0u8; 32];
                                    a.copy_from_slice(&b);
                                    Some(a)
                                } else {
                                    None
                                }
                            });
                        peer_bytes.and_then(|b| {
                            let contacts =
                                self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                            contacts.get(&PeerId(b)).and_then(|c| c.tor_endpoint.clone())
                        })
                    };
                    if let Some(ref tor_ep) = tor_endpoint {
                        let (onion_addr, port) = if let Some(colon) = tor_ep.rfind(':') {
                            let addr = &tor_ep[..colon];
                            let port: u16 = tor_ep[colon + 1..].parse().unwrap_or(DEFAULT_HS_PORT);
                            (addr.to_string(), port)
                        } else {
                            (tor_ep.clone(), DEFAULT_HS_PORT)
                        };
                        let guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(ref tor) = *guard {
                            match tor.connect(&peer_hex, &onion_addr, port) {
                                Ok(mut stream) => {
                                    let ok = write_tcp_frame(&mut stream, &frame).is_ok();
                                    if ok {
                                        self.clearnet_connections
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .insert(peer_hex.clone(), stream);
                                        tor.record_message(&peer_hex);
                                    }
                                    ok
                                }
                                Err(e) => {
                                    tracing::debug!(peer=%peer_hex, "Tor outbound connect failed: {e}");
                                    false
                                }
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };

            if !clearnet_ok && !tor_ok {
                remaining.push((peer_hex, endpoint, frame));
            }
        }
        *outbox = remaining;
    }
}

