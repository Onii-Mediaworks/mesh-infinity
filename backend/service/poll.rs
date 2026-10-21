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

// Imports for the poll cycle:
// - `PeerId` for peer identity lookups in the contact store.
// - `DeviceAddress` for routing table operations (same 32 bytes as PeerId but
//   typed separately to distinguish identity from routing concerns).
// - `FileDirection`, `CHUNKS_PER_TICK`, `FILE_CHUNK_SIZE` for file transfer
//   throttling — the poll loop sends at most CHUNKS_PER_TICK 64KiB chunks
//   per transfer per tick to stay responsive.
// - `write_tcp_frame`, `try_read_frame` are the length-prefixed TCP frame
//   helpers shared across all TCP paths; `try_random_fill` draws handshake
//   nonces.
// - `PendingLink` plus the `LINK_AUTH_*` / `MAX_PENDING_LINKS` bounds govern
//   accepted sockets that have not yet proved their identity (§5.1).
// - `link_auth` is the pure handshake state machine every TCP link must
//   complete before its frames reach any handler.
// - `TrustLevel` and `RoutingEntry` for routing table updates.
use crate::identity::peer_id::PeerId;
use crate::routing::table::DeviceAddress;
use crate::routing::table::RoutingEntry;
use crate::service::runtime::{try_random_fill, try_read_frame, write_tcp_frame};
use crate::service::runtime::{
    FileDirection, MeshRuntime, PendingLink, CHUNKS_PER_TICK, FILE_CHUNK_SIZE,
    LINK_AUTH_READ_TIMEOUT, LINK_AUTH_TIMEOUT, MAX_PENDING_LINKS,
};
use crate::transport::link_auth::{
    claimed_sender_matches, is_link_handshake_frame, parse_hello, InitiatorLink, LinkAuthError,
    LinkSigner, ResponderLink, LINK_NONCE_LEN, MAX_LINK_AUTH_FRAME_BYTES,
};
use crate::trust::levels::TrustLevel;

/// Outcome of feeding one complete frame to a pending inbound link.
///
/// The link itself stays with the caller (borrowed mutably), so this enum
/// only reports what to do with it next.
enum PendingLinkStep {
    /// Handshake not finished yet; keep waiting on this socket.
    Waiting,
    /// Handshake complete: the link is bound to this proven peer id.
    Authenticated(PeerId),
    /// The socket must be closed: probe answered, frame rejected, or I/O error.
    Closed,
}

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Master tick
    // -----------------------------------------------------------------------

    /// Start the Layer 1 background poll loop used by headless startup.
    ///
    /// Flutter normally drives `advance_clearnet_transport()` by calling
    /// `mi_poll_events()` every few hundred milliseconds.  During Android
    /// device-unlock startup Flutter does not exist yet, so Layer 1 needs its
    /// own lightweight loop to advance listeners, LAN discovery, gossip
    /// cleanup, store-and-forward maintenance, keepalives, and cover-traffic
    /// participation.
    pub fn start_layer1_background_poll(&self) {
        if self
            .layer1_poll_active
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }

        if let Some(handle) = self
            .layer1_poll_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = handle.join();
        }

        let active = self.layer1_poll_active.clone();
        let runtime_addr = self as *const MeshRuntime as usize;
        let spawn_result = std::thread::Builder::new()
            .name("mesh-layer1-poll".to_string())
            .spawn(move || {
                while active.load(std::sync::atomic::Ordering::Acquire) {
                    // SAFETY: `MeshRuntime::drop` calls `stop_layer1_background_poll`,
                    // which sets `layer1_poll_active` to false and joins this thread
                    // before the allocation is freed.  Therefore `runtime_addr` is
                    // valid for the entire lifetime of this closure.
                    let runtime = unsafe { &*(runtime_addr as *const MeshRuntime) };
                    runtime.advance_clearnet_transport();
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            });

        match spawn_result {
            Ok(handle) => {
                *self
                    .layer1_poll_thread
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(handle);
            }
            Err(error) => {
                self.layer1_poll_active
                    .store(false, std::sync::atomic::Ordering::Release);
                self.set_error(&format!("Layer 1 background poll failed: {error}"));
            }
        }
    }

    /// Stop the Layer 1 background poll loop and wait for it to exit.
    pub fn stop_layer1_background_poll(&self) {
        self.layer1_poll_active
            .store(false, std::sync::atomic::Ordering::Release);

        let handle = self
            .layer1_poll_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();

        if let Some(handle) = handle {
            if let Err(error) = handle.join() {
                eprintln!("[Layer1] background poll thread join failed: {error:?}");
            }
        }
    }

    /// Advance all transport sub-systems for one poll cycle.
    ///
    /// Called from `mi_poll_events` approximately every 200 ms.
    /// Returns after all non-blocking sub-system steps have been run.
    pub fn advance_clearnet_transport(&self) {
        self.poll_tor_bootstrap();
        // Phase 1 — Connection management: accept new TCP connections from
        // both clearnet and Tor hidden service listeners.  Tor inbound streams
        // are mixed into the same pending queue so the identification path
        // is transport-agnostic (§5.3 transport abstraction).
        self.clearnet_accept_new_connections();
        self.tor_drain_inbound();

        // Phase 2 — Frame processing: identify pending (anonymous) connections
        // by reading their first frame to extract the sender's peer ID, then
        // process all identified connections to dispatch complete frames.
        // This ordering ensures a newly identified connection's first frame
        // is processed in the same tick it was promoted.
        self.clearnet_process_pending_incoming();
        self.clearnet_process_identified();

        // Phase 3 — Delivery: retry any queued outbox messages that failed
        // delivery on previous ticks (peer was offline or connection broken).
        // Tries clearnet TCP first, then Tor if enabled (§5.1 local S&F).
        self.clearnet_flush_outbox();

        // Phase 4 — LAN discovery: broadcast our presence on the local
        // network and perform TCP challenge-response handshakes with
        // newly discovered peers (§4.9.5).
        self.advance_lan_discovery();
        self.advance_lan_discovery_handshakes();

        // Phase 5 — File transfers: send the next batch of chunks for each
        // active outgoing transfer.  Throttled to CHUNKS_PER_TICK per transfer
        // to keep the event loop responsive.
        self.advance_file_transfers();

        // Phase 6 — Housekeeping: garbage-collect store-and-forward entries,
        // trigger scheduled group Sender Key rekeying, dispatch coalesced
        // notifications, prune stale gossip map entries, and send keepalive
        // probes to idle peers.
        self.advance_sf_gc();
        self.advance_group_rekeys();
        self.advance_notifications();
        self.advance_gossip_cleanup();
        self.advance_keepalives();
        self.advance_layer1_participation();

        // Phase 7 — Overlay transports: drain inbound frames from ZeroTier and
        // inject them into the mesh data plane (§5.5 overlay client parity).
        self.advance_overlay_inbound();
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
        /// Seconds of idle (no data received) before we send a keepalive probe.
        /// 30 seconds balances prompt detection with bandwidth conservation.
        const KEEPALIVE_INTERVAL_SECS: u64 = 30;
        /// Seconds of total silence before declaring the peer dead and closing
        /// the TCP connection.  120 seconds allows for transient network drops
        /// without prematurely disconnecting.
        const KEEPALIVE_TIMEOUT_SECS: u64 = 120;
        /// Minimum gap between successive keepalive probes to the same peer.
        /// Prevents a flood of probes if the peer is slow to respond — we
        /// send at most one probe per 10-second window.
        const KEEPALIVE_TX_MIN_GAP_SECS: u64 = 10;

        let now = std::time::Instant::now();

        // Snapshot the peer list first to avoid holding the connection lock
        // across the entire keepalive loop, which could block incoming I/O.
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
                let map = self
                    .clearnet_last_rx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
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

        // Close stale connections and clean up all per-peer state.
        // We remove from five separate maps: connections, recv buffers,
        // last_rx timestamps, last_keepalive_tx timestamps, and the routing
        // table.  The order does not matter since each map is independently
        // locked; what matters is that ALL maps are cleaned to prevent
        // resource leaks from orphaned entries.
        for peer_hex in to_drop {
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
                let peer_bytes_opt =
                    hex::decode(&peer_hex)
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
                        .map(|c| {
                            (
                                c.display_name.clone().unwrap_or_default(),
                                c.trust_level as u8,
                            )
                        })
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

        // Gather our peer ID and signing key bytes.  We clone the bytes out
        // of the identity lock so we can drop the lock before the broadcast
        // loop (which acquires the clearnet_connections lock).
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
        // The domain separator (DOMAIN_ROUTING_ANNOUNCEMENT) prevents cross-protocol
        // signature reuse.  The announcement_id provides deduplication at receivers
        // and the timestamp enables age-based filtering (§6.2).
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
            destination: our_addr,
            hop_count: 0,
            latency_ms: 0,
            next_hop_trust: TrustLevel::InnerCircle,
            announcement_id,
            timestamp: now,
            scope: AnnouncementScope::Public,
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
        let addr = DeviceAddress(peer_bytes);
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

        // Zero announcement_id for direct entries — they are locally observed,
        // not received via gossip.  This distinguishes them from gossip-propagated
        // routes so the routing table can apply different expiry policies.
        let entry = RoutingEntry {
            destination: addr,
            next_hop: addr,
            hop_count: 1,
            latency_ms: 0,
            next_hop_trust: trust,
            last_updated: now,
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

    /// Reconcile Layer 1 participation state on every poll cycle.
    ///
    /// This keeps the exported startup/runtime posture current as threat
    /// context, conversation activity, transport availability, and tunnel
    /// gossip knowledge change over time.
    pub fn advance_layer1_participation(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.tunnel_gossip
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .gc(now);
        self.refresh_layer1_participation_state();
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
        use crate::service::runtime::try_random_fill;
        use chacha20poly1305::{
            aead::{Aead, Nonce},
            ChaCha20Poly1305, Key, KeyInit,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Snapshot the groups that need rekeying without holding the groups
        // lock during the expensive encrypt-and-send loop below.  This prevents
        // blocking inbound group message processing during rekey distribution.
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
                        group.symmetric_key = new_symmetric_key;
                        group.sender_key_epoch += 1;
                        group.last_rekey_at = now;
                        group.sender_key_epoch
                    }
                    None => continue,
                }
            };

            let group_id_hex = hex::encode(group_id);
            let new_key_hex = hex::encode(new_symmetric_key);

            // Our own peer ID — skip when iterating members.
            let our_peer_id = self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|id| id.peer_id());

            for member_bytes in &member_ids {
                let member_id = PeerId(*member_bytes);
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
                    let mut sessions = self
                        .ratchet_sessions
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if let Some(session) = sessions.get_mut(&member_id) {
                        match session.next_send_msg_key() {
                            Ok((header, msg_key)) => {
                                let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
                                // All-zero 12-byte nonce is safe because the ratchet msg_key
                                // is never reused — each next_send_msg_key() produces a
                                // unique key, so (key, nonce) pair uniqueness is guaranteed.
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

        // Snapshot the active transfer IDs to avoid holding the active_file_io
        // lock during I/O operations.  New transfers added mid-tick will be
        // picked up on the next poll cycle — a 200ms delay is acceptable.
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
                let map = self
                    .active_file_io
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                match map.get(&tid) {
                    Some(s) => (
                        if s.direction == FileDirection::Send {
                            "send"
                        } else {
                            "recv"
                        },
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
                    let mut map = self
                        .active_file_io
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
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
                    let map = self
                        .active_file_io
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    map.get(&tid).map(|s| s.transferred_bytes).unwrap_or(0)
                };
                {
                    let mut transfers = self
                        .file_transfers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
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
    ///
    /// Drains all pending `accept()` results in a tight loop until `WouldBlock`
    /// (the listener is non-blocking).  Each accepted stream is set to
    /// non-blocking mode immediately so that subsequent `read()` calls in the
    /// poll loop never stall.  The streams are placed in the "pending" queue
    /// where they must complete the link handshake before being keyed on a
    /// peer id (§5.1).
    pub fn clearnet_accept_new_connections(&self) {
        let new_streams: Vec<std::net::TcpStream> = {
            let guard = self
                .clearnet_listener
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
        self.enqueue_pending_links(new_streams);
    }

    /// Drain inbound streams accepted by the Tor hidden-service transport.
    ///
    /// Inserts them into the same pending-incoming queue as clearnet
    /// connections so the same link handshake gates both.
    pub fn tor_drain_inbound(&self) {
        let new_streams: Vec<std::net::TcpStream> = {
            let guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(tor) => tor.drain_inbound(),
                None => Vec::new(),
            }
        };
        self.enqueue_pending_links(new_streams);
    }

    /// Queue freshly accepted sockets for the link handshake (§5.1).
    ///
    /// Enforces `MAX_PENDING_LINKS`: once the queue is full, further sockets
    /// are closed on arrival.  An attacker opening idle connections can thus
    /// hold at most a fixed number of descriptors and never displaces a
    /// socket that is already mid-handshake.
    pub fn enqueue_pending_links(&self, streams: Vec<std::net::TcpStream>) {
        if streams.is_empty() {
            return;
        }
        let mut pending = self
            .clearnet_pending_incoming
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for stream in streams {
            if pending.len() >= MAX_PENDING_LINKS {
                // Dropping the stream closes it; nothing was read from it.
                self.diagnostic_log("link", "pending_cap_reached");
                continue;
            }
            pending.push(PendingLink::new(stream));
        }
    }

    /// Snapshot the local identity as a link-handshake signer.
    ///
    /// Taken once per handshake step so the identity lock is never held
    /// across socket I/O.
    fn link_signer(&self) -> Result<LinkSigner, LinkAuthError> {
        let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let id = guard.as_ref().ok_or(LinkAuthError::NoLocalIdentity)?;
        Ok(LinkSigner::new(
            id.ed25519_pub,
            id.ed25519_signing.to_bytes(),
        ))
    }

    /// Advance one pending inbound link by one complete frame.
    ///
    /// Frame sequence on an accepted socket:
    ///   - `mi_discover` (LAN probe, §4.9.5): answered inline, socket closed.
    ///   - `link_hello`: answered with our signed `link_auth`; the responder
    ///     state is kept so the peer's reply can be checked against it.
    ///   - `link_auth`: verified against that state; on success the link is
    ///     bound to the proven peer id.
    ///
    /// Anything else, in any order, closes the socket.  An unauthenticated
    /// peer gets exactly one protocol and no second chances; nothing it sent
    /// is ever dispatched to a frame handler.
    fn advance_pending_link(&self, link: &mut PendingLink, frame: &[u8]) -> PendingLinkStep {
        let value: serde_json::Value = match serde_json::from_slice(frame) {
            Ok(v) => v,
            Err(_) => {
                self.diagnostic_log("link", "handshake_frame_malformed");
                return PendingLinkStep::Closed;
            }
        };

        // Step 1: no challenge issued yet, so this must be a probe or a hello.
        let Some(challenge) = link.challenge.as_ref() else {
            if value.get("type").and_then(|t| t.as_str()) == Some("mi_discover") {
                self.handle_lan_discover_request(frame, &mut link.stream);
                // The probe socket is never kept alive.
                return PendingLinkStep::Closed;
            }
            let hello = match parse_hello(&value) {
                Ok(hello) => hello,
                Err(_) => {
                    self.diagnostic_log("link", "hello_rejected");
                    return PendingLinkStep::Closed;
                }
            };
            // Without an unlocked identity we cannot prove who we are, and a
            // link we cannot sign for must not be opened.
            let signer = match self.link_signer() {
                Ok(signer) => signer,
                Err(_) => return PendingLinkStep::Closed,
            };
            let mut nonce = [0u8; LINK_NONCE_LEN];
            if !try_random_fill(&mut nonce) {
                return PendingLinkStep::Closed;
            }
            let (responder, reply) = ResponderLink::answer(signer, hello, nonce);
            let reply_bytes = match serde_json::to_vec(&reply) {
                Ok(bytes) => bytes,
                Err(_) => return PendingLinkStep::Closed,
            };
            if write_tcp_frame(&mut link.stream, &reply_bytes).is_err() {
                return PendingLinkStep::Closed;
            }
            link.challenge = Some(responder);
            return PendingLinkStep::Waiting;
        };

        // Step 2: a challenge is outstanding, so this must be the signed auth.
        match challenge.accept_auth(&value) {
            Ok(peer) => PendingLinkStep::Authenticated(peer),
            Err(_) => {
                self.diagnostic_log("link", "auth_rejected");
                PendingLinkStep::Closed
            }
        }
    }

    /// Run the initiator side of the link handshake on a freshly connected
    /// socket, proving our identity and verifying the peer's (§5.1).
    ///
    /// This is the one blocking exchange on an outbound socket; it is bounded
    /// by `LINK_AUTH_READ_TIMEOUT`.  On success the stream is left in
    /// blocking mode with no read timeout and the caller decides its mode.
    /// On any error the caller must drop the stream: nothing may be keyed on
    /// a socket whose far end did not prove it holds `expected_peer_hex`.
    pub fn authenticate_outbound_link(
        &self,
        stream: &mut std::net::TcpStream,
        expected_peer_hex: &str,
    ) -> Result<PeerId, LinkAuthError> {
        use std::io::Read;

        let expected = PeerId::from_hex(expected_peer_hex)
            .map_err(|_| LinkAuthError::MalformedField("peer"))?;
        let signer = self.link_signer()?;
        let mut nonce = [0u8; LINK_NONCE_LEN];
        if !try_random_fill(&mut nonce) {
            return Err(LinkAuthError::RandomFailure);
        }
        let link = InitiatorLink::new(signer, nonce, Some(expected));
        let io = |error: std::io::Error| LinkAuthError::Io(error.kind());

        stream.set_nonblocking(false).map_err(io)?;
        stream
            .set_read_timeout(Some(LINK_AUTH_READ_TIMEOUT))
            .map_err(io)?;
        let hello =
            serde_json::to_vec(&link.hello_frame()).map_err(|_| LinkAuthError::MalformedFrame)?;
        write_tcp_frame(stream, &hello).map_err(io)?;

        // Read exactly one framed reply, refusing to buffer more than a
        // handshake frame's worth from a peer that has not yet proved itself.
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let reply = loop {
            if let Some(frame) = try_read_frame(&mut buf) {
                break frame;
            }
            if buf.len() > MAX_LINK_AUTH_FRAME_BYTES + 4 {
                return Err(LinkAuthError::MalformedFrame);
            }
            let n = stream.read(&mut tmp).map_err(io)?;
            if n == 0 {
                return Err(LinkAuthError::Io(std::io::ErrorKind::UnexpectedEof));
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        let value: serde_json::Value =
            serde_json::from_slice(&reply).map_err(|_| LinkAuthError::MalformedFrame)?;
        let (peer, proof) = link.accept_response(&value)?;
        let proof_bytes = serde_json::to_vec(&proof).map_err(|_| LinkAuthError::MalformedFrame)?;
        write_tcp_frame(stream, &proof_bytes).map_err(io)?;
        stream.set_read_timeout(None).map_err(io)?;
        Ok(peer)
    }

    /// Whether a frame received on the link keyed `peer_hex` may be dispatched.
    ///
    /// Handshake frames on an already-authenticated link are protocol noise
    /// and are dropped.  A frame whose `sender` / `from` names anyone other
    /// than the proven link peer is a spoofing attempt and is dropped before
    /// it can reach a handler that would trust that field (§2.0).
    fn frame_bound_to_link(&self, peer_hex: &str, frame: &serde_json::Value) -> bool {
        let Ok(link_peer) = PeerId::from_hex(peer_hex) else {
            return false;
        };
        if is_link_handshake_frame(frame) {
            self.diagnostic_log("link", "handshake_frame_on_open_link");
            return false;
        }
        if !claimed_sender_matches(frame, &link_peer) {
            self.diagnostic_log("link", "sender_mismatch");
            return false;
        }
        true
    }

    /// Advance the link handshake on pending (unauthenticated) inbound connections.
    ///
    /// Reads whatever has arrived, feeds complete frames to
    /// `advance_pending_link`, and promotes sockets whose peer completed the
    /// handshake to `clearnet_connections` keyed on the *proven* peer id.
    /// Sockets older than `LINK_AUTH_TIMEOUT`, or buffering more than one
    /// handshake frame without completing one, are closed.
    ///
    /// In Critical threat mode (isolation, §3.4), authenticated peers that
    /// are not contacts are silently dropped — the socket is closed without
    /// reply.  Because the identity is proven first, a stranger cannot pass
    /// this gate by claiming a contact's id.  This provides plausible
    /// deniability — an adversary cannot distinguish between "no node is
    /// running" and "node is in isolation mode".
    pub fn clearnet_process_pending_incoming(&self) {
        use std::io::Read;

        // Take ownership of the pending queue atomically, releasing the lock
        // immediately.  This allows new connections to be accepted during the
        // handshake loop below.
        let pending_links: Vec<PendingLink> = {
            let mut guard = self
                .clearnet_pending_incoming
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };

        let mut still_pending: Vec<PendingLink> = Vec::new();
        let mut authenticated: Vec<(PeerId, std::net::TcpStream, Vec<u8>)> = Vec::new();

        for mut link in pending_links {
            // Age out sockets that never finished; dropping closes them.
            if link.accepted_at.elapsed() > LINK_AUTH_TIMEOUT {
                self.diagnostic_log("link", "auth_timeout");
                continue;
            }

            // Non-blocking read until WouldBlock or EOF.
            let mut tmp = [0u8; 4096];
            let closed = loop {
                match link.stream.read(&mut tmp) {
                    Ok(0) => break true,
                    Ok(n) => link.buf.extend_from_slice(&tmp[..n]),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break false,
                    Err(_) => break true,
                }
            };
            if closed {
                continue; // Peer disconnected mid-handshake.
            }

            match try_read_frame(&mut link.buf) {
                None => {
                    // No complete frame yet: an unauthenticated peer may not
                    // make us hold more than one handshake frame of bytes.
                    if link.buf.len() > MAX_LINK_AUTH_FRAME_BYTES + 4 {
                        self.diagnostic_log("link", "handshake_frame_too_large");
                        continue;
                    }
                    still_pending.push(link);
                }
                Some(frame) => match self.advance_pending_link(&mut link, &frame) {
                    PendingLinkStep::Waiting => still_pending.push(link),
                    PendingLinkStep::Authenticated(peer) => {
                        // Bytes after the auth frame are application frames.
                        authenticated.push((peer, link.stream, link.buf));
                    }
                    PendingLinkStep::Closed => {}
                },
            }
        }

        // Re-queue connections still inside the handshake.
        self.clearnet_pending_incoming
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(still_pending);

        // Enforce isolation mode (§3.4): Critical threat context → accept only known peers.
        let in_critical_mode =
            self.threat_context == crate::network::threat_context::ThreatContext::Critical;

        let mut newly_identified: Vec<String> = Vec::new();
        for (peer, stream, buf) in authenticated {
            if in_critical_mode {
                let known = self
                    .contacts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&peer)
                    .is_some();
                if !known {
                    drop(stream); // Close socket — no reply.
                    continue;
                }
            }
            // The key is the proven id, canonical lowercase hex.  A peer that
            // re-authenticates replaces its own earlier socket (reconnect);
            // nobody else can, because nobody else can sign for this id.
            let peer_id_hex = peer.to_hex();
            self.clearnet_connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(peer_id_hex.clone(), stream);
            // Bytes received after the auth frame are application frames and
            // are dispatched by `clearnet_process_identified` this same tick.
            self.clearnet_recv_buffers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(peer_id_hex.clone(), buf);
            newly_identified.push(peer_id_hex);
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
                let peer_bytes_opt =
                    hex::decode(peer_id_hex)
                        .ok()
                        .filter(|b| b.len() == 32)
                        .map(|b| {
                            let mut a = [0u8; 32];
                            a.copy_from_slice(&b);
                            a
                        });
                if let Some(peer_bytes) = peer_bytes_opt {
                    let pid = PeerId(peer_bytes);
                    let (
                        display_name,
                        trust_val,
                        pairing_method,
                        cap_exit,
                        cap_wrapper,
                        cap_sf,
                        cap_endorse,
                    ) = {
                        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(c) = contacts.get(&pid) {
                            (
                                c.display_name.clone().unwrap_or_default(),
                                c.trust_level as u8,
                                format!("{:?}", c.pairing_method),
                                c.can_be_exit_node,
                                c.can_be_wrapper_node,
                                c.can_be_store_forward,
                                c.can_endorse_peers,
                            )
                        } else {
                            (
                                String::new(),
                                0u8,
                                "Unspecified".to_string(),
                                false,
                                false,
                                false,
                                false,
                            )
                        }
                    };
                    self.push_event(
                        "PeerUpdated",
                        serde_json::json!({
                            "id":               peer_id_hex,
                            "name":             display_name,
                            "trustLevel":       trust_val,
                            "pairingMethod":    pairing_method,
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

            // Flush store-and-forward-buffered messages for this peer (§6.8).
            // When a peer comes online, we check whether we have any queued S&F
            // messages waiting for them and deliver them immediately.  This
            // provides transparent offline message delivery without the sender
            // needing to know whether the recipient was online at send time.
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
                let mut conns = self
                    .clearnet_connections
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let stream = match conns.get_mut(&peer_hex) {
                    Some(s) => s,
                    None => continue,
                };
                let closed = loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break true,
                        Ok(n) => {
                            let mut bufs = self
                                .clearnet_recv_buffers
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            bufs.entry(peer_hex.clone())
                                .or_default()
                                .extend_from_slice(&tmp[..n]);
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
                    let mut bufs = self
                        .clearnet_recv_buffers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    match bufs.get_mut(&peer_hex) {
                        Some(buf) => try_read_frame(buf),
                        None => None,
                    }
                };
                match frame {
                    None => break,
                    Some(bytes) => {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            // Open the link-layer envelope first (§5.2): a
                            // `wg_ct` frame is decrypted with the connection
                            // peer's session, and a plaintext non-handshake
                            // frame from a peer with a session is dropped.
                            if let Some(inner) = self.unwrap_inbound_wg_frame(&peer_hex, v) {
                                // Only frames consistent with the proven link
                                // identity reach a handler (§5.1, §2.0).
                                if self.frame_bound_to_link(&peer_hex, &inner) {
                                    self.process_inbound_frame(&inner);
                                }
                            }
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
    ///
    /// The attempt order (existing connection → clearnet TCP → Tor) reflects
    /// a latency-first strategy: reusing an existing TCP stream is fastest,
    /// a fresh clearnet connection is next, and Tor (with circuit establishment
    /// overhead) is the fallback of last resort.
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
                let mut conns = self
                    .clearnet_connections
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
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
            let clearnet_ok = flags.clearnet && {
                if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
                    if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
                        &addr,
                        std::time::Duration::from_secs(3),
                    ) {
                        // Prove identities both ways before the first
                        // application frame crosses the socket (§5.1).
                        let ok = self
                            .authenticate_outbound_link(&mut stream, &peer_hex)
                            .is_ok()
                            && write_tcp_frame(&mut stream, &frame).is_ok()
                            && stream.set_nonblocking(true).is_ok();
                        if ok {
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
            let tor_ok = flags.tor && {
                let tor_endpoint = {
                    let peer_bytes = hex::decode(&peer_hex).ok().and_then(|b| {
                        if b.len() == 32 {
                            let mut a = [0u8; 32];
                            a.copy_from_slice(&b);
                            Some(a)
                        } else {
                            None
                        }
                    });
                    peer_bytes.and_then(|b| {
                        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                        contacts
                            .get(&PeerId(b))
                            .and_then(|c| c.tor_endpoint.clone())
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
                                // Same mutual proof as clearnet: a hidden
                                // service address is a hint, not an identity.
                                let ok = self
                                    .authenticate_outbound_link(&mut stream, &peer_hex)
                                    .is_ok()
                                    && write_tcp_frame(&mut stream, &frame).is_ok()
                                    && stream.set_nonblocking(true).is_ok();
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

    // -----------------------------------------------------------------------
    // Overlay transport inbound polling (§5.5 — T2-D)
    // -----------------------------------------------------------------------

    /// Drain inbound Ethernet frames from the ZeroTier data-plane transport and
    /// inject them into the mesh data plane via `ingest_tun_packet`.
    ///
    /// ZeroTier's background receive thread (started by `start_recv`) fills
    /// `ZeroTierTransport::inbound`; this method drains that buffer each poll
    /// tick.  Frames are raw Ethernet payloads — they are forwarded identically
    /// to packets arriving from the Android TUN interface (§17.5).
    ///
    /// The method is a no-op when no ZeroTier transport is configured.
    pub fn advance_overlay_inbound(&self) {
        let frames: Vec<Vec<u8>> = {
            let guard = self
                .zerotier_transport
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(zt) => zt.drain_inbound(),
                None => return,
            }
        };

        for frame in frames {
            // Strip the 14-byte Ethernet header (dst + src MAC + EtherType) to
            // obtain the raw IP payload before feeding into ingest_tun_packet.
            // Frames shorter than 14 bytes are malformed — skip silently.
            if frame.len() > 14 {
                self.ingest_tun_packet(&frame[14..]);
            }
        }
    }
}

#[cfg(test)]
mod link_auth_tests {
    use super::*;
    use crate::identity::self_identity::SelfIdentity;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use tempfile::TempDir;

    /// A runtime with a fresh unlocked identity and all transports off.
    fn test_runtime(name: &str) -> (TempDir, MeshRuntime) {
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
        runtime.create_identity(Some(name.to_string())).unwrap();
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

    /// A signer for a standalone test identity.
    fn signer_for(id: &SelfIdentity) -> LinkSigner {
        LinkSigner::new(id.ed25519_pub, id.ed25519_signing.to_bytes())
    }

    /// Run the responder's poll steps until `done` holds or ~3 s elapse.
    fn pump(runtime: &MeshRuntime, done: impl Fn() -> bool) {
        for _ in 0..300 {
            runtime.clearnet_process_pending_incoming();
            runtime.clearnet_process_identified();
            if done() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Peer ids of all `TypingIndicator` events pushed so far.
    fn typing_senders(runtime: &MeshRuntime) -> Vec<String> {
        runtime
            .event_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|event| event["type"] == "TypingIndicator")
            .map(|event| event["data"]["peerId"].as_str().unwrap_or("").to_string())
            .collect()
    }

    /// Whether an authenticated connection is keyed on `peer`.
    fn connected(runtime: &MeshRuntime, peer: &PeerId) -> bool {
        runtime
            .clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&peer.to_hex())
    }

    /// A typing-indicator frame claiming to come from `sender`.
    fn typing_frame(sender: &PeerId) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type":   "typing_indicator",
            "sender": sender.to_hex(),
            "roomId": "room",
            "active": true,
        }))
        .unwrap()
    }

    /// Read one framed message from `stream`, blocking up to 3 s.
    fn read_frame_blocking(stream: &mut TcpStream) -> Option<Vec<u8>> {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            if let Some(frame) = try_read_frame(&mut buf) {
                return Some(frame);
            }
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
    }

    /// Whether the far end closed `stream` (EOF or reset) within 3 s.
    fn closed_by_peer(stream: &mut TcpStream) -> bool {
        read_frame_blocking(stream).is_none()
    }

    /// A loopback listener plus a connected client socket.
    fn loopback_pair() -> (TcpListener, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (listener, client)
    }

    /// Accept the pending client and hand the socket to the runtime's
    /// pending-link queue, as the poll loop's accept step would.
    fn accept_into(runtime: &MeshRuntime, listener: &TcpListener) {
        let (server, _) = listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();
        runtime.enqueue_pending_links(vec![server]);
    }

    /// Drive the honest initiator side by hand over `client` as `me`,
    /// expecting to reach `server_id`.  Returns the proven server id.
    fn client_handshake(client: &mut TcpStream, me: &SelfIdentity, server_id: &PeerId) -> PeerId {
        let init = InitiatorLink::new(signer_for(me), [0x5Au8; 32], Some(*server_id));
        write_tcp_frame(client, &serde_json::to_vec(&init.hello_frame()).unwrap()).unwrap();
        let reply = read_frame_blocking(client).expect("server challenge");
        let value: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        let (proven, proof) = init.accept_response(&value).unwrap();
        write_tcp_frame(client, &serde_json::to_vec(&proof).unwrap()).unwrap();
        proven
    }

    /// On a link authenticated as Alice, a frame naming Mallory as its
    /// sender is dropped before any handler sees it, while Alice's own
    /// frame on the same link is dispatched.
    #[test]
    fn forged_sender_on_authenticated_link_is_dropped() {
        let (_dir, runtime) = test_runtime("Bob");
        let (listener, mut client) = loopback_pair();
        let (server, _) = listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();
        let alice = PeerId([0xA1u8; 32]);
        let mallory = PeerId([0xB2u8; 32]);
        // Simulate a link that already completed authentication as Alice.
        runtime
            .clearnet_connections
            .lock()
            .unwrap()
            .insert(alice.to_hex(), server);

        write_tcp_frame(&mut client, &typing_frame(&mallory)).unwrap();
        write_tcp_frame(&mut client, &typing_frame(&alice)).unwrap();
        pump(&runtime, || !typing_senders(&runtime).is_empty());

        assert_eq!(typing_senders(&runtime), vec![alice.to_hex()]);
    }

    /// An inbound socket is keyed on a peer id only after the peer proves
    /// its key; the frames it sends afterwards are then dispatched.
    #[test]
    fn inbound_link_requires_completed_handshake() {
        let (_dir, runtime) = test_runtime("Server");
        let server_id = our_peer_id(&runtime);
        let bob = SelfIdentity::generate(Some("Bob".to_string()));
        let bob_id = bob.peer_id();
        let (listener, mut client) = loopback_pair();
        accept_into(&runtime, &listener);

        let client_thread = std::thread::spawn(move || {
            let proven = client_handshake(&mut client, &bob, &server_id);
            write_tcp_frame(&mut client, &typing_frame(&bob_id)).unwrap();
            (proven, client)
        });
        pump(&runtime, || !typing_senders(&runtime).is_empty());
        let (proven, _client) = client_thread.join().unwrap();

        assert_eq!(proven, server_id, "client verified the server's identity");
        assert!(connected(&runtime, &bob_id));
        assert!(runtime.clearnet_pending_incoming.lock().unwrap().is_empty());
        assert_eq!(typing_senders(&runtime), vec![bob_id.to_hex()]);
    }

    /// A socket that skips the handshake, or answers the challenge with a
    /// different key than its hello, is closed and never keyed on any id.
    #[test]
    fn inbound_link_rejects_unauthenticated_and_forged_peers() {
        let (_dir, runtime) = test_runtime("Server");
        let bob = SelfIdentity::generate(Some("Bob".to_string()));
        let mallory = SelfIdentity::generate(Some("Mallory".to_string()));

        // Case 1: an application frame before any handshake.
        let (listener, mut client) = loopback_pair();
        accept_into(&runtime, &listener);
        write_tcp_frame(&mut client, &typing_frame(&bob.peer_id())).unwrap();
        pump(&runtime, || {
            runtime.clearnet_pending_incoming.lock().unwrap().is_empty()
        });
        assert!(closed_by_peer(&mut client));
        assert!(runtime.clearnet_connections.lock().unwrap().is_empty());
        assert!(typing_senders(&runtime).is_empty());

        // Case 2: Bob's hello, but Mallory signs the auth.
        let (listener, mut client) = loopback_pair();
        accept_into(&runtime, &listener);
        let bob_init = InitiatorLink::new(signer_for(&bob), [0x5Au8; 32], None);
        let reply_frame = {
            write_tcp_frame(
                &mut client,
                &serde_json::to_vec(&bob_init.hello_frame()).unwrap(),
            )
            .unwrap();
            let waiter = std::thread::spawn(move || (read_frame_blocking(&mut client), client));
            pump(&runtime, || {
                runtime
                    .clearnet_pending_incoming
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|link| link.challenge.is_some())
            });
            let (reply, returned) = waiter.join().unwrap();
            client = returned;
            reply.expect("server challenge")
        };
        // The server answered Bob's hello.  Mallory, who does not hold Bob's
        // key, sends an auth that is well-formed for Bob's id and nonce but
        // carries a signature she made up.
        let challenge: serde_json::Value = serde_json::from_slice(&reply_frame).unwrap();
        assert_eq!(challenge["type"], "link_auth", "server issued a challenge");
        let forged_auth = serde_json::json!({
            "type":           "link_auth",
            "sender":         bob.peer_id().to_hex(),
            "ed25519_public": hex::encode(bob.ed25519_pub),
            "nonce":          hex::encode([0x5Au8; 32]),
            "sig":            hex::encode([0x99u8; 64]),
        });
        write_tcp_frame(&mut client, &serde_json::to_vec(&forged_auth).unwrap()).unwrap();
        pump(&runtime, || {
            runtime.clearnet_pending_incoming.lock().unwrap().is_empty()
        });
        assert!(closed_by_peer(&mut client));
        assert!(!connected(&runtime, &bob.peer_id()));
        assert!(!connected(&runtime, &mallory.peer_id()));
    }

    /// The outbound side proves itself to the responder and refuses a
    /// responder that is not the peer it dialled.
    #[test]
    fn outbound_link_authenticates_against_expected_peer() {
        let (_dir_a, server) = test_runtime("Server");
        let (_dir_b, client_rt) = test_runtime("Client");
        let server_id = our_peer_id(&server);
        let client_id = our_peer_id(&client_rt);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Declared outside the scope so the second dial thread may borrow it.
        let wrong = PeerId([0x77u8; 32]);

        std::thread::scope(|scope| {
            // Honest dial: both sides end up bound to each other.
            let dial = scope.spawn(|| {
                let mut stream = TcpStream::connect(addr).unwrap();
                let proven = client_rt.authenticate_outbound_link(&mut stream, &server_id.to_hex());
                (proven, stream)
            });
            accept_into(&server, &listener);
            pump(&server, || connected(&server, &client_id));
            let (proven, _stream) = dial.join().unwrap();
            assert_eq!(proven, Ok(server_id));
            assert!(connected(&server, &client_id));

            // Dial expecting someone else: the client refuses the answer.
            let dial = scope.spawn(|| {
                let mut stream = TcpStream::connect(addr).unwrap();
                client_rt.authenticate_outbound_link(&mut stream, &wrong.to_hex())
            });
            accept_into(&server, &listener);
            pump(&server, || {
                server.clearnet_pending_incoming.lock().unwrap().is_empty()
            });
            assert_eq!(dial.join().unwrap(), Err(LinkAuthError::UnexpectedPeer));
        });
    }
}
