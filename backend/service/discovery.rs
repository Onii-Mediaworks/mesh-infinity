//! LAN peer discovery logic for `MeshRuntime`.
//!
//! Implements the §4.9.5 LAN-mDNS / UDP-broadcast discovery protocol:
//!   1. Broadcast `mi_presence` packets every 5 seconds so peers on the same
//!      LAN can find us without any centralised infrastructure.
//!   2. On receiving a presence packet, queue the sender for a TCP
//!      challenge-response handshake (`advance_lan_discovery_handshakes`).
//!   3. Respond to inbound `mi_discover` frames from peers probing us.
//!
//! ## Security notes
//! - Presence packets carry **no** cryptographic material — only the TCP port.
//! - All key material is exchanged during the TCP handshake which uses an
//!   Ed25519-signed nonce to authenticate the responder.
//! - A 60-second cooldown prevents amplification by fast-broadcasting peers.

use crate::service::runtime::{
    local_clearnet_ip, try_random_fill, try_read_frame, write_tcp_frame, MeshRuntime,
};

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Outbound broadcast
    // -----------------------------------------------------------------------

    /// Drive the LAN discovery subsystem for one poll cycle.
    ///
    /// Drains all pending UDP presence packets from the socket (non-blocking),
    /// then broadcasts our own presence every 5 seconds if we are ready.
    ///
    /// The presence packet contains only the clearnet TCP port.  The peer's IP
    /// is inferred by the receiver from the UDP source address, so we do not
    /// embed it here (it would be wrong behind many NAT configurations anyway).
    pub fn advance_lan_discovery(&self) {
        // Guard: discovery must be enabled.
        if !*self.mdns_running.lock().unwrap_or_else(|e| e.into_inner()) {
            return;
        }

        // Borrow the socket for the duration of this method.
        let socket_guard = self
            .lan_discovery_socket
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let socket = match socket_guard.as_ref() {
            Some(s) => s,
            None => return,
        };

        // ---- Receive: drain all pending packets (non-blocking). ----
        let mut buf = [0u8; 1024];
        while let Ok((len, src_addr)) = socket.recv_from(&mut buf) {
            // Process each packet; ignore errors (malformed packets are
            // simply dropped — an attacker cannot cause a crash).
            let _ = self.handle_lan_presence_packet(&buf[..len], src_addr);
            // WouldBlock or any other error exits the while-let naturally.
        }

        // ---- Send: broadcast our presence every 5 seconds. ----
        let now = std::time::Instant::now();
        let next = *self
            .lan_next_announce
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if now < next {
            return;
        }

        // Advance the timer before sending so a send failure does not cause
        // a tight retry loop.
        *self
            .lan_next_announce
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = now + std::time::Duration::from_secs(5);

        // Identity must be unlocked to know our clearnet port.
        let clearnet_port = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_none() {
                return;
            }
            *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner())
        };

        // Build the presence announcement.  `ts` is included so receivers can
        // apply a basic replay-prevention window if desired (§4.9.5).
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let announcement = serde_json::json!({
            "v": 1,
            "type": "mi_presence",
            "clearnet_port": clearnet_port,
            "ts": ts,
        });

        if let Ok(bytes) = serde_json::to_vec(&announcement) {
            // Broadcast to 255.255.255.255:7235 (LAN discovery port).
            let dest = std::net::SocketAddr::from(([255, 255, 255, 255], 7235));
            let _ = socket.send_to(&bytes, dest);
        }
    }

    // -----------------------------------------------------------------------
    // Inbound presence packet
    // -----------------------------------------------------------------------

    /// Process a single received LAN presence packet from `src`.
    ///
    /// Per §4.9.5, presence packets carry **no** cryptographic material.
    /// They only tell us that a Mesh Infinity node is reachable at a given
    /// IP:port.  We queue the endpoint for a TCP challenge-response handshake
    /// (`advance_lan_discovery_handshakes`) which is the first moment any key
    /// material is exchanged.
    ///
    /// Returns `Some(())` on success, `None` if the packet is malformed or
    /// should be ignored (our own broadcast, cooldown not expired).
    fn handle_lan_presence_packet(&self, data: &[u8], src: std::net::SocketAddr) -> Option<()> {
        // Parse the packet: must be well-formed JSON with type == "mi_presence".
        let pkt: serde_json::Value = serde_json::from_slice(data).ok()?;
        if pkt.get("type")?.as_str()? != "mi_presence" {
            return None;
        }
        if pkt.get("v")?.as_u64()? != 1 {
            return None;
        }

        // Extract the peer's TCP port.  Default to 7234 if absent.
        let clearnet_port = pkt
            .get("clearnet_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(7234);
        let src_ip = src.ip().to_string();
        let endpoint = format!("{src_ip}:{clearnet_port}");

        // Do not probe our own presence broadcast (same IP + port as our listener).
        let our_port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let our_ip_opt = local_clearnet_ip().map(|ip| ip.to_string());
        if clearnet_port as u16 == our_port {
            if let Some(our_ip) = our_ip_opt {
                if src_ip == our_ip {
                    return None;
                }
            }
        }

        // Cooldown: only queue an endpoint once per 60 seconds to prevent
        // amplification from a fast-broadcasting peer.
        const DISCOVERY_COOLDOWN_SECS: u64 = 60;
        {
            let seen = self
                .lan_discovery_seen
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(&last) = seen.get(&endpoint) {
                if last.elapsed().as_secs() < DISCOVERY_COOLDOWN_SECS {
                    return Some(());
                }
            }
        }

        // Queue for TCP challenge-response handshake in the next poll step.
        self.lan_discovery_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(endpoint);

        Some(())
    }

    // -----------------------------------------------------------------------
    // TCP challenge-response handshakes
    // -----------------------------------------------------------------------

    /// Drain the LAN discovery pending queue and perform TCP challenge-response
    /// handshakes with each candidate endpoint (§4.9.5).
    ///
    /// For each queued endpoint:
    ///   1. Connect TCP (100 ms timeout — LAN should be <5 ms).
    ///   2. Send:  `{"type":"mi_discover","nonce":"<32-byte-hex>"}` as a framed message.
    ///   3. Read:  `{"type":"mi_discover_ack","wg_pub":"<hex>","ed_pub":"<hex>","sig":"<hex>"}`.
    ///   4. Verify: Ed25519 sig over `DOMAIN_LAN_DISCOVER || nonce_bytes`.
    ///   5. If a known contact matches the wg_pub: update their endpoint and emit PeerUpdated.
    ///   6. If unknown: add to `mdns_discovered` cache so the UI can offer pairing.
    ///
    /// The cooldown in `lan_discovery_seen` is updated regardless of outcome,
    /// so a non-responsive or malicious endpoint only wastes one probe per 60 s.
    ///
    /// SECURITY: The nonce ensures each handshake is fresh (prevents replay).
    /// The Ed25519 signature proves the responder holds the private key
    /// corresponding to the advertised public key (prevents impersonation).
    /// No key material is sent by the initiator — the probe is read-only.
    pub fn advance_lan_discovery_handshakes(&self) {
        use std::io::Read;

        // Take ownership of the pending queue (no lock held during handshake).
        let pending: Vec<String> = {
            let mut guard = self
                .lan_discovery_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };
        if pending.is_empty() {
            return;
        }

        let now = std::time::Instant::now();

        for endpoint in pending {
            // Mark as seen immediately before the handshake attempt so even a
            // connection failure prevents re-queue for the cooldown window.
            self.lan_discovery_seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(endpoint.clone(), now);

            // Generate a fresh 32-byte nonce for this handshake.
            let mut nonce = [0u8; 32];
            if !try_random_fill(&mut nonce) {
                continue;
            }
            let nonce_hex = hex::encode(nonce);

            // Connect TCP with a short timeout (LAN is fast; > 100 ms = likely NAT/WAN).
            let addr = match endpoint.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let mut stream = match std::net::TcpStream::connect_timeout(
                &addr,
                std::time::Duration::from_millis(100),
            ) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Send the mi_discover request frame.
            let request = serde_json::json!({
                "type": "mi_discover",
                "nonce": nonce_hex,
            });
            let req_bytes = match serde_json::to_vec(&request) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if write_tcp_frame(&mut stream, &req_bytes).is_err() {
                continue;
            }

            // Read the mi_discover_ack with a generous LAN timeout.
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let ack_payload = loop {
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break None,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(frame) = try_read_frame(&mut buf) {
                            break Some(frame);
                        }
                    }
                }
            };
            let ack_payload = match ack_payload {
                Some(p) => p,
                None => continue,
            };

            // Parse and validate the ack.
            let ack: serde_json::Value = match serde_json::from_slice(&ack_payload) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if ack.get("type").and_then(|t| t.as_str()) != Some("mi_discover_ack") {
                continue;
            }

            // Extract required hex fields.
            let wg_pub_hex = match ack.get("wg_pub").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let ed_pub_hex = match ack.get("ed_pub").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let sig_hex = match ack.get("sig").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            // Decode keys and signature.
            let wg_pub_bytes: [u8; 32] = match hex::decode(wg_pub_hex)
                .ok()
                .filter(|b| b.len() == 32)
                .map(|b| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }) {
                Some(b) => b,
                None => continue,
            };
            let ed_pub_bytes: [u8; 32] = match hex::decode(ed_pub_hex)
                .ok()
                .filter(|b| b.len() == 32)
                .map(|b| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }) {
                Some(b) => b,
                None => continue,
            };
            let sig_bytes = match hex::decode(sig_hex).ok().filter(|b| b.len() == 64) {
                Some(b) => b,
                None => continue,
            };

            // SECURITY: Verify Ed25519_verify(ed_pub, DOMAIN_LAN_DISCOVER || nonce, sig).
            // This proves the responder possesses the private key for ed_pub.
            // The domain separator prevents cross-protocol signature reuse.
            // The fresh nonce prevents replay of old acks.
            // A failed verification means the responder is either not who they
            // claim (MITM) or is responding with a stale/forged ack — discard.
            if !crate::crypto::signing::verify(
                &ed_pub_bytes,
                crate::crypto::signing::DOMAIN_LAN_DISCOVER,
                &nonce,
                &sig_bytes,
            ) {
                continue;
            }

            // Signature valid — look up the contact by their mesh WireGuard
            // public key when available, falling back to the older x25519
            // field for contacts created before mesh transport keys were
            // stored explicitly.
            let matched: Option<(
                crate::identity::peer_id::PeerId,
                String,
                u8,
                bool,
                bool,
                bool,
                bool,
            )> = {
                let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                contacts
                    .all()
                    .into_iter()
                    .find(|c| c.mesh_x25519_public.unwrap_or(c.x25519_public) == wg_pub_bytes)
                    .map(|c| {
                        (
                            c.peer_id,
                            c.display_name.clone().unwrap_or_default(),
                            c.trust_level.value(),
                            c.can_be_exit_node,
                            c.can_be_wrapper_node,
                            c.can_be_store_forward,
                            c.can_endorse_peers,
                        )
                    })
            };

            if let Some((
                peer_id,
                display_name,
                trust_val,
                cap_exit,
                cap_wrapper,
                cap_sf,
                cap_endorse,
            )) = matched
            {
                // Known peer — update their clearnet endpoint and emit PeerUpdated.
                let wall = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                {
                    let mut contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(c) = contacts.get_mut(&peer_id) {
                        c.last_seen = Some(wall);
                        c.clearnet_endpoint = Some(endpoint.clone());
                    }
                }
                self.push_event(
                    "PeerUpdated",
                    serde_json::json!({
                        "id":               peer_id.to_hex(),
                        "name":             display_name,
                        "trustLevel":       trust_val,
                        "status":           "online",
                        "canBeExitNode":    cap_exit,
                        "canBeWrapperNode": cap_wrapper,
                        "canBeStoreForward": cap_sf,
                        "canEndorsePeers":  cap_endorse,
                    }),
                );
            } else {
                // Unknown peer — add to the discovery cache so the UI can
                // prompt pairing.  Keys come from the verified ack, not the
                // unauthenticated broadcast.
                let mut discovered = self
                    .mdns_discovered
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let already = discovered
                    .iter()
                    .any(|e| e.get("wgPub").and_then(|v| v.as_str()) == Some(wg_pub_hex));
                if !already {
                    discovered.push(serde_json::json!({
                        "wgPub":    wg_pub_hex,
                        "edPub":    ed_pub_hex,
                        "address":  endpoint,
                    }));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Handle inbound discover request
    // -----------------------------------------------------------------------

    /// Respond to an inbound LAN discovery request on an unauthenticated connection.
    ///
    /// Called from `clearnet_process_pending_incoming` when the first frame of
    /// an incoming connection has type `"mi_discover"`.  The connection is a
    /// one-shot probe — we respond and close it; it is never promoted to an
    /// identified long-lived connection.
    ///
    /// Response:
    /// `{"type":"mi_discover_ack","wg_pub":"<hex>","ed_pub":"<hex>","sig":"<hex>"}`
    /// where `sig = Ed25519_sign(ed_sign, DOMAIN_LAN_DISCOVER || nonce_bytes)`.
    ///
    /// Also emits a `DiscoveryRequest` event so the UI can log who probed us
    /// (non-passive activity — per §4.9.5).
    pub fn handle_lan_discover_request(&self, frame: &[u8], stream: &mut std::net::TcpStream) {
        // Parse the request — malformed frames are silently dropped.
        let req: serde_json::Value = match serde_json::from_slice(frame) {
            Ok(v) => v,
            Err(_) => return,
        };

        let nonce_hex = match req.get("nonce").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return,
        };
        let nonce_bytes = match hex::decode(nonce_hex).ok().filter(|b| b.len() == 32) {
            Some(b) => b,
            None => return,
        };

        // Extract our transport-facing mesh key and the signed identity key we
        // use to authenticate the probe response.
        let (wg_pub_bytes, ed_pub_bytes, ed_sign_bytes) = {
            let mesh_pub_bytes = match self
                .mesh_identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                Some(identity) => identity.public_bytes(),
                None => return,
            };
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                None => return, // Identity not unlocked — cannot sign the probe.
                Some(id) => (
                    mesh_pub_bytes,
                    id.ed25519_pub,
                    id.ed25519_signing.to_bytes(),
                ),
            }
        };

        // Sign: DOMAIN_LAN_DISCOVER || nonce_bytes so the initiator can verify
        // that we hold the signing key corresponding to our Ed25519 public key.
        let sig = crate::crypto::signing::sign(
            &ed_sign_bytes,
            crate::crypto::signing::DOMAIN_LAN_DISCOVER,
            &nonce_bytes,
        );

        let ack = serde_json::json!({
            "type":   "mi_discover_ack",
            "wg_pub": hex::encode(wg_pub_bytes),
            "ed_pub": hex::encode(ed_pub_bytes),
            "sig":    hex::encode(&sig),
        });

        // Best-effort write — if it fails the initiator will simply time out.
        if let Ok(bytes) = serde_json::to_vec(&ack) {
            let _ = write_tcp_frame(stream, &bytes);
        }

        // Emit DiscoveryRequest so the UI can show who probed us.
        // The remote IP is logged; probing requires active effort from the
        // initiator so this is non-passive activity per §4.9.5.
        let peer_addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        self.push_event(
            "DiscoveryRequest",
            serde_json::json!({
                "fromAddress": peer_addr,
            }),
        );
    }
}
