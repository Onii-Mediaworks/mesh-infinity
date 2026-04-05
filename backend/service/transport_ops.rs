//! Transport configuration and control operations for `MeshRuntime`.
//!
//! Covers all externally-driven transport mutations:
//! - **Clearnet TCP**: start/stop listener, set port, transport flags.
//! - **Tor hidden service**: enable/disable, get onion address, connect.
//! - **mDNS / LAN discovery**: enable/disable, query discovered peers.
//! - **VPN routing**: mode, exit node, clearnet route, status.
//! - **Overlay networks**: Tailscale auth + OAuth, ZeroTier connect, status.
//! - **SDR/RF**: configure, status, current FHSS channel, hardware list.
//! - **LoSec** low-traffic security mode: request, ambient status.
//! - **WireGuard** (synchronous API): initiate, respond, complete handshake.
//! - **Node mode** and **settings**: get/set node mode, get settings, toggle
//!   transport flags, set/get threat context, active conversation, security mode.
//!
//! ## Design note
//! Every method that mutates transport state calls `save_settings` before
//! returning so that the vault is always in sync with in-memory state.
//! The only exception is `set_clearnet_route`, which is a best-effort store
//! of routing hints that are not persisted across restarts.

use crate::network::threat_context::ThreatContext;
use crate::service::runtime::{MeshRuntime, TransportFlags, DEFAULT_HS_PORT};
use crate::vpn::app_connector::AppConnectorConfig;
use crate::vpn::routing_mode::RoutingMode;

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Clearnet TCP transport
    // -----------------------------------------------------------------------

    /// Start the clearnet TCP listener on the configured port.
    ///
    /// Binds a non-blocking `TcpListener` on `0.0.0.0:<clearnet_port>` and
    /// stores it in `clearnet_listener`.  Once started, `advance_clearnet_transport`
    /// (called on every poll cycle) will accept connections and process frames.
    ///
    /// Returns `Ok(())` on success, `Err(String)` if the listener could not
    /// be bound (e.g. port in use, permission denied).
    pub fn start_clearnet_listener(&self) -> Result<(), String> {
        if self
            .clearnet_listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(());
        }
        let port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        match std::net::TcpListener::bind(addr) {
            Ok(listener) => {
                // Non-blocking so the poll loop can drain without stalling.
                listener
                    .set_nonblocking(true)
                    .map_err(|e| format!("set_nonblocking failed: {e}"))?;
                *self
                    .clearnet_listener
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(listener);
                Ok(())
            }
            Err(e) => Err(format!("failed to bind clearnet listener on :{port}: {e}")),
        }
    }

    /// Stop the clearnet TCP listener and close all active connections.
    ///
    /// Drops the `TcpListener` and clears the connection map, pending-incoming
    /// queue, and receive buffers.  Idempotent — safe to call when already stopped.
    pub fn stop_clearnet_listener(&self) {
        // Dropping the listener closes the OS socket.
        *self
            .clearnet_listener
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        // Close all established connections.
        self.clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.clearnet_pending_incoming
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.clearnet_recv_buffers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Set the clearnet TCP listen port.
    ///
    /// Takes effect on the next `start_clearnet_listener` call.  Persists the
    /// value to vault via `save_settings`.  Port 0 is rejected.
    pub fn set_clearnet_port(&self, port: u16) -> Result<(), String> {
        if port == 0 {
            return Err("port 0 is not valid".into());
        }
        *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()) = port;
        self.emit_settings_updated();
        self.save_settings();
        Ok(())
    }

    /// Persist the mesh participation profile (0 = minimal, 1 = standard, 2 = generous).
    pub fn set_bandwidth_profile(&self, profile: u8) -> Result<(), String> {
        if profile > 2 {
            return Err("invalid bandwidth profile".into());
        }
        *self
            .bandwidth_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = profile;
        self.emit_settings_updated();
        self.save_settings();
        Ok(())
    }

    /// Unlock the next feature tier up to `target_tier` (0 = social .. 4 = power).
    pub fn set_active_tier(&self, target_tier: u8) -> Result<(), String> {
        if target_tier > 4 {
            return Err("invalid tier".into());
        }
        let mut active_tier = self.active_tier.lock().unwrap_or_else(|e| e.into_inner());
        if target_tier < *active_tier {
            return Err("tier downgrade is not supported here".into());
        }
        if target_tier > active_tier.saturating_add(1) {
            return Err("tiers must be unlocked sequentially".into());
        }
        if target_tier == *active_tier {
            return Ok(());
        }
        *active_tier = target_tier;
        drop(active_tier);
        self.emit_settings_updated();
        self.save_settings();
        Ok(())
    }

    /// Apply a JSON transport-flags patch to the current flag set.
    ///
    /// Each key in `flags_json` is optional; missing keys leave the current
    /// value unchanged.  Emits `SettingsUpdated` and persists to vault.
    pub fn set_transport_flags(&self, flags_json: &str) -> Result<(), String> {
        let parsed: serde_json::Value =
            serde_json::from_str(flags_json).map_err(|e| e.to_string())?;

        // Helper closure — reads a bool key or falls back to the current value.
        let get_bool = |key: &str, default: bool| -> bool {
            parsed.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
        };

        {
            let mut f = self
                .transport_flags
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            f.tor = get_bool("tor", f.tor);
            f.clearnet = get_bool("clearnet", f.clearnet);
            f.clearnet_fallback = get_bool("clearnet_fallback", f.clearnet_fallback);
            f.i2p = get_bool("i2p", f.i2p);
            f.bluetooth = get_bool("bluetooth", f.bluetooth);
            f.rf = get_bool("rf", f.rf);
            f.mesh_discovery = get_bool("mesh_discovery", f.mesh_discovery);
            f.allow_relays = get_bool("allow_relays", f.allow_relays);
        }

        self.reconcile_layer1_runtime()?;
        self.emit_settings_updated();
        self.save_settings();
        Ok(())
    }

    /// Toggle a single transport flag by name.
    ///
    /// Valid names: `"tor"`, `"clearnet"`, `"clearnet_fallback"`, `"i2p"`,
    /// `"bluetooth"`, `"rf"`, `"mesh_discovery"`, `"relays"`.
    ///
    /// Emits `SettingsUpdated` and persists to vault.
    pub fn toggle_transport_flag(&self, transport: &str, enabled: bool) -> Result<(), String> {
        {
            let mut f = self
                .transport_flags
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match transport {
                "tor" => f.tor = enabled,
                "clearnet" => f.clearnet = enabled,
                "clearnet_fallback" => f.clearnet_fallback = enabled,
                "i2p" => f.i2p = enabled,
                "bluetooth" => f.bluetooth = enabled,
                "rf" => f.rf = enabled,
                "mesh_discovery" => f.mesh_discovery = enabled,
                "relays" => f.allow_relays = enabled,
                _ => return Err(format!("unknown transport flag: {transport}")),
            }
        }

        self.reconcile_layer1_runtime()?;
        self.emit_settings_updated();
        self.save_settings();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Tor transport (§5.3)
    // -----------------------------------------------------------------------

    /// Bootstrap the Tor hidden service and set `tor = true` in flags.
    ///
    /// Derives the onion address from the identity master key
    /// (HKDF-SHA256 domain `"meshinfinity-tor-service-v1"`), then calls
    /// `TorTransport::bootstrap`.  On success, inbound hidden-service
    /// connections are drained by `advance_clearnet_transport` on every poll.
    ///
    /// Idempotent — returns `Ok(())` if Tor is already running.
    pub fn tor_enable(&self) -> Result<(), String> {
        // Idempotent: if Tor is already running, return success immediately.
        // This allows Flutter to call tor_enable() on every app resume without
        // worrying about double-bootstrap.
        if self
            .tor_transport
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(());
        }

        // Require an unlocked identity because the Tor v3 onion address is
        // deterministically derived from the identity master key via
        // HKDF-SHA256 with domain "meshinfinity-tor-service-v1".  This means
        // the same identity always produces the same onion address, which
        // allows peers to reach us at a stable .onion even across restarts.
        let (master_key, peer_id_hex) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = guard.as_ref().ok_or("identity not unlocked")?;
            (*id.master_key, id.peer_id().to_hex())
        };

        let state_dir = std::path::PathBuf::from(&self.data_dir);
        let transport = crate::transport::tor::TorTransport::bootstrap(
            &master_key,
            &peer_id_hex,
            &state_dir,
            DEFAULT_HS_PORT,
        )
        .map_err(|e| format!("Tor bootstrap failed: {e}"))?;

        let onion_addr = transport.onion_address.clone();
        *self.tor_transport.lock().unwrap_or_else(|e| e.into_inner()) = Some(transport);
        self.transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tor = true;
        self.save_settings();

        tracing::info!("Tor transport enabled — onion address: {}", onion_addr);
        Ok(())
    }

    /// Disable the Tor transport and shut down the hidden service.
    ///
    /// Drops the `TorTransport` (which closes the runtime and all circuits).
    /// Idempotent.
    pub fn tor_disable(&self) {
        *self.tor_transport.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tor = false;
        self.save_settings();
    }

    /// Return our Tor v3 onion address, or an error string if Tor is disabled.
    pub fn tor_get_onion_address(&self) -> Result<String, String> {
        let guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .map(|t| t.onion_address.clone())
            .ok_or_else(|| "Tor not enabled".into())
    }

    /// Connect to a peer via the Tor network.
    ///
    /// Opens a Tor `DataStream` to `onion_addr:port` and inserts the resulting
    /// `TcpStream` into `clearnet_connections` under `peer_id_hex`.  Port 0
    /// defaults to `DEFAULT_HS_PORT` (7234).
    pub fn tor_connect(
        &self,
        peer_id_hex: &str,
        onion_addr: &str,
        port: u16,
    ) -> Result<(), String> {
        let port = if port == 0 { DEFAULT_HS_PORT } else { port };
        let guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
        let tor = guard.as_ref().ok_or("Tor not enabled")?;
        let stream = tor
            .connect(peer_id_hex, onion_addr, port)
            .map_err(|e| format!("tor_connect: {e}"))?;
        self.clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer_id_hex.to_string(), stream);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // mDNS / LAN discovery
    // -----------------------------------------------------------------------

    /// Enable mDNS peer discovery on the local network (§4.6).
    ///
    /// Binds a UDP broadcast socket on `0.0.0.0:7235`, marks
    /// `mdns_running = true`, and resets the announce timer so the first
    /// presence broadcast is sent on the next poll tick.
    ///
    /// The socket is set to broadcast mode (SO_BROADCAST) and non-blocking
    /// so presence packets can be sent to `255.255.255.255:7235` and received
    /// without stalling the poll loop.
    ///
    /// Emits `MdnsStarted`.
    pub fn mdns_enable(&self) {
        // Bind the UDP discovery socket if not already bound (idempotent).
        {
            let mut sock_guard = self
                .lan_discovery_socket
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if sock_guard.is_none() {
                match std::net::UdpSocket::bind("0.0.0.0:7235") {
                    Ok(socket) => {
                        // Broadcast + non-blocking so the poll loop can drain
                        // packets without blocking.
                        let _ = socket.set_broadcast(true);
                        let _ = socket.set_nonblocking(true);
                        *sock_guard = Some(socket);
                    }
                    Err(_) => {
                        // Port in use or permission denied — still mark as running;
                        // receive side will be silent but announce still attempted.
                    }
                }
            }
        }

        *self.mdns_running.lock().unwrap_or_else(|e| e.into_inner()) = true;
        // Reset the announce timer so we send immediately on the next tick.
        *self
            .lan_next_announce
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            std::time::Instant::now() - std::time::Duration::from_secs(1);
        self.push_event("MdnsStarted", serde_json::json!({}));
    }

    /// Disable mDNS peer discovery and clear the discovered-peers cache.
    ///
    /// Drops the UDP socket and emits `MdnsStopped`.
    pub fn mdns_disable(&self) {
        *self.mdns_running.lock().unwrap_or_else(|e| e.into_inner()) = false;
        self.mdns_discovered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        // Drop the socket to stop receiving broadcasts.
        *self
            .lan_discovery_socket
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.push_event("MdnsStopped", serde_json::json!({}));
    }

    /// Returns `true` if mDNS is currently running.
    pub fn mdns_is_running(&self) -> bool {
        *self.mdns_running.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Return the mDNS-discovered peers as a JSON array string.
    ///
    /// Each entry: `{"peerId": "...", "name": "...", "address": "...", "trustLevel": N}`.
    pub fn mdns_get_discovered_peers(&self) -> String {
        let peers = self
            .mdns_discovered
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        serde_json::to_string(&*peers).unwrap_or_else(|_| "[]".into())
    }

    // -----------------------------------------------------------------------
    // VPN routing (§6.9)
    // -----------------------------------------------------------------------

    /// Configure VPN routing rules from a JSON object.
    ///
    /// Emits `ClearnetRouteChanged` so the Flutter network screen can reflect
    /// the new routing policy.  The payload is stored in the event only and
    /// not persisted to vault (routing rules are ephemeral).
    pub fn set_clearnet_route(&self, route_json: &str) -> Result<(), String> {
        let value: serde_json::Value = serde_json::from_str(route_json)
            .unwrap_or_else(|_| serde_json::json!({ "raw": route_json }));
        self.push_event("ClearnetRouteChanged", value);
        Ok(())
    }

    /// Set the VPN routing mode (§6.9).
    ///
    /// `mode_json` fields:
    /// - `"mode"`: `"off"` | `"mesh_only"` | `"exit_node"` | `"policy"` | `"policy_based"`
    /// - `"killSwitch"`: `"permissive"` | `"strict"`
    /// - `"exitNodePeerId"`: optional hex peer ID for exit-node egress
    /// - `"tailscaleExitNode"`: optional tailnet peer name for Tailscale exit-node egress
    /// - `"exitProfileId"`: optional hex profile ID for provider/profile egress
    ///
    /// Emits `VpnModeChanged`.
    pub fn set_vpn_mode(&self, mode_json: &str) -> Result<(), String> {
        let config: serde_json::Value =
            serde_json::from_str(mode_json).map_err(|e| e.to_string())?;
        let mode_str = config.get("mode").and_then(|v| v.as_str()).unwrap_or("off");
        let mode = match mode_str {
            "off" => RoutingMode::Off,
            "mesh_only" => RoutingMode::MeshOnly,
            "exit_node" => RoutingMode::ExitNode,
            "policy" | "policy_based" => RoutingMode::PolicyBased,
            _ => return Err(format!("unknown VPN mode: {mode_str}")),
        };
        let kill_switch = match config
            .get("killSwitch")
            .and_then(|v| v.as_str())
            .unwrap_or("strict")
        {
            "strict" => crate::vpn::routing_mode::KillSwitchMode::Strict,
            "permissive" => crate::vpn::routing_mode::KillSwitchMode::Permissive,
            other => return Err(format!("unknown kill switch mode: {other}")),
        };

        let exit_peer_id = match config.get("exitNodePeerId").and_then(|v| v.as_str()) {
            Some("") | None => None,
            Some(peer_id_hex) => Some(
                hex::decode(peer_id_hex)
                    .ok()
                    .filter(|b| b.len() == 32)
                    .map(|b| {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        a
                    })
                    .ok_or("invalid exitNodePeerId")?,
            ),
        };

        let exit_profile_id = match config.get("exitProfileId").and_then(|v| v.as_str()) {
            Some("") | None => None,
            Some(profile_id_hex) => Some(
                hex::decode(profile_id_hex)
                    .ok()
                    .filter(|b| b.len() == 16)
                    .map(|b| {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&b);
                        a
                    })
                    .ok_or("invalid exitProfileId")?,
            ),
        };
        let tailscale_exit_node = config
            .get("tailscaleExitNode")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);

        // Apply the mode using the backend-owned App Connector state so
        // policy-based routing cannot activate without real rules.
        let threat = self.threat_context;
        let has_policy_rules = !self
            .app_connector_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .apps
            .is_empty();
        let mut vpn = self.vpn.lock().unwrap_or_else(|e| e.into_inner());
        vpn.config.kill_switch = kill_switch;
        if config.get("exitNodePeerId").is_some() {
            vpn.config.exit_peer_id = exit_peer_id;
            if vpn.config.exit_peer_id.is_some() {
                vpn.config.tailscale_exit_node = None;
            }
        }
        if config.get("tailscaleExitNode").is_some() {
            vpn.config.tailscale_exit_node = tailscale_exit_node;
            if vpn.config.tailscale_exit_node.is_some() {
                vpn.config.exit_peer_id = None;
            }
        }
        if config.get("exitProfileId").is_some() {
            vpn.config.exit_profile_id = exit_profile_id;
        }
        vpn.set_mode(mode, threat, has_policy_rules)
            .map_err(|e| format!("{e:?}"))?;

        self.push_event(
            "VpnModeChanged",
            serde_json::json!({
                "mode": mode_str,
                "exitNodePeerId": vpn.config.exit_peer_id.map(hex::encode),
                "tailscaleExitNode": vpn.config.tailscale_exit_node,
                "exitProfileId": vpn.config.exit_profile_id.map(hex::encode),
            }),
        );
        Ok(())
    }

    /// Set or clear the exit-node peer for VPN `exit_node` mode (§6.9.2).
    ///
    /// Pass an empty string to clear the current exit node.
    pub fn set_exit_node(&self, peer_id_hex: &str) -> Result<(), String> {
        if peer_id_hex.is_empty() {
            self.vpn
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .config
                .exit_peer_id = None;
            self.vpn
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .config
                .tailscale_exit_node = None;
            self.push_event("ExitNodeChanged", serde_json::json!({ "peerId": null }));
            return Ok(());
        }

        let bytes: [u8; 32] = hex::decode(peer_id_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .ok_or("invalid peer_id_hex")?;

        self.vpn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .config
            .exit_peer_id = Some(bytes);
        self.vpn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .config
            .tailscale_exit_node = None;
        self.push_event(
            "ExitNodeChanged",
            serde_json::json!({ "peerId": peer_id_hex }),
        );
        Ok(())
    }

    /// Get the current VPN status as a JSON string.
    ///
    /// Returns fields the Flutter UI consumes directly:
    /// `enabled`, `mode`, `connectionStatus`, `killSwitch`,
    /// `exitNodePeerId`, `uptimeSeconds`, `internetAllowed`,
    /// `securityPosture`, `changesInternetIp`, `exitNodeSeesDestinations`,
    /// `exitProfileId`, `exitRouteKind`.
    pub fn get_vpn_status(&self) -> String {
        let vpn = self.vpn.lock().unwrap_or_else(|e| e.into_inner());
        let mode = match vpn.config.mode {
            RoutingMode::Off => "off",
            RoutingMode::MeshOnly => "mesh_only",
            RoutingMode::ExitNode => "exit_node",
            RoutingMode::PolicyBased => "policy_based",
        };
        let security_posture = match vpn.config.mode {
            RoutingMode::Off => "normal_network",
            RoutingMode::MeshOnly => "mesh_only",
            RoutingMode::ExitNode => {
                if vpn.config.tailscale_exit_node.is_some() {
                    "tailscale_exit_node"
                } else if vpn.config.exit_profile_id.is_some() {
                    "exit_node_profile"
                } else {
                    "exit_node"
                }
            }
            RoutingMode::PolicyBased => {
                if vpn.config.exit_profile_id.is_some() {
                    "policy_based_profile"
                } else {
                    "policy_based"
                }
            }
        };
        let has_exit_egress =
            vpn.config.exit_peer_id.is_some() || vpn.config.tailscale_exit_node.is_some();
        let exit_route_kind = match (
            vpn.config.exit_peer_id.is_some(),
            vpn.config.tailscale_exit_node.is_some(),
            vpn.config.exit_profile_id.is_some(),
        ) {
            (false, false, false) => "none",
            (true, false, false) => "peer_exit",
            (false, true, false) => "tailscale_exit",
            (true, false, true) => "profile_exit",
            (false, false, true) => "profile_only",
            (false, true, true) => "tailscale_profile_exit",
            (true, true, false) => "peer_exit",
            (true, true, true) => "profile_exit",
        };
        let connection_status = match vpn.state {
            crate::vpn::routing_mode::VpnState::Inactive => "disconnected",
            crate::vpn::routing_mode::VpnState::Connecting => "connecting",
            crate::vpn::routing_mode::VpnState::Active => "connected",
            crate::vpn::routing_mode::VpnState::KillSwitchEngaged => "blocked",
            crate::vpn::routing_mode::VpnState::Disconnecting => "disconnecting",
        };
        serde_json::json!({
            "enabled":         vpn.config.mode != RoutingMode::Off,
            "mode":            mode,
            "connectionStatus": connection_status,
            "killSwitch":      vpn.config.kill_switch == crate::vpn::routing_mode::KillSwitchMode::Strict,
            "exitNodePeerId":  vpn.config.exit_peer_id.map(hex::encode),
            "tailscaleExitNode": vpn.config.tailscale_exit_node,
            "exitProfileId":   vpn.config.exit_profile_id.map(hex::encode),
            "uptimeSeconds":   0,
            "internetAllowed": vpn.internet_traffic_allowed(),
            "securityPosture": security_posture,
            "changesInternetIp": vpn.config.mode == RoutingMode::ExitNode && has_exit_egress,
            "exitNodeSeesDestinations": has_exit_egress,
            "exitRouteKind": exit_route_kind,
        })
        .to_string()
    }

    /// Return the current App Connector configuration as JSON.
    pub fn get_app_connector_config(&self) -> String {
        let config = self
            .app_connector_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        serde_json::to_string(&config)
            .unwrap_or_else(|_| "{\"mode\":\"allowlist\",\"apps\":[],\"rules\":[]}".to_string())
    }

    /// Return the backend-owned Android VPN enforcement policy as JSON.
    ///
    /// This is the native policy surface for Android `VpnService` integration.
    /// Flutter may trigger synchronization, but Rust remains the source of
    /// truth for which apps should be captured by the OS VPN layer.
    pub fn get_android_vpn_policy(&self) -> String {
        let vpn = self.vpn.lock().unwrap_or_else(|e| e.into_inner());
        let config = self
            .app_connector_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let mut app_ids = config
            .apps
            .iter()
            .map(|app| app.app_id.clone())
            .collect::<Vec<_>>();
        app_ids.extend(config.rules.iter().filter_map(|rule| {
            rule.app_selector
                .app_id
                .as_ref()
                .map(|app_id| app_id.trim().to_string())
                .filter(|app_id| !app_id.is_empty())
        }));
        app_ids.sort();
        app_ids.dedup();

        let unresolved_selector_rule_count = config
            .rules
            .iter()
            .filter(|rule| {
                rule.app_selector.app_id.is_none()
                    || rule.app_selector.domain_pattern.is_some()
                    || rule.app_selector.ip_range.is_some()
                    || rule.app_selector.port.is_some()
            })
            .count();

        let enabled = vpn.config.mode == RoutingMode::PolicyBased && !app_ids.is_empty();
        let (allowed_apps, disallowed_apps, app_mode) = match config.mode {
            crate::vpn::app_connector::AppConnectorMode::Allowlist => {
                (app_ids.clone(), Vec::<String>::new(), "allowlist")
            }
            crate::vpn::app_connector::AppConnectorMode::Denylist => {
                (Vec::<String>::new(), app_ids.clone(), "denylist")
            }
        };

        serde_json::json!({
            "enabled": enabled,
            "mode": if enabled { "policy_based" } else { "off" },
            "sessionName": "Mesh Infinity App Connector",
            "mtu": 1280,
            "requiresFullTunnel": enabled,
            "allowedApps": allowed_apps,
            "disallowedApps": disallowed_apps,
            "appMode": app_mode,
            "unresolvedSelectorRuleCount": unresolved_selector_rule_count,
        })
        .to_string()
    }

    /// Replace the current App Connector configuration from a JSON payload.
    pub fn set_app_connector_config(&self, config_json: &str) -> Result<(), String> {
        let mut config: AppConnectorConfig =
            serde_json::from_str(config_json).map_err(|e| e.to_string())?;

        for app in &mut config.apps {
            app.app_id = app.app_id.trim().to_string();
            app.name = app.name.trim().to_string();
            if app.app_id.is_empty() {
                return Err("app connector entries require a non-empty app_id".into());
            }
            if app.name.is_empty() {
                app.name = app.app_id.clone();
            }
        }

        config.apps.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        config.apps.dedup_by(|a, b| a.app_id == b.app_id);

        for rule in &mut config.rules {
            rule.app_selector.app_id = rule
                .app_selector
                .app_id
                .take()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            rule.app_selector.domain_pattern = rule
                .app_selector
                .domain_pattern
                .take()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            rule.app_selector.ip_range = rule
                .app_selector
                .ip_range
                .take()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            if let Some(ip_range) = &rule.app_selector.ip_range {
                if !ip_range.contains('/') {
                    return Err("app connector ip_range must be CIDR notation".into());
                }
            }
            if rule.app_selector.is_empty() {
                return Err("app connector rules require at least one selector".into());
            }
            match &mut rule.routing_target {
                crate::vpn::app_connector::RoutingTarget::ExitNode { peer_id, profile } => {
                    *peer_id = peer_id.trim().to_string();
                    if peer_id.is_empty() {
                        return Err("exit node rules require a peer_id".into());
                    }
                    if let Some(profile_id) = profile {
                        *profile_id = profile_id.trim().to_string();
                        if profile_id.is_empty() {
                            *profile = None;
                        }
                    }
                }
                crate::vpn::app_connector::RoutingTarget::Infinet { infinet_id } => {
                    *infinet_id = infinet_id.trim().to_string();
                    if infinet_id.is_empty() {
                        return Err("infinet rules require an infinet_id".into());
                    }
                }
                _ => {}
            }
        }

        config.rules.sort_by(|a, b| {
            a.priority.cmp(&b.priority).then_with(|| {
                b.app_selector
                    .specificity()
                    .cmp(&a.app_selector.specificity())
            })
        });
        config.rules.dedup_by(|a, b| a == b);

        *self
            .app_connector_config
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = config.clone();
        self.save_settings();
        self.push_event(
            "AppConnectorConfigChanged",
            serde_json::to_value(config).unwrap_or_else(|_| serde_json::json!({})),
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Overlay networks — Tailscale and ZeroTier (§5.22, §5.23)
    // -----------------------------------------------------------------------

    fn overlay_hostname(&self) -> String {
        std::env::var("HOSTNAME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "mesh-infinity".to_string())
    }

    fn overlay_mesh_pubkey(&self) -> Result<[u8; 32], String> {
        self.mesh_identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|identity| identity.public_bytes())
            .ok_or_else(|| "Mesh identity is not available".to_string())
    }

    fn overlay_local_identity_pubkey(&self) -> Result<[u8; 32], String> {
        self.identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|identity| identity.ed25519_pub)
            .ok_or_else(|| {
                "Identity must be unlocked before configuring overlay clients".to_string()
            })
    }

    fn sync_tailscale_client(&self) -> Result<(), String> {
        use crate::transport::overlay_client::{
            OverlayClientStatus, TailscaleController as OverlayController, TailscaleDeviceInfo,
            TailscalePeer as OverlayPeer,
        };
        use crate::transport::tailscale::{TailscaleAuth, TailscaleClient as ControlClient};

        let credentials = {
            self.overlay
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .tailscale
                .credentials
                .clone()
        }
        .ok_or_else(|| "Tailscale is not configured".to_string())?;

        let wg_pubkey = self.overlay_mesh_pubkey()?;
        let hostname = self.overlay_hostname();
        let client = match &credentials.controller {
            OverlayController::Vendor => ControlClient::new_central(wg_pubkey, &hostname),
            OverlayController::Headscale { url } => {
                ControlClient::new_headscale(url, wg_pubkey, &hostname)
            }
        };

        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to create overlay runtime: {e}"))?;
        let register = runtime
            .block_on(client.register(TailscaleAuth::AuthKey(credentials.auth_token.clone())))
            .map_err(|e| format!("Tailscale registration failed: {e}"))?;

        let map = if register.node_authorized {
            Some(
                runtime
                    .block_on(client.poll_map_once())
                    .map_err(|e| format!("Tailscale map sync failed: {e}"))?,
            )
        } else {
            None
        };

        let relay_mode = if client.best_derp_relay().is_some() {
            if self
                .overlay
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .tailscale
                .prefer_mesh_relay
            {
                "mesh_preferred"
            } else {
                "derp"
            }
        } else {
            "direct"
        };

        let mapped_peers: Vec<OverlayPeer> = map
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .peers
                    .iter()
                    .map(|peer| OverlayPeer {
                        name: peer.name.clone(),
                        ip: peer
                            .addresses
                            .iter()
                            .find(|addr| addr.starts_with("100."))
                            .cloned()
                            .or_else(|| peer.addresses.first().cloned())
                            .unwrap_or_default(),
                        online: peer.online,
                        is_exit_node: peer.exit_node_option,
                        os: String::new(),
                        last_seen: 0,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let device_info = if register.node_authorized {
            let tailscale_ip = register
                .ip_addresses
                .iter()
                .find(|addr| addr.starts_with("100."))
                .cloned()
                .or_else(|| register.ip_addresses.first().cloned())
                .unwrap_or_default();
            Some(TailscaleDeviceInfo {
                tailscale_ip,
                device_name: if register.machine_name.is_empty() {
                    hostname
                } else {
                    register.machine_name.clone()
                },
                tailnet_name: credentials.controller.base_url().to_string(),
                can_be_exit_node: false,
                os: std::env::consts::OS.to_string(),
            })
        } else {
            None
        };
        let key_expiry_ms = map
            .as_ref()
            .map(|snapshot| snapshot.key_expiry)
            .unwrap_or(0);

        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        overlay.tailscale.status = if register.node_authorized {
            OverlayClientStatus::Connected
        } else if register.auth_url.is_some() {
            OverlayClientStatus::Connecting
        } else {
            OverlayClientStatus::Disconnected
        };
        overlay.tailscale.device_info = device_info;
        overlay.tailscale.peers = mapped_peers;
        overlay.tailscale.relay_mode = relay_mode.to_string();
        overlay.tailscale.key_expiry_ms = key_expiry_ms;
        overlay.tailscale.active_exit_node =
            overlay.tailscale.active_exit_node.clone().filter(|active| {
                overlay
                    .tailscale
                    .peers
                    .iter()
                    .any(|peer| peer.name == *active)
            });
        drop(overlay);

        self.save_overlay_state();
        self.push_event(
            "OverlayStatusChanged",
            serde_json::json!({
                "overlay": "tailscale",
                "status": if register.node_authorized { "connected" } else { "connecting" },
                "relayMode": relay_mode,
                "authUrl": register.auth_url,
            }),
        );
        Ok(())
    }

    fn sync_zerotier_client(&self) -> Result<(), String> {
        use crate::transport::overlay_client::{
            OverlayClientStatus, ZeroTierController as OverlayController, ZeroTierMember,
            ZeroTierNetwork, ZeroTierNetworkAuthStatus,
        };
        use crate::transport::zerotier::{ZeroTierTransport, ZtControllerClient, ZtNodeId};

        let credentials = {
            self.overlay
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .zerotier
                .credentials
                .clone()
        }
        .ok_or_else(|| "ZeroTier is not configured".to_string())?;

        let ed25519_pub = self.overlay_local_identity_pubkey()?;
        let node_id = ZtNodeId::from_ed25519(&ed25519_pub).to_hex();
        let mut transport = ZeroTierTransport::new(&ed25519_pub);
        let _ = transport.bind(0);
        let _ = transport.hello_roots();
        for network_id in &credentials.network_ids {
            transport.join_network(network_id);
        }

        let controller = match &credentials.controller {
            OverlayController::Central => ZtControllerClient::central(&credentials.api_key),
            OverlayController::SelfHosted { url } => {
                ZtControllerClient::self_hosted(url, &credentials.api_key)
            }
        };
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to create overlay runtime: {e}"))?;

        let mut networks = Vec::new();
        let mut members = Vec::new();
        let mut any_authorized = false;

        for network_id in &credentials.network_ids {
            let network_config = runtime
                .block_on(controller.get_network(network_id))
                .map_err(|e| format!("ZeroTier network query failed for {network_id}: {e}"))?;
            let member_values = runtime
                .block_on(controller.list_members(network_id))
                .map_err(|e| format!("ZeroTier member query failed for {network_id}: {e}"))?;

            let mut our_assigned_ip = network_config.assigned_ip.map(|ip| ip.to_string());
            let mut auth_status = if network_config.authorized {
                ZeroTierNetworkAuthStatus::Authorized
            } else {
                ZeroTierNetworkAuthStatus::AwaitingAuthorization
            };
            let mut authorized_count = 0usize;

            for member in member_values {
                let node_id_value = member
                    .get("nodeId")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string();
                let name = member
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string();
                let config = member.get("config").cloned().unwrap_or_default();
                let authorized = config
                    .get("authorized")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false);
                if authorized {
                    authorized_count += 1;
                }
                let ips: Vec<String> = config
                    .get("ipAssignments")
                    .and_then(|value| value.as_array())
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| value.as_str().map(ToString::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if node_id_value == node_id {
                    our_assigned_ip = ips.first().cloned().or(our_assigned_ip);
                    auth_status = if authorized {
                        any_authorized = true;
                        ZeroTierNetworkAuthStatus::Authorized
                    } else {
                        ZeroTierNetworkAuthStatus::AwaitingAuthorization
                    };
                }
                members.push(ZeroTierMember {
                    network_id: network_id.clone(),
                    node_id: node_id_value,
                    name,
                    ips,
                    authorized,
                    last_seen: member
                        .get("lastOnline")
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0),
                });
            }

            networks.push(ZeroTierNetwork {
                network_id: network_id.clone(),
                name: network_config.name,
                assigned_ip: our_assigned_ip,
                auth_status,
                member_count: authorized_count,
            });
        }

        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        overlay.zerotier.node_id = Some(node_id.clone());
        overlay.zerotier.networks = networks;
        overlay.zerotier.members = members;
        overlay.zerotier.relay_mode = if overlay.zerotier.prefer_mesh_relay {
            "mesh_preferred".to_string()
        } else {
            "vendor_relay".to_string()
        };
        overlay.zerotier.status = if any_authorized {
            OverlayClientStatus::Connected
        } else {
            OverlayClientStatus::Connecting
        };
        drop(overlay);

        self.save_overlay_state();
        self.push_event(
            "OverlayStatusChanged",
            serde_json::json!({
                "overlay": "zerotier",
                "status": if any_authorized { "connected" } else { "connecting" },
                "nodeId": node_id,
            }),
        );
        Ok(())
    }

    /// Authenticate the Tailscale client with an auth key.
    ///
    /// Stores the credential in the overlay manager, marks the client as
    /// `Connecting`, and emits `TailscaleConnecting`.  The actual WireGuard
    /// handshake with the control plane happens asynchronously.
    ///
    /// `auth_key`: a Tailscale auth key (`tskey-auth-…`) or OAuth token.
    /// `control_url`: empty string for the official server, or a Headscale URL.
    pub fn tailscale_auth_key(&self, auth_key: &str, control_url: &str) -> Result<(), String> {
        use crate::transport::overlay_client::{
            OverlayClientStatus, TailscaleController, TailscaleCredentials,
        };

        if auth_key.is_empty() {
            return Err("auth_key must not be empty".into());
        }

        let controller = if control_url.is_empty() {
            TailscaleController::Vendor
        } else {
            TailscaleController::Headscale {
                url: control_url.to_string(),
            }
        };
        let creds = TailscaleCredentials {
            controller,
            auth_token: auth_key.to_string(),
            is_auth_key: true,
        };

        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        overlay.tailscale.credentials = Some(creds);
        overlay.tailscale.status = OverlayClientStatus::Connecting;
        drop(overlay);
        self.save_overlay_state();

        self.push_event("TailscaleConnecting", serde_json::json!({}));
        self.sync_tailscale_client()
    }

    /// Begin the Tailscale OAuth interactive login flow.
    ///
    /// Marks the client as `Connecting` and emits `TailscaleOAuthUrl` with
    /// the redirect URL for the UI to open in a browser.
    ///
    /// `control_url`: empty string for official server, or Headscale URL.
    pub fn tailscale_begin_oauth(&self, control_url: &str) -> Result<(), String> {
        use crate::transport::overlay_client::{OverlayClientStatus, TailscaleController};
        use crate::transport::tailscale::{TailscaleAuth, TailscaleClient as ControlClient};

        let controller = if control_url.is_empty() {
            TailscaleController::Vendor
        } else {
            TailscaleController::Headscale {
                url: control_url.to_string(),
            }
        };
        let wg_pubkey = self.overlay_mesh_pubkey()?;
        let hostname = self.overlay_hostname();
        let client = match &controller {
            TailscaleController::Vendor => ControlClient::new_central(wg_pubkey, &hostname),
            TailscaleController::Headscale { url } => {
                ControlClient::new_headscale(url, wg_pubkey, &hostname)
            }
        };
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to create overlay runtime: {e}"))?;
        let register = runtime
            .block_on(client.register(TailscaleAuth::AuthUrl(String::new())))
            .map_err(|e| format!("Tailscale OAuth start failed: {e}"))?;
        let oauth_url = register
            .auth_url
            .unwrap_or_else(|| format!("{}/a/", controller.base_url()));

        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        overlay.tailscale.status = OverlayClientStatus::Connecting;
        drop(overlay);
        self.save_overlay_state();

        self.push_event("TailscaleOAuthUrl", serde_json::json!({ "url": oauth_url }));
        Ok(())
    }

    /// Disconnect and forget the current Tailscale configuration.
    pub fn tailscale_disconnect(&self) -> Result<(), String> {
        use crate::transport::overlay_client::{OverlayClientStatus, TailscaleClient};

        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        overlay.tailscale = TailscaleClient::new();
        overlay.tailscale.status = OverlayClientStatus::NotConfigured;
        drop(overlay);
        self.save_overlay_state();
        self.push_event(
            "OverlayStatusChanged",
            serde_json::json!({
                "overlay": "tailscale",
                "status": "not_configured",
            }),
        );
        Ok(())
    }

    /// Refresh Tailscale control-plane state from the configured controller.
    pub fn tailscale_refresh(&self) -> Result<(), String> {
        self.sync_tailscale_client()
    }

    /// Toggle whether mesh relay is preferred over DERP when both are possible.
    pub fn tailscale_set_prefer_mesh_relay(&self, enabled: bool) -> Result<(), String> {
        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        if overlay.tailscale.credentials.is_none() {
            return Err("Tailscale is not configured".into());
        }
        overlay.tailscale.prefer_mesh_relay = enabled;
        drop(overlay);
        self.save_overlay_state();
        self.sync_tailscale_client()
    }

    /// Select the active Tailscale exit node by peer name, or clear it.
    pub fn tailscale_set_exit_node(&self, peer_name: &str) -> Result<(), String> {
        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        if overlay.tailscale.credentials.is_none() {
            return Err("Tailscale is not configured".into());
        }
        if peer_name.is_empty() {
            overlay.tailscale.active_exit_node = None;
        } else {
            let Some(peer) = overlay
                .tailscale
                .peers
                .iter()
                .find(|peer| peer.name == peer_name)
            else {
                return Err("Unknown Tailscale exit node".into());
            };
            if !peer.is_exit_node {
                return Err("Selected Tailscale peer is not an exit node".into());
            }
            overlay.tailscale.active_exit_node = Some(peer_name.to_string());
        }
        drop(overlay);
        self.save_overlay_state();
        self.push_event(
            "OverlayStatusChanged",
            serde_json::json!({
                "overlay": "tailscale",
                "status": "connected",
                "activeExitNode": if peer_name.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(peer_name.to_string())
                },
            }),
        );
        Ok(())
    }

    /// Connect to one or more ZeroTier networks (§5.23).
    ///
    /// `api_key`: ZeroTier Central API key (empty for self-hosted).
    /// `controller_url`: empty for Central, or a self-hosted controller URL.
    /// `network_ids_json`: JSON array of 16-char hex network IDs.
    ///
    /// Emits `ZeroTierConnecting`.
    pub fn zerotier_connect(
        &self,
        api_key: &str,
        controller_url: &str,
        network_ids_json: &str,
    ) -> Result<(), String> {
        use crate::transport::overlay_client::{
            OverlayClientStatus, ZeroTierController, ZeroTierCredentials, ZeroTierNetwork,
            ZeroTierNetworkAuthStatus,
        };

        let network_ids: Vec<String> =
            serde_json::from_str(network_ids_json).map_err(|e| e.to_string())?;
        if network_ids.is_empty() {
            return Err("network_ids must not be empty".into());
        }

        let controller = if controller_url.is_empty() {
            ZeroTierController::Central
        } else {
            ZeroTierController::SelfHosted {
                url: controller_url.to_string(),
            }
        };
        let creds = ZeroTierCredentials {
            controller,
            api_key: api_key.to_string(),
            network_ids: network_ids.clone(),
        };

        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        overlay.zerotier.credentials = Some(creds);
        overlay.zerotier.status = OverlayClientStatus::Connecting;

        // Enqueue each network as pending (if not already tracked).
        for nid in &network_ids {
            if !overlay
                .zerotier
                .networks
                .iter()
                .any(|n| &n.network_id == nid)
            {
                overlay.zerotier.networks.push(ZeroTierNetwork {
                    network_id: nid.clone(),
                    name: nid.clone(),
                    assigned_ip: None,
                    auth_status: ZeroTierNetworkAuthStatus::AwaitingAuthorization,
                    member_count: 0,
                });
            }
        }
        drop(overlay);
        self.save_overlay_state();

        self.push_event(
            "ZeroTierConnecting",
            serde_json::json!({ "networkIds": network_ids }),
        );
        self.sync_zerotier_client()
    }

    /// Disconnect and forget the current ZeroTier configuration.
    pub fn zerotier_disconnect(&self) -> Result<(), String> {
        use crate::transport::overlay_client::{OverlayClientStatus, ZeroTierClient};

        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        overlay.zerotier = ZeroTierClient::new();
        overlay.zerotier.status = OverlayClientStatus::NotConfigured;
        drop(overlay);
        self.save_overlay_state();
        self.push_event(
            "OverlayStatusChanged",
            serde_json::json!({
                "overlay": "zerotier",
                "status": "not_configured",
            }),
        );
        Ok(())
    }

    /// Refresh ZeroTier controller state from the configured controller.
    pub fn zerotier_refresh(&self) -> Result<(), String> {
        self.sync_zerotier_client()
    }

    /// Join an additional ZeroTier network using the stored controller config.
    pub fn zerotier_join_network(&self, network_id: &str) -> Result<(), String> {
        if network_id.len() != 16 || !network_id.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err("network_id must be 16 hex characters".into());
        }

        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        let Some(credentials) = overlay.zerotier.credentials.as_mut() else {
            return Err("ZeroTier is not configured".into());
        };
        if !credentials
            .network_ids
            .iter()
            .any(|entry| entry == network_id)
        {
            credentials.network_ids.push(network_id.to_string());
        }
        drop(overlay);
        self.save_overlay_state();
        self.sync_zerotier_client()
    }

    /// Toggle whether mesh relay is preferred over vendor relay for ZeroTier.
    pub fn zerotier_set_prefer_mesh_relay(&self, enabled: bool) -> Result<(), String> {
        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        if overlay.zerotier.credentials.is_none() {
            return Err("ZeroTier is not configured".into());
        }
        overlay.zerotier.prefer_mesh_relay = enabled;
        drop(overlay);
        self.save_overlay_state();
        self.sync_zerotier_client()
    }

    /// Change a ZeroTier member's authorization state on a specific network.
    pub fn zerotier_set_member_authorized(
        &self,
        network_id: &str,
        node_id: &str,
        authorized: bool,
    ) -> Result<(), String> {
        use crate::transport::overlay_client::ZeroTierController as OverlayController;
        use crate::transport::zerotier::ZtControllerClient;

        if network_id.is_empty() || node_id.is_empty() {
            return Err("network_id and node_id are required".into());
        }

        let credentials = {
            self.overlay
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .zerotier
                .credentials
                .clone()
        }
        .ok_or_else(|| "ZeroTier is not configured".to_string())?;

        let controller = match &credentials.controller {
            OverlayController::Central => ZtControllerClient::central(&credentials.api_key),
            OverlayController::SelfHosted { url } => {
                ZtControllerClient::self_hosted(url, &credentials.api_key)
            }
        };
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to create overlay runtime: {e}"))?;
        runtime
            .block_on(controller.set_member_authorized(network_id, node_id, authorized))
            .map_err(|e| format!("ZeroTier member update failed: {e}"))?;
        self.sync_zerotier_client()
    }

    /// Get the current status of all overlay networks as a JSON string.
    pub fn overlay_status(&self) -> String {
        let _ = self.sync_tailscale_client();
        let _ = self.sync_zerotier_client();
        let overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::json!({
            "tailscale": {
                "status":              format!("{:?}", overlay.tailscale.status).to_lowercase(),
                "connected":           overlay.tailscale.is_connected(),
                "deviceIp":            overlay.tailscale.device_info.as_ref().map(|d| d.tailscale_ip.as_str()),
                "deviceName":          overlay.tailscale.device_info.as_ref().map(|d| d.device_name.as_str()),
                "tailnetName":         overlay.tailscale.device_info.as_ref().map(|d| d.tailnet_name.as_str()),
                "os":                  overlay.tailscale.device_info.as_ref().map(|d| d.os.as_str()),
                "controller":          overlay.tailscale.credentials.as_ref().map(|c| c.controller.base_url()),
                "relayMode":           overlay.tailscale.relay_mode,
                "keyExpiryUnixMs":     overlay.tailscale.key_expiry_ms,
                "peers":               overlay.tailscale.peers.iter().map(|peer| serde_json::json!({
                    "name":       peer.name,
                    "ip":         peer.ip,
                    "online":     peer.online,
                    "isExitNode": peer.is_exit_node,
                    "os":         peer.os,
                    "lastSeen":   peer.last_seen,
                })).collect::<Vec<_>>(),
                "exitNode":            overlay.tailscale.active_exit_node,
                "exitNodes":           overlay.tailscale.available_exit_nodes().iter().map(|peer| serde_json::json!({
                    "name": peer.name,
                    "ip": peer.ip,
                    "online": peer.online,
                })).collect::<Vec<_>>(),
                "preferMeshRelay":     overlay.tailscale.prefer_mesh_relay,
                "anonymizationScore":  overlay.tailscale.anonymization_score(),
            },
            "zerotier": {
                "status":    format!("{:?}", overlay.zerotier.status).to_lowercase(),
                "connected": overlay.zerotier.is_connected(),
                "nodeId":    overlay.zerotier.node_id,
                "controller": overlay.zerotier.credentials.as_ref().map(|c| c.controller.api_base_url()),
                "networks":  overlay.zerotier.networks.iter().map(|n| serde_json::json!({
                    "networkId":  n.network_id,
                    "name":       n.name,
                    "assignedIp": n.assigned_ip,
                    "authStatus": format!("{:?}", n.auth_status).to_lowercase(),
                    "memberCount": n.member_count,
                })).collect::<Vec<_>>(),
                "members": overlay.zerotier.members.iter().map(|member| serde_json::json!({
                    "networkId": member.network_id,
                    "nodeId": member.node_id,
                    "name": member.name,
                    "ips": member.ips,
                    "authorized": member.authorized,
                    "lastSeen": member.last_seen,
                })).collect::<Vec<_>>(),
                "relayMode": overlay.zerotier.relay_mode,
                "preferMeshRelay": overlay.zerotier.prefer_mesh_relay,
                "anonymizationScore": overlay.zerotier.anonymization_score(),
            },
            "anyActive": overlay.any_overlay_active(),
        })
        .to_string()
    }

    // -----------------------------------------------------------------------
    // SDR / RF transport (§5.X)
    // -----------------------------------------------------------------------

    /// Configure the SDR transport with a profile and hardware driver.
    ///
    /// `config_json` fields:
    /// - `"profile"`: `"balanced"` | `"secure"` | `"long_range"` |
    ///   `"long_range_hf"` | `"evasive"`
    /// - `"driver"`:  `"lora"` | `"hackrf"` | `"limesdr"` | `"pluto"` |
    ///   `"rtlsdr"` | `"hf_transceiver"` | `"meshtastic"` | `"simulated"`
    /// - `"freq_hz"`: primary frequency in Hz
    /// - `"hop_key_hex"`: 64-char hex (required for `secure` / `evasive`)
    ///
    /// Emits `SettingsUpdated` after applying the config.
    pub fn sdr_configure(&self, config_json: &str) -> Result<(), String> {
        use crate::transport::rf_sdr::{LoRaChipModel, SdrConfig, SdrDriverType};

        let parsed: serde_json::Value =
            serde_json::from_str(config_json).map_err(|e| e.to_string())?;

        let profile = parsed
            .get("profile")
            .and_then(|v| v.as_str())
            .unwrap_or("balanced");
        let driver_str = parsed
            .get("driver")
            .and_then(|v| v.as_str())
            .unwrap_or("simulated");
        let freq_hz = parsed
            .get("freq_hz")
            .and_then(|v| v.as_u64())
            .unwrap_or(433_175_000);

        let driver = match driver_str {
            "lora" => SdrDriverType::LoRaChip {
                model: LoRaChipModel::Sx1262,
            },
            "hackrf" => SdrDriverType::HackRf,
            "limesdr" => SdrDriverType::LimeSdr,
            "pluto" => SdrDriverType::PlutoSdr,
            "rtlsdr" => SdrDriverType::RtlSdr,
            "hf_transceiver" => SdrDriverType::HfTransceiver {
                model: "Generic".into(),
            },
            "meshtastic" => SdrDriverType::Meshtastic,
            _ => SdrDriverType::Simulated,
        };

        // Resolve the FHSS hop key for frequency-hopping profiles.
        // The hop key determines the pseudo-random frequency sequence;
        // all nodes in a mesh must share the same hop key to communicate.
        // Defaults to all-zeros (which produces a fixed sequence) if not
        // provided — suitable for testing but NOT secure in production.
        let hop_key: [u8; 32] = parsed
            .get("hop_key_hex")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
            .and_then(|v| v.try_into().ok())
            .unwrap_or([0u8; 32]);

        let config = match profile {
            "secure" => SdrConfig::secure(driver, hop_key),
            "long_range" => SdrConfig::long_range(driver, freq_hz),
            "long_range_hf" => SdrConfig::long_range_hf(driver),
            "evasive" => SdrConfig::evasive(driver, hop_key),
            _ => SdrConfig::balanced(driver, freq_hz),
        };

        self.sdr
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .apply_config(config);

        // Emit settings update so Flutter can refresh the RF config display.
        self.emit_settings_updated();
        Ok(())
    }

    /// Get current SDR/RF status as a JSON string.
    pub fn sdr_status(&self) -> String {
        let mgr = self.sdr.lock().unwrap_or_else(|e| e.into_inner());
        let stats = mgr.aggregate_stats();
        let (profile, driver, fhss, ale, freq_hz) = mgr
            .global_config
            .as_ref()
            .map(|c| {
                (
                    format!("{:?}", c.profile),
                    format!("{:?}", c.driver),
                    c.is_fhss(),
                    c.is_ale(),
                    c.primary_channel.freq_hz,
                )
            })
            .unwrap_or_else(|| ("None".into(), "None".into(), false, false, 0));

        serde_json::json!({
            "enabled":      mgr.enabled,
            "profile":      profile,
            "driver":       driver,
            "fhss":         fhss,
            "ale":          ale,
            "primaryFreqHz": freq_hz,
            "stats": {
                "txBytes":    stats.tx_bytes,
                "rxBytes":    stats.rx_bytes,
                "txFrames":   stats.tx_frames,
                "rxFrames":   stats.rx_frames,
                "lostFrames": stats.lost_frames,
                "lossRatio":  stats.loss_ratio(),
                "fhssHops":   stats.fhss_hops,
                "aleRelinks": stats.ale_relinks,
                "lastRssiDbm": stats.last_rssi_dbm,
                "lastSnrDb":   stats.last_snr_db,
            },
        })
        .to_string()
    }

    /// Get the current FHSS channel for the current epoch.
    ///
    /// Returns JSON `{"freq_hz":…,"epoch":…,"label":"…"}` or
    /// `{"error":"FHSS not configured"}`.
    pub fn sdr_current_channel(&self) -> String {
        let mgr = self.sdr.lock().unwrap_or_else(|e| e.into_inner());
        let result = mgr
            .global_config
            .as_ref()
            .and_then(|c| c.fhss.as_ref())
            .and_then(|fhss| {
                let epoch = fhss.current_epoch();
                fhss.current_channel().map(|ch| {
                    serde_json::json!({
                        "freq_hz":      ch.freq_hz,
                        "epoch":        epoch,
                        "label":        ch.label,
                        "bandwidth_hz": ch.bandwidth_hz,
                    })
                })
            })
            .unwrap_or_else(|| serde_json::json!({ "error": "FHSS not configured" }));
        result.to_string()
    }

    /// List available SDR hardware profiles as a static JSON array string.
    pub fn sdr_list_profiles(&self) -> String {
        serde_json::json!([
            { "id": "balanced",     "name": "Balanced",      "fhss": false, "ale": false, "approx_range_km": "5-15"     },
            { "id": "secure",       "name": "Secure",        "fhss": true,  "ale": false, "approx_range_km": "1-10"     },
            { "id": "long_range",   "name": "Long Range",    "fhss": false, "ale": false, "approx_range_km": "10-40"    },
            { "id": "long_range_hf","name": "Long Range HF", "fhss": false, "ale": true,  "approx_range_km": "500-4000" },
            { "id": "evasive",      "name": "Evasive",       "fhss": true,  "ale": false, "approx_range_km": "1-5"      },
        ])
        .to_string()
    }

    /// List supported SDR hardware types as a static JSON array string.
    pub fn sdr_list_hardware(&self) -> String {
        serde_json::json!([
            { "id": "lora",           "name": "LoRa Chip (SX1276/SX1262)",   "full_duplex": false, "raw_iq": false },
            { "id": "meshtastic",     "name": "Meshtastic Node",              "full_duplex": false, "raw_iq": false },
            { "id": "hackrf",         "name": "HackRF One",                   "full_duplex": false, "raw_iq": true  },
            { "id": "limesdr",        "name": "LimeSDR",                      "full_duplex": true,  "raw_iq": true  },
            { "id": "pluto",          "name": "ADALM-PLUTO (PlutoSDR)",       "full_duplex": true,  "raw_iq": true  },
            { "id": "rtlsdr",         "name": "RTL-SDR (RX only)",            "full_duplex": false, "raw_iq": true  },
            { "id": "hf_transceiver", "name": "HF Transceiver",               "full_duplex": false, "raw_iq": true  },
            { "id": "simulated",      "name": "Simulated (Testing)",          "full_duplex": true,  "raw_iq": true  },
        ])
        .to_string()
    }

    // -----------------------------------------------------------------------
    // LoSec — Low-Traffic Security Mode (§6.9.6)
    // -----------------------------------------------------------------------

    /// Initiate a LoSec negotiation request toward a peer (§6.9.6).
    ///
    /// Builds and signs a `SignedLoSecRequest`, sends it to the peer if a TCP
    /// connection exists, or simulates the responder locally for single-device
    /// testing.  Returns a JSON result with `"accepted"` and optional
    /// `"rejection_reason"`.
    pub fn losec_request(&self, request_json: &str) -> Result<String, String> {
        use crate::routing::losec::{
            handle_losec_request, AmbientTrafficMonitor, ConnectionMode, ServiceLoSecConfig,
            SignedLoSecRequest,
        };
        use ed25519_dalek::SigningKey;

        let parsed: serde_json::Value =
            serde_json::from_str(request_json).map_err(|e| e.to_string())?;

        // Extract signing key from local identity.
        let signing_key: SigningKey = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .as_ref()
                .map(|id| SigningKey::from_bytes(&id.ed25519_signing.to_bytes()))
                .ok_or("identity not unlocked")?
        };

        // Parse mode and session_id.
        let mode = match parsed
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("losec")
        {
            "standard" => ConnectionMode::Standard,
            "direct" => ConnectionMode::Direct,
            _ => ConnectionMode::LoSec,
        };
        let session_id_hex = parsed
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let session_id_bytes = hex::decode(session_id_hex).unwrap_or_else(|_| vec![0u8; 32]);
        let mut session_id = [0u8; 32];
        let copy_len = session_id_bytes.len().min(32);
        session_id[..copy_len].copy_from_slice(&session_id_bytes[..copy_len]);

        let hop_count = parsed
            .get("hop_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(2) as u8;
        let reason = parsed
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let signed = SignedLoSecRequest::new(session_id, mode, hop_count, reason, &signing_key)
            .map_err(|e| format!("{e:?}"))?;

        // Build ambient monitor from caller-supplied stats.
        let ambient_bytes = parsed
            .get("ambient_bytes_per_sec")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let active_tunnels = parsed
            .get("active_tunnels")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let mut monitor = AmbientTrafficMonitor::new();
        monitor.update(active_tunnels, ambient_bytes);

        // Permissive service config — production can override via module config.
        let service_config = ServiceLoSecConfig {
            allow_losec: true,
            allow_direct: true,
        };

        // If a peer connection exists, send on-wire.
        if let Some(peer_id_hex) = parsed.get("peer_id").and_then(|v| v.as_str()) {
            let our_peer_id_hex = {
                let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                guard
                    .as_ref()
                    .map(|id| id.peer_id().to_hex())
                    .unwrap_or_default()
            };
            let signed_json = serde_json::to_string(&signed).map_err(|e| e.to_string())?;
            let frame = serde_json::json!({
                "type":       "losec_request",
                "sender":     our_peer_id_hex,
                "session_id": hex::encode(signed.request.session_id),
                "payload":    signed_json,
            });
            let frame_bytes = serde_json::to_vec(&frame).unwrap_or_default();
            let sent = {
                use std::io::Write as _;
                let mut conns = self
                    .clearnet_connections
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(stream) = conns.get_mut(peer_id_hex) {
                    let len = (frame_bytes.len() as u32).to_be_bytes();
                    stream.write_all(&len).is_ok() && stream.write_all(&frame_bytes).is_ok()
                } else {
                    false
                }
            };
            if sent {
                return Ok(serde_json::json!({ "sent": true }).to_string());
            }
            // No connection — fall through to local simulation.
        }

        // Local simulation: run the responder side here (single-device testing).
        let response = handle_losec_request(
            &signed,
            &service_config,
            monitor.losec_available(),
            &signing_key,
        );
        Ok(serde_json::json!({
            "accepted":          response.response.accepted,
            "rejection_reason":  response.response.rejection_reason,
        })
        .to_string())
    }

    /// Query the current ambient traffic level used by the LoSec policy engine.
    ///
    /// Returns `{"available": bool, "active_tunnels": usize, "bytes_per_sec": u64}`.
    pub fn losec_ambient_status(&self) -> String {
        use crate::routing::losec::AmbientTrafficMonitor;

        // Use SDR session count as a proxy for active tunnels.
        let active_tunnels = self
            .sdr
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .len();
        let mut monitor = AmbientTrafficMonitor::new();
        // Volume proxy: active_tunnels × estimated 1 kB/s minimum.
        monitor.update(active_tunnels, active_tunnels as u64 * 1024);

        serde_json::json!({
            "available":      monitor.losec_available(),
            "active_tunnels": active_tunnels,
            "bytes_per_sec":  monitor.volume(),
        })
        .to_string()
    }

    // -----------------------------------------------------------------------
    // Node mode and settings
    // -----------------------------------------------------------------------

    /// Set the node operating mode (0 = client, 1 = relay, 2 = server).
    ///
    /// Also updates the VPN routing mode to match.  Emits `SettingsUpdated`
    /// and persists to vault.
    pub fn set_node_mode(&self, mode: u8) -> Result<(), String> {
        if mode > 2 {
            return Err(format!("invalid node mode {mode}: must be 0-2"));
        }

        *self.node_mode.lock().unwrap_or_else(|e| e.into_inner()) = mode;
        let routing_mode = match mode {
            0 => RoutingMode::Off,
            1 => RoutingMode::MeshOnly,
            _ => RoutingMode::ExitNode,
        };
        self.vpn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .config
            .mode = routing_mode;

        self.emit_settings_updated();
        self.save_settings();
        Ok(())
    }

    /// Get live network statistics as a JSON string.
    ///
    /// Returned fields: `activeTunnels`, `connectedPeers`, `activeTransports`,
    /// `sdrEnabled`, `vpnMode`, `routingEntries`, `gossipMapSize`,
    /// `wireGuardSessions`, `sfPendingMessages`, `clearnetConnections`.
    pub fn get_network_stats(&self) -> String {
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut active_transports: Vec<&'static str> = Vec::new();
        if flags.clearnet {
            active_transports.push("clearnet");
        }
        if flags.tor {
            active_transports.push("tor");
        }
        if flags.i2p {
            active_transports.push("i2p");
        }
        if flags.bluetooth {
            active_transports.push("bluetooth");
        }
        if flags.rf {
            active_transports.push("rf");
        }

        let sdr = self.sdr.lock().unwrap_or_else(|e| e.into_inner());
        let sdr_sessions = sdr.sessions.len();
        let sdr_enabled = sdr.enabled;
        drop(sdr);

        let vpn = self.vpn.lock().unwrap_or_else(|e| e.into_inner());
        let vpn_mode_str = format!("{:?}", vpn.config.mode);
        drop(vpn);

        let routing_entry_count = self
            .routing_table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let gossip_map_size = self
            .gossip
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map_size();
        let wg_session_count = self
            .wireguard_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let sf_pending = self
            .sf_server
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .total_pending();
        let clearnet_connection_count = self
            .clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let connected_peers = self
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .all()
            .len();
        let mesh_identity_pubkey = self
            .mesh_identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|identity| hex::encode(identity.public_bytes()))
            .unwrap_or_default();
        let tunnel_gossip_known_nodes = self
            .tunnel_gossip
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .known_node_count();

        serde_json::json!({
            "activeTunnels":        sdr_sessions,
            "connectedPeers":       connected_peers,
            "activeTransports":     active_transports,
            "sdrEnabled":           sdr_enabled,
            "vpnMode":              vpn_mode_str,
            "routingEntries":       routing_entry_count,
            "gossipMapSize":        gossip_map_size,
            "wireGuardSessions":    wg_session_count,
            "sfPendingMessages":    sf_pending,
            "clearnetConnections":  clearnet_connection_count,
            "meshIdentityPubkey":   mesh_identity_pubkey,
            "tunnelGossipKnownNodes": tunnel_gossip_known_nodes,
        })
        .to_string()
    }

    /// Get a privacy-safe diagnostic report as a JSON string.
    ///
    /// The report is built directly from live runtime state and sanitized
    /// before crossing the FFI boundary.
    pub fn get_diagnostic_report_json(&self) -> String {
        let mut report = crate::testing::diagnostics::generate_report_for_runtime(self);
        crate::testing::diagnostics::sanitize_report(&mut report);
        crate::testing::diagnostics::report_to_json(&report)
    }

    /// Return the current settings JSON (same payload as `SettingsUpdated` events).
    pub fn get_settings(&self) -> String {
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let node_mode = *self.node_mode.lock().unwrap_or_else(|e| e.into_inner());
        let (peer_id, ed25519_pub) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => (id.peer_id().to_hex(), hex::encode(id.ed25519_pub)),
                None => (String::new(), String::new()),
            }
        };
        let clearnet_port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let active_tier = *self.active_tier.lock().unwrap_or_else(|e| e.into_inner());
        let bandwidth_profile = *self
            .bandwidth_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Self::build_settings_json(
            &flags,
            node_mode,
            &self.threat_context,
            &peer_id,
            &ed25519_pub,
            clearnet_port,
            active_tier,
            bandwidth_profile,
            self.build_layer1_status_json(),
        )
        .to_string()
    }

    /// Set the threat context level (0 = Normal … 4 = Critical).
    ///
    /// Also propagates the new level to the notification dispatcher so
    /// routing decisions for push notifications are updated immediately.
    pub fn set_threat_context(&mut self, level: u8) -> Result<(), String> {
        let tc = ThreatContext::from_u8(level).ok_or("invalid threat context level")?;
        self.threat_context = tc;
        self.notifications
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_threat_context(tc);
        self.reconcile_layer1_runtime()?;
        self.emit_settings_updated();
        self.save_settings();
        Ok(())
    }

    /// Return the current threat context level as `u8`.
    pub fn get_threat_context(&self) -> u8 {
        self.threat_context as u8
    }

    /// Set the active conversation room for read-receipt priority escalation.
    ///
    /// Pass `None` to clear the active conversation.
    pub fn set_active_conversation(&self, room_id_hex: Option<&str>) {
        match room_id_hex {
            None => {
                *self
                    .active_conversation
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
            }
            Some(id_str) => {
                // Parse the 16-byte room ID from hex.
                if let Ok(bytes) = hex::decode(id_str) {
                    if bytes.len() == 16 {
                        let mut id = [0u8; 16];
                        id.copy_from_slice(&bytes);
                        *self
                            .active_conversation
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = Some(id);
                    }
                }
            }
        }
        self.refresh_layer1_participation_state();
        self.emit_settings_updated();
    }

    /// Set the message security mode for a room (§6.7).
    ///
    /// Updates the `Room::security_mode` field, persists rooms to vault, and
    /// emits `RoomUpdated`.
    pub fn set_conversation_security_mode(
        &self,
        room_id_hex: &str,
        mode: u8,
    ) -> Result<(), String> {
        use crate::messaging::message::MessageSecurityMode;

        let new_mode = MessageSecurityMode::from_u8(mode).ok_or("invalid security mode")?;

        // Parse room ID.
        let room_bytes: [u8; 16] = hex::decode(room_id_hex)
            .ok()
            .filter(|b| b.len() == 16)
            .map(|b| {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b);
                a
            })
            .ok_or("invalid room_id_hex")?;

        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        match rooms.iter_mut().find(|r| r.id == room_bytes) {
            Some(room) => {
                room.security_mode = new_mode;
                drop(rooms);
                self.save_rooms();
                self.push_event(
                    "RoomUpdated",
                    serde_json::json!({
                        "roomId":       room_id_hex,
                        "securityMode": mode,
                    }),
                );
                Ok(())
            }
            None => Err("room not found".into()),
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Build the canonical settings JSON value from current in-memory state.
    ///
    /// Used by `get_settings` and `emit_settings_updated`.  Factored out so
    /// it can be called without holding any locks.
    pub fn build_settings_json(
        flags: &TransportFlags,
        node_mode: u8,
        threat_context: &ThreatContext,
        peer_id: &str,
        ed25519_pub: &str,
        clearnet_port: u16,
        active_tier: u8,
        bandwidth_profile: u8,
        layer1_status: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "nodeMode":          node_mode,
            "threatContext":     *threat_context as u8,
            "enableTor":         flags.tor,
            "enableClearnet":    flags.clearnet,
            "clearnetFallback":  flags.clearnet_fallback,
            "enableI2p":         flags.i2p,
            "enableBluetooth":   flags.bluetooth,
            "enableRf":          flags.rf,
            "meshDiscovery":     flags.mesh_discovery,
            "allowRelays":       flags.allow_relays,
            "localPeerId":       peer_id,
            "ed25519Pub":        ed25519_pub,
            "clearnetPort":      clearnet_port,
            "activeTier":        active_tier.min(4),
            "bandwidthProfile":  bandwidth_profile.min(2),
            "layer1Status":      layer1_status,
        })
    }

    /// Build the backend-owned Layer 1 startup and participation status.
    pub fn build_layer1_status_json(&self) -> serde_json::Value {
        let cover = *self
            .layer1_cover_traffic
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let activity_state = *self
            .layer1_activity_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let threat_context = self.threat_context;
        let (available_transport_types, active_transport_type_count) = {
            let transport_manager = self
                .transport_manager
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            (
                transport_manager
                    .available_types()
                    .into_iter()
                    .map(|transport| format!("{transport:?}").to_lowercase())
                    .collect::<Vec<_>>(),
                transport_manager.active_transport_type_count(),
            )
        };
        let allow_relays = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .allow_relays;
        let tunnel_gossip_known_nodes = self
            .tunnel_gossip
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .known_node_count();
        let android_startup = self
            .android_startup_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let startup_sequence = serde_json::json!({
            "deviceUnlockObserved": android_startup.user_unlocked,
            "meshIdentityLoaded": self.mesh_identity.lock().unwrap_or_else(|e| e.into_inner()).is_some(),
            "tunnelManagerReady": active_transport_type_count > 0,
            "coverTrafficReady": cover.target_tunnels_min > 0 && cover.cover_rate_bytes_per_sec > 0,
            "tunnelGossipReady": tunnel_gossip_known_nodes > 0 || android_startup.startup_service_started,
            "relayParticipationReady": allow_relays && active_transport_type_count > 0,
            "startupServiceStarted": android_startup.startup_service_started,
            "startupServiceForeground": android_startup.startup_service_foreground,
        });

        serde_json::json!({
            "started": *self.layer1_participation_started.lock().unwrap_or_else(|e| e.into_inner()),
            "identityLoaded": self.mesh_identity.lock().unwrap_or_else(|e| e.into_inner()).is_some(),
            "activityState": format!("{activity_state:?}").to_lowercase(),
            "threatContext": threat_context as u8,
            "androidStartup": android_startup,
            "startupSequence": startup_sequence,
            "availableTransportTypes": available_transport_types,
            "activeTransportTypeCount": active_transport_type_count,
            "allowRelays": allow_relays,
            "policy": {
                "allowsMdns": threat_context.allows_mdns(),
                "allowsClearnet": threat_context.allows_clearnet(),
                "allowsProximityDirect": threat_context.allows_proximity_direct(),
                "minimumHops": threat_context.min_hops(),
            },
            "coverTraffic": {
                "targetTunnelsMin": cover.target_tunnels_min,
                "targetTunnelsMax": cover.target_tunnels_max,
                "coverRateBytesPerSec": cover.cover_rate_bytes_per_sec,
            },
            "tunnelGossipKnownNodes": tunnel_gossip_known_nodes,
        })
    }

    /// Emit a `SettingsUpdated` event with the current transport flags and
    /// identity (if unlocked).
    ///
    /// Called after every mutation that affects `get_settings`.
    pub fn emit_settings_updated(&self) {
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let node_mode = *self.node_mode.lock().unwrap_or_else(|e| e.into_inner());
        let (peer_id, ed25519_pub) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => (id.peer_id().to_hex(), hex::encode(id.ed25519_pub)),
                None => (String::new(), String::new()),
            }
        };
        let clearnet_port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let active_tier = *self.active_tier.lock().unwrap_or_else(|e| e.into_inner());
        let bandwidth_profile = *self
            .bandwidth_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.push_event(
            "SettingsUpdated",
            Self::build_settings_json(
                &flags,
                node_mode,
                &self.threat_context,
                &peer_id,
                &ed25519_pub,
                clearnet_port,
                active_tier,
                bandwidth_profile,
                self.build_layer1_status_json(),
            ),
        );
    }

    // -----------------------------------------------------------------------
    // Service list and module configuration (§17.13)
    // -----------------------------------------------------------------------

    /// Return the full service list as a JSON array string.
    ///
    /// Each entry includes `id`, `name`, `path`, `address`, `enabled`,
    /// `minTrustLevel`, and `allowedTransports`.
    pub fn get_service_list(&self) -> String {
        let mc = self.module_config.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::json!([
            {"id":"gardens",      "name":"Gardens",          "path":"/gardens",    "address":"","enabled":mc.social.gardens,            "minTrustLevel":1,"allowedTransports":["mesh","clearnet"]},
            {"id":"file_sharing", "name":"File Sharing",     "path":"/files",      "address":"","enabled":mc.social.file_sharing,        "minTrustLevel":1,"allowedTransports":["mesh","clearnet"]},
            {"id":"store_forward","name":"Store & Forward",  "path":"/sf",         "address":"","enabled":mc.social.store_forward,       "minTrustLevel":2,"allowedTransports":["mesh"]},
            {"id":"notifications","name":"Notifications",    "path":"/notify",     "address":"","enabled":mc.social.notifications,       "minTrustLevel":1,"allowedTransports":["mesh","clearnet","tor"]},
            {"id":"infinet",      "name":"Infinet",          "path":"/infinet",    "address":"","enabled":mc.network.infinet,            "minTrustLevel":2,"allowedTransports":["mesh"]},
            {"id":"exit_nodes",   "name":"Exit Nodes",       "path":"/exit",       "address":"","enabled":mc.network.exit_nodes,         "minTrustLevel":3,"allowedTransports":["clearnet","tor"]},
            {"id":"vpn_mode",     "name":"VPN Mode",         "path":"/vpn",        "address":"","enabled":mc.network.vpn_mode,           "minTrustLevel":2,"allowedTransports":["clearnet","tor"]},
            {"id":"app_connector","name":"App Connector",    "path":"/connector",  "address":"","enabled":mc.network.app_connector,      "minTrustLevel":2,"allowedTransports":["mesh","clearnet"]},
            {"id":"funnel",       "name":"Funnel",           "path":"/funnel",     "address":"","enabled":mc.network.funnel,             "minTrustLevel":3,"allowedTransports":["clearnet"]},
            {"id":"mnrdp_server", "name":"Remote Desktop",   "path":"/rdp",        "address":"","enabled":mc.protocols.mnrdp_server,     "minTrustLevel":3,"allowedTransports":["mesh","clearnet"]},
            {"id":"mnsp_server",  "name":"Screen Share",     "path":"/screencast", "address":"","enabled":mc.protocols.screen_share,     "minTrustLevel":2,"allowedTransports":["mesh","clearnet"]},
            {"id":"api_gateway",  "name":"API Gateway",      "path":"/api",        "address":"","enabled":mc.protocols.api_gateway,      "minTrustLevel":2,"allowedTransports":["mesh","clearnet"]},
            {"id":"print_service","name":"Print Service",    "path":"/print",      "address":"","enabled":mc.protocols.print_service,    "minTrustLevel":2,"allowedTransports":["mesh"]},
            {"id":"plugins",      "name":"Plugin Runtime",   "path":"/plugins",    "address":"","enabled":mc.plugins.runtime_enabled,    "minTrustLevel":2,"allowedTransports":["mesh","clearnet"]},
        ]).to_string()
    }

    /// Toggle or configure a service/module by ID.
    ///
    /// `config_json` must contain at minimum `{"enabled": bool}`.
    /// Returns `true` if the service ID was recognised.
    pub fn configure_service(&self, service_id: &str, config_json: &str) -> bool {
        let parsed: serde_json::Value = match serde_json::from_str(config_json) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let enabled = match parsed.get("enabled").and_then(|v| v.as_bool()) {
            Some(b) => b,
            None => return false,
        };
        let mut mc = self.module_config.lock().unwrap_or_else(|e| e.into_inner());
        let changed = match service_id {
            "gardens" => {
                mc.social.gardens = enabled;
                true
            }
            "file_sharing" => {
                mc.social.file_sharing = enabled;
                true
            }
            "store_forward" => {
                mc.social.store_forward = enabled;
                true
            }
            "notifications" => {
                mc.social.notifications = enabled;
                true
            }
            "infinet" => {
                mc.network.infinet = enabled;
                true
            }
            "exit_nodes" => {
                mc.network.exit_nodes = enabled;
                true
            }
            "vpn_mode" => {
                mc.network.vpn_mode = enabled;
                true
            }
            "app_connector" => {
                mc.network.app_connector = enabled;
                true
            }
            "funnel" => {
                mc.network.funnel = enabled;
                true
            }
            "mnrdp_server" => {
                mc.protocols.mnrdp_server = enabled;
                true
            }
            "mnsp_server" => {
                mc.protocols.screen_share = enabled;
                true
            }
            "api_gateway" => {
                mc.protocols.api_gateway = enabled;
                true
            }
            "print_service" => {
                mc.protocols.print_service = enabled;
                true
            }
            "plugins" => {
                mc.plugins.runtime_enabled = enabled;
                true
            }
            _ => false,
        };
        drop(mc);
        if changed {
            self.save_settings();
        }
        changed
    }

    /// Return hosted-service configuration in the shape the Flutter hosting
    /// screen expects.
    pub fn get_hosting_config(&self) -> String {
        let mc = self.module_config.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::json!({
            "remoteDesktop": mc.protocols.mnrdp_server,
            "remoteShell": mc.protocols.mnsp_server,
            "fileAccess": mc.protocols.mnfp_server,
            "apiGateway": mc.protocols.api_gateway,
            "clipboardSync": mc.protocols.clipboard_sync,
            "screenShare": mc.protocols.screen_share,
            "printService": mc.protocols.print_service,
        })
        .to_string()
    }

    /// Enable or disable a hosted service by the user-facing service ID.
    pub fn set_hosted_service(&self, service_id: &str, enabled: bool) -> bool {
        let mut mc = self.module_config.lock().unwrap_or_else(|e| e.into_inner());
        let changed = match service_id {
            "remoteDesktop" => {
                mc.protocols.mnrdp_server = enabled;
                true
            }
            "remoteShell" => {
                mc.protocols.mnsp_server = enabled;
                true
            }
            "fileAccess" => {
                mc.protocols.mnfp_server = enabled;
                true
            }
            "apiGateway" => {
                mc.protocols.api_gateway = enabled;
                true
            }
            "clipboardSync" => {
                mc.protocols.clipboard_sync = enabled;
                true
            }
            "screenShare" => {
                mc.protocols.screen_share = enabled;
                true
            }
            "printService" => {
                mc.protocols.print_service = enabled;
                true
            }
            _ => false,
        };
        drop(mc);
        if changed {
            self.save_settings();
        }
        changed
    }

    /// Return currently enabled local services in the discovery format the
    /// Flutter browse screen expects.
    pub fn discover_mesh_services(&self) -> String {
        let mc = self
            .module_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let identity = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let host_peer_id = identity
            .as_ref()
            .map(|id| id.peer_id().to_hex())
            .unwrap_or_default();
        let host_name = identity
            .as_ref()
            .and_then(|id| id.display_name.clone())
            .unwrap_or_else(|| "This device".to_string());
        let mut services = Vec::new();

        let mut push_service =
            |enabled: bool, id: &str, name: &str, service_type: &str, trust: u8| {
                if enabled {
                    services.push(serde_json::json!({
                        "id": id,
                        "name": name,
                        "type": service_type,
                        "hostPeerId": host_peer_id,
                        "hostName": host_name,
                        "address": "",
                        "trustRequired": trust,
                    }));
                }
            };

        push_service(
            mc.protocols.mnrdp_server,
            "remoteDesktop",
            "Remote Desktop",
            "remoteDesktop",
            3,
        );
        push_service(
            mc.protocols.mnsp_server,
            "remoteShell",
            "Remote Shell",
            "remoteShell",
            3,
        );
        push_service(
            mc.protocols.mnfp_server,
            "fileAccess",
            "File Access",
            "fileAccess",
            2,
        );
        push_service(
            mc.protocols.api_gateway,
            "apiGateway",
            "API Gateway",
            "apiGateway",
            2,
        );
        push_service(
            mc.protocols.clipboard_sync,
            "clipboardSync",
            "Clipboard Sync",
            "clipboardSync",
            1,
        );
        push_service(
            mc.protocols.screen_share,
            "screenShare",
            "Screen Share",
            "screenShare",
            2,
        );
        push_service(
            mc.protocols.print_service,
            "printService",
            "Print Service",
            "printService",
            2,
        );

        serde_json::Value::Array(services).to_string()
    }

    // -----------------------------------------------------------------------
    // Backup (§3.7)
    // -----------------------------------------------------------------------

    /// Create an encrypted backup of social state (contacts, rooms, messages).
    ///
    /// `backup_type`: 0 = Standard (contacts + rooms), 1 = Extended (+ messages).
    /// Returns JSON `{"ok":true,"backup_b64":"..."}` or `{"ok":false,"error":"..."}`.
    pub fn create_backup(&self, passphrase: &str, backup_type: u8) -> String {
        use crate::crypto::backup::{create_backup, BackupType};
        use base64::Engine as _;

        if passphrase.is_empty() {
            return r#"{"ok":false,"error":"passphrase required"}"#.into();
        }
        {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_none() {
                return r#"{"ok":false,"error":"no identity loaded"}"#.into();
            }
        }

        let is_extended = backup_type == 1;
        let btype = if is_extended {
            BackupType::Extended
        } else {
            BackupType::Standard
        };

        // Collect contacts + rooms (no private key material, §3.7).
        let contacts: Vec<crate::pairing::contact::ContactRecord> = self
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .all()
            .into_iter()
            .cloned()
            .collect();
        let rooms: Vec<crate::messaging::room::Room> =
            self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let messages = if is_extended {
            self.messages
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        } else {
            std::collections::HashMap::new()
        };

        #[derive(serde::Serialize)]
        struct BackupContents {
            version: u8,
            contacts: Vec<crate::pairing::contact::ContactRecord>,
            rooms: Vec<crate::messaging::room::Room>,
            messages: std::collections::HashMap<String, Vec<serde_json::Value>>,
        }

        let contents = BackupContents {
            version: 1,
            contacts,
            rooms,
            messages,
        };
        let payload = match serde_json::to_vec(&contents) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({"ok":false,"error":e.to_string()}).to_string(),
        };

        match create_backup(&payload, passphrase.as_bytes(), btype, is_extended) {
            Ok(encrypted) => match serde_json::to_vec(&encrypted) {
                Ok(json_bytes) => {
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&json_bytes);
                    serde_json::json!({"ok":true,"backup_b64":b64}).to_string()
                }
                Err(e) => serde_json::json!({"ok":false,"error":e.to_string()}).to_string(),
            },
            Err(e) => serde_json::json!({"ok":false,"error":format!("{e:?}")}).to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Routing table queries (§6)
    // -----------------------------------------------------------------------

    /// Return routing table statistics as a JSON string.
    ///
    /// Fields: `directPeers`, `totalRoutes`.
    pub fn routing_table_stats(&self) -> String {
        let table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::json!({
            "directPeers": table.direct_peer_count(),
            "totalRoutes": table.total_route_count(),
        })
        .to_string()
    }

    /// Look up the best route to a destination peer.
    ///
    /// Returns JSON `{"found":true,"nextHop":"...","hopCount":N,"latencyMs":N}`
    /// or `{"found":false}` if no route exists.
    pub fn routing_lookup(&self, dest_peer_id_hex: &str) -> String {
        use crate::routing::table::DeviceAddress;

        let dest_bytes: [u8; 32] = match hex::decode(dest_peer_id_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return r#"{"found":false}"#.into(),
        };
        let dest = DeviceAddress(dest_bytes);
        let table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match table.lookup(&dest, None, now) {
            Some(entry) => serde_json::json!({
                "found":     true,
                "nextHop":   hex::encode(entry.next_hop.0),
                "hopCount":  entry.hop_count,
                "latencyMs": entry.latency_ms,
                "direct":    entry.is_direct(),
            })
            .to_string(),
            None => r#"{"found":false}"#.into(),
        }
    }

    // -----------------------------------------------------------------------
    // Notification configuration (§14)
    // -----------------------------------------------------------------------

    /// Return the current notification configuration as a JSON string.
    pub fn get_notification_config(&self) -> String {
        let notif = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
        let cfg = &notif.config;
        let tc = self.threat_context;
        let effective = cfg.effective_tier(tc) as u8;
        let suppressed = cfg.is_suppressed_by_threat(tc);
        let tier_label = match cfg.tier {
            crate::notifications::NotificationTier::MeshTunnel => "MeshTunnel",
            crate::notifications::NotificationTier::UnifiedPush => "UnifiedPush",
            crate::notifications::NotificationTier::SilentPush => "SilentPush",
            crate::notifications::NotificationTier::RichPush => "RichPush",
        };
        let push_url: String = cfg
            .push_relay
            .as_ref()
            .map(|r| match &r.relay_address {
                crate::notifications::RelayAddress::ClearnetUrl { url } => url.clone(),
                crate::notifications::RelayAddress::UnifiedPush { endpoint } => endpoint.clone(),
                crate::notifications::RelayAddress::MeshService { .. } => String::new(),
            })
            .unwrap_or_default();

        serde_json::json!({
            "enabled":            cfg.enabled,
            "tier":               cfg.tier as u8,
            "tierLabel":          tier_label,
            "cloudPingEnabled":   cfg.tier as u8 >= 2,
            "pushServerUrl":      push_url,
            "showPreviews":       cfg.rich_content_level as u8 >= 1,
            "soundEnabled":       true,
            "vibrationEnabled":   true,
            "suppressedByThreat": suppressed,
            "effectiveTier":      effective,
        })
        .to_string()
    }

    /// Update the notification configuration from a JSON object.
    ///
    /// Recognised fields: `enabled` (bool), `tier` (1-4), `pushServerUrl` (str),
    /// `showPreviews` (bool).
    ///
    /// Returns `Ok(())` on success, `Err(reason)` on parse failure.
    pub fn set_notification_config(&self, json: &str) -> Result<(), String> {
        let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;

        let mut notif = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
        let mut cfg = notif.config.clone();

        if let Some(enabled) = v["enabled"].as_bool() {
            cfg.enabled = enabled;
        }
        if let Some(tier) = v["tier"].as_u64() {
            cfg.tier = match tier {
                1 => crate::notifications::NotificationTier::MeshTunnel,
                2 => crate::notifications::NotificationTier::UnifiedPush,
                3 => crate::notifications::NotificationTier::SilentPush,
                4 => crate::notifications::NotificationTier::RichPush,
                _ => return Err(format!("invalid tier {tier}")),
            };
        }
        if let Some(url) = v["pushServerUrl"].as_str() {
            if url.is_empty() {
                cfg.push_relay = None;
            } else {
                cfg.push_relay = Some(crate::notifications::PushRelayConfig {
                    relay_address: crate::notifications::RelayAddress::UnifiedPush {
                        endpoint: url.to_string(),
                    },
                    device_token: Vec::new(),
                    platform: crate::notifications::PushPlatform::UnifiedPush,
                });
            }
        }
        if let Some(previews) = v["showPreviews"].as_bool() {
            cfg.rich_content_level = if previews {
                crate::notifications::RichPushContentLevel::Standard
            } else {
                crate::notifications::RichPushContentLevel::Minimal
            };
        }
        notif.config = cfg;
        drop(notif);
        self.save_settings();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Emergency / duress erase (§3.9)
    // -----------------------------------------------------------------------

    /// Standard emergency erase: destroy all identity layers (§3.9).
    ///
    /// Calls `killswitch::standard_erase` on disk (overwrite + unlink) and
    /// clears all in-memory state.  Non-reversible.  This is the "panic
    /// button" — after this call, the app must be set up from scratch.
    ///
    /// SECURITY: in-memory clearing (setting fields to None / clear()) is
    /// best-effort — the Rust allocator may leave freed data in the heap.
    /// For high-assurance scenarios, the spec recommends process termination
    /// after disk erase (which releases all process memory to the OS).
    pub fn emergency_erase(&mut self) {
        let data_dir = std::path::Path::new(&self.data_dir);
        crate::identity::killswitch::standard_erase(data_dir);
        self.identity_unlocked = false;
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.vault = None;
    }

    /// Duress erase: destroy Layers 2 and 3, preserve Layer 1 (§3.9).
    ///
    /// Calls `killswitch::duress_erase` on disk.  Non-reversible.
    /// Layer 1 (the identity master key) is preserved so the user can
    /// re-create the device identity after the duress situation passes.
    /// All social state (contacts, rooms, messages) is destroyed.
    pub fn duress_erase(&mut self) {
        let data_dir = std::path::Path::new(&self.data_dir);
        crate::identity::killswitch::duress_erase(data_dir);
        self.identity_unlocked = false;
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.vault = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::app_connector::{
        AppConnectorApp, AppConnectorConfig, AppConnectorMode, AppConnectorRule, AppSelector,
        RoutingTarget,
    };

    #[test]
    fn android_vpn_policy_uses_backend_owned_allowlist_rules() {
        let runtime = MeshRuntime::new("target/test-android-vpn-policy-allow".to_string());
        *runtime
            .app_connector_config
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = AppConnectorConfig {
            mode: AppConnectorMode::Allowlist,
            apps: vec![AppConnectorApp {
                app_id: "org.example.chat".to_string(),
                name: "Chat".to_string(),
            }],
            rules: vec![AppConnectorRule {
                app_selector: AppSelector {
                    app_id: Some("org.example.browser".to_string()),
                    domain_pattern: None,
                    ip_range: None,
                    port: None,
                },
                routing_target: RoutingTarget::DirectMesh,
                priority: 1,
                enabled: true,
                threat_context_min: None,
            }],
        };
        runtime
            .vpn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .config
            .mode = RoutingMode::PolicyBased;

        let policy: serde_json::Value =
            serde_json::from_str(&runtime.get_android_vpn_policy()).unwrap();
        let allowed_apps = policy["allowedApps"].as_array().unwrap();

        assert_eq!(policy["enabled"], true);
        assert_eq!(policy["appMode"], "allowlist");
        assert_eq!(allowed_apps.len(), 2);
        assert!(allowed_apps.iter().any(|value| value == "org.example.chat"));
        assert!(allowed_apps
            .iter()
            .any(|value| value == "org.example.browser"));
    }

    #[test]
    fn android_vpn_policy_counts_unresolved_selector_rules() {
        let runtime = MeshRuntime::new("target/test-android-vpn-policy-unresolved".to_string());
        *runtime
            .app_connector_config
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = AppConnectorConfig {
            mode: AppConnectorMode::Denylist,
            apps: vec![],
            rules: vec![AppConnectorRule {
                app_selector: AppSelector {
                    app_id: None,
                    domain_pattern: Some("*.example.com".to_string()),
                    ip_range: None,
                    port: Some(443),
                },
                routing_target: RoutingTarget::Tor,
                priority: 1,
                enabled: true,
                threat_context_min: None,
            }],
        };
        runtime
            .vpn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .config
            .mode = RoutingMode::PolicyBased;

        let policy: serde_json::Value =
            serde_json::from_str(&runtime.get_android_vpn_policy()).unwrap();

        assert_eq!(policy["enabled"], false);
        assert_eq!(policy["unresolvedSelectorRuleCount"], 1);
        assert_eq!(policy["disallowedApps"].as_array().unwrap().len(), 0);
    }
}
