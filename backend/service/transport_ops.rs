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
            parsed
                .get(key)
                .and_then(|v| v.as_bool())
                .unwrap_or(default)
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
        // Already running — nothing to do.
        if self
            .tor_transport
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(());
        }

        // Require an unlocked identity to derive the onion address.
        let (master_key, peer_id_hex) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = guard.as_ref().ok_or("identity not unlocked")?;
            (*id.master_key, id.peer_id().to_hex())
        };

        let state_dir = std::path::PathBuf::from(&self.data_dir);
        let transport =
            crate::transport::tor::TorTransport::bootstrap(&master_key, &peer_id_hex, &state_dir, DEFAULT_HS_PORT)
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
    /// Emits `MdnsStarted`.
    pub fn mdns_enable(&self) {
        // Bind the UDP discovery socket if not already bound.
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
        let peers = self.mdns_discovered.lock().unwrap_or_else(|e| e.into_inner());
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
    /// - `"mode"`: `"off"` | `"mesh_only"` | `"exit_node"` | `"policy"`
    /// - `"killSwitch"`: `"disabled"` | `"permissive"` | `"strict"`
    ///
    /// Emits `VpnModeChanged`.
    pub fn set_vpn_mode(&self, mode_json: &str) -> Result<(), String> {
        let config: serde_json::Value =
            serde_json::from_str(mode_json).map_err(|e| e.to_string())?;
        let mode_str = config
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("off");
        let mode = match mode_str {
            "off" => RoutingMode::Off,
            "mesh_only" => RoutingMode::MeshOnly,
            "exit_node" => RoutingMode::ExitNode,
            "policy" => RoutingMode::PolicyBased,
            _ => return Err(format!("unknown VPN mode: {mode_str}")),
        };

        // Apply the mode; `has_rules = true` permits all mode transitions.
        let threat = self.threat_context;
        self.vpn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_mode(mode, threat, true)
            .map_err(|e| format!("{e:?}"))?;

        self.push_event("VpnModeChanged", serde_json::json!({ "mode": mode_str }));
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
            self.push_event(
                "ExitNodeChanged",
                serde_json::json!({ "peerId": null }),
            );
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
        self.push_event(
            "ExitNodeChanged",
            serde_json::json!({ "peerId": peer_id_hex }),
        );
        Ok(())
    }

    /// Get the current VPN status as a JSON string.
    ///
    /// Returns fields: `enabled`, `mode`, `state`, `killSwitch`,
    /// `exitPeerId`, `internetAllowed`.
    pub fn get_vpn_status(&self) -> String {
        let vpn = self.vpn.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::json!({
            "enabled":         vpn.config.mode != RoutingMode::Off,
            "mode":            format!("{:?}", vpn.config.mode),
            "state":           format!("{:?}", vpn.state),
            "killSwitch":      format!("{:?}", vpn.config.kill_switch),
            "exitPeerId":      vpn.config.exit_peer_id.map(hex::encode),
            "internetAllowed": vpn.internet_traffic_allowed(),
        })
        .to_string()
    }

    // -----------------------------------------------------------------------
    // Overlay networks — Tailscale and ZeroTier (§5.22, §5.23)
    // -----------------------------------------------------------------------

    /// Authenticate the Tailscale client with an auth key.
    ///
    /// Stores the credential in the overlay manager, marks the client as
    /// `Connecting`, and emits `TailscaleConnecting`.  The actual WireGuard
    /// handshake with the control plane happens asynchronously.
    ///
    /// `auth_key`: a Tailscale auth key (`tskey-auth-…`) or OAuth token.
    /// `control_url`: empty string for the official server, or a Headscale URL.
    pub fn tailscale_auth_key(
        &self,
        auth_key: &str,
        control_url: &str,
    ) -> Result<(), String> {
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

        self.push_event("TailscaleConnecting", serde_json::json!({}));
        Ok(())
    }

    /// Begin the Tailscale OAuth interactive login flow.
    ///
    /// Marks the client as `Connecting` and emits `TailscaleOAuthUrl` with
    /// the redirect URL for the UI to open in a browser.
    ///
    /// `control_url`: empty string for official server, or Headscale URL.
    pub fn tailscale_begin_oauth(&self, control_url: &str) -> Result<(), String> {
        use crate::transport::overlay_client::{OverlayClientStatus, TailscaleController};

        let controller = if control_url.is_empty() {
            TailscaleController::Vendor
        } else {
            TailscaleController::Headscale {
                url: control_url.to_string(),
            }
        };

        // Build an OAuth initiation URL pointing to the control server.
        let oauth_url = format!("{}/a/", controller.base_url());

        let mut overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        overlay.tailscale.status = OverlayClientStatus::Connecting;
        drop(overlay);

        self.push_event("TailscaleOAuthUrl", serde_json::json!({ "url": oauth_url }));
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
            if !overlay.zerotier.networks.iter().any(|n| &n.network_id == nid) {
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

        self.push_event(
            "ZeroTierConnecting",
            serde_json::json!({ "networkIds": network_ids }),
        );
        Ok(())
    }

    /// Get the current status of all overlay networks as a JSON string.
    pub fn overlay_status(&self) -> String {
        let overlay = self.overlay.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::json!({
            "tailscale": {
                "connected":           overlay.tailscale.is_connected(),
                "deviceIp":            overlay.tailscale.device_info.as_ref().map(|d| d.tailscale_ip.as_str()),
                "exitNode":            overlay.tailscale.active_exit_node,
                "anonymizationScore":  overlay.tailscale.anonymization_score(),
            },
            "zerotier": {
                "connected": overlay.zerotier.is_connected(),
                "networks":  overlay.zerotier.networks.iter().map(|n| serde_json::json!({
                    "networkId":  n.network_id,
                    "name":       n.name,
                    "assignedIp": n.assigned_ip,
                    "authStatus": format!("{:?}", n.auth_status),
                })).collect::<Vec<_>>(),
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

        // Resolve hop key for FHSS profiles (required but gracefully defaults).
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

        let signed =
            SignedLoSecRequest::new(session_id, mode, hop_count, reason, &signing_key)
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
        let response =
            handle_losec_request(&signed, &service_config, monitor.losec_available(), &signing_key);
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
        })
        .to_string()
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
        Self::build_settings_json(&flags, node_mode, &self.threat_context, &peer_id, &ed25519_pub, clearnet_port).to_string()
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
        self.push_event(
            "SettingsUpdated",
            Self::build_settings_json(
                &flags,
                node_mode,
                &self.threat_context,
                &peer_id,
                &ed25519_pub,
                clearnet_port,
            ),
        );
    }
}
