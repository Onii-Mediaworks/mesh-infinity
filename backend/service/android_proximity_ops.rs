//! Android proximity state and pairing intake.
//!
//! The Android platform layer still performs platform-specific NFC and
//! Wi-Fi Direct operations, but the backend owns the authoritative snapshot of
//! those capabilities and consumes received pairing payloads.

use crate::service::runtime::{AndroidProximityState, MeshRuntime};

impl MeshRuntime {
    /// Return the backend-owned Android proximity snapshot as JSON.
    pub fn get_android_proximity_state_json(&self) -> String {
        let state = self
            .android_proximity_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
    }

    /// Replace the backend-owned Android proximity snapshot.
    pub fn update_android_proximity_state(&self, state_json: &str) -> Result<(), String> {
        let state: AndroidProximityState = serde_json::from_str(state_json)
            .map_err(|e| format!("invalid android proximity state: {e}"))?;
        crate::transport::nfc::update_android_adapter_state(state.nfc_available, state.nfc_enabled);
        crate::transport::wifi_direct::update_android_adapter_state(
            state.wifi_direct_available,
            state.wifi_direct_enabled,
            state.wifi_direct_permission_granted,
            state.wifi_direct_discovery_active,
            state.wifi_direct_connected,
            state.wifi_direct_connection_role.clone(),
            state.wifi_direct_group_owner_address.clone(),
            state.wifi_direct_connected_device_address.clone(),
            state
                .peers
                .iter()
                .map(|peer| crate::transport::wifi_direct::WifiDirectPeer {
                    mac_address: peer.device_address.clone(),
                    device_name: peer.device_name.clone(),
                    peer_id_hex: None,
                    group_ip: None,
                    rssi: None,
                })
                .collect(),
        );
        *self
            .android_proximity_state
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = state.clone();
        self.push_event(
            "AndroidProximityUpdated",
            serde_json::to_value(&state).unwrap_or_else(|_| serde_json::json!({})),
        );
        Ok(())
    }

    /// Accept a pairing payload received over Android NFC or Wi-Fi Direct.
    pub fn ingest_android_pairing_payload(
        &self,
        payload_json: &str,
        source: &str,
    ) -> Result<(), String> {
        match source {
            "NFC" => crate::transport::nfc::enqueue_android_pairing_payload(payload_json),
            "WiFi Direct" => {
                crate::transport::wifi_direct::enqueue_android_inbound_pairing_payload(payload_json)
            }
            _ => {}
        }
        self.pair_peer(payload_json)?;
        self.push_event(
            "AndroidPairingPayloadAccepted",
            serde_json::json!({
                "source": source,
            }),
        );
        Ok(())
    }

    /// Accept one generic Wi-Fi Direct session frame from the Android bridge.
    pub fn ingest_android_wifi_direct_session_frame(
        &self,
        frame_bytes: &[u8],
    ) -> Result<(), String> {
        if frame_bytes.is_empty() {
            return Err("android wifi direct session frame is empty".into());
        }
        crate::transport::wifi_direct::enqueue_android_inbound_session_frame(frame_bytes);
        self.push_event(
            "AndroidWiFiDirectSessionFrameAccepted",
            serde_json::json!({
                "byteLength": frame_bytes.len(),
            }),
        );
        Ok(())
    }

    /// Queue a backend-authored Android Wi-Fi Direct pairing payload.
    pub fn queue_android_wifi_direct_pairing_payload(
        &self,
        payload_json: &str,
    ) -> Result<(), String> {
        if payload_json.trim().is_empty() {
            return Err("android wifi direct pairing payload is empty".into());
        }
        crate::transport::wifi_direct::queue_android_outbound_pairing_payload(payload_json);
        self.push_event(
            "AndroidWiFiDirectPairingPayloadQueued",
            serde_json::json!({}),
        );
        Ok(())
    }

    /// Dequeue the next backend-authored Android Wi-Fi Direct pairing payload.
    pub fn dequeue_android_wifi_direct_pairing_payload_json(&self) -> String {
        serde_json::json!({
            "payloadJson": crate::transport::wifi_direct::dequeue_android_outbound_pairing_payload(),
        })
        .to_string()
    }

    /// Queue a backend-authored Android Wi-Fi Direct session frame.
    pub fn queue_android_wifi_direct_session_frame(
        &self,
        frame_bytes: &[u8],
    ) -> Result<(), String> {
        if frame_bytes.is_empty() {
            return Err("android wifi direct session frame is empty".into());
        }
        crate::transport::wifi_direct::queue_android_outbound_session_frame(frame_bytes);
        self.push_event(
            "AndroidWiFiDirectSessionFrameQueued",
            serde_json::json!({
                "byteLength": frame_bytes.len(),
            }),
        );
        Ok(())
    }

    /// Dequeue the next backend-authored Android Wi-Fi Direct session frame.
    pub fn dequeue_android_wifi_direct_session_frame_json(&self) -> String {
        serde_json::json!({
            "frameHex": crate::transport::wifi_direct::dequeue_android_outbound_session_frame()
                .map(hex::encode),
        })
        .to_string()
    }

    /// Accept a Wi-Fi Direct socket file descriptor from the Kotlin bridge and
    /// transfer ownership to Rust.
    ///
    /// # Why Rust takes the fd
    ///
    /// Until this call the Kotlin bridge owned both sides of the socket.
    /// Ownership transfer closes the gap identified in the Android proximity
    /// transport audit: the native bridge managed the socket lifecycle, so Rust
    /// could not control send ordering, implement flow control, or react to
    /// socket errors without bouncing through JNI on every frame.
    ///
    /// After this call:
    /// - Rust owns the fd exclusively via a `TcpStream`.
    /// - Kotlin MUST NOT close, read, or write the fd or its wrapping `Socket`.
    /// - Kotlin calls `mi_wifi_direct_drain_session` in a tight coroutine loop
    ///   to flush frames Rust has queued for the peer.
    ///
    /// # Arguments
    ///
    /// * `peer_mac` — MAC address string from `WifiP2pDevice.deviceAddress`.
    /// * `fd`       — Connected socket file descriptor (from
    ///               `socket.fileDescriptor.fd` via reflection, or from a
    ///               `ParcelFileDescriptor.detachFd()` call).
    #[cfg(target_os = "android")]
    pub fn register_wifi_direct_session_fd(
        &self,
        peer_mac: &str,
        fd: i32,
    ) -> Result<(), String> {
        // Guard: peer_mac must be a non-empty string to be a usable key.
        if peer_mac.trim().is_empty() {
            return Err("peer_mac must not be empty".into());
        }
        // Guard: fd must be a plausible file descriptor value.
        // The lowest valid fd is 0 (stdin), but a connected socket is
        // always >= 3 because 0/1/2 are pre-opened by the process.
        if fd < 0 {
            return Err(format!("invalid file descriptor: {fd}"));
        }
        // Delegate to the transport layer.  The transport function validates
        // adapter state before wrapping the fd, so we do not double-check here.
        crate::transport::wifi_direct::register_wifi_direct_session_fd(peer_mac, fd)?;
        self.push_event(
            "AndroidWiFiDirectSessionFdRegistered",
            serde_json::json!({ "peerMac": peer_mac }),
        );
        Ok(())
    }

    /// Drain the outbound frame queue for a Rust-owned Wi-Fi Direct session.
    ///
    /// Called by the Kotlin drain coroutine in a tight loop after registering
    /// a session via `mi_wifi_direct_session_fd`.  Returns the number of frames
    /// flushed to the socket, or an error string on socket failure.
    ///
    /// The coroutine pattern on the Kotlin side should be:
    ///
    /// ```kotlin
    /// while (sessionActive) {
    ///     val n = MeshInfinityJni.wifiDirectDrainSession(ctxPtr, peerMac)
    ///     if (n < 0) break   // error — remove session
    ///     if (n == 0) delay(5)  // nothing to send — yield briefly
    /// }
    /// ```
    #[cfg(target_os = "android")]
    pub fn drain_wifi_direct_session(&self, peer_mac: &str) -> Result<usize, String> {
        crate::transport::wifi_direct::drain_wifi_direct_session(peer_mac)
    }
}
