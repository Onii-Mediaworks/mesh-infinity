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
}
