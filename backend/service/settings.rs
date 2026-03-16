//! Service settings and transport-toggle operations.
//!
//! This module isolates mutable runtime configuration methods so toggle policy
//! logic is centralized and does not mix with messaging/discovery concerns.

use crate::core::core::MeshConfig;

use super::{MeshInfinityService, Settings};

impl MeshInfinityService {
    /// Return current user-facing settings snapshot.
    pub fn settings(&self) -> Settings {
        let state = self.state.read().unwrap();
        let mut settings = state.settings.clone();
        sync_settings_from_mesh(&mut settings, &state.mesh_config);
        settings
    }

    /// Enable/disable Tor transport preference.
    pub fn set_enable_tor(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.enable_tor = value;
        state.settings.enable_tor = value;
        self.transport_manager.set_tor_enabled(value);
    }

    /// Enable/disable clearnet transport preference.
    pub fn set_enable_clearnet(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.enable_clearnet = value;
        state.settings.enable_clearnet = value;
        self.transport_manager.set_clearnet_enabled(value);
    }

    /// Enable/disable mesh discovery behavior.
    pub fn set_mesh_discovery(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.mesh_discovery = value;
        state.settings.mesh_discovery = value;
    }

    /// Enable/disable relay usage policy.
    pub fn set_allow_relays(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.allow_relays = value;
        state.settings.allow_relays = value;
    }

    /// Enable/disable I2P transport preference.
    pub fn set_enable_i2p(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.enable_i2p = value;
        state.settings.enable_i2p = value;
        self.transport_manager.set_i2p_enabled(value);
    }

    /// Enable/disable Bluetooth transport preference.
    pub fn set_enable_bluetooth(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.enable_bluetooth = value;
        state.settings.enable_bluetooth = value;
        self.transport_manager.set_bluetooth_enabled(value);
    }

    /// Enable/disable RF transport preference.
    pub fn set_enable_rf(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.enable_rf = value;
        state.settings.enable_rf = value;
        self.transport_manager.set_rf_enabled(value);
    }

    /// Enable/disable clearnet fallback for originating connections.
    ///
    /// When `false`, this node will not use clearnet as a last resort when
    /// routing messages it originated.  Relay hops are unaffected.
    pub fn set_clearnet_fallback(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.clearnet_fallback = value;
        state.settings.clearnet_fallback = value;
        self.transport_manager.set_clearnet_fallback_enabled(value);
    }

    /// Return current mesh configuration snapshot.
    pub fn mesh_config(&self) -> MeshConfig {
        self.state.read().unwrap().mesh_config.clone()
    }

    /// Store VPN routing policy configuration blob.
    pub fn set_vpn_route_config(&self, config_json: String) {
        self.state.write().unwrap().vpn_route_config = Some(config_json);
    }

    /// Store clearnet routing policy configuration blob.
    pub fn set_clearnet_route_config(&self, config_json: String) {
        self.state.write().unwrap().clearnet_route_config = Some(config_json);
    }
}

/// Mirror mesh transport toggles into user-facing settings snapshot.
pub(super) fn sync_settings_from_mesh(settings: &mut Settings, mesh_config: &MeshConfig) {
    settings.enable_tor = mesh_config.enable_tor;
    settings.enable_clearnet = mesh_config.enable_clearnet;
    settings.mesh_discovery = mesh_config.mesh_discovery;
    settings.allow_relays = mesh_config.allow_relays;
    settings.enable_i2p = mesh_config.enable_i2p;
    settings.enable_bluetooth = mesh_config.enable_bluetooth;
    settings.enable_rf = mesh_config.enable_rf;
    settings.clearnet_fallback = mesh_config.clearnet_fallback;
}
