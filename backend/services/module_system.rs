//! Module System (§17.13)
//!
//! # What is the Module System?
//!
//! The module system allows enabling/disabling major subsystems
//! at compile-time or runtime. Each module is a self-contained
//! feature that can be activated independently.
//!
//! # Module Categories
//!
//! - **Social**: Gardens, file sharing, S&F, notifications
//! - **Network**: Infinet, exit nodes, VPN, app connector, funnel
//! - **Protocols**: MNRDP, MNSP, MNFP, API gateway, screen share, etc.
//! - **Agentic**: MISLP (agentic distribution)
//! - **Plugins**: Runtime plugin system

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Module Configuration (§17.13)
// ---------------------------------------------------------------------------

/// Top-level module configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Default)]
pub struct ModuleConfig {
    pub social: SocialModuleConfig,
    pub network: NetworkModuleConfig,
    pub protocols: ProtocolModuleConfig,
    pub agentic: AgenticModuleConfig,
    pub plugins: PluginModuleConfig,
}


/// Social subsystem modules.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SocialModuleConfig {
    pub gardens: bool,
    pub file_sharing: bool,
    pub store_forward: bool,
    pub notifications: bool,
}

impl Default for SocialModuleConfig {
    fn default() -> Self {
        Self {
            gardens: true,
            file_sharing: true,
            store_forward: true,
            notifications: true,
        }
    }
}

/// Network subsystem modules.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Default)]
pub struct NetworkModuleConfig {
    pub infinet: bool,
    pub exit_nodes: bool,
    pub vpn_mode: bool,
    pub app_connector: bool,
    pub funnel: bool,
}


/// Protocol subsystem modules.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Default)]
pub struct ProtocolModuleConfig {
    pub mnrdp_server: bool,
    pub mnsp_server: bool,
    pub mnfp_server: bool,
    pub api_gateway: bool,
    pub screen_share: bool,
    pub clipboard_sync: bool,
    pub print_service: bool,
}


/// Agentic subsystem modules.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Default)]
pub struct AgenticModuleConfig {
    pub mislp: bool,
}


/// Plugin subsystem configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Default)]
pub struct PluginModuleConfig {
    pub runtime_enabled: bool,
    pub installed_plugins: HashMap<String, bool>,
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ModuleConfig::default();
        assert!(config.social.gardens);
        assert!(!config.network.infinet);
        assert!(!config.protocols.mnrdp_server);
        assert!(!config.plugins.runtime_enabled);
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = ModuleConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let recovered: ModuleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.social.file_sharing, true);
    }
}
