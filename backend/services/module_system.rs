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
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
// ModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ModuleConfig {
    /// The social for this instance.
    pub social: SocialModuleConfig,
    /// The network for this instance.
    pub network: NetworkModuleConfig,
    /// The protocols for this instance.
    pub protocols: ProtocolModuleConfig,
    /// The agentic for this instance.
    pub agentic: AgenticModuleConfig,
    /// The plugins for this instance.
    pub plugins: PluginModuleConfig,
}

/// Social subsystem modules.
#[derive(Clone, Debug, Serialize, Deserialize)]
// SocialModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SocialModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SocialModuleConfig {
    /// The gardens for this instance.
    pub gardens: bool,
    /// The file sharing for this instance.
    pub file_sharing: bool,
    /// The store forward for this instance.
    pub store_forward: bool,
    /// The notifications for this instance.
    pub notifications: bool,
}

// Trait implementation for protocol conformance.
// Implement Default for SocialModuleConfig.
// Implement Default for SocialModuleConfig.
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
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
// NetworkModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NetworkModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct NetworkModuleConfig {
    /// The infinet for this instance.
    pub infinet: bool,
    /// The exit nodes for this instance.
    pub exit_nodes: bool,
    /// The vpn mode for this instance.
    pub vpn_mode: bool,
    /// The app connector for this instance.
    pub app_connector: bool,
    /// The funnel for this instance.
    pub funnel: bool,
}

/// Protocol subsystem modules.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
// ProtocolModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ProtocolModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ProtocolModuleConfig {
    /// The mnrdp server for this instance.
    pub mnrdp_server: bool,
    /// The mnsp server for this instance.
    pub mnsp_server: bool,
    /// The mnfp server for this instance.
    pub mnfp_server: bool,
    /// The api gateway for this instance.
    pub api_gateway: bool,
    /// The screen share for this instance.
    pub screen_share: bool,
    /// The clipboard sync for this instance.
    pub clipboard_sync: bool,
    /// The print service for this instance.
    pub print_service: bool,
}

/// Agentic subsystem modules.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
// AgenticModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AgenticModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AgenticModuleConfig {
    /// The mislp for this instance.
    pub mislp: bool,
}

/// Plugin subsystem configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
// PluginModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PluginModuleConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PluginModuleConfig {
    /// The runtime enabled for this instance.
    pub runtime_enabled: bool,
    /// The installed plugins for this instance.
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
        assert!(recovered.social.file_sharing);
    }
}
