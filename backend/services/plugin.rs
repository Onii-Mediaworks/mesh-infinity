//! Plugin System (§18)
//!
//! # Three Tiers of Extensibility (§18.1)
//!
//! 1. **API integration**: external apps connect via service ports
//! 2. **Service hosting**: custom services on the mesh
//! 3. **Native plugins**: WASM modules with restricted permissions
//!
//! # Plugin Security (§18.3)
//!
//! Permanently off-limits (11 items):
//! - Key material access
//! - Raw transport layer access
//! - Trust graph mutation
//! - Other plugins' data
//! - Rust backend internals
//! - Anonymous mask linkage
//! - Root keypair operations
//! - Killswitch activation
//! - Threat context modification
//! - OIDC tokens
//! - Trust-related UI dialogs

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum CPU time per plugin callback (milliseconds).
pub const MAX_CPU_PER_CALLBACK_MS: u64 = 100;

/// Consecutive timeout count before auto-disable.
pub const TIMEOUT_AUTO_DISABLE: u32 = 3;

/// Init crash loop threshold before quarantine.
pub const CRASH_QUARANTINE_THRESHOLD: u32 = 3;

/// Shutdown deadline (seconds).
pub const SHUTDOWN_DEADLINE_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Plugin Manifest
// ---------------------------------------------------------------------------

/// Plugin manifest (§18).
///
/// Describes a plugin's identity, version, permissions, and
/// resource requirements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique plugin identifier (reverse-domain, e.g., "com.example.myplugin").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Plugin version (semver).
    pub version: String,
    /// Minimum API version required.
    pub api_version: String,
    /// Description.
    pub description: Option<String>,
    /// Author name.
    pub author: Option<String>,
    /// Homepage URL.
    pub homepage: Option<String>,
    /// License identifier (SPDX).
    pub license: Option<String>,
    /// Minimum Mesh Infinity version.
    pub min_mesh_version: Option<String>,
    /// Required permissions.
    pub required_permissions: Vec<String>,
    /// Optional permissions.
    pub optional_permissions: Vec<String>,
    /// Resource limits.
    pub resources: PluginResources,
}

/// Plugin resource limits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginResources {
    /// Maximum memory (MB).
    pub max_memory_mb: u32,
    /// Maximum persistent storage (MB).
    pub max_storage_mb: u32,
    /// Maximum CPU time per callback (ms).
    pub max_cpu_ms_per_call: u64,
    /// Maximum open handles (files, connections).
    pub max_open_handles: u32,
}

impl Default for PluginResources {
    fn default() -> Self {
        Self {
            max_memory_mb: 64,
            max_storage_mb: 256,
            max_cpu_ms_per_call: MAX_CPU_PER_CALLBACK_MS,
            max_open_handles: 32,
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin Signature
// ---------------------------------------------------------------------------

/// Cryptographic signature for a plugin (§18).
///
/// Verifies the plugin was built by the claimed author
/// and hasn't been tampered with.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginSignature {
    /// Author's Ed25519 public key.
    pub author_pubkey: [u8; 32],
    /// SHA-256 of the manifest.
    pub manifest_hash: [u8; 32],
    /// SHA-256 of the WASM binary.
    pub wasm_hash: [u8; 32],
    /// When the signature was created.
    pub timestamp: u64,
    /// Ed25519 signature over all above fields.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Plugin State
// ---------------------------------------------------------------------------

/// Runtime state of a plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginState {
    /// Installed but not yet started.
    Installed,
    /// Running normally.
    Running,
    /// Stopped by the user.
    Stopped,
    /// Auto-disabled due to repeated timeouts.
    Disabled,
    /// Quarantined due to crash loop.
    Quarantined,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_resources() {
        let res = PluginResources::default();
        assert_eq!(res.max_cpu_ms_per_call, MAX_CPU_PER_CALLBACK_MS);
        assert_eq!(res.max_memory_mb, 64);
    }

    #[test]
    fn test_plugin_states() {
        let state = PluginState::Running;
        let json = serde_json::to_string(&state).unwrap();
        let recovered: PluginState = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, PluginState::Running);
    }
}
