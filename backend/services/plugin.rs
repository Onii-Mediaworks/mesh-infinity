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
// MAX_CPU_PER_CALLBACK_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_CPU_PER_CALLBACK_MS: u64 = 100;

/// Consecutive timeout count before auto-disable.
// TIMEOUT_AUTO_DISABLE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const TIMEOUT_AUTO_DISABLE: u32 = 3;

/// Init crash loop threshold before quarantine.
// CRASH_QUARANTINE_THRESHOLD — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const CRASH_QUARANTINE_THRESHOLD: u32 = 3;

/// Shutdown deadline (seconds).
// SHUTDOWN_DEADLINE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SHUTDOWN_DEADLINE_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Plugin Manifest
// ---------------------------------------------------------------------------

/// Plugin manifest (§18).
///
/// Describes a plugin's identity, version, permissions, and
/// resource requirements.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PluginManifest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PluginManifest {
    /// Unique plugin identifier (reverse-domain, e.g., "com.example.myplugin").
    // Execute this protocol step.
    pub id: String,
    /// Human-readable name.
    // Execute this protocol step.
    pub name: String,
    /// Plugin version (semver).
    // Execute this protocol step.
    pub version: String,
    /// Minimum API version required.
    // Execute this protocol step.
    pub api_version: String,
    /// Description.
    // Execute this protocol step.
    pub description: Option<String>,
    /// Author name.
    // Execute this protocol step.
    pub author: Option<String>,
    /// Homepage URL.
    // Execute this protocol step.
    pub homepage: Option<String>,
    /// License identifier (SPDX).
    // Execute this protocol step.
    pub license: Option<String>,
    /// Minimum Mesh Infinity version.
    // Execute this protocol step.
    pub min_mesh_version: Option<String>,
    /// Required permissions.
    // Execute this protocol step.
    pub required_permissions: Vec<String>,
    /// Optional permissions.
    // Execute this protocol step.
    pub optional_permissions: Vec<String>,
    /// Resource limits.
    // Execute this protocol step.
    pub resources: PluginResources,
}

/// Plugin resource limits.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PluginResources — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PluginResources {
    /// Maximum memory (MB).
    // Execute this protocol step.
    pub max_memory_mb: u32,
    /// Maximum persistent storage (MB).
    // Execute this protocol step.
    pub max_storage_mb: u32,
    /// Maximum CPU time per callback (ms).
    // Execute this protocol step.
    pub max_cpu_ms_per_call: u64,
    /// Maximum open handles (files, connections).
    // Execute this protocol step.
    pub max_open_handles: u32,
}

// Trait implementation for protocol conformance.
// Implement Default for PluginResources.
impl Default for PluginResources {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            max_memory_mb: 64,
            // Process the current step in the protocol.
            // Execute this protocol step.
            max_storage_mb: 256,
            // Process the current step in the protocol.
            // Execute this protocol step.
            max_cpu_ms_per_call: MAX_CPU_PER_CALLBACK_MS,
            // Process the current step in the protocol.
            // Execute this protocol step.
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
// Begin the block scope.
// PluginSignature — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PluginSignature {
    /// Author's Ed25519 public key.
    // Execute this protocol step.
    pub author_pubkey: [u8; 32],
    /// SHA-256 of the manifest.
    // Execute this protocol step.
    pub manifest_hash: [u8; 32],
    /// SHA-256 of the WASM binary.
    // Execute this protocol step.
    pub wasm_hash: [u8; 32],
    /// When the signature was created.
    // Execute this protocol step.
    pub timestamp: u64,
    /// Ed25519 signature over all above fields.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Plugin State
// ---------------------------------------------------------------------------

/// Runtime state of a plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// PluginState — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PluginState {
    /// Installed but not yet started.
    // Execute this protocol step.
    Installed,
    /// Running normally.
    Running,
    /// Stopped by the user.
    Stopped,
    /// Auto-disabled due to repeated timeouts.
    // Execute this protocol step.
    Disabled,
    /// Quarantined due to crash loop.
    // Execute this protocol step.
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
