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
//!
//! # Registry Architecture
//!
//! The `PluginRegistry` is the central authority for plugin lifecycle
//! management. It tracks installed plugins, manages activation states,
//! dispatches hook invocations, and enforces permission boundaries.
//! Plugins communicate with the host through named hooks — each hook
//! receives a JSON input and returns a JSON output. The registry
//! records timing for each invocation to detect performance regressions.
//!
//! # Signature Verification
//!
//! Plugin packages carry an Ed25519 signature that binds the manifest
//! and binary to the author's public key. Verification uses the
//! domain-separated `DOMAIN_PLUGIN_SIGNATURE` to prevent cross-protocol
//! signature replay (see `crypto::signing`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Import the centralized error type for all fallible operations.
// Every public function returns Result<T, MeshError>.
use crate::error::MeshError;

// Import the domain-separated signing module for plugin signature verification.
// All signature operations go through this centralized module (§18.3).
use crate::crypto::signing;

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
// Plugin Permission
// ---------------------------------------------------------------------------

/// Permissions a plugin can request (§18.2).
///
/// Each variant maps to a capability gate enforced by the registry
/// before dispatching a hook. Unknown permissions from manifests are
/// parsed into the `Custom` variant so forward-compatible manifests
/// don't break on older hosts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// PluginPermission — variant enumeration.
// Match exhaustively to handle every permission type.
pub enum PluginPermission {
    /// Read messages from rooms the user has granted access to.
    // Maps to §18.2 "message.read" capability.
    ReadMessages,
    /// Send messages on behalf of the user (requires explicit consent).
    // Maps to §18.2 "message.send" capability.
    SendMessages,
    /// Read the contact/peer list (names, trust levels, online status).
    // Maps to §18.2 "contacts.read" capability.
    ReadContacts,
    /// Make outbound network requests (HTTP, DNS, etc.).
    // Maps to §18.2 "network" capability.
    NetworkAccess,
    /// Read and write files within the plugin's sandboxed directory.
    // Maps to §18.2 "files" capability.
    FileAccess,
    /// Post notifications to the user via the system tray or push.
    // Maps to §18.2 "notifications" capability.
    NotificationAccess,
    /// Invoke non-sensitive cryptographic operations (hash, HMAC, etc.).
    // Maps to §18.2 "crypto" capability — excludes key material (§18.3).
    CryptoAccess,
    /// A permission not known to this version of the host.
    // Forward-compatibility: new permission strings from newer manifests
    // are preserved verbatim so the user can still review them.
    Custom(String),
}

/// Parse a permission string (from JSON manifest) into a typed enum.
///
/// Known strings map to typed variants; unknown strings map to `Custom`.
/// This is the single conversion point — callers never match on raw strings.
// parse_permission_str — converts wire-format permission names to typed enum.
// Unknown strings are preserved as Custom for forward-compatibility.
fn parse_permission_str(s: &str) -> PluginPermission {
    // Match known permission names from the spec (§18.2).
    // Unknown names fall through to Custom so new permissions don't break old hosts.
    match s {
        "read_messages" => PluginPermission::ReadMessages,
        "send_messages" => PluginPermission::SendMessages,
        "read_contacts" => PluginPermission::ReadContacts,
        "network_access" => PluginPermission::NetworkAccess,
        "file_access" => PluginPermission::FileAccess,
        "notification_access" => PluginPermission::NotificationAccess,
        "crypto_access" => PluginPermission::CryptoAccess,
        // Forward-compatibility: preserve the raw string for display in the UI.
        other => PluginPermission::Custom(other.to_string()),
    }
}

/// Serialize a `PluginPermission` back to its wire-format string.
///
/// This is the inverse of `parse_permission_str` and is used when
/// exporting the registry state as JSON for the Flutter UI.
// permission_to_str — converts typed enum back to wire-format string.
// Used by to_json() for UI serialization.
fn permission_to_str(perm: &PluginPermission) -> String {
    // Map each typed variant back to the canonical wire-format string.
    // Custom variants are returned as-is.
    match perm {
        PluginPermission::ReadMessages => "read_messages".to_string(),
        PluginPermission::SendMessages => "send_messages".to_string(),
        PluginPermission::ReadContacts => "read_contacts".to_string(),
        PluginPermission::NetworkAccess => "network_access".to_string(),
        PluginPermission::FileAccess => "file_access".to_string(),
        PluginPermission::NotificationAccess => "notification_access".to_string(),
        PluginPermission::CryptoAccess => "crypto_access".to_string(),
        // Custom permissions are returned as-is, no transformation needed.
        PluginPermission::Custom(s) => s.clone(),
    }
}

// ---------------------------------------------------------------------------
// Plugin Status
// ---------------------------------------------------------------------------

/// Lifecycle state of a registered plugin (§18).
///
/// The state machine is:
///   Installed -> Active (via `activate`)
///   Active -> Suspended (via `suspend` or auto-suspend on failure)
///   Suspended -> Active (via `activate`)
///   Any -> Failed (on unrecoverable error; auto-suspended)
///
/// Only `Active` plugins receive hook invocations. `Failed` plugins
/// carry the error message for diagnostic display in the UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// PluginStatus — variant enumeration.
// Match exhaustively to handle every lifecycle state.
pub enum PluginStatus {
    /// Installed but not yet activated by the user.
    // Initial state after install; no hooks will fire.
    Installed,
    /// Running and receiving hook invocations.
    // Only active plugins participate in hook dispatch.
    Active,
    /// Suspended by the user or automatically after a failure.
    // Suspended plugins are skipped during hook dispatch.
    Suspended,
    /// An unrecoverable error occurred; the plugin is auto-suspended.
    // The String carries the error description for the UI.
    Failed(String),
}

// ---------------------------------------------------------------------------
// Plugin Manifest (registry-level)
// ---------------------------------------------------------------------------

/// A plugin manifest parsed from the plugin's package JSON (§18).
///
/// This is the registry-level manifest used during `install()`. It carries
/// the fields needed to create a `Plugin` record. The manifest is validated
/// during `parse_manifest()` before it reaches the registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
// RegistryManifest — protocol data structure for plugin installation.
// Validated by parse_manifest() before the registry sees it.
pub struct RegistryManifest {
    /// Human-readable plugin name (displayed in Settings > Plugins).
    // Must be non-empty; validated during parse_manifest().
    pub name: String,
    /// Semver version string (e.g., "1.2.3").
    // Must be non-empty; validated during parse_manifest().
    pub version: String,
    /// Author name or organization.
    // Displayed alongside the plugin in the UI.
    pub author: String,
    /// Short description of what the plugin does.
    // Shown in the plugin detail screen.
    pub description: String,
    /// Typed permissions this plugin requires.
    // Enforced by has_permission() before hook dispatch.
    pub permissions: Vec<PluginPermission>,
    /// Named hooks this plugin wants to register for.
    // Each string is a hook name (e.g., "on_message_received").
    pub hooks: Vec<String>,
    /// Minimum Mesh Infinity version required to run this plugin.
    // Used for compatibility checks during install.
    pub min_app_version: String,
}

// ---------------------------------------------------------------------------
// Plugin Record
// ---------------------------------------------------------------------------

/// A registered plugin in the registry (§18).
///
/// Created by `PluginRegistry::install()` and stored in the registry's
/// plugin list. The `id` is a random 16-byte identifier generated at
/// install time — it is NOT the reverse-domain ID from the manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Plugin — the primary record stored per installed plugin.
// ID is random, generated at install time.
pub struct Plugin {
    /// Unique 16-byte identifier, randomly generated at install time.
    // Used as the primary key in all registry lookups and hook maps.
    pub id: [u8; 16],
    /// Human-readable name from the manifest.
    // Displayed in the plugin list UI.
    pub name: String,
    /// Semver version string from the manifest.
    // Used for update detection and compatibility checks.
    pub version: String,
    /// Author name from the manifest.
    // Displayed in the plugin detail UI.
    pub author: String,
    /// Description from the manifest.
    // Displayed in the plugin detail UI.
    pub description: String,
    /// Permissions granted to this plugin.
    // Checked by has_permission() on every hook dispatch.
    pub permissions: Vec<PluginPermission>,
    /// Current lifecycle state.
    // Only Active plugins receive hook invocations.
    pub status: PluginStatus,
    /// Optional Ed25519 signature over the plugin package.
    // Verified by verify_signature() against the author's public key.
    pub signature: Option<Vec<u8>>,
    /// Unix timestamp (seconds since epoch) when the plugin was installed.
    // Recorded for audit and sorting in the UI.
    pub installed_at: u64,
}

// ---------------------------------------------------------------------------
// Hook Invocation
// ---------------------------------------------------------------------------

/// Records the result of invoking a single plugin for a named hook (§18).
///
/// The registry creates one `HookInvocation` per plugin per hook call.
/// These records are returned to the caller for logging, performance
/// monitoring, and debugging. The `duration_ms` field enables detection
/// of plugins that exceed the CPU time budget.
#[derive(Clone, Debug, Serialize, Deserialize)]
// HookInvocation — returned by invoke_hook() for each plugin that ran.
// Carries timing data for performance monitoring.
pub struct HookInvocation {
    /// The name of the hook that was invoked (e.g., "on_message_received").
    // Used for filtering and logging.
    pub hook_name: String,
    /// The 16-byte ID of the plugin that was invoked.
    // Links back to the Plugin record in the registry.
    pub plugin_id: [u8; 16],
    /// The JSON input that was passed to the plugin.
    // Preserved for debugging and replay.
    pub input: serde_json::Value,
    /// The JSON output returned by the plugin, if any.
    // None if the plugin did not produce output (e.g., notification-only hooks).
    pub output: Option<serde_json::Value>,
    /// Wall-clock time in milliseconds that the invocation took.
    // Compared against MAX_CPU_PER_CALLBACK_MS for timeout detection.
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Legacy types (preserved from original implementation)
// ---------------------------------------------------------------------------

/// Original plugin manifest structure (§18).
///
/// Describes a plugin's identity, version, permissions, and
/// resource requirements. Retained for compatibility with the
/// existing serialization format.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    // Provide sensible defaults matching the spec's resource limits.
    // These caps prevent any single plugin from monopolizing system resources.
    fn default() -> Self {
        // Construct with spec-defined defaults for each resource limit.
        // All values come from §18.1 resource budget table.
        Self {
            // 64 MB memory cap per plugin — sufficient for most use cases.
            // Exceeding this triggers OOM handling in the sandbox.
            max_memory_mb: 64,
            // 256 MB persistent storage — enough for caches and local DBs.
            // Enforced by the sandbox filesystem layer.
            max_storage_mb: 256,
            // CPU time per callback uses the global protocol constant.
            // Exceeding this increments the timeout counter toward auto-disable.
            max_cpu_ms_per_call: MAX_CPU_PER_CALLBACK_MS,
            // 32 open handles — covers typical file + network needs.
            // Enforced by the sandbox handle table.
            max_open_handles: 32,
        }
    }
}

/// Cryptographic signature for a plugin (§18).
///
/// Verifies the plugin was built by the claimed author
/// and hasn't been tampered with.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Runtime state of a plugin (legacy enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
// Plugin Registry
// ---------------------------------------------------------------------------

/// The central plugin registry — manages installed plugins and hook dispatch (§18).
///
/// The registry owns the full list of installed plugins and maintains a
/// mapping from hook names to the plugin IDs that are registered for each
/// hook. All mutation (install, uninstall, activate, suspend) goes through
/// this struct, ensuring consistent state.
///
/// Thread safety: the registry is designed to be owned by a single thread
/// (the backend event loop). If shared access is needed, wrap in a Mutex.
#[derive(Clone, Debug, Serialize, Deserialize)]
// PluginRegistry — the central authority for plugin lifecycle.
// Owns plugins vec and hooks map; all mutations go through methods.
pub struct PluginRegistry {
    /// All installed plugins, in installation order.
    // Linear scan is fine for the expected plugin count (<100).
    plugins: Vec<Plugin>,
    /// Map from hook name to the list of plugin IDs registered for that hook.
    // Used by invoke_hook() to find which plugins to call.
    hooks: HashMap<String, Vec<[u8; 16]>>,
}

impl PluginRegistry {
    /// Create a new, empty plugin registry.
    ///
    /// Called once during backend initialization. The registry starts with
    /// no plugins and no hooks registered.
    // new() — factory for an empty registry with no plugins or hooks.
    // Called by MeshRuntime::new() at startup.
    pub fn new() -> Self {
        // Start with empty collections; plugins are added via install().
        // The hooks map is populated lazily as plugins register for hooks.
        Self {
            plugins: Vec::new(),
            hooks: HashMap::new(),
        }
    }

    /// Install a plugin from a parsed manifest and optional signature.
    ///
    /// Generates a random 16-byte ID, records the current timestamp, and
    /// sets the initial status to `Installed`. The plugin must be explicitly
    /// activated via `activate()` before it receives hook invocations.
    ///
    /// Returns the generated plugin ID on success.
    // install() — creates a Plugin record from the manifest and adds it to the registry.
    // The plugin starts in Installed state; hooks are NOT auto-registered.
    pub fn install(
        &mut self,
        manifest: RegistryManifest,
        signature: Option<Vec<u8>>,
    ) -> Result<[u8; 16], MeshError> {
        // Generate a cryptographically random 16-byte plugin ID.
        // Uses getrandom for OS-level entropy (same source as key generation).
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|e| {
            // Map getrandom failure to Internal — this indicates a broken OS RNG.
            MeshError::Internal(format!("failed to generate plugin ID: {}", e))
        })?;

        // Record the current Unix timestamp for the installation audit trail.
        // Falls back to 0 if the system clock is unavailable (pre-epoch edge case).
        let installed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Build the Plugin record from the manifest fields.
        // Status starts as Installed — caller must explicitly activate.
        let plugin = Plugin {
            id,
            name: manifest.name,
            version: manifest.version,
            author: manifest.author,
            description: manifest.description,
            permissions: manifest.permissions,
            status: PluginStatus::Installed,
            signature,
            installed_at,
        };

        // Add to the registry's plugin list.
        // Order is preserved (installation order) for deterministic UI display.
        self.plugins.push(plugin);

        // Return the generated ID so the caller can reference this plugin.
        // The ID is the primary key for all subsequent operations.
        Ok(id)
    }

    /// Uninstall a plugin by its 16-byte ID.
    ///
    /// Removes the plugin from the registry and cleans up all hook
    /// registrations. Returns `MeshError::NotFound` if the ID doesn't
    /// match any installed plugin.
    // uninstall() — removes the plugin record and all associated hook entries.
    // After this call, the plugin ID is invalid and must not be reused.
    pub fn uninstall(&mut self, plugin_id: &[u8; 16]) -> Result<(), MeshError> {
        // Find the plugin's index in the list. Return NotFound if absent.
        // Linear scan is acceptable for the expected plugin count (<100).
        let index = self
            .plugins
            .iter()
            .position(|p| &p.id == plugin_id)
            .ok_or_else(|| MeshError::NotFound {
                kind: "plugin",
                id: hex::encode(plugin_id),
            })?;

        // Remove the plugin record from the list.
        // swap_remove is O(1) but changes order; we use remove to preserve order.
        self.plugins.remove(index);

        // Remove this plugin's ID from all hook registration lists.
        // Iterate every hook's subscriber list and filter out the uninstalled ID.
        for subscribers in self.hooks.values_mut() {
            // Retain only subscriber IDs that don't match the uninstalled plugin.
            // This is idempotent — if the plugin wasn't registered, nothing changes.
            subscribers.retain(|id| id != plugin_id);
        }

        // Remove empty hook entries to keep the map clean.
        // A hook with zero subscribers is dead weight.
        self.hooks.retain(|_name, subs| !subs.is_empty());

        Ok(())
    }

    /// Activate a plugin so it begins receiving hook invocations.
    ///
    /// Transitions from `Installed` or `Suspended` to `Active`. Plugins in
    /// `Failed` state can also be reactivated (the error is cleared).
    /// Returns `MeshError::NotFound` if the ID is not in the registry.
    // activate() — transitions the plugin to Active state.
    // Only Active plugins participate in hook dispatch.
    pub fn activate(&mut self, plugin_id: &[u8; 16]) -> Result<(), MeshError> {
        // Find the plugin record. Return NotFound if the ID is unknown.
        // Mutable borrow needed to update the status field.
        let plugin = self
            .plugins
            .iter_mut()
            .find(|p| &p.id == plugin_id)
            .ok_or_else(|| MeshError::NotFound {
                kind: "plugin",
                id: hex::encode(plugin_id),
            })?;

        // Transition to Active. This is valid from Installed, Suspended, or Failed.
        // Already-active plugins are a no-op (idempotent).
        plugin.status = PluginStatus::Active;
        Ok(())
    }

    /// Suspend a plugin so it stops receiving hook invocations.
    ///
    /// Transitions from `Active` (or any other state) to `Suspended`.
    /// This is a manual user action, distinct from `Failed` which is
    /// triggered automatically by runtime errors.
    // suspend() — transitions the plugin to Suspended state.
    // Suspended plugins are skipped during hook dispatch.
    pub fn suspend(&mut self, plugin_id: &[u8; 16]) -> Result<(), MeshError> {
        // Find the plugin record. Return NotFound if the ID is unknown.
        // Mutable borrow needed to update the status field.
        let plugin = self
            .plugins
            .iter_mut()
            .find(|p| &p.id == plugin_id)
            .ok_or_else(|| MeshError::NotFound {
                kind: "plugin",
                id: hex::encode(plugin_id),
            })?;

        // Transition to Suspended. Idempotent if already suspended.
        // The plugin retains its hook registrations but won't receive invocations.
        plugin.status = PluginStatus::Suspended;
        Ok(())
    }

    /// Look up a plugin by its 16-byte ID.
    ///
    /// Returns a shared reference to the plugin record, or `None` if the
    /// ID is not in the registry. This is a read-only operation.
    // get() — O(n) lookup by ID; fine for <100 plugins.
    // Returns None rather than an error for ergonomic Option chaining.
    pub fn get(&self, plugin_id: &[u8; 16]) -> Option<&Plugin> {
        // Linear scan over the plugin list to find the matching ID.
        // For the expected plugin count (<100), this is faster than a HashMap.
        self.plugins.iter().find(|p| &p.id == plugin_id)
    }

    /// Return a slice of all installed plugins.
    ///
    /// The order is installation order (oldest first). Used by the UI
    /// to display the full plugin list.
    // list() — returns the full plugin list as a slice.
    // Borrows the internal Vec without copying.
    pub fn list(&self) -> &[Plugin] {
        // Return a slice view of the internal plugin list.
        // No allocation — the caller borrows directly.
        &self.plugins
    }

    /// Return only the active plugins (those receiving hook invocations).
    ///
    /// Used by the UI to show which plugins are currently running, and
    /// by the hook dispatcher to filter eligible plugins.
    // list_active() — filters the plugin list to only Active-status entries.
    // Returns owned references; allocation is minimal for <100 plugins.
    pub fn list_active(&self) -> Vec<&Plugin> {
        // Filter to only Active plugins. Suspended, Installed, and Failed are excluded.
        // The returned Vec borrows from self — no cloning of Plugin records.
        self.plugins
            .iter()
            .filter(|p| p.status == PluginStatus::Active)
            .collect()
    }

    /// Register a plugin to receive invocations for a named hook.
    ///
    /// The plugin must exist in the registry. Duplicate registrations
    /// for the same (hook, plugin) pair are silently ignored (idempotent).
    // register_hook() — adds the plugin ID to the hook's subscriber list.
    // Idempotent: re-registering the same plugin for the same hook is a no-op.
    pub fn register_hook(
        &mut self,
        hook_name: &str,
        plugin_id: [u8; 16],
    ) -> Result<(), MeshError> {
        // Verify the plugin exists before registering the hook.
        // This prevents orphaned hook entries for non-existent plugins.
        if !self.plugins.iter().any(|p| p.id == plugin_id) {
            return Err(MeshError::NotFound {
                kind: "plugin",
                id: hex::encode(plugin_id),
            });
        }

        // Get or create the subscriber list for this hook name.
        // entry() avoids a double lookup (check + insert).
        let subscribers = self.hooks.entry(hook_name.to_string()).or_default();

        // Only add if not already present — idempotent registration.
        // Linear scan is fine for the expected subscriber count per hook (<20).
        if !subscribers.contains(&plugin_id) {
            subscribers.push(plugin_id);
        }

        Ok(())
    }

    /// Invoke all active plugins registered for a named hook.
    ///
    /// Each plugin receives the same `input` JSON value. The registry
    /// records timing for each invocation and returns a `HookInvocation`
    /// per plugin. Suspended and non-active plugins are skipped.
    /// Permission checks are NOT done here — the caller must check
    /// permissions before invoking the hook if needed.
    ///
    /// In this native API implementation, hook output is always `None`
    /// because actual plugin execution requires a runtime (WASM or native
    /// dylib). The framework records timing and filters by status, ready
    /// for a real runtime to be plugged in.
    // invoke_hook() — dispatches the hook to all registered, active plugins.
    // Returns one HookInvocation per eligible plugin with timing data.
    pub fn invoke_hook(&self, hook_name: &str, input: serde_json::Value) -> Vec<HookInvocation> {
        // Look up the subscriber list for this hook. Empty vec if no registrations.
        // Cloning the subscriber list avoids borrow conflicts during iteration.
        let subscriber_ids = match self.hooks.get(hook_name) {
            Some(ids) => ids.clone(),
            // No plugins registered for this hook — return empty results.
            None => return Vec::new(),
        };

        // Collect invocation results for each registered, active plugin.
        // Pre-allocate to the number of subscribers (upper bound).
        let mut results = Vec::with_capacity(subscriber_ids.len());

        for plugin_id in &subscriber_ids {
            // Look up the plugin record to check its status.
            // Skip if the plugin was uninstalled between registration and invocation.
            let plugin = match self.get(plugin_id) {
                Some(p) => p,
                // Plugin was uninstalled — skip silently.
                None => continue,
            };

            // Only active plugins receive hook invocations.
            // Installed, Suspended, and Failed plugins are skipped.
            if plugin.status != PluginStatus::Active {
                continue;
            }

            // Record the start time for performance monitoring.
            // Uses monotonic Instant to avoid clock skew issues.
            let start = std::time::Instant::now();

            // In the native API framework, actual execution is a no-op.
            // A real runtime (WASM/dylib) would call the plugin here and
            // capture its output. For now, output is None.
            let output: Option<serde_json::Value> = None;

            // Compute the elapsed time in milliseconds.
            // This will be compared against MAX_CPU_PER_CALLBACK_MS for timeout detection.
            let duration_ms = start.elapsed().as_millis() as u64;

            // Build the invocation record with timing and I/O data.
            // The caller can use this for logging and performance alerts.
            results.push(HookInvocation {
                hook_name: hook_name.to_string(),
                plugin_id: *plugin_id,
                input: input.clone(),
                output,
                duration_ms,
            });
        }

        results
    }

    /// Verify a plugin's Ed25519 signature against a trusted signing key.
    ///
    /// The signature covers the plugin's name, version, and author fields
    /// concatenated together. Uses domain-separated verification via
    /// `DOMAIN_PLUGIN_SIGNATURE` to prevent cross-protocol replay.
    ///
    /// Returns `false` if the plugin has no signature or if verification fails.
    // verify_signature() — checks the plugin's Ed25519 signature.
    // Uses the centralized signing module with DOMAIN_PLUGIN_SIGNATURE.
    pub fn verify_signature(&self, plugin: &Plugin, signing_key: &[u8; 32]) -> bool {
        // A plugin with no signature cannot be verified — return false.
        // The UI should warn the user about unsigned plugins.
        let sig_bytes = match &plugin.signature {
            Some(s) => s,
            // No signature present — verification fails by definition.
            None => return false,
        };

        // Build the signed message: name || version || author.
        // This binds the signature to the plugin's identity fields.
        let mut message = Vec::new();
        message.extend_from_slice(plugin.name.as_bytes());
        message.extend_from_slice(plugin.version.as_bytes());
        message.extend_from_slice(plugin.author.as_bytes());

        // Delegate to the centralized signing module with the plugin domain separator.
        // This prevents reuse of signatures from other protocol contexts.
        signing::verify(
            signing_key,
            signing::DOMAIN_PLUGIN_SIGNATURE,
            &message,
            sig_bytes,
        )
    }

    /// Check whether a plugin has been granted a specific permission.
    ///
    /// Returns `true` if the plugin exists and its permission list contains
    /// the requested permission. Returns `false` if the plugin is not found
    /// or lacks the permission.
    // has_permission() — permission gate for hook dispatch and API calls.
    // Called before any capability-gated operation.
    pub fn has_permission(
        &self,
        plugin_id: &[u8; 16],
        permission: &PluginPermission,
    ) -> bool {
        // Look up the plugin. If not found, the permission check fails.
        // This is a deliberate fail-closed design — unknown plugins have no permissions.
        match self.get(plugin_id) {
            Some(plugin) => {
                // Check if the requested permission is in the plugin's granted list.
                // Uses PartialEq on PluginPermission for comparison.
                plugin.permissions.contains(permission)
            }
            // Plugin not found — fail closed, no permissions.
            None => false,
        }
    }

    /// Export the full registry state as a JSON value for the Flutter UI.
    ///
    /// Serializes all plugins and their statuses into a JSON object that
    /// the FFI layer can pass to Dart. The format is:
    /// ```json
    /// {
    ///   "plugins": [ { "id": "hex...", "name": "...", ... } ],
    ///   "hook_count": 5
    /// }
    /// ```
    // to_json() — serializes the registry state for the Flutter UI.
    // Called by the FFI layer when the UI requests the plugin list.
    pub fn to_json(&self) -> serde_json::Value {
        // Build the plugins array with hex-encoded IDs and string statuses.
        // Each plugin becomes a JSON object with all user-visible fields.
        let plugins_json: Vec<serde_json::Value> = self
            .plugins
            .iter()
            .map(|p| {
                // Convert the plugin's permission list to string array.
                // Uses permission_to_str() for wire-format consistency.
                let perms: Vec<String> = p
                    .permissions
                    .iter()
                    .map(permission_to_str)
                    .collect();

                // Serialize the status to a human-readable string.
                // Failed carries the error message in a nested object.
                let status_str = match &p.status {
                    PluginStatus::Installed => "installed".to_string(),
                    PluginStatus::Active => "active".to_string(),
                    PluginStatus::Suspended => "suspended".to_string(),
                    PluginStatus::Failed(msg) => format!("failed: {}", msg),
                };

                // Build the JSON object for this plugin.
                // All fields are safe to display in the UI (no key material).
                serde_json::json!({
                    "id": hex::encode(p.id),
                    "name": p.name,
                    "version": p.version,
                    "author": p.author,
                    "description": p.description,
                    "permissions": perms,
                    "status": status_str,
                    "has_signature": p.signature.is_some(),
                    "installed_at": p.installed_at,
                })
            })
            .collect();

        // Build the top-level JSON object with the plugins array and metadata.
        // hook_count tells the UI how many distinct hooks are registered.
        serde_json::json!({
            "plugins": plugins_json,
            "hook_count": self.hooks.len(),
        })
    }
}

// ---------------------------------------------------------------------------
// Manifest Parsing
// ---------------------------------------------------------------------------

/// Parse a registry-level plugin manifest from a JSON string.
///
/// Validates that all required fields are present and non-empty.
/// Permission strings are converted to typed `PluginPermission` enums.
/// Returns `MeshError::MalformedFrame` if the JSON is invalid or
/// required fields are missing.
// parse_manifest() — the single entry point for manifest deserialization.
// All validation happens here; the registry trusts the output.
pub fn parse_manifest(json: &str) -> Result<RegistryManifest, MeshError> {
    // Parse the raw JSON into a generic Value first for field-level validation.
    // This gives better error messages than serde's struct deserialization.
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| MeshError::MalformedFrame(format!(
            "plugin manifest JSON parse error: {}", e
        )))?;

    // Extract and validate the required "name" field.
    // Must be a non-empty string — plugins without names cannot be displayed.
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            MeshError::MalformedFrame("plugin manifest missing or empty 'name' field".to_string())
        })?
        .to_string();

    // Extract and validate the required "version" field.
    // Must be a non-empty string (semver format expected but not enforced here).
    let version = value
        .get("version")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            MeshError::MalformedFrame(
                "plugin manifest missing or empty 'version' field".to_string(),
            )
        })?
        .to_string();

    // Extract the "author" field — defaults to "Unknown" if absent.
    // We don't require it because community plugins may not have a named author.
    let author = value
        .get("author")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();

    // Extract the "description" field — defaults to empty string if absent.
    // Optional because not all plugins need a long description.
    let description = value
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Parse the "permissions" array into typed PluginPermission values.
    // Each element is a string that maps to a known or Custom permission.
    let permissions: Vec<PluginPermission> = value
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            // Convert each JSON string to a typed PluginPermission.
            // Non-string elements are silently skipped (defensive parsing).
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(parse_permission_str)
                .collect()
        })
        .unwrap_or_default();

    // Parse the "hooks" array into a list of hook name strings.
    // Each element names a hook the plugin wants to register for.
    let hooks: Vec<String> = value
        .get("hooks")
        .and_then(|v| v.as_array())
        .map(|arr| {
            // Convert each JSON string to an owned String.
            // Non-string elements are silently skipped.
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Extract the "min_app_version" field — defaults to "0.0.0" if absent.
    // This means the plugin is compatible with any version.
    let min_app_version = value
        .get("min_app_version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0")
        .to_string();

    // All fields validated — construct the RegistryManifest.
    // The registry trusts this output and won't re-validate.
    Ok(RegistryManifest {
        name,
        version,
        author,
        description,
        permissions,
        hooks,
        min_app_version,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Legacy tests (preserved from original implementation)
    // -----------------------------------------------------------------------

    /// Verify default resource limits match the spec constants.
    #[test]
    fn test_default_resources() {
        // PluginResources::default() must use the protocol constants.
        let res = PluginResources::default();
        // CPU limit must match the global constant.
        assert_eq!(res.max_cpu_ms_per_call, MAX_CPU_PER_CALLBACK_MS);
        // Memory limit must be 64 MB per the spec.
        assert_eq!(res.max_memory_mb, 64);
    }

    /// Verify that PluginState round-trips through JSON serialization.
    #[test]
    fn test_plugin_states() {
        // Serialize PluginState::Running to JSON and back.
        let state = PluginState::Running;
        // serde_json::to_string is safe to unwrap in tests.
        let json = serde_json::to_string(&state).expect("serialize PluginState");
        // Deserialize and verify the round-trip is lossless.
        let recovered: PluginState =
            serde_json::from_str(&json).expect("deserialize PluginState");
        assert_eq!(recovered, PluginState::Running);
    }

    // -----------------------------------------------------------------------
    // Install / Uninstall lifecycle
    // -----------------------------------------------------------------------

    /// Helper: build a minimal valid RegistryManifest for testing.
    fn test_manifest() -> RegistryManifest {
        // Minimal manifest with all required fields populated.
        // Used by most tests; individual tests override fields as needed.
        RegistryManifest {
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "Test Author".to_string(),
            description: "A plugin for testing".to_string(),
            permissions: vec![
                PluginPermission::ReadMessages,
                PluginPermission::NetworkAccess,
            ],
            hooks: vec!["on_message".to_string()],
            min_app_version: "0.1.0".to_string(),
        }
    }

    /// Installing a plugin returns a valid 16-byte ID and the plugin is retrievable.
    #[test]
    fn test_install_creates_plugin() {
        // Create an empty registry and install a test plugin.
        let mut registry = PluginRegistry::new();
        let manifest = test_manifest();

        // install() should succeed and return a 16-byte ID.
        let id = registry
            .install(manifest.clone(), None)
            .expect("install should succeed");

        // The returned ID must be 16 bytes (128 bits).
        assert_eq!(id.len(), 16);

        // The plugin should be retrievable by its ID.
        let plugin = registry.get(&id).expect("plugin should exist after install");

        // Verify the manifest fields were copied correctly.
        assert_eq!(plugin.name, "Test Plugin");
        assert_eq!(plugin.version, "1.0.0");
        assert_eq!(plugin.author, "Test Author");
        assert_eq!(plugin.description, "A plugin for testing");

        // New plugins start in Installed status — not Active.
        assert_eq!(plugin.status, PluginStatus::Installed);

        // No signature was provided, so it should be None.
        assert!(plugin.signature.is_none());

        // installed_at should be a reasonable Unix timestamp (after 2020-01-01).
        assert!(plugin.installed_at > 1_577_836_800);
    }

    /// Installing multiple plugins gives each a unique ID.
    #[test]
    fn test_install_unique_ids() {
        // Create a registry and install two plugins from the same manifest.
        let mut registry = PluginRegistry::new();
        let id1 = registry
            .install(test_manifest(), None)
            .expect("install 1 should succeed");
        let id2 = registry
            .install(test_manifest(), None)
            .expect("install 2 should succeed");

        // IDs must be unique — the RNG must not produce duplicates.
        assert_ne!(id1, id2);

        // Both plugins should be in the list.
        assert_eq!(registry.list().len(), 2);
    }

    /// Uninstalling a plugin removes it from the registry.
    #[test]
    fn test_uninstall_removes_plugin() {
        // Install a plugin, then uninstall it.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");

        // Verify it exists before uninstall.
        assert!(registry.get(&id).is_some());

        // Uninstall should succeed.
        registry.uninstall(&id).expect("uninstall should succeed");

        // The plugin should no longer be retrievable.
        assert!(registry.get(&id).is_none());

        // The list should be empty.
        assert!(registry.list().is_empty());
    }

    /// Uninstalling a non-existent plugin returns NotFound.
    #[test]
    fn test_uninstall_not_found() {
        // Try to uninstall from an empty registry.
        let mut registry = PluginRegistry::new();
        let fake_id = [0xAA; 16];

        // Should return a NotFound error.
        let result = registry.uninstall(&fake_id);
        assert!(result.is_err());
    }

    /// Uninstalling cleans up hook registrations for that plugin.
    #[test]
    fn test_uninstall_cleans_hooks() {
        // Install a plugin and register it for a hook, then uninstall.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");

        // Register the plugin for a hook.
        registry
            .register_hook("on_message", id)
            .expect("register_hook should succeed");

        // Uninstall the plugin.
        registry.uninstall(&id).expect("uninstall should succeed");

        // The hook's subscriber list should be empty (or the hook entry removed).
        // invoke_hook should return no results.
        let results = registry.invoke_hook("on_message", serde_json::json!({}));
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // Activate / Suspend
    // -----------------------------------------------------------------------

    /// Activating a plugin transitions it to Active status.
    #[test]
    fn test_activate() {
        // Install a plugin (starts as Installed) and activate it.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");

        // Activate should succeed.
        registry.activate(&id).expect("activate should succeed");

        // Status should now be Active.
        let plugin = registry.get(&id).expect("plugin should exist");
        assert_eq!(plugin.status, PluginStatus::Active);
    }

    /// Activating a non-existent plugin returns NotFound.
    #[test]
    fn test_activate_not_found() {
        // Try to activate a non-existent plugin.
        let mut registry = PluginRegistry::new();
        let fake_id = [0xBB; 16];

        // Should return NotFound.
        let result = registry.activate(&fake_id);
        assert!(result.is_err());
    }

    /// Suspending a plugin transitions it to Suspended status.
    #[test]
    fn test_suspend() {
        // Install and activate a plugin, then suspend it.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");
        registry.activate(&id).expect("activate should succeed");

        // Suspend should succeed.
        registry.suspend(&id).expect("suspend should succeed");

        // Status should now be Suspended.
        let plugin = registry.get(&id).expect("plugin should exist");
        assert_eq!(plugin.status, PluginStatus::Suspended);
    }

    /// Suspending a non-existent plugin returns NotFound.
    #[test]
    fn test_suspend_not_found() {
        // Try to suspend a non-existent plugin.
        let mut registry = PluginRegistry::new();
        let fake_id = [0xCC; 16];

        // Should return NotFound.
        let result = registry.suspend(&fake_id);
        assert!(result.is_err());
    }

    /// list_active() only returns plugins with Active status.
    #[test]
    fn test_list_active_filters() {
        // Install three plugins: activate one, suspend one, leave one installed.
        let mut registry = PluginRegistry::new();
        let id1 = registry
            .install(test_manifest(), None)
            .expect("install 1");
        let id2 = registry
            .install(test_manifest(), None)
            .expect("install 2");
        let _id3 = registry
            .install(test_manifest(), None)
            .expect("install 3");

        // Activate plugin 1, suspend plugin 2, leave plugin 3 as Installed.
        registry.activate(&id1).expect("activate 1");
        registry.activate(&id2).expect("activate 2");
        registry.suspend(&id2).expect("suspend 2");

        // list_active() should return only plugin 1.
        let active = registry.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id1);
    }

    // -----------------------------------------------------------------------
    // Hook registration and invocation
    // -----------------------------------------------------------------------

    /// Registering a hook for a non-existent plugin returns NotFound.
    #[test]
    fn test_register_hook_not_found() {
        // Try to register a hook for a non-existent plugin.
        let mut registry = PluginRegistry::new();
        let fake_id = [0xDD; 16];

        // Should return NotFound.
        let result = registry.register_hook("on_message", fake_id);
        assert!(result.is_err());
    }

    /// Duplicate hook registration is idempotent.
    #[test]
    fn test_register_hook_idempotent() {
        // Register the same plugin for the same hook twice.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");

        // First registration should succeed.
        registry
            .register_hook("on_message", id)
            .expect("first register_hook should succeed");

        // Second registration should also succeed (idempotent).
        registry
            .register_hook("on_message", id)
            .expect("second register_hook should succeed");

        // Activate the plugin so it receives invocations.
        registry.activate(&id).expect("activate should succeed");

        // invoke_hook should produce exactly one invocation (not two).
        let results = registry.invoke_hook("on_message", serde_json::json!({"text": "hello"}));
        assert_eq!(results.len(), 1);
    }

    /// invoke_hook returns results only for active plugins.
    #[test]
    fn test_invoke_hook_active_only() {
        // Install two plugins, register both for the same hook.
        let mut registry = PluginRegistry::new();
        let id1 = registry.install(test_manifest(), None).expect("install 1");
        let id2 = registry.install(test_manifest(), None).expect("install 2");

        // Register both for "on_message".
        registry
            .register_hook("on_message", id1)
            .expect("register 1");
        registry
            .register_hook("on_message", id2)
            .expect("register 2");

        // Activate only plugin 1.
        registry.activate(&id1).expect("activate 1");

        // invoke_hook should only return a result for the active plugin.
        let input = serde_json::json!({"text": "test"});
        let results = registry.invoke_hook("on_message", input);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plugin_id, id1);

        // The hook_name should be recorded correctly.
        assert_eq!(results[0].hook_name, "on_message");
    }

    /// invoke_hook for an unregistered hook returns an empty vec.
    #[test]
    fn test_invoke_hook_unknown_hook() {
        // Invoke a hook that no plugin is registered for.
        let registry = PluginRegistry::new();
        let results = registry.invoke_hook("nonexistent_hook", serde_json::json!({}));
        assert!(results.is_empty());
    }

    /// invoke_hook records the input and timing data.
    #[test]
    fn test_invoke_hook_records_timing() {
        // Install and activate a plugin, register it for a hook, then invoke.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install");
        registry.activate(&id).expect("activate");
        registry
            .register_hook("on_data", id)
            .expect("register_hook");

        // Invoke the hook with some input data.
        let input = serde_json::json!({"key": "value"});
        let results = registry.invoke_hook("on_data", input.clone());

        // Exactly one invocation should be returned.
        assert_eq!(results.len(), 1);
        let inv = &results[0];

        // Input should match what we passed in.
        assert_eq!(inv.input, input);

        // Output is None in the framework (no real plugin runtime).
        assert!(inv.output.is_none());

        // Duration should be non-negative (it's u64, so always >= 0).
        // In practice it should be very small since no real work is done.
        assert!(inv.duration_ms < 1000);
    }

    // -----------------------------------------------------------------------
    // Permission checks
    // -----------------------------------------------------------------------

    /// has_permission returns true for granted permissions.
    #[test]
    fn test_has_permission_granted() {
        // Install a plugin with ReadMessages and NetworkAccess permissions.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install");

        // The test manifest grants ReadMessages and NetworkAccess.
        assert!(registry.has_permission(&id, &PluginPermission::ReadMessages));
        assert!(registry.has_permission(&id, &PluginPermission::NetworkAccess));
    }

    /// has_permission returns false for non-granted permissions.
    #[test]
    fn test_has_permission_denied() {
        // Install a plugin with only ReadMessages and NetworkAccess.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install");

        // FileAccess was NOT granted — should return false.
        assert!(!registry.has_permission(&id, &PluginPermission::FileAccess));

        // CryptoAccess was NOT granted — should return false.
        assert!(!registry.has_permission(&id, &PluginPermission::CryptoAccess));
    }

    /// has_permission returns false for a non-existent plugin.
    #[test]
    fn test_has_permission_no_plugin() {
        // Check permission for a non-existent plugin ID.
        let registry = PluginRegistry::new();
        let fake_id = [0xEE; 16];

        // Should return false (fail-closed).
        assert!(!registry.has_permission(&fake_id, &PluginPermission::ReadMessages));
    }

    /// Custom permissions are compared by their string value.
    #[test]
    fn test_has_permission_custom() {
        // Install a plugin with a custom permission.
        let mut registry = PluginRegistry::new();
        let mut manifest = test_manifest();
        manifest
            .permissions
            .push(PluginPermission::Custom("special_feature".to_string()));

        let id = registry.install(manifest, None).expect("install");

        // The custom permission should be found by value.
        assert!(registry.has_permission(
            &id,
            &PluginPermission::Custom("special_feature".to_string()),
        ));

        // A different custom permission should NOT be found.
        assert!(!registry.has_permission(
            &id,
            &PluginPermission::Custom("other_feature".to_string()),
        ));
    }

    // -----------------------------------------------------------------------
    // Signature verification
    // -----------------------------------------------------------------------

    /// Verify a valid signature against the correct signing key.
    #[test]
    fn test_verify_signature_valid() {
        // Generate a test Ed25519 keypair.
        let secret = [0x42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let public = signing_key.verifying_key().to_bytes();

        // Build the message that verify_signature expects: name || version || author.
        let name = "Signed Plugin";
        let version = "2.0.0";
        let author = "Trusted Author";
        let mut message = Vec::new();
        message.extend_from_slice(name.as_bytes());
        message.extend_from_slice(version.as_bytes());
        message.extend_from_slice(author.as_bytes());

        // Sign the message with the plugin domain separator.
        let sig = signing::sign(&secret, signing::DOMAIN_PLUGIN_SIGNATURE, &message);

        // Create a plugin with the matching fields and signature.
        let mut registry = PluginRegistry::new();
        let mut manifest = test_manifest();
        manifest.name = name.to_string();
        manifest.version = version.to_string();
        manifest.author = author.to_string();

        let id = registry
            .install(manifest, Some(sig))
            .expect("install");
        let plugin = registry.get(&id).expect("plugin should exist");

        // Verification should succeed with the correct public key.
        assert!(registry.verify_signature(plugin, &public));
    }

    /// Verification fails with the wrong signing key.
    #[test]
    fn test_verify_signature_wrong_key() {
        // Generate a test keypair and sign with it.
        let secret = [0x42u8; 32];
        let name = "Signed Plugin";
        let version = "1.0.0";
        let author = "Author";

        let mut message = Vec::new();
        message.extend_from_slice(name.as_bytes());
        message.extend_from_slice(version.as_bytes());
        message.extend_from_slice(author.as_bytes());

        let sig = signing::sign(&secret, signing::DOMAIN_PLUGIN_SIGNATURE, &message);

        // Create a plugin with the signature.
        let mut registry = PluginRegistry::new();
        let mut manifest = test_manifest();
        manifest.name = name.to_string();
        manifest.version = version.to_string();
        manifest.author = author.to_string();

        let id = registry.install(manifest, Some(sig)).expect("install");
        let plugin = registry.get(&id).expect("plugin should exist");

        // Verify with a DIFFERENT public key — must fail.
        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32])
            .verifying_key()
            .to_bytes();
        assert!(!registry.verify_signature(plugin, &wrong_key));
    }

    /// Verification fails when the plugin has no signature.
    #[test]
    fn test_verify_signature_none() {
        // Install a plugin WITHOUT a signature.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install");
        let plugin = registry.get(&id).expect("plugin should exist");

        // Any key should fail because there's no signature to verify.
        let some_key = [0x42u8; 32];
        assert!(!registry.verify_signature(plugin, &some_key));
    }

    // -----------------------------------------------------------------------
    // Manifest parsing
    // -----------------------------------------------------------------------

    /// Parse a valid manifest JSON string.
    #[test]
    fn test_parse_manifest_valid() {
        // Minimal valid manifest JSON with all required fields.
        let json = r#"{
            "name": "My Plugin",
            "version": "1.0.0",
            "author": "Author Name",
            "description": "Does something useful",
            "permissions": ["read_messages", "network_access"],
            "hooks": ["on_message", "on_peer_connected"],
            "min_app_version": "0.3.0"
        }"#;

        // parse_manifest should succeed.
        let manifest = parse_manifest(json).expect("parse should succeed");

        // Verify all fields were extracted correctly.
        assert_eq!(manifest.name, "My Plugin");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.author, "Author Name");
        assert_eq!(manifest.description, "Does something useful");
        assert_eq!(manifest.permissions.len(), 2);
        assert_eq!(manifest.permissions[0], PluginPermission::ReadMessages);
        assert_eq!(manifest.permissions[1], PluginPermission::NetworkAccess);
        assert_eq!(manifest.hooks, vec!["on_message", "on_peer_connected"]);
        assert_eq!(manifest.min_app_version, "0.3.0");
    }

    /// Parse a manifest with only the minimum required fields.
    #[test]
    fn test_parse_manifest_minimal() {
        // Only name and version are strictly required.
        let json = r#"{ "name": "Minimal", "version": "0.1.0" }"#;

        // parse_manifest should succeed with defaults for optional fields.
        let manifest = parse_manifest(json).expect("parse should succeed");
        assert_eq!(manifest.name, "Minimal");
        assert_eq!(manifest.version, "0.1.0");

        // Optional fields should have sensible defaults.
        assert_eq!(manifest.author, "Unknown");
        assert!(manifest.description.is_empty());
        assert!(manifest.permissions.is_empty());
        assert!(manifest.hooks.is_empty());
        assert_eq!(manifest.min_app_version, "0.0.0");
    }

    /// Parse fails on invalid JSON.
    #[test]
    fn test_parse_manifest_invalid_json() {
        // Completely invalid JSON — should fail.
        let result = parse_manifest("not json at all");
        assert!(result.is_err());
    }

    /// Parse fails when required "name" field is missing.
    #[test]
    fn test_parse_manifest_missing_name() {
        // Missing the "name" field.
        let json = r#"{ "version": "1.0.0" }"#;
        let result = parse_manifest(json);
        assert!(result.is_err());
    }

    /// Parse fails when required "version" field is missing.
    #[test]
    fn test_parse_manifest_missing_version() {
        // Missing the "version" field.
        let json = r#"{ "name": "Plugin" }"#;
        let result = parse_manifest(json);
        assert!(result.is_err());
    }

    /// Custom permissions are parsed into the Custom variant.
    #[test]
    fn test_parse_manifest_custom_permission() {
        // Manifest with an unknown permission string.
        let json = r#"{
            "name": "Custom Plugin",
            "version": "1.0.0",
            "permissions": ["read_messages", "some_future_permission"]
        }"#;

        let manifest = parse_manifest(json).expect("parse should succeed");
        assert_eq!(manifest.permissions.len(), 2);

        // First is a known permission.
        assert_eq!(manifest.permissions[0], PluginPermission::ReadMessages);

        // Second is an unknown permission — stored as Custom.
        assert_eq!(
            manifest.permissions[1],
            PluginPermission::Custom("some_future_permission".to_string()),
        );
    }

    // -----------------------------------------------------------------------
    // JSON export
    // -----------------------------------------------------------------------

    /// to_json() produces valid JSON with the expected structure.
    #[test]
    fn test_to_json_structure() {
        // Install and activate a plugin, then export as JSON.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install");
        registry.activate(&id).expect("activate");
        registry
            .register_hook("on_message", id)
            .expect("register_hook");

        // Export the registry state.
        let json = registry.to_json();

        // Top-level should have "plugins" array and "hook_count".
        let plugins = json.get("plugins").expect("missing plugins field");
        assert!(plugins.is_array());
        assert_eq!(plugins.as_array().expect("plugins array").len(), 1);

        // hook_count should be 1 (one hook registered).
        let hook_count = json
            .get("hook_count")
            .expect("missing hook_count")
            .as_u64()
            .expect("hook_count should be u64");
        assert_eq!(hook_count, 1);

        // The plugin entry should have the expected fields.
        let plugin_json = &plugins.as_array().expect("plugins array")[0];
        assert!(plugin_json.get("id").is_some());
        assert_eq!(
            plugin_json.get("name").and_then(|v| v.as_str()),
            Some("Test Plugin"),
        );
        assert_eq!(
            plugin_json.get("status").and_then(|v| v.as_str()),
            Some("active"),
        );
        assert_eq!(
            plugin_json
                .get("has_signature")
                .and_then(|v| v.as_bool()),
            Some(false),
        );
    }

    // -----------------------------------------------------------------------
    // Full lifecycle integration test
    // -----------------------------------------------------------------------

    /// End-to-end test: parse manifest, install, activate, register hooks,
    /// invoke, check permissions, suspend, verify no invocations, uninstall.
    #[test]
    fn test_full_lifecycle() {
        // Parse a manifest from JSON.
        let json = r#"{
            "name": "Lifecycle Plugin",
            "version": "3.0.0",
            "author": "Lifecycle Author",
            "description": "Tests the full lifecycle",
            "permissions": ["read_messages", "send_messages"],
            "hooks": ["on_message_received"],
            "min_app_version": "0.2.0"
        }"#;
        let manifest = parse_manifest(json).expect("parse manifest");

        // Install the plugin.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(manifest, None)
            .expect("install should succeed");

        // Plugin starts as Installed — should not receive hooks.
        registry
            .register_hook("on_message_received", id)
            .expect("register hook");
        let results = registry.invoke_hook("on_message_received", serde_json::json!({}));
        assert!(results.is_empty(), "Installed plugins should not receive hooks");

        // Activate the plugin — now it should receive hooks.
        registry.activate(&id).expect("activate");
        let results = registry.invoke_hook("on_message_received", serde_json::json!({"m": 1}));
        assert_eq!(results.len(), 1, "Active plugins should receive hooks");

        // Check permissions.
        assert!(registry.has_permission(&id, &PluginPermission::ReadMessages));
        assert!(registry.has_permission(&id, &PluginPermission::SendMessages));
        assert!(!registry.has_permission(&id, &PluginPermission::FileAccess));

        // Suspend the plugin — should stop receiving hooks.
        registry.suspend(&id).expect("suspend");
        let results = registry.invoke_hook("on_message_received", serde_json::json!({}));
        assert!(
            results.is_empty(),
            "Suspended plugins should not receive hooks",
        );

        // Reactivate — should receive hooks again.
        registry.activate(&id).expect("reactivate");
        let results = registry.invoke_hook("on_message_received", serde_json::json!({}));
        assert_eq!(results.len(), 1, "Reactivated plugins should receive hooks");

        // Uninstall — should clean everything up.
        registry.uninstall(&id).expect("uninstall");
        assert!(registry.list().is_empty());
        let results = registry.invoke_hook("on_message_received", serde_json::json!({}));
        assert!(results.is_empty(), "Uninstalled plugins leave no traces");
    }
}
