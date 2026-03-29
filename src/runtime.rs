//! Mesh Infinity runtime — top-level application lifecycle.
//!
//! Manages the three-layer identity initialization sequence (§3.1.4),
//! module system (§17.13), and the event loop.

/// Runtime configuration.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Data directory for vault storage
    pub data_dir: std::path::PathBuf,
    /// Whether the Flutter UI is attached
    pub ui_enabled: bool,
}

/// The top-level runtime. Owns all subsystems.
pub struct MeshInfinityRuntime {
    pub config: RuntimeConfig,
}

impl MeshInfinityRuntime {
    /// Create a new runtime with the given configuration.
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }
}
