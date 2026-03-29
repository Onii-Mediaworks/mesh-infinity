// Integration tests for the Mesh Infinity crate.
// These tests exercise the public API surface across module boundaries.
#[cfg(test)]
mod tests {
    use mesh_infinity::runtime::{MeshInfinityRuntime, RuntimeConfig};

    #[test]
    fn test_runtime_creation() {
        let config = RuntimeConfig {
            data_dir: std::path::PathBuf::from("/tmp/mesh-infinity-test"),
            ui_enabled: false,
        };
        let runtime = MeshInfinityRuntime::new(config.clone());
        assert_eq!(runtime.config.data_dir, config.data_dir);
        assert!(!runtime.config.ui_enabled);
    }
}
