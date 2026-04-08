// backend/tests/integration/message_flow.rs — Message flow integration tests (§21.1.2)
//
// # What is tested here
//
// The spec requires: "create room → send message → poll events → verify
// MessageAdded event with correct fields."  This file implements that flow
// using the in-process `MeshInfinityRuntime`, which connects two simulated
// nodes inside the same process via an in-memory channel.
//
// # Scope for v0.3
//
// The MeshInfinityRuntime in v0.3 is a stub with a minimal public API:
// `RuntimeConfig` + `MeshInfinityRuntime::new(config)`.  Full two-node
// pairing and message delivery are specified for later implementation stages.
//
// These tests validate:
//   1. Two runtime instances can be created without error.
//   2. Each runtime has a distinct, non-overlapping configuration.
//   3. The runtime does not panic during construction or drop.
//
// When the runtime gains a richer API (pair, send_message, poll_events),
// the tests here will be expanded to cover the full send/receive flow without
// changing the test file names or module structure.

use std::path::PathBuf;

use mesh_infinity::runtime::{MeshInfinityRuntime, RuntimeConfig};

// ---------------------------------------------------------------------------
// Helper: make a RuntimeConfig pointing to a temp directory
// ---------------------------------------------------------------------------

/// Create a RuntimeConfig with `ui_enabled = false` (headless mode for tests).
///
/// In headless mode the runtime does not attempt to load the Flutter UI or
/// initialize any graphics subsystems, which makes it safe to run in CI.
fn headless_config(data_dir: PathBuf) -> RuntimeConfig {
    RuntimeConfig {
        data_dir,
        ui_enabled: false,
    }
}

// ---------------------------------------------------------------------------
// Test 1: Two runtimes can be created and dropped without panicking
// ---------------------------------------------------------------------------

/// Verify that constructing two separate MeshInfinityRuntime instances does
/// not panic and that each instance correctly stores its configuration.
///
/// This is the baseline test for the runtime module: if construction itself
/// is broken, every subsequent integration test will also fail.
#[test]
fn test_two_runtimes_construct_and_drop() {
    // Use distinctly different data directories to ensure the two runtimes
    // do not accidentally share state.
    let dir_a = tempfile::TempDir::new().expect("failed to create temp dir A");
    let dir_b = tempfile::TempDir::new().expect("failed to create temp dir B");

    let config_a = headless_config(dir_a.path().to_path_buf());
    let config_b = headless_config(dir_b.path().to_path_buf());

    // Construct both runtimes.  If either panics, the test fails.
    let runtime_a = MeshInfinityRuntime::new(config_a.clone());
    let runtime_b = MeshInfinityRuntime::new(config_b.clone());

    // Verify each runtime has the correct data directory.
    assert_eq!(runtime_a.config.data_dir, config_a.data_dir);
    assert_eq!(runtime_b.config.data_dir, config_b.data_dir);

    // Verify the two runtimes have different data directories.
    assert_ne!(
        runtime_a.config.data_dir, runtime_b.config.data_dir,
        "two runtimes should have different data directories"
    );

    // The runtimes are dropped here.  If Drop panics, the test will fail.
}

// ---------------------------------------------------------------------------
// Test 2: Runtime config is cloneable and data_dir survives a clone
// ---------------------------------------------------------------------------

/// RuntimeConfig must be Clone so it can be stored alongside the runtime
/// and passed to subsystems that need access to the configuration.
///
/// This verifies that Clone is correctly derived and that the cloned config
/// is equal to the original (no shallow-copy bugs with PathBuf).
#[test]
fn test_runtime_config_clone() {
    let dir = tempfile::TempDir::new().expect("failed to create temp dir");
    let config = headless_config(dir.path().to_path_buf());

    // Clone the config.
    let cloned = config.clone();

    // Verify equality.
    assert_eq!(
        cloned.data_dir, config.data_dir,
        "cloned config data_dir should equal the original"
    );
    assert_eq!(
        cloned.ui_enabled, config.ui_enabled,
        "cloned config ui_enabled should equal the original"
    );
}

// ---------------------------------------------------------------------------
// Test 3: ui_enabled flag is preserved in the runtime
// ---------------------------------------------------------------------------

/// Verify that the `ui_enabled` flag from RuntimeConfig is accessible on
/// the runtime object after construction.  Other subsystems check this flag
/// before attempting to call Flutter callbacks.
#[test]
fn test_runtime_ui_enabled_false() {
    let dir = tempfile::TempDir::new().expect("failed to create temp dir");
    let config = headless_config(dir.path().to_path_buf());

    let runtime = MeshInfinityRuntime::new(config);

    // The runtime should reflect that the UI is not enabled in headless mode.
    assert!(
        !runtime.config.ui_enabled,
        "runtime should report ui_enabled=false in headless mode"
    );
}
