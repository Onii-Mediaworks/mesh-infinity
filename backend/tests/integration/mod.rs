// backend/tests/integration/mod.rs — Integration test harness (§21.1.2)
//
// # What are integration tests?
//
// Integration tests differ from unit tests in scope.  A unit test tests one
// function in isolation, often with mock inputs.  An integration test exercises
// a complete, realistic flow across multiple modules working together.
//
// The spec (§21.1.2) requires these flows:
//   - Identity lifecycle: create → save → close → reload → verify peer ID
//   - Message send/receive: room → send → poll → verify event
//   - Trust lifecycle: pair → attest → poll → verify TrustUpdated event
//   - Vault persistence: create identity → write → reload → verify intact
//   - Event queue: verify no events lost; verify empty-poll returns []
//   - Transport flag toggle: toggle → verify SettingsUpdated event
//   - PIN change: no-PIN → set PIN → wrong PIN reject → correct PIN accept
//
// # How Cargo discovers these tests
//
// Cargo's test harness automatically runs files under `tests/` as integration
// tests.  The `mod` declarations below wire up each test sub-module.  Each
// sub-module uses `#[test]` functions just like unit tests, but with access
// to the full public API of the crate.
//
// # Running the integration tests
//
//   cargo test --test integration     # run only this file's tests
//   cargo test                         # run all tests including these
//   make quality                       # runs via `cargo test --lib` + integration

/// Identity lifecycle tests: create, persist, reload, PIN lock/unlock.
pub mod identity_lifecycle;

/// Message flow tests: in-process pair → send → verify receipt.
pub mod message_flow;

/// Vault persistence tests: write entry, reload runtime, verify entry survives.
pub mod vault;
