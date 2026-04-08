// tests/integration.rs — Cargo integration test entry point (§21.1.2)
//
// # What is this file?
//
// Cargo's integration test runner looks for files directly in the `tests/`
// directory (one level below the crate root, alongside `src/` and `backend/`).
// Each file in `tests/` becomes a separate test binary.  Sub-modules are
// declared with `mod` and live in `tests/<filename>/` subdirectories.
//
// This file is the entry point for the full integration test suite.  It pulls
// in sub-modules from `backend/tests/integration/`, which are organized by
// subsystem (identity, messaging, vault).
//
// # Running
//
//   cargo test --test integration          # runs only this suite
//   cargo test                              # runs all tests (unit + integration)
//   make quality                            # CI target: includes integration run
//
// # Why `#[path]` instead of a normal mod path?
//
// Cargo integration tests look for sub-modules in `tests/<entry_stem>/`.  That
// would put the modules in `tests/integration/`, but the spec and task
// description locate the implementation files under `backend/tests/integration/`.
// The `#[path]` attribute overrides the default path lookup, letting us store
// the implementation in the backend tree while using the standard Cargo entry
// point convention.

#[path = "../backend/tests/integration/identity_lifecycle.rs"]
mod identity_lifecycle;

#[path = "../backend/tests/integration/message_flow.rs"]
mod message_flow;

#[path = "../backend/tests/integration/vault.rs"]
mod vault;
