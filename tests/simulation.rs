// tests/simulation.rs — Cargo integration entry for simulator scenarios (§21.1.4)
//
// This suite exists because the spec requires multi-node in-process simulation
// coverage under `backend/tests/simulation/`, not only unit tests embedded
// inside the simulator module itself.
//
// The simulator implementation already lives in `backend/testing/simulator.rs`.
// These tests exercise it through the public crate surface as integration-style
// scenarios so future changes cannot silently break the expected higher-level
// topology and recovery behavior.

#[path = "../backend/tests/simulation/scenarios.rs"]
mod scenarios;

#[path = "../backend/tests/simulation/action_sequence.rs"]
mod action_sequence;

#[path = "../backend/tests/simulation/store_and_forward_delivery.rs"]
mod store_and_forward_delivery;

#[path = "../backend/tests/simulation/trust_disavow_propagation.rs"]
mod trust_disavow_propagation;

#[path = "../backend/tests/simulation/kill_switch_wipe.rs"]
mod kill_switch_wipe;

#[path = "../backend/tests/simulation/transport_toggle_under_load.rs"]
mod transport_toggle_under_load;

#[path = "../backend/tests/simulation/restart_reload_vault.rs"]
mod restart_reload_vault;
