// backend/tests/simulation/action_sequence.rs — shared simulator action model
//
// These tests give the stateful-fuzz action decoder and runner an integration
// foothold alongside the `fuzz_network_sim_actions` harness.

use mesh_infinity::testing::invariants::assert_no_panic_on_bytes;
use mesh_infinity::testing::sim::{
    decode_action_sequence, run_action_sequence, run_decoded_action_sequence, SimulatorAction,
};

// ---------------------------------------------------------------------------
// Action decoder safety
// ---------------------------------------------------------------------------

/// Arbitrary bytes must never make the shared action decoder panic.
///
/// This is a minimal but real invariant check for the simulator-fuzz surface.
/// The decoder itself is held to the "no panic on attacker-controlled input"
/// rule before the action runner sees the decoded sequence.
#[test]
fn decode_action_sequence_never_panics() {
    assert_no_panic_on_bytes("decode_action_sequence", b"\x00\xff\x10\x80", |data| {
        decode_action_sequence(data, 16)
    });
}

// ---------------------------------------------------------------------------
// Action decoder bounds
// ---------------------------------------------------------------------------

/// The decoded action sequence must respect the supplied maximum length.
#[test]
fn decode_action_sequence_honors_bound() {
    let actions = decode_action_sequence(&[255; 64], 8);
    assert!(
        actions.len() <= 8,
        "decoded action count must never exceed the configured bound"
    );
}

/// The decoder should map arbitrary bytes onto the documented action enum.
#[test]
fn decode_action_sequence_produces_known_actions() {
    let actions = decode_action_sequence(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 10);
    assert!(
        actions.iter().all(|action| matches!(
            action,
            SimulatorAction::CreateNode
                | SimulatorAction::PairNodes
                | SimulatorAction::SendMessage
                | SimulatorAction::DropPacket
                | SimulatorAction::DuplicatePacket
                | SimulatorAction::DelayPacket
                | SimulatorAction::PartitionLink
                | SimulatorAction::RestoreLink
                | SimulatorAction::AdvanceTime
                | SimulatorAction::RotateKey
                | SimulatorAction::DisavowPeer
                | SimulatorAction::TriggerKillswitch
                | SimulatorAction::RestartNode
                | SimulatorAction::ReloadVault
                | SimulatorAction::ToggleTransport
        )),
        "decoded actions must remain within the documented action vocabulary"
    );
}

// ---------------------------------------------------------------------------
// Stateful action execution
// ---------------------------------------------------------------------------

/// Decoded simulator actions should execute as a real bounded scenario.
#[test]
fn run_action_sequence_executes_stateful_scenario() {
    let report = run_action_sequence(&[
        SimulatorAction::CreateNode,
        SimulatorAction::CreateNode,
        SimulatorAction::PairNodes,
        SimulatorAction::SendMessage,
        SimulatorAction::DropPacket,
        SimulatorAction::RestoreLink,
        SimulatorAction::DuplicatePacket,
        SimulatorAction::AdvanceTime,
    ]);

    assert_eq!(report.executed_actions, 8);
    assert_eq!(report.node_count, 2);
    assert!(
        report.delivered_packets >= 1,
        "stateful action run should exercise packet delivery"
    );
    assert!(
        report.dropped_packets >= 1,
        "stateful action run should exercise packet dropping"
    );
    assert!(
        report.current_tick >= 1,
        "actions must advance simulation time"
    );
}

/// Arbitrary bytes should drive the stateful simulator without panicking.
#[test]
fn run_decoded_action_sequence_never_panics() {
    assert_no_panic_on_bytes(
        "run_decoded_action_sequence",
        b"\x0f\x00\x01\x02\xff",
        |data| run_decoded_action_sequence(data, 16),
    );
}
