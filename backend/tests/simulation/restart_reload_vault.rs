// backend/tests/simulation/restart_reload_vault.rs
//
// Node restart and vault reload scenarios (§21.5.5)
//
// RestartNode replaces the node's in-memory state (inbox, outbox) while
// leaving the simulator's link map intact, modelling a process restart that
// loads a previously persisted vault.  ReloadVault models a configuration
// reload (an additional tick) that must not disrupt in-flight packets.
//
// Key invariants:
//   1. After restart, the node's inbox is empty (old state was wiped).
//   2. Links are preserved across restarts; new sends deliver immediately.
//   3. A vault-reload tick (sim.tick()) does not cancel in-flight packets.

use mesh_infinity::testing::sim::{run_action_sequence, SimulatorAction};
use mesh_infinity::testing::simulator::NetworkSimulator;

// ---------------------------------------------------------------------------
// Scenario 1: restarted node has empty state but receives new messages
// ---------------------------------------------------------------------------

/// After a node restart the inbox is empty (prior state wiped).  New messages
/// sent over the existing link must be delivered normally.
///
/// This models a process restart: the node identity is preserved (same ID),
/// the link topology is preserved, but the in-memory message state is gone.
#[test]
fn restarted_node_receives_post_restart_messages() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("alice");
    sim.add_node("bob");
    sim.add_link("alice", "bob", 0, 0.0);

    // Pre-restart: deliver one packet so bob's inbox has content.
    sim.send("alice", "bob", b"pre-restart".to_vec());
    sim.tick();
    assert_eq!(
        sim.node("bob").unwrap().inbox.len(),
        1,
        "pre-restart delivery must succeed"
    );

    // Restart bob: add_node replaces the existing node with an empty one.
    // The simulator's link map is unchanged — the alice->bob link still exists.
    sim.add_node("bob");

    // Post-restart: bob's inbox must be empty (state was wiped).
    assert_eq!(
        sim.node("bob").unwrap().inbox.len(),
        0,
        "restarted node must start with an empty inbox"
    );

    // New delivery over the unchanged link must work.
    sim.send("alice", "bob", b"post-restart".to_vec());
    sim.tick();

    let bob = sim.node("bob").expect("bob must exist after restart");
    assert_eq!(
        bob.inbox.len(),
        1,
        "restarted node must receive new messages over the preserved link"
    );
    assert_eq!(bob.inbox[0], b"post-restart");
}

// ---------------------------------------------------------------------------
// Scenario 2: vault reload does not disrupt in-flight packets
// ---------------------------------------------------------------------------

/// A vault reload (modelled as an extra tick) must not cancel or delay packets
/// that are already in the in-flight queue.
///
/// In the real runtime a vault reload re-reads keying material from disk but
/// does not close or reset active transport connections.  The simulator tick
/// is the closest model: time advances, in-flight packets continue to their
/// destination.
#[test]
fn vault_reload_does_not_disrupt_in_flight() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("a");
    sim.add_node("b");
    // latency=1: packet admitted on tick 1 with deliver_at=0+1=1.
    // The check `deliver_at <= current_tick` fires when current_tick=1, i.e.
    // at the start of tick 2 (current_tick increments at the END of each tick).
    sim.add_link("a", "b", 1, 0.0);

    // Enqueue at tick 0 — delivered at the start of tick 2 (current_tick=1).
    sim.send("a", "b", b"in-flight-during-reload".to_vec());
    sim.tick(); // tick 1 (current_tick 0→1): outbox drains; packet in-flight, deliver_at=1

    // Simulate a vault reload — just advance one tick (no state change in sim).
    sim.tick(); // tick 2 (current_tick 1→2): 1<=1? Yes — delivered

    let b = sim.node("b").expect("b must exist");
    assert_eq!(
        b.inbox.len(),
        1,
        "vault reload tick must not disrupt in-flight packet delivery"
    );
    assert_eq!(b.inbox[0], b"in-flight-during-reload");
}

// ---------------------------------------------------------------------------
// Scenario 3: restart and reload via action runner
// ---------------------------------------------------------------------------

/// The stateful action runner must handle RestartNode and ReloadVault without
/// panicking and must still satisfy all post-action invariants.
#[test]
fn restart_and_vault_reload_via_action_runner() {
    let report = run_action_sequence(&[
        SimulatorAction::CreateNode,
        SimulatorAction::CreateNode,
        SimulatorAction::PairNodes,
        SimulatorAction::SendMessage,
        SimulatorAction::RestartNode,
        SimulatorAction::ReloadVault,
        SimulatorAction::SendMessage,
        SimulatorAction::AdvanceTime,
    ]);

    assert_eq!(report.executed_actions, 8);
    assert!(
        report.current_tick >= 1,
        "time must advance through restart and vault reload actions"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: restart clears state but does not break disavowal
// ---------------------------------------------------------------------------

/// A node restart must not accidentally restore a previously disavowed link.
/// Trust revocation is permanent for the session regardless of restarts.
#[test]
fn restart_does_not_restore_disavowed_link() {
    let report = run_action_sequence(&[
        SimulatorAction::CreateNode,
        SimulatorAction::CreateNode,
        SimulatorAction::PairNodes,
        SimulatorAction::SendMessage,       // delivers
        SimulatorAction::DisavowPeer,       // permanent trust revocation
        SimulatorAction::RestartNode,       // must not lift disavowal
        SimulatorAction::SendMessage,       // still dropped (disavowal intact)
        SimulatorAction::AdvanceTime,
    ]);

    // The invariant checker in the action runner verifies the disavowed link
    // stays at loss_rate=1.0 after every action including RestartNode.
    // If this test completes without panic, the invariant held throughout.
    assert_eq!(report.executed_actions, 8);
    assert!(report.current_tick >= 1);
}

// ---------------------------------------------------------------------------
// Scenario 5: multiple restarts do not corrupt link topology
// ---------------------------------------------------------------------------

/// Repeated restart actions must leave the link topology intact and deliveries
/// must succeed between restarts once new messages are queued.
#[test]
fn multiple_restarts_do_not_corrupt_links() {
    let report = run_action_sequence(&[
        SimulatorAction::CreateNode,
        SimulatorAction::CreateNode,
        SimulatorAction::PairNodes,
        SimulatorAction::SendMessage,
        SimulatorAction::RestartNode,
        SimulatorAction::SendMessage,
        SimulatorAction::RestartNode,
        SimulatorAction::SendMessage,
        SimulatorAction::AdvanceTime,
    ]);

    assert_eq!(report.executed_actions, 9);
    assert!(
        report.current_tick >= 1,
        "repeated restart sequence must remain stable"
    );
}
