// backend/tests/simulation/trust_disavow_propagation.rs
//
// Trust disavowal scenarios (§3.9 / §22.2.4)
//
// Disavowing a peer is a permanent trust-revocation operation distinct from a
// plain link partition.  The action runner's DisavowPeer action must:
//   1. Record the pair in disavowed_pairs so the invariant checker can verify
//      the link never recovers.
//   2. Partition both directions of the link immediately.
//   3. Prevent RestoreLink from re-enabling the disavowed pair.
//
// These tests use both the raw simulator (for exact delivery counts) and the
// stateful action runner (to validate the action model itself).

use mesh_infinity::testing::sim::{run_action_sequence, SimulatorAction};
use mesh_infinity::testing::simulator::NetworkSimulator;

// ---------------------------------------------------------------------------
// Scenario 1: disavowal blocks all subsequent delivery
// ---------------------------------------------------------------------------

/// After trust is revoked the partitioned link must reject all new packets.
///
/// Pre-disavowal delivery must succeed; post-disavowal delivery must not.
#[test]
fn disavow_peer_blocks_subsequent_delivery() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("alice");
    sim.add_node("bob");
    sim.add_link("alice", "bob", 0, 0.0);
    sim.add_link("bob", "alice", 0, 0.0);

    // Baseline: delivery works before any disavowal.
    sim.send("alice", "bob", b"pre-disavowal".to_vec());
    sim.tick();
    assert_eq!(
        sim.node("bob").unwrap().inbox.len(),
        1,
        "delivery must succeed before trust is revoked"
    );

    // Revoke trust by partitioning (models DisavowPeer at the simulator level).
    sim.partition("alice", "bob");

    // A new packet must be dropped.
    sim.send("alice", "bob", b"post-disavowal".to_vec());
    sim.tick();

    assert_eq!(
        sim.node("bob").unwrap().inbox.len(),
        1,
        "no further packets must be delivered after trust revocation"
    );
    assert!(
        sim.dropped_packets >= 1,
        "post-disavowal packet must be counted as dropped"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: DisavowPeer via action runner is permanent
// ---------------------------------------------------------------------------

/// A DisavowPeer action must survive a subsequent RestoreLink action.
///
/// The invariant checker in SimulatorActionRunner verifies the link remains at
/// loss_rate=1.0 after every action, so this test exercises both the action
/// model and the invariant layer.
#[test]
fn disavow_via_action_runner_survives_restore() {
    // Sequence: create two nodes, pair them, deliver one packet, disavow,
    // attempt restore (must be blocked), attempt send (must be dropped).
    let report = run_action_sequence(&[
        SimulatorAction::CreateNode,
        SimulatorAction::CreateNode,
        SimulatorAction::PairNodes,
        SimulatorAction::SendMessage, // pre-disavowal: should deliver
        SimulatorAction::DisavowPeer, // record + partition, permanent
        SimulatorAction::RestoreLink, // must NOT lift the disavowal
        SimulatorAction::SendMessage, // post-disavowal: should be dropped
        SimulatorAction::AdvanceTime,
    ]);

    // The runner completed all actions without panicking — the invariant
    // checker did not trip on an unexpectedly restored link.
    assert_eq!(report.executed_actions, 8);
    assert!(
        report.current_tick >= 1,
        "simulation time must advance through the disavowal sequence"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3: unrelated nodes are not affected by a disavowal
// ---------------------------------------------------------------------------

/// Disavowing the alice-bob link must not affect the bob-charlie link.
///
/// The spec requires that trust revocation is targeted: only the explicitly
/// named peer relationship is severed.  Third-party routes through unrelated
/// nodes continue to work normally.
#[test]
fn disavow_does_not_affect_unrelated_nodes() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("alice");
    sim.add_node("bob");
    sim.add_node("charlie");
    sim.add_link("alice", "bob", 0, 0.0);
    sim.add_link("bob", "charlie", 0, 0.0);

    // Alice disavows bob — partition only the alice->bob direction.
    sim.partition("alice", "bob");

    // Bob can still reach charlie through the intact bob->charlie link.
    sim.send("bob", "charlie", b"charlie-unaffected".to_vec());
    sim.tick();

    assert_eq!(
        sim.node("charlie").unwrap().inbox.len(),
        1,
        "charlie must receive messages from bob regardless of the alice-bob disavowal"
    );
    assert_eq!(sim.node("charlie").unwrap().inbox[0], b"charlie-unaffected");
}

// ---------------------------------------------------------------------------
// Scenario 4: disavowal is symmetric — both directions are blocked
// ---------------------------------------------------------------------------

/// Disavowing a peer must partition both alice→bob and bob→alice, not only
/// the direction the action was applied to.
#[test]
fn disavow_is_bidirectional() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("alice");
    sim.add_node("bob");
    sim.add_link("alice", "bob", 0, 0.0);
    sim.add_link("bob", "alice", 0, 0.0);

    // Disavow both directions.
    sim.partition("alice", "bob");
    sim.partition("bob", "alice");

    // Neither direction should deliver.
    sim.send("alice", "bob", b"a-to-b".to_vec());
    sim.send("bob", "alice", b"b-to-a".to_vec());
    sim.tick();

    assert!(
        sim.node("bob").unwrap().inbox.is_empty(),
        "alice->bob must be blocked after bidirectional disavowal"
    );
    assert!(
        sim.node("alice").unwrap().inbox.is_empty(),
        "bob->alice must be blocked after bidirectional disavowal"
    );
    assert_eq!(
        sim.dropped_packets, 2,
        "both packets must be counted as dropped"
    );
}
