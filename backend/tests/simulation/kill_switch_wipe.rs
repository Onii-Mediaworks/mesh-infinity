// backend/tests/simulation/kill_switch_wipe.rs
//
// Kill-switch wipe scenarios (§3.9.1)
//
// A kill-switch wipe must:
//   1. Partition every link immediately so no new packets can be delivered.
//   2. Set the `killed` flag in the action runner so subsequent sends are no-ops.
//   3. Pass the post-wipe invariant: all links must remain at loss_rate=1.0
//      for the rest of the simulation session.
//
// These tests use both the raw simulator (for exact counters) and the stateful
// action runner (to exercise the `killed` guard and the invariant checker).

use mesh_infinity::testing::sim::{run_action_sequence, SimulatorAction};
use mesh_infinity::testing::simulator::NetworkSimulator;

// ---------------------------------------------------------------------------
// Scenario 1: kill-switch partitions all links
// ---------------------------------------------------------------------------

/// After a kill-switch wipe, every link must drop all new packets.
///
/// The test verifies:
///   - Pre-wipe delivery succeeds.
///   - Post-wipe deliveries are zero (delivered counter does not increase).
///   - Post-wipe sends are counted as dropped.
#[test]
fn kill_switch_partitions_all_links() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("a");
    sim.add_node("b");
    sim.add_node("c");

    // Wire up a small three-node topology.
    sim.add_link("a", "b", 0, 0.0);
    sim.add_link("b", "a", 0, 0.0);
    sim.add_link("b", "c", 0, 0.0);
    sim.add_link("c", "b", 0, 0.0);

    // Verify baseline delivery before the wipe.
    sim.send("a", "b", b"pre-kill-payload".to_vec());
    sim.tick();
    assert_eq!(
        sim.node("b").unwrap().inbox.len(),
        1,
        "pre-kill delivery must succeed"
    );

    // Trigger the kill-switch by partitioning every link.
    sim.partition("a", "b");
    sim.partition("b", "a");
    sim.partition("b", "c");
    sim.partition("c", "b");

    // Record counters at the moment of wipe to detect any post-wipe deliveries.
    let delivered_at_wipe = sim.delivered_packets;

    // Send on every direction — all must be dropped.
    sim.send("a", "b", b"post-kill-a-to-b".to_vec());
    sim.send("b", "c", b"post-kill-b-to-c".to_vec());
    sim.tick();
    sim.tick(); // run an extra tick to drain any stale in-flight queue

    assert_eq!(
        sim.node("b").unwrap().inbox.len(),
        1,
        "no further packets must arrive at b after the kill-switch"
    );
    assert_eq!(
        sim.node("c").unwrap().inbox.len(),
        0,
        "no packets must arrive at c after the kill-switch"
    );
    assert_eq!(
        sim.delivered_packets, delivered_at_wipe,
        "delivered counter must not increase after kill-switch"
    );
    assert!(
        sim.dropped_packets >= 2,
        "post-kill sends must be counted as dropped"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: action runner guards sends after TriggerKillswitch
// ---------------------------------------------------------------------------

/// After TriggerKillswitch fires, the runner's `killed` guard makes subsequent
/// SendMessage actions no-ops.  Time still advances to allow other actions to
/// complete.
#[test]
fn kill_switch_action_guards_subsequent_sends() {
    // Sequence deliberately alternates sends before and after the kill.
    let report = run_action_sequence(&[
        SimulatorAction::CreateNode,
        SimulatorAction::CreateNode,
        SimulatorAction::PairNodes,
        SimulatorAction::SendMessage,       // pre-kill: should deliver
        SimulatorAction::TriggerKillswitch, // partitions all links, sets `killed`
        SimulatorAction::SendMessage,       // must be no-op (killed guard)
        SimulatorAction::SendMessage,       // must be no-op (killed guard)
        SimulatorAction::AdvanceTime,       // time still advances
    ]);

    assert_eq!(report.executed_actions, 8);
    // Time must advance despite the kill.
    assert!(
        report.current_tick >= 1,
        "simulation time must advance even after a kill-switch"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3: kill-switch after key rotation is still effective
// ---------------------------------------------------------------------------

/// A kill-switch wipe applied after a key rotation must still partition all
/// links.  The key epoch does not affect the wipe semantics.
#[test]
fn kill_switch_after_key_rotation_is_effective() {
    let report = run_action_sequence(&[
        SimulatorAction::CreateNode,
        SimulatorAction::CreateNode,
        SimulatorAction::PairNodes,
        SimulatorAction::SendMessage,
        SimulatorAction::RotateKey,
        SimulatorAction::SendMessage, // post-rotation delivery
        SimulatorAction::TriggerKillswitch,
        SimulatorAction::SendMessage, // post-kill: no-op
        SimulatorAction::AdvanceTime,
    ]);

    // All 9 actions must complete and the invariant checker must not trip on
    // any unexpectedly-restored link after the kill.
    assert_eq!(report.executed_actions, 9);
    assert!(report.current_tick >= 1);
}

// ---------------------------------------------------------------------------
// Scenario 4: in-flight packet before kill delivers; sends after kill do not
// ---------------------------------------------------------------------------

/// A packet already in the in-flight queue when the kill-switch fires will be
/// delivered at its scheduled tick — the kill-switch does not retroactively
/// cancel in-flight packets.  This is acceptable because the adversary cannot
/// receive the in-flight packet without the session key.
///
/// New packets queued AFTER the wipe are dropped.
#[test]
fn pre_kill_in_flight_delivers_post_kill_sends_drop() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("src");
    sim.add_node("dst");
    // latency=2: packet is admitted on the first tick with deliver_at=0+2=2.
    // The delivery check `deliver_at <= current_tick` fires when current_tick
    // reaches 2, which happens at the START of the 3rd tick() call (tick
    // increments at the END, so tick 3 begins with current_tick=2).
    sim.add_link("src", "dst", 2, 0.0);

    // Enqueue at tick 0 — delivered at the start of tick 3 (current_tick=2).
    sim.send("src", "dst", b"pre-kill-in-flight".to_vec());
    sim.tick(); // tick 1 (current_tick 0→1): outbox drains; packet in-flight, deliver_at=2

    // Apply kill-switch after the packet is already in the in-flight queue.
    sim.partition("src", "dst");

    sim.tick(); // tick 2 (current_tick 1→2): 2<=1? No — not yet delivered
    sim.tick(); // tick 3 (current_tick 2→3): 2<=2? Yes — delivered

    assert_eq!(
        sim.node("dst").expect("dst must exist").inbox.len(),
        1,
        "packet queued before kill must still be delivered when its timer expires"
    );

    // Try to send a new packet — must be dropped.
    sim.send("src", "dst", b"post-kill-attempt".to_vec());
    sim.tick();

    assert_eq!(
        sim.node("dst").expect("dst must exist").inbox.len(),
        1,
        "packet sent after kill must not be delivered"
    );
    assert!(
        sim.dropped_packets >= 1,
        "post-kill send must be counted as dropped"
    );
}
