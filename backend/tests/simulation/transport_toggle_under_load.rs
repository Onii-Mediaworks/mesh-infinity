// backend/tests/simulation/transport_toggle_under_load.rs
//
// Transport toggle under load (§5.10, §5.26)
//
// ToggleTransport simulates disabling a transport layer (e.g. the obfuscation
// carrier or a physical transport type) while packets are in flight.  The key
// invariants:
//
//   1. Packets already in the in-flight queue when transport is toggled off
//      continue to be delivered at their scheduled tick.  The toggle affects
//      future enqueues, not already-admitted packets.
//
//   2. Sends issued while transport is disabled are dropped.
//
//   3. After transport is re-enabled (re-toggled), new sends deliver normally.
//
// These properties mirror the real carrier-ladder contract: a carrier that
// goes dormant does not cancel packets it already accepted.

use mesh_infinity::testing::sim::{run_action_sequence, SimulatorAction};
use mesh_infinity::testing::simulator::NetworkSimulator;

// ---------------------------------------------------------------------------
// Scenario 1: in-flight packets survive transport toggle
// ---------------------------------------------------------------------------

/// A packet already in the simulator's in-flight queue when a partition is
/// applied must be delivered when its latency timer expires.
///
/// The partition (which models "transport disabled") only blocks new packets
/// from entering the queue.
#[test]
fn in_flight_packets_survive_transport_disable() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("src");
    sim.add_node("dst");
    // latency=2: packet is admitted on tick 1 with deliver_at=0+2=2.
    // The delivery check `deliver_at <= current_tick` fires at the start of
    // tick 3 (when current_tick=2, before the increment to 3).
    sim.add_link("src", "dst", 2, 0.0);

    // Enqueue at tick 0 — delivered at the start of tick 3 (current_tick=2).
    sim.send("src", "dst", b"in-flight-before-disable".to_vec());
    sim.tick(); // tick 1 (current_tick 0→1): outbox drains; packet in-flight, deliver_at=2

    // Disable transport (partition the link after the packet is already in flight).
    sim.partition("src", "dst");

    sim.tick(); // tick 2 (current_tick 1→2): 2<=1? No — not yet delivered
    sim.tick(); // tick 3 (current_tick 2→3): 2<=2? Yes — delivered

    assert_eq!(
        sim.node("dst").expect("dst must exist").inbox.len(),
        1,
        "packet queued before transport was disabled must still be delivered"
    );
    assert_eq!(
        sim.node("dst").expect("dst must exist").inbox[0],
        b"in-flight-before-disable"
    );

    // A packet sent while transport is off must be dropped.
    sim.send("src", "dst", b"while-disabled".to_vec());
    sim.tick();

    assert_eq!(
        sim.node("dst").expect("dst must exist").inbox.len(),
        1,
        "packet sent while transport is disabled must not be delivered"
    );
    assert_eq!(
        sim.dropped_packets,
        1,
        "send while transport is disabled must be counted as dropped"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: re-enabling transport resumes delivery
// ---------------------------------------------------------------------------

/// After transport is re-enabled (partition restored), new sends must succeed.
/// The resume must be clean: no duplicates or stale state from the disabled
/// period.
#[test]
fn re_enabling_transport_resumes_delivery() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("a");
    sim.add_node("b");
    sim.add_link("a", "b", 0, 0.0);

    // Disable transport.
    sim.partition("a", "b");
    sim.send("a", "b", b"dropped".to_vec());
    sim.tick();
    assert!(
        sim.node("b").unwrap().inbox.is_empty(),
        "send while disabled must not deliver"
    );

    // Re-enable transport.
    sim.restore("a", "b");
    sim.send("a", "b", b"restored-delivery".to_vec());
    sim.tick();

    let b = sim.node("b").expect("b must exist");
    assert_eq!(b.inbox.len(), 1, "delivery must resume after transport is re-enabled");
    assert_eq!(b.inbox[0], b"restored-delivery");
}

// ---------------------------------------------------------------------------
// Scenario 3: toggle under load via action runner
// ---------------------------------------------------------------------------

/// The stateful action runner must handle repeated ToggleTransport cycles,
/// including mid-flight packets, without panicking or violating invariants.
#[test]
fn toggle_transport_via_action_runner_is_stable() {
    // Sequence: deliver pre-toggle, disable, attempt (dropped), re-enable, deliver.
    let report = run_action_sequence(&[
        SimulatorAction::CreateNode,
        SimulatorAction::CreateNode,
        SimulatorAction::PairNodes,
        SimulatorAction::SendMessage,      // delivers (transport enabled)
        SimulatorAction::ToggleTransport,  // transport off
        SimulatorAction::SendMessage,      // dropped (transport off)
        SimulatorAction::ToggleTransport,  // transport on
        SimulatorAction::SendMessage,      // delivers (transport re-enabled)
        SimulatorAction::AdvanceTime,
    ]);

    assert_eq!(report.executed_actions, 9);
    // At least the pre-toggle and post-restore sends should have delivered.
    assert!(
        report.delivered_packets >= 1,
        "at least one packet must be delivered in the toggle cycle"
    );
    assert!(report.current_tick >= 1);
}

// ---------------------------------------------------------------------------
// Scenario 4: multiple toggle cycles are stable
// ---------------------------------------------------------------------------

/// Repeated enable/disable cycles must not accumulate dropped counter errors
/// or violate invariants.  The simulation must stay consistent after N cycles.
#[test]
fn multiple_toggle_cycles_are_stable() {
    let report = run_action_sequence(&[
        SimulatorAction::CreateNode,
        SimulatorAction::CreateNode,
        SimulatorAction::PairNodes,
        SimulatorAction::SendMessage,
        SimulatorAction::ToggleTransport,
        SimulatorAction::ToggleTransport,
        SimulatorAction::SendMessage,
        SimulatorAction::ToggleTransport,
        SimulatorAction::ToggleTransport,
        SimulatorAction::SendMessage,
        SimulatorAction::AdvanceTime,
    ]);

    assert_eq!(report.executed_actions, 11);
    assert!(
        report.current_tick >= 1,
        "multi-cycle toggle sequence must advance simulation time"
    );
}
