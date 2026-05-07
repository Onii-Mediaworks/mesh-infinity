// backend/tests/simulation/scenarios.rs — Integration-style simulator scenarios
//
// These tests cover the concrete scenario expectations called out by the spec:
// basic two-node delivery, relayed delivery through an intermediate node, and
// link partition / restore behavior.

use mesh_infinity::testing::simulator::NetworkSimulator;

// ---------------------------------------------------------------------------
// Scenario 1: two-node hello
// ---------------------------------------------------------------------------

/// Two directly connected nodes must exchange one packet successfully.
///
/// This is the lowest-level network-simulation smoke test. If this fails, the
/// simulator cannot support any more complex topology or transport scenario.
#[test]
fn two_node_hello_delivers_one_packet() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("alice");
    sim.add_node("bob");
    sim.add_link("alice", "bob", 0, 0.0);

    sim.send("alice", "bob", b"hello".to_vec());
    sim.tick();

    let bob = sim.node("bob").expect("bob must exist");
    assert_eq!(bob.inbox.len(), 1, "bob should receive one packet");
    assert_eq!(bob.inbox[0], b"hello");
    assert_eq!(sim.delivered_packets, 1);
    assert_eq!(sim.dropped_packets, 0);
}

// ---------------------------------------------------------------------------
// Scenario 2: three-node relay
// ---------------------------------------------------------------------------

/// A packet can reach C from A through B even when there is no direct A->C link.
///
/// The simulator does not implement automatic routing logic. We model the relay
/// step explicitly by having B forward the packet after it receives it.
#[test]
fn three_node_relay_reaches_destination() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("alice");
    sim.add_node("relay");
    sim.add_node("charlie");

    sim.add_link("alice", "relay", 0, 0.0);
    sim.add_link("relay", "charlie", 0, 0.0);

    sim.send("alice", "relay", b"relay-payload".to_vec());
    sim.tick();

    let relay_packet = sim
        .node("relay")
        .expect("relay must exist")
        .inbox
        .first()
        .expect("relay must receive the first hop")
        .clone();

    sim.send("relay", "charlie", relay_packet);
    sim.tick();

    let charlie = sim.node("charlie").expect("charlie must exist");
    assert_eq!(
        charlie.inbox.len(),
        1,
        "charlie should receive the relayed packet"
    );
    assert_eq!(charlie.inbox[0], b"relay-payload");
}

// ---------------------------------------------------------------------------
// Scenario 3: partition / restore
// ---------------------------------------------------------------------------

/// A partitioned link must drop packets until the link is restored.
///
/// This gives the repo a concrete integration-style recovery scenario under the
/// `backend/tests/simulation/` tree required by the spec.
#[test]
fn partition_then_restore_changes_delivery_outcome() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("a");
    sim.add_node("b");
    sim.add_link("a", "b", 0, 0.0);

    sim.partition("a", "b");
    sim.send("a", "b", b"dropped-during-partition".to_vec());
    sim.tick();

    let b = sim.node("b").expect("b must exist");
    assert!(
        b.inbox.is_empty(),
        "partitioned link must not deliver packets"
    );
    assert_eq!(sim.dropped_packets, 1);

    sim.restore("a", "b");
    sim.send("a", "b", b"delivered-after-restore".to_vec());
    sim.tick();

    let b = sim.node("b").expect("b must exist");
    assert_eq!(b.inbox.len(), 1, "restored link must deliver again");
    assert_eq!(b.inbox[0], b"delivered-after-restore");
}
