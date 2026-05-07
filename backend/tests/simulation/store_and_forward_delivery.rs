// backend/tests/simulation/store_and_forward_delivery.rs
//
// Store-and-forward delivery scenarios (§21.5.4)
//
// The in-memory simulator schedules packets by delivery tick, not by link
// state at delivery time.  A packet queued with latency=N ticks before a
// partition is applied will still be delivered when tick N arrives — the
// partition only blocks packets queued AFTER it is applied.  These tests
// give that behaviour a concrete integration-level foothold.

use mesh_infinity::testing::simulator::NetworkSimulator;

// ---------------------------------------------------------------------------
// Scenario: in-flight packet survives a partition applied after enqueue
// ---------------------------------------------------------------------------

/// A packet queued with non-zero latency before a link is partitioned must be
/// delivered when its scheduled tick arrives.
///
/// Spec §5.28 requires that store-and-forward paths honour packets that were
/// already in the delivery pipeline when a disruption occurred.  The simulator
/// models this property: the in-flight queue is processed by scheduled tick,
/// independent of the link's current loss_rate.
#[test]
fn in_flight_packet_survives_partition() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("src");
    sim.add_node("dst");
    // latency=2 places the packet in-flight for 2 ticks before delivery.
    sim.add_link("src", "dst", 2, 0.0);

    // tick 0: send the packet — it enters the in-flight queue scheduled at tick 2.
    sim.send("src", "dst", b"store-and-forward".to_vec());
    sim.tick(); // tick 1: drains outbox; packet is now in-flight

    // Partition the link AFTER the packet has already entered the in-flight queue.
    // This models a network disruption that occurs after the packet departed the sender.
    sim.partition("src", "dst");

    sim.tick(); // tick 2: in-flight packet is due — must be delivered despite partition
    sim.tick(); // tick 3: confirm no further spurious delivery

    let dst = sim.node("dst").expect("dst must exist");
    assert_eq!(
        dst.inbox.len(),
        1,
        "packet enqueued before partition must still arrive from the in-flight queue"
    );
    assert_eq!(dst.inbox[0], b"store-and-forward");

    // A new packet sent after the partition is applied must be dropped immediately.
    sim.send("src", "dst", b"blocked-by-partition".to_vec());
    sim.tick();

    let dst = sim.node("dst").expect("dst must exist");
    assert_eq!(
        dst.inbox.len(),
        1,
        "packet sent after partition must not be delivered"
    );
    assert_eq!(
        sim.dropped_packets, 1,
        "post-partition send must be counted as a dropped packet"
    );
}

// ---------------------------------------------------------------------------
// Scenario: multiple in-flight packets with different latencies
// ---------------------------------------------------------------------------

/// With two packets enqueued before a partition — one with latency=1 and one
/// with latency=3 — both must be delivered at their respective ticks even
/// though the link is partitioned throughout.
#[test]
fn multiple_in_flight_packets_both_survive_partition() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("sender");
    sim.add_node("receiver");
    sim.add_link("sender", "receiver", 1, 0.0);

    // Send first packet at latency=1 (link default).
    sim.send("sender", "receiver", b"fast-packet".to_vec());
    sim.tick(); // tick 1: fast packet delivered (latency=1)

    // Change the link to latency=3 and send a second packet before partitioning.
    if let Some(link) = sim.link_mut("sender", "receiver") {
        link.latency_ms = 3;
    }
    sim.send("sender", "receiver", b"slow-packet".to_vec());
    sim.tick(); // tick 2: slow packet in-flight, not yet due (due at tick 2+3=5)

    // Partition the link — the slow packet is already in the in-flight queue.
    sim.partition("sender", "receiver");

    sim.tick(); // tick 3
    sim.tick(); // tick 4
    sim.tick(); // tick 5: slow packet delivery time reached

    let rx = sim.node("receiver").expect("receiver must exist");
    // fast-packet was delivered at tick 1; slow-packet at tick 5.
    assert_eq!(
        rx.inbox.len(),
        2,
        "both packets queued before partition must be delivered"
    );
    assert_eq!(rx.inbox[0], b"fast-packet");
    assert_eq!(rx.inbox[1], b"slow-packet");
}

// ---------------------------------------------------------------------------
// Scenario: partition-then-restore resumes new delivery
// ---------------------------------------------------------------------------

/// After a partition is restored, new sends deliver normally.  This confirms
/// the baseline recovery path: disruption followed by restoration works.
#[test]
fn partition_then_restore_resumes_delivery() {
    let mut sim = NetworkSimulator::new();
    sim.add_node("a");
    sim.add_node("b");
    sim.add_link("a", "b", 0, 0.0);

    // Partition and verify drops.
    sim.partition("a", "b");
    sim.send("a", "b", b"during-partition".to_vec());
    sim.tick();

    assert!(
        sim.node("b").unwrap().inbox.is_empty(),
        "packet sent during partition must not be delivered"
    );

    // Restore and verify delivery resumes.
    sim.restore("a", "b");
    sim.send("a", "b", b"after-restore".to_vec());
    sim.tick();

    let b = sim.node("b").expect("b must exist");
    assert_eq!(b.inbox.len(), 1, "delivery must resume after partition is restored");
    assert_eq!(b.inbox[0], b"after-restore");
}
