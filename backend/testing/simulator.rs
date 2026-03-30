//! In-Memory Network Simulator (Spec SS 21.5)
//!
//! # Purpose
//!
//! The network simulator allows development and QA to test multi-node mesh
//! scenarios without physical devices or real network connections.  N virtual
//! nodes communicate through an in-memory channel layer that simulates:
//!
//! - **Latency** -- configurable per-link delay in milliseconds
//! - **Packet loss** -- configurable per-link loss rate (0.0 = no loss, 1.0 = total loss)
//! - **Bandwidth limits** -- per-link throughput cap in bits per second
//! - **Network partitions** -- complete link severance (simulating node failure or
//!   network segmentation)
//!
//! # Architecture (SS 21.5.2)
//!
//! The simulator is tick-based: each call to `tick()` advances the simulation
//! by one time step.  During a tick:
//!
//! 1. Packets in the delivery queue whose latency timer has expired are
//!    delivered to the destination node's inbox.
//! 2. Packets that fail the loss-rate check are silently dropped.
//! 3. Statistics (delivered/dropped counts) are updated.
//!
//! Nodes send messages by calling `send()`, which places them in the outbox.
//! The simulator moves outbox contents to the delivery queue with the
//! appropriate latency delay applied.
//!
//! # Thread safety
//!
//! The simulator is single-threaded by design -- all operations happen on the
//! calling thread.  For async test scenarios, wrap in a `tokio::task::spawn_blocking`.

use std::collections::{HashMap, VecDeque};

// ---------------------------------------------------------------------------
// Simulation time
// ---------------------------------------------------------------------------

/// Simulated time counter (in ticks).
///
/// Each call to `tick()` increments this by 1.  Latency is expressed in ticks,
/// not wall-clock time, so tests are deterministic and independent of the
/// host machine's speed.
type SimTime = u64;

// ---------------------------------------------------------------------------
// SimNode
// ---------------------------------------------------------------------------

/// A simulated mesh node.
///
/// Each node has an inbox (received packets) and an outbox (packets waiting
/// to be transmitted).  The simulator moves packets between outboxes and
/// inboxes according to the configured link conditions.
#[derive(Debug, Clone)]
pub struct SimNode {
    /// Unique identifier for this node (e.g. "alice", "relay-1", "bob").
    pub id: String,

    /// Inbox: packets that have been delivered to this node.
    /// Each entry is a raw byte vector representing one packet.
    /// Tests read from the inbox to verify message delivery.
    pub inbox: Vec<Vec<u8>>,

    /// Outbox: packets queued for transmission.
    /// Each entry is (destination_id, packet_bytes).
    /// The simulator drains the outbox on each tick.
    pub outbox: Vec<(String, Vec<u8>)>,
}

impl SimNode {
    /// Create a new simulated node with the given identifier.
    ///
    /// The node starts with empty inbox and outbox -- it is idle until
    /// the test scenario begins sending messages.
    fn new(id: &str) -> Self {
        SimNode {
            id: id.to_string(),
            inbox: Vec::new(),
            outbox: Vec::new(),
        }
    }

    /// Queue a packet for transmission to the specified destination.
    ///
    /// The packet is placed in the outbox and will be picked up by the
    /// simulator on the next `tick()`.  This does NOT directly deliver
    /// the packet -- it must traverse the simulated link first.
    pub fn queue_send(&mut self, to: &str, data: Vec<u8>) {
        self.outbox.push((to.to_string(), data));
    }
}

// ---------------------------------------------------------------------------
// SimLink
// ---------------------------------------------------------------------------

/// A simulated network link between two nodes.
///
/// Links are unidirectional: a link from "alice" to "bob" does not
/// automatically create a link from "bob" to "alice".  Bidirectional
/// communication requires two links.
///
/// Link conditions can be modified at any time during the simulation
/// to model dynamic network changes (e.g. congestion, node movement).
#[derive(Debug, Clone)]
pub struct SimLink {
    /// Source node identifier.
    pub from: String,

    /// Destination node identifier.
    pub to: String,

    /// One-way latency in simulation ticks.
    /// A packet sent at tick T arrives at tick T + latency_ms.
    /// Set to 0 for instant delivery (useful for unit tests).
    pub latency_ms: u32,

    /// Packet loss rate as a fraction between 0.0 and 1.0.
    /// 0.0 = no loss (all packets delivered).
    /// 0.5 = 50% loss (roughly half of packets dropped).
    /// 1.0 = total loss (all packets dropped -- equivalent to partition).
    pub loss_rate: f64,

    /// Maximum throughput in bits per second.
    /// 0 means unlimited bandwidth (no throttling).
    /// When bandwidth is limited, excess packets are dropped.
    pub bandwidth_bps: u64,
}

impl SimLink {
    /// Create a new link with default conditions (zero latency, no loss,
    /// unlimited bandwidth).
    fn new(from: &str, to: &str) -> Self {
        SimLink {
            from: from.to_string(),
            to: to.to_string(),
            latency_ms: 0,
            loss_rate: 0.0,
            bandwidth_bps: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// In-flight packet
// ---------------------------------------------------------------------------

/// A packet that is "in transit" on a simulated link.
///
/// The packet has been sent but not yet delivered -- it is waiting in the
/// delivery queue until `deliver_at` is reached.
#[derive(Debug, Clone)]
struct InFlightPacket {
    /// Destination node identifier.
    to: String,

    /// Raw packet bytes.
    data: Vec<u8>,

    /// Simulation tick at which this packet should be delivered.
    /// The packet remains in the queue until `current_tick >= deliver_at`.
    deliver_at: SimTime,
}

// ---------------------------------------------------------------------------
// NetworkSimulator
// ---------------------------------------------------------------------------

/// The main network simulator (SS 21.5).
///
/// Manages a set of simulated nodes connected by configurable links.
/// The simulator is tick-based: call `tick()` to advance time and deliver
/// packets.  Call `run(n)` to advance multiple ticks at once.
///
/// # Example
///
/// ```rust,ignore
/// let mut sim = NetworkSimulator::new();
/// sim.add_node("alice");
/// sim.add_node("bob");
/// sim.add_link("alice", "bob", 2, 0.0);  // 2-tick latency, no loss
/// sim.send("alice", "bob", b"hello".to_vec());
/// sim.run(3);  // Advance 3 ticks -- packet delivered after tick 2
/// assert_eq!(sim.node("bob").inbox.len(), 1);
/// ```
pub struct NetworkSimulator {
    /// All nodes in the simulation, indexed by their string ID.
    /// Using a HashMap for O(1) lookup by node ID.
    nodes: HashMap<String, SimNode>,

    /// All links in the simulation.
    /// Links are stored as (from, to) -> SimLink for fast lookup.
    links: HashMap<(String, String), SimLink>,

    /// Packets currently in transit (not yet delivered).
    /// Ordered by delivery time for efficient processing.
    in_flight: VecDeque<InFlightPacket>,

    /// Current simulation time (in ticks).
    current_tick: SimTime,

    /// Total number of packets successfully delivered since simulation start.
    pub delivered_packets: u64,

    /// Total number of packets dropped (due to loss or missing links).
    pub dropped_packets: u64,

    /// Deterministic pseudo-random state for packet loss decisions.
    /// We use a simple LCG (linear congruential generator) to keep the
    /// simulator dependency-free and fully deterministic.
    rng_state: u64,
}

impl NetworkSimulator {
    /// Create a new empty simulator with no nodes or links.
    ///
    /// The simulation clock starts at tick 0.  Add nodes with `add_node()`,
    /// links with `add_link()`, then send packets and advance time.
    pub fn new() -> Self {
        NetworkSimulator {
            nodes: HashMap::new(),
            links: HashMap::new(),
            in_flight: VecDeque::new(),
            current_tick: 0,
            delivered_packets: 0,
            dropped_packets: 0,
            // Seed the deterministic RNG with a fixed value for reproducibility.
            // The same sequence of send/tick operations always produces the
            // same delivery/drop pattern, making test failures reproducible.
            rng_state: 0x5EED_CAFE_BABE_F00D,
        }
    }

    /// Add a node to the simulation.
    ///
    /// Returns a mutable reference to the newly created node so the caller
    /// can configure it (e.g. pre-populate the inbox for testing).
    ///
    /// # Panics
    ///
    /// Does not panic -- if a node with the same ID already exists, it is
    /// replaced (useful for test reset scenarios).
    pub fn add_node(&mut self, id: &str) -> &mut SimNode {
        // Insert or replace the node.  Using entry().or_insert_with() would
        // preserve an existing node; we intentionally overwrite to allow
        // test scenarios that reset node state.
        self.nodes.insert(id.to_string(), SimNode::new(id));
        // Return a mutable reference for caller convenience.
        self.nodes.get_mut(id).expect("just inserted")
    }

    /// Add a unidirectional link between two nodes.
    ///
    /// The link is from `from` to `to` with the specified latency and loss
    /// rate.  For bidirectional communication, call this twice with swapped
    /// from/to arguments.
    ///
    /// Returns a mutable reference to the link for further configuration
    /// (e.g. setting bandwidth limits).
    pub fn add_link(
        &mut self,
        from: &str,
        to: &str,
        latency_ms: u32,
        loss_rate: f64,
    ) -> &mut SimLink {
        // Create the link with the specified conditions.
        let mut link = SimLink::new(from, to);
        link.latency_ms = latency_ms;
        // Clamp loss_rate to [0.0, 1.0] to prevent nonsensical values.
        link.loss_rate = loss_rate.clamp(0.0, 1.0);

        // Insert into the link map.
        let key = (from.to_string(), to.to_string());
        self.links.insert(key.clone(), link);
        self.links.get_mut(&key).expect("just inserted")
    }

    /// Get an immutable reference to a node by ID.
    ///
    /// Returns `None` if no node with the given ID exists.  Useful for
    /// assertions in tests (e.g. checking inbox contents).
    pub fn node(&self, id: &str) -> Option<&SimNode> {
        self.nodes.get(id)
    }

    /// Get a mutable reference to a node by ID.
    ///
    /// Returns `None` if no node with the given ID exists.
    pub fn node_mut(&mut self, id: &str) -> Option<&mut SimNode> {
        self.nodes.get_mut(id)
    }

    /// Get an immutable reference to a link by (from, to) pair.
    ///
    /// Returns `None` if no link exists between the specified nodes.
    pub fn link(&self, from: &str, to: &str) -> Option<&SimLink> {
        self.links.get(&(from.to_string(), to.to_string()))
    }

    /// Get a mutable reference to a link for runtime condition changes.
    ///
    /// Returns `None` if no link exists between the specified nodes.
    /// Use this to dynamically change latency, loss rate, or bandwidth
    /// during a simulation run.
    pub fn link_mut(&mut self, from: &str, to: &str) -> Option<&mut SimLink> {
        self.links.get_mut(&(from.to_string(), to.to_string()))
    }

    /// Queue a packet for delivery from one node to another.
    ///
    /// The packet is placed in the sending node's outbox (if the node exists).
    /// It will be picked up by the next `tick()` call, which applies link
    /// conditions (latency, loss) and either delivers or drops it.
    pub fn send(&mut self, from: &str, to: &str, data: Vec<u8>) {
        // Look up the sending node and queue the packet.
        if let Some(node) = self.nodes.get_mut(from) {
            node.queue_send(to, data);
        }
        // If the sender doesn't exist, the packet is silently lost.
        // This matches real-world behavior: sending from a nonexistent node
        // is equivalent to the packet never being created.
    }

    /// Advance the simulation by one tick.
    ///
    /// This is the core simulation step.  It performs three operations:
    ///
    /// 1. **Drain outboxes**: move all queued packets from node outboxes into
    ///    the in-flight queue, applying link latency.
    /// 2. **Deliver packets**: deliver all in-flight packets whose delivery
    ///    time has been reached to the destination node's inbox.
    /// 3. **Update stats**: increment delivered/dropped counters.
    pub fn tick(&mut self) {
        // Step 1: Drain all node outboxes into the in-flight queue.
        // We collect the outbox contents first to avoid borrow conflicts
        // (we need mutable access to nodes to drain outboxes, but also
        // need to read link conditions).
        let mut pending: Vec<(String, String, Vec<u8>)> = Vec::new();
        for node in self.nodes.values_mut() {
            for (dest, data) in node.outbox.drain(..) {
                pending.push((node.id.clone(), dest, data));
            }
        }

        // Process each pending packet through its link.
        for (from, to, data) in pending {
            let link_key = (from.clone(), to.clone());

            // Read link conditions into local variables to avoid holding
            // an immutable borrow on `self.links` while we need mutable
            // access to `self.rng_state` for the loss-rate check.
            let link_conditions = self.links.get(&link_key).map(|link| {
                (link.loss_rate, link.bandwidth_bps, link.latency_ms)
            });

            if let Some((loss_rate, bandwidth_bps, latency_ms)) = link_conditions {
                // Check for packet loss using deterministic PRNG.
                // Generate a pseudo-random f64 in [0.0, 1.0) and compare
                // against the link's loss rate.
                let rand_val = self.next_random_f64();
                if rand_val < loss_rate {
                    // Packet dropped due to simulated loss.
                    self.dropped_packets += 1;
                    continue;
                }

                // Check bandwidth limit (simplified: drop if packet exceeds
                // per-tick byte budget).
                if bandwidth_bps > 0 {
                    // Convert bandwidth to bytes per tick (assuming 1 tick = 1ms).
                    let bytes_per_tick = bandwidth_bps / 8 / 1000;
                    if bytes_per_tick > 0 && data.len() as u64 > bytes_per_tick {
                        // Packet exceeds bandwidth -- drop it.
                        self.dropped_packets += 1;
                        continue;
                    }
                }

                // Packet survives -- schedule delivery after latency delay.
                let deliver_at = self.current_tick + latency_ms as u64;
                self.in_flight.push_back(InFlightPacket {
                    to: to.clone(),
                    data,
                    deliver_at,
                });
            } else {
                // No link exists between these nodes -- packet dropped.
                // This models a network partition or misconfigured route.
                self.dropped_packets += 1;
            }
        }

        // Step 2: Deliver packets whose latency timer has expired.
        // We iterate the queue and deliver/remove expired packets.
        let mut remaining = VecDeque::new();
        for pkt in self.in_flight.drain(..) {
            if pkt.deliver_at <= self.current_tick {
                // Delivery time reached -- put in destination's inbox.
                if let Some(dest_node) = self.nodes.get_mut(&pkt.to) {
                    dest_node.inbox.push(pkt.data);
                    self.delivered_packets += 1;
                } else {
                    // Destination node doesn't exist (removed mid-sim).
                    self.dropped_packets += 1;
                }
            } else {
                // Not yet ready -- keep in flight.
                remaining.push_back(pkt);
            }
        }
        self.in_flight = remaining;

        // Step 3: Advance the clock.
        self.current_tick += 1;
    }

    /// Run the simulation for the specified number of ticks.
    ///
    /// Equivalent to calling `tick()` N times.  Convenience method for
    /// tests that need to advance past a latency period.
    pub fn run(&mut self, ticks: usize) {
        for _ in 0..ticks {
            self.tick();
        }
    }

    /// Get the current simulation time (in ticks).
    pub fn current_tick(&self) -> SimTime {
        self.current_tick
    }

    /// Set a link to "partitioned" (total packet loss) between two nodes.
    ///
    /// This is a convenience method equivalent to setting `loss_rate = 1.0`
    /// on the link.  Models a complete network partition.
    pub fn partition(&mut self, from: &str, to: &str) {
        if let Some(link) = self.link_mut(from, to) {
            link.loss_rate = 1.0;
        }
    }

    /// Restore a previously partitioned link to zero loss.
    ///
    /// Sets `loss_rate = 0.0` on the link, restoring full connectivity.
    pub fn restore(&mut self, from: &str, to: &str) {
        if let Some(link) = self.link_mut(from, to) {
            link.loss_rate = 0.0;
        }
    }

    /// Deterministic pseudo-random number generator.
    ///
    /// Uses a 64-bit LCG (linear congruential generator) with the same
    /// constants as the Numerical Recipes recommendation.  Produces
    /// reproducible sequences so that packet loss patterns are identical
    /// across test runs with the same seed.
    fn next_random_f64(&mut self) -> f64 {
        // LCG: state = state * a + c (mod 2^64)
        // Constants from Numerical Recipes (Knuth's recommendation).
        self.rng_state = self.rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // Convert to f64 in [0.0, 1.0) by dividing by 2^64.
        (self.rng_state as f64) / (u64::MAX as f64)
    }
}

/// Default implementation creates an empty simulator.
impl Default for NetworkSimulator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Basic node operations -----------------------------------------------

    /// Adding a node creates it with empty inbox and outbox.
    #[test]
    fn add_node_creates_empty_node() {
        let mut sim = NetworkSimulator::new();
        let node = sim.add_node("alice");
        assert_eq!(node.id, "alice");
        assert!(node.inbox.is_empty(), "new node inbox must be empty");
        assert!(node.outbox.is_empty(), "new node outbox must be empty");
    }

    /// Nodes can be looked up by ID after creation.
    #[test]
    fn node_lookup_by_id() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("alice");
        sim.add_node("bob");

        assert!(sim.node("alice").is_some());
        assert!(sim.node("bob").is_some());
        assert!(sim.node("charlie").is_none());
    }

    // --- Basic link operations -----------------------------------------------

    /// Adding a link configures the specified conditions.
    #[test]
    fn add_link_stores_conditions() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_link("a", "b", 5, 0.1);

        let link = sim.link("a", "b").expect("link must exist");
        assert_eq!(link.latency_ms, 5);
        assert!((link.loss_rate - 0.1).abs() < f64::EPSILON);
    }

    /// Links are unidirectional -- adding a->b does not create b->a.
    #[test]
    fn links_are_unidirectional() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_link("a", "b", 1, 0.0);

        assert!(sim.link("a", "b").is_some(), "forward link must exist");
        assert!(sim.link("b", "a").is_none(), "reverse link must not exist");
    }

    /// Loss rate is clamped to [0.0, 1.0].
    #[test]
    fn loss_rate_clamped() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");

        // Negative loss rate should be clamped to 0.0.
        sim.add_link("a", "b", 0, -0.5);
        assert!((sim.link("a", "b").expect("link").loss_rate - 0.0).abs() < f64::EPSILON);

        // Loss rate > 1.0 should be clamped to 1.0.
        sim.add_link("a", "b", 0, 1.5);
        assert!((sim.link("a", "b").expect("link").loss_rate - 1.0).abs() < f64::EPSILON);
    }

    // --- Packet delivery (zero latency) --------------------------------------

    /// Instant delivery (latency=0): packet arrives after one tick.
    #[test]
    fn instant_delivery_one_tick() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("alice");
        sim.add_node("bob");
        sim.add_link("alice", "bob", 0, 0.0);

        // Send a message from alice to bob.
        sim.send("alice", "bob", b"hello".to_vec());

        // After one tick, the message should be in bob's inbox.
        sim.tick();
        let bob = sim.node("bob").expect("bob must exist");
        assert_eq!(bob.inbox.len(), 1, "bob should have 1 message after 1 tick");
        assert_eq!(bob.inbox[0], b"hello");
    }

    /// Multiple packets are all delivered in order.
    #[test]
    fn multiple_packets_delivered_in_order() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_link("a", "b", 0, 0.0);

        // Send 3 packets in sequence.
        sim.send("a", "b", b"one".to_vec());
        sim.send("a", "b", b"two".to_vec());
        sim.send("a", "b", b"three".to_vec());

        sim.tick();
        let b = sim.node("b").expect("b must exist");
        assert_eq!(b.inbox.len(), 3);
        assert_eq!(b.inbox[0], b"one");
        assert_eq!(b.inbox[1], b"two");
        assert_eq!(b.inbox[2], b"three");
    }

    // --- Latency simulation --------------------------------------------------

    /// Packet with latency > 0 is not delivered until the delay expires.
    #[test]
    fn latency_delays_delivery() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        // 3-tick latency, no loss.
        sim.add_link("a", "b", 3, 0.0);

        sim.send("a", "b", b"delayed".to_vec());

        // After 1 tick: outbox drained, packet in flight.
        sim.tick();
        assert!(
            sim.node("b").expect("b").inbox.is_empty(),
            "packet must not arrive before latency expires (tick 1)"
        );

        // After 2 ticks: still in flight.
        sim.tick();
        assert!(
            sim.node("b").expect("b").inbox.is_empty(),
            "packet must not arrive before latency expires (tick 2)"
        );

        // After 3 ticks: still in flight (deliver_at = tick 3, but tick() runs
        // step 2 before incrementing the clock at step 3).
        sim.tick();
        assert!(
            sim.node("b").expect("b").inbox.is_empty(),
            "packet must not arrive before latency expires (tick 3)"
        );

        // After 4 ticks: delivered (current_tick = 3 after tick 3 increment,
        // then tick 4 checks deliver_at <= 3).
        sim.tick();
        let b = sim.node("b").expect("b must exist");
        assert_eq!(b.inbox.len(), 1, "packet must arrive after latency period");
        assert_eq!(b.inbox[0], b"delayed");
    }

    // --- Packet loss ---------------------------------------------------------

    /// 100% loss rate drops all packets.
    #[test]
    fn total_loss_drops_all_packets() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_link("a", "b", 0, 1.0); // 100% loss

        // Send 10 packets -- all should be dropped.
        for i in 0..10 {
            sim.send("a", "b", vec![i]);
        }
        sim.run(5);

        let b = sim.node("b").expect("b must exist");
        assert!(
            b.inbox.is_empty(),
            "100% loss rate should drop all packets"
        );
        assert_eq!(sim.dropped_packets, 10, "all 10 packets should be counted as dropped");
    }

    /// 0% loss rate delivers all packets.
    #[test]
    fn zero_loss_delivers_all_packets() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_link("a", "b", 0, 0.0); // no loss

        for i in 0u8..20 {
            sim.send("a", "b", vec![i]);
        }
        sim.run(3);

        let b = sim.node("b").expect("b must exist");
        assert_eq!(b.inbox.len(), 20, "0% loss should deliver all 20 packets");
        assert_eq!(sim.delivered_packets, 20);
        assert_eq!(sim.dropped_packets, 0);
    }

    // --- No link between nodes -----------------------------------------------

    /// Sending between nodes with no link drops the packet.
    #[test]
    fn no_link_drops_packet() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        // No link added between a and b.

        sim.send("a", "b", b"lost".to_vec());
        sim.tick();

        let b = sim.node("b").expect("b must exist");
        assert!(b.inbox.is_empty(), "packet must be dropped without a link");
        assert_eq!(sim.dropped_packets, 1);
    }

    // --- Network partition/restore -------------------------------------------

    /// Partition severs a link (100% loss); restore reconnects it.
    #[test]
    fn partition_and_restore() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_link("a", "b", 0, 0.0);

        // Verify initial connectivity.
        sim.send("a", "b", b"before".to_vec());
        sim.tick();
        assert_eq!(sim.node("b").expect("b").inbox.len(), 1);

        // Partition the link.
        sim.partition("a", "b");
        sim.send("a", "b", b"during".to_vec());
        sim.tick();
        // The "during" packet should be dropped.
        assert_eq!(
            sim.node("b").expect("b").inbox.len(), 1,
            "partitioned link should not deliver"
        );

        // Restore the link.
        sim.restore("a", "b");
        sim.send("a", "b", b"after".to_vec());
        sim.tick();
        assert_eq!(
            sim.node("b").expect("b").inbox.len(), 2,
            "restored link should deliver"
        );
    }

    // --- Multi-hop relay scenario -------------------------------------------

    /// Three-node relay: A -> B -> C with no direct A -> C link.
    #[test]
    fn three_node_relay() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_node("c");

        // A can reach B, B can reach C.  No direct A -> C link.
        sim.add_link("a", "b", 0, 0.0);
        sim.add_link("b", "c", 0, 0.0);

        // A sends to B.
        sim.send("a", "b", b"relay-me".to_vec());
        sim.tick();

        // B receives the message.
        let b_inbox_len = sim.node("b").expect("b").inbox.len();
        assert_eq!(b_inbox_len, 1, "B must receive from A");

        // B forwards to C (simulating relay behavior).
        let packet = sim.node("b").expect("b").inbox[0].clone();
        sim.send("b", "c", packet);
        sim.tick();

        // C receives the relayed message.
        let c = sim.node("c").expect("c must exist");
        assert_eq!(c.inbox.len(), 1, "C must receive relayed packet");
        assert_eq!(c.inbox[0], b"relay-me");
    }

    // --- Run multiple ticks --------------------------------------------------

    /// run(n) is equivalent to calling tick() n times.
    #[test]
    fn run_advances_multiple_ticks() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_link("a", "b", 5, 0.0); // 5-tick latency

        sim.send("a", "b", b"timed".to_vec());
        // Run 10 ticks -- enough for the 5-tick latency to expire.
        sim.run(10);

        let b = sim.node("b").expect("b must exist");
        assert_eq!(b.inbox.len(), 1, "packet must arrive after run(10) with 5-tick latency");
        assert_eq!(sim.current_tick(), 10);
    }

    // --- Statistics -----------------------------------------------------------

    /// delivered_packets and dropped_packets track correctly.
    #[test]
    fn stats_track_delivered_and_dropped() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_link("a", "b", 0, 0.0); // no loss

        // Send 5 packets with delivery.
        for i in 0u8..5 {
            sim.send("a", "b", vec![i]);
        }
        sim.tick();
        assert_eq!(sim.delivered_packets, 5);

        // Send to a node without a link (dropped).
        sim.add_node("c");
        sim.send("a", "c", b"dropped".to_vec());
        sim.tick();
        assert_eq!(sim.dropped_packets, 1);
    }

    // --- Empty simulation ----------------------------------------------------

    /// Ticking an empty simulator does not panic.
    #[test]
    fn empty_simulator_tick_no_panic() {
        let mut sim = NetworkSimulator::new();
        sim.tick();
        sim.run(100);
        assert_eq!(sim.current_tick(), 101);
        assert_eq!(sim.delivered_packets, 0);
        assert_eq!(sim.dropped_packets, 0);
    }

    // --- Default trait -------------------------------------------------------

    /// Default creates an empty simulator identical to new().
    #[test]
    fn default_matches_new() {
        let sim = NetworkSimulator::default();
        assert_eq!(sim.current_tick(), 0);
        assert_eq!(sim.delivered_packets, 0);
        assert_eq!(sim.dropped_packets, 0);
    }

    // --- Bidirectional communication ----------------------------------------

    /// Two nodes can communicate in both directions with separate links.
    #[test]
    fn bidirectional_communication() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        sim.add_link("a", "b", 0, 0.0);
        sim.add_link("b", "a", 0, 0.0);

        // Both nodes send to each other simultaneously.
        sim.send("a", "b", b"hello-from-a".to_vec());
        sim.send("b", "a", b"hello-from-b".to_vec());
        sim.tick();

        // Both should receive.
        assert_eq!(sim.node("a").expect("a").inbox.len(), 1);
        assert_eq!(sim.node("b").expect("b").inbox.len(), 1);
        assert_eq!(sim.node("a").expect("a").inbox[0], b"hello-from-b");
        assert_eq!(sim.node("b").expect("b").inbox[0], b"hello-from-a");
    }

    // --- Large-scale simulation ----------------------------------------------

    /// 10-node mesh with full connectivity delivers messages correctly.
    #[test]
    fn ten_node_mesh_delivery() {
        let mut sim = NetworkSimulator::new();

        // Create 10 nodes.
        let ids: Vec<String> = (0..10).map(|i| format!("node-{}", i)).collect();
        for id in &ids {
            sim.add_node(id);
        }

        // Create full mesh links (every node can reach every other node).
        for from in &ids {
            for to in &ids {
                if from != to {
                    sim.add_link(from, to, 1, 0.0);
                }
            }
        }

        // Node 0 sends to node 9.
        sim.send("node-0", "node-9", b"mesh-test".to_vec());
        sim.run(5);

        let dest = sim.node("node-9").expect("node-9 must exist");
        assert_eq!(dest.inbox.len(), 1, "message must arrive in 10-node mesh");
        assert_eq!(dest.inbox[0], b"mesh-test");
    }

    // --- Bandwidth limiting -------------------------------------------------

    /// Packets exceeding the bandwidth limit are dropped.
    #[test]
    fn bandwidth_limit_drops_oversized_packets() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        let link = sim.add_link("a", "b", 0, 0.0);
        // Set bandwidth to 8000 bps = 1 byte/ms = 1 byte/tick.
        link.bandwidth_bps = 8000;

        // Send a 2-byte packet (exceeds 1 byte/tick budget).
        sim.send("a", "b", vec![0xAA, 0xBB]);
        sim.tick();

        let b = sim.node("b").expect("b must exist");
        assert!(
            b.inbox.is_empty(),
            "oversized packet should be dropped by bandwidth limit"
        );
        assert_eq!(sim.dropped_packets, 1);
    }

    /// Small packets within bandwidth limit are delivered.
    #[test]
    fn bandwidth_limit_passes_small_packets() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("a");
        sim.add_node("b");
        let link = sim.add_link("a", "b", 0, 0.0);
        // Set bandwidth to 80000 bps = 10 bytes/tick.
        link.bandwidth_bps = 80000;

        // Send a 5-byte packet (within limit).
        sim.send("a", "b", vec![1, 2, 3, 4, 5]);
        sim.tick();

        let b = sim.node("b").expect("b must exist");
        assert_eq!(b.inbox.len(), 1, "small packet should pass bandwidth limit");
    }

    // --- Sending from nonexistent node --------------------------------------

    /// Sending from a node that doesn't exist is silently ignored.
    #[test]
    fn send_from_nonexistent_node_ignored() {
        let mut sim = NetworkSimulator::new();
        sim.add_node("b");
        // "a" does not exist.
        sim.send("a", "b", b"ghost".to_vec());
        sim.tick();

        // No crash, no delivery, no dropped count increment
        // (the packet was never created in the first place).
        let b = sim.node("b").expect("b must exist");
        assert!(b.inbox.is_empty());
    }
}
