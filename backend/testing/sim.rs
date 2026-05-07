//! Shared stateful-simulator action model for property and fuzz tests.
//!
//! This module does not replace the concrete simulator. It provides a stable
//! action vocabulary that stateful fuzzers can decode from arbitrary bytes and
//! then execute against `backend/testing/simulator.rs`.

use crate::testing::arbitrary::ByteCursor;
use crate::testing::simulator::NetworkSimulator;

/// Default upper bound for stateful simulator fuzz cases.
pub const DEFAULT_MAX_ACTIONS: usize = 64;

/// Default upper bound for nodes created by one decoded simulator case.
const DEFAULT_MAX_NODES: usize = 8;

/// One simulator action in a stateful fuzz or property-test sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulatorAction {
    CreateNode,
    PairNodes,
    SendMessage,
    DropPacket,
    DuplicatePacket,
    DelayPacket,
    PartitionLink,
    RestoreLink,
    AdvanceTime,
    RotateKey,
    DisavowPeer,
    TriggerKillswitch,
    RestartNode,
    ReloadVault,
    ToggleTransport,
}

/// Summary returned after executing a decoded simulator action sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatorRunReport {
    pub executed_actions: usize,
    pub node_count: usize,
    pub delivered_packets: u64,
    pub dropped_packets: u64,
    pub current_tick: u64,
}

/// Decode a bounded action sequence from arbitrary bytes.
pub fn decode_action_sequence(data: &[u8], max_actions: usize) -> Vec<SimulatorAction> {
    let mut cursor = ByteCursor::new(data);
    let count = cursor.take_bounded_usize(max_actions);
    let mut actions = Vec::with_capacity(count);

    for _ in 0..count {
        let action = match cursor.take_u8() % 15 {
            0 => SimulatorAction::CreateNode,
            1 => SimulatorAction::PairNodes,
            2 => SimulatorAction::SendMessage,
            3 => SimulatorAction::DropPacket,
            4 => SimulatorAction::DuplicatePacket,
            5 => SimulatorAction::DelayPacket,
            6 => SimulatorAction::PartitionLink,
            7 => SimulatorAction::RestoreLink,
            8 => SimulatorAction::AdvanceTime,
            9 => SimulatorAction::RotateKey,
            10 => SimulatorAction::DisavowPeer,
            11 => SimulatorAction::TriggerKillswitch,
            12 => SimulatorAction::RestartNode,
            13 => SimulatorAction::ReloadVault,
            _ => SimulatorAction::ToggleTransport,
        };
        actions.push(action);
    }

    actions
}

/// Decode and execute a bounded simulator action sequence.
pub fn run_decoded_action_sequence(data: &[u8], max_actions: usize) -> SimulatorRunReport {
    let actions = decode_action_sequence(data, max_actions);
    run_action_sequence(&actions)
}

/// Execute a decoded action sequence against the in-memory network simulator.
pub fn run_action_sequence(actions: &[SimulatorAction]) -> SimulatorRunReport {
    let mut runner = SimulatorActionRunner::new(DEFAULT_MAX_NODES);

    for action in actions {
        let previous_delivered = runner.sim.delivered_packets;
        let previous_dropped = runner.sim.dropped_packets;
        let previous_tick = runner.sim.current_tick();

        runner.apply(action);
        runner.assert_invariants(previous_delivered, previous_dropped, previous_tick);
    }

    SimulatorRunReport {
        executed_actions: actions.len(),
        node_count: runner.nodes.len(),
        delivered_packets: runner.sim.delivered_packets,
        dropped_packets: runner.sim.dropped_packets,
        current_tick: runner.sim.current_tick(),
    }
}

/// Small deterministic adapter from abstract fuzz actions to simulator calls.
///
/// The runner wraps a [`NetworkSimulator`] and translates abstract
/// [`SimulatorAction`] values into concrete simulator operations.  It also
/// maintains auxiliary bookkeeping that the raw simulator does not have:
///
/// - `disavowed_pairs`: pairs whose trust has been revoked this session.
///   A disavowal is permanent — [`SimulatorAction::RestoreLink`] will never
///   re-enable a disavowed link (unlike a plain partition).
/// - `killed`: set by [`SimulatorAction::TriggerKillswitch`]; all subsequent
///   sends are no-ops and the invariant checker verifies permanent partition.
struct SimulatorActionRunner {
    /// The underlying in-memory network simulator.
    sim: NetworkSimulator,
    /// Node IDs created so far by [`SimulatorAction::CreateNode`].
    nodes: Vec<String>,
    /// All directional links added so far (each bidirectional link is two entries).
    links: Vec<(String, String)>,
    /// Maximum number of nodes this runner will create.
    max_nodes: usize,
    /// Monotonically increasing counter stamped on each outgoing packet so
    /// test payloads are unique and order can be verified.
    sequence: u64,
    /// Incremented by [`SimulatorAction::RotateKey`]; stamped on payloads so
    /// tests can distinguish pre- and post-rotation packets.
    key_epoch: u64,
    /// Set to `true` by [`SimulatorAction::TriggerKillswitch`].  While `true`,
    /// all send operations are skipped and the invariant checker verifies that
    /// all links remain fully partitioned.
    killed: bool,
    /// Toggled by [`SimulatorAction::ToggleTransport`].  When `false`, sends
    /// are no-ops (unless `force_send` is set) and all links are partitioned.
    transport_enabled: bool,
    /// Pairs for which trust has been permanently revoked this session.
    /// Stored as `(from, to)` directional pairs.  Both directions are recorded
    /// when [`SimulatorAction::DisavowPeer`] fires.  [`restore_links`] skips
    /// any pair in this list so the partition cannot be accidentally lifted.
    disavowed_pairs: Vec<(String, String)>,
}

impl SimulatorActionRunner {
    fn new(max_nodes: usize) -> Self {
        Self {
            sim: NetworkSimulator::new(),
            nodes: Vec::new(),
            links: Vec::new(),
            max_nodes,
            sequence: 0,
            key_epoch: 0,
            killed: false,
            transport_enabled: true,
            disavowed_pairs: Vec::new(),
        }
    }

    fn apply(&mut self, action: &SimulatorAction) {
        self.sequence = self.sequence.saturating_add(1);

        match action {
            SimulatorAction::CreateNode => self.create_node(),
            SimulatorAction::PairNodes => self.pair_nodes(),
            SimulatorAction::SendMessage => self.send_message(1, 0, false),
            SimulatorAction::DropPacket => self.drop_packet(),
            SimulatorAction::DuplicatePacket => self.send_message(2, 0, false),
            SimulatorAction::DelayPacket => self.send_message(1, 3, false),
            SimulatorAction::PartitionLink => self.partition_primary_link(),
            SimulatorAction::RestoreLink => self.restore_links(),
            SimulatorAction::AdvanceTime => self.sim.run(3),
            SimulatorAction::RotateKey => self.rotate_key(),
            SimulatorAction::DisavowPeer => self.revoke_trust(),
            SimulatorAction::TriggerKillswitch => self.trigger_killswitch(),
            SimulatorAction::RestartNode => self.restart_primary_node(),
            SimulatorAction::ReloadVault => self.sim.tick(),
            SimulatorAction::ToggleTransport => self.toggle_transport(),
        }
    }

    fn create_node(&mut self) {
        if self.nodes.len() >= self.max_nodes {
            return;
        }

        let id = format!("node-{}", self.nodes.len());
        self.sim.add_node(&id);

        if let Some(previous) = self.nodes.last().cloned() {
            self.add_bidirectional_link(&previous, &id, 0);
        }

        self.nodes.push(id);
    }

    fn pair_nodes(&mut self) {
        self.ensure_min_nodes(2);

        if let Some((from, to)) = self.primary_pair() {
            self.add_bidirectional_link(&from, &to, 0);
        }
    }

    fn send_message(&mut self, copies: usize, latency: u32, force_send: bool) {
        self.ensure_min_nodes(2);

        if self.killed || (!self.transport_enabled && !force_send) {
            self.sim.tick();
            return;
        }

        let Some((from, to)) = self.primary_pair() else {
            return;
        };

        self.add_bidirectional_link(&from, &to, latency);

        let payload = vec![
            self.sequence as u8,
            self.key_epoch as u8,
            self.nodes.len() as u8,
        ];

        for _ in 0..copies {
            self.sim.send(&from, &to, payload.clone());
        }
        self.sim.tick();
    }

    fn drop_packet(&mut self) {
        self.ensure_min_nodes(2);

        let Some((from, to)) = self.primary_pair() else {
            return;
        };

        self.sim.partition(&from, &to);
        self.sim.send(&from, &to, vec![self.sequence as u8]);
        self.sim.tick();
    }

    fn partition_primary_link(&mut self) {
        self.ensure_min_nodes(2);

        if let Some((from, to)) = self.primary_pair() {
            self.sim.partition(&from, &to);
            self.sim.partition(&to, &from);
        }
    }

    fn restore_links(&mut self) {
        for (from, to) in self.links.clone() {
            // Never restore a link that has been permanently disavowed.  Trust
            // revocation is session-scoped: even after a RestoreLink action or
            // node restart, the disavowed pair stays partitioned.
            if !self.disavowed_pairs.contains(&(from.clone(), to.clone())) {
                self.sim.restore(&from, &to);
            }
        }
    }

    /// Revoke trust for the primary node pair.
    ///
    /// Unlike a plain partition, a trust revocation is recorded in
    /// `disavowed_pairs` and is permanent for the session: subsequent
    /// [`SimulatorAction::RestoreLink`] actions will not re-enable the pair's
    /// link.  Both directions (from→to and to→from) are recorded and
    /// partitioned so the disavowal is fully bidirectional.
    fn revoke_trust(&mut self) {
        // A disavowal requires at least two nodes.
        self.ensure_min_nodes(2);

        if let Some((from, to)) = self.primary_pair() {
            // Record both directions as permanently disavowed.  Checking for
            // duplicates avoids bloating the list on repeated DisavowPeer actions.
            let fwd = (from.clone(), to.clone());
            let rev = (to.clone(), from.clone());
            if !self.disavowed_pairs.contains(&fwd) {
                self.disavowed_pairs.push(fwd);
            }
            if !self.disavowed_pairs.contains(&rev) {
                self.disavowed_pairs.push(rev);
            }

            // Apply the physical partition to match the disavowal.
            self.sim.partition(&from, &to);
            self.sim.partition(&to, &from);
        }

        // Advance time so the disavowal is reflected in the next tick's stats.
        self.sim.tick();
    }

    fn rotate_key(&mut self) {
        self.key_epoch = self.key_epoch.saturating_add(1);
        self.sim.tick();
    }

    fn trigger_killswitch(&mut self) {
        self.killed = true;
        for (from, to) in self.links.clone() {
            self.sim.partition(&from, &to);
        }
        self.sim.tick();
    }

    fn restart_primary_node(&mut self) {
        if let Some(id) = self.nodes.first().cloned() {
            self.sim.add_node(&id);
            self.restore_links();
        } else {
            self.create_node();
        }
        self.sim.tick();
    }

    fn toggle_transport(&mut self) {
        self.transport_enabled = !self.transport_enabled;

        if self.transport_enabled && !self.killed {
            self.restore_links();
        } else {
            for (from, to) in self.links.clone() {
                self.sim.partition(&from, &to);
            }
        }

        self.sim.tick();
    }

    fn ensure_min_nodes(&mut self, min_nodes: usize) {
        while self.nodes.len() < min_nodes && self.nodes.len() < self.max_nodes {
            self.create_node();
        }
    }

    fn primary_pair(&self) -> Option<(String, String)> {
        if self.nodes.len() < 2 {
            return None;
        }

        let from = self.nodes.first()?.clone();
        let to = self.nodes.last()?.clone();
        Some((from, to))
    }

    fn add_bidirectional_link(&mut self, a: &str, b: &str, latency: u32) {
        self.add_link(a, b, latency);
        self.add_link(b, a, latency);
    }

    fn add_link(&mut self, from: &str, to: &str, latency: u32) {
        // Never recreate a link for a disavowed pair.  `sim.add_link()` always
        // starts the new link at loss_rate=0.0, which would silently undo the
        // permanent partition that trust revocation requires.
        if self.disavowed_pairs.contains(&(from.to_string(), to.to_string())) {
            return;
        }

        self.sim.add_link(from, to, latency, 0.0);

        let link = (from.to_string(), to.to_string());
        if !self.links.contains(&link) {
            self.links.push(link);
        }
    }

    fn assert_invariants(
        &self,
        previous_delivered: u64,
        previous_dropped: u64,
        previous_tick: u64,
    ) {
        // --- Universal monotonicity invariants ---
        //
        // These hold regardless of network state.  Delivered and dropped counts
        // never go backwards.  Simulated time only moves forward.

        assert!(
            self.sim.delivered_packets >= previous_delivered,
            "delivered packet count must be monotonic"
        );
        assert!(
            self.sim.dropped_packets >= previous_dropped,
            "dropped packet count must be monotonic"
        );
        assert!(
            self.sim.current_tick() >= previous_tick,
            "simulated time must be monotonic"
        );
        assert!(
            self.nodes.len() <= self.max_nodes,
            "action runner must enforce the node bound"
        );

        // All tracked node IDs must still be present in the simulator.
        for id in &self.nodes {
            assert!(
                self.sim.node(id).is_some(),
                "tracked simulator node must exist: {id}"
            );
        }

        // --- Post-kill-switch invariants ---
        //
        // After TriggerKillswitch fires, every link the runner knows about must
        // be fully partitioned (loss_rate = 1.0).  The send_message helper
        // already guards on `self.killed` so no new sends can succeed, but we
        // also assert the physical link state to catch any code that bypasses
        // the guard.
        if self.killed {
            for (from, to) in &self.links {
                // The link might not exist if it was never fully established
                // (e.g. node created but pair never wired up).  Only assert
                // links that actually exist in the simulator.
                if let Some(link) = self.sim.link(from, to) {
                    assert_eq!(
                        link.loss_rate, 1.0,
                        "link {from}->{to} must be fully partitioned after kill-switch"
                    );
                }
            }
        }

        // --- Post-disavowal invariants ---
        //
        // Each pair in disavowed_pairs must maintain loss_rate = 1.0 for the
        // rest of the session.  restore_links() already skips disavowed pairs,
        // so this assertion catches any code that accidentally bypasses that
        // guard or calls sim.restore() directly on a disavowed pair.
        for (from, to) in &self.disavowed_pairs {
            if let Some(link) = self.sim.link(from, to) {
                assert_eq!(
                    link.loss_rate, 1.0,
                    "disavowed link {from}->{to} must remain permanently partitioned"
                );
            }
        }
    }
}
