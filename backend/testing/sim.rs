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
struct SimulatorActionRunner {
    sim: NetworkSimulator,
    nodes: Vec<String>,
    links: Vec<(String, String)>,
    max_nodes: usize,
    sequence: u64,
    key_epoch: u64,
    killed: bool,
    transport_enabled: bool,
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
            SimulatorAction::DisavowPeer => self.partition_primary_link(),
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
            self.sim.restore(&from, &to);
        }
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

        for id in &self.nodes {
            assert!(
                self.sim.node(id).is_some(),
                "tracked simulator node must exist: {id}"
            );
        }
    }
}
