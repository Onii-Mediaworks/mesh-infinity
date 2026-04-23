//! Shared stateful-simulator action model for future property and fuzz tests.
//!
//! This module does not replace the concrete simulator. It provides a stable
//! action vocabulary that future stateful fuzzers can decode from arbitrary
//! bytes and then execute against `backend/testing/simulator.rs`.

use crate::testing::arbitrary::ByteCursor;

/// One simulator action in a future stateful fuzz or property-test sequence.
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
