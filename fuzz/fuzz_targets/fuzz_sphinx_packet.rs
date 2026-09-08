// Fuzz target: complete native Sphinx packet receive path (§11.3 mixnet transport)
//
// Feeds attacker-controlled fixed-size wire frames and routing keys through
// `MixnetNode::receive()` to exercise framing, epoch selection, Sphinx parsing,
// authentication, replay handling, and final payload rejection without panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::transport::mixnet::{MixRole, MixnetNode, MIXNET_MTU};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&data[..32]);

    let mut wire = [0u8; MIXNET_MTU];
    let available = data.len() - 32;
    let wire_len = available.min(MIXNET_MTU);
    wire[..wire_len].copy_from_slice(&data[32..32 + wire_len]);

    let epoch = if wire_len >= 9 {
        u64::from_be_bytes(wire[1..9].try_into().expect("fixed epoch slice"))
    } else {
        0
    };
    let mut node =
        MixnetNode::new_with_epoch_and_seed(MixRole::MixNode, epoch, private_key, private_key);

    let _ = node.receive(&wire);
});
