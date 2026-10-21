// fuzz_targets/fuzz_admin_command.rs — admin command payload fuzz target (§3.9.3)
//
// # What this target tests
//
// An `AdminCommand` mesh packet can erase the receiving device.  Its payload
// arrives from the network inside an unsigned envelope, so
// `mesh::admin_command` must:
//   - never panic on any payload bytes,
//   - never produce a verified `RemoteKillswitchRequest` unless the signature
//     was made by the key it is checked against (the fuzzer does not hold
//     the fixture private key, so any `Ok` from `verify` is a bug),
//   - enforce the freshness window and replay cache without panicking.
//
// # Input layout
//
// Bytes 0..8 are the "now" clock; the remainder is the payload.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::mesh::admin_command::{
    parse_admin_command, AdminCommand, KillswitchReplayCache,
};

/// Fixture verifying key: the public half of a throwaway seed the fuzzer
/// never sees, so no fuzz input can carry a valid signature under it.
fn fixture_public_key() -> [u8; 32] {
    let seed = [0x77u8; 32];
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let (clock, payload) = data.split_at(8);
    let now = u64::from_le_bytes([
        clock[0], clock[1], clock[2], clock[3], clock[4], clock[5], clock[6], clock[7],
    ]);
    // Must not panic regardless of input.
    let Ok(AdminCommand::Killswitch(request)) = parse_admin_command(payload) else {
        return;
    };
    let _ = request.check_freshness(now);
    // The fixture private key is not derivable from the fuzz input, so a
    // verified signature here would mean the verifier accepted garbage.
    assert!(request.verify(&fixture_public_key()).is_err());
    let mut cache = KillswitchReplayCache::new();
    assert!(cache.record(&request.signature));
    assert!(!cache.record(&request.signature));
});
