// Fuzz target: store-and-forward deposit / retrieve / gc (§13)
//
// Exercises `StoreForwardServer::deposit()`, `retrieve()`, and `gc()` with
// attacker-controlled inputs to ensure:
// - No panics on malformed payloads, expiry values, or signatures.
// - Expiry signature validation enforces correctness without panicking.
// - Storage cap and queue limits are enforced without overflow.
// - GC does not panic on empty or partially-expired queues.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::routing::store_forward::{StoreForwardServer, StoreAndForwardRequest};
use mesh_infinity::routing::store_forward::{Priority, ReleaseCondition};
use mesh_infinity::routing::table::DeviceAddress;
use mesh_infinity::testing::arbitrary::ByteCursor;

fuzz_target!(|data: &[u8]| {
    let mut cur = ByteCursor::new(data);

    // Build a destination address from fuzz bytes.
    let mut dest_bytes = [0u8; 32];
    for b in dest_bytes.iter_mut() {
        *b = cur.take_u8();
    }
    let destination = DeviceAddress(dest_bytes);

    // Fuzz-controlled payload.
    let payload_len = cur.take_bounded_usize(4096);
    let payload: Vec<u8> = (0..payload_len).map(|_| cur.take_u8()).collect();

    // Fuzz-controlled expiry and now timestamps.
    let expiry = u64::from_le_bytes([
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
    ]);
    let now = u64::from_le_bytes([
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
    ]);

    // Fuzz-controlled expiry signature (arbitrary bytes — usually invalid).
    let sig_len = cur.take_bounded_usize(128);
    let expiry_sig: Vec<u8> = (0..sig_len).map(|_| cur.take_u8()).collect();

    // Priority from fuzz byte.
    let priority = match cur.take_u8() % 3 {
        0 => Priority::Low,
        1 => Priority::Normal,
        _ => Priority::Critical,
    };

    let request = StoreAndForwardRequest {
        destination: destination.clone(),
        payload,
        expiry,
        expiry_sig,
        priority,
        cancellation_pubkey: None,
        release_condition: ReleaseCondition::Immediate,
        application_id: None,
    };

    // Small cap to exercise eviction logic quickly.
    let mut server = StoreForwardServer::new(65536);
    let tunnel_id = u64::from_le_bytes([
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
    ]);

    // Must not panic regardless of input.
    let _ = server.deposit(request, tunnel_id, now);

    // Retrieve must not panic.
    let _ = server.retrieve(&destination, now);

    // GC must not panic.
    server.gc(now);
});
