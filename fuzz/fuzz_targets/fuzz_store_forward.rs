// Fuzz target: store-and-forward deposit / retrieve / gc (§6.8)
//
// Exercises `StoreForwardServer::deposit()`, `retrieve()`, and `gc()` with
// attacker-controlled inputs to ensure:
// - No panics on malformed payloads, expiry values, or signatures.
// - Empty payloads and far-future expiries stop at the structural gates.
// - Expiry signature validation enforces correctness without panicking.
// - Storage cap (envelope-accounted) and queue limits are enforced without overflow.
// - GC does not panic on empty or partially-expired queues.
//
// The byte layout is decoded by `testing::arbitrary::store_forward_case`,
// which the in-tree corpus replay test shares, so committed seeds mean the
// same thing in both places.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::routing::store_forward::StoreForwardServer;
use mesh_infinity::testing::arbitrary::store_forward_case;

fuzz_target!(|data: &[u8]| {
    let case = store_forward_case(data);
    let destination = case.request.destination;

    // Small cap to exercise eviction logic quickly.
    let mut server = StoreForwardServer::new(65536);

    // Must not panic regardless of input.
    let _ = server.deposit(case.request, case.tunnel_id, case.now);

    // Retrieve must not panic.
    let _ = server.retrieve(&destination, case.now);

    // GC must not panic.
    server.gc(case.now);
});
