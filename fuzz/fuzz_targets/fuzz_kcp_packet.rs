#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ok = mesh_infinity::testing::fuzz::fuzz_kcp_input(data);
    assert!(ok, "KCP input parser must not panic on malformed segment bytes");
});
