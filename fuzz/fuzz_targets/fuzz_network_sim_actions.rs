#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::testing::sim::{run_decoded_action_sequence, DEFAULT_MAX_ACTIONS};

fuzz_target!(|data: &[u8]| {
    let _report = run_decoded_action_sequence(data, DEFAULT_MAX_ACTIONS);
});
