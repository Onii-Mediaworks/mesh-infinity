#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::testing::ffi_json::run_ffi_json_input;

fuzz_target!(|data: &[u8]| {
    run_ffi_json_input(data);
});
