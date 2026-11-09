//! The core's protocol decoder against arbitrary bytes from the UI process
//! (SPEC §21.2.1: every external byte boundary is fuzzed). It must never
//! panic, never accept a frame over the size cap, and anything it accepts
//! must re-encode to exactly the bytes it read.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_ui_protocol_spike::{read_frame, write_frame, MAX_FRAME};

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    while let Ok((envelope, used)) = read_frame(input) {
        // An accepted frame is within the cap and canonical.
        assert!(used - 4 <= MAX_FRAME);
        let mut again = Vec::new();
        write_frame(&envelope, &mut again);
        assert_eq!(again.as_slice(), &input[..used]);
        input = &input[used..];
    }
});
