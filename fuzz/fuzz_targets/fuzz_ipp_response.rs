#![no_main]

// Fuzz the IPP response decoder and the HTTP framing around it (§20.8.1).
//
// Both parsers consume bytes from a printer or spooler socket, so they must
// reject any malformed input with a typed error and never panic.

use libfuzzer_sys::fuzz_target;
use mesh_infinity::services::ipp::{parse_http_response, parse_message};

fuzz_target!(|data: &[u8]| {
    let _ = parse_message(data);
    if let Ok(body) = parse_http_response(data) {
        let _ = parse_message(&body);
    }
});
