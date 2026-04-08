// fuzz_targets/fuzz_pairing_payload.rs — Pairing payload parser fuzz target (§8.3, §21.1.3)
//
// # What this target tests
//
// The pairing subsystem is the first point of contact between Mesh Infinity
// and an unknown peer.  QR codes, BLE advertisements, NFC records, and link
// shares all carry a `PairingPayload` serialized as JSON.  The JSON
// deserialization path must never panic on any byte sequence.
//
// # Attack surface
//
// A hostile peer can craft an arbitrary pairing QR code or NFC record.  The
// bytes that arrive at `PairingPayload` deserialization may be:
//   - Completely random (not JSON at all)
//   - Valid JSON with missing or extra fields
//   - Valid JSON with fields of the wrong type (e.g. `"version": "not_a_number"`)
//   - JSON with extremely long string values
//   - JSON with deeply nested structures (stack-overflow risk)
//   - Truncated JSON with no closing brace
//
// All of these must be handled by returning a deserialization error — never
// by panicking.
//
// # Corpus
//
// `fuzz/corpus/fuzz_pairing_payload/` contains seed inputs.  The canonical
// seed is a minimal valid pairing JSON (see the corpus file).  cargo-fuzz
// mutates from these seeds to explore adjacent inputs efficiently.

#![no_main]

use libfuzzer_sys::fuzz_target;

// `PairingPayload` derives `serde::Deserialize`, so `serde_json::from_slice`
// exercises the full deserialization path including field validation.
use mesh_infinity::pairing::methods::PairingPayload;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse the arbitrary bytes as a JSON-encoded PairingPayload.
    // serde_json::from_slice returns Err(...) for malformed JSON — it must
    // never panic.
    let _ = serde_json::from_slice::<PairingPayload>(data);
});
