// fuzz_targets/fuzz_message_frame.rs — MeshPacket frame parser fuzz target (§6.5, §21.1.3)
//
// # What this target tests
//
// Every message, routing announcement, file-transfer chunk, and keepalive
// travels inside a `MeshPacket` envelope.  Intermediate relay nodes receive
// these envelopes from peers they may not fully trust and must deserialize
// the outer frame to make forwarding decisions.  The deserialization path
// must never panic on any byte sequence.
//
// # Attack surface
//
// A compromised relay node could forward:
//   - A packet with a `ttl` field set to 0 (should be dropped, not crash)
//   - A packet with a `version` field set to an unknown protocol version
//   - A packet where `packet_id` is not 32 hex-encoded bytes
//   - Completely random bytes with no JSON structure at all
//   - JSON where `kind` is a variant string the local binary does not recognize
//   - A packet with an extremely long `payload` field
//
// All of these must result in a deserialization error — never a panic.
//
// # Corpus
//
// `fuzz/corpus/fuzz_message_frame/` contains seed inputs.  The canonical seed
// is a minimal valid MeshPacket JSON (see the corpus file).  cargo-fuzz
// mutates from these seeds toward adjacent inputs that explore untested paths.

#![no_main]

use libfuzzer_sys::fuzz_target;

// `MeshPacket` derives `serde::Deserialize`.  Deserializing via
// `serde_json::from_slice` exercises the full field-parsing path including
// the custom `hex_bytes32` serde helpers for `packet_id`, `src`, and `dst`.
use mesh_infinity::mesh::packet::MeshPacket;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse the arbitrary bytes as a JSON-encoded MeshPacket.
    // serde_json returns Err(...) for malformed or structurally invalid JSON —
    // it must never panic regardless of input.
    let _ = serde_json::from_slice::<MeshPacket>(data);
});
