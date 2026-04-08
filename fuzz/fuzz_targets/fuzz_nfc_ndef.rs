// fuzz_targets/fuzz_nfc_ndef.rs — NFC NDEF record parser fuzz target (§5.9, §21.1.3)
//
// # What this target tests
//
// The NFC transport uses the NDEF (NFC Data Exchange Format) binary encoding
// to carry pairing payloads between devices.  When Alice taps her phone on
// Bob's device, Bob's device reads raw bytes from the NFC tag and hands them
// to `decode_ndef_message`.  That function must never panic on any input.
//
// # Attack surface
//
// Any NFC-capable device in the physical vicinity can broadcast an arbitrary
// NDEF record.  A hostile tag could contain:
//   - A zero-length type field
//   - A payload length that claims to be larger than the remaining bytes
//   - An ID-length flag (NDEF_IL) set with no ID bytes following
//   - Truncated records mid-field
//   - Completely random bytes that share no structure with NDEF at all
//
// All of these must be handled by returning `None` — not by panicking.
//
// # Corpus
//
// The corpus directory `fuzz/corpus/fuzz_nfc_ndef/` contains seed inputs,
// including at least one valid Mesh Infinity NDEF record.  cargo-fuzz reads
// these seeds on startup and uses them as the initial population to mutate.

#![no_main]

// The `fuzz_target!` macro is provided by libfuzzer-sys.  It wraps our
// closure as the `LLVMFuzzerTestOneInput` entry point that libFuzzer calls
// with each generated input.  The macro handles the C → Rust ABI bridging.
use libfuzzer_sys::fuzz_target;

// The NDEF decoder from the NFC transport module.
// `decode_ndef_message` takes a byte slice and returns `Option<Vec<u8>>`:
//   - `Some(payload_bytes)` — a well-formed Mesh Infinity NDEF record was found
//   - `None`               — the bytes are not a valid NDEF record (or not our type)
// It must NEVER panic.
use mesh_infinity::transport::nfc::decode_ndef_message;

fuzz_target!(|data: &[u8]| {
    // Feed the raw fuzz input directly to the NDEF parser.
    // The return value (Some / None) is intentionally discarded — we only
    // care that no panic occurs.  The fuzzer's sanitizers (AddressSanitizer,
    // UndefinedBehaviorSanitizer) will catch memory bugs even when we discard
    // the output.
    let _ = decode_ndef_message(data);
});
