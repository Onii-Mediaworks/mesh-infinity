// fuzz_targets/fuzz_ring_verify.rs — Ring signature verifier fuzz target (§3.5.2)
//
// # What this target tests
//
// Every member of a Private or Closed group verifies the `ring_sig` field of
// each inbound `group_message_sk` frame before touching the ciphertext.  That
// field is attacker-controlled bytes; `RingSignature::from_bytes` (the length
// gate) and `ring_verify` (canonical scalar parsing plus the challenge walk)
// are the two boundaries that must be total.
//
// # Attack surface
//
// Inputs may be empty, not a multiple of 32 bytes, the wrong size for the
// ring, scalars at or above the group order (malleability), or bit-flipped
// genuine signatures.  All must come back as `Err`, never a panic, and only
// a genuine signature over the fixture may verify.
//
// # Layout
//
// The in-tree harness `testing::fuzz::fuzz_ring_verify` consumes one size
// byte (selecting a deterministic fixture ring of 1..=4 members) followed by
// the candidate signature, and additionally feeds the first signature bytes
// back in as a hostile ring entry so the roster validator is fuzzed too.
//
// # Corpus
//
// `fuzz/corpus/fuzz_ring_verify/` holds one genuine n=2 signature over the
// fixture and a few malformed variants (truncated, non-canonical, empty).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The harness catches panics and reports them as `false`; a panic in the
    // verifier is a bug, so surface it as a fuzzer crash.
    assert!(mesh_infinity::testing::fuzz::fuzz_ring_verify(data));
});
