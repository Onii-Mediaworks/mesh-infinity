// fuzz_targets/fuzz_backup_restore.rs — Backup envelope parser fuzz target (§3.7.4)
//
// # What this target tests
//
// `import_identity_backup` (FFI) accepts a base64/JSON blob the user picked
// from disk or a cloud folder and feeds it to `restore_backup`. The envelope
// header (version, type, Argon2id parameters, salt, nonce) is plaintext and
// attacker-controlled. `validate_envelope` is the gate that must reject every
// malformed or hostile header *before* the KDF runs: it is the only thing
// standing between a tampered file and a 4 TiB Argon2 allocation.
//
// # Attack surface
//
// Inputs may be random bytes, structurally valid JSON with wrong types,
// absurd `m_cost`/`t_cost`/`p_cost`, empty or multi-megabyte salts, wrong
// nonce lengths, unknown versions, or unknown backup types. All must come
// back as `Err`, never a panic, and never reach `derive_backup_key`.
//
// # Why not call restore_backup directly
//
// A structurally valid envelope legitimately costs one 64 MiB / t=3 / p=4
// Argon2id derivation (hundreds of ms). That would throttle the fuzzer to a
// few executions per second and tell us nothing new about the parser. The
// KDF is covered by unit tests; the parser and gate are what need coverage.
//
// # Corpus
//
// `fuzz/corpus/fuzz_backup_restore/` holds one minimal valid version-2
// envelope and a few malformed variants.

#![no_main]

use libfuzzer_sys::fuzz_target;

use mesh_infinity::crypto::backup::{validate_envelope, EncryptedBackup};

fuzz_target!(|data: &[u8]| {
    // JSON deserialization must be total: any Err is fine, panics are not.
    if let Ok(envelope) = serde_json::from_slice::<EncryptedBackup>(data) {
        // The structural gate must also be total over any parsed envelope.
        let _ = validate_envelope(&envelope);
    }
});
