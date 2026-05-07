// Fuzz target: encrypted offline bundle decode (§5.28)
//
// Drives `OfflineBundle::open_as_recipient()` with:
// - arbitrary raw data as the bundle bytes
// - a deterministic recipient X25519 secret key derived from the fuzz seed
//
// Ensures:
// - No panics on malformed, truncated, or garbage encrypted bundle data.
// - AEAD authentication failures return `Err` rather than panicking.
// - Partial or corrupt magic/version/length fields are handled gracefully.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::transport::offline_bundle::OfflineBundle;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        // Need at least 32 bytes to derive a recipient secret key.
        return;
    }

    // First 32 bytes → deterministic recipient X25519 secret key.
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&data[..32]);

    // Rest of the data → bundle bytes to try to decode.
    let bundle_bytes = &data[32..];

    // Must not panic regardless of input.
    let _ = OfflineBundle::open_as_recipient(bundle_bytes, &secret);
});
