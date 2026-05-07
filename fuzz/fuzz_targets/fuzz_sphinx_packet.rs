// Fuzz target: Sphinx packet peel-layer (§11.3 mixnet transport)
//
// Drives `sphinx_peel_layer()` with arbitrary header bytes and a random node
// private key to ensure:
// - No panics on malformed or truncated headers.
// - All error paths return `Err` rather than panicking.
// - No unsafe memory access when the header contains garbage values.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::transport::mixnet::{sphinx_peel_layer, SPHINX_HEADER_SIZE};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + SPHINX_HEADER_SIZE {
        // Need at least: 32 bytes node privkey + SPHINX_HEADER_SIZE bytes header.
        return;
    }

    // First 32 bytes → node private key.
    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(&data[..32]);

    // Next SPHINX_HEADER_SIZE bytes → header to peel.
    let header_bytes = &data[32..32 + SPHINX_HEADER_SIZE];
    let header: &[u8; SPHINX_HEADER_SIZE] = header_bytes.try_into().unwrap();

    // Seed an RNG deterministically from the fuzz input so runs are reproducible.
    let mut seed = [0u8; 32];
    let remaining = &data[32 + SPHINX_HEADER_SIZE..];
    let seed_len = seed.len().min(remaining.len());
    seed[..seed_len].copy_from_slice(&remaining[..seed_len]);
    let mut rng = ChaCha20Rng::from_seed(seed);

    // Must not panic regardless of input.
    let _ = sphinx_peel_layer(header, &privkey, &mut rng);
});
