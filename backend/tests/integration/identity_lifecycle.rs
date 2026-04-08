// backend/tests/integration/identity_lifecycle.rs — Identity lifecycle integration tests (§21.1.2)
//
// # What is tested here
//
// The identity lifecycle is the most security-critical flow in Mesh Infinity:
// an identity is the user's cryptographic persona on the mesh.  Each identity
// consists of an Ed25519 keypair (for signing) and an X25519 keypair (for
// key agreement).  The peer ID is the SHA-256 hash of the Ed25519 public key.
//
// These tests verify that:
//   1. A newly generated identity can be round-tripped through disk storage.
//   2. The peer ID is stable across save → reload.
//   3. A PIN-protected identity rejects wrong PINs and accepts the correct PIN.
//   4. A locked identity cannot be used until unlocked.
//
// # Why integration tests (not unit tests)?
//
// Identity persistence touches the crypto layer (key wrapping), the filesystem
// (serialization), and the identity module (key generation and validation) all
// at once.  Unit tests for each layer in isolation cannot catch bugs at the
// boundaries between them.

use std::path::PathBuf;

use mesh_infinity::identity::self_identity::SelfIdentity;

// ---------------------------------------------------------------------------
// Helper: temporary directory for each test
// ---------------------------------------------------------------------------

/// Returns a PathBuf to a unique temporary directory that is automatically
/// deleted when the `TempDir` guard returned alongside it is dropped.
///
/// Using `tempfile::TempDir` ensures that even if a test panics, the
/// temporary files are cleaned up — tests must never leave state on disk.
fn temp_dir() -> (tempfile::TempDir, PathBuf) {
    // tempfile::TempDir creates a randomly-named subdirectory under the OS
    // temporary directory (e.g. /tmp/tmp.XXXXXXXX on Linux).
    let dir = tempfile::TempDir::new().expect("failed to create temp dir");
    let path = dir.path().to_path_buf();
    (dir, path)
}

// ---------------------------------------------------------------------------
// Test 1: Create → save → reload (no PIN)
// ---------------------------------------------------------------------------

/// Generate an identity, save it to disk without a PIN, reload it, and verify
/// that the peer ID is identical after the round-trip.
///
/// This is the happy path for the most common case: a user running without a
/// PIN.  If this fails, identity persistence is broken.
#[test]
fn test_identity_create_save_reload_no_pin() {
    // Create a temporary data directory.  The `_dir` variable must be kept
    // in scope until the end of the test — when it drops, the directory is
    // deleted.  Prefix with `_` signals it's only kept for its Drop side-effect.
    let (_dir, data_dir) = temp_dir();

    // Step 1: Generate a fresh identity.
    // `generate()` creates a new Ed25519 + X25519 keypair from OS randomness.
    // `None` means no display name is set.
    let identity = SelfIdentity::generate(None);

    // Record the peer ID before saving so we can compare it after reloading.
    let original_peer_id = identity.peer_id();

    // Step 2: Save the identity to disk without a PIN.
    // This serializes the identity, encrypts it with a randomly-generated
    // master key (stored in the OS keychain), and writes it to data_dir.
    identity
        .save_to_disk(&data_dir, None)
        .expect("identity save_to_disk failed");

    // Step 3: Reload the identity from disk without a PIN.
    // This reads the files, retrieves the master key from the OS keychain,
    // decrypts, and reconstructs the keypairs.
    let reloaded = SelfIdentity::load_from_disk(&data_dir, None)
        .expect("identity load_from_disk failed");

    // Step 4: Verify the peer ID survived the round-trip.
    // The peer ID is derived from the public key, so if this matches, the
    // entire keypair was preserved correctly.
    assert_eq!(
        reloaded.peer_id(),
        original_peer_id,
        "peer ID changed after save → reload round-trip"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Create → save with PIN → reload with wrong PIN → reject
//         → reload with correct PIN → accept
// ---------------------------------------------------------------------------

/// Verify that PIN-protected identity storage:
///   - Rejects a wrong PIN with an error (not a panic or silent corruption)
///   - Accepts the correct PIN and restores the identity with the same peer ID
///
/// This tests the PIN-wrap key derivation (Argon2id) and the authenticated
/// encryption of the identity payload (ChaCha20-Poly1305).
#[test]
fn test_identity_pin_protection() {
    let (_dir, data_dir) = temp_dir();

    // Generate a fresh identity.
    let identity = SelfIdentity::generate(Some("Test User".to_string()));
    let original_peer_id = identity.peer_id();

    // Save with a PIN.  The PIN wraps the master key using Argon2id so that
    // without the PIN, the encrypted key blob is unrecoverable.
    let correct_pin = "hunter2";
    identity
        .save_to_disk(&data_dir, Some(correct_pin))
        .expect("identity save_to_disk with PIN failed");

    // Attempt to load with the WRONG PIN.  This should return an Err, not panic.
    let wrong_result = SelfIdentity::load_from_disk(&data_dir, Some("wrongpassword"));
    assert!(
        wrong_result.is_err(),
        "loading with wrong PIN should return Err, got Ok instead"
    );

    // Load with the CORRECT PIN — must succeed.
    let reloaded = SelfIdentity::load_from_disk(&data_dir, Some(correct_pin))
        .expect("identity load_from_disk with correct PIN failed");

    // Verify peer ID stability across the PIN-protected round-trip.
    assert_eq!(
        reloaded.peer_id(),
        original_peer_id,
        "peer ID changed after PIN-protected save → reload round-trip"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Payload round-trip (serialize → deserialize)
// ---------------------------------------------------------------------------

/// Verify that `serialize_payload` and `from_payload` form a lossless
/// round-trip for the identity payload bytes.
///
/// This is a lower-level test that validates the binary serialization format
/// independently of the disk I/O layer — useful for catching regressions in
/// the payload encoding without needing a filesystem.
#[test]
fn test_identity_payload_roundtrip() {
    // Generate an identity with a display name so the optional name field
    // is exercised.
    let identity = SelfIdentity::generate(Some("Alice".to_string()));
    let original_peer_id = identity.peer_id();

    // Serialize to raw bytes.  The payload is a Zeroizing<Vec<u8>> to ensure
    // the secret key bytes are wiped from memory when the variable is dropped.
    let payload = identity.serialize_payload();

    // Deserialize back from raw bytes.
    let restored = SelfIdentity::from_payload(&payload)
        .expect("from_payload returned None for a valid payload");

    // Verify that the peer ID (derived from the public key) is preserved.
    assert_eq!(
        restored.peer_id(),
        original_peer_id,
        "peer ID changed across serialize_payload → from_payload"
    );
}
