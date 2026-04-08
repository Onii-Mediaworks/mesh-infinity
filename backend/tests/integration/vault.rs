// backend/tests/integration/vault.rs — Vault persistence integration tests (§21.1.2)
//
// # What is tested here
//
// The vault is Mesh Infinity's encrypted key-value store for persistent data
// (rooms, contacts, settings, routing state).  The spec requires:
// "create identity → write rooms/contacts → reload from disk → verify intact."
//
// These tests verify:
//   1. A VaultManager can be created with a given data directory and master key.
//   2. A value written to a VaultCollection survives a save → new manager → load.
//   3. Deleting a vault entry makes it unretrievable on the next load.
//   4. A VaultCollection that has never had a value written returns None on load.
//
// # Why VaultManager directly?
//
// The spec says to test "vault persistence" — the atomic unit of that is
// VaultManager + VaultCollection.  Testing through the full runtime is also
// valid, but the runtime's vault API is not yet stabilized.  Testing the vault
// layer directly gives the most precise failure messages.
//
// # Master key in tests
//
// Tests use a hard-coded 32-byte master key of all zeros.  This is safe for
// testing because:
//   - The vault is encrypted with this key; test data has no real secrets.
//   - Using a fixed key makes tests deterministic and reproducible.
//   - The real runtime derives the master key from the OS keychain, which is
//     not available in CI without a user session.

use mesh_infinity::storage::vault::VaultManager;

// ---------------------------------------------------------------------------
// Helper: all-zeros master key (safe for tests — no real secrets)
// ---------------------------------------------------------------------------

/// A 32-byte master key filled with zeros.  Used only in tests; real keys
/// are derived from OS-protected storage (keychain, DPAPI).
const TEST_MASTER_KEY: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Helper: create a VaultManager backed by a temp directory
// ---------------------------------------------------------------------------

/// Create a `VaultManager` whose data lives in a newly-created temporary
/// directory.  Returns the `TempDir` guard (which must be kept alive for the
/// duration of the test) alongside the manager.
fn temp_vault() -> (tempfile::TempDir, VaultManager) {
    let dir = tempfile::TempDir::new().expect("failed to create temp dir");
    let manager = VaultManager::new(dir.path().to_path_buf(), TEST_MASTER_KEY);
    (dir, manager)
}

// ---------------------------------------------------------------------------
// Test 1: Write a value → reload from a new VaultManager → value is intact
// ---------------------------------------------------------------------------

/// The core vault persistence test: write a serializable value, then open a
/// new VaultManager pointing at the same directory, and verify the value is
/// exactly equal to what was written.
///
/// This exercises the full path:
///   VaultManager::collection → VaultCollection::save → disk
///   → new VaultManager::collection → VaultCollection::load → assert equality
#[test]
fn test_vault_write_reload_survives() {
    let (dir, manager_1) = temp_vault();

    // Use a simple String as the test value.  VaultCollection uses serde
    // for serialization, so any Serialize + DeserializeOwned type works.
    let collection_name = "test_settings";
    let stored_value = "hello from vault".to_string();

    // Open the collection and write the value.
    let collection = manager_1
        .collection(collection_name)
        .expect("failed to open vault collection for writing");

    collection
        .save(&stored_value)
        .expect("vault save failed");

    // Drop manager_1 so no in-memory state is shared with manager_2.
    drop(manager_1);

    // Open a new VaultManager pointing at the same directory and master key.
    // This simulates a runtime restart — no cached state survives.
    let manager_2 = VaultManager::new(dir.path().to_path_buf(), TEST_MASTER_KEY);

    let collection_2 = manager_2
        .collection(collection_name)
        .expect("failed to open vault collection for reading");

    // Load the value.  It must equal what we stored.
    let loaded: Option<String> = collection_2.load().expect("vault load failed");

    assert_eq!(
        loaded,
        Some(stored_value),
        "vault value did not survive manager restart"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Unwritten collection returns None (not an error)
// ---------------------------------------------------------------------------

/// Loading from a VaultCollection that has never been written to must return
/// `Ok(None)`, not an error.  This is the expected behaviour when the app
/// starts for the first time and no data has been persisted yet.
#[test]
fn test_vault_empty_collection_returns_none() {
    let (_dir, manager) = temp_vault();

    // Open a collection that we have NOT written to.
    let collection = manager
        .collection("never_written")
        .expect("failed to open fresh vault collection");

    // Load should succeed and return None.
    let loaded: Option<String> = collection.load().expect("vault load on empty collection failed");

    assert!(
        loaded.is_none(),
        "loading from an empty vault collection should return None, got Some"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Write → delete → reload returns None
// ---------------------------------------------------------------------------

/// After deleting a vault entry, a subsequent load from a fresh VaultManager
/// must return `Ok(None)` — the entry must not reappear.
#[test]
fn test_vault_delete_removes_entry() {
    let (dir, manager_1) = temp_vault();

    let collection_name = "deletable_entry";
    let stored_value = 42u64;

    // Write the value.
    let collection = manager_1
        .collection(collection_name)
        .expect("failed to open vault collection");

    collection
        .save(&stored_value)
        .expect("vault save failed");

    // Verify it exists (belt-and-suspenders: confirm save worked).
    let check: Option<u64> = collection.load().expect("vault load after save failed");
    assert_eq!(check, Some(stored_value), "vault save did not persist in-process");

    // Delete the entry.
    collection.delete().expect("vault delete failed");

    drop(manager_1);

    // Reload from a new manager — the entry must not be present.
    let manager_2 = VaultManager::new(dir.path().to_path_buf(), TEST_MASTER_KEY);
    let collection_2 = manager_2
        .collection(collection_name)
        .expect("failed to open vault collection after delete");

    let loaded: Option<u64> = collection_2.load().expect("vault load after delete failed");

    assert!(
        loaded.is_none(),
        "vault entry was still present after delete + manager restart"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Wrong master key cannot decrypt the vault
// ---------------------------------------------------------------------------

/// Attempting to load a vault entry using a different master key than the one
/// used to write it must fail (return Err), not silently return corrupted data
/// and not panic.
///
/// This verifies that the authenticated encryption (ChaCha20-Poly1305) is
/// correctly applied and that the authentication tag check rejects wrong keys.
#[test]
fn test_vault_wrong_key_cannot_decrypt() {
    let (dir, manager_correct) = temp_vault();

    let collection_name = "encrypted_entry";
    let stored_value = "secret data".to_string();

    // Write with the correct (all-zeros) key.
    let collection = manager_correct
        .collection(collection_name)
        .expect("failed to open vault collection");
    collection
        .save(&stored_value)
        .expect("vault save failed");

    drop(manager_correct);

    // Try to read with a different key (all-ones).
    let wrong_key = [0xFFu8; 32];
    let manager_wrong = VaultManager::new(dir.path().to_path_buf(), wrong_key);
    let collection_wrong = manager_wrong
        .collection(collection_name)
        .expect("failed to open vault collection with wrong key");

    // Loading must return an Err — decryption must fail, not produce garbage.
    let result: Result<Option<String>, _> = collection_wrong.load();
    assert!(
        result.is_err(),
        "vault load with wrong key should return Err (authentication failed), got Ok"
    );
}
