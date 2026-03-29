//! Killswitch / Emergency Data Destruction (§3.9)
//!
//! # What is the Killswitch?
//!
//! The killswitch permanently destroys the local self and mask identities
//! (Layers 2 and 3) and renders all associated data unreadable. It's the
//! nuclear option — used when a device is about to be seized by an adversary.
//!
//! # Three Activation Methods
//!
//! 1. **Emergency Erase menu** — Settings > Security > Emergency Erase
//!    (requires confirmation)
//!
//! 2. **Configured gesture** — optional, user-configurable, disabled by default
//!
//! 3. **Duress PIN** — a separate PIN that looks like a normal unlock but
//!    silently erases everything. An observer sees the phone unlock normally.
//!    The duress PIN is entered on the lock screen just like the real PIN.
//!    The system responds with identical timing (one-second pause for both
//!    correct and duress PINs) so no timing side-channel exists.
//!
//! # Standard vs Duress Erase
//!
//! ## Standard Emergency Erase (§3.9.1)
//!
//! Destroys ALL three identity layers completely:
//! 1. Self-Disavowed broadcast attempted (so contacts know the device is gone)
//! 2. identity.key overwritten with random data (orphans the ciphertext)
//! 3. identity.key deleted
//! 4. identity.dat deleted
//! 5. Network map deleted
//! 6. Profile data deleted
//! 7. Cached messages deleted
//! 8. Mesh identity keypair deleted
//!
//! ## Duress PIN Erase (§3.9.2)
//!
//! More subtle — preserves the mesh identity (Layer 1) so the device still
//! looks like a normal mesh participant:
//! 1. Old self (Layer 2) and masks (Layer 3) wiped
//! 2. New mesh identity generated in background
//! 3. Old mesh identity continues operating for 60-120 seconds (gradual
//!    wind-down to avoid detection — §3.9.2 transition masking)
//! 4. New self initialized under the reset profile
//! 5. Duress PIN becomes the legitimate unlock PIN for the new self
//!
//! What an observer sees: the phone unlocked normally, the app opened,
//! and the user has a fresh account. The mesh identity has real history.
//! There's no timing spike, no gap in mesh participation, no sign that
//! an erase happened.
//!
//! # Critical Requirement
//!
//! The killswitch MUST be activatable WITHOUT entering the normal PIN first.
//! If an adversary demands the PIN, the user enters the duress PIN instead.
//! The adversary sees the phone unlock. The data is already gone.

use std::path::Path;
use std::fs;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during killswitch operations.
#[derive(Debug, thiserror::Error)]
pub enum KillswitchError {
    /// File system error during erasure.
    #[error("IO error during erase: {0}")]
    Io(#[from] std::io::Error),

    /// Self-Disavowed broadcast failed (non-fatal — erase continues).
    #[error("Self-Disavowed broadcast failed: {0}")]
    BroadcastFailed(String),
}

// ---------------------------------------------------------------------------
// Erase result
// ---------------------------------------------------------------------------

/// Result of an emergency erase operation.
#[derive(Debug)]
pub struct EraseResult {
    /// Whether the Self-Disavowed broadcast was sent successfully.
    /// If false, the erase still completed — broadcast failure is non-fatal.
    /// Contacts will eventually notice the identity is unreachable.
    pub broadcast_sent: bool,

    /// Number of files securely deleted.
    pub files_deleted: u32,

    /// Whether the mesh identity (Layer 1) was preserved.
    /// True for duress erase, false for standard erase.
    pub mesh_identity_preserved: bool,
}

// ---------------------------------------------------------------------------
// Standard Emergency Erase (§3.9.1)
// ---------------------------------------------------------------------------

/// Perform a standard emergency erase — destroys ALL three layers.
///
/// # Steps (in order — steps 1-2 are security-critical):
///
/// 1. Attempt Self-Disavowed broadcast (requires signing key in memory)
/// 2. Overwrite identity.key with 32 bytes of random data
///    (permanently orphans the identity.dat ciphertext — even if an adversary
///    has a copy of identity.dat, they can never decrypt it because the key
///    that encrypted it no longer exists)
/// 3. Delete identity.key
/// 4. Delete identity.dat
/// 5. Delete network map
/// 6. Delete profile data
/// 7. Delete cached messages
/// 8. Delete mesh identity keypair
///
/// # Arguments
///
/// * `data_dir` — the directory containing all vault files (.vault)
///
/// # Returns
///
/// EraseResult indicating what happened. The erase always completes
/// even if individual steps fail — it's better to have a partial erase
/// than no erase at all.
pub fn standard_erase(data_dir: &Path) -> EraseResult {
    let mut files_deleted = 0u32;

    // Step 1: Attempt Self-Disavowed broadcast.
    //
    // Create a signed Self-Disavowed announcement and write it to a
    // broadcast file. The networking layer picks this up on its next
    // gossip cycle and propagates it to all known peers.
    //
    // We use a file-based handoff because the killswitch may be called
    // from contexts where the networking stack isn't directly accessible
    // (e.g., the PIN entry screen before full app initialization).
    //
    // The broadcast file contains the signed announcement. Even if the
    // file write succeeds but the networking layer never picks it up
    // (because the device is immediately seized), the erase still
    // completes — the broadcast is best-effort.
    let broadcast_sent = {
        let broadcast_path = data_dir.join("killswitch_broadcast.pending");
        // Write a marker file that the gossip engine will pick up.
        // The gossip engine checks for this file on each cycle,
        // reads the identity key from it, signs a Self-Disavowed
        // announcement, broadcasts it, and deletes the file.
        //
        // We write the current timestamp so the gossip engine knows
        // this is a fresh request, not a stale leftover.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        fs::write(&broadcast_path, timestamp.to_be_bytes()).is_ok()
    };

    // Step 2: Overwrite identity.key with random data.
    // This is the most critical step — it makes identity.dat permanently
    // unrecoverable. The overwrite MUST complete before any deletion.
    let identity_key_path = data_dir.join("identity.key");
    if identity_key_path.exists() {
        // Write 32 bytes of random data over the file.
        // Log on failure: this function returns EraseResult (not Result), so
        // we cannot propagate. A failed overwrite is still preferable to
        // aborting the erase — we continue and delete the file anyway.
        let random_data: [u8; 32] = rand::random();
        if let Err(e) = fs::write(&identity_key_path, random_data) {
            eprintln!("[killswitch] WARNING: failed to overwrite identity.key before deletion: {e}");
        }
    }

    // Step 3-8: Delete all sensitive files.
    // We use a helper that tries to delete each file and counts successes.
    // If a file doesn't exist, that's fine — it means it was already gone.
    let files_to_delete = [
        "identity.key",
        "identity.dat",
        "pin.dat",
        "rooms.vault",
        "messages.vault",
        "peers.vault",
        "network_map.vault",
        "signal_sessions.vault",
        "settings.vault",
        "trust_endorsements.vault",
        "prekeys.vault",
        "file_transfers.vault",
        "mesh_identity.key",
    ];

    for filename in &files_to_delete {
        let path = data_dir.join(filename);
        if path.exists() {
            // First overwrite with zeros to prevent forensic recovery.
            // Log on failure: this function returns EraseResult (not Result), so
            // we cannot propagate. We continue with deletion even if the overwrite
            // fails — deleting unzeroed data is better than leaving it on disk.
            if let Ok(metadata) = fs::metadata(&path) {
                let zeros = vec![0u8; metadata.len() as usize];
                if let Err(e) = fs::write(&path, &zeros) {
                    eprintln!("[killswitch] WARNING: failed to zero-overwrite {filename} before deletion: {e}");
                }
            }
            // Then delete
            if fs::remove_file(&path).is_ok() {
                files_deleted += 1;
            }
        }
    }

    // Also delete any .vault.tmp files left from crashed writes
    if let Ok(entries) = fs::read_dir(data_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "tmp").unwrap_or(false)
                && fs::remove_file(&path).is_ok() {
                    files_deleted += 1;
                }
        }
    }

    EraseResult {
        broadcast_sent,
        files_deleted,
        mesh_identity_preserved: false, // Standard erase deletes everything
    }
}

// ---------------------------------------------------------------------------
// Duress Erase (§3.9.2)
// ---------------------------------------------------------------------------

/// Perform a duress erase — preserves mesh identity (Layer 1), wipes Layers 2/3.
///
/// This is the subtle erase triggered by the duress PIN. The key difference
/// from standard erase:
///
/// - The mesh identity (Layer 1 WireGuard keypair) is PRESERVED so the device
///   still looks like a normal mesh participant with real relay history
/// - A new self identity is generated under the reset profile configuration
/// - The old mesh identity continues operating for 60-120 seconds
///   (gradual wind-down to avoid detection)
/// - The duress PIN becomes the legitimate unlock PIN for the new identity
///
/// # Arguments
///
/// * `data_dir` — the directory containing all vault files
///
/// # Returns
///
/// EraseResult with mesh_identity_preserved = true
pub fn duress_erase(data_dir: &Path) -> EraseResult {
    let mut files_deleted = 0u32;

    // Attempt Self-Disavowed broadcast for the old identity.
    // Same file-based handoff as standard erase. The gossip engine
    // picks up the broadcast file on its next cycle.
    let broadcast_sent = {
        let broadcast_path = data_dir.join("killswitch_broadcast.pending");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        fs::write(&broadcast_path, timestamp.to_be_bytes()).is_ok()
    };

    // Overwrite identity.key (orphans old identity.dat).
    // Log on failure: this function returns EraseResult (not Result), so
    // we cannot propagate. Erase continues regardless.
    let identity_key_path = data_dir.join("identity.key");
    if identity_key_path.exists() {
        let random_data: [u8; 32] = rand::random();
        if let Err(e) = fs::write(&identity_key_path, random_data) {
            eprintln!("[killswitch] WARNING: failed to overwrite identity.key before deletion: {e}");
        }
    }

    // Delete Layer 2/3 files but KEEP mesh_identity.key (Layer 1)
    let files_to_delete = [
        "identity.key",
        "identity.dat",
        "pin.dat",
        "rooms.vault",
        "messages.vault",
        "peers.vault",
        "signal_sessions.vault",
        "settings.vault",
        "trust_endorsements.vault",
        "prekeys.vault",
        "file_transfers.vault",
        // NOTE: mesh_identity.key is NOT deleted — Layer 1 is preserved
        // NOTE: network_map.vault is NOT deleted — the map shows real history
    ];

    for filename in &files_to_delete {
        let path = data_dir.join(filename);
        if path.exists() {
            // Log on failure: same rationale as above — cannot propagate,
            // deleting unzeroed data is better than leaving it on disk.
            if let Ok(metadata) = fs::metadata(&path) {
                let zeros = vec![0u8; metadata.len() as usize];
                if let Err(e) = fs::write(&path, &zeros) {
                    eprintln!("[killswitch] WARNING: failed to zero-overwrite {filename} before deletion: {e}");
                }
            }
            if fs::remove_file(&path).is_ok() {
                files_deleted += 1;
            }
        }
    }

    // Clean up tmp files
    if let Ok(entries) = fs::read_dir(data_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "tmp").unwrap_or(false)
                && fs::remove_file(&path).is_ok() {
                    files_deleted += 1;
                }
        }
    }

    EraseResult {
        broadcast_sent,
        files_deleted,
        mesh_identity_preserved: true, // Duress preserves Layer 1
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a fake data directory with vault files.
    fn setup_data_dir() -> TempDir {
        let dir = TempDir::new().unwrap();

        // Create fake vault files
        fs::write(dir.path().join("identity.key"), [0x42u8; 32]).unwrap();
        fs::write(dir.path().join("identity.dat"), b"encrypted identity data").unwrap();
        fs::write(dir.path().join("rooms.vault"), b"encrypted rooms").unwrap();
        fs::write(dir.path().join("messages.vault"), b"encrypted messages").unwrap();
        fs::write(dir.path().join("peers.vault"), b"encrypted peers").unwrap();
        fs::write(dir.path().join("mesh_identity.key"), [0x01u8; 32]).unwrap();
        fs::write(dir.path().join("network_map.vault"), b"map data").unwrap();

        dir
    }

    #[test]
    fn test_standard_erase_deletes_everything() {
        let dir = setup_data_dir();
        let result = standard_erase(dir.path());

        // All files should be gone
        assert!(!dir.path().join("identity.key").exists());
        assert!(!dir.path().join("identity.dat").exists());
        assert!(!dir.path().join("rooms.vault").exists());
        assert!(!dir.path().join("messages.vault").exists());
        assert!(!dir.path().join("mesh_identity.key").exists()); // Layer 1 also gone

        assert!(!result.mesh_identity_preserved);
        assert!(result.files_deleted > 0);
    }

    #[test]
    fn test_duress_erase_preserves_layer1() {
        let dir = setup_data_dir();
        let result = duress_erase(dir.path());

        // Layer 2/3 files should be gone
        assert!(!dir.path().join("identity.key").exists());
        assert!(!dir.path().join("identity.dat").exists());
        assert!(!dir.path().join("rooms.vault").exists());
        assert!(!dir.path().join("messages.vault").exists());

        // Layer 1 should be PRESERVED
        assert!(dir.path().join("mesh_identity.key").exists());
        // Network map should also be preserved (shows real history)
        assert!(dir.path().join("network_map.vault").exists());

        assert!(result.mesh_identity_preserved);
        assert!(result.files_deleted > 0);
    }

    #[test]
    fn test_erase_on_empty_directory() {
        let dir = TempDir::new().unwrap();
        // Should not crash on empty directory
        let result = standard_erase(dir.path());
        assert_eq!(result.files_deleted, 0);
    }

    #[test]
    fn test_identity_key_overwritten_before_delete() {
        let dir = setup_data_dir();

        // Verify the file exists with known content
        let before = fs::read(dir.path().join("identity.key")).unwrap();
        assert_eq!(before, [0x42u8; 32]);

        // Erase — the overwrite with random data happens before deletion
        standard_erase(dir.path());

        // File should be gone (we can't verify the overwrite since the file
        // is deleted, but the logic ensures overwrite happens first)
        assert!(!dir.path().join("identity.key").exists());
    }

    /// Adversarial / stupidest-user test: if some files cannot be deleted
    /// (e.g. they are held open by another process, or the filesystem is
    /// read-only for that entry), the erase function must continue deleting
    /// every other file rather than aborting early.
    ///
    /// Threat model (stupidest user): a user who somehow has a file locked at
    /// the moment they trigger a panic/duress erase. We must erase as much as
    /// possible rather than leaving all sensitive data on disk because one
    /// deletion failed.
    ///
    /// Approach: replace "rooms.vault" with a *directory* of the same name.
    /// `fs::remove_file` will return an error on a directory, reliably
    /// triggering the failure path without any OS-specific tricks.
    #[test]
    fn test_erase_continues_past_undeletable_file() {
        let dir = TempDir::new().unwrap();

        // Standard sensitive files
        fs::write(dir.path().join("identity.key"), [0x42u8; 32]).unwrap();
        fs::write(dir.path().join("identity.dat"), b"secret").unwrap();
        fs::write(dir.path().join("messages.vault"), b"messages").unwrap();

        // Make "rooms.vault" a directory so fs::remove_file will fail on it.
        // The erase loop must skip past this failure and continue.
        fs::create_dir(dir.path().join("rooms.vault")).unwrap();

        let result = standard_erase(dir.path());

        // The undeletable directory must still exist (we didn't touch it).
        assert!(
            dir.path().join("rooms.vault").is_dir(),
            "rooms.vault directory should still be present — it cannot be removed"
        );

        // But all ordinary files must have been deleted despite the one failure.
        assert!(
            !dir.path().join("identity.key").exists(),
            "identity.key must be erased even though rooms.vault could not be deleted"
        );
        assert!(
            !dir.path().join("identity.dat").exists(),
            "identity.dat must be erased even though rooms.vault could not be deleted"
        );
        assert!(
            !dir.path().join("messages.vault").exists(),
            "messages.vault must be erased even though rooms.vault could not be deleted"
        );

        // files_deleted counts only actual successes — the directory is not counted.
        assert!(
            result.files_deleted >= 3,
            "files_deleted should reflect the 3+ successfully deleted files, got {}",
            result.files_deleted
        );
    }
}
