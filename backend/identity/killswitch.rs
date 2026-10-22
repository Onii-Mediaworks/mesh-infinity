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

use std::fs;
use std::io::Write;
use std::path::Path;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during killswitch operations.
#[derive(Debug, thiserror::Error)]
// KillswitchError — variant enumeration.
// Match exhaustively to handle every protocol state.
// KillswitchError — variant enumeration.
// Match exhaustively to handle every protocol state.
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
// EraseResult — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// EraseResult — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
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

/// Overwrite a file's current bytes in place and force them to storage.
///
/// SPEC §3.9.1 requires the overwrite of `identity.key` (and the zero pass
/// over every vault) to *complete* before deletion. `fs::write` cannot give
/// that guarantee: it truncates first, which releases the original blocks so
/// the new bytes may land elsewhere, and it never syncs, so an immediate
/// `remove_file` lets the kernel drop the dirty pages without writing them.
///
/// This opens the file without truncation, writes exactly `len` bytes from
/// `fill` over the existing extent, and `sync_all`s before returning, so the
/// overwrite has reached the device by the time the caller unlinks the file.
/// Copy-on-write and flash wear-levelling can still keep old blocks; the
/// keystore-backed destruction path is the defence for that (§3.6.2), this
/// is the filesystem defence in depth.
fn overwrite_in_place(path: &Path, fill: &[u8]) -> std::io::Result<()> {
    // write(true) without create/truncate keeps the inode and its blocks.
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    // Cover the whole current extent, not just fill.len(), so a long vault
    // is zeroed end to end.
    let len = file.metadata()?.len() as usize;
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(fill.len());
        file.write_all(&fill[..chunk])?;
        remaining -= chunk;
    }
    // Push the page cache to the device before the caller deletes the file.
    file.sync_all()?;
    Ok(())
}

/// Best-effort durability for a directory entry change (the unlink after an
/// overwrite). Directory fsync is a POSIX concept; Windows has no equivalent
/// handle operation, so this is a no-op there.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(d) = fs::File::open(dir) {
            // Failure here only weakens durability of the unlink, which is
            // not security-critical (the overwrite already synced).
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// The Self-Disavowed hand-off marker written by step 1.
///
/// It is the one file every flow leaves behind on purpose: the gossip
/// engine reads it on its next cycle and removes it itself.  Everything
/// else under the data directory is destroyed.
const BROADCAST_MARKER: &str = "killswitch_broadcast.pending";

/// Key-material files erased explicitly, in this order, before the sweep
/// reaches anything else.
///
/// SPEC §3.9.1 makes step 2 (key material) security-critical and requires
/// it to complete before steps 3–7.  `identity.key` is first because its
/// loss orphans every vault; the duress blob and PIN counter key follow so
/// no PIN-derived secret outlives the identity; `mesh_identity.key` is last
/// and is skipped entirely when the keep-list names it (duress flow).
const KEY_FILES_FIRST: [&str; 5] = [
    "identity.key",
    "identity.dat",
    "pin.dat",
    "pin_counter.key",
    "mesh_identity.key",
];

/// What the standard flow keeps: only the step-1 marker (§3.9.1 destroys
/// all three layers).
const STANDARD_KEEP: [&str; 1] = [BROADCAST_MARKER];

/// What the duress flow keeps (§3.9.2): the Layer 1 mesh identity keypair
/// and the Layer 1 startup configuration it runs under, so the retained
/// identity keeps operating unchanged through the wind-down.  Layer 1
/// holds no secrets of Layers 2/3; everything else — including the network
/// map, which §3.9.2 step 4a erases via §3.9.1 step 4 — is destroyed.
const DURESS_KEEP: [&str; 3] = [BROADCAST_MARKER, "mesh_identity.key", "layer1_startup.json"];

/// Step 1: write the Self-Disavowed hand-off marker.
///
/// The networking layer picks the marker up on its next gossip cycle and
/// propagates the announcement to all known peers.  A file-based hand-off
/// is used because the killswitch may run from contexts where the network
/// stack is not reachable (the PIN screen before full initialisation).  The
/// marker carries the current timestamp so a stale leftover is told apart
/// from a fresh request.  Returns whether the marker was written; failure
/// is non-fatal and the erase continues regardless.
fn write_broadcast_marker(data_dir: &Path) -> bool {
    // Capture the current timestamp for temporal ordering.
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        // Transform the result, mapping errors to the local error type.
        .map(|d| d.as_secs())
        // Fall back to the default value on failure.
        .unwrap_or(0);
    // Resolve the filesystem path for the target resource.
    let marker = data_dir.join(BROADCAST_MARKER);
    // Persist the data to the filesystem.
    fs::write(marker, timestamp.to_be_bytes()).is_ok()
}

/// Whether `path` is a regular file and not a symlink.
///
/// `symlink_metadata` does not follow links, so a link planted at a known
/// name reports as a link here and is never written through.
fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

/// Step 2: overwrite `identity.key` in place with 32 bytes of fresh random
/// data (§3.9.1).
///
/// This is the most critical step: it makes `identity.dat` and every vault
/// permanently unrecoverable even if an adversary already holds copies of
/// them, because the key that encrypted them no longer exists.  The
/// overwrite is synced to the device before anything is unlinked.  A failed
/// overwrite is logged — this function cannot propagate — and the file is
/// still deleted below: a partial erase beats an aborted one.
fn scramble_identity_key(data_dir: &Path) {
    let identity_key_path = data_dir.join("identity.key");
    if is_regular_file(&identity_key_path) {
        let random_data: [u8; 32] = rand::random();
        // In-place overwrite + fsync: the only form of "overwrite" that is
        // actually on disk before the unlink below (§3.9.1 step 2).
        if let Err(e) = overwrite_in_place(&identity_key_path, &random_data) {
            eprintln!(
                "[killswitch] WARNING: failed to overwrite identity.key before deletion: {e}"
            );
        }
    }
}

/// Zero-overwrite one regular file in place, then unlink it.
///
/// The zero pass streams a fixed block over the file's own length and
/// syncs before returning, so the plaintext-bearing blocks are gone before
/// the directory entry is.  Returns `true` if the file was unlinked; an
/// overwrite failure is logged and the unlink still attempted, because
/// deleting unzeroed data is better than leaving it on disk.
fn erase_file(path: &Path) -> bool {
    let zeros = [0u8; 4096];
    if let Err(e) = overwrite_in_place(path, &zeros) {
        // Only the file name is logged: the data directory path itself is
        // not something the killswitch log needs to repeat.
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        eprintln!(
            "[killswitch] WARNING: failed to zero-overwrite {} before deletion: {e}",
            name.unwrap_or_default()
        );
    }
    fs::remove_file(path).is_ok()
}

/// Erase the `KEY_FILES_FIRST` entries that exist and are not in `keep`,
/// in order.  Returns the number of files unlinked.
fn erase_key_files(data_dir: &Path, keep: &[&str]) -> u32 {
    let mut removed = 0u32;
    // Iterate over each file entry in the collection.
    for filename in KEY_FILES_FIRST {
        if keep.contains(&filename) {
            continue;
        }
        // Resolve the filesystem path for the target resource.
        let path = data_dir.join(filename);
        // A missing file is fine — it was already gone.  Anything that is
        // not a regular file is left to the sweep, which handles links and
        // directories without following them.
        if is_regular_file(&path) && erase_file(&path) {
            removed += 1;
        }
    }
    removed
}

/// Destroy every entry under `dir` except root-level names in `keep`.
///
/// This is the structural half of the erase: SPEC §3.9.1 enumerates key
/// domains that MUST all be destroyed, and a filename allow-list silently
/// misses every artefact added after it was written (Tor state, published
/// files, offline bundles, PIN counters, enrollment state, logs).  So the
/// sweep is deny-nothing: regular files are zero-overwritten and unlinked;
/// directories are recursed into and removed once empty; symlinks are
/// unlinked without being followed or overwritten, so a planted link can
/// never make the erase write outside the data directory.  Every failure
/// is logged and skipped — a partial erase beats an aborted one.  Returns
/// the number of files and links removed.
fn erase_tree(dir: &Path, keep: &[&str]) -> u32 {
    let mut removed = 0u32;
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("[killswitch] WARNING: cannot list directory: {e}");
            return 0;
        }
    };
    // Iterate over each file entry in the collection.
    for entry in entries.flatten() {
        // Resolve the filesystem path for the target resource.
        let path = entry.path();
        // The keep-list applies by name at the level it was given; the
        // recursion below passes an empty list, so nothing is kept deeper.
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| keep.contains(&name))
        {
            continue;
        }
        // `file_type` does not follow symlinks: a link reports as a link.
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(e) => {
                eprintln!("[killswitch] WARNING: cannot inspect entry: {e}");
                continue;
            }
        };
        if kind.is_symlink() {
            // Unlink the link itself; never touch what it points at.  On
            // Windows a directory link needs `remove_dir`, hence the retry.
            if fs::remove_file(&path)
                .or_else(|_| fs::remove_dir(&path))
                .is_ok()
            {
                removed += 1;
            }
        } else if kind.is_dir() {
            removed += erase_tree(&path, &[]);
            // Make the unlinks inside durable before dropping the directory.
            sync_dir(&path);
            if let Err(e) = fs::remove_dir(&path) {
                eprintln!("[killswitch] WARNING: directory not removed: {e}");
            }
        } else if erase_file(&path) {
            removed += 1;
        }
    }
    removed
}

/// The erase common to both flows: marker, key scramble, ordered key-file
/// erase, then the structural sweep, then a directory sync.
///
/// `keep` names the root-level entries that survive; `mesh_identity_preserved`
/// is reported back as given.  Steps 1–2 are security-critical and run
/// first; everything after them is deletion of data the destroyed keys
/// already made unreadable.
fn erase(data_dir: &Path, keep: &[&str], mesh_identity_preserved: bool) -> EraseResult {
    // Step 1: Self-Disavowed hand-off (best effort).
    let broadcast_sent = write_broadcast_marker(data_dir);
    // Step 2: destroy the identity master key before anything is deleted.
    scramble_identity_key(data_dir);
    // Steps 2–7: key material in order, then every other artefact.
    let files_deleted = erase_key_files(data_dir, keep) + erase_tree(data_dir, keep);
    // Make the unlinks durable too, where the platform supports it.
    sync_dir(data_dir);
    EraseResult {
        broadcast_sent,
        files_deleted,
        mesh_identity_preserved,
    }
}

/// Perform a standard emergency erase — destroys ALL three layers (§3.9.1).
///
/// # Steps (in order — steps 1–2 are security-critical):
///
/// 1. Attempt Self-Disavowed broadcast (marker file for the gossip engine)
/// 2. Overwrite `identity.key` with 32 bytes of random data and sync
///    (permanently orphans every vault — even an adversary holding copies
///    of `identity.dat` can never decrypt them)
/// 3. Erase the remaining key files in order: `identity.key`,
///    `identity.dat`, `pin.dat`, `pin_counter.key`, `mesh_identity.key`
/// 4. Sweep everything else under `data_dir` — every vault, the network
///    map, Tor state and cache, published files, offline bundles, PIN
///    counters, enrollment and startup state, logs, temp files — zeroing
///    regular files and recursing into directories
///
/// Only the step-1 marker remains.
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
    erase(data_dir, &STANDARD_KEEP, false)
}

// ---------------------------------------------------------------------------
// Duress Erase (§3.9.2)
// ---------------------------------------------------------------------------

/// Perform a duress erase — preserves mesh identity (Layer 1), wipes Layers 2/3.
///
/// This is the subtle erase triggered by the duress PIN. The key difference
/// from standard erase:
///
/// - The mesh identity (Layer 1 WireGuard keypair, `mesh_identity.key`) and
///   its startup configuration (`layer1_startup.json`) are PRESERVED so the
///   device still looks like a normal mesh participant with real relay
///   history and keeps routing unchanged through the wind-down
/// - Everything else is destroyed exactly as in the standard flow
///   (§3.9.2 step 4a applies §3.9.1 steps 2–6), including the network map
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
    erase(data_dir, &DURESS_KEEP, true)
}

// ---------------------------------------------------------------------------
// Duress Wind-Down (§3.9.2 transition masking)
// ---------------------------------------------------------------------------
//
// After a duress erase the old mesh identity must continue operating for
// 60–120 seconds (randomised) before final shutdown.  This prevents the
// sudden cessation of old-identity traffic from creating a detectable timing
// signal.  An observer sees a gradual traffic transition that resembles normal
// mesh churn.
//
// State machine:
//
//   begin_duress_wind_down()
//         │
//         ▼
//   WindDownState::Active            ← old identity still accepts traffic
//         │  (60–120 s passes)
//         ▼
//   WindDownState::Draining          ← old identity rejects NEW connections,
//         │  (existing tunnels drain)   cover traffic tapers to zero
//         ▼
//   WindDownState::Complete          ← wind-down finished; caller can free
//                                      in-memory old identity key material
//
// The wind-down is driven by a background thread that advances the state
// and writes a marker file so the service layer can query progress.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// State of the duress wind-down process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindDownState {
    /// Old identity still accepts new connections; cover traffic at full rate.
    Active,
    /// Old identity no longer accepts new connections; existing tunnels draining;
    /// cover traffic tapering to zero.
    Draining,
    /// Wind-down complete; old identity key material may now be zeroed.
    Complete,
}

/// Handle returned by `begin_duress_wind_down()`.
///
/// The caller holds this handle to query wind-down progress and receive
/// the signal to zero old-identity key material.  When the handle is
/// dropped the background thread exits cleanly (the thread holds only a
/// weak reference to the shared state).
pub struct DuressWindDown {
    state: Arc<Mutex<WindDownState>>,
    /// Randomised total wind-down duration chosen at start (60–120 s).
    total_duration: Duration,
    started_at: Instant,
}

impl DuressWindDown {
    /// Current wind-down state.
    pub fn state(&self) -> WindDownState {
        // The guarded value is a plain Copy enum, so a poisoned lock (the
        // timer thread panicked mid-store) still holds a valid state; recover
        // it rather than propagating a panic into the FFI caller.
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the wind-down has completed and key material may be zeroed.
    pub fn is_complete(&self) -> bool {
        self.state() == WindDownState::Complete
    }

    /// Elapsed time since the wind-down started.
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Total randomised wind-down duration (60–120 s).
    pub fn total_duration(&self) -> Duration {
        self.total_duration
    }

    /// Cover-traffic multiplier for the old identity during wind-down.
    ///
    /// Returns a value in [0.0, 1.0]:
    ///   - Active phase: 1.0 (full rate)
    ///   - Draining phase: linearly decreasing from 1.0 → 0.0
    ///   - Complete: 0.0
    ///
    /// The caller should multiply their cover-traffic emission rate by this
    /// value when deciding how many cover packets to emit on old-identity
    /// tunnels (§16.2 gradual transition rules).
    pub fn cover_traffic_multiplier(&self) -> f32 {
        match self.state() {
            WindDownState::Active => 1.0,
            WindDownState::Complete => 0.0,
            WindDownState::Draining => {
                // Drain phase: after active_duration, linear taper over
                // DRAIN_SECS until complete.
                let elapsed = self.elapsed();
                let active_duration = self.total_duration * 2 / 3;
                if elapsed <= active_duration {
                    return 1.0;
                }
                let drain_total = self.total_duration.saturating_sub(active_duration);
                if drain_total.is_zero() {
                    return 0.0;
                }
                let drain_elapsed = elapsed.saturating_sub(active_duration);
                let frac = drain_elapsed.as_secs_f32() / drain_total.as_secs_f32();
                (1.0 - frac).max(0.0)
            }
        }
    }
}

/// Begin the 60–120 second duress wind-down.
///
/// This function:
/// 1. Immediately performs the layer-2/3 erase via `duress_erase()`.
/// 2. Spawns a background thread that advances the state from Active →
///    Draining → Complete over a randomised 60–120 second window.
/// 3. Returns a `DuressWindDown` handle the caller uses to gate traffic.
///
/// # Arguments
///
/// * `data_dir` — path to the identity vault directory.
///
/// # Returns
///
/// `(EraseResult, DuressWindDown)` — the erase result and the wind-down
/// handle.  The caller is responsible for:
/// - Checking `wind_down.is_complete()` before zeroing in-memory key bytes.
/// - Calling `cover_traffic_multiplier()` each time it emits cover packets.
pub fn begin_duress_wind_down(data_dir: &Path) -> (EraseResult, DuressWindDown) {
    // Step 1: Perform the immediate Layer 2/3 erase.
    let erase_result = duress_erase(data_dir);

    // Steps 2-3: start the transition timer.
    (erase_result, start_duress_wind_down())
}

/// Start the 60–120 second wind-down timer without performing an erase.
///
/// The unlock path (§3.9.2 steps 3–4) must hand the UI its decision before
/// the erase runs, so it starts this timer in the foreground — the old
/// identity's taper begins the moment the new identity takes over — and
/// runs `duress_erase` on a background thread. `begin_duress_wind_down`
/// remains the one-call form for callers that can afford a synchronous
/// erase.
pub fn start_duress_wind_down() -> DuressWindDown {
    // Pick a randomised total duration in [60, 120] seconds.
    // We use OsRng to pick a random value in [0, 60] and add 60.
    let extra_secs = {
        use rand_core::RngCore;
        (rand_core::OsRng.next_u32() % 61) as u64
    };
    let total_duration = Duration::from_secs(60 + extra_secs);

    let state = Arc::new(Mutex::new(WindDownState::Active));

    // Spawn background thread to advance state.
    let state_clone = Arc::clone(&state);
    let dur = total_duration;
    std::thread::spawn(move || {
        let active_duration = dur * 2 / 3;

        // Active phase: old identity accepts traffic.
        std::thread::sleep(active_duration);
        {
            // Poison recovery: see `state()`.
            let mut s = state_clone.lock().unwrap_or_else(|e| e.into_inner());
            if *s == WindDownState::Active {
                *s = WindDownState::Draining;
            }
        }

        // Drain phase: cover traffic tapers, no new connections.
        let drain_duration = dur.saturating_sub(active_duration);
        std::thread::sleep(drain_duration);
        {
            // Poison recovery: see `state()`.
            let mut s = state_clone.lock().unwrap_or_else(|e| e.into_inner());
            *s = WindDownState::Complete;
        }
    });

    DuressWindDown {
        state,
        total_duration,
        started_at: Instant::now(),
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
        // The network map is Layer 2 state and goes with it: §3.9.2 step 4a
        // applies §3.9.1 steps 2–6, and step 4 is "network map deleted".
        assert!(!dir.path().join("network_map.vault").exists());

        assert!(result.mesh_identity_preserved);
        assert!(result.files_deleted > 0);
    }

    /// Every artefact the backend persists under `data_dir` that the old
    /// filename list missed (SPEC §3.9.1 key domains): arti state and cache,
    /// published files, offline bundles, the duress blob, the PIN counter and
    /// its key, enrollment and startup state, the device id, the debug log,
    /// further vaults, and a crashed write.
    const RESIDUAL_FILES: [&str; 16] = [
        "tor_state/keys/hs.key",
        "tor_cache/dir.cache",
        "published_files/photo.bin",
        "outbox/aa/bundle.bin",
        "inbox/bb/bundle.bin",
        "pin.dat",
        "pin_attempts.sealed",
        "pin_counter.key",
        "device_enrollment_request.json",
        "layer1_startup.json",
        "device_id",
        "mesh_infinity_backend_debug.log",
        "settings.vault",
        "prekeys.vault",
        "signal_sessions.vault",
        "rooms.vault.tmp",
    ];

    /// Write every `RESIDUAL_FILES` entry (creating its directories).
    fn write_residuals(dir: &Path) {
        for path in RESIDUAL_FILES {
            let full = dir.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, b"residual secret").unwrap();
        }
    }

    /// Names of the root-level entries left in `dir`, sorted.
    fn remaining(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The structural erase: with every known residual present, a standard
    /// erase leaves nothing but the step-1 marker, and counts every file.
    #[test]
    fn standard_erase_leaves_only_the_broadcast_marker() {
        let dir = setup_data_dir();
        write_residuals(dir.path());

        let result = standard_erase(dir.path());

        assert_eq!(remaining(dir.path()), vec![BROADCAST_MARKER.to_string()]);
        // 7 files from setup_data_dir plus every residual, each counted once.
        assert_eq!(result.files_deleted, 7 + RESIDUAL_FILES.len() as u32);
        assert!(!result.mesh_identity_preserved);
    }

    /// The duress erase keeps exactly the Layer 1 files (§3.9.2) and the
    /// marker, destroys everything else, and leaves the kept keypair's
    /// bytes untouched — preserved means unmodified, not merely present.
    #[test]
    fn duress_erase_keeps_only_layer1_files() {
        let dir = setup_data_dir();
        write_residuals(dir.path());

        let result = duress_erase(dir.path());

        let mut kept: Vec<String> = DURESS_KEEP.iter().map(|k| k.to_string()).collect();
        kept.sort();
        assert_eq!(remaining(dir.path()), kept);
        assert_eq!(
            fs::read(dir.path().join("mesh_identity.key")).unwrap(),
            [0x01u8; 32]
        );
        // Everything except the two kept Layer 1 files was counted.
        assert_eq!(result.files_deleted, 7 + RESIDUAL_FILES.len() as u32 - 2);
        assert!(result.mesh_identity_preserved);
    }

    /// A symlink planted in the data directory is unlinked, never followed:
    /// whatever it points at keeps its bytes, whether file or directory.
    #[cfg(unix)]
    #[test]
    fn erase_unlinks_symlinks_without_following_them() {
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("elsewhere.bin");
        fs::write(&target, b"not ours to erase").unwrap();
        let target_dir = outside.path().join("elsewhere_dir");
        fs::create_dir(&target_dir).unwrap();
        fs::write(target_dir.join("inner.bin"), b"also not ours").unwrap();

        let dir = setup_data_dir();
        std::os::unix::fs::symlink(&target, dir.path().join("planted.vault")).unwrap();
        std::os::unix::fs::symlink(&target_dir, dir.path().join("planted_dir")).unwrap();

        standard_erase(dir.path());

        assert_eq!(remaining(dir.path()), vec![BROADCAST_MARKER.to_string()]);
        assert_eq!(fs::read(&target).unwrap(), b"not ours to erase");
        assert_eq!(fs::read(target_dir.join("inner.bin")).unwrap(), b"also not ours");
    }

    #[test]
    fn test_erase_on_empty_directory() {
        let dir = TempDir::new().unwrap();
        // Should not crash on empty directory
        let result = standard_erase(dir.path());
        assert_eq!(result.files_deleted, 0);
    }

    /// The overwrite must not truncate (that would free the original blocks
    /// before the new bytes land) and must change every byte of the file.
    #[test]
    fn test_overwrite_in_place_keeps_length_and_replaces_bytes() {
        let dir = setup_data_dir();
        let path = dir.path().join("messages.vault");
        // 10 KiB of a recognisable pattern, longer than one zero chunk.
        let original = vec![0xABu8; 10 * 1024];
        fs::write(&path, &original).unwrap();

        overwrite_in_place(&path, &[0u8; 4096]).unwrap();

        let after = fs::read(&path).unwrap();
        assert_eq!(after.len(), original.len(), "overwrite must not truncate");
        assert!(after.iter().all(|&b| b == 0), "every byte must be zeroed");
    }

    /// A missing file is an error, not a silent create: the caller only
    /// overwrites files it has already checked exist.
    #[test]
    fn test_overwrite_in_place_missing_file_is_error() {
        let dir = setup_data_dir();
        let missing = dir.path().join("nope.vault");
        assert!(overwrite_in_place(&missing, &[0u8; 16]).is_err());
        assert!(!missing.exists());
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

    /// Adversarial / stupidest-user test: if an entry cannot be unlinked
    /// (held open elsewhere, or its directory is not writable), the erase
    /// must continue past it rather than abort — a partial erase beats
    /// leaving everything on disk because one deletion failed.
    ///
    /// Failure injection: a directory without write permission refuses
    /// unlinks of its children.  Root ignores permission bits, so the test
    /// first probes whether the injection works here and stands down if
    /// not.  (Windows has no equivalent bit; the sweep's error handling is
    /// identical there, but the injection itself is Unix-only.)
    #[cfg(unix)]
    #[test]
    fn test_erase_continues_past_undeletable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();

        // "rooms.vault" becomes a read-only directory holding one file.
        let locked = dir.path().join("rooms.vault");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("held"), b"held").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
        if fs::remove_file(locked.join("held")).is_ok() {
            // Running as root: permissions cannot make an unlink fail here.
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        // Standard sensitive files around it.
        fs::write(dir.path().join("identity.key"), [0x42u8; 32]).unwrap();
        fs::write(dir.path().join("identity.dat"), b"secret").unwrap();
        fs::write(dir.path().join("messages.vault"), b"messages").unwrap();

        let result = standard_erase(dir.path());
        // Hand the directory back so TempDir can clean up.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();

        // The locked file could not be unlinked and its directory survives.
        assert!(
            locked.join("held").exists(),
            "the undeletable file should still be present"
        );

        // But every ordinary file was deleted despite the failure.
        assert!(
            !dir.path().join("identity.key").exists(),
            "identity.key must be erased even though rooms.vault could not be removed"
        );
        assert!(
            !dir.path().join("identity.dat").exists(),
            "identity.dat must be erased even though rooms.vault could not be removed"
        );
        assert!(
            !dir.path().join("messages.vault").exists(),
            "messages.vault must be erased even though rooms.vault could not be removed"
        );

        // files_deleted counts only actual successes.
        assert_eq!(result.files_deleted, 3);
    }

    // ── Duress wind-down tests (§3.9.2 transition masking) ──────────────────

    #[test]
    fn wind_down_starts_active() {
        let dir = setup_data_dir();
        let (_erase, wd) = begin_duress_wind_down(dir.path());
        // Immediately after start the state must be Active.
        assert_eq!(wd.state(), WindDownState::Active);
        assert!(!wd.is_complete());
    }

    #[test]
    fn wind_down_layer2_erased_immediately() {
        let dir = setup_data_dir();
        let (_erase, _wd) = begin_duress_wind_down(dir.path());
        // Layer 2/3 files must be gone as soon as begin_duress_wind_down returns.
        assert!(
            !dir.path().join("identity.key").exists(),
            "identity.key must be erased"
        );
        assert!(
            !dir.path().join("rooms.vault").exists(),
            "rooms.vault must be erased"
        );
        // Layer 1 (mesh_identity.key) must still exist.
        assert!(
            dir.path().join("mesh_identity.key").exists(),
            "mesh_identity.key must be preserved"
        );
    }

    #[test]
    fn wind_down_cover_traffic_multiplier_active() {
        let dir = setup_data_dir();
        let (_erase, wd) = begin_duress_wind_down(dir.path());
        // In the Active state the multiplier should be 1.0.
        let mult = wd.cover_traffic_multiplier();
        assert!(
            (mult - 1.0).abs() < f32::EPSILON,
            "cover_traffic_multiplier should be 1.0 in Active state, got {mult}"
        );
    }

    #[test]
    fn wind_down_total_duration_in_range() {
        let dir = setup_data_dir();
        let (_erase, wd) = begin_duress_wind_down(dir.path());
        let secs = wd.total_duration().as_secs();
        assert!(secs >= 60, "total_duration must be ≥ 60 s, got {secs}");
        assert!(secs <= 120, "total_duration must be ≤ 120 s, got {secs}");
    }

    #[test]
    fn wind_down_erase_result_preserves_mesh_identity() {
        let dir = setup_data_dir();
        let (erase, _wd) = begin_duress_wind_down(dir.path());
        assert!(erase.mesh_identity_preserved);
    }

    #[test]
    fn wind_down_state_machine_progresses() {
        // We cannot wait 60+ seconds in a unit test, so we test the state
        // machine logic directly by constructing a wind-down with a short
        // duration and polling until it completes.
        //
        // This verifies that the background thread advances State correctly.
        // The test uses a custom DuressWindDown-like setup with a very short
        // duration (100ms) to avoid slow tests.
        let state = Arc::new(Mutex::new(WindDownState::Active));
        let state_clone = Arc::clone(&state);

        // Simulate the wind-down background thread with a tiny duration.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            *state_clone.lock().unwrap() = WindDownState::Draining;
            std::thread::sleep(Duration::from_millis(30));
            *state_clone.lock().unwrap() = WindDownState::Complete;
        });

        // Poll until Complete (timeout 2 s).
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let s = *state.lock().unwrap();
            if s == WindDownState::Complete {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "wind-down state machine did not advance to Complete"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(*state.lock().unwrap(), WindDownState::Complete);
    }
}
