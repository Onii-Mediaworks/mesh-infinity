//! Keyfile-encrypted on-disk identity persistence.
//!
//! # What this module does and why it exists
//!
//! Every Mesh Infinity node has a long-term *identity* — a pair of
//! cryptographic keys that define who this node is on the network.  Those keys
//! must survive application restarts, which means they must be written to disk.
//! But writing raw private keys to a plain file is dangerous: anyone who can
//! read the filesystem (another app, a cloud backup, a stolen device) would
//! have the keys.
//!
//! This module solves the problem with a two-file scheme:
//!
//! ```text
//! Platform keystore  ←→  identity.key  (or identity.key.wrap on Android)
//!                              │
//!                              │ 32-byte AES/ChaCha key
//!                              ▼
//!                         identity.dat
//!                         ┌─────────────────────────────────────────────┐
//!                         │ nonce (12 B) │ ChaCha20-Poly1305 ciphertext │
//!                         └─────────────────────────────────────────────┘
//! ```
//!
//! The encryption key (`identity.key` / keystore entry) and the encrypted data
//! (`identity.dat`) are stored separately.  An attacker who steals only the
//! data file cannot decrypt it — they also need the key.  An attacker who
//! steals only the key file has a key but no data.  They need both, AND
//! (on Android) they need the physical hardware.
//!
//! ANALOGY: Think of `identity.dat` as a locked safe, and the keystore entry
//! as the combination.  The safe can be left in plain sight — without the
//! combination it is useless.  The combination is stored at the bank (the OS
//! keystore), where the bank teller only hands it to the account owner
//! (the logged-in user on this device).
//!
//! # Encryption scheme
//!
//! **ChaCha20-Poly1305** — an "Authenticated Encryption with Associated Data"
//! (AEAD) cipher.  It provides two guarantees simultaneously:
//!
//! 1. **Confidentiality** — the plaintext is scrambled; nobody without the key
//!    can read the identity fields.
//!
//! 2. **Integrity** — if any byte of `identity.dat` is changed on disk (even
//!    accidentally by filesystem corruption, not necessarily malicious), the
//!    decryption step will fail with an error rather than returning garbled data.
//!
//! A random 12-byte **nonce** is generated fresh on every save and prepended to
//! the ciphertext.  This ensures that even if you save the same identity twice,
//! the two `identity.dat` files look completely different — preventing an
//! attacker from learning anything by comparing old backups.
//!
//! WHY A NEW NONCE ON EVERY SAVE?
//! ChaCha20-Poly1305 requires that a given key is NEVER used with the same nonce
//! twice.  If you reused a nonce, an attacker who has two ciphertexts encrypted
//! under the same key+nonce could XOR them together to cancel the keystream,
//! potentially revealing both plaintexts.  A fresh random nonce on every save
//! makes this cryptographically impossible (with overwhelming probability).
//!
//! WHY DOES THE NONCE NOT NEED TO BE SECRET?
//! The nonce's only job is to be unique — it does not need to be unpredictable.
//! Prepending it to the file means the decryptor always knows which nonce was
//! used without any additional bookkeeping.
//!
//! # Platform key storage
//!
//! See `keystore.rs` for how the encryption key itself is protected on each
//! platform.  The short version:
//!
//! * **Android** — the key is wrapped (hardware-encrypted) by the Android
//!   Keystore chip and stored as `identity.key.wrap`.
//! * **macOS / iOS / Windows / Linux (GUI)** — the key is stored directly in
//!   the platform keychain / credential manager.
//! * **Linux (headless, no Secret Service daemon)** — the key falls back to a
//!   plain file (`identity.key`) with 0600 permissions (owner-read-only).
//!
//! # Emergency destroy
//!
//! To permanently destroy all identity data without leaving recoverable
//! plaintext, call [`IdentityStore::destroy`]:
//!   1. It deletes the encryption key from the platform keystore first.
//!      Once the key is gone, `identity.dat` is cryptographically locked
//!      forever — even if copies of it exist elsewhere.
//!   2. It then overwrites any leftover key files with random bytes before
//!      deleting them (preventing forensic recovery from the filesystem).
//!   3. Finally it removes `identity.dat` itself.
//!
//! # Why does order matter in destroy?
//!
//! The key is destroyed FIRST (step 1), before any files are deleted (steps 2-3).
//! This means even if the process crashes mid-destroy (power failure, force-quit),
//! the key is already gone and `identity.dat` is permanently unreadable.
//! If we deleted files first and then crashed before deleting the key, an attacker
//! with a disk snapshot made during the crash window might still be able to
//! reconstruct the identity.  Deleting the key first eliminates this risk.

// --- ChaCha20-Poly1305 AEAD cipher ---
// `Aead`    — the trait that provides `.encrypt()` and `.decrypt()` methods.
//             An "AEAD" (Authenticated Encryption with Associated Data) cipher
//             simultaneously encrypts data AND produces a tag that detects
//             any tampering.  This is stronger than encrypting and MAC-ing
//             separately, because it avoids subtle composition mistakes.
// `KeyInit` — the trait that provides `.new(key)` to construct a cipher object
//             from a raw byte key.
use chacha20poly1305::aead::{Aead, KeyInit};
// `ChaCha20Poly1305` — the concrete cipher type.
// `Key`              — a newtype wrapping a 32-byte array used as the AES/ChaCha key.
//                      Using a newtype rather than a raw array prevents accidentally
//                      passing the wrong 32-byte value where a key is expected.
// `Nonce`            — a newtype wrapping a 12-byte array used as the nonce.
//                      12 bytes is the standard nonce size for ChaCha20-Poly1305
//                      (defined by RFC 8439).
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

// --- Random number generation ---
// `OsRng`   — draws entropy from the operating system's cryptographically
//              secure random pool (/dev/urandom on Linux, CryptGenRandom on
//              Windows, SecRandomCopyBytes on Apple).  This is the gold standard
//              for generating keys, nonces, and other security-critical randomness.
// `RngCore` — the trait that provides `.fill_bytes(buf)`, which fills a byte
//              buffer with random bytes.  We import it so the `.fill_bytes`
//              method is available on the `OsRng` type.
use rand_core::{OsRng, RngCore};

// --- Serde: serialization and deserialization framework ---
// `Serialize`   — the trait that allows a Rust struct to be converted to JSON
//                 (or other formats).  Derived automatically via `#[derive(Serialize)]`.
// `Deserialize` — the inverse: allows JSON to be converted back to a Rust struct.
//
// We serialise `PersistedIdentity` to JSON before encrypting, and deserialise
// after decrypting.  Serde handles the conversion between Rust structs and JSON.
//
// WHY JSON RATHER THAN A BINARY FORMAT?
//   JSON is self-describing: each field has a name.  This means:
//   a) New fields can be added in future versions without breaking old files
//      (unknown fields are ignored during deserialization).
//   b) If you ever need to manually inspect an identity (with a temporary key
//      export tool), the decrypted output is human-readable.
//   A binary format (e.g. MessagePack, Protocol Buffers) would be more compact,
//   but for an identity file that is saved only occasionally, the size difference
//   is negligible.
use serde::{Deserialize, Serialize};

// --- Path handling ---
// `PathBuf` is Rust's owned, heap-allocated path type (equivalent to `String`
// but for filesystem paths).  It handles OS-specific path separators (/ on Unix,
// \ on Windows) correctly.  We use it to build paths like "/data/user/0/.../identity.dat".
use std::path::PathBuf;

// --- Internal imports ---
use crate::core::error::{MeshInfinityError, Result};
use crate::auth::keystore; // platform-specific key storage (see keystore.rs)

// ============================================================================
// PersistedIdentity — what actually gets written to disk
// ============================================================================

/// All identity material for a single local node, serialised to JSON and
/// encrypted into `identity.dat`.
///
/// # Why serialise to JSON?
///
/// JSON is human-readable (useful for debugging with a one-time key export)
/// and self-describing (new fields can be added without breaking old files).
/// The AEAD encryption ensures that in normal operation nobody can read the
/// JSON without the key.
///
/// # Field privacy
///
/// Not all fields are transmitted over the network.  Some are strictly local
/// device data (`private_display_name`, `private_bio`) and are never sent to
/// peers — they only ever exist on this device.
///
/// # Why `#[derive(Clone, Serialize, Deserialize)]`?
///
/// `Clone`       — allows making a copy of the struct (needed when the service
///                 layer wants to snapshot the identity without taking ownership).
/// `Serialize`   — generated by Serde: adds a `serialize` method that converts
///                 this struct to JSON (or any other Serde format).
/// `Deserialize` — generated by Serde: adds a `deserialize` method that parses
///                 JSON back into this struct.
///
/// These three derives add zero runtime cost beyond what is explicitly used —
/// they just generate the boilerplate conversion code at compile time.
#[derive(Clone, Serialize, Deserialize)]
pub struct PersistedIdentity {
    /// The Ed25519 signing key scalar (32 bytes, raw little-endian).
    ///
    /// This is the MOST SENSITIVE field.  It allows signing messages as this
    /// node.  If it were stolen, an attacker could impersonate this node on
    /// the Mesh Infinity network — forging messages, establishing false trust
    /// relationships, etc.
    ///
    /// In memory this is a `Vec<u8>` so it can be passed to the `ed25519-dalek`
    /// crate's `SigningKey::from_bytes()` constructor.
    ///
    /// WHY NOT STORE AS `SigningKey` DIRECTLY?
    /// `SigningKey` does not implement `Serialize` / `Deserialize` (deliberately
    /// — the ed25519-dalek crate avoids accidentally serialising secret keys
    /// into formats that might be logged or sent over the network).  Storing
    /// as `Vec<u8>` puts the serialization decision explicitly in our hands.
    /// We only serialize it here, inside the encryption layer, where we know
    /// the output will be immediately encrypted before touching disk.
    pub ed25519_secret: Vec<u8>,

    /// The X25519 Diffie-Hellman static private key scalar (32 bytes).
    ///
    /// Used to derive shared secrets with other peers for key exchange and
    /// trust-pair encryption.  Also sensitive — an attacker with this key can
    /// decrypt messages encrypted to this node's public DH key.
    ///
    /// IMPORTANT DISTINCTION FROM THE ED25519 KEY:
    /// The Ed25519 key is used for SIGNING (proving you wrote something).
    /// The X25519 key is used for ENCRYPTION (letting others send you secrets).
    /// They are separate keys using different mathematical foundations.
    /// Keeping them separate limits blast radius: if one is compromised, the
    /// other remains safe.
    pub x25519_secret: Vec<u8>,

    /// A display name that this node shares with explicitly trusted peers
    /// (i.e. peers in its Web of Trust).
    ///
    /// This is more personal / detailed than `public_display_name` because it
    /// is only shared within trusted circles.  `None` if the user has not set
    /// one.
    ///
    /// EXAMPLE: The user might set `name` to their real name ("Alice Smith")
    /// but leave `public_display_name` as a pseudonym ("aSmith_dev").
    pub name: Option<String>,

    /// A display name visible to any peer during discovery, including untrusted ones.
    ///
    /// The user may choose a pseudonym here.  `None` means use a default or
    /// remain unnamed.
    ///
    /// This is the "public face" of the node on the network — broadcast in
    /// mDNS service announcements and DHT records.
    pub public_display_name: Option<String>,

    /// Whether this node is discoverable by unknown (untrusted) peers.
    ///
    /// `true`  — the node responds to mDNS / DHT / peer discovery queries.
    ///           Other devices on the local network can find and attempt to
    ///           connect to this node.
    /// `false` — the node only connects to peers it has explicitly paired with.
    ///           It does not advertise its presence to strangers.
    ///
    /// This is a privacy preference: "stealth mode" vs "discoverable mode".
    pub identity_is_public: bool,

    /// A display name that is NEVER transmitted to any peer.
    ///
    /// This is purely a device-local label — the user might set it to their
    /// real name for their own reference while keeping their on-network name
    /// pseudonymous.  Encrypted with the identity and never shared.
    ///
    /// EXAMPLE: A journalist might use "Jane Doe" as `private_display_name`
    /// on their own device but show only a random code as `public_display_name`
    /// to protect their identity on the network.
    pub private_display_name: Option<String>,

    /// A freeform biographical note that is NEVER transmitted to any peer.
    ///
    /// Like `private_display_name`, this is a device-local note encrypted
    /// inside `identity.dat` and never sent over the network.
    ///
    /// Could be used for notes like "This is my work identity — do not use
    /// for personal contacts" or any other memo the user wants to keep
    /// alongside their keys.
    pub private_bio: Option<String>,
}

// ============================================================================
// IdentityStore — manages the files that protect the identity
// ============================================================================

/// Manages loading, saving, and destroying the encrypted identity on disk.
///
/// The `dir` field is the directory where both files live:
///   * `identity.dat`       — the ChaCha20-Poly1305 encrypted identity blob.
///   * `identity.key`       — fallback plain keyfile (0600, headless Linux only).
///   * `identity.key.wrap`  — Android-only hardware-wrapped keyfile.
///
/// On all other platforms (macOS, iOS, Windows, Linux with a GUI), the
/// encryption key lives in the platform keychain and no `identity.key` file
/// is created.
///
/// # File layout summary
///
/// | File              | Platform       | Contents |
/// |---|---|---|
/// | identity.dat      | all platforms  | nonce (12 B) + ChaCha20-Poly1305 ciphertext |
/// | identity.key      | headless Linux | raw 32-byte key (0600 permissions) |
/// | identity.key.wrap | Android        | hardware-wrapped 32-byte key blob |
/// | (no file)         | macOS/iOS/Win/Linux GUI | key is in the platform keychain |
///
/// # Why a struct instead of standalone functions?
///
/// Bundling the `dir` path into a struct avoids passing it to every function
/// as a parameter.  The `IdentityStore` instance acts as a "context" for
/// all operations on this particular identity directory.  This makes the API
/// cleaner and prevents mismatches where the data file is in one directory
/// and the key file is in another.
pub struct IdentityStore {
    /// Directory where `identity.dat` (and optionally `identity.key`) live.
    ///
    /// On Android this is typically:
    ///   `/data/user/0/com.oniimediaworks.meshinfinity/files/`
    /// On macOS / desktop Linux:
    ///   `~/.local/share/mesh-infinity/` or platform equivalent.
    dir: PathBuf,
}

impl IdentityStore {
    // ========================================================================
    // Constructor and path helpers
    // ========================================================================

    /// Create a new `IdentityStore` rooted at `dir`.
    ///
    /// No filesystem operations are performed here; this just records the
    /// directory path.  Call [`exists`](Self::exists) to check for a saved
    /// identity, [`load`](Self::load) to read one, or [`save`](Self::save)
    /// to write one.
    ///
    /// # `impl Into<PathBuf>`
    ///
    /// The `impl Into<PathBuf>` parameter type means the caller can pass:
    ///   * A `PathBuf` (owned path object).
    ///   * A `&str` (string literal) — Rust automatically converts it.
    ///   * A `String` — also automatically converted.
    ///   * A `&Path` — also works.
    /// This flexibility avoids forcing callers to construct a `PathBuf`
    /// themselves when they already have a string.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Full path to the plain fallback keyfile.
    ///
    /// This file only exists on headless Linux or on older installs that
    /// predate the platform-keystore integration.  It is created with 0600
    /// permissions (owner-read-only) when the keychain is unavailable.
    ///
    /// `dir.join("identity.key")` concatenates the directory path with the
    /// filename, using the OS-appropriate separator.
    fn key_path(&self) -> PathBuf {
        self.dir.join("identity.key")
    }

    /// Full path to the Android hardware-wrapped keyfile.
    ///
    /// On Android the encryption key cannot be stored in plain form; instead
    /// it is wrapped (encrypted) by the Android Keystore hardware and stored
    /// as this opaque blob.  Only the same physical device's hardware can
    /// unwrap it.
    ///
    /// The `.wrap` extension signals that this is not a plain key — it is an
    /// opaque blob that must be "unwrapped" (hardware-decrypted) before use.
    #[cfg(target_os = "android")]
    fn wrapped_key_path(&self) -> PathBuf {
        self.dir.join("identity.key.wrap")
    }

    /// Full path to the encrypted identity data file.
    ///
    /// Contains: `[ nonce (12 B) | ChaCha20-Poly1305 ciphertext ]`.
    ///
    /// The nonce is prepended in the clear; the ciphertext follows immediately.
    /// The Poly1305 authentication tag (16 bytes) is embedded at the end of
    /// the ciphertext (appended by the AEAD cipher during encryption).
    fn data_path(&self) -> PathBuf {
        self.dir.join("identity.dat")
    }

    // ========================================================================
    // Existence check
    // ========================================================================

    /// Return `true` if a complete, usable identity is saved on this device.
    ///
    /// "Complete" means BOTH the key AND the data file are present.  Having
    /// only one of the two is useless — the data cannot be decrypted without
    /// the key, and the key alone contains no identity.
    ///
    /// This is typically called at startup to decide whether to launch the
    /// onboarding flow (no identity) or load the existing identity.
    pub fn exists(&self) -> bool {
        // Both conditions must be true:
        //   self.key_exists() — the encryption key is available (in keychain,
        //                        wrapped file, or plain file).
        //   self.data_path().exists() — the encrypted identity file is present.
        self.key_exists() && self.data_path().exists()
    }

    /// Android variant: check for a wrapped key file OR a legacy plain key file.
    ///
    /// New Android installs use `identity.key.wrap`; older installs (before
    /// the Android Keystore integration was added) used the plain `identity.key`.
    /// We accept either so that users upgrading from an old version are not
    /// forced to re-create their identity.
    ///
    /// # Why check both?
    ///
    /// When this code was first written for Android, it stored the key as a
    /// plain file.  Later, the Android Keystore hardware-wrapping integration
    /// was added.  If we only checked for the new `.wrap` file, existing users
    /// would lose their identity after an app update.  By checking both, we
    /// detect the legacy case and migrate it transparently in `load_key_bytes`.
    #[cfg(target_os = "android")]
    fn key_exists(&self) -> bool {
        // `.exists()` returns true if the file exists and is accessible.
        // Note: on Android, `std::fs::metadata` (which `.exists()` uses)
        // can be called from any thread without special permissions.
        self.wrapped_key_path().exists() || self.key_path().exists()
    }

    /// Non-Android variant: check the platform keychain first, then the
    /// fallback plain file.
    ///
    /// # Behaviour on headless Linux
    ///
    /// `key_in_keystore()` returns `false` (not an error) if the Secret Service
    /// daemon is not running.  We then fall back to checking the plain file.
    /// This means `key_exists()` correctly returns `true` for headless Linux
    /// nodes that have a plain `identity.key` file.
    #[cfg(not(target_os = "android"))]
    fn key_exists(&self) -> bool {
        // `key_in_keystore()` returns false (not an error) if the keychain is
        // unavailable, so it is safe to call unconditionally.
        keystore::key_in_keystore() || self.key_path().exists()
    }

    // ========================================================================
    // Key loading (internal)
    // ========================================================================

    /// Android variant: load and return the raw 32-byte encryption key.
    ///
    /// # Migration path (plain file → wrapped file)
    ///
    /// If a wrapped key file exists, we unwrap it via the Android Keystore
    /// hardware and return the raw bytes.
    ///
    /// If only the plain `identity.key` exists (legacy install), we:
    ///   1. Read the raw bytes from disk.
    ///   2. Immediately wrap them with the Android Keystore hardware.
    ///   3. Write the wrapped blob as `identity.key.wrap`.
    ///   4. Delete the plain `identity.key` (so it no longer exists in plaintext).
    ///   5. Return the raw bytes (the caller can proceed without restarting).
    ///
    /// This "silent migration" upgrades old installations to the hardware-backed
    /// scheme on the next app launch, without any user interaction required.
    ///
    /// # Why is migration done in the LOAD path, not a separate migration step?
    ///
    /// Running migration "lazily" (on the first load after upgrade) is more
    /// robust than a separate one-time migration:
    ///   * There is no "have I migrated?" flag to track.
    ///   * If the app is uninstalled/reinstalled, the migration runs again.
    ///   * If the migration crashes partway, the next launch will retry it.
    ///   * The user does not experience any visible "upgrading" step.
    #[cfg(target_os = "android")]
    fn load_key_bytes(&self) -> Result<Vec<u8>> {
        // Prefer the hardware-wrapped file (normal case for new installs).
        if self.wrapped_key_path().exists() {
            // Read the opaque wrapped blob from disk.
            // `std::fs::read` reads the entire file into a `Vec<u8>`.
            // The wrapped blob is typically a few hundred bytes (the raw 32
            // bytes plus the Android Keystore's AES-GCM nonce and tag).
            let wrapped = std::fs::read(self.wrapped_key_path())?;
            // Ask the Android Keystore hardware to decrypt it.
            // This will fail if:
            //   * The device is locked (if the key requires authentication).
            //   * The hardware key entry was deleted (identity destroy sequence).
            //   * The device was factory-reset (hardware key is gone).
            return keystore::unwrap_key_bytes(&wrapped);
        }

        // Legacy path: plain key file exists but no wrapped file.
        // This only runs on devices that installed the app before the
        // Android Keystore integration was added.
        let key_bytes = std::fs::read(self.key_path())?;
        if key_bytes.len() != 32 {
            // The file should always be exactly 32 bytes.  If it is not,
            // the file is corrupted (truncated, padded, or wrong file).
            // We cannot safely use a key of the wrong length.
            return Err(MeshInfinityError::CryptoError(
                "Identity keyfile has unexpected length".to_string(),
            ));
        }

        // Migrate: wrap the plain key with the Android Keystore hardware.
        // After this call, the hardware holds a master key that can unwrap
        // our 32-byte key, and `wrapped` is the opaque encrypted blob.
        let wrapped = keystore::wrap_key_bytes(&key_bytes)?;
        // Store the wrapped blob alongside the identity data.
        // From this point on, `identity.key.wrap` is the primary key file.
        std::fs::write(self.wrapped_key_path(), &wrapped)?;
        // Delete the now-redundant plain key file.
        // `let _ = ...` ignores any error (e.g. if the file was already
        // removed in a previous partial migration attempt — idempotent).
        let _ = std::fs::remove_file(self.key_path());

        // Return the raw bytes so the caller can proceed immediately.
        // The next load will use the wrapped file instead.
        Ok(key_bytes)
    }

    /// Non-Android variant: load the raw 32-byte encryption key.
    ///
    /// # Priority order
    ///
    /// 1. Try the platform keychain (macOS Keychain, Windows Credential Manager,
    ///    Linux Secret Service).  This is the normal path for desktop/laptop devices.
    ///
    /// 2. Fall back to reading `identity.key` from disk.  This happens on:
    ///    * Headless Linux servers (no Secret Service daemon).
    ///    * Older installs that predate the keychain integration.
    ///
    /// # Migration path (plain file → keychain)
    ///
    /// If we successfully read the key from a plain file AND the keychain is
    /// now available (e.g. the user installed a keyring daemon since the last
    /// run), we silently migrate:
    ///   1. Store the key in the keychain.
    ///   2. Delete the plain file.
    ///
    /// If migration fails (keychain still unavailable), we keep the plain file
    /// and continue without an error.
    ///
    /// # Why is the migration "opportunistic"?
    ///
    /// We do not want to force users to set up a keychain before they can
    /// use the app.  A headless server is a valid deployment target.  So we
    /// try the migration on every load (it is cheap — just a keychain write
    /// and a file delete), and silently skip it if the keychain is unavailable.
    /// Once a keychain becomes available, the migration happens automatically
    /// on the next launch.
    #[cfg(not(target_os = "android"))]
    fn load_key_bytes(&self) -> Result<Vec<u8>> {
        // Try the platform keystore first (preferred, more secure).
        // `keystore::load_key()` returns Err if the entry does not exist
        // or if the keychain is unavailable.
        if let Ok(key) = keystore::load_key() {
            return Ok(key);
        }

        // Fall back to the legacy plain file.
        // `MeshInfinityError::IoError` wraps the standard I/O error so it fits
        // into our unified error type.  This error is returned if the plain
        // file also does not exist (neither key source is available).
        let key = std::fs::read(self.key_path()).map_err(MeshInfinityError::IoError)?;

        // Opportunistic migration: try to move the key into the keychain.
        // `.is_ok()` discards the `Result` and returns true only on success.
        // If this fails (keychain still unavailable), we carry on with the plain file.
        // We only delete the plain file if the keychain store succeeded —
        // otherwise we would lose the key entirely.
        if keystore::store_key(&key).is_ok() {
            // Plain file successfully migrated to keychain.
            // The `let _ = ...` ignores any error from the delete (e.g. if the
            // file was already deleted by another process — idempotent).
            let _ = std::fs::remove_file(self.key_path());
        }

        Ok(key)
    }

    // ========================================================================
    // Public API: load
    // ========================================================================

    /// Decrypt and deserialise the persisted identity from disk.
    ///
    /// # Step-by-step
    ///
    /// 1. Load the 32-byte encryption key from wherever it is stored (keychain,
    ///    wrapped file, or plain file — see `load_key_bytes`).
    /// 2. Read `identity.dat` into memory.
    /// 3. Split `identity.dat` into: nonce (first 12 bytes) + ciphertext (rest).
    /// 4. Decrypt and authenticate the ciphertext with ChaCha20-Poly1305.
    ///    If decryption fails (wrong key, tampered file), return an error.
    /// 5. Deserialise the resulting JSON bytes into a `PersistedIdentity` struct.
    ///
    /// # Error cases
    /// * Key or data file missing.
    /// * Key is not exactly 32 bytes (file corrupted).
    /// * Data file is shorter than 13 bytes (nonce + at least 1 byte is impossible).
    /// * AEAD authentication fails (wrong key, or `identity.dat` was modified).
    /// * JSON deserialisation fails (structural mismatch, file corrupted).
    ///
    /// # Why is the length check > 12 rather than > 28?
    ///
    /// A technically valid ChaCha20-Poly1305 file must be at least
    /// 12 (nonce) + 16 (Poly1305 tag) + 1 (at least 1 plaintext byte encrypted)
    /// = 29 bytes.  We conservatively check > 12 here because the AEAD
    /// decryption call will itself reject anything too short to contain a tag.
    /// The check at 13 bytes is a fast fail for obviously truncated files
    /// (e.g. an empty file created by a failed write).
    pub fn load(&self) -> Result<PersistedIdentity> {
        // Step 1: get the encryption key.
        // Handles the platform-specific key loading logic (keychain, wrapped
        // file, plain file) and optional migration.
        let key_bytes = self.load_key_bytes()?;
        if key_bytes.len() != 32 {
            // ChaCha20-Poly1305 requires exactly a 256-bit (32-byte) key.
            // Any other length is an error — likely a corrupted key file.
            return Err(MeshInfinityError::CryptoError(
                "Identity keyfile has unexpected length".to_string(),
            ));
        }

        // Step 2: read the encrypted data.
        // `std::fs::read` reads the entire file into a Vec<u8> in one syscall.
        // For an identity file (a few hundred bytes), this is fast and simple.
        let data_bytes = std::fs::read(self.data_path())?;

        // Step 3: basic length sanity check.
        // The minimum valid file is 12 bytes of nonce + at least 1 byte of
        // ciphertext (plus the 16-byte Poly1305 tag = 29 bytes minimum really,
        // but we conservatively check > 12 here).  Files this short would
        // indicate truncation or corruption.
        if data_bytes.len() < 13 {
            return Err(MeshInfinityError::CryptoError(
                "Identity data file is too short".to_string(),
            ));
        }

        // Step 4: decrypt.
        //
        // `Key::from_slice` creates a reference into the key_bytes slice.
        // No copying occurs — the slice is reinterpreted as the `Key` type.
        // This is safe because we verified `key_bytes.len() == 32` above,
        // and `Key` is exactly 32 bytes.
        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        // Split the data file at offset 12: first 12 bytes = nonce, rest = ciphertext.
        // `split_at(12)` returns two non-overlapping slices without copying.
        let (nonce_bytes, ciphertext) = data_bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt AND verify the Poly1305 authentication tag in one step.
        //
        // If the key is wrong OR the file was tampered with, `cipher.decrypt`
        // returns an opaque error.  Deliberately, it does not reveal which
        // byte was wrong or whether the problem was the key or the data.
        // This opaqueness prevents "padding oracle" style information leaks
        // where an attacker probes what happens with different invalid inputs.
        //
        // On success, `plaintext` contains the original JSON bytes.
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            MeshInfinityError::CryptoError("Failed to decrypt identity data".to_string())
        })?;

        // Step 5: deserialise the JSON.
        // `serde_json::from_slice` parses JSON from a byte slice.
        // It returns a `PersistedIdentity` struct with all fields populated.
        // If the JSON is malformed (e.g. missing a required field, wrong type),
        // it returns a `DeserializationError`.
        serde_json::from_slice(&plaintext)
            .map_err(|e| MeshInfinityError::DeserializationError(e.to_string()))
    }

    // ========================================================================
    // Public API: save
    // ========================================================================

    /// Serialise, encrypt, and write the identity to disk.
    ///
    /// # Key lifecycle
    ///
    /// * **First save** — no key exists yet.  We generate 32 cryptographically
    ///   random bytes and store them via `store_key_bytes` (which puts them in
    ///   the platform keychain or, as a fallback, a 0600-restricted file).
    ///
    /// * **Subsequent saves** — the key already exists.  We load it via
    ///   `load_key_bytes` and reuse it.  This is important: if we regenerated
    ///   the key on every save, any backup of `identity.dat` made before the
    ///   last save would become permanently undecryptable.
    ///
    ///   EXAMPLE OF WHY KEY REUSE MATTERS:
    ///   Suppose the user makes a backup on Monday, then updates their display
    ///   name and saves on Tuesday.  If we generated a new key on Tuesday's save,
    ///   the Monday backup (encrypted under the old key) would be unreadable.
    ///   By reusing the same key, the Monday backup can always be decrypted by
    ///   loading the saved key from the keychain.
    ///
    /// # Step-by-step
    ///
    /// 1. Create the directory if it does not exist.
    /// 2. Load or generate the 32-byte encryption key.
    /// 3. Serialise `identity` to JSON bytes.
    /// 4. Generate a fresh 12-byte random nonce.
    /// 5. Encrypt the JSON with ChaCha20-Poly1305 (nonce + key → ciphertext+tag).
    /// 6. Write `[ nonce | ciphertext+tag ]` to `identity.dat`.
    pub fn save(&self, identity: &PersistedIdentity) -> Result<()> {
        // Ensure the directory exists.
        // `create_dir_all` is like `mkdir -p` — it creates all intermediate
        // directories as needed and does not fail if the directory already exists.
        std::fs::create_dir_all(&self.dir)?;

        // Step 2: get or generate the encryption key.
        let key_bytes: Vec<u8> = if self.key_exists() {
            // Key already stored — load it so we stay consistent with old data.
            // If we used a different key, any previously saved `identity.dat`
            // would become unreadable.
            self.load_key_bytes()?
        } else {
            // First save: generate 32 cryptographically random bytes.
            // `OsRng.fill_bytes` draws from the OS secure random pool.
            // We use a `vec![0u8; 32]` (heap-allocated) rather than `[0u8; 32]`
            // (stack-allocated) because `store_key_bytes` takes a `&[u8]` slice
            // and we may need to pass it around.
            let mut k = vec![0u8; 32];
            OsRng.fill_bytes(&mut k);
            // Persist the key to the platform keychain (or fallback file).
            // If this fails, the entire save fails — we must not write
            // an `identity.dat` that we cannot decrypt.
            self.store_key_bytes(&k)?;
            k
        };

        // Construct the ChaCha20-Poly1305 cipher object with the 32-byte key.
        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        // Step 4: generate a fresh random 12-byte nonce.
        //
        // A nonce ("number used once") MUST be unique for every encryption
        // with the same key.  Reusing a nonce with ChaCha20-Poly1305 is
        // catastrophic — it allows an attacker to trivially recover the
        // plaintext.  We use OsRng to generate a random nonce; the probability
        // of a collision is astronomically small (2^-96 per pair of saves).
        //
        // WHY RANDOM INSTEAD OF COUNTER?
        //   A counter (0, 1, 2, ...) would also avoid nonce reuse within a
        //   session.  But if the app is reinstalled or the counter state is
        //   reset, the counter would restart at 0 and reuse nonces.  A random
        //   nonce is simpler and eliminates this risk — each save independently
        //   generates a fresh nonce with no persistent counter state to manage.
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Step 3: serialise the identity to JSON bytes.
        // `serde_json::to_vec` converts the `PersistedIdentity` struct into
        // a UTF-8 JSON byte vector.  Field names and values become a JSON
        // object, e.g. `{"ed25519_secret":[...],"x25519_secret":[...],...}`.
        let plaintext = serde_json::to_vec(identity)
            .map_err(|e| MeshInfinityError::SerializationError(e.to_string()))?;

        // Step 5: encrypt.
        // `cipher.encrypt(nonce, plaintext)` returns a new Vec containing:
        //   [ ChaCha20_encrypted_bytes | Poly1305_authentication_tag (16 bytes) ]
        // The tag is appended automatically by the AEAD cipher.
        let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).map_err(|_| {
            MeshInfinityError::CryptoError("Failed to encrypt identity data".to_string())
        })?;

        // Step 6: write `[ nonce (12 B) | ciphertext+tag ]` to disk.
        //
        // We build the full blob in memory first, then write it in one syscall.
        // This is more atomic than writing the nonce and ciphertext separately:
        // a crash during a single `write` call is less likely to leave a
        // partially-written file than a crash between two `write` calls.
        //
        // `Vec::with_capacity` pre-allocates exactly the memory we need,
        // avoiding reallocations.
        let mut data = Vec::with_capacity(12 + ciphertext.len());
        data.extend_from_slice(&nonce_bytes); // the 12-byte random nonce
        data.extend_from_slice(&ciphertext);  // the encrypted identity + auth tag
        // `std::fs::write` creates the file if it does not exist,
        // or overwrites it entirely if it does.
        std::fs::write(self.data_path(), &data)?;

        Ok(())
    }

    // ========================================================================
    // Public API: destroy (killswitch)
    // ========================================================================

    /// Permanently destroy all identity data on this device.
    ///
    /// # Why this is irreversible
    ///
    /// The destroy sequence is carefully ordered:
    ///
    /// 1. **Delete the encryption key first** (`destroy_keyfile`).
    ///    The moment the key is gone, `identity.dat` becomes unreadable —
    ///    not "hard to read" but *mathematically impossible* to read without
    ///    the key.  Even if the attacker had a copy of `identity.dat` made
    ///    five minutes ago, it is now permanently locked.
    ///
    ///    WHY IS IT MATHEMATICALLY IMPOSSIBLE?
    ///    ChaCha20-Poly1305 uses a 256-bit key.  There are 2^256 possible
    ///    keys — approximately 10^77.  Even if every atom in the observable
    ///    universe were a computer checking a billion keys per second for the
    ///    lifetime of the universe, it would still only check a tiny fraction
    ///    of all possible keys.  Without the specific key, brute force is
    ///    computationally infeasible.
    ///
    /// 2. **Remove `identity.dat`**.
    ///    Belt-and-suspenders: even though the file is already unreadable,
    ///    we remove it to reduce forensic surface area.
    ///
    /// # Why overwrite before deleting?
    ///
    /// On some filesystems and storage devices, a deleted file's sectors are
    /// not immediately overwritten — the data lingers until the OS reuses those
    /// blocks.  A forensic tool (like `photorec` or `foremost`) could recover
    /// the old content.
    ///
    /// We overwrite the key file with random bytes BEFORE deleting it.  This
    /// means even if a forensic tool recovers the file's old sectors, it finds
    /// random noise rather than a real key.
    ///
    /// NOTE: This is a best-effort mitigation.  On SSDs with wear-levelling and
    /// on filesystems with copy-on-write (e.g. btrfs, APFS), the OS may write
    /// the random bytes to a different physical sector, leaving the original
    /// sectors intact until they are reused.  There is no portable, guaranteed
    /// way to securely erase data on all storage types.  The keystore deletion
    /// (step 1) remains the primary destruction mechanism.
    ///
    /// # Use case
    ///
    /// This is intended for an in-app "destroy identity" button — an emergency
    /// killswitch for users who believe their device has been compromised or
    /// who want to permanently leave the network.  It is intentionally
    /// irreversible: after this call, there is no recovery path.
    pub fn destroy(&self) -> Result<()> {
        // Step 1: destroy the key (rendering identity.dat permanently unreadable).
        // This is the most important step.  Even if subsequent steps fail,
        // the identity cannot be reconstructed without the key.
        self.destroy_keyfile()?;

        // Step 2: remove the data file if it exists.
        // We only attempt deletion if the file actually exists — calling
        // `remove_file` on a non-existent file returns an error on most OSes.
        // Since `identity.dat` is already unreadable (key is gone), this step
        // is belt-and-suspenders, but it keeps the filesystem clean.
        if self.data_path().exists() {
            std::fs::remove_file(self.data_path())?;
        }
        Ok(())
    }

    // ========================================================================
    // Key storage (internal)
    // ========================================================================

    /// Android variant: wrap and store the encryption key.
    ///
    /// Asks the Android Keystore hardware to encrypt the raw key bytes and
    /// stores the opaque wrapped blob as `identity.key.wrap`.  The raw bytes
    /// are never written to disk in plaintext.
    ///
    /// # Why never write the raw key to disk on Android?
    ///
    /// Android devices are frequently rooted by users or compromised by
    /// malware that gains root access.  A root-privileged attacker can read
    /// any file on the filesystem, including files with 0600 permissions.
    ///
    /// The Android Keystore hardware (TEE/SE) provides a protection boundary
    /// that root cannot cross — the hardware key cannot be exported even with
    /// root shell access.  By wrapping our key with the hardware before writing
    /// to disk, we ensure that even a rooted device cannot expose the raw key.
    #[cfg(target_os = "android")]
    fn store_key_bytes(&self, key: &[u8]) -> Result<()> {
        // Wrap (hardware-encrypt) the raw key.
        // The result is an opaque blob — it looks like random bytes to anyone
        // who reads it without the hardware key.
        let wrapped = keystore::wrap_key_bytes(key)?;
        // Store the opaque wrapped blob on disk.
        // This file is only useful on this specific physical device — the
        // hardware key used to wrap it is unique to this device's TEE/SE.
        std::fs::write(self.wrapped_key_path(), &wrapped)?;
        Ok(())
    }

    /// Non-Android variant: store the encryption key.
    ///
    /// # Priority order
    ///
    /// 1. Try the platform keychain (macOS Keychain, Windows Credential
    ///    Manager, Linux Secret Service).  If successful, nothing is written
    ///    to disk.
    ///
    /// 2. Fall back to writing `identity.key` with 0600 permissions.
    ///    This happens on headless Linux servers where no keychain daemon runs.
    ///    The 0600 mode means only the file owner can read it — other users on
    ///    the system cannot access it (subject to root having full access).
    ///
    /// # What does "0600 permissions" mean?
    ///
    /// Unix file permissions are represented as an octal number:
    ///   6 = read + write for the file owner
    ///   0 = no access for the owning group
    ///   0 = no access for all other users
    ///
    /// So 0600 means "only the owner can read or write this file".
    /// Other users (except root) get "Permission denied" when they try to
    /// open it.  This is the standard security practice for private key files
    /// (e.g. SSH private keys are also stored with 0600 permissions).
    #[cfg(not(target_os = "android"))]
    fn store_key_bytes(&self, key: &[u8]) -> Result<()> {
        // Attempt to store in the platform keychain.
        // If successful, the key is in the OS keychain — no file needed.
        if keystore::store_key(key).is_ok() {
            // Successfully stored in the keychain — no file needed.
            return Ok(());
        }

        // Fallback: write a plain 0600-restricted file.
        // `std::fs::write` creates the file if it does not exist.
        // On creation, the file inherits the process's umask — typically 0644
        // (readable by group and others).  We explicitly set 0600 below.
        std::fs::write(self.key_path(), key)?;

        // On Unix systems, set the file permissions to 0600 (owner read+write only).
        // This `#[cfg(unix)]` block is compiled only on Unix-like systems
        // (Linux, macOS, etc.).  On Windows, file permissions work differently
        // and we rely on NTFS ACLs and the user's account security.
        //
        // WHY IS THIS A SEPARATE STEP INSTEAD OF CREATING THE FILE WITH 0600?
        //   Rust's `std::fs::write` does not accept a mode argument (unlike
        //   the POSIX `open(2)` syscall).  After creation, we change the mode.
        //   There is a tiny race window between creation (default mode) and
        //   `set_permissions` (0600) where the file might briefly be readable
        //   by others.  This is acceptable in practice because: a) the write is
        //   fast, b) no other processes are expected to race on this file, and
        //   c) the file might not even contain valid data yet at the moment it
        //   is created (the write and set_permissions happen atomically enough
        //   for our threat model).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // `from_mode(0o600)` creates a permissions object for octal 600:
            //   6 = read + write for owner (binary 110)
            //   0 = no access for group  (binary 000)
            //   0 = no access for others (binary 000)
            // The `0o` prefix is Rust's syntax for octal literals.
            std::fs::set_permissions(self.key_path(), std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    // ========================================================================
    // Keyfile destruction (internal)
    // ========================================================================

    /// Android variant: overwrite and delete the wrapped key file, then
    /// delete the Keystore hardware key entry.
    ///
    /// # Why overwrite before deleting?
    ///
    /// See the `destroy` documentation above.  We fill the wrapped key file
    /// with a freshly wrapped *random* key before removing it.  This means
    /// any filesystem snapshot of the file contains a valid-looking (but
    /// useless) wrapped blob rather than the real one.
    ///
    /// A forensic analyst who recovers the file from a deleted-file sector
    /// would find a wrapped blob for a random key — not the user's real
    /// wrapped key.  Combined with deleting the hardware Keystore entry
    /// (which makes ALL wrapped blobs permanently unreadable), this is a
    /// thorough destruction.
    ///
    /// # Why also call `keystore::delete_key_alias()`?
    ///
    /// The hardware Keystore entry IS the master key used to unwrap blobs.
    /// By deleting it, we ensure:
    ///   * Even the original wrapped key file (if recovered from disk) is
    ///     unreadable — the hardware key that could unwrap it no longer exists.
    ///   * A future call to `unwrap_key_bytes` on ANY wrapped blob for this
    ///     alias will fail.
    #[cfg(target_os = "android")]
    fn destroy_keyfile(&self) -> Result<()> {
        if self.wrapped_key_path().exists() {
            // Generate 32 random bytes — this is a "decoy" key.
            // The decoy replaces the real wrapped key in the file.
            // It is wrapped with the hardware so it looks identical in format
            // to the real wrapped key — a forensic analyst cannot tell them apart.
            let mut random_key = vec![0u8; 32];
            OsRng.fill_bytes(&mut random_key);
            // Wrap the decoy key (so the file looks plausibly valid after overwrite).
            let wrapped = keystore::wrap_key_bytes(&random_key)?;
            // Overwrite the real wrapped key file with the decoy.
            // After this write, the file on disk contains a wrapped-decoy,
            // not the wrapped-real-key.
            std::fs::write(self.wrapped_key_path(), &wrapped)?;
            // Delete the (now-decoy-containing) file.
            std::fs::remove_file(self.wrapped_key_path())?;
            // Also delete the Android Keystore hardware entry.
            // Once deleted, no wrapped blob (real or decoy) can be unwrapped.
            // `let _ = ...` ignores errors (e.g. if the entry was already deleted).
            let _ = keystore::delete_key_alias();
        } else if self.key_path().exists() {
            // Legacy plain key file: overwrite with random bytes, then delete.
            // Same "overwrite then delete" pattern to defeat forensic recovery.
            let mut random_key = vec![0u8; 32];
            OsRng.fill_bytes(&mut random_key);
            // Write the random bytes over the real key bytes.
            std::fs::write(self.key_path(), &random_key)?;
            // Delete the overwritten file.
            std::fs::remove_file(self.key_path())?;
        }
        Ok(())
    }

    /// Non-Android variant: delete the keychain entry and overwrite/delete any
    /// legacy plain key file.
    ///
    /// # Order of operations
    ///
    /// 1. `keystore::delete_key()` — removes the entry from the platform
    ///    keychain.  This is the critical step.  After this, `identity.dat`
    ///    is permanently unreadable even if copies of it exist.
    ///
    /// 2. If a legacy plain `identity.key` file exists (old install or headless
    ///    Linux), overwrite it with 32 random bytes and then delete it.
    ///    This prevents forensic recovery of the key from the filesystem.
    ///
    /// # What happens on headless Linux where the key was always in a file?
    ///
    /// On headless Linux, the key was never in the keychain — it was always
    /// in `identity.key`.  `keystore::delete_key()` is a no-op (the keychain
    /// never had an entry).  Step 2 then overwrites and deletes the plain file.
    /// The end result is the same: the key is gone, `identity.dat` is locked.
    #[cfg(not(target_os = "android"))]
    fn destroy_keyfile(&self) -> Result<()> {
        // Step 1: delete the keychain entry.
        // After this call, identity.dat is cryptographically locked forever —
        // even if an attacker has a backup of identity.dat from earlier today,
        // they cannot decrypt it.
        keystore::delete_key()?;

        // Step 2: clean up any legacy plain-file remnant.
        // This handles:
        //   a) Headless Linux: the key was always in this file.
        //   b) Desktop that used this file before keychain migration.
        if self.key_path().exists() {
            // Overwrite with 32 bytes of random noise before deleting.
            // This defeats low-level filesystem forensics that can recover
            // deleted file content from unreleased disk sectors.
            let mut random_key = vec![0u8; 32];
            OsRng.fill_bytes(&mut random_key);
            // `std::fs::write` overwrites the existing file contents with
            // the random bytes.  The file size changes from 32 (the old key)
            // to 32 (the random noise) — no data is appended or truncated.
            std::fs::write(self.key_path(), &random_key)?;
            // Delete the now-noise-filled file.
            std::fs::remove_file(self.key_path())?;
        }
        Ok(())
    }
}
