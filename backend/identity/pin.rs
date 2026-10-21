//! App PIN (§3.10, §3.6.2, §3.9)
//!
//! PIN wraps `identity.key` via Argon2id. Without PIN entry:
//! Layer 1 active, Layers 2/3 inaccessible.
//!
//! This module owns every primitive the PIN system shares:
//!
//! - the Argon2id parameter window (§3.7.4 floor and ceilings) and the
//!   single `derive_key_from_pin` that both `identity.key` and the duress
//!   blob (`pin.dat`) are wrapped under, so one derivation per unlock
//!   attempt can be tried against both blobs (§3.10 timing normalization);
//! - the AEAD-sealed attempt counter (§3.10 "attempt counter"), so a deleted
//!   or edited counter is detected as tampering instead of silently reset;
//! - the backoff schedule and the clock-rollback rule (§3.10 "backoff curve");
//! - the one-second response deadline every PIN attempt is padded to (§3.9).
//!
//! Security properties:
//! - Argon2id derivation runs exactly once per attempt regardless of outcome
//! - Attempt counter persists across app restarts and is authenticated
//! - Backoff: attempts 1-5 no delay, 6=30s, 7=2m, 8=10m, 9=1h, 10=24h, 11+=72h
//! - A wall clock that moved backwards past the last failure keeps the lock
//! - Key clearing uses atomic once-flag (§3.6.4 race condition fix)

use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    // AEAD cipher for authenticated encryption.
    ChaCha20Poly1305,
    Nonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
// Securely erase key material to prevent forensic recovery.
use zeroize::Zeroizing;

// The §3.7.4 ceilings are defined once, next to the backup envelope that
// first needed them; the PIN wrap reuses them rather than restating magic
// numbers that must stay in lock-step.
use crate::crypto::backup::{MAX_M_COST, MAX_P_COST, MAX_T_COST};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum Argon2id memory cost in KiB (§3.7.4 — backup minimum; PIN uses
/// the same floor). 65536 KiB = 64 MiB.
// ARGON2_M_COST — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const ARGON2_M_COST: u32 = 65536;
/// Minimum Argon2id pass count (§3.7.4).
// ARGON2_T_COST — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const ARGON2_T_COST: u32 = 3;
/// Minimum Argon2id parallelism (§3.7.4).
// ARGON2_P_COST — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const ARGON2_P_COST: u32 = 4;

/// Fixed wall-clock budget for every PIN unlock attempt (§3.9 activation
/// method 3, §3.9.2 step 2, §3.10 "timing normalization").
///
/// Correct, wrong and duress PINs all return at `start + deadline`; the
/// service layer sleeps whatever remains after the single derivation and
/// the decision so that the outcome is not recoverable from response time.
pub const UNLOCK_RESPONSE_DEADLINE: Duration = Duration::from_secs(1);

/// ChaCha20-Poly1305 nonce length written by `wrap_key_under`.
const NONCE_LEN: usize = 12;
/// Argon2id salt length written by `wrap_key_with_pin` and by the 0x02
/// `identity.key` layout; the duress blob shares the identity salt, so the
/// two lengths must agree.
pub const SALT_LEN: usize = 32;
/// Wrapped identity key: 32 key bytes + 16-byte Poly1305 tag.
const WRAPPED_KEY_LEN: usize = 48;

/// Format byte written at the front of the sealed attempt counter.
const COUNTER_VERSION: u8 = 0x01;
/// Associated data that binds the sealed counter to its purpose, so a blob
/// sealed under the same key for some other record cannot be swapped in.
const COUNTER_AAD: &[u8] = b"mesh-infinity-pin-attempt-counter-v1";

/// PIN attempt backoff schedule (§3.10): seconds of delay imposed *after*
/// the N-th consecutive failure. Index 0 is "one failure"; the last entry
/// applies to every failure beyond the table.
// BACKOFF_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
const BACKOFF_SECS: [u64; 11] = [
    0, 0, 0, 0, 0,      // attempts 1-5: no delay
    30,     // attempt 6
    120,    // attempt 7: 2 minutes
    600,    // attempt 8: 10 minutes
    3600,   // attempt 9: 1 hour
    86400,  // attempt 10: 24 hours
    259200, // attempt 11+: 72 hours
];

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
// PinError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PinError {
    #[error("Argon2id derivation failed: {0}")]
    // Argon2id password hashing for key derivation.
    Argon2(String),
    #[error("AEAD encryption failed")]
    Encrypt,
    #[error("AEAD decryption failed — wrong PIN")]
    WrongPin,
    #[error("Account locked — too many attempts")]
    LockedOut,
    #[error("PIN too short (minimum 4 digits)")]
    TooShort,
    #[error("PIN too long (maximum 16 digits)")]
    TooLong,
    /// `pin.dat` did not have the field lengths this module writes. A
    /// truncated or tampered file is reported, never panicked on, because
    /// every unlock path reaches this code across the FFI boundary.
    #[error("PIN record is malformed (unexpected field length)")]
    Malformed,
    /// Stored Argon2id parameters are below the §3.7.4 floor. A record that
    /// claims weaker parameters than the spec minimum is either from a
    /// broken writer or an attacker trying to make brute force cheaper.
    #[error("PIN record uses Argon2id parameters below the spec minimum")]
    WeakParams,
    /// Stored Argon2id parameters exceed the §3.7.4 ceilings. The header is
    /// untrusted storage; without this check a tampered record could demand
    /// a multi-gigabyte allocation before the first byte is authenticated.
    #[error("PIN record uses Argon2id parameters above the accepted ceiling")]
    ParamsTooLarge,
    /// The sealed attempt counter is missing, truncated, or fails
    /// authentication. With a PIN configured this is tampering (§3.10).
    #[error("PIN attempt counter is missing or failed authentication")]
    CounterTampered,
}

// ---------------------------------------------------------------------------
// Argon2id parameter triple
// ---------------------------------------------------------------------------

/// Argon2id cost triple stored next to every PIN-wrapped blob (§3.6.2:
/// "`pin.dat` stores: Argon2id params + salt + encrypt(...)").
///
/// Storing the parameters makes a record self-describing, so a future bump
/// of the defaults cannot silently orphan existing identities, and lets the
/// loader refuse records outside the §3.7.4 window before running the KDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Number of passes over the memory.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// The parameters every record written by the current build uses.
    pub const SPEC: KdfParams = KdfParams {
        m_cost: ARGON2_M_COST,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
    };

    /// Parameters the legacy `identity.key` mode 0x01 layout was written
    /// with: the argon2 crate's defaults at the time (19 MiB, t=2, p=1).
    ///
    /// They are below the spec floor and exist only so a 0x01 file can be
    /// read once and re-wrapped under `SPEC`; `validate` rejects them, and
    /// no code path writes them. A test pins them to the crate's defaults
    /// so a crate upgrade that changes the defaults is caught at once.
    pub const LEGACY_0X01: KdfParams = KdfParams {
        m_cost: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    /// Reject parameters outside the §3.7.4 window.
    ///
    /// Called before any derivation on parameters read from storage. The
    /// floor keeps an extracted blob at least as expensive to brute-force
    /// as the spec promises; the ceiling keeps a tampered header from
    /// turning into a denial of service.
    pub fn validate(&self) -> Result<(), PinError> {
        // Below the floor: cheaper than the spec allows.
        if self.m_cost < ARGON2_M_COST || self.t_cost < ARGON2_T_COST || self.p_cost < ARGON2_P_COST
        {
            return Err(PinError::WeakParams);
        }
        // Above the ceiling: a resource-exhaustion vector, never legitimate.
        if self.m_cost > MAX_M_COST || self.t_cost > MAX_T_COST || self.p_cost > MAX_P_COST {
            return Err(PinError::ParamsTooLarge);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PIN-wrapped key storage
// ---------------------------------------------------------------------------

/// Stored on disk when a duress PIN is configured (`pin.dat`).
/// Contains the identity master key wrapped by Argon2id(duress PIN).
///
/// The salt and parameters are those of the primary `identity.key` wrap at
/// the time the duress PIN was set, so one derivation serves both blobs.
#[derive(Serialize, Deserialize, Clone)]
// PinWrappedKey — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PinWrappedKey {
    /// Argon2id salt (32 bytes)
    pub salt: Vec<u8>,
    /// Argon2id parameters
    pub m_cost: u32,
    /// The t cost for this instance.
    pub t_cost: u32,
    /// The p cost for this instance.
    pub p_cost: u32,
    /// Nonce for ChaCha20-Poly1305 encryption of identity.key
    pub nonce: Vec<u8>,
    /// Encrypted identity.key (32 bytes + 16 byte auth tag = 48 bytes)
    pub ciphertext: Vec<u8>,
}

impl PinWrappedKey {
    /// The parameter triple this record was wrapped under.
    pub fn params(&self) -> KdfParams {
        KdfParams {
            m_cost: self.m_cost,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
        }
    }

    /// Validate every length the record is supposed to have before any
    /// field reaches Argon2 or the AEAD. `Nonce::from_slice` panics on
    /// anything but 12 bytes, and a corrupted pin.dat (crash mid-write, disk
    /// error, tampering) must turn into a typed error, not a panic unwinding
    /// through `extern "C"`.
    fn check_lengths(&self) -> Result<(), PinError> {
        if self.nonce.len() != NONCE_LEN
            || self.salt.len() != SALT_LEN
            || self.ciphertext.len() != WRAPPED_KEY_LEN
        {
            return Err(PinError::Malformed);
        }
        Ok(())
    }
}

/// PIN attempt tracking state (§3.10 "attempt counter").
///
/// Persisted only through `seal_attempt_state` / `open_attempt_state`, so
/// the plaintext never sits on disk unauthenticated.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
// PinAttemptState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PinAttemptState {
    /// Number of consecutive failed attempts
    pub failed_attempts: u32,
    /// Unix timestamp of last failed attempt. Also the rollback reference:
    /// a current time earlier than this means the clock moved backwards.
    pub last_failed_at: u64,
    /// Wipe threshold (None = no auto-wipe). Stored here because the
    /// settings vault that also holds it is encrypted under the master key
    /// and therefore unreadable at the unlock screen where it must apply.
    pub wipe_threshold: Option<u32>,
}

// ---------------------------------------------------------------------------
// PIN operations
// ---------------------------------------------------------------------------

/// Validate PIN length (4-16 digits).
pub fn validate_pin(pin: &[u8]) -> Result<(), PinError> {
    // Validate the input length to prevent out-of-bounds access.
    if pin.len() < 4 {
        return Err(PinError::TooShort);
    }
    // Validate the input length to prevent out-of-bounds access.
    if pin.len() > 16 {
        return Err(PinError::TooLong);
    }
    Ok(())
}

/// Derive the 32-byte wrapping key from a PIN with Argon2id.
///
/// This is the one derivation the whole PIN system goes through: the
/// `identity.key` wrap, the duress blob, PIN changes and every unlock
/// attempt call it with the parameters and salt stored in the record. The
/// parameters are validated first so storage can never make this cheaper
/// than the spec floor or more expensive than the ceiling.
pub fn derive_key_from_pin(
    pin: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, PinError> {
    // Refuse out-of-window parameters before touching memory.
    params.validate()?;
    derive_key_unchecked(pin, salt, params)
}

/// Derivation without the window check, for reading the legacy 0x01
/// `identity.key` layout whose fixed parameters are below the floor.
///
/// Crate-private so the only caller is the legacy loader; every other path
/// goes through `derive_key_from_pin`.
pub(crate) fn derive_key_unchecked(
    pin: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, PinError> {
    // Configure the operation parameters.
    let params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        // Map the error to the local error type.
        .map_err(|e| PinError::Argon2(e.to_string()))?;
    // Configure the operation parameters.
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Allocate the output buffer for the result.
    let mut output = Zeroizing::new([0u8; 32]);
    // Argon2id password hashing for key derivation.
    argon2
        .hash_password_into(pin, salt, &mut *output)
        // Map the error to the local error type.
        .map_err(|e| PinError::Argon2(e.to_string()))?;
    Ok(output)
}

/// Wrap (encrypt) an identity key under an already-derived wrapping key.
///
/// `salt` and `params` are recorded verbatim so the record stays
/// self-describing; no derivation happens here. The service layer uses this
/// to wrap the duress blob under the primary wrap's salt, and to wrap the
/// post-duress identity without a second Argon2 pass.
pub fn wrap_key_under(
    identity_key: &[u8; 32],
    wrapping_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<PinWrappedKey, PinError> {
    // Generate nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    // OS-provided cryptographic random number generator.
    OsRng.fill_bytes(&mut nonce_bytes);

    // Initialize the AEAD cipher with the derived key material.
    let cipher = ChaCha20Poly1305::new_from_slice(wrapping_key)
        // Map the error to the local error type.
        .map_err(|_| PinError::Encrypt)?;
    // Fresh nonce — must never be reused with the same key.
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        // AEAD-encrypt the plaintext.
        .encrypt(nonce, identity_key.as_ref())
        // Map the error to the local error type.
        .map_err(|_| PinError::Encrypt)?;

    Ok(PinWrappedKey {
        salt: salt.to_vec(),
        m_cost: params.m_cost,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Wrap (encrypt) an identity key with a PIN under a fresh random salt and
/// the spec parameters.
///
/// Returns the encrypted key blob to store on disk.
pub fn wrap_key_with_pin(identity_key: &[u8; 32], pin: &[u8]) -> Result<PinWrappedKey, PinError> {
    validate_pin(pin)?;

    // Generate salt
    let mut salt = [0u8; SALT_LEN];
    // OS-provided cryptographic random number generator.
    OsRng.fill_bytes(&mut salt);

    // Derive wrapping key through the shared derivation.
    let wrapping_key = derive_key_from_pin(pin, &salt, KdfParams::SPEC)?;
    wrap_key_under(identity_key, &wrapping_key, &salt, KdfParams::SPEC)
}

/// Open a wrapped record under an already-derived wrapping key.
///
/// No derivation happens here, so trying the same key against several
/// records (primary and duress) costs microseconds and leaks nothing about
/// which one, if any, matched.
pub fn open_wrapped_key(
    wrapped: &PinWrappedKey,
    wrapping_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, PinError> {
    // Lengths first: untrusted storage must never reach a panicking slice.
    wrapped.check_lengths()?;

    // Initialize the AEAD cipher with the derived key material.
    let cipher = ChaCha20Poly1305::new_from_slice(wrapping_key)
        // Map the error to the local error type.
        .map_err(|_| PinError::WrongPin)?;
    let nonce = Nonce::from_slice(&wrapped.nonce);
    let plaintext = Zeroizing::new(
        cipher
            // AEAD-decrypt and authenticate the ciphertext.
            .decrypt(nonce, wrapped.ciphertext.as_ref())
            // Map the error to the local error type.
            .map_err(|_| PinError::WrongPin)?,
    );

    // Validate the input length to prevent out-of-bounds access.
    if plaintext.len() != 32 {
        return Err(PinError::WrongPin);
    }

    let mut key = Zeroizing::new([0u8; 32]);
    // Copy into the fixed-size buffer.
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Unwrap (decrypt) an identity key with a PIN.
///
/// On success, returns the 32-byte identity key.
/// On failure (wrong PIN), returns PinError::WrongPin.
/// Derives under the record's own salt and parameters; the parameters are
/// validated against the §3.7.4 window before the derivation runs.
pub fn unwrap_key_with_pin(
    wrapped: &PinWrappedKey,
    pin: &[u8],
) -> Result<Zeroizing<[u8; 32]>, PinError> {
    // Lengths before parameters before crypto: cheapest rejection first.
    wrapped.check_lengths()?;

    // Always run Argon2id regardless of PIN validity (timing normalization)
    let wrapping_key = derive_key_from_pin(pin, &wrapped.salt, wrapped.params())?;
    open_wrapped_key(wrapped, &wrapping_key)
}

// ---------------------------------------------------------------------------
// Sealed attempt counter
// ---------------------------------------------------------------------------

/// Seal the attempt counter for storage: `[0x01][12-byte nonce][AEAD(JSON)]`.
///
/// The counter is encrypted and authenticated under `counter_key` with a
/// fixed associated-data string. An edit to any byte fails authentication
/// on the next open; a deleted file is a missing record. Both are treated
/// as tampering by the service layer when a PIN is configured (§3.10).
pub fn seal_attempt_state(
    state: &PinAttemptState,
    counter_key: &[u8; 32],
) -> Result<Vec<u8>, PinError> {
    // Serialize to the wire format for storage.
    let plaintext = serde_json::to_vec(state).map_err(|_| PinError::Encrypt)?;

    // Fresh nonce — must never be reused with the same key.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    // OS-provided cryptographic random number generator.
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Initialize the AEAD cipher with the counter key.
    let cipher = ChaCha20Poly1305::new_from_slice(counter_key)
        // Map the error to the local error type.
        .map_err(|_| PinError::Encrypt)?;
    let ciphertext = cipher
        // AEAD-encrypt with the purpose string bound as associated data.
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: COUNTER_AAD,
            },
        )
        // Map the error to the local error type.
        .map_err(|_| PinError::Encrypt)?;

    // Assemble the on-disk layout.
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    // Append to the collection.
    out.push(COUNTER_VERSION);
    // Append bytes to the accumulator.
    out.extend_from_slice(&nonce_bytes);
    // Append bytes to the accumulator.
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed attempt counter written by `seal_attempt_state`.
///
/// Every structural or authentication failure maps to `CounterTampered`:
/// the caller cannot distinguish "corrupt" from "edited" and must not try,
/// because an attacker controls which of the two a tampered file looks like.
pub fn open_attempt_state(
    sealed: &[u8],
    counter_key: &[u8; 32],
) -> Result<PinAttemptState, PinError> {
    // Version byte, nonce, and at least a Poly1305 tag must be present.
    if sealed.len() < 1 + NONCE_LEN + 16 || sealed[0] != COUNTER_VERSION {
        return Err(PinError::CounterTampered);
    }
    let nonce = Nonce::from_slice(&sealed[1..1 + NONCE_LEN]);
    let ciphertext = &sealed[1 + NONCE_LEN..];

    // Initialize the AEAD cipher with the counter key.
    let cipher = ChaCha20Poly1305::new_from_slice(counter_key)
        // Map the error to the local error type.
        .map_err(|_| PinError::CounterTampered)?;
    let plaintext = cipher
        // AEAD-decrypt and authenticate against the purpose string.
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: COUNTER_AAD,
            },
        )
        // Map the error to the local error type.
        .map_err(|_| PinError::CounterTampered)?;

    // A record that authenticates but does not parse was written by a
    // different schema; refuse rather than guess.
    serde_json::from_slice(&plaintext).map_err(|_| PinError::CounterTampered)
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

/// Get the backoff delay (in seconds) for the given failed attempt count.
/// attempt=0 means no failures yet, attempt=1 means 1 failure, etc.
pub fn backoff_delay(failed_attempts: u32) -> u64 {
    // No failures yet: nothing to wait for.
    if failed_attempts == 0 {
        return 0;
    }
    // Attempt N reads row N-1; anything past the table clamps to the last
    // row (72 hours per attempt, §3.10).
    let idx = (failed_attempts as usize - 1).min(BACKOFF_SECS.len() - 1);
    BACKOFF_SECS[idx]
}

/// Check if the current attempt is allowed given the state and current time.
///
/// `now_unix` must come from the wall clock *after* the caller has verified
/// the clock is readable; a clock error is never mapped to zero here.
///
/// Clock rollback rule: if there has been at least one failure and the
/// current time is earlier than that failure, the clock has moved backwards
/// (adversary, or a user "fixing" the date to shortcut the wait). The
/// attempt stays locked until the clock passes the recorded failure time
/// again — the conservative reading of §3.10's "not user-configurable".
pub fn is_attempt_allowed(state: &PinAttemptState, now_unix: u64) -> Result<(), PinError> {
    // Check wipe threshold
    if let Some(threshold) = state.wipe_threshold {
        // At or past the threshold the next attempt is never allowed; the
        // service layer wipes instead of waiting.
        if state.failed_attempts >= threshold {
            return Err(PinError::LockedOut);
        }
    }

    // Rollback: a failure recorded in the future means the clock went back.
    if state.failed_attempts > 0 && now_unix < state.last_failed_at {
        return Err(PinError::LockedOut);
    }

    // Check backoff
    let delay = backoff_delay(state.failed_attempts);
    // Bounds check to enforce protocol constraints.
    if delay > 0 {
        // Elapsed since the last failure; saturating is safe after the
        // rollback check above has ruled out now < last_failed_at.
        let elapsed = now_unix.saturating_sub(state.last_failed_at);
        // Still inside the delay window.
        if elapsed < delay {
            return Err(PinError::LockedOut);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let identity_key = [0x42u8; 32];
        let pin = b"123456";

        let wrapped = wrap_key_with_pin(&identity_key, pin).unwrap();
        let unwrapped = unwrap_key_with_pin(&wrapped, pin).unwrap();

        assert_eq!(*unwrapped, identity_key);
    }

    /// Every record the current build writes carries the spec parameters.
    #[test]
    fn test_wrapped_record_meets_spec_floor() {
        let wrapped = wrap_key_with_pin(&[0x42u8; 32], b"1234").expect("wrap");
        assert_eq!(wrapped.params(), KdfParams::SPEC);
        assert!(wrapped.params().validate().is_ok());
    }

    /// The legacy constants must track the argon2 crate's defaults exactly,
    /// otherwise a crate upgrade would silently orphan every 0x01 file.
    #[test]
    fn test_legacy_params_match_crate_defaults() {
        let defaults = Params::default();
        assert_eq!(KdfParams::LEGACY_0X01.m_cost, defaults.m_cost());
        assert_eq!(KdfParams::LEGACY_0X01.t_cost, defaults.t_cost());
        assert_eq!(KdfParams::LEGACY_0X01.p_cost, defaults.p_cost());
        // And they are below the floor, so `validate` must refuse them.
        assert!(matches!(
            KdfParams::LEGACY_0X01.validate(),
            Err(PinError::WeakParams)
        ));
    }

    /// Parameters below the floor are refused before any derivation runs.
    #[test]
    fn test_weak_params_rejected_without_derivation() {
        let mut wrapped = wrap_key_with_pin(&[0x11u8; 32], b"1234").expect("wrap");
        wrapped.m_cost = 1024;
        let started = std::time::Instant::now();
        assert!(matches!(
            unwrap_key_with_pin(&wrapped, b"1234"),
            Err(PinError::WeakParams)
        ));
        // A real derivation takes hundreds of milliseconds; a rejection
        // must be effectively instant.
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    /// Parameters above the ceiling are refused before any allocation.
    #[test]
    fn test_oversized_params_rejected_without_allocation() {
        let mut wrapped = wrap_key_with_pin(&[0x11u8; 32], b"1234").expect("wrap");
        wrapped.m_cost = u32::MAX;
        assert!(matches!(
            unwrap_key_with_pin(&wrapped, b"1234"),
            Err(PinError::ParamsTooLarge)
        ));
        let mut wrapped = wrap_key_with_pin(&[0x11u8; 32], b"1234").expect("wrap");
        wrapped.p_cost = MAX_P_COST + 1;
        assert!(matches!(
            unwrap_key_with_pin(&wrapped, b"1234"),
            Err(PinError::ParamsTooLarge)
        ));
    }

    /// A truncated nonce must be a typed error, not a panic: this is the
    /// FFI-reachable unlock path and pin.dat is untrusted storage.
    #[test]
    fn test_malformed_nonce_length_rejected() {
        let key = Zeroizing::new([0x11u8; 32]);
        let mut wrapped = wrap_key_with_pin(&key, b"1234").expect("wrap");
        wrapped.nonce.truncate(8);
        assert!(matches!(
            unwrap_key_with_pin(&wrapped, b"1234"),
            Err(PinError::Malformed)
        ));
    }

    /// Same for the salt and the ciphertext: every field length is checked
    /// before the record reaches Argon2 or the AEAD.
    #[test]
    fn test_malformed_salt_and_ciphertext_rejected() {
        let key = Zeroizing::new([0x22u8; 32]);
        let good = wrap_key_with_pin(&key, b"1234").expect("wrap");

        let mut short_salt = good.clone();
        short_salt.salt.pop();
        assert!(matches!(
            unwrap_key_with_pin(&short_salt, b"1234"),
            Err(PinError::Malformed)
        ));

        let mut long_ct = good.clone();
        long_ct.ciphertext.push(0);
        assert!(matches!(
            unwrap_key_with_pin(&long_ct, b"1234"),
            Err(PinError::Malformed)
        ));

        // The untouched record still unwraps, so the checks are exact.
        assert!(unwrap_key_with_pin(&good, b"1234").is_ok());
    }

    #[test]
    fn test_wrong_pin_fails() {
        let identity_key = [0x42u8; 32];
        let wrapped = wrap_key_with_pin(&identity_key, b"123456").unwrap();
        let result = unwrap_key_with_pin(&wrapped, b"654321");
        assert!(result.is_err());
    }

    /// One derivation can be tried against two records wrapped under the
    /// same salt and parameters; only the record wrapped with that PIN opens.
    #[test]
    fn test_single_derivation_opens_only_matching_record() {
        let salt = [0x5Au8; SALT_LEN];
        let key_a = derive_key_from_pin(b"1111", &salt, KdfParams::SPEC).expect("derive a");
        let key_b = derive_key_from_pin(b"2222", &salt, KdfParams::SPEC).expect("derive b");
        let rec_a = wrap_key_under(&[0xAAu8; 32], &key_a, &salt, KdfParams::SPEC).expect("wrap a");
        let rec_b = wrap_key_under(&[0xBBu8; 32], &key_b, &salt, KdfParams::SPEC).expect("wrap b");

        assert_eq!(*open_wrapped_key(&rec_a, &key_a).expect("a opens a"), [0xAAu8; 32]);
        assert!(matches!(open_wrapped_key(&rec_b, &key_a), Err(PinError::WrongPin)));
        assert_eq!(*open_wrapped_key(&rec_b, &key_b).expect("b opens b"), [0xBBu8; 32]);
        assert!(matches!(open_wrapped_key(&rec_a, &key_b), Err(PinError::WrongPin)));
    }

    #[test]
    fn test_pin_too_short() {
        assert!(validate_pin(b"123").is_err());
    }

    #[test]
    fn test_pin_too_long() {
        assert!(validate_pin(b"12345678901234567").is_err());
    }

    #[test]
    fn test_pin_valid_lengths() {
        assert!(validate_pin(b"1234").is_ok());
        assert!(validate_pin(b"1234567890123456").is_ok());
    }

    #[test]
    fn test_backoff_schedule() {
        assert_eq!(backoff_delay(0), 0);
        assert_eq!(backoff_delay(1), 0);
        assert_eq!(backoff_delay(5), 0);
        assert_eq!(backoff_delay(6), 30);
        assert_eq!(backoff_delay(7), 120);
        assert_eq!(backoff_delay(8), 600);
        assert_eq!(backoff_delay(9), 3600);
        assert_eq!(backoff_delay(10), 86400);
        assert_eq!(backoff_delay(11), 259200);
        assert_eq!(backoff_delay(100), 259200); // clamp at max
    }

    #[test]
    fn test_attempt_allowed_fresh() {
        let state = PinAttemptState::default();
        assert!(is_attempt_allowed(&state, 0).is_ok());
    }

    #[test]
    fn test_attempt_blocked_by_backoff() {
        let state = PinAttemptState {
            failed_attempts: 6, // 30 second delay
            last_failed_at: 100,
            wipe_threshold: None,
        };
        // Too soon
        assert!(is_attempt_allowed(&state, 110).is_err());
        // After delay
        assert!(is_attempt_allowed(&state, 131).is_ok());
    }

    /// Moving the clock backwards past the last failure keeps the lock,
    /// even though a naive "elapsed" computation would saturate to zero and
    /// a naive "72 h have passed" check could be satisfied by jumping
    /// forward and back.
    #[test]
    fn test_clock_rollback_stays_locked() {
        let state = PinAttemptState {
            failed_attempts: 6,
            last_failed_at: 1_000_000,
            wipe_threshold: None,
        };
        // Clock reads earlier than the failure: rollback, still locked.
        assert!(matches!(
            is_attempt_allowed(&state, 500_000),
            Err(PinError::LockedOut)
        ));
        // Even one second before the failure counts as rollback.
        assert!(is_attempt_allowed(&state, 999_999).is_err());
        // Once the clock passes failure + delay the attempt is allowed.
        assert!(is_attempt_allowed(&state, 1_000_031).is_ok());
    }

    /// With no failures recorded there is nothing to protect, so an odd
    /// clock must not lock a user out of a fresh counter.
    #[test]
    fn test_rollback_rule_ignores_fresh_counter() {
        let state = PinAttemptState {
            failed_attempts: 0,
            last_failed_at: 1_000_000,
            wipe_threshold: None,
        };
        assert!(is_attempt_allowed(&state, 0).is_ok());
    }

    #[test]
    fn test_wipe_threshold() {
        let state = PinAttemptState {
            failed_attempts: 10,
            last_failed_at: 0,
            wipe_threshold: Some(10),
        };
        assert!(is_attempt_allowed(&state, 999999).is_err());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let pin = b"123456";
        let wrapped1 = wrap_key_with_pin(&[0x42u8; 32], pin).unwrap();
        let wrapped2 = wrap_key_with_pin(&[0x42u8; 32], pin).unwrap();
        // Different salts → different ciphertexts
        assert_ne!(wrapped1.ciphertext, wrapped2.ciphertext);
    }

    // ── Sealed attempt counter ───────────────────────────────────────────

    /// Seal and open round-trips every field.
    #[test]
    fn test_counter_seal_open_roundtrip() {
        let key = [0x77u8; 32];
        let state = PinAttemptState {
            failed_attempts: 7,
            last_failed_at: 123_456,
            wipe_threshold: Some(10),
        };
        let sealed = seal_attempt_state(&state, &key).expect("seal");
        let opened = open_attempt_state(&sealed, &key).expect("open");
        assert_eq!(opened, state);
    }

    /// Any edited byte — version, nonce, ciphertext or tag — is tampering.
    #[test]
    fn test_counter_edit_detected() {
        let key = [0x77u8; 32];
        let sealed = seal_attempt_state(&PinAttemptState::default(), &key).expect("seal");
        for idx in 0..sealed.len() {
            let mut edited = sealed.clone();
            edited[idx] ^= 0x01;
            assert!(
                matches!(open_attempt_state(&edited, &key), Err(PinError::CounterTampered)),
                "flipping byte {idx} must fail authentication"
            );
        }
    }

    /// A counter sealed under one key never opens under another, so a
    /// swapped-in key file is detected as tampering.
    #[test]
    fn test_counter_wrong_key_detected() {
        let sealed = seal_attempt_state(&PinAttemptState::default(), &[0x01u8; 32]).expect("seal");
        assert!(matches!(
            open_attempt_state(&sealed, &[0x02u8; 32]),
            Err(PinError::CounterTampered)
        ));
    }

    /// Truncated and empty records are typed errors, never panics.
    #[test]
    fn test_counter_truncation_detected() {
        let key = [0x77u8; 32];
        let sealed = seal_attempt_state(&PinAttemptState::default(), &key).expect("seal");
        for len in 0..sealed.len() {
            assert!(matches!(
                open_attempt_state(&sealed[..len], &key),
                Err(PinError::CounterTampered)
            ));
        }
    }
}
