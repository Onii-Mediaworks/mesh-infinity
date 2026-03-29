//! App PIN (§3.10, §3.6.2)
//!
//! PIN wraps `identity.key` via Argon2id. Without PIN entry:
//! Layer 1 active, Layers 2/3 inaccessible.
//!
//! Security properties:
//! - Argon2id derivation runs for every attempt regardless of correctness (timing normalization)
//! - Attempt counter persists across app restarts (stored in keystore)
//! - Backoff: attempts 1-5 no delay, 6=30s, 7=2m, 8=10m, 9=1h, 10=24h, 11+=72h
//! - Key clearing uses atomic once-flag (§3.6.4 race condition fix)

use argon2::{Argon2, Algorithm, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum Argon2id parameters (§3.7.4 — backup minimum; PIN uses same or higher)
const ARGON2_M_COST: u32 = 65536; // 64 MB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// PIN attempt backoff schedule (§3.10)
const BACKOFF_SECS: [u64; 11] = [
    0, 0, 0, 0, 0,     // attempts 1-5: no delay
    30,                  // attempt 6
    120,                 // attempt 7: 2 minutes
    600,                 // attempt 8: 10 minutes
    3600,                // attempt 9: 1 hour
    86400,               // attempt 10: 24 hours
    259200,              // attempt 11+: 72 hours
];

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("Argon2id derivation failed: {0}")]
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
}

// ---------------------------------------------------------------------------
// PIN-wrapped key storage
// ---------------------------------------------------------------------------

/// Stored on disk when a PIN is configured.
/// Contains the encrypted identity.key wrapped by Argon2id(PIN).
#[derive(Serialize, Deserialize, Clone)]
pub struct PinWrappedKey {
    /// Argon2id salt (32 bytes)
    pub salt: Vec<u8>,
    /// Argon2id parameters
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// Nonce for ChaCha20-Poly1305 encryption of identity.key
    pub nonce: Vec<u8>,
    /// Encrypted identity.key (32 bytes + 16 byte auth tag = 48 bytes)
    pub ciphertext: Vec<u8>,
}

/// PIN attempt tracking state.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(Default)]
pub struct PinAttemptState {
    /// Number of consecutive failed attempts
    pub failed_attempts: u32,
    /// Unix timestamp of last failed attempt
    pub last_failed_at: u64,
    /// Wipe threshold (None = no auto-wipe)
    pub wipe_threshold: Option<u32>,
}


// ---------------------------------------------------------------------------
// PIN operations
// ---------------------------------------------------------------------------

/// Validate PIN length (4-16 digits).
pub fn validate_pin(pin: &[u8]) -> Result<(), PinError> {
    if pin.len() < 4 {
        return Err(PinError::TooShort);
    }
    if pin.len() > 16 {
        return Err(PinError::TooLong);
    }
    Ok(())
}

/// Derive an encryption key from a PIN using Argon2id.
fn derive_key_from_pin(pin: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, PinError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| PinError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(pin, salt, &mut *output)
        .map_err(|e| PinError::Argon2(e.to_string()))?;
    Ok(output)
}

/// Wrap (encrypt) an identity key with a PIN.
///
/// Returns the encrypted key blob to store on disk.
pub fn wrap_key_with_pin(
    identity_key: &[u8; 32],
    pin: &[u8],
) -> Result<PinWrappedKey, PinError> {
    validate_pin(pin)?;

    // Generate salt
    let mut salt = vec![0u8; 32];
    OsRng.fill_bytes(&mut salt);

    // Derive wrapping key
    let wrapping_key = derive_key_from_pin(pin, &salt)?;

    // Generate nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Encrypt identity key
    let cipher = ChaCha20Poly1305::new_from_slice(&*wrapping_key)
        .map_err(|_| PinError::Encrypt)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, identity_key.as_ref())
        .map_err(|_| PinError::Encrypt)?;

    Ok(PinWrappedKey {
        salt,
        m_cost: ARGON2_M_COST,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Unwrap (decrypt) an identity key with a PIN.
///
/// On success, returns the 32-byte identity key.
/// On failure (wrong PIN), returns PinError::WrongPin.
/// Timing is constant regardless of correctness (Argon2id always runs).
pub fn unwrap_key_with_pin(
    wrapped: &PinWrappedKey,
    pin: &[u8],
) -> Result<Zeroizing<[u8; 32]>, PinError> {
    // Always run Argon2id regardless of PIN validity (timing normalization)
    let wrapping_key = derive_key_from_pin(pin, &wrapped.salt)?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&*wrapping_key)
        .map_err(|_| PinError::WrongPin)?;
    let nonce = Nonce::from_slice(&wrapped.nonce);
    let plaintext = cipher
        .decrypt(nonce, wrapped.ciphertext.as_ref())
        .map_err(|_| PinError::WrongPin)?;

    if plaintext.len() != 32 {
        return Err(PinError::WrongPin);
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Get the backoff delay (in seconds) for the given failed attempt count.
/// attempt=0 means no failures yet, attempt=1 means 1 failure, etc.
pub fn backoff_delay(failed_attempts: u32) -> u64 {
    if failed_attempts <= 5 {
        return 0; // First 5 attempts: no delay
    }
    // Attempts 6+ use the schedule
    let _idx = ((failed_attempts - 5) as usize).min(BACKOFF_SECS.len() - 6);
    match failed_attempts {
        6 => 30,
        7 => 120,
        8 => 600,
        9 => 3600,
        10 => 86400,
        _ => 259200, // 11+: 72 hours
    }
}

/// Check if the current attempt is allowed given the state and current time.
pub fn is_attempt_allowed(state: &PinAttemptState, now_unix: u64) -> Result<(), PinError> {
    // Check wipe threshold
    if let Some(threshold) = state.wipe_threshold {
        if state.failed_attempts >= threshold {
            return Err(PinError::LockedOut);
        }
    }

    // Check backoff
    let delay = backoff_delay(state.failed_attempts);
    if delay > 0 {
        let elapsed = now_unix.saturating_sub(state.last_failed_at);
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

    #[test]
    fn test_wrong_pin_fails() {
        let identity_key = [0x42u8; 32];
        let wrapped = wrap_key_with_pin(&identity_key, b"123456").unwrap();
        let result = unwrap_key_with_pin(&wrapped, b"654321");
        assert!(result.is_err());
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
}
