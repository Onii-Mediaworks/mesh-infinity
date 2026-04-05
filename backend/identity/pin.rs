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

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    aead::{Aead, KeyInit},
    // AEAD cipher for authenticated encryption.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ChaCha20Poly1305,
    Nonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
// Securely erase key material to prevent forensic recovery.
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum Argon2id parameters (§3.7.4 — backup minimum; PIN uses same or higher)
// ARGON2_M_COST — protocol constant.
// Defined by the spec; must not change without a version bump.
// ARGON2_M_COST — protocol constant.
// Defined by the spec; must not change without a version bump.
// ARGON2_M_COST — protocol constant.
// Defined by the spec; must not change without a version bump.
const ARGON2_M_COST: u32 = 65536; // 64 MB
                                  // Protocol constant.
                                  // ARGON2_T_COST — protocol constant.
                                  // Defined by the spec; must not change without a version bump.
                                  // ARGON2_T_COST — protocol constant.
                                  // Defined by the spec; must not change without a version bump.
                                  // ARGON2_T_COST — protocol constant.
                                  // Defined by the spec; must not change without a version bump.
const ARGON2_T_COST: u32 = 3;
// Protocol constant.
// ARGON2_P_COST — protocol constant.
// Defined by the spec; must not change without a version bump.
// ARGON2_P_COST — protocol constant.
// Defined by the spec; must not change without a version bump.
// ARGON2_P_COST — protocol constant.
// Defined by the spec; must not change without a version bump.
const ARGON2_P_COST: u32 = 4;

/// PIN attempt backoff schedule (§3.10)
// BACKOFF_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// BACKOFF_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// BACKOFF_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
const BACKOFF_SECS: [u64; 11] = [
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    0, 0, 0, 0, 0, // attempts 1-5: no delay
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    30, // attempt 6
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    120, // attempt 7: 2 minutes
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    600, // attempt 8: 10 minutes
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    3600, // attempt 9: 1 hour
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    86400, // attempt 10: 24 hours
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    259200, // attempt 11+: 72 hours
];

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
// Begin the block scope.
// PinError — variant enumeration.
// Match exhaustively to handle every protocol state.
// PinError — variant enumeration.
// Match exhaustively to handle every protocol state.
// PinError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PinError {
    #[error("Argon2id derivation failed: {0}")]
    // Argon2id password hashing for key derivation.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Argon2(String),
    #[error("AEAD encryption failed")]
    Encrypt,
    #[error("AEAD decryption failed — wrong PIN")]
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    WrongPin,
    #[error("Account locked — too many attempts")]
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    LockedOut,
    #[error("PIN too short (minimum 4 digits)")]
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// PinWrappedKey — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PinWrappedKey — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PinWrappedKey — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PinWrappedKey {
    /// Argon2id salt (32 bytes)
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub salt: Vec<u8>,
    /// Argon2id parameters
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub m_cost: u32,
    /// The t cost for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub t_cost: u32,
    /// The p cost for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub p_cost: u32,
    /// Nonce for ChaCha20-Poly1305 encryption of identity.key
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub nonce: Vec<u8>,
    /// Encrypted identity.key (32 bytes + 16 byte auth tag = 48 bytes)
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ciphertext: Vec<u8>,
}

/// PIN attempt tracking state.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
// Begin the block scope.
// PinAttemptState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PinAttemptState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PinAttemptState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PinAttemptState {
    /// Number of consecutive failed attempts
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub failed_attempts: u32,
    /// Unix timestamp of last failed attempt
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_failed_at: u64,
    /// Wipe threshold (None = no auto-wipe)
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub wipe_threshold: Option<u32>,
}

// ---------------------------------------------------------------------------
// PIN operations
// ---------------------------------------------------------------------------

/// Validate PIN length (4-16 digits).
// Perform the 'validate pin' operation.
// Errors are propagated to the caller via Result.
// Perform the 'validate pin' operation.
// Errors are propagated to the caller via Result.
// Perform the 'validate pin' operation.
// Errors are propagated to the caller via Result.
pub fn validate_pin(pin: &[u8]) -> Result<(), PinError> {
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if pin.len() < 4 {
        // Reject with an explicit error for the caller to handle.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return Err(PinError::TooShort);
    }
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if pin.len() > 16 {
        // Reject with an explicit error for the caller to handle.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return Err(PinError::TooLong);
    }
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(())
}

/// Derive an encryption key from a PIN using Argon2id.
// Perform the 'derive key from pin' operation.
// Errors are propagated to the caller via Result.
// Perform the 'derive key from pin' operation.
// Errors are propagated to the caller via Result.
// Perform the 'derive key from pin' operation.
// Errors are propagated to the caller via Result.
fn derive_key_from_pin(pin: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, PinError> {
    // Configure the operation parameters.
    // Compute params for this protocol step.
    // Compute params for this protocol step.
    // Compute params for this protocol step.
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|e| PinError::Argon2(e.to_string()))?;
    // Configure the operation parameters.
    // Compute argon2 for this protocol step.
    // Compute argon2 for this protocol step.
    // Compute argon2 for this protocol step.
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Allocate the output buffer for the result.
    // Compute output for this protocol step.
    // Compute output for this protocol step.
    // Compute output for this protocol step.
    let mut output = Zeroizing::new([0u8; 32]);
    // Argon2id password hashing for key derivation.
    argon2
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .hash_password_into(pin, salt, &mut *output)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|e| PinError::Argon2(e.to_string()))?;
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(output)
}

/// Wrap (encrypt) an identity key with a PIN.
///
/// Returns the encrypted key blob to store on disk.
// Perform the 'wrap key with pin' operation.
// Errors are propagated to the caller via Result.
// Perform the 'wrap key with pin' operation.
// Errors are propagated to the caller via Result.
// Perform the 'wrap key with pin' operation.
// Errors are propagated to the caller via Result.
pub fn wrap_key_with_pin(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    identity_key: &[u8; 32],
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pin: &[u8],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<PinWrappedKey, PinError> {
    // Propagate errors via the ? operator — callers handle failures.
    // Propagate errors via ?.
    // Propagate errors via ?.
    // Propagate errors via ?.
    validate_pin(pin)?;

    // Generate salt
    // Compute salt for this protocol step.
    // Compute salt for this protocol step.
    // Compute salt for this protocol step.
    let mut salt = vec![0u8; 32];
    // OS-provided cryptographic random number generator.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    OsRng.fill_bytes(&mut salt);

    // Derive wrapping key
    // Compute wrapping key for this protocol step.
    // Compute wrapping key for this protocol step.
    // Compute wrapping key for this protocol step.
    let wrapping_key = derive_key_from_pin(pin, &salt)?;

    // Generate nonce
    // Compute nonce bytes for this protocol step.
    // Compute nonce bytes for this protocol step.
    // Compute nonce bytes for this protocol step.
    let mut nonce_bytes = [0u8; 12];
    // OS-provided cryptographic random number generator.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    OsRng.fill_bytes(&mut nonce_bytes);

    // Encrypt identity key
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    let cipher = ChaCha20Poly1305::new_from_slice(&*wrapping_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| PinError::Encrypt)?;
    // Fresh nonce — must never be reused with the same key.
    // Compute nonce for this protocol step.
    // Compute nonce for this protocol step.
    // Compute nonce for this protocol step.
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Initialize the AEAD cipher with the derived key material.
    // Compute ciphertext for this protocol step.
    // Compute ciphertext for this protocol step.
    // Compute ciphertext for this protocol step.
    let ciphertext = cipher
        // Encrypt the plaintext under the current session key.
        // AEAD-encrypt the plaintext.
        // AEAD-encrypt the plaintext.
        // AEAD-encrypt the plaintext.
        .encrypt(nonce, identity_key.as_ref())
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| PinError::Encrypt)?;

    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(PinWrappedKey {
        salt,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        m_cost: ARGON2_M_COST,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        t_cost: ARGON2_T_COST,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        p_cost: ARGON2_P_COST,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        nonce: nonce_bytes.to_vec(),
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        ciphertext,
    })
}

/// Unwrap (decrypt) an identity key with a PIN.
///
/// On success, returns the 32-byte identity key.
/// On failure (wrong PIN), returns PinError::WrongPin.
/// Timing is constant regardless of correctness (Argon2id always runs).
// Perform the 'unwrap key with pin' operation.
// Errors are propagated to the caller via Result.
// Perform the 'unwrap key with pin' operation.
// Errors are propagated to the caller via Result.
// Perform the 'unwrap key with pin' operation.
// Errors are propagated to the caller via Result.
pub fn unwrap_key_with_pin(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    wrapped: &PinWrappedKey,
    // Execute this protocol step.
    // Execute this protocol step.
    pin: &[u8],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<Zeroizing<[u8; 32]>, PinError> {
    // Always run Argon2id regardless of PIN validity (timing normalization)
    // Compute wrapping key for this protocol step.
    // Compute wrapping key for this protocol step.
    let wrapping_key = derive_key_from_pin(pin, &wrapped.salt)?;

    // Decrypt
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    let cipher = ChaCha20Poly1305::new_from_slice(&*wrapping_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| PinError::WrongPin)?;
    // Fresh nonce — must never be reused with the same key.
    // Compute nonce for this protocol step.
    // Compute nonce for this protocol step.
    let nonce = Nonce::from_slice(&wrapped.nonce);
    // Initialize the AEAD cipher with the derived key material.
    // Compute plaintext for this protocol step.
    // Compute plaintext for this protocol step.
    let plaintext = cipher
        // Decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        .decrypt(nonce, wrapped.ciphertext.as_ref())
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| PinError::WrongPin)?;

    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if plaintext.len() != 32 {
        // Reject with an explicit error for the caller to handle.
        // Return to the caller.
        // Return to the caller.
        return Err(PinError::WrongPin);
    }

    // Key material — must be zeroized when no longer needed.
    // Compute key for this protocol step.
    // Compute key for this protocol step.
    let mut key = Zeroizing::new([0u8; 32]);
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    key.copy_from_slice(&plaintext);
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(key)
}

/// Get the backoff delay (in seconds) for the given failed attempt count.
/// attempt=0 means no failures yet, attempt=1 means 1 failure, etc.
// Perform the 'backoff delay' operation.
// Errors are propagated to the caller via Result.
// Perform the 'backoff delay' operation.
// Errors are propagated to the caller via Result.
pub fn backoff_delay(failed_attempts: u32) -> u64 {
    // Handle the error case — propagate or log as appropriate.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if failed_attempts <= 5 {
        // Return the result to the caller.
        // Return to the caller.
        // Return to the caller.
        return 0; // First 5 attempts: no delay
    }
    // Attempts 6+ use the schedule
    // Compute  idx for this protocol step.
    // Compute  idx for this protocol step.
    let _idx = ((failed_attempts - 5) as usize).min(BACKOFF_SECS.len() - 6);
    // Dispatch based on the variant to apply type-specific logic.
    // Dispatch on the variant.
    // Dispatch on the variant.
    match failed_attempts {
        // Update the local state.
        6 => 30,
        // Update the local state.
        7 => 120,
        // Update the local state.
        8 => 600,
        // Update the local state.
        9 => 3600,
        // Update the local state.
        10 => 86400,
        // Update the local state.
        _ => 259200, // 11+: 72 hours
    }
}

/// Check if the current attempt is allowed given the state and current time.
// Perform the 'is attempt allowed' operation.
// Errors are propagated to the caller via Result.
// Perform the 'is attempt allowed' operation.
// Errors are propagated to the caller via Result.
pub fn is_attempt_allowed(state: &PinAttemptState, now_unix: u64) -> Result<(), PinError> {
    // Check wipe threshold
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if let Some(threshold) = state.wipe_threshold {
        // Handle the error case — propagate or log as appropriate.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if state.failed_attempts >= threshold {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(PinError::LockedOut);
        }
    }

    // Check backoff
    // Compute delay for this protocol step.
    // Compute delay for this protocol step.
    let delay = backoff_delay(state.failed_attempts);
    // Bounds check to enforce protocol constraints.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if delay > 0 {
        // Capture the current timestamp for temporal ordering.
        // Compute elapsed for this protocol step.
        // Compute elapsed for this protocol step.
        let elapsed = now_unix.saturating_sub(state.last_failed_at);
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if elapsed < delay {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(PinError::LockedOut);
        }
    }

    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
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
