//! Shared low-level KDF primitives (§7.0.3, §7.0.4)
//!
//! Both the Double Ratchet (`double_ratchet.rs`) and Sender Keys
//! (`sender_keys.rs`) advance their symmetric KDF chains using the same
//! HMAC-SHA256-based formula.  This module holds the single implementation
//! so both protocols stay in sync and there is no room for subtle divergence.
//!
//! # Chain step formula
//!
//! ```text
//! msg_key       = HMAC-SHA256(chain_key, 0x01)
//! new_chain_key = HMAC-SHA256(chain_key, 0x02)
//! ```
//!
//! The input bytes 0x01 / 0x02 follow the Signal Protocol convention and are
//! specified in §7.0.3 of SPEC.md.

use hmac::{Hmac, Mac};
use sha2::Sha256;

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/// HMAC input byte for deriving a message key from the chain key.
///
/// Value 0x01 matches the Signal Protocol convention (§7.0.3).
// CHAIN_MSG_KEY_INPUT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const CHAIN_MSG_KEY_INPUT: u8 = 0x01;

/// HMAC input byte for advancing the chain key to its next state.
///
/// Value 0x02 matches the Signal Protocol convention (§7.0.3).
// CHAIN_ADVANCE_INPUT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const CHAIN_ADVANCE_INPUT: u8 = 0x02;

/// Zero-byte salt for HKDF operations that have no external salt.
///
/// HKDF-SHA256 with a zero salt is semantically equivalent to using a
/// PRF whose key is derived from the IKM alone.  This is the standard
/// approach when no salt is available (RFC 5869 §3.1).
// ZERO_SALT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const ZERO_SALT: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// kdf_chain_step
// ---------------------------------------------------------------------------

/// Advance a symmetric KDF chain by one step.
///
/// Returns `(msg_key, new_chain_key)`:
/// - `msg_key` is used to encrypt/decrypt the current message.
/// - `new_chain_key` replaces `chain_key` for all subsequent messages,
///   providing forward secrecy within the chain.
///
/// # Algorithm
///
/// ```text
/// msg_key       = HMAC-SHA256(chain_key, 0x01)
/// new_chain_key = HMAC-SHA256(chain_key, 0x02)
/// ```
///
/// Both computations use the **same** `chain_key` as the HMAC key so that
/// neither output can be derived from the other.
// Perform the 'kdf chain step' operation.
// Errors are propagated to the caller via Result.
pub fn kdf_chain_step(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Derive message key: HMAC-SHA256(chain_key, 0x01).
    // Infallible: HMAC-SHA256 (via the `hmac` crate) accepts any non-empty key; the
    // only way new_from_slice can fail is a zero-length key, which is impossible here
    // because chain_key is &[u8; 32].  This function returns ([u8;32],[u8;32]), not a
    // Result, so we cannot use `?`; expect() with the explanation is the correct pattern.
    // Compute mac for this protocol step.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(chain_key)
        // Execute the operation and bind the result.
        // Execute this protocol step.
        .expect("HMAC-SHA256 accepts any key length — [u8;32] is always valid");
    // Feed the next data segment into the running hash/MAC.
    // Feed data into the running computation.
    mac.update(&[CHAIN_MSG_KEY_INPUT]);
    // Initialize the MAC for authentication tag computation.
    // Compute msg key bytes for this protocol step.
    let msg_key_bytes = mac.finalize().into_bytes();
    // Key material — must be zeroized when no longer needed.
    // Compute msg key for this protocol step.
    let mut msg_key = [0u8; 32];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    msg_key.copy_from_slice(&msg_key_bytes);

    // Derive next chain key: HMAC-SHA256(chain_key, 0x02).
    // Uses a fresh HMAC instance with the same chain_key as the key, not the msg_key —
    // this ensures msg_key and new_chain_key are independent (forward secrecy invariant).
    // Infallible for the same reason as the msg_key derivation above: chain_key is [u8;32].
    // Compute mac2 for this protocol step.
    let mut mac2 = <Hmac<Sha256> as Mac>::new_from_slice(chain_key)
        // Execute the operation and bind the result.
        // Execute this protocol step.
        .expect("HMAC-SHA256 accepts any key length — [u8;32] is always valid");
    // Feed the next data segment into the running hash/MAC.
    // Feed data into the running computation.
    mac2.update(&[CHAIN_ADVANCE_INPUT]);
    // Initialize the MAC for authentication tag computation.
    // Compute new ck bytes for this protocol step.
    let new_ck_bytes = mac2.finalize().into_bytes();
    // Key material — must be zeroized when no longer needed.
    // Compute new chain key for this protocol step.
    let mut new_chain_key = [0u8; 32];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    new_chain_key.copy_from_slice(&new_ck_bytes);

    // Process the current step in the protocol.
    // Execute this protocol step.
    (msg_key, new_chain_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Identical chain_key must produce identical outputs (determinism).
    #[test]
    fn test_kdf_chain_step_deterministic() {
        let ck = [0x42u8; 32];
        let (mk1, nck1) = kdf_chain_step(&ck);
        let (mk2, nck2) = kdf_chain_step(&ck);
        assert_eq!(mk1, mk2, "msg_key must be deterministic");
        assert_eq!(nck1, nck2, "new_chain_key must be deterministic");
    }

    /// msg_key and new_chain_key must not be equal to each other or to the
    /// input chain_key — independence is required for forward secrecy.
    #[test]
    fn test_kdf_chain_step_outputs_differ() {
        let ck = [0xABu8; 32];
        let (mk, nck) = kdf_chain_step(&ck);
        assert_ne!(mk, nck, "msg_key and new_chain_key must differ");
        assert_ne!(mk, ck, "msg_key must not equal chain_key");
        assert_ne!(nck, ck, "new_chain_key must not equal chain_key");
    }

    /// The chain must advance: step N+1 output must differ from step N output.
    #[test]
    fn test_kdf_chain_step_advances() {
        let ck = [0x01u8; 32];
        let (mk1, nck1) = kdf_chain_step(&ck);
        let (mk2, _nck2) = kdf_chain_step(&nck1);
        assert_ne!(mk1, mk2, "successive message keys must differ");
    }

    /// Adversarial: knowing msg_key at step N must not allow deriving
    /// new_chain_key (and hence all future message keys).
    ///
    /// This is a regression guard — both values are computed from the same
    /// chain_key, so an attacker who only observes mk cannot recompute nck.
    /// We verify here that `mk != nck` so the two are not trivially related.
    #[test]
    fn test_kdf_chain_step_forward_secrecy_invariant() {
        for seed in 0u8..=255 {
            let ck = [seed; 32];
            let (mk, nck) = kdf_chain_step(&ck);
            // If these were equal an attacker with mk could derive nck and all
            // future keys — that would break forward secrecy.
            assert_ne!(mk, nck, "seed {seed}: msg_key must not equal new_chain_key");
        }
    }
}
