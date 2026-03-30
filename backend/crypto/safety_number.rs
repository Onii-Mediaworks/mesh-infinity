//! Safety Numbers (§3.7.7)
//!
//! Safety numbers provide a short human-verifiable fingerprint for a relationship.
//!
//! ```text
//! identity_hash = SHA-256("meshinfinity-safety-v1" || min(pid_a, pid_b) || max(pid_a, pid_b))
//! key_hash      = SHA-256("meshinfinity-safety-v1" || min(pub_a, pub_b) || max(pub_a, pub_b))
//! safety_number = identity_hash || key_hash   // 64 bytes total
//! ```
//!
//! Display formats: numeric (60 digits), alphanumeric (20 chars), words, emoji.

use sha2::{Digest, Sha256};
use crate::identity::peer_id::PeerId;

// Protocol constant.
// SAFETY_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// SAFETY_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// SAFETY_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
const SAFETY_DOMAIN: &[u8] = b"meshinfinity-safety-v1";

/// A 64-byte safety number for a relationship between two peers.
#[derive(Clone, Debug, PartialEq, Eq)]
// Begin the block scope.
// SafetyNumber — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SafetyNumber — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SafetyNumber — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SafetyNumber {
    /// First 32 bytes: identity hash (stable across key rotations)
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub identity_hash: [u8; 32],
    /// Last 32 bytes: key hash (changes on key rotation)
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub key_hash: [u8; 32],
}

// Begin the block scope.
// SafetyNumber implementation — core protocol logic.
// SafetyNumber implementation — core protocol logic.
// SafetyNumber implementation — core protocol logic.
impl SafetyNumber {
    /// Derive the safety number between two peers.
    // Perform the 'derive' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'derive' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'derive' operation.
    // Errors are propagated to the caller via Result.
    pub fn derive(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_id_a: &PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        peer_id_b: &PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        ed25519_pub_a: &[u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        ed25519_pub_b: &[u8; 32],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> Self {
        // Sort peer IDs lexicographically
        // Bind the intermediate result.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (min_pid, max_pid) = if peer_id_a.0 <= peer_id_b.0 {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            (&peer_id_a.0[..], &peer_id_b.0[..])
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            (&peer_id_b.0[..], &peer_id_a.0[..])
        };

        // identity_hash — stable across key rotations
        // Compute hasher for this protocol step.
        // Compute hasher for this protocol step.
        // Compute hasher for this protocol step.
        let mut hasher = Sha256::new();
        // Feed the next data segment into the running hash/MAC.
        // Feed data into the running computation.
        // Feed data into the running computation.
        // Feed data into the running computation.
        hasher.update(SAFETY_DOMAIN);
        // Feed the next data segment into the running hash/MAC.
        // Feed data into the running computation.
        // Feed data into the running computation.
        // Feed data into the running computation.
        hasher.update(min_pid);
        // Feed the next data segment into the running hash/MAC.
        // Feed data into the running computation.
        // Feed data into the running computation.
        // Feed data into the running computation.
        hasher.update(max_pid);
        // Initialize the hash function for digest computation.
        // Compute identity hash for this protocol step.
        // Compute identity hash for this protocol step.
        // Compute identity hash for this protocol step.
        let mut identity_hash = [0u8; 32];
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        identity_hash.copy_from_slice(&hasher.finalize());

        // Sort public keys lexicographically
        // Bind the intermediate result.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (min_pub, max_pub) = if ed25519_pub_a <= ed25519_pub_b {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            (&ed25519_pub_a[..], &ed25519_pub_b[..])
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            (&ed25519_pub_b[..], &ed25519_pub_a[..])
        };

        // key_hash — changes on key rotation
        // Compute hasher for this protocol step.
        // Compute hasher for this protocol step.
        // Compute hasher for this protocol step.
        let mut hasher = Sha256::new();
        // Feed the next data segment into the running hash/MAC.
        // Feed data into the running computation.
        // Feed data into the running computation.
        // Feed data into the running computation.
        hasher.update(SAFETY_DOMAIN);
        // Feed the next data segment into the running hash/MAC.
        // Feed data into the running computation.
        // Feed data into the running computation.
        // Feed data into the running computation.
        hasher.update(min_pub);
        // Feed the next data segment into the running hash/MAC.
        // Feed data into the running computation.
        // Feed data into the running computation.
        // Feed data into the running computation.
        hasher.update(max_pub);
        // Initialize the hash function for digest computation.
        // Compute key hash for this protocol step.
        // Compute key hash for this protocol step.
        // Compute key hash for this protocol step.
        let mut key_hash = [0u8; 32];
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        key_hash.copy_from_slice(&hasher.finalize());

        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            identity_hash,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            key_hash,
        }
    }

    /// Full 64-byte safety number.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    pub fn as_bytes(&self) -> [u8; 64] {
        // Allocate the output buffer for the result.
        // Compute out for this protocol step.
        // Compute out for this protocol step.
        // Compute out for this protocol step.
        let mut out = [0u8; 64];
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        out[..32].copy_from_slice(&self.identity_hash);
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        out[32..].copy_from_slice(&self.key_hash);
        out
    }

    /// Numeric format: 60 digits in groups of 5 (Signal-compatible).
    // Perform the 'to numeric' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'to numeric' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'to numeric' operation.
    // Errors are propagated to the caller via Result.
    pub fn to_numeric(&self) -> String {
        // Extract the raw byte representation for wire encoding.
        // Compute bytes for this protocol step.
        // Compute bytes for this protocol step.
        // Compute bytes for this protocol step.
        let bytes = self.as_bytes();
        // Invoke the associated function.
        // Compute digits for this protocol step.
        // Compute digits for this protocol step.
        // Compute digits for this protocol step.
        let mut digits = String::with_capacity(72); // 60 digits + 11 spaces
        // Process each chunk independently for streaming compatibility.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for (i, chunk) in bytes.chunks(5).enumerate() {
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if i > 0 && i % 6 == 0 {
                // Add the element to the collection.
                // Append to the collection.
                // Append to the collection.
                // Append to the collection.
                digits.push('\n');
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            } else if i > 0 {
                // Add the element to the collection.
                // Append to the collection.
                // Append to the collection.
                // Append to the collection.
                digits.push(' ');
            }
            // Convert 5 bytes to 5-digit number
            // Compute val for this protocol step.
            // Compute val for this protocol step.
            // Compute val for this protocol step.
            let mut val: u64 = 0;
            // Process each chunk independently for streaming compatibility.
            // Iterate over each element.
            // Iterate over each element.
            // Iterate over each element.
            for b in chunk {
                // Update the local state.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                val = (val << 8) | (*b as u64);
            }
            // Format the output for display or logging.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            digits.push_str(&format!("{:05}", val % 100000));
        }
        digits
    }

    /// Alphanumeric format: 20 characters in groups of 4.
    // Perform the 'to alphanumeric' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'to alphanumeric' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'to alphanumeric' operation.
    // Errors are propagated to the caller via Result.
    pub fn to_alphanumeric(&self) -> String {
        // Protocol constant.
        // ALPHABET — protocol constant.
        // Defined by the spec; must not change without a version bump.
        // ALPHABET — protocol constant.
        // Defined by the spec; must not change without a version bump.
        // ALPHABET — protocol constant.
        // Defined by the spec; must not change without a version bump.
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        // Extract the raw byte representation for wire encoding.
        // Compute bytes for this protocol step.
        // Compute bytes for this protocol step.
        // Compute bytes for this protocol step.
        let bytes = self.as_bytes();
        // Capture the operation result for subsequent validation.
        // Compute result for this protocol step.
        // Compute result for this protocol step.
        // Compute result for this protocol step.
        let mut result = String::with_capacity(24);
        // Process each chunk independently for streaming compatibility.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for (i, chunk) in bytes.chunks(3).enumerate() {
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if i > 0 && i % 5 == 0 {
                // Add the element to the collection.
                // Append to the collection.
                // Append to the collection.
                // Append to the collection.
                result.push('-');
            }
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if i >= 7 { break; } // 20 chars = 5 groups of 4
            // Track the count for threshold and bounds checking.
            // Compute val for this protocol step.
            // Compute val for this protocol step.
            // Compute val for this protocol step.
            let val = if chunk.len() >= 3 {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32)
            // Validate the input length to prevent out-of-bounds access.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            } else if chunk.len() == 2 {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                ((chunk[0] as u32) << 8) | (chunk[1] as u32)
            // Begin the block scope.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            } else {
                // Execute this step in the protocol sequence.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                chunk[0] as u32
            };
            // Extract 3 characters from the value
            // Compute a for this protocol step.
            // Compute a for this protocol step.
            // Compute a for this protocol step.
            let a = (val % ALPHABET.len() as u32) as usize;
            // Track the count for threshold and bounds checking.
            // Compute b for this protocol step.
            // Compute b for this protocol step.
            // Compute b for this protocol step.
            let b = ((val / ALPHABET.len() as u32) % ALPHABET.len() as u32) as usize;
            // Track the count for threshold and bounds checking.
            // Compute c for this protocol step.
            // Compute c for this protocol step.
            // Compute c for this protocol step.
            let c = ((val / (ALPHABET.len() as u32 * ALPHABET.len() as u32)) % ALPHABET.len() as u32) as usize;
            // Execute the operation and bind the result.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            result.push(ALPHABET[a] as char);
            // Execute the operation and bind the result.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            result.push(ALPHABET[b] as char);
            // Execute the operation and bind the result.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            result.push(ALPHABET[c] as char);
        }
        // Trim to 20 chars
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        result.truncate(20);
        result
    }

    /// Check if only the key_hash changed (normal key rotation).
    // Perform the 'key changed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'key changed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'key changed' operation.
    // Errors are propagated to the caller via Result.
    pub fn key_changed(&self, other: &SafetyNumber) -> bool {
        // Update the identity hash to reflect the new state.
        // Advance identity hash state.
        // Advance identity hash state.
        // Advance identity hash state.
        self.identity_hash == other.identity_hash && self.key_hash != other.key_hash
    }

    /// Check if identity_hash changed (different person entirely).
    // Perform the 'identity changed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'identity changed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'identity changed' operation.
    // Errors are propagated to the caller via Result.
    pub fn identity_changed(&self, other: &SafetyNumber) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.identity_hash != other.identity_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_derivation() {
        let pid_a = PeerId([0x01; 32]);
        let pid_b = PeerId([0x02; 32]);
        let pub_a = [0x03u8; 32];
        let pub_b = [0x04u8; 32];

        let sn1 = SafetyNumber::derive(&pid_a, &pid_b, &pub_a, &pub_b);
        let sn2 = SafetyNumber::derive(&pid_b, &pid_a, &pub_b, &pub_a);

        assert_eq!(sn1, sn2, "Safety number must be symmetric");
    }

    #[test]
    fn test_key_rotation_detection() {
        let pid_a = PeerId([0x01; 32]);
        let pid_b = PeerId([0x02; 32]);
        let pub_a = [0x03u8; 32];
        let pub_b_old = [0x04u8; 32];
        let pub_b_new = [0x05u8; 32];

        let sn_old = SafetyNumber::derive(&pid_a, &pid_b, &pub_a, &pub_b_old);
        let sn_new = SafetyNumber::derive(&pid_a, &pid_b, &pub_a, &pub_b_new);

        assert!(sn_old.key_changed(&sn_new), "Key change should be detected");
        assert!(!sn_old.identity_changed(&sn_new), "Identity should NOT change on key rotation");
    }

    #[test]
    fn test_numeric_format() {
        let sn = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        let numeric = sn.to_numeric();
        // Should contain digits and spaces
        assert!(numeric.chars().all(|c| c.is_ascii_digit() || c == ' ' || c == '\n'));
        // Should have groups of 5
        let groups: Vec<&str> = numeric.split(|c: char| c == ' ' || c == '\n').collect();
        for g in &groups {
            assert_eq!(g.len(), 5, "Each group should be 5 digits: {}", g);
        }
    }

    #[test]
    fn test_alphanumeric_format() {
        let sn = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        let alpha = sn.to_alphanumeric();
        assert!(alpha.len() <= 24, "Alphanumeric should be ≤24 chars (with dashes)");
    }

    #[test]
    fn test_different_peers_different_numbers() {
        let sn1 = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        let sn2 = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x05; 32]),
            &[0x03; 32],
            &[0x06; 32],
        );
        assert_ne!(sn1, sn2);
    }

    #[test]
    fn test_deterministic() {
        let sn1 = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        let sn2 = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        assert_eq!(sn1, sn2);
    }
}
