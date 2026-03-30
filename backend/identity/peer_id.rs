//! Peer ID (§3.1.5)
//!
//! The canonical identity reference for a mask (Layer 3).
//! ```text
//! peer_id = SHA-256("meshinfinity-peer-id-v1" || ed25519_public_key_bytes)
//! ```

use sha2::{Digest, Sha256};

/// Domain separator for peer ID derivation.
// PEER_ID_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// PEER_ID_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// PEER_ID_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
const PEER_ID_DOMAIN: &[u8] = b"meshinfinity-peer-id-v1";

/// A 32-byte peer identifier derived from an Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
// Execute the operation and bind the result.
// PeerId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PeerId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PeerId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PeerId(pub [u8; 32]);

// Begin the block scope.
// PeerId implementation — core protocol logic.
// PeerId implementation — core protocol logic.
// PeerId implementation — core protocol logic.
impl PeerId {
    /// Derive a peer ID from an Ed25519 public key.
    // Perform the 'from ed25519 pub' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from ed25519 pub' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from ed25519 pub' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_ed25519_pub(pubkey: &[u8; 32]) -> Self {
        // Initialize the hash function for digest computation.
        // Compute hasher for this protocol step.
        // Compute hasher for this protocol step.
        // Compute hasher for this protocol step.
        let mut hasher = Sha256::new();
        // Feed the next data segment into the running hash/MAC.
        // Feed data into the running computation.
        // Feed data into the running computation.
        // Feed data into the running computation.
        hasher.update(PEER_ID_DOMAIN);
        // Feed the next data segment into the running hash/MAC.
        // Feed data into the running computation.
        // Feed data into the running computation.
        // Feed data into the running computation.
        hasher.update(pubkey);
        // Initialize the hash function for digest computation.
        // Compute result for this protocol step.
        // Compute result for this protocol step.
        // Compute result for this protocol step.
        let result = hasher.finalize();
        // Unique identifier for lookup and deduplication.
        // Compute id for this protocol step.
        // Compute id for this protocol step.
        // Compute id for this protocol step.
        let mut id = [0u8; 32];
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        id.copy_from_slice(&result);
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        PeerId(id)
    }

    /// Truncated hex representation (first 8 hex chars) for UI display.
    // Perform the 'short hex' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'short hex' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'short hex' operation.
    // Errors are propagated to the caller via Result.
    pub fn short_hex(&self) -> String {
        // Invoke the associated function.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        hex::encode(&self.0[..4])
    }

    /// Full hex representation.
    // Perform the 'to hex' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'to hex' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'to hex' operation.
    // Errors are propagated to the caller via Result.
    pub fn to_hex(&self) -> String {
        // Invoke the associated function.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        hex::encode(self.0)
    }

    /// Parse from hex string.
    // Perform the 'from hex' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from hex' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from hex' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        // Propagate errors via the ? operator — callers handle failures.
        // Compute bytes for this protocol step.
        // Compute bytes for this protocol step.
        // Compute bytes for this protocol step.
        let bytes = hex::decode(s)?;
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if bytes.len() != 32 {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(hex::FromHexError::InvalidStringLength);
        }
        // Unique identifier for lookup and deduplication.
        // Compute id for this protocol step.
        // Compute id for this protocol step.
        // Compute id for this protocol step.
        let mut id = [0u8; 32];
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        id.copy_from_slice(&bytes);
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(PeerId(id))
    }

    /// Get raw bytes.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    pub fn as_bytes(&self) -> &[u8; 32] {
        // Chain the operation on the intermediate result.
        &self.0
    }
}

// Begin the block scope.
// Implement Display for PeerId.
// Implement Display for PeerId.
// Implement Display for PeerId.
impl std::fmt::Display for PeerId {
    // Begin the block scope.
    // Perform the 'fmt' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'fmt' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'fmt' operation.
    // Errors are propagated to the caller via Result.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format the output for display or logging.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        write!(f, "{}", self.short_hex())
    }
}

// Begin the block scope.
// Implement Serialize for PeerId.
// Implement Serialize for PeerId.
// Implement Serialize for PeerId.
impl serde::Serialize for PeerId {
    // Begin the block scope.
    // Perform the 'serialize' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'serialize' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'serialize' operation.
    // Errors are propagated to the caller via Result.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        serializer.serialize_str(&self.to_hex())
    }
}

// Begin the block scope.
// Trait implementation.
// Trait implementation.
// Trait implementation.
impl<'de> serde::Deserialize<'de> for PeerId {
    // Begin the block scope.
    // Perform the 'deserialize' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deserialize' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deserialize' operation.
    // Errors are propagated to the caller via Result.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Serialize to the wire format for transmission or storage.
        // Compute s for this protocol step.
        // Compute s for this protocol step.
        // Compute s for this protocol step.
        let s = String::deserialize(deserializer)?;
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        PeerId::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_derivation() {
        let pubkey = [0x42u8; 32];
        let id = PeerId::from_ed25519_pub(&pubkey);
        // Should be deterministic
        let id2 = PeerId::from_ed25519_pub(&pubkey);
        assert_eq!(id, id2);
    }

    #[test]
    fn test_different_keys_different_ids() {
        let id1 = PeerId::from_ed25519_pub(&[0x01u8; 32]);
        let id2 = PeerId::from_ed25519_pub(&[0x02u8; 32]);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let id = PeerId::from_ed25519_pub(&[0x42u8; 32]);
        let hex = id.to_hex();
        let recovered = PeerId::from_hex(&hex).unwrap();
        assert_eq!(id, recovered);
    }

    #[test]
    fn test_short_hex() {
        let id = PeerId::from_ed25519_pub(&[0x42u8; 32]);
        assert_eq!(id.short_hex().len(), 8);
    }

    #[test]
    fn test_serde_roundtrip() {
        let id = PeerId::from_ed25519_pub(&[0x42u8; 32]);
        let json = serde_json::to_string(&id).unwrap();
        let recovered: PeerId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, recovered);
    }
}
