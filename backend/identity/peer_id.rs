//! Peer ID (§3.1.5)
//!
//! The canonical identity reference for a mask (Layer 3).
//! ```text
//! peer_id = SHA-256("meshinfinity-peer-id-v1" || ed25519_public_key_bytes)
//! ```

use sha2::{Digest, Sha256};

/// Domain separator for peer ID derivation.
const PEER_ID_DOMAIN: &[u8] = b"meshinfinity-peer-id-v1";

/// A 32-byte peer identifier derived from an Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Derive a peer ID from an Ed25519 public key.
    pub fn from_ed25519_pub(pubkey: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(PEER_ID_DOMAIN);
        hasher.update(pubkey);
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        PeerId(id)
    }

    /// Truncated hex representation (first 8 hex chars) for UI display.
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// Full hex representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(PeerId(id))
    }

    /// Get raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short_hex())
    }
}

impl serde::Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
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
