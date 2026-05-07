//! BLE rotating advertisement token encoding/decoding (§5.6.1).
//!
//! Tokens are 64 bits embedded in advertisement data:
//!   Bytes 0–3: random 32-bit nonce
//!   Bytes 4–7: first 4 bytes of SHA-256(peer_id)
//!
//! The nonce ensures tokens change on every advertisement cycle.
//! The peer-ID hash allows the receiver to confirm the token belongs to a
//! known peer without exposing the peer ID directly.
//!
//! The full BLE transport (GATT services, connection lifecycle, pairing
//! handshake) is owned by the platform layer (AndroidProximityBridge /
//! CoreBluetooth) and calls back into Rust via the proximity FFI.  This
//! module provides only the token encoding helpers shared by all platform
//! paths.

use sha2::{Digest, Sha256};

use crate::service::runtime::try_random_fill;

/// Byte length of a BLE rotating advertisement token (§5.6.1).
pub const ROTATING_TOKEN_BYTES: usize = 8;

/// BLE transport helper — token encoding for rotating advertisement IDs.
pub struct BluetoothTransport;

impl BluetoothTransport {
    /// Generate a rotating BLE advertisement token for `peer_id`.
    ///
    /// Returns `None` if the CSRNG is unavailable (should never happen on
    /// supported hardware; the caller must not advertise without a valid token).
    pub fn generate_rotating_token(peer_id: &[u8; 32]) -> Option<[u8; ROTATING_TOKEN_BYTES]> {
        let mut nonce = [0u8; 4];
        if !try_random_fill(&mut nonce) {
            return None;
        }
        // SHA-256 always produces 32 bytes; the first 4 serve as a non-identifying
        // peer hint that lets the receiver confirm the token without learning the
        // peer ID from the raw advertisement.
        let hash = Sha256::digest(peer_id);
        let peer_hash: [u8; 4] = hash[..4]
            .try_into()
            .expect("SHA-256 output is always 32 bytes");
        Some([
            nonce[0], nonce[1], nonce[2], nonce[3],
            peer_hash[0], peer_hash[1], peer_hash[2], peer_hash[3],
        ])
    }

    /// Decode a rotating advertisement token from raw BLE advertisement data.
    ///
    /// Returns the 8-byte token as a lowercase hex string, or `None` if the
    /// data is too short or the token is the all-zero sentinel (rejected as
    /// a malformed advertisement).
    pub fn decode_rotating_token(data: &[u8]) -> Option<String> {
        if data.len() < ROTATING_TOKEN_BYTES {
            return None;
        }
        let token = &data[..ROTATING_TOKEN_BYTES];
        // All-zero tokens are rejected: they indicate a missing or zeroed nonce
        // field, which would make advertisements correlatable across cycles.
        if token.iter().all(|b| *b == 0) {
            return None;
        }
        Some(hex::encode(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_token_valid() {
        let data = vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90];
        let result = BluetoothTransport::decode_rotating_token(&data);
        assert_eq!(result, Some("abcdef1234567890".to_string()));
    }

    #[test]
    fn decode_token_too_short() {
        let data = vec![0xab, 0xcd];
        let result = BluetoothTransport::decode_rotating_token(&data);
        assert!(result.is_none());
    }

    #[test]
    fn decode_token_all_zero_rejected() {
        let data = vec![0x00; 8];
        let result = BluetoothTransport::decode_rotating_token(&data);
        assert!(result.is_none());
    }

    #[test]
    fn decode_token_with_extra_bytes() {
        let data = vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xff, 0xfe];
        let result = BluetoothTransport::decode_rotating_token(&data);
        assert_eq!(result, Some("abcdef1234567890".to_string()));
    }

    #[test]
    fn generate_token_non_zero_nonce() {
        // Can't predict the nonce, but it must not produce all-zero output
        // given a non-zero peer ID (all-zero peer ID would hash to non-zero anyway).
        let peer_id = [0x42u8; 32];
        let token = BluetoothTransport::generate_rotating_token(&peer_id)
            .expect("CSRNG must be available in test context");
        assert_eq!(token.len(), ROTATING_TOKEN_BYTES);
        // The peer-hash bytes (4–7) are deterministic for a given peer_id.
        let expected_hash = sha2::Sha256::digest(&peer_id);
        assert_eq!(token[4], expected_hash[0]);
        assert_eq!(token[5], expected_hash[1]);
        assert_eq!(token[6], expected_hash[2]);
        assert_eq!(token[7], expected_hash[3]);
    }
}
