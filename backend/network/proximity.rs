//! Proximity Share (§10.4)
//!
//! # What is Proximity Share?
//!
//! AirDrop-like file sharing over BLE/WiFi Direct. Uses ephemeral
//! X25519 keypairs for E2E encryption. No mesh identity required.
//!
//! # Protocol Flow
//!
//! 1. Sender broadcasts a ProximityOffer (via BLE/WiFi Direct).
//! 2. Nearby devices see the offer (filtered by receive policy).
//! 3. Receiver sends ProximityAccept with selected files.
//! 4. Sender streams ProximityChunk messages for each file.
//! 5. Receiver ACKs each chunk.
//!
//! # Receive Policies
//!
//! - Disabled: ignore all proximity offers
//! - TrustedOnly: accept only from paired peers
//! - Everyone: accept from anyone (no gate code)
//! - EveryoneWithCode: accept from anyone who knows the gate code

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default offer expiry (seconds). 60 seconds.
pub const OFFER_EXPIRY_SECS: u64 = 60;

/// Maximum files per proximity offer.
pub const MAX_FILES_PER_OFFER: usize = 64;

/// Maximum thumbnail size (bytes). 8 KB.
pub const MAX_THUMBNAIL_SIZE: usize = 8192;

/// Maximum chunk size (bytes). 64 KB.
pub const PROXIMITY_CHUNK_SIZE: usize = 65_536;

/// Transfer resume timeout (seconds). 30 seconds (iOS background limit).
pub const RESUME_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Receive Policy
// ---------------------------------------------------------------------------

/// How this device handles incoming proximity shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProximityReceivePolicy {
    /// Ignore all offers.
    Disabled,
    /// Accept only from paired peers (known PeerIds).
    TrustedOnly,
    /// Accept from anyone (no gate code required).
    Everyone,
    /// Accept from anyone who knows the gate code.
    EveryoneWithCode,
}

// ---------------------------------------------------------------------------
// Protocol Messages
// ---------------------------------------------------------------------------

/// A proximity share offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProximityOffer {
    /// Unique offer identifier.
    pub offer_id: [u8; 16],
    /// Sender's display name.
    pub sender_name: String,
    /// Ephemeral X25519 public key for E2E encryption.
    pub sender_token: [u8; 32],
    /// Random nonce for the receiver.
    pub receiver_nonce: [u8; 16],
    /// Files being offered (max 64).
    pub files: Vec<FileOffer>,
    /// When this offer expires.
    pub expires_at: u64,
    /// Optional gate code hash (for EveryoneWithCode policy).
    pub gate_code_hash: Option<[u8; 32]>,
}

/// A single file in a proximity offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileOffer {
    pub file_id: [u8; 16],
    pub name: String,
    pub size: u64,
    pub mime_type: String,
    pub sha256: [u8; 32],
    /// Thumbnail (max 8 KB). For image/video previews.
    pub thumbnail: Option<Vec<u8>>,
}

/// Accept a proximity share offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProximityAccept {
    pub offer_id: [u8; 16],
    /// Which files to accept (by file_id).
    pub accepted_files: Vec<[u8; 16]>,
    /// Receiver's ephemeral X25519 public key.
    pub receiver_token: [u8; 32],
    /// Gate code proof (if required by sender).
    pub gate_code_proof: Option<[u8; 32]>,
    /// Optional identity claim (if the receiver wants to
    /// identify themselves as a known peer).
    pub identity_claim: Option<ProximityIdentityClaim>,
}

/// A chunk of file data in a proximity transfer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProximityChunk {
    pub offer_id: [u8; 16],
    pub file_id: [u8; 16],
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub data: Vec<u8>,
    pub is_last: bool,
}

/// ACK for a proximity chunk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProximityChunkAck {
    pub offer_id: [u8; 16],
    pub file_id: [u8; 16],
    pub chunk_index: u32,
    pub ok: bool,
}

/// Optional identity claim during proximity accept.
///
/// Allows the receiver to prove they're a known peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProximityIdentityClaim {
    pub peer_id: [u8; 32],
    pub offer_id: [u8; 16],
    /// Ed25519 signature over (peer_id || offer_id).
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receive_policy_default() {
        // Should be serializable.
        let policy = ProximityReceivePolicy::TrustedOnly;
        let json = serde_json::to_string(&policy).unwrap();
        let recovered: ProximityReceivePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, ProximityReceivePolicy::TrustedOnly);
    }

    #[test]
    fn test_offer_serde() {
        let offer = ProximityOffer {
            offer_id: [0x01; 16],
            sender_name: "Alice".to_string(),
            sender_token: [0x02; 32],
            receiver_nonce: [0x03; 16],
            files: vec![FileOffer {
                file_id: [0x04; 16],
                name: "photo.jpg".to_string(),
                size: 1_000_000,
                mime_type: "image/jpeg".to_string(),
                sha256: [0x05; 32],
                thumbnail: None,
            }],
            expires_at: 2000,
            gate_code_hash: None,
        };

        let json = serde_json::to_string(&offer).unwrap();
        let recovered: ProximityOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.sender_name, "Alice");
        assert_eq!(recovered.files.len(), 1);
    }
}
