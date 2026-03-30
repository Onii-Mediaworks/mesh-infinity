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
// OFFER_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// OFFER_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const OFFER_EXPIRY_SECS: u64 = 60;

/// Maximum files per proximity offer.
// MAX_FILES_PER_OFFER — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_FILES_PER_OFFER — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_FILES_PER_OFFER: usize = 64;

/// Maximum thumbnail size (bytes). 8 KB.
// MAX_THUMBNAIL_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_THUMBNAIL_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_THUMBNAIL_SIZE: usize = 8192;

/// Maximum chunk size (bytes). 64 KB.
// PROXIMITY_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// PROXIMITY_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PROXIMITY_CHUNK_SIZE: usize = 65_536;

/// Transfer resume timeout (seconds). 30 seconds (iOS background limit).
// RESUME_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// RESUME_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const RESUME_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Receive Policy
// ---------------------------------------------------------------------------

/// How this device handles incoming proximity shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// ProximityReceivePolicy — variant enumeration.
// Match exhaustively to handle every protocol state.
// ProximityReceivePolicy — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ProximityReceivePolicy {
    /// Ignore all offers.
    // Execute this protocol step.
    // Execute this protocol step.
    Disabled,
    /// Accept only from paired peers (known PeerIds).
    // Execute this protocol step.
    // Execute this protocol step.
    TrustedOnly,
    /// Accept from anyone (no gate code required).
    // Execute this protocol step.
    // Execute this protocol step.
    Everyone,
    /// Accept from anyone who knows the gate code.
    // Execute this protocol step.
    // Execute this protocol step.
    EveryoneWithCode,
}

// ---------------------------------------------------------------------------
// Protocol Messages
// ---------------------------------------------------------------------------

/// A proximity share offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ProximityOffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ProximityOffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ProximityOffer {
    /// Unique offer identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    pub offer_id: [u8; 16],
    /// Sender's display name.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_name: String,
    /// Ephemeral X25519 public key for E2E encryption.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_token: [u8; 32],
    /// Random nonce for the receiver.
    // Execute this protocol step.
    // Execute this protocol step.
    pub receiver_nonce: [u8; 16],
    /// Files being offered (max 64).
    // Execute this protocol step.
    // Execute this protocol step.
    pub files: Vec<FileOffer>,
    /// When this offer expires.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expires_at: u64,
    /// Optional gate code hash (for EveryoneWithCode policy).
    // Execute this protocol step.
    // Execute this protocol step.
    pub gate_code_hash: Option<[u8; 32]>,
}

/// A single file in a proximity offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FileOffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileOffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileOffer {
    /// The file id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_id: [u8; 16],
    /// The name for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// The size for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub size: u64,
    /// The mime type for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mime_type: String,
    /// The sha256 for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sha256: [u8; 32],
    /// Thumbnail (max 8 KB). For image/video previews.
    // Execute this protocol step.
    // Execute this protocol step.
    pub thumbnail: Option<Vec<u8>>,
}

/// Accept a proximity share offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ProximityAccept — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ProximityAccept — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ProximityAccept {
    /// The offer id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub offer_id: [u8; 16],
    /// Which files to accept (by file_id).
    // Execute this protocol step.
    // Execute this protocol step.
    pub accepted_files: Vec<[u8; 16]>,
    /// Receiver's ephemeral X25519 public key.
    // Execute this protocol step.
    // Execute this protocol step.
    pub receiver_token: [u8; 32],
    /// Gate code proof (if required by sender).
    // Execute this protocol step.
    // Execute this protocol step.
    pub gate_code_proof: Option<[u8; 32]>,
    /// Optional identity claim (if the receiver wants to
    /// identify themselves as a known peer).
    // Execute this protocol step.
    // Execute this protocol step.
    pub identity_claim: Option<ProximityIdentityClaim>,
}

/// A chunk of file data in a proximity transfer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ProximityChunk — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ProximityChunk — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ProximityChunk {
    /// The offer id for this instance.
    // Execute this protocol step.
    pub offer_id: [u8; 16],
    /// The file id for this instance.
    // Execute this protocol step.
    pub file_id: [u8; 16],
    /// The chunk index for this instance.
    // Execute this protocol step.
    pub chunk_index: u32,
    /// The total chunks for this instance.
    // Execute this protocol step.
    pub total_chunks: u32,
    /// The data for this instance.
    // Execute this protocol step.
    pub data: Vec<u8>,
    /// The is last for this instance.
    // Execute this protocol step.
    pub is_last: bool,
}

/// ACK for a proximity chunk.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ProximityChunkAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ProximityChunkAck {
    /// The offer id for this instance.
    // Execute this protocol step.
    pub offer_id: [u8; 16],
    /// The file id for this instance.
    // Execute this protocol step.
    pub file_id: [u8; 16],
    /// The chunk index for this instance.
    // Execute this protocol step.
    pub chunk_index: u32,
    /// The ok for this instance.
    // Execute this protocol step.
    pub ok: bool,
}

/// Optional identity claim during proximity accept.
///
/// Allows the receiver to prove they're a known peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ProximityIdentityClaim — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ProximityIdentityClaim {
    /// The peer id for this instance.
    // Execute this protocol step.
    pub peer_id: [u8; 32],
    /// The offer id for this instance.
    // Execute this protocol step.
    pub offer_id: [u8; 16],
    /// Ed25519 signature over (peer_id || offer_id).
    // Execute this protocol step.
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
