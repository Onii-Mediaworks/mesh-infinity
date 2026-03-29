//! Distributed Object Storage (§11.2)
//!
//! # Content-Addressed Storage
//!
//! Files are split into chunks, each addressed by SHA-256 of its
//! ciphertext. A FileManifest ties the chunks together with metadata.
//!
//! # Security Levels
//!
//! | Level | Name | Encryption | Key Distribution |
//! |-------|------|-----------|------------------|
//! | 0 | Public | None | Hash published |
//! | 1 | Unlisted | None | Hash shared OOB |
//! | 2 | TrustGated | Yes | Trusted channel |
//! | 3 | GroupScoped | Yes | Group Sender Key |
//! | 4 | Direct | Yes | Direct message |
//!
//! # Storage Methods
//!
//! - **Distributed**: Freenet-style, availability proportional to demand
//! - **Sticky**: pinned to specific nodes with committed expiry
//! - **Scoped**: restricted to a group or LAN

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum chunk size for distributed storage (bytes). 128 KB.
pub const MIN_CHUNK_SIZE: u32 = 128 * 1024;

/// Maximum chunk size for distributed storage (bytes). 16 MB.
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

/// Default chunk size (bytes). 1 MB.
pub const DEFAULT_STORAGE_CHUNK_SIZE: u32 = 1_048_576;

/// Maximum age of a stop-storing signal (seconds). 30 days.
pub const STOP_STORING_MAX_AGE_SECS: u64 = 30 * 24 * 3600;

// ---------------------------------------------------------------------------
// Content Security Level (§11.2)
// ---------------------------------------------------------------------------

/// Content security level determining encryption and key distribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentSecurityLevel {
    /// No encryption. Hash published in indexes.
    Public = 0,
    /// No encryption. Hash NOT published; shared out-of-band.
    Unlisted = 1,
    /// Encrypted. Key shared via trusted channel to specific peers.
    TrustGated = 2,
    /// Encrypted. Key shared via group Sender Key mechanism.
    GroupScoped = 3,
    /// Encrypted. Key shared via direct trusted-channel message.
    Direct = 4,
}

// ---------------------------------------------------------------------------
// Storage Scope
// ---------------------------------------------------------------------------

/// Where content is stored and who can access it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageScope {
    /// Available mesh-wide.
    Global,
    /// Restricted to a specific group.
    Group([u8; 32]),
    /// Restricted to the local network.
    LAN,
}

// ---------------------------------------------------------------------------
// Storage Method
// ---------------------------------------------------------------------------

/// How content is stored across the mesh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMethod {
    /// Freenet-style: availability proportional to demand and node count.
    Distributed,
    /// Pinned to specific nodes with committed expiry.
    Sticky,
    /// Restricted to group or LAN scope.
    Scoped,
}

// ---------------------------------------------------------------------------
// File Manifest (§11.2)
// ---------------------------------------------------------------------------

/// A file manifest tying chunks together with metadata.
///
/// Content-addressed: the manifest itself has a hash that serves
/// as the file's unique identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileManifest {
    /// Manifest format version.
    pub version: u32,
    /// File name (plaintext for L0-1, encrypted for L2-4).
    pub file_name: Option<Vec<u8>>,
    /// MIME type.
    pub mime_type: Option<Vec<u8>>,
    /// Total plaintext file size (bytes).
    pub total_size: u64,
    /// Chunk size (power of two, constant within file).
    pub chunk_size: u32,
    /// Total number of chunks.
    pub chunk_count: u32,
    /// Individual chunk entries with content hashes.
    pub chunks: Vec<ChunkEntry>,
    /// SHA-256 hash of a thumbnail (separate content-addressed blob).
    pub thumbnail_hash: Option<[u8; 32]>,
    /// Recipient-encrypted file key blob (convenience).
    pub file_key_hint: Option<Vec<u8>>,
    /// Content security level.
    pub security_level: ContentSecurityLevel,
    /// When the manifest was created (Unix timestamp).
    pub created_at: u64,
    /// Publisher peer ID (attribution only, not a signature).
    pub publisher: Option<[u8; 32]>,
}

/// A single chunk entry in a file manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkEntry {
    /// Zero-indexed chunk number.
    pub index: u32,
    /// SHA-256 of the encrypted ciphertext.
    pub content_hash: [u8; 32],
    /// Size of this chunk (bytes). Last chunk may be smaller.
    pub size: u32,
}

// ---------------------------------------------------------------------------
// Storage Announcement
// ---------------------------------------------------------------------------

/// Announcement that a node is storing a content chunk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageAnnouncement {
    /// SHA-256 of the encrypted chunk ciphertext.
    pub content_hash: [u8; 32],
    /// The storing node's ID.
    pub node_id: [u8; 32],
    /// When the storage expires.
    pub expires_at: u64,
    /// Storage scope.
    pub scope: StorageScope,
    /// Ed25519 signature over (content_hash || node_id || expires_at).
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Storage Commitment (Sticky)
// ---------------------------------------------------------------------------

/// A commitment to store content until a specific time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageCommitment {
    /// Hash of the manifest being committed to.
    pub manifest_hash: [u8; 32],
    /// Hashes of all chunks in the file.
    pub chunk_hashes: Vec<[u8; 32]>,
    /// Committed storage duration (Unix timestamp).
    pub committed_until: u64,
    /// Publisher's Ed25519 signature.
    pub publisher_sig: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Stop-Storing Signal
// ---------------------------------------------------------------------------

/// A signal to delete stored content.
///
/// Only the original publisher can issue this.
/// Anonymous publishes (publisher: None) cannot issue stop-storing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StopStoringSignal {
    /// Hash of the manifest to stop storing.
    pub manifest_hash: [u8; 32],
    /// Hashes of all chunks to delete.
    pub chunk_hashes: Vec<[u8; 32]>,
    /// When the signal was issued (rejected if > 30 days old).
    pub issued_at: u64,
    /// Must match manifest.publisher.
    pub issuer: [u8; 32],
    /// Ed25519 signature over (manifest_hash || issued_at).
    pub signature: Vec<u8>,
}

impl StopStoringSignal {
    /// Check if this signal is still valid (not too old).
    pub fn is_valid(&self, now: u64) -> bool {
        now.saturating_sub(self.issued_at) <= STOP_STORING_MAX_AGE_SECS
    }
}

// ---------------------------------------------------------------------------
// Fetch State (persisted in vault)
// ---------------------------------------------------------------------------

/// Tracks progress of a multi-chunk fetch.
///
/// Persisted so that interrupted downloads can be resumed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchState {
    /// Hash of the manifest being fetched.
    pub manifest_hash: [u8; 32],
    /// Bitfield of received chunks.
    pub received_chunks: Vec<u8>,
    /// Bitfield of chunks that passed content_hash verification.
    pub verified_chunks: Vec<u8>,
    /// When the fetch started.
    pub started_at: u64,
    /// Last progress update timestamp.
    pub last_progress: u64,
}

impl FetchState {
    /// Create a new fetch state for a manifest.
    pub fn new(manifest_hash: [u8; 32], chunk_count: u32, now: u64) -> Self {
        let byte_count = (chunk_count as usize).div_ceil(8);
        Self {
            manifest_hash,
            received_chunks: vec![0u8; byte_count],
            verified_chunks: vec![0u8; byte_count],
            started_at: now,
            last_progress: now,
        }
    }

    /// Mark a chunk as received.
    pub fn mark_received(&mut self, index: u32) {
        let byte_idx = (index / 8) as usize;
        let bit_idx = index % 8;
        if byte_idx < self.received_chunks.len() {
            self.received_chunks[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Mark a chunk as verified (content hash matches).
    pub fn mark_verified(&mut self, index: u32) {
        let byte_idx = (index / 8) as usize;
        let bit_idx = index % 8;
        if byte_idx < self.verified_chunks.len() {
            self.verified_chunks[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Check if a chunk has been received.
    pub fn is_received(&self, index: u32) -> bool {
        let byte_idx = (index / 8) as usize;
        let bit_idx = index % 8;
        if byte_idx < self.received_chunks.len() {
            (self.received_chunks[byte_idx] >> bit_idx) & 1 == 1
        } else {
            false
        }
    }

    /// Count of received chunks.
    pub fn received_count(&self, total: u32) -> u32 {
        (0..total).filter(|&i| self.is_received(i)).count() as u32
    }
}

// ---------------------------------------------------------------------------
// Stickiness Metric (§11.2)
// ---------------------------------------------------------------------------

/// Compute the stickiness metric for content (1-5).
///
/// Higher = harder to revoke/delete. Used to warn the user
/// about the permanence of their publication.
pub fn compute_stickiness(
    security_level: ContentSecurityLevel,
    storage_method: &StorageMethod,
    publisher_anon: bool,
    scope: &StorageScope,
    estimated_nodes: usize,
    days_since_publish: u64,
    observed_fetches: u64,
) -> u8 {
    let mut score: i32 = match security_level {
        ContentSecurityLevel::Public => 4,
        ContentSecurityLevel::Unlisted => 3,
        ContentSecurityLevel::TrustGated => 2,
        ContentSecurityLevel::GroupScoped => 1,
        ContentSecurityLevel::Direct => 1,
    };

    if *storage_method == StorageMethod::Distributed {
        score += 1;
    }

    if publisher_anon {
        score += 1;
    }

    match scope {
        StorageScope::Global => score += 1,
        StorageScope::LAN => score -= 1,
        StorageScope::Group(_) => {} // +0
    }

    if estimated_nodes > 10 {
        score += 1;
    }
    if days_since_publish > 7 {
        score += 1;
    }
    if observed_fetches > 100 {
        score += 1;
    }

    score.clamp(1, 5) as u8
}

/// Human-readable stickiness label.
pub fn stickiness_label(score: u8) -> &'static str {
    match score {
        1 => "Fully revocable",
        2 => "Mostly revocable",
        3 => "Partially revocable",
        4 => "Mostly permanent",
        5 => "Effectively permanent",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_state() {
        let mut state = FetchState::new([0xAA; 32], 16, 1000);

        assert!(!state.is_received(0));

        state.mark_received(0);
        state.mark_received(5);
        state.mark_verified(0);

        assert!(state.is_received(0));
        assert!(state.is_received(5));
        assert!(!state.is_received(1));
        assert_eq!(state.received_count(16), 2);
    }

    #[test]
    fn test_stickiness_public_global() {
        let score = compute_stickiness(
            ContentSecurityLevel::Public,
            &StorageMethod::Distributed,
            true, // anonymous
            &StorageScope::Global,
            100,  // many nodes
            30,   // 30 days old
            200,  // many fetches
        );
        assert_eq!(score, 5); // Maximum stickiness.
    }

    #[test]
    fn test_stickiness_direct_lan() {
        let score = compute_stickiness(
            ContentSecurityLevel::Direct,
            &StorageMethod::Sticky,
            false,
            &StorageScope::LAN,
            2,
            0,
            0,
        );
        // Base 1, sticky +0, not anon +0, LAN -1, <10 nodes +0 = 0 → clamped to 1.
        assert_eq!(score, 1);
    }

    #[test]
    fn test_stickiness_labels() {
        assert_eq!(stickiness_label(1), "Fully revocable");
        assert_eq!(stickiness_label(5), "Effectively permanent");
    }

    #[test]
    fn test_stop_storing_validity() {
        let signal = StopStoringSignal {
            manifest_hash: [0xAA; 32],
            chunk_hashes: vec![[0xBB; 32]],
            issued_at: 1000,
            issuer: [0x01; 32],
            signature: vec![0x42; 64],
        };

        assert!(signal.is_valid(1000));
        assert!(signal.is_valid(1000 + STOP_STORING_MAX_AGE_SECS));
        assert!(!signal.is_valid(1000 + STOP_STORING_MAX_AGE_SECS + 1));
    }

    #[test]
    fn test_security_level_ordering() {
        assert!(ContentSecurityLevel::Public < ContentSecurityLevel::Direct);
        assert!(ContentSecurityLevel::TrustGated < ContentSecurityLevel::GroupScoped);
    }
}
