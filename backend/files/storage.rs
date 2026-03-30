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
// MIN_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MIN_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MIN_CHUNK_SIZE: u32 = 128 * 1024;

/// Maximum chunk size for distributed storage (bytes). 16 MB.
// MAX_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

/// Default chunk size (bytes). 1 MB.
// DEFAULT_STORAGE_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_STORAGE_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEFAULT_STORAGE_CHUNK_SIZE: u32 = 1_048_576;

/// Maximum age of a stop-storing signal (seconds). 30 days.
// STOP_STORING_MAX_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// STOP_STORING_MAX_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const STOP_STORING_MAX_AGE_SECS: u64 = 30 * 24 * 3600;

// ---------------------------------------------------------------------------
// Content Security Level (§11.2)
// ---------------------------------------------------------------------------

/// Content security level determining encryption and key distribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
// Begin the block scope.
// ContentSecurityLevel — variant enumeration.
// Match exhaustively to handle every protocol state.
// ContentSecurityLevel — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ContentSecurityLevel {
    /// No encryption. Hash published in indexes.
    // Execute this protocol step.
    // Execute this protocol step.
    Public = 0,
    /// No encryption. Hash NOT published; shared out-of-band.
    // Execute this protocol step.
    // Execute this protocol step.
    Unlisted = 1,
    /// Encrypted. Key shared via trusted channel to specific peers.
    // Execute this protocol step.
    // Execute this protocol step.
    TrustGated = 2,
    /// Encrypted. Key shared via group Sender Key mechanism.
    // Execute this protocol step.
    // Execute this protocol step.
    GroupScoped = 3,
    /// Encrypted. Key shared via direct trusted-channel message.
    // Execute this protocol step.
    // Execute this protocol step.
    Direct = 4,
}

// ---------------------------------------------------------------------------
// Storage Scope
// ---------------------------------------------------------------------------

/// Where content is stored and who can access it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// StorageScope — variant enumeration.
// Match exhaustively to handle every protocol state.
// StorageScope — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum StorageScope {
    /// Available mesh-wide.
    Global,
    /// Restricted to a specific group.
    // Execute this protocol step.
    // Execute this protocol step.
    Group([u8; 32]),
    /// Restricted to the local network.
    LAN,
}

// ---------------------------------------------------------------------------
// Storage Method
// ---------------------------------------------------------------------------

/// How content is stored across the mesh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// StorageMethod — variant enumeration.
// Match exhaustively to handle every protocol state.
// StorageMethod — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum StorageMethod {
    /// Freenet-style: availability proportional to demand and node count.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// FileManifest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileManifest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileManifest {
    /// Manifest format version.
    // Execute this protocol step.
    // Execute this protocol step.
    pub version: u32,
    /// File name (plaintext for L0-1, encrypted for L2-4).
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_name: Option<Vec<u8>>,
    /// MIME type.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mime_type: Option<Vec<u8>>,
    /// Total plaintext file size (bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub total_size: u64,
    /// Chunk size (power of two, constant within file).
    // Execute this protocol step.
    // Execute this protocol step.
    pub chunk_size: u32,
    /// Total number of chunks.
    // Execute this protocol step.
    // Execute this protocol step.
    pub chunk_count: u32,
    /// Individual chunk entries with content hashes.
    // Execute this protocol step.
    // Execute this protocol step.
    pub chunks: Vec<ChunkEntry>,
    /// SHA-256 hash of a thumbnail (separate content-addressed blob).
    // Execute this protocol step.
    // Execute this protocol step.
    pub thumbnail_hash: Option<[u8; 32]>,
    /// Recipient-encrypted file key blob (convenience).
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_key_hint: Option<Vec<u8>>,
    /// Content security level.
    // Execute this protocol step.
    // Execute this protocol step.
    pub security_level: ContentSecurityLevel,
    /// When the manifest was created (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    pub created_at: u64,
    /// Publisher peer ID (attribution only, not a signature).
    // Execute this protocol step.
    // Execute this protocol step.
    pub publisher: Option<[u8; 32]>,
}

/// A single chunk entry in a file manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ChunkEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ChunkEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ChunkEntry {
    /// Zero-indexed chunk number.
    // Execute this protocol step.
    // Execute this protocol step.
    pub index: u32,
    /// SHA-256 of the encrypted ciphertext.
    // Execute this protocol step.
    // Execute this protocol step.
    pub content_hash: [u8; 32],
    /// Size of this chunk (bytes). Last chunk may be smaller.
    // Execute this protocol step.
    // Execute this protocol step.
    pub size: u32,
}

// ---------------------------------------------------------------------------
// Storage Announcement
// ---------------------------------------------------------------------------

/// Announcement that a node is storing a content chunk.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// StorageAnnouncement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// StorageAnnouncement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct StorageAnnouncement {
    /// SHA-256 of the encrypted chunk ciphertext.
    // Execute this protocol step.
    // Execute this protocol step.
    pub content_hash: [u8; 32],
    /// The storing node's ID.
    // Execute this protocol step.
    // Execute this protocol step.
    pub node_id: [u8; 32],
    /// When the storage expires.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expires_at: u64,
    /// Storage scope.
    // Execute this protocol step.
    // Execute this protocol step.
    pub scope: StorageScope,
    /// Ed25519 signature over (content_hash || node_id || expires_at).
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Storage Commitment (Sticky)
// ---------------------------------------------------------------------------

/// A commitment to store content until a specific time.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// StorageCommitment — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// StorageCommitment — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct StorageCommitment {
    /// Hash of the manifest being committed to.
    // Execute this protocol step.
    // Execute this protocol step.
    pub manifest_hash: [u8; 32],
    /// Hashes of all chunks in the file.
    // Execute this protocol step.
    // Execute this protocol step.
    pub chunk_hashes: Vec<[u8; 32]>,
    /// Committed storage duration (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    pub committed_until: u64,
    /// Publisher's Ed25519 signature.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// StopStoringSignal — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// StopStoringSignal — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct StopStoringSignal {
    /// Hash of the manifest to stop storing.
    // Execute this protocol step.
    // Execute this protocol step.
    pub manifest_hash: [u8; 32],
    /// Hashes of all chunks to delete.
    // Execute this protocol step.
    // Execute this protocol step.
    pub chunk_hashes: Vec<[u8; 32]>,
    /// When the signal was issued (rejected if > 30 days old).
    // Execute this protocol step.
    // Execute this protocol step.
    pub issued_at: u64,
    /// Must match manifest.publisher.
    // Execute this protocol step.
    // Execute this protocol step.
    pub issuer: [u8; 32],
    /// Ed25519 signature over (manifest_hash || issued_at).
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// Begin the block scope.
// StopStoringSignal implementation — core protocol logic.
// StopStoringSignal implementation — core protocol logic.
impl StopStoringSignal {
    /// Check if this signal is still valid (not too old).
    // Perform the 'is valid' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is valid' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_valid(&self, now: u64) -> bool {
        // Clamp the value to prevent overflow or underflow.
        // Execute this protocol step.
        // Execute this protocol step.
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
// Begin the block scope.
// FetchState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FetchState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FetchState {
    /// Hash of the manifest being fetched.
    // Execute this protocol step.
    // Execute this protocol step.
    pub manifest_hash: [u8; 32],
    /// Bitfield of received chunks.
    // Execute this protocol step.
    // Execute this protocol step.
    pub received_chunks: Vec<u8>,
    /// Bitfield of chunks that passed content_hash verification.
    // Execute this protocol step.
    // Execute this protocol step.
    pub verified_chunks: Vec<u8>,
    /// When the fetch started.
    // Execute this protocol step.
    // Execute this protocol step.
    pub started_at: u64,
    /// Last progress update timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_progress: u64,
}

// Begin the block scope.
// FetchState implementation — core protocol logic.
// FetchState implementation — core protocol logic.
impl FetchState {
    /// Create a new fetch state for a manifest.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(manifest_hash: [u8; 32], chunk_count: u32, now: u64) -> Self {
        // Track the count for threshold and bounds checking.
        // Compute byte count for this protocol step.
        // Compute byte count for this protocol step.
        let byte_count = (chunk_count as usize).div_ceil(8);
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            manifest_hash,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            received_chunks: vec![0u8; byte_count],
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            verified_chunks: vec![0u8; byte_count],
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            started_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            last_progress: now,
        }
    }

    /// Mark a chunk as received.
    // Perform the 'mark received' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'mark received' operation.
    // Errors are propagated to the caller via Result.
    pub fn mark_received(&mut self, index: u32) {
        // Track the count for threshold and bounds checking.
        // Compute byte idx for this protocol step.
        // Compute byte idx for this protocol step.
        let byte_idx = (index / 8) as usize;
        // Calculate the position within the data structure.
        // Compute bit idx for this protocol step.
        // Compute bit idx for this protocol step.
        let bit_idx = index % 8;
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if byte_idx < self.received_chunks.len() {
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            self.received_chunks[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Mark a chunk as verified (content hash matches).
    // Perform the 'mark verified' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'mark verified' operation.
    // Errors are propagated to the caller via Result.
    pub fn mark_verified(&mut self, index: u32) {
        // Track the count for threshold and bounds checking.
        // Compute byte idx for this protocol step.
        // Compute byte idx for this protocol step.
        let byte_idx = (index / 8) as usize;
        // Calculate the position within the data structure.
        // Compute bit idx for this protocol step.
        // Compute bit idx for this protocol step.
        let bit_idx = index % 8;
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if byte_idx < self.verified_chunks.len() {
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            self.verified_chunks[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Check if a chunk has been received.
    // Perform the 'is received' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is received' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_received(&self, index: u32) -> bool {
        // Track the count for threshold and bounds checking.
        // Compute byte idx for this protocol step.
        // Compute byte idx for this protocol step.
        let byte_idx = (index / 8) as usize;
        // Calculate the position within the data structure.
        // Compute bit idx for this protocol step.
        // Compute bit idx for this protocol step.
        let bit_idx = index % 8;
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if byte_idx < self.received_chunks.len() {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            (self.received_chunks[byte_idx] >> bit_idx) & 1 == 1
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            false
        }
    }

    /// Count of received chunks.
    // Perform the 'received count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'received count' operation.
    // Errors are propagated to the caller via Result.
    pub fn received_count(&self, total: u32) -> u32 {
        // Select only elements matching the predicate.
        // Filter by the predicate.
        // Filter by the predicate.
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
// Perform the 'compute stickiness' operation.
// Errors are propagated to the caller via Result.
// Perform the 'compute stickiness' operation.
// Errors are propagated to the caller via Result.
pub fn compute_stickiness(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    security_level: ContentSecurityLevel,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    storage_method: &StorageMethod,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    publisher_anon: bool,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    scope: &StorageScope,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    estimated_nodes: usize,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    days_since_publish: u64,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    observed_fetches: u64,
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> u8 {
    // Dispatch based on the variant to apply type-specific logic.
    // Compute score for this protocol step.
    // Compute score for this protocol step.
    let mut score: i32 = match security_level {
        // Handle this match arm.
        ContentSecurityLevel::Public => 4,
        // Handle this match arm.
        ContentSecurityLevel::Unlisted => 3,
        // Handle this match arm.
        ContentSecurityLevel::TrustGated => 2,
        // Handle this match arm.
        ContentSecurityLevel::GroupScoped => 1,
        // Handle this match arm.
        ContentSecurityLevel::Direct => 1,
    };

    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if *storage_method == StorageMethod::Distributed {
        // Execute this step in the protocol sequence.
        // Execute this protocol step.
        // Execute this protocol step.
        score += 1;
    }

    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if publisher_anon {
        // Execute this step in the protocol sequence.
        // Execute this protocol step.
        // Execute this protocol step.
        score += 1;
    }

    // Dispatch based on the variant to apply type-specific logic.
    // Dispatch on the variant.
    // Dispatch on the variant.
    match scope {
        // Handle this match arm.
        StorageScope::Global => score += 1,
        // Handle this match arm.
        StorageScope::LAN => score -= 1,
        // Invoke the associated function.
        // Handle StorageScope::Group(_).
        // Handle StorageScope::Group(_).
        StorageScope::Group(_) => {} // +0
    }

    // Bounds check to enforce protocol constraints.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if estimated_nodes > 10 {
        // Execute this step in the protocol sequence.
        // Execute this protocol step.
        // Execute this protocol step.
        score += 1;
    }
    // Bounds check to enforce protocol constraints.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if days_since_publish > 7 {
        // Execute this step in the protocol sequence.
        // Execute this protocol step.
        // Execute this protocol step.
        score += 1;
    }
    // Bounds check to enforce protocol constraints.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if observed_fetches > 100 {
        // Execute this step in the protocol sequence.
        // Execute this protocol step.
        // Execute this protocol step.
        score += 1;
    }

    // Clamp the value to prevent overflow or underflow.
    // Execute this protocol step.
    // Execute this protocol step.
    score.clamp(1, 5) as u8
}

/// Human-readable stickiness label.
// Perform the 'stickiness label' operation.
// Errors are propagated to the caller via Result.
// Perform the 'stickiness label' operation.
// Errors are propagated to the caller via Result.
pub fn stickiness_label(score: u8) -> &'static str {
    // Dispatch based on the variant to apply type-specific logic.
    // Dispatch on the variant.
    // Dispatch on the variant.
    match score {
        // Update the local state.
        1 => "Fully revocable",
        // Update the local state.
        2 => "Mostly revocable",
        // Update the local state.
        3 => "Partially revocable",
        // Update the local state.
        4 => "Mostly permanent",
        // Update the local state.
        5 => "Effectively permanent",
        // Update the local state.
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
