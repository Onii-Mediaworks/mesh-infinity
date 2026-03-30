//! Storage Backend Adapter Interface (§11.5)
//!
//! # What is a Storage Backend?
//!
//! A pluggable storage layer for distributed content. Different
//! content types route to different backends by default:
//!
//! | Content Type | Default Backend |
//! |---|---|
//! | Message history | Local vault |
//! | S&F payloads | Local vault |
//! | Public files | IPFS |
//! | Private files | Local vault + direct |
//! | Backups | Local + cloud |
//! | Garden media | Local vault on cluster |
//!
//! # Backend Capabilities
//!
//! Each backend declares its capabilities (mutability, persistence,
//! redundancy, latency class). The system routes content to
//! appropriate backends based on these capabilities.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Content ID
// ---------------------------------------------------------------------------

/// A content identifier — the universal reference for stored blobs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
// Begin the block scope.
// ContentId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ContentId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ContentId {
    /// SHA-256 hash of the content.
    // Execute this protocol step.
    // Execute this protocol step.
    pub hash: [u8; 32],
    /// Content size (bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub size: u64,
    /// Which backend stores this content.
    // Execute this protocol step.
    // Execute this protocol step.
    pub backend: BackendId,
}

/// Backend identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
// Begin the block scope.
// BackendId — variant enumeration.
// Match exhaustively to handle every protocol state.
// BackendId — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum BackendId {
    // Execute this protocol step.
    // Execute this protocol step.
    LocalVault,
    Ipfs,
    // Execute this protocol step.
    // Execute this protocol step.
    TahoeLafs,
    // Execute this protocol step.
    // Execute this protocol step.
    Hypercore,
    // Execute this protocol step.
    // Execute this protocol step.
    Custom(String),
}

// ---------------------------------------------------------------------------
// Backend Capabilities
// ---------------------------------------------------------------------------

/// What a storage backend can do (§11.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// BackendCapabilities — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// BackendCapabilities — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct BackendCapabilities {
    /// Whether stored content can be mutated in place.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mutable: bool,
    /// Whether content can be deleted.
    // Execute this protocol step.
    // Execute this protocol step.
    pub deletable: bool,
    /// Whether content survives restarts.
    // Execute this protocol step.
    // Execute this protocol step.
    pub persistent: bool,
    /// Maximum blob size (0 = unlimited).
    // Execute this protocol step.
    // Execute this protocol step.
    pub max_blob_size: u64,
    /// How content is replicated.
    // Execute this protocol step.
    // Execute this protocol step.
    pub redundancy: RedundancyModel,
    /// Expected access latency.
    // Execute this protocol step.
    // Execute this protocol step.
    pub latency_class: LatencyClass,
}

/// How a backend replicates data.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// RedundancyModel — variant enumeration.
// Match exhaustively to handle every protocol state.
// RedundancyModel — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RedundancyModel {
    /// No redundancy (single copy).
    // No value available.
    // No value available.
    None,
    /// N copies on different nodes.
    // Execute this protocol step.
    // Execute this protocol step.
    Replication(u32),
    /// Erasure coding (k of n).
    // Execute this protocol step.
    // Execute this protocol step.
    ErasureCoding { k: u32, n: u32 },
}

/// Expected access latency class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// LatencyClass — variant enumeration.
// Match exhaustively to handle every protocol state.
// LatencyClass — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum LatencyClass {
    /// Local storage (< 1ms).
    Local,
    /// LAN (< 10ms).
    Lan,
    /// Internet (< 500ms).
    // Execute this protocol step.
    // Execute this protocol step.
    Internet,
    /// High latency (> 500ms, e.g., satellite, Tor).
    // Execute this protocol step.
    // Execute this protocol step.
    HighLatency,
}

/// Result of a delete/remove operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// RemoveResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// RemoveResult — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RemoveResult {
    /// Content was deleted.
    Deleted,
    /// Content was not found.
    // Execute this protocol step.
    // Execute this protocol step.
    NotFound,
    /// Best-effort deletion (distributed storage, can't guarantee).
    // Execute this protocol step.
    // Execute this protocol step.
    BestEffort,
}

// ---------------------------------------------------------------------------
// IPFS Configuration
// ---------------------------------------------------------------------------

/// IPFS backend configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// IpfsConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// IpfsConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct IpfsConfig {
    /// IPFS API endpoint.
    // Execute this protocol step.
    // Execute this protocol step.
    pub api_endpoint: String,
    /// IPFS gateway for HTTP access.
    // Execute this protocol step.
    // Execute this protocol step.
    pub gateway: Option<String>,
    /// Whether to pin content on add.
    // Execute this protocol step.
    // Execute this protocol step.
    pub pin_on_add: bool,
    /// Remote pinning service configuration.
    // Execute this protocol step.
    // Execute this protocol step.
    pub remote_pinning: Option<String>,
}

// Trait implementation for protocol conformance.
// Implement Default for IpfsConfig.
// Implement Default for IpfsConfig.
impl Default for IpfsConfig {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            api_endpoint: "http://127.0.0.1:5001".to_string(),
            // Execute this protocol step.
            // Execute this protocol step.
            gateway: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            pin_on_add: true,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            remote_pinning: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tahoe-LAFS Configuration
// ---------------------------------------------------------------------------

/// Tahoe-LAFS backend configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TahoeLafsConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TahoeLafsConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TahoeLafsConfig {
    /// Introducer FURL.
    // Execute this protocol step.
    // Execute this protocol step.
    pub introducer_furl: String,
    /// Shares needed to reconstruct (K).
    // Execute this protocol step.
    // Execute this protocol step.
    pub shares_needed: u32,
    /// Happy threshold (H).
    // Execute this protocol step.
    // Execute this protocol step.
    pub shares_happy: u32,
    /// Total shares generated (N).
    // Execute this protocol step.
    // Execute this protocol step.
    pub shares_total: u32,
}

// Trait implementation for protocol conformance.
// Implement Default for TahoeLafsConfig.
// Implement Default for TahoeLafsConfig.
impl Default for TahoeLafsConfig {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            introducer_furl: String::new(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            shares_needed: 3,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            shares_happy: 7,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            shares_total: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Hypercore Configuration
// ---------------------------------------------------------------------------

/// Hypercore backend configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// HypercoreConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// HypercoreConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct HypercoreConfig {
    /// Storage directory.
    // Execute this protocol step.
    // Execute this protocol step.
    pub storage_dir: String,
    /// Replication mode.
    // Execute this protocol step.
    // Execute this protocol step.
    pub replication: ReplicationMode,
    /// Whether discovery is enabled.
    /// Keep false for private data.
    // Execute this protocol step.
    // Execute this protocol step.
    pub discovery: bool,
}

/// Hypercore replication mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// ReplicationMode — variant enumeration.
// Match exhaustively to handle every protocol state.
// ReplicationMode — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ReplicationMode {
    Manual,
    // Execute this protocol step.
    // Execute this protocol step.
    OnConnect,
    // Execute this protocol step.
    // Execute this protocol step.
    AlwaysOn,
}

// ---------------------------------------------------------------------------
// Blob Metadata
// ---------------------------------------------------------------------------

/// Metadata for a stored blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// BlobMetadata — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// BlobMetadata — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct BlobMetadata {
    /// Content type (MIME).
    // Execute this protocol step.
    // Execute this protocol step.
    pub content_type: Option<String>,
    /// When the blob was stored.
    // Execute this protocol step.
    // Execute this protocol step.
    pub stored_at: u64,
    /// Which backend to prefer.
    // Execute this protocol step.
    // Execute this protocol step.
    pub preferred_backend: Option<BackendId>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipfs_defaults() {
        let config = IpfsConfig::default();
        assert_eq!(config.api_endpoint, "http://127.0.0.1:5001");
        assert!(config.pin_on_add);
    }

    #[test]
    fn test_tahoe_defaults() {
        let config = TahoeLafsConfig::default();
        assert_eq!(config.shares_needed, 3);
        assert_eq!(config.shares_total, 10);
    }

    #[test]
    fn test_content_id_serde() {
        let id = ContentId {
            hash: [0xAA; 32],
            size: 1024,
            backend: BackendId::Ipfs,
        };
        let json = serde_json::to_string(&id).unwrap();
        let recovered: ContentId = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.backend, BackendId::Ipfs);
    }

    #[test]
    fn test_backend_capabilities() {
        let caps = BackendCapabilities {
            mutable: false,
            deletable: false,
            persistent: true,
            max_blob_size: 0,
            redundancy: RedundancyModel::ErasureCoding { k: 3, n: 10 },
            latency_class: LatencyClass::Internet,
        };
        assert!(!caps.mutable);
    }
}
