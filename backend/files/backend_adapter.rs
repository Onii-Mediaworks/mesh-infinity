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
pub struct ContentId {
    /// SHA-256 hash of the content.
    pub hash: [u8; 32],
    /// Content size (bytes).
    pub size: u64,
    /// Which backend stores this content.
    pub backend: BackendId,
}

/// Backend identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackendId {
    LocalVault,
    Ipfs,
    TahoeLafs,
    Hypercore,
    Custom(String),
}

// ---------------------------------------------------------------------------
// Backend Capabilities
// ---------------------------------------------------------------------------

/// What a storage backend can do (§11.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Whether stored content can be mutated in place.
    pub mutable: bool,
    /// Whether content can be deleted.
    pub deletable: bool,
    /// Whether content survives restarts.
    pub persistent: bool,
    /// Maximum blob size (0 = unlimited).
    pub max_blob_size: u64,
    /// How content is replicated.
    pub redundancy: RedundancyModel,
    /// Expected access latency.
    pub latency_class: LatencyClass,
}

/// How a backend replicates data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RedundancyModel {
    /// No redundancy (single copy).
    None,
    /// N copies on different nodes.
    Replication(u32),
    /// Erasure coding (k of n).
    ErasureCoding { k: u32, n: u32 },
}

/// Expected access latency class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LatencyClass {
    /// Local storage (< 1ms).
    Local,
    /// LAN (< 10ms).
    Lan,
    /// Internet (< 500ms).
    Internet,
    /// High latency (> 500ms, e.g., satellite, Tor).
    HighLatency,
}

/// Result of a delete/remove operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoveResult {
    /// Content was deleted.
    Deleted,
    /// Content was not found.
    NotFound,
    /// Best-effort deletion (distributed storage, can't guarantee).
    BestEffort,
}

// ---------------------------------------------------------------------------
// IPFS Configuration
// ---------------------------------------------------------------------------

/// IPFS backend configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpfsConfig {
    /// IPFS API endpoint.
    pub api_endpoint: String,
    /// IPFS gateway for HTTP access.
    pub gateway: Option<String>,
    /// Whether to pin content on add.
    pub pin_on_add: bool,
    /// Remote pinning service configuration.
    pub remote_pinning: Option<String>,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "http://127.0.0.1:5001".to_string(),
            gateway: None,
            pin_on_add: true,
            remote_pinning: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tahoe-LAFS Configuration
// ---------------------------------------------------------------------------

/// Tahoe-LAFS backend configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TahoeLafsConfig {
    /// Introducer FURL.
    pub introducer_furl: String,
    /// Shares needed to reconstruct (K).
    pub shares_needed: u32,
    /// Happy threshold (H).
    pub shares_happy: u32,
    /// Total shares generated (N).
    pub shares_total: u32,
}

impl Default for TahoeLafsConfig {
    fn default() -> Self {
        Self {
            introducer_furl: String::new(),
            shares_needed: 3,
            shares_happy: 7,
            shares_total: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Hypercore Configuration
// ---------------------------------------------------------------------------

/// Hypercore backend configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HypercoreConfig {
    /// Storage directory.
    pub storage_dir: String,
    /// Replication mode.
    pub replication: ReplicationMode,
    /// Whether discovery is enabled.
    /// Keep false for private data.
    pub discovery: bool,
}

/// Hypercore replication mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationMode {
    Manual,
    OnConnect,
    AlwaysOn,
}

// ---------------------------------------------------------------------------
// Blob Metadata
// ---------------------------------------------------------------------------

/// Metadata for a stored blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobMetadata {
    /// Content type (MIME).
    pub content_type: Option<String>,
    /// When the blob was stored.
    pub stored_at: u64,
    /// Which backend to prefer.
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
