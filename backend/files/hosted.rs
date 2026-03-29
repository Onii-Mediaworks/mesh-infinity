//! Public and Group File Hosting (§11.3, §11.4)
//!
//! # Public File Hosting (§11.3)
//!
//! Nodes can host files publicly, addressable by both a URL path
//! and by content hash (sha256:<hex>). Cached copies with verified
//! hashes are unconditionally valid forever — no cache invalidation.
//!
//! # Group File Repositories (§11.4)
//!
//! Groups can maintain shared file repositories. Files are encrypted
//! with the group's epoch key and published to GroupScoped storage.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public File Hosting (§11.3)
// ---------------------------------------------------------------------------

/// A publicly hosted file entry.
///
/// Dual-addressed: by host path (e.g., "/files/report.pdf") and
/// by content hash (sha256:<manifest_hash_hex>).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostedFileEntry {
    /// SHA-256 hash of the file manifest.
    pub manifest_hash: [u8; 32],
    /// File name.
    pub name: String,
    /// File size (bytes).
    pub size: u64,
    /// MIME type.
    pub mime_type: String,
    /// Optional description.
    pub description: Option<String>,
    /// URL path under the mesh HTTP service.
    pub path: String,
    /// When this file was published (Unix timestamp).
    pub published_at: u64,
}

// ---------------------------------------------------------------------------
// Group File Repository (§11.4)
// ---------------------------------------------------------------------------

/// A group's shared file repository.
///
/// Files are encrypted with the group's epoch key. The repository
/// is signed by admin quorum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupFileRepository {
    /// Which group owns this repository.
    pub group_id: [u8; 32],
    /// Files in the repository.
    pub files: Vec<GroupFileEntry>,
    /// Monotonically increasing version number.
    pub version: u64,
    /// Admin signatures (one per approving admin).
    pub sigs: Vec<Vec<u8>>,
}

/// A single file in a group repository.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupFileEntry {
    /// SHA-256 hash of the file manifest.
    pub manifest_hash: [u8; 32],
    /// File name.
    pub name: String,
    /// File size (bytes).
    pub size: u64,
    /// MIME type.
    pub mime_type: String,
    /// Who added this file (member peer ID).
    pub added_by: [u8; 32],
    /// When it was added (Unix timestamp).
    pub added_at: u64,
    /// Optional description.
    pub description: Option<String>,
}

impl GroupFileRepository {
    /// Create a new empty repository for a group.
    pub fn new(group_id: [u8; 32]) -> Self {
        Self {
            group_id,
            files: Vec::new(),
            version: 1,
            sigs: Vec::new(),
        }
    }

    /// Add a file to the repository.
    pub fn add_file(&mut self, entry: GroupFileEntry) {
        self.files.push(entry);
        self.version += 1;
        // Signatures are invalidated — need re-signing.
        self.sigs.clear();
    }

    /// Remove a file by manifest hash.
    pub fn remove_file(&mut self, manifest_hash: &[u8; 32]) -> bool {
        let len_before = self.files.len();
        self.files.retain(|f| f.manifest_hash != *manifest_hash);
        if self.files.len() < len_before {
            self.version += 1;
            self.sigs.clear();
            true
        } else {
            false
        }
    }

    /// Number of files.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Total size of all files.
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_repo_lifecycle() {
        let mut repo = GroupFileRepository::new([0xAA; 32]);
        assert_eq!(repo.file_count(), 0);
        assert_eq!(repo.version, 1);

        let entry = GroupFileEntry {
            manifest_hash: [0xBB; 32],
            name: "doc.pdf".to_string(),
            size: 1_000_000,
            mime_type: "application/pdf".to_string(),
            added_by: [0x01; 32],
            added_at: 1000,
            description: None,
        };

        repo.add_file(entry);
        assert_eq!(repo.file_count(), 1);
        assert_eq!(repo.version, 2);
        assert_eq!(repo.total_size(), 1_000_000);

        assert!(repo.remove_file(&[0xBB; 32]));
        assert_eq!(repo.file_count(), 0);
        assert_eq!(repo.version, 3);
    }

    #[test]
    fn test_hosted_file_entry() {
        let entry = HostedFileEntry {
            manifest_hash: [0xCC; 32],
            name: "readme.txt".to_string(),
            size: 1024,
            mime_type: "text/plain".to_string(),
            description: Some("A readme file".to_string()),
            path: "/files/readme.txt".to_string(),
            published_at: 2000,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let recovered: HostedFileEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.name, "readme.txt");
    }
}
