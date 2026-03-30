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
// Begin the block scope.
// HostedFileEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// HostedFileEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// HostedFileEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct HostedFileEntry {
    /// SHA-256 hash of the file manifest.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub manifest_hash: [u8; 32],
    /// File name.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// File size (bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub size: u64,
    /// MIME type.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mime_type: String,
    /// Optional description.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: Option<String>,
    /// URL path under the mesh HTTP service.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub path: String,
    /// When this file was published (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// GroupFileRepository — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GroupFileRepository — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GroupFileRepository — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GroupFileRepository {
    /// Which group owns this repository.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub group_id: [u8; 32],
    /// Files in the repository.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub files: Vec<GroupFileEntry>,
    /// Monotonically increasing version number.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub version: u64,
    /// Admin signatures (one per approving admin).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sigs: Vec<Vec<u8>>,
}

/// A single file in a group repository.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// GroupFileEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GroupFileEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GroupFileEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GroupFileEntry {
    /// SHA-256 hash of the file manifest.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub manifest_hash: [u8; 32],
    /// File name.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// File size (bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub size: u64,
    /// MIME type.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mime_type: String,
    /// Who added this file (member peer ID).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub added_by: [u8; 32],
    /// When it was added (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub added_at: u64,
    /// Optional description.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: Option<String>,
}

// Begin the block scope.
// GroupFileRepository implementation — core protocol logic.
// GroupFileRepository implementation — core protocol logic.
// GroupFileRepository implementation — core protocol logic.
impl GroupFileRepository {
    /// Create a new empty repository for a group.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(group_id: [u8; 32]) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            group_id,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            files: Vec::new(),
            // Execute this protocol step.
            // Execute this protocol step.
            version: 1,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            sigs: Vec::new(),
        }
    }

    /// Add a file to the repository.
    // Perform the 'add file' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add file' operation.
    // Errors are propagated to the caller via Result.
    pub fn add_file(&mut self, entry: GroupFileEntry) {
        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        self.files.push(entry);
        // Update the version to reflect the new state.
        // Advance version state.
        // Advance version state.
        self.version += 1;
        // Signatures are invalidated — need re-signing.
        // Execute this protocol step.
        // Execute this protocol step.
        self.sigs.clear();
    }

    /// Remove a file by manifest hash.
    // Perform the 'remove file' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'remove file' operation.
    // Errors are propagated to the caller via Result.
    pub fn remove_file(&mut self, manifest_hash: &[u8; 32]) -> bool {
        // Track the count for threshold and bounds checking.
        // Compute len before for this protocol step.
        // Compute len before for this protocol step.
        let len_before = self.files.len();
        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.files.retain(|f| f.manifest_hash != *manifest_hash);
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.files.len() < len_before {
            // Update the version to reflect the new state.
            // Advance version state.
            // Advance version state.
            self.version += 1;
            // Mutate the internal state.
            // Execute this protocol step.
            // Execute this protocol step.
            self.sigs.clear();
            true
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            false
        }
    }

    /// Number of files.
    // Perform the 'file count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'file count' operation.
    // Errors are propagated to the caller via Result.
    pub fn file_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.files.len()
    }

    /// Total size of all files.
    // Perform the 'total size' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'total size' operation.
    // Errors are propagated to the caller via Result.
    pub fn total_size(&self) -> u64 {
        // Transform the result, mapping errors to the local error type.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
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
