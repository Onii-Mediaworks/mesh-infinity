// Trust graph persistence and storage
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use serde::{Deserialize, Serialize};

use crate::core::{PeerId, TrustLevel};
use crate::core::error::{MeshInfinityError, Result};
use super::web_of_trust::{TrustAttestation, VerificationMethod};

/// Serializable trust relationship
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableTrustRelationship {
    pub peer_id: PeerId,
    pub trust_level: TrustLevel,
    pub verification_methods: Vec<VerificationMethod>,
    pub last_seen_timestamp: u64, // Unix timestamp
}

/// Exported trust graph for persistence
#[derive(Serialize, Deserialize)]
pub struct ExportedTrustGraph {
    pub relationships: Vec<SerializableTrustRelationship>,
    pub attestations: HashMap<PeerId, Vec<TrustAttestation>>,
    pub version: u32,
}

/// Trust storage manager
pub struct TrustStorage {
    storage_path: PathBuf,
}

impl TrustStorage {
    /// Create a new trust storage with specified path
    pub fn new<P: AsRef<Path>>(storage_path: P) -> Result<Self> {
        let path = storage_path.as_ref().to_path_buf();

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| MeshInfinityError::IoError(e))?;
        }

        Ok(Self {
            storage_path: path,
        })
    }

    /// Save trust graph to disk
    pub fn save(&self, exported: &ExportedTrustGraph) -> Result<()> {
        let json = serde_json::to_string_pretty(exported)
            .map_err(|e| MeshInfinityError::SerializationError(e.to_string()))?;

        fs::write(&self.storage_path, json)
            .map_err(|e| MeshInfinityError::IoError(e))?;

        Ok(())
    }

    /// Load trust graph from disk
    pub fn load(&self) -> Result<ExportedTrustGraph> {
        let json = fs::read_to_string(&self.storage_path)
            .map_err(|e| MeshInfinityError::IoError(e))?;

        let exported = serde_json::from_str(&json)
            .map_err(|e| MeshInfinityError::DeserializationError(e.to_string()))?;

        Ok(exported)
    }

    /// Check if storage file exists
    pub fn exists(&self) -> bool {
        self.storage_path.exists()
    }

    /// Get storage path
    pub fn path(&self) -> &Path {
        &self.storage_path
    }
}

/// Revocation certificate for revoking trust
#[derive(Clone, Serialize, Deserialize)]
pub struct RevocationCertificate {
    pub target: PeerId,
    pub revoker: PeerId,
    pub reason: RevocationReason,
    pub timestamp: u64, // Unix timestamp
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum RevocationReason {
    Compromised,
    Malicious,
    UserRequested,
    Timeout,
}

impl RevocationCertificate {
    /// Create a new revocation certificate
    pub fn new(target: PeerId, revoker: PeerId, reason: RevocationReason) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            target,
            revoker,
            reason,
            timestamp,
            signature: Vec::new(), // Signature to be added separately
        }
    }

    /// Get the message that should be signed
    pub fn signable_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.target);
        msg.extend_from_slice(&self.revoker);
        msg.push(match self.reason {
            RevocationReason::Compromised => 1,
            RevocationReason::Malicious => 2,
            RevocationReason::UserRequested => 3,
            RevocationReason::Timeout => 4,
        });
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_storage_save_load() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_path_buf();

        let storage = TrustStorage::new(&temp_path).unwrap();

        // Create test data
        let exported = ExportedTrustGraph {
            relationships: vec![
                SerializableTrustRelationship {
                    peer_id: [1u8; 32],
                    trust_level: TrustLevel::Trusted,
                    verification_methods: vec![VerificationMethod::InPerson],
                    last_seen_timestamp: 1234567890,
                },
            ],
            attestations: HashMap::new(),
            version: 1,
        };

        // Save
        storage.save(&exported).unwrap();

        // Load
        let loaded = storage.load().unwrap();

        assert_eq!(loaded.relationships.len(), 1);
        assert_eq!(loaded.relationships[0].peer_id, [1u8; 32]);
        assert_eq!(loaded.relationships[0].trust_level, TrustLevel::Trusted);
        assert_eq!(loaded.version, 1);
    }

    #[test]
    fn test_revocation_certificate() {
        let target = [1u8; 32];
        let revoker = [2u8; 32];
        let cert = RevocationCertificate::new(
            target,
            revoker,
            RevocationReason::Compromised,
        );

        let msg = cert.signable_message();
        assert!(!msg.is_empty());
        assert_eq!(&msg[0..32], &target);
        assert_eq!(&msg[32..64], &revoker);
    }
}
