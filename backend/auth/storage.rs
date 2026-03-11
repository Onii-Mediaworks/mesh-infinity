// Trust graph persistence and storage
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::web_of_trust::{TrustAttestation, VerificationMethod};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::{PeerId, TrustLevel};

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
    #[serde(default)]
    pub revocations: Vec<RevocationCertificate>,
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
            fs::create_dir_all(parent).map_err(MeshInfinityError::IoError)?;
        }

        Ok(Self { storage_path: path })
    }

    /// Save trust graph to disk
    pub fn save(&self, exported: &ExportedTrustGraph) -> Result<()> {
        let json = serde_json::to_string_pretty(exported)
            .map_err(|e| MeshInfinityError::SerializationError(e.to_string()))?;

        fs::write(&self.storage_path, json).map_err(MeshInfinityError::IoError)?;

        Ok(())
    }

    /// Load trust graph from disk
    pub fn load(&self) -> Result<ExportedTrustGraph> {
        let json = fs::read_to_string(&self.storage_path).map_err(MeshInfinityError::IoError)?;

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

    /// Attach a detached Ed25519 signature for this certificate payload.
    pub fn attach_signature(&mut self, signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            return Err(MeshInfinityError::AuthError(
                "Invalid revocation signature length".to_string(),
            ));
        }
        self.signature = signature.to_vec();
        Ok(())
    }

    /// Verify certificate signature against provided public key bytes.
    ///
    /// Also enforces that `revoker` deterministically matches the signing key.
    pub fn verify_signature(&self, revoker_public_key: &[u8; 32]) -> Result<bool> {
        if self.signature.len() != 64 {
            return Ok(false);
        }

        let derived_revoker = derive_peer_id_from_public_key(revoker_public_key);
        if derived_revoker != self.revoker {
            return Ok(false);
        }

        let public_key = VerifyingKey::from_bytes(revoker_public_key)
            .map_err(|e| MeshInfinityError::CryptoError(format!("Invalid public key: {}", e)))?;
        let sig_bytes: [u8; 64] = self.signature[..64]
            .try_into()
            .map_err(|_| MeshInfinityError::CryptoError("Invalid signature bytes".to_string()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        Ok(public_key
            .verify(&self.signable_message(), &signature)
            .is_ok())
    }
}

/// Derive deterministic peer id from public key bytes.
fn derive_peer_id_from_public_key(public_key: &[u8; 32]) -> PeerId {
    const DOMAIN: &str = "meshinfinity-peer-id-v1";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN.as_bytes());
    hasher.update(public_key);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Test case: storage save load.
    #[test]
    fn test_storage_save_load() {
        let temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_path_buf();

        let storage = TrustStorage::new(&temp_path).unwrap();

        // Create test data
        let exported = ExportedTrustGraph {
            relationships: vec![SerializableTrustRelationship {
                peer_id: [1u8; 32],
                trust_level: TrustLevel::Trusted,
                verification_methods: vec![VerificationMethod::InPerson],
                last_seen_timestamp: 1234567890,
            }],
            attestations: HashMap::new(),
            revocations: Vec::new(),
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

    /// Test case: revocation certificate.
    #[test]
    fn test_revocation_certificate() {
        let target = [1u8; 32];
        let revoker = [2u8; 32];
        let cert = RevocationCertificate::new(target, revoker, RevocationReason::Compromised);

        let msg = cert.signable_message();
        assert!(!msg.is_empty());
        assert_eq!(&msg[0..32], &target);
        assert_eq!(&msg[32..64], &revoker);
    }
}
