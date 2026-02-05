// Encrypted backup system
// Backs up identity, trust store, and network map WITHOUT compromising PFS
// Old communications remain unrecoverable even with backup

use std::collections::HashMap;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use argon2::{Argon2, ParamsBuilder};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::core::error::{MeshInfinityError, Result};
use super::secmem::{SecureKey32, SecureMemory};

/// Encrypted backup containing identity and trust data
/// DOES NOT include message history to maintain PFS
#[derive(Serialize, Deserialize)]
pub struct EncryptedBackup {
    /// Version for future compatibility
    version: u32,

    /// Salt for key derivation from passphrase
    salt: [u8; 32],

    /// Nonce for ChaCha20-Poly1305
    nonce: [u8; 12],

    /// Encrypted backup data
    ciphertext: Vec<u8>,

    /// Argon2 parameters (stored separately for transparency)
    argon2_mem_cost: u32,
    argon2_time_cost: u32,
    argon2_parallelism: u32,
}

/// Plaintext backup contents
/// Contains only identity and trust data, NOT message history
#[derive(Serialize, Deserialize)]
struct BackupContents {
    /// User's identity keypair (ed25519)
    identity_private_key: Vec<u8>,

    identity_public_key: Vec<u8>,

    /// Web of Trust data
    trust_store: TrustStore,

    /// Network map (known peers, not conversations)
    network_map: NetworkMap,

    /// Settings and preferences
    settings: BackupSettings,

    /// Timestamp of backup creation
    created_at: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TrustStore {
    /// Peer ID → Trust level
    trust_levels: HashMap<String, u8>,

    /// Peer ID → Shared verification data
    verification_data: HashMap<String, Vec<u8>>,

    /// Peer ID → Trust endorsements from others
    endorsements: HashMap<String, Vec<TrustEndorsement>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TrustEndorsement {
    endorser_id: String,
    target_id: String,
    trust_level: u8,
    signature: Vec<u8>,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NetworkMap {
    /// Known peers and their metadata (NOT conversation history)
    peers: HashMap<String, PeerMetadata>,

    /// Relay nodes
    relays: Vec<RelayNode>,

    /// Bootstrap nodes
    bootstrap_nodes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PeerMetadata {
    peer_id: String,
    display_name: Option<String>,
    public_key: Vec<u8>,
    last_seen: u64,
    available_transports: Vec<String>,
    // NOTE: No message history, no session keys
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RelayNode {
    node_id: String,
    onion_address: Option<String>,
    i2p_address: Option<String>,
    clearnet_address: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BackupSettings {
    display_name: Option<String>,
    preferred_transports: Vec<String>,
    enable_tor: bool,
    enable_i2p: bool,
    enable_clearnet: bool,
    // Other non-sensitive settings
}

pub struct BackupManager {
    /// Argon2 parameters for key derivation
    argon2_mem_cost: u32,
    argon2_time_cost: u32,
    argon2_parallelism: u32,
}

impl Default for BackupManager {
    fn default() -> Self {
        Self {
            // High security parameters
            // Memory cost: 64 MB
            argon2_mem_cost: 65536,
            // Time cost: 3 iterations
            argon2_time_cost: 3,
            // Parallelism: 4 threads
            argon2_parallelism: 4,
        }
    }
}

impl BackupManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create encrypted backup from identity and trust data
    /// IMPORTANT: Does NOT include message history
    pub fn create_backup(
        &self,
        passphrase: &str,
        identity_keypair: &[u8],  // ed25519 keypair (64 bytes)
        trust_store: TrustStore,
        network_map: NetworkMap,
        settings: BackupSettings,
    ) -> Result<EncryptedBackup> {
        // Validate passphrase strength
        if passphrase.len() < 12 {
            return Err(MeshInfinityError::CryptoError(
                "Passphrase must be at least 12 characters".to_string()
            ));
        }

        // Split keypair
        let (secret_key, public_key) = identity_keypair.split_at(32);

        // Create backup contents
        let contents = BackupContents {
            identity_private_key: secret_key.to_vec(),
            identity_public_key: public_key.to_vec(),
            trust_store,
            network_map,
            settings,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Serialize
        let plaintext = serde_json::to_vec(&contents)
            .map_err(|e| MeshInfinityError::SerializationError(e.to_string()))?;

        // Generate salt
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        // Derive encryption key from passphrase
        let encryption_key = self.derive_key_from_passphrase(passphrase, &salt)?;

        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt with ChaCha20-Poly1305
        let key = Key::from_slice(encryption_key.as_ref().as_bytes());
        let cipher = ChaCha20Poly1305::new(key);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|_| MeshInfinityError::CryptoError("Encryption failed".to_string()))?;

        Ok(EncryptedBackup {
            version: 1,
            salt,
            nonce: nonce_bytes,
            ciphertext,
            argon2_mem_cost: self.argon2_mem_cost,
            argon2_time_cost: self.argon2_time_cost,
            argon2_parallelism: self.argon2_parallelism,
        })
    }

    /// Restore from encrypted backup
    /// Returns identity and trust data, NOT message history
    pub fn restore_backup(
        &self,
        backup: &EncryptedBackup,
        passphrase: &str,
    ) -> Result<(Vec<u8>, TrustStore, NetworkMap, BackupSettings)> {
        // Check version
        if backup.version != 1 {
            return Err(MeshInfinityError::CryptoError(
                "Unsupported backup version".to_string()
            ));
        }

        // Derive decryption key
        let decryption_key = self.derive_key_from_passphrase(passphrase, &backup.salt)?;

        // Decrypt
        let key = Key::from_slice(decryption_key.as_ref().as_bytes());
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&backup.nonce);

        let plaintext = cipher
            .decrypt(nonce, backup.ciphertext.as_slice())
            .map_err(|_| MeshInfinityError::AuthError("Invalid passphrase or corrupted backup".to_string()))?;

        // Deserialize
        let contents: BackupContents = serde_json::from_slice(&plaintext)
            .map_err(|e| MeshInfinityError::DeserializationError(e.to_string()))?;

        // Reconstruct keypair
        let mut keypair = Vec::with_capacity(64);
        keypair.extend_from_slice(&contents.identity_private_key);
        keypair.extend_from_slice(&contents.identity_public_key);

        let trust_store = contents.trust_store.clone();
        let network_map = contents.network_map.clone();
        let settings = contents.settings.clone();

        Ok((keypair, trust_store, network_map, settings))
    }

    /// Export backup to encrypted file
    pub fn export_to_file(&self, backup: &EncryptedBackup, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(backup)
            .map_err(|e| MeshInfinityError::SerializationError(e.to_string()))?;

        std::fs::write(path, json)
            .map_err(|e| MeshInfinityError::CryptoError(format!("Failed to write backup: {}", e)))?;

        Ok(())
    }

    /// Import backup from encrypted file
    pub fn import_from_file(&self, path: &std::path::Path) -> Result<EncryptedBackup> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| MeshInfinityError::CryptoError(format!("Failed to read backup: {}", e)))?;

        let backup = serde_json::from_str(&json)
            .map_err(|e| MeshInfinityError::DeserializationError(e.to_string()))?;

        Ok(backup)
    }

    /// Derive encryption key from passphrase using Argon2
    fn derive_key_from_passphrase(
        &self,
        passphrase: &str,
        salt: &[u8; 32],
    ) -> Result<SecureMemory<SecureKey32>> {
        let params = ParamsBuilder::new()
            .m_cost(self.argon2_mem_cost)
            .t_cost(self.argon2_time_cost)
            .p_cost(self.argon2_parallelism)
            .build()
            .map_err(|e| MeshInfinityError::CryptoError(format!("Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| MeshInfinityError::CryptoError(format!("Key derivation failed: {}", e)))?;

        SecureKey32::new(key)
            .map_err(|_| MeshInfinityError::CryptoError("Secure memory allocation failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_restore_cycle() {
        let manager = BackupManager::new();

        // Create test data
        let keypair = [42u8; 64];
        let trust_store = TrustStore {
            trust_levels: HashMap::new(),
            verification_data: HashMap::new(),
            endorsements: HashMap::new(),
        };
        let network_map = NetworkMap {
            peers: HashMap::new(),
            relays: Vec::new(),
            bootstrap_nodes: Vec::new(),
        };
        let settings = BackupSettings {
            display_name: Some("Test User".to_string()),
            preferred_transports: vec!["tor".to_string()],
            enable_tor: true,
            enable_i2p: false,
            enable_clearnet: false,
        };

        // Create backup
        let passphrase = "very_strong_passphrase_here";
        let backup = manager
            .create_backup(passphrase, &keypair, trust_store.clone(), network_map.clone(), settings.clone())
            .unwrap();

        // Restore backup
        let (restored_keypair, restored_trust, restored_map, restored_settings) =
            manager.restore_backup(&backup, passphrase).unwrap();

        // Verify
        assert_eq!(&keypair[..], &restored_keypair[..]);
        assert_eq!(settings.display_name, restored_settings.display_name);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let manager = BackupManager::new();

        let keypair = [42u8; 64];
        let backup = manager
            .create_backup(
                "correct_passphrase",
                &keypair,
                TrustStore {
                    trust_levels: HashMap::new(),
                    verification_data: HashMap::new(),
                    endorsements: HashMap::new(),
                },
                NetworkMap {
                    peers: HashMap::new(),
                    relays: Vec::new(),
                    bootstrap_nodes: Vec::new(),
                },
                BackupSettings {
                    display_name: None,
                    preferred_transports: Vec::new(),
                    enable_tor: true,
                    enable_i2p: false,
                    enable_clearnet: false,
                },
            )
            .unwrap();

        // Wrong passphrase should fail
        let result = manager.restore_backup(&backup, "wrong_passphrase");
        assert!(result.is_err());
    }
}
