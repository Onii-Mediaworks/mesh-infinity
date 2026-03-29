//! Backup Encryption (§3.7.4)
//!
//! Both backup types use the same encryption envelope:
//! ```text
//! EncryptedBackup {
//!     version:         u32,
//!     backup_type:     u8,        // 0 = standard, 1 = extended
//!     argon2id_salt:   [u8; 32],
//!     argon2id_params: { m_cost, t_cost, p_cost },
//!     nonce:           [u8; 12],
//!     ciphertext:      Vec<u8>,   // ChaCha20-Poly1305 of BackupPayload
//! }
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum Argon2id parameters (§3.7.4).
const MIN_M_COST: u32 = 65536; // 64 MB
const MIN_T_COST: u32 = 3;
const MIN_P_COST: u32 = 4;

/// Minimum passphrase length for local backups.
const MIN_PASSPHRASE_LOCAL: usize = 8;
/// Minimum passphrase length for cloud-synced backups (§3.7.4).
const MIN_PASSPHRASE_CLOUD: usize = 16;

/// Current backup format version.
const BACKUP_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("Passphrase too short (need {required}, got {provided})")]
    PassphraseTooShort { required: usize, provided: usize },
    #[error("Argon2id derivation failed: {0}")]
    Argon2(String),
    #[error("Encryption failed")]
    Encrypt,
    #[error("Decryption failed — wrong passphrase or corrupted backup")]
    Decrypt,
    #[error("Invalid backup format")]
    InvalidFormat,
    #[error("Argon2id parameters below minimum")]
    WeakParams,
    #[error("Unknown backup version {0}")]
    UnknownVersion(u32),
    #[error("Serialization: {0}")]
    Serialize(String),
}

// ---------------------------------------------------------------------------
// Backup types
// ---------------------------------------------------------------------------

/// Backup type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BackupType {
    /// Standard: identity + trust graph + contacts. Small (<1 MB).
    Standard = 0,
    /// Extended: everything in standard + message history + contact keys.
    Extended = 1,
}

/// The encrypted backup envelope (serialized to disk / cloud).
#[derive(Serialize, Deserialize)]
pub struct EncryptedBackup {
    pub version: u32,
    pub backup_type: u8,
    pub argon2id_salt: Vec<u8>,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Create backup
// ---------------------------------------------------------------------------

/// Create an encrypted backup from a plaintext payload.
///
/// Enforces minimum passphrase length based on whether the backup
/// is destined for cloud storage.
pub fn create_backup(
    payload: &[u8],
    passphrase: &[u8],
    backup_type: BackupType,
    is_cloud: bool,
) -> Result<EncryptedBackup, BackupError> {
    // Enforce passphrase length (§3.7.4)
    let min_len = if is_cloud {
        MIN_PASSPHRASE_CLOUD
    } else {
        MIN_PASSPHRASE_LOCAL
    };
    if passphrase.len() < min_len {
        return Err(BackupError::PassphraseTooShort {
            required: min_len,
            provided: passphrase.len(),
        });
    }

    // Generate salt
    let mut salt = vec![0u8; 32];
    OsRng.fill_bytes(&mut salt);

    // Derive key via Argon2id
    let key = derive_backup_key(passphrase, &salt, MIN_M_COST, MIN_T_COST, MIN_P_COST)?;

    // Generate nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Encrypt
    let cipher =
        ChaCha20Poly1305::new_from_slice(&*key).map_err(|_| BackupError::Encrypt)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| BackupError::Encrypt)?;

    Ok(EncryptedBackup {
        version: BACKUP_VERSION,
        backup_type: backup_type as u8,
        argon2id_salt: salt,
        m_cost: MIN_M_COST,
        t_cost: MIN_T_COST,
        p_cost: MIN_P_COST,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

// ---------------------------------------------------------------------------
// Restore backup
// ---------------------------------------------------------------------------

/// Decrypt and restore a backup.
pub fn restore_backup(
    backup: &EncryptedBackup,
    passphrase: &[u8],
) -> Result<(Vec<u8>, BackupType), BackupError> {
    // Validate version
    if backup.version > BACKUP_VERSION {
        return Err(BackupError::UnknownVersion(backup.version));
    }

    // Validate parameters
    if backup.m_cost < MIN_M_COST || backup.t_cost < MIN_T_COST || backup.p_cost < MIN_P_COST {
        return Err(BackupError::WeakParams);
    }

    // Derive key
    let key = derive_backup_key(
        passphrase,
        &backup.argon2id_salt,
        backup.m_cost,
        backup.t_cost,
        backup.p_cost,
    )?;

    // Validate nonce length (ChaCha20-Poly1305 requires exactly 12 bytes).
    if backup.nonce.len() != 12 {
        return Err(BackupError::InvalidFormat);
    }

    // Validate salt length (Argon2id requires non-empty salt).
    if backup.argon2id_salt.is_empty() {
        return Err(BackupError::InvalidFormat);
    }

    // Decrypt
    let cipher =
        ChaCha20Poly1305::new_from_slice(&*key).map_err(|_| BackupError::Decrypt)?;
    let nonce = Nonce::from_slice(&backup.nonce);
    let plaintext = cipher
        .decrypt(nonce, backup.ciphertext.as_ref())
        .map_err(|_| BackupError::Decrypt)?;

    let backup_type = match backup.backup_type {
        0 => BackupType::Standard,
        1 => BackupType::Extended,
        _ => return Err(BackupError::InvalidFormat),
    };

    Ok((plaintext, backup_type))
}

/// Check if the backup was created with older/weaker parameters.
/// Returns true if re-encryption with current params is recommended.
pub fn needs_param_upgrade(backup: &EncryptedBackup) -> bool {
    backup.m_cost < MIN_M_COST || backup.t_cost < MIN_T_COST || backup.p_cost < MIN_P_COST
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn derive_backup_key(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| BackupError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|e| BackupError::Argon2(e.to_string()))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_roundtrip() {
        let payload = b"secret backup data with trust graph and contacts";
        let passphrase = b"correct horse battery staple!";

        let backup =
            create_backup(payload, passphrase, BackupType::Standard, false).unwrap();
        let (restored, bt) = restore_backup(&backup, passphrase).unwrap();

        assert_eq!(restored, payload);
        assert_eq!(bt, BackupType::Standard);
    }

    #[test]
    fn test_wrong_passphrase() {
        let backup =
            create_backup(b"data", b"rightpassword!!!", BackupType::Standard, false).unwrap();
        let result = restore_backup(&backup, b"wrongpassword!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_cloud_passphrase_minimum() {
        let result = create_backup(b"data", b"short", BackupType::Standard, true);
        assert!(matches!(result, Err(BackupError::PassphraseTooShort { required: 16, .. })));
    }

    #[test]
    fn test_local_passphrase_minimum() {
        let result = create_backup(b"data", b"1234567", BackupType::Standard, false);
        assert!(matches!(result, Err(BackupError::PassphraseTooShort { required: 8, .. })));

        let result = create_backup(b"data", b"12345678", BackupType::Standard, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extended_backup() {
        let payload = b"extended backup with message history";
        let passphrase = b"long enough passphrase for cloud!";

        let backup =
            create_backup(payload, passphrase, BackupType::Extended, true).unwrap();
        let (_, bt) = restore_backup(&backup, passphrase).unwrap();
        assert_eq!(bt, BackupType::Extended);
    }

    #[test]
    fn test_backup_serialization() {
        let backup =
            create_backup(b"test", b"passphrase!!", BackupType::Standard, false).unwrap();
        let json = serde_json::to_string(&backup).unwrap();
        let recovered: EncryptedBackup = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.version, BACKUP_VERSION);
    }

    #[test]
    fn test_param_upgrade_check() {
        let backup =
            create_backup(b"test", b"passphrase!!", BackupType::Standard, false).unwrap();
        assert!(!needs_param_upgrade(&backup)); // Current params, no upgrade needed

        let weak = EncryptedBackup {
            m_cost: 1024, // Way below minimum
            ..backup
        };
        assert!(needs_param_upgrade(&weak));
    }

    // --- Malformed envelope rejection tests ---

    #[test]
    fn test_malformed_empty_salt_rejected() {
        let backup = create_backup(b"payload", b"passphrase123", BackupType::Standard, false).unwrap();
        let bad = EncryptedBackup { argon2id_salt: vec![], ..backup };
        let result = restore_backup(&bad, b"passphrase123");
        assert!(result.is_err(), "empty salt must be rejected");
    }

    #[test]
    fn test_malformed_wrong_nonce_length_rejected() {
        let backup = create_backup(b"payload", b"passphrase123", BackupType::Standard, false).unwrap();
        let bad = EncryptedBackup { nonce: vec![0u8; 8], ..backup }; // 8 bytes instead of 12
        let result = restore_backup(&bad, b"passphrase123");
        assert!(result.is_err(), "wrong-length nonce must be rejected");
    }

    #[test]
    fn test_malformed_truncated_ciphertext_rejected() {
        let backup = create_backup(b"hello world", b"passphrase123", BackupType::Standard, false).unwrap();
        let truncated = backup.ciphertext[..backup.ciphertext.len() / 2].to_vec();
        let bad = EncryptedBackup { ciphertext: truncated, ..backup };
        let result = restore_backup(&bad, b"passphrase123");
        assert!(result.is_err(), "truncated ciphertext must fail AEAD verification");
    }

    #[test]
    fn test_malformed_tampered_ciphertext_rejected() {
        let backup = create_backup(b"hello world", b"passphrase123", BackupType::Standard, false).unwrap();
        let mut tampered = backup.ciphertext.clone();
        tampered[0] ^= 0xFF;
        let bad = EncryptedBackup { ciphertext: tampered, ..backup };
        let result = restore_backup(&bad, b"passphrase123");
        assert!(result.is_err(), "tampered ciphertext must fail AEAD verification");
    }

    #[test]
    fn test_malformed_unknown_version_rejected() {
        let backup = create_backup(b"payload", b"passphrase123", BackupType::Standard, false).unwrap();
        let bad = EncryptedBackup { version: 99, ..backup };
        let result = restore_backup(&bad, b"passphrase123");
        assert!(
            matches!(result, Err(BackupError::UnknownVersion(99))),
            "unknown version must be rejected with UnknownVersion error"
        );
    }

    #[test]
    fn test_malformed_weak_params_rejected() {
        let backup = create_backup(b"payload", b"passphrase123", BackupType::Standard, false).unwrap();
        let bad = EncryptedBackup { m_cost: 1024, ..backup };
        let result = restore_backup(&bad, b"passphrase123");
        assert!(
            matches!(result, Err(BackupError::WeakParams)),
            "below-minimum Argon2id params must be rejected"
        );
    }

    #[test]
    fn test_malformed_invalid_backup_type_rejected() {
        let backup = create_backup(b"payload", b"passphrase123", BackupType::Standard, false).unwrap();
        let bad = EncryptedBackup { backup_type: 0xFF, ..backup };
        // Must decrypt successfully (AEAD is intact) but fail on backup_type parse.
        // However, since the ciphertext was not re-encrypted, it will fail AEAD.
        // In practice: backup_type is not part of AEAD AAD so it CAN be tampered.
        // restore_backup() should catch it with InvalidFormat.
        // (The AEAD protects the plaintext, not the envelope fields.)
        let result = restore_backup(&bad, b"passphrase123");
        // Either InvalidFormat or Decrypt is acceptable — the point is it rejects.
        assert!(result.is_err(), "invalid backup_type must be rejected");
    }
}
