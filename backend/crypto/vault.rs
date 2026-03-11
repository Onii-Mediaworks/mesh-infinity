// Secure vault for on-disk encryption and key recovery.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params as ArgonParams, Version};
use base64::{engine::general_purpose, Engine as _};
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"NIV1";
const HEADER_VERSION: u8 = 1;
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("invalid header")]
    InvalidHeader,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("cryptographic error")]
    CryptoError,
    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,
    #[error("password required")]
    PasswordRequired,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("argon2 error: {0}")]
    Argon2(String),
    #[error("hkdf error")]
    Hkdf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEnvelope {
    pub version: u8,
    pub created_at: u64,
    pub password_slot: Option<WrappedKeySlot>,
    pub recovery_slot: WrappedKeySlot,
    pub keystore_slot: Option<KeystoreSlot>,
}

impl KeyEnvelope {
    /// Construct a new instance.
    pub fn new(recovery_slot: WrappedKeySlot, password_slot: Option<WrappedKeySlot>) -> Self {
        Self {
            version: HEADER_VERSION,
            created_at: now_epoch_seconds(),
            password_slot,
            recovery_slot,
            keystore_slot: None,
        }
    }

    /// Set keystore slot.
    pub fn set_keystore_slot(&mut self, slot: KeystoreSlot) {
        self.keystore_slot = Some(slot);
    }

    /// Requires password.
    pub fn requires_password(&self) -> bool {
        self.password_slot.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKeySlot {
    pub nonce_b64: String,
    pub salt_b64: String,
    pub ciphertext_b64: String,
    pub kdf: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreSlot {
    pub wrapped_key_b64: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_len: u32,
    pub kdf_type: String,
}

#[derive(Debug, Clone)]
pub struct VaultKey {
    key: Zeroizing<[u8; 32]>,
}

impl VaultKey {
    /// New random.
    pub fn new_random() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self {
            key: Zeroizing::new(key),
        }
    }

    /// From bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(bytes),
        }
    }

    /// As bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub version: u8,
    pub chunk_size: u32,
    pub file_id: [u8; 16],
    pub nonce_base: [u8; 24],
}

pub struct Vault;

impl From<argon2::Error> for VaultError {
    /// From.
    fn from(error: argon2::Error) -> Self {
        VaultError::Argon2(error.to_string())
    }
}

impl Vault {
    /// Generate recovery phrase.
    pub fn generate_recovery_phrase() -> Mnemonic {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        Mnemonic::from_entropy_in(Language::English, &entropy)
            .unwrap_or_else(|_| Mnemonic::from_entropy(&entropy).expect("valid entropy"))
    }

    /// Wrap with password.
    pub fn wrap_with_password(
        key: &VaultKey,
        password: &str,
    ) -> Result<WrappedKeySlot, VaultError> {
        let salt = random_bytes(16);
        let params = KdfParams::argon2_default();
        let derived = derive_password_key(password, &salt, &params)?;
        encrypt_key_slot(&derived, &salt, &params, key)
    }

    /// Unwrap with password.
    pub fn unwrap_with_password(
        slot: &WrappedKeySlot,
        password: &str,
    ) -> Result<VaultKey, VaultError> {
        let salt = decode_b64(&slot.salt_b64)?;
        let params = slot.kdf.clone();
        let derived = derive_password_key(password, &salt, &params)?;
        decrypt_key_slot(&derived, slot)
    }

    /// Wrap with recovery phrase.
    pub fn wrap_with_recovery_phrase(
        key: &VaultKey,
        phrase: &str,
    ) -> Result<WrappedKeySlot, VaultError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| VaultError::InvalidRecoveryPhrase)?;
        Self::wrap_with_mnemonic(key, &mnemonic)
    }

    /// Wrap with mnemonic.
    pub fn wrap_with_mnemonic(
        key: &VaultKey,
        mnemonic: &Mnemonic,
    ) -> Result<WrappedKeySlot, VaultError> {
        let salt = random_bytes(16);
        let params = KdfParams::bip39_default();
        let derived = derive_recovery_key(mnemonic, &salt)?;
        encrypt_key_slot(&derived, &salt, &params, key)
    }

    /// Unwrap with recovery phrase.
    pub fn unwrap_with_recovery_phrase(
        slot: &WrappedKeySlot,
        phrase: &str,
    ) -> Result<VaultKey, VaultError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| VaultError::InvalidRecoveryPhrase)?;
        Self::unwrap_with_mnemonic(slot, &mnemonic)
    }

    /// Unwrap with mnemonic.
    pub fn unwrap_with_mnemonic(
        slot: &WrappedKeySlot,
        mnemonic: &Mnemonic,
    ) -> Result<VaultKey, VaultError> {
        let salt = decode_b64(&slot.salt_b64)?;
        let derived = derive_recovery_key(mnemonic, &salt)?;
        decrypt_key_slot(&derived, slot)
    }

    /// Encrypt bytes.
    pub fn encrypt_bytes(key: &VaultKey, plaintext: &[u8]) -> Result<EncryptedPayload, VaultError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let nonce = random_xnonce();
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| VaultError::CryptoError)?;

        Ok(EncryptedPayload {
            nonce_b64: general_purpose::STANDARD.encode(nonce.as_slice()),
            ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
        })
    }

    /// Decrypt bytes.
    pub fn decrypt_bytes(
        key: &VaultKey,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, VaultError> {
        let nonce = decode_b64(&payload.nonce_b64)?;
        let ciphertext = decode_b64(&payload.ciphertext_b64)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        cipher
            .decrypt(XNonce::from_slice(&nonce), ciphertext.as_slice())
            .map_err(|_| VaultError::InvalidCiphertext)
    }

    pub fn encrypt_file<P: AsRef<Path>>(
        key: &VaultKey,
        input: P,
        output: P,
    ) -> Result<FileHeader, VaultError> {
        let mut input = File::open(input)?;
        let mut output = File::create(output)?;
        let header = FileHeader::new(DEFAULT_CHUNK_SIZE as u32);
        write_header(&mut output, &header)?;

        let file_key = derive_file_key(key, &header.file_id)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&file_key));

        let mut buffer = vec![0u8; header.chunk_size as usize];
        let mut index: u64 = 0;

        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let nonce = chunk_nonce(&header.nonce_base, index);
            let ciphertext = cipher
                .encrypt(XNonce::from_slice(&nonce), &buffer[..read])
                .map_err(|_| VaultError::CryptoError)?;
            output.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
            output.write_all(&ciphertext)?;
            index = index.saturating_add(1);
        }

        Ok(header)
    }

    pub fn decrypt_file<P: AsRef<Path>>(
        key: &VaultKey,
        input: P,
        output: P,
    ) -> Result<(), VaultError> {
        let mut input = File::open(input)?;
        let mut output = File::create(output)?;
        let header = read_header(&mut input)?;
        let file_key = derive_file_key(key, &header.file_id)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&file_key));

        let mut index: u64 = 0;
        loop {
            let mut length_bytes = [0u8; 4];
            if input.read_exact(&mut length_bytes).is_err() {
                break;
            }
            let length = u32::from_le_bytes(length_bytes) as usize;
            if length == 0 {
                return Err(VaultError::InvalidHeader);
            }
            let mut ciphertext = vec![0u8; length];
            input.read_exact(&mut ciphertext)?;
            let nonce = chunk_nonce(&header.nonce_base, index);
            let plaintext = cipher
                .decrypt(XNonce::from_slice(&nonce), ciphertext.as_slice())
                .map_err(|_| VaultError::InvalidCiphertext)?;
            output.write_all(&plaintext)?;
            index = index.saturating_add(1);
        }

        Ok(())
    }
}

impl FileHeader {
    /// Construct a new instance.
    pub fn new(chunk_size: u32) -> Self {
        let mut file_id = [0u8; 16];
        OsRng.fill_bytes(&mut file_id);
        let mut nonce_base = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_base);
        Self {
            version: HEADER_VERSION,
            chunk_size,
            file_id,
            nonce_base,
        }
    }
}

impl KdfParams {
    /// Argon2 default.
    pub fn argon2_default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
            output_len: 32,
            kdf_type: "argon2id".to_string(),
        }
    }

    /// Bip39 default.
    pub fn bip39_default() -> Self {
        Self {
            memory_kib: 0,
            iterations: 0,
            parallelism: 0,
            output_len: 32,
            kdf_type: "bip39".to_string(),
        }
    }
}

/// Derive password key.
fn derive_password_key(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<[u8; 32], VaultError> {
    let argon_params = ArgonParams::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_len as usize),
    )?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut output = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut output)?;
    Ok(output)
}

/// Derive recovery key.
fn derive_recovery_key(mnemonic: &Mnemonic, salt: &[u8]) -> Result<[u8; 32], VaultError> {
    let seed = mnemonic.to_seed("");
    let hkdf = Hkdf::<Sha512>::new(Some(salt), seed.as_slice());
    let mut output = [0u8; 32];
    hkdf.expand(b"mesh-infinity recovery key", &mut output)
        .map_err(|_| VaultError::Hkdf)?;
    Ok(output)
}

/// Encrypt key slot.
fn encrypt_key_slot(
    derived_key: &[u8; 32],
    salt: &[u8],
    params: &KdfParams,
    key: &VaultKey,
) -> Result<WrappedKeySlot, VaultError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(derived_key));
    let nonce = random_xnonce();
    let ciphertext = cipher
        .encrypt(&nonce, key.as_bytes().as_slice())
        .map_err(|_| VaultError::CryptoError)?;

    Ok(WrappedKeySlot {
        nonce_b64: general_purpose::STANDARD.encode(nonce.as_slice()),
        salt_b64: general_purpose::STANDARD.encode(salt),
        ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
        kdf: params.clone(),
    })
}

/// Decrypt key slot.
fn decrypt_key_slot(derived_key: &[u8; 32], slot: &WrappedKeySlot) -> Result<VaultKey, VaultError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(derived_key));
    let nonce = decode_b64(&slot.nonce_b64)?;
    let ciphertext = decode_b64(&slot.ciphertext_b64)?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| VaultError::InvalidCiphertext)?;
    if plaintext.len() != 32 {
        return Err(VaultError::InvalidCiphertext);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plaintext);
    Ok(VaultKey::from_bytes(key_bytes))
}

/// Derive file key.
fn derive_file_key(key: &VaultKey, file_id: &[u8; 16]) -> Result<[u8; 32], VaultError> {
    let hkdf = Hkdf::<Sha512>::new(Some(file_id), key.as_bytes());
    let mut output = [0u8; 32];
    hkdf.expand(b"mesh-infinity file key", &mut output)
        .map_err(|_| VaultError::Hkdf)?;
    Ok(output)
}

fn write_header<W: Write>(writer: &mut W, header: &FileHeader) -> Result<(), VaultError> {
    writer.write_all(MAGIC)?;
    writer.write_all(&[header.version])?;
    writer.write_all(&header.chunk_size.to_le_bytes())?;
    writer.write_all(&header.file_id)?;
    writer.write_all(&header.nonce_base)?;
    Ok(())
}

fn read_header<R: Read>(reader: &mut R) -> Result<FileHeader, VaultError> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(VaultError::InvalidHeader);
    }

    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != HEADER_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }

    let mut chunk_bytes = [0u8; 4];
    reader.read_exact(&mut chunk_bytes)?;
    let chunk_size = u32::from_le_bytes(chunk_bytes);

    let mut file_id = [0u8; 16];
    reader.read_exact(&mut file_id)?;

    let mut nonce_base = [0u8; 24];
    reader.read_exact(&mut nonce_base)?;

    Ok(FileHeader {
        version: version[0],
        chunk_size,
        file_id,
        nonce_base,
    })
}

/// Chunk nonce.
fn chunk_nonce(base: &[u8; 24], index: u64) -> [u8; 24] {
    let mut nonce = *base;
    nonce[16..24].copy_from_slice(&index.to_le_bytes());
    nonce
}

/// Random xnonce.
fn random_xnonce() -> XNonce {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    *XNonce::from_slice(&bytes)
}

/// Random bytes.
fn random_bytes(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    OsRng.fill_bytes(&mut data);
    data
}

/// Decode b64.
fn decode_b64(value: &str) -> Result<Vec<u8>, VaultError> {
    Ok(general_purpose::STANDARD.decode(value)?)
}

/// Now epoch seconds.
fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
