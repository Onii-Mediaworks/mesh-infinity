//! Four-Layer Message Encryption (§7.2)
//!
//! All discrete messages use a multi-layer signing and encryption scheme:
//!
//! ```text
//! Step 1 — Inner authentication:
//!   mac = HMAC-SHA256(ratchet_msg_key, plaintext)   // deniable
//!   authenticated = plaintext || mac
//!
//! Step 2 — Trust-channel encryption (trusted peers only):
//!   trust_encrypted = ChaCha20Poly1305(session_key, nonce, authenticated)
//!   payload = dr_header || trust_encrypted
//!
//! Step 3 — Outer signing (relationship-specific mask key):
//!   outer_sig = Ed25519_Sign(rel_mask_key, payload)
//!   double_signed = payload || outer_sig
//!
//! Step 4 — Recipient encryption:
//!   ephemeral DH → derive message_key + nonce (with context_type domain separation)
//!   final = ephemeral_public || ChaCha20Poly1305(message_key, nonce, double_signed)
//! ```

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MSG_KEY_INFO_PREFIX: &[u8] = b"meshinfinity-message-v1";
const NONCE_INFO_PREFIX: &[u8] = b"meshinfinity-nonce-v1-";

/// HMAC-SHA256 output size (32 bytes).
const MAC_SIZE: usize = 32;

/// Ed25519 signature size (64 bytes).
const SIG_SIZE: usize = 64;

/// X25519 public key size (32 bytes).
const EPH_PUB_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum MessageCryptoError {
    #[error("HMAC verification failed — content tampered")]
    HmacMismatch,
    #[error("Ed25519 signature verification failed")]
    SignatureInvalid,
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("AEAD decryption failed")]
    DecryptFailed,
    #[error("HKDF expansion failed")]
    HkdfExpand,
    #[error("Message too short to contain required fields")]
    MessageTooShort,
    #[error("Ed25519 key error: {0}")]
    KeyError(String),
}

// ---------------------------------------------------------------------------
// Context types for nonce domain separation (§7.2)
// ---------------------------------------------------------------------------

/// Message context for nonce domain separation.
/// Different contexts produce different nonces even with the same ephemeral key.
#[derive(Clone, Copy, Debug)]
pub enum MessageContext {
    Direct,
    Group,
    File,
    Stream,
    Offline,
    System,
}

impl MessageContext {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Direct => b"direct",
            Self::Group => b"group",
            Self::File => b"file",
            Self::Stream => b"stream",
            Self::Offline => b"offline",
            Self::System => b"system",
        }
    }
}

// ---------------------------------------------------------------------------
// Step 1 — Inner authentication (deniable HMAC)
// ---------------------------------------------------------------------------

/// Step 1: Authenticate plaintext with HMAC-SHA256 using the ratchet message key.
/// Both parties can produce this MAC — provides deniability (§3.5.1).
pub fn step1_authenticate(plaintext: &[u8], msg_key: &[u8; 32]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(msg_key)
        .expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(plaintext);
    let tag = mac.finalize().into_bytes();

    let mut authenticated = Vec::with_capacity(plaintext.len() + MAC_SIZE);
    authenticated.extend_from_slice(plaintext);
    authenticated.extend_from_slice(&tag);
    authenticated
}

/// Step 1 verify: Check HMAC on received authenticated payload.
pub fn step1_verify(authenticated: &[u8], msg_key: &[u8; 32]) -> Result<Vec<u8>, MessageCryptoError> {
    if authenticated.len() < MAC_SIZE {
        return Err(MessageCryptoError::MessageTooShort);
    }
    let (plaintext, mac_bytes) = authenticated.split_at(authenticated.len() - MAC_SIZE);

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(msg_key)
        .expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(plaintext);
    mac.verify_slice(mac_bytes)
        .map_err(|_| MessageCryptoError::HmacMismatch)?;

    Ok(plaintext.to_vec())
}

// ---------------------------------------------------------------------------
// Step 2 — Trust-channel encryption (Double Ratchet session key)
// ---------------------------------------------------------------------------

/// Step 2: Encrypt authenticated payload with the session's cipher key + nonce.
/// These come from the Double Ratchet's message key expansion (§7.0.3).
pub fn step2_encrypt(
    authenticated: &[u8],
    cipher_key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, MessageCryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(cipher_key)
        .map_err(|_| MessageCryptoError::EncryptFailed)?;
    let n = Nonce::from_slice(nonce);
    cipher
        .encrypt(n, authenticated)
        .map_err(|_| MessageCryptoError::EncryptFailed)
}

/// Step 2 decrypt.
pub fn step2_decrypt(
    ciphertext: &[u8],
    cipher_key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, MessageCryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(cipher_key)
        .map_err(|_| MessageCryptoError::DecryptFailed)?;
    let n = Nonce::from_slice(nonce);
    cipher
        .decrypt(n, ciphertext)
        .map_err(|_| MessageCryptoError::DecryptFailed)
}

// ---------------------------------------------------------------------------
// Step 3 — Outer signing (relationship-specific mask key)
// ---------------------------------------------------------------------------

/// Step 3: Sign payload with the sender's relationship-specific mask key.
/// This signature is inside Step 4 encryption — only the recipient sees it.
pub fn step3_sign(payload: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let sig = signing_key.sign(payload);
    let mut signed = Vec::with_capacity(payload.len() + SIG_SIZE);
    signed.extend_from_slice(payload);
    signed.extend_from_slice(&sig.to_bytes());
    signed
}

/// Step 3 verify: Check Ed25519 signature.
pub fn step3_verify(
    signed: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<Vec<u8>, MessageCryptoError> {
    if signed.len() < SIG_SIZE {
        return Err(MessageCryptoError::MessageTooShort);
    }
    let (payload, sig_bytes) = signed.split_at(signed.len() - SIG_SIZE);

    let sig = Signature::from_slice(sig_bytes)
        .map_err(|e| MessageCryptoError::KeyError(e.to_string()))?;
    verifying_key
        .verify(payload, &sig)
        .map_err(|_| MessageCryptoError::SignatureInvalid)?;

    Ok(payload.to_vec())
}

// ---------------------------------------------------------------------------
// Step 4 — Recipient encryption (ephemeral DH)
// ---------------------------------------------------------------------------

/// Step 4: Encrypt the double-signed payload for the recipient.
/// Uses a fresh ephemeral X25519 keypair and derives key + nonce from DH.
pub fn step4_encrypt(
    double_signed: &[u8],
    recipient_x25519_pub: &X25519Public,
    context: MessageContext,
) -> Result<Vec<u8>, MessageCryptoError> {
    // Generate fresh ephemeral keypair
    let eph_secret = X25519Secret::random_from_rng(rand_core::OsRng);
    let eph_pub = X25519Public::from(&eph_secret);

    // DH shared secret
    let shared = eph_secret.diffie_hellman(recipient_x25519_pub);

    // Derive message key + nonce with context type domain separation
    let (msg_key, nonce) = derive_step4_keys(shared.as_bytes(), eph_pub.as_bytes(), context)?;

    // Encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&msg_key)
        .map_err(|_| MessageCryptoError::EncryptFailed)?;
    let n = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(n, double_signed)
        .map_err(|_| MessageCryptoError::EncryptFailed)?;

    // Output: ephemeral_public || ciphertext
    let mut output = Vec::with_capacity(EPH_PUB_SIZE + ciphertext.len());
    output.extend_from_slice(eph_pub.as_bytes());
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Step 4 decrypt: Recipient decrypts using their X25519 secret key.
pub fn step4_decrypt(
    encrypted: &[u8],
    recipient_x25519_secret: &X25519Secret,
    context: MessageContext,
) -> Result<Vec<u8>, MessageCryptoError> {
    if encrypted.len() < EPH_PUB_SIZE + 16 {
        // Need at least ephemeral pub + AEAD tag
        return Err(MessageCryptoError::MessageTooShort);
    }

    let (eph_pub_bytes, ciphertext) = encrypted.split_at(EPH_PUB_SIZE);
    let mut eph_arr = [0u8; 32];
    eph_arr.copy_from_slice(eph_pub_bytes);
    let eph_pub = X25519Public::from(eph_arr);

    // DH shared secret
    let shared = recipient_x25519_secret.diffie_hellman(&eph_pub);

    // Derive key + nonce
    let (msg_key, nonce) = derive_step4_keys(shared.as_bytes(), &eph_arr, context)?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&msg_key)
        .map_err(|_| MessageCryptoError::DecryptFailed)?;
    let n = Nonce::from_slice(&nonce);
    cipher
        .decrypt(n, ciphertext)
        .map_err(|_| MessageCryptoError::DecryptFailed)
}

/// Derive Step 4 message key and nonce from DH shared secret.
fn derive_step4_keys(
    shared: &[u8],
    eph_pub: &[u8],
    context: MessageContext,
) -> Result<([u8; 32], [u8; 12]), MessageCryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(eph_pub), shared);

    // Message key
    let mut msg_key = Zeroizing::new([0u8; 32]);
    hk.expand(MSG_KEY_INFO_PREFIX, &mut *msg_key)
        .map_err(|_| MessageCryptoError::HkdfExpand)?;

    // Nonce with context type domain separation
    let mut nonce_info = Vec::with_capacity(NONCE_INFO_PREFIX.len() + context.as_bytes().len());
    nonce_info.extend_from_slice(NONCE_INFO_PREFIX);
    nonce_info.extend_from_slice(context.as_bytes());

    let mut nonce = [0u8; 12];
    hk.expand(&nonce_info, &mut nonce)
        .map_err(|_| MessageCryptoError::HkdfExpand)?;

    Ok((*msg_key, nonce))
}

// ---------------------------------------------------------------------------
// Full pipeline: encrypt + decrypt
// ---------------------------------------------------------------------------

/// Encrypt a message through all four layers.
///
/// This is the main entry point for sending a message.
pub fn encrypt_message(
    plaintext: &[u8],
    ratchet_msg_key: &[u8; 32],
    session_cipher_key: &[u8; 32],
    session_nonce: &[u8; 12],
    sender_mask_key: &SigningKey,
    recipient_x25519_pub: &X25519Public,
    context: MessageContext,
) -> Result<Vec<u8>, MessageCryptoError> {
    // Step 1: Inner authentication (deniable HMAC)
    let authenticated = step1_authenticate(plaintext, ratchet_msg_key);

    // Step 2: Trust-channel encryption
    let trust_encrypted = step2_encrypt(&authenticated, session_cipher_key, session_nonce)?;

    // Step 3: Outer signing (relationship-specific mask key)
    let double_signed = step3_sign(&trust_encrypted, sender_mask_key);

    // Step 4: Recipient encryption (ephemeral DH)
    step4_encrypt(&double_signed, recipient_x25519_pub, context)
}

/// Decrypt a message through all four layers (reverse order: 4 → 3 → 2 → 1).
pub fn decrypt_message(
    encrypted: &[u8],
    recipient_x25519_secret: &X25519Secret,
    sender_verifying_key: &VerifyingKey,
    session_cipher_key: &[u8; 32],
    session_nonce: &[u8; 12],
    ratchet_msg_key: &[u8; 32],
    context: MessageContext,
) -> Result<Vec<u8>, MessageCryptoError> {
    // Step 4: Recipient decryption
    let double_signed = step4_decrypt(encrypted, recipient_x25519_secret, context)?;

    // Step 3: Verify sender signature
    let trust_encrypted = step3_verify(&double_signed, sender_verifying_key)?;

    // Step 2: Trust-channel decryption
    let authenticated = step2_decrypt(&trust_encrypted, session_cipher_key, session_nonce)?;

    // Step 1: Verify HMAC
    step1_verify(&authenticated, ratchet_msg_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn test_keys() -> (SigningKey, VerifyingKey, X25519Secret, X25519Public) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let x_secret = X25519Secret::random_from_rng(OsRng);
        let x_public = X25519Public::from(&x_secret);
        (signing, verifying, x_secret, x_public)
    }

    #[test]
    fn test_step1_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello world";
        let authed = step1_authenticate(plaintext, &key);
        let recovered = step1_verify(&authed, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_step1_tamper_detected() {
        let key = [0x42u8; 32];
        let mut authed = step1_authenticate(b"Hello", &key);
        authed[0] ^= 0xFF;
        assert!(step1_verify(&authed, &key).is_err());
    }

    #[test]
    fn test_step2_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret data";
        let ct = step2_encrypt(plaintext, &key, &nonce).unwrap();
        let pt = step2_decrypt(&ct, &key, &nonce).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_step3_roundtrip() {
        let (signing, verifying, _, _) = test_keys();
        let payload = b"payload to sign";
        let signed = step3_sign(payload, &signing);
        let recovered = step3_verify(&signed, &verifying).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_step3_wrong_key_fails() {
        let (signing, _, _, _) = test_keys();
        let (_, wrong_verifying, _, _) = test_keys();
        let signed = step3_sign(b"payload", &signing);
        assert!(step3_verify(&signed, &wrong_verifying).is_err());
    }

    #[test]
    fn test_step4_roundtrip() {
        let (_, _, x_secret, x_public) = test_keys();
        let payload = b"encrypted payload";
        let encrypted = step4_encrypt(payload, &x_public, MessageContext::Direct).unwrap();
        let decrypted = step4_decrypt(&encrypted, &x_secret, MessageContext::Direct).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_step4_wrong_context_fails() {
        let (_, _, x_secret, x_public) = test_keys();
        let encrypted = step4_encrypt(b"data", &x_public, MessageContext::Direct).unwrap();
        // Wrong context → different nonce → decryption fails
        assert!(step4_decrypt(&encrypted, &x_secret, MessageContext::Group).is_err());
    }

    #[test]
    fn test_full_pipeline_roundtrip() {
        let (sender_sign, sender_verify, _, _) = test_keys();
        let (_, _, recip_secret, recip_public) = test_keys();

        let ratchet_key = [0x42u8; 32];
        let session_key = [0x99u8; 32];
        let session_nonce = [0x01u8; 12];
        let plaintext = b"Full pipeline test message!";

        let encrypted = encrypt_message(
            plaintext,
            &ratchet_key,
            &session_key,
            &session_nonce,
            &sender_sign,
            &recip_public,
            MessageContext::Direct,
        )
        .unwrap();

        let decrypted = decrypt_message(
            &encrypted,
            &recip_secret,
            &sender_verify,
            &session_key,
            &session_nonce,
            &ratchet_key,
            MessageContext::Direct,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_full_pipeline_wrong_recipient_fails() {
        let (sender_sign, _, _, _) = test_keys();
        let (_, _, _, recip_public) = test_keys();
        let (_, _, wrong_secret, _) = test_keys();

        let encrypted = encrypt_message(
            b"secret",
            &[0x42u8; 32],
            &[0x99u8; 32],
            &[0x01u8; 12],
            &sender_sign,
            &recip_public,
            MessageContext::Direct,
        )
        .unwrap();

        // Wrong recipient key → Step 4 fails
        assert!(decrypt_message(
            &encrypted,
            &wrong_secret,
            &sender_sign.verifying_key(),
            &[0x99u8; 32],
            &[0x01u8; 12],
            &[0x42u8; 32],
            MessageContext::Direct,
        )
        .is_err());
    }

    #[test]
    fn test_different_contexts_produce_different_ciphertext() {
        let (sender_sign, _, _, _) = test_keys();
        let (_, _, _, recip_public) = test_keys();

        let msg = b"same message";
        let rk = [0x42u8; 32];
        let sk = [0x99u8; 32];
        let sn = [0x01u8; 12];

        let ct1 = encrypt_message(msg, &rk, &sk, &sn, &sender_sign, &recip_public, MessageContext::Direct).unwrap();
        let ct2 = encrypt_message(msg, &rk, &sk, &sn, &sender_sign, &recip_public, MessageContext::Group).unwrap();

        // Different contexts → different ephemeral keys → different ciphertext
        assert_ne!(ct1, ct2);
    }
}
