// Message Crypto - Multi-layer signing and encryption scheme
//
// Messages are processed through 4 steps:
// 1. Sign with sender's private key
// 2. If trusted, encrypt with trust-pair symmetric key
// 3. Re-sign the encrypted content
// 4. Encrypt with recipient's global public key
//
// This ensures:
// - Authenticity at every step
// - Sender privacy (identity hidden in final encryption)
// - Trust verification for trusted channels
// - Forward secrecy via ephemeral keys

use std::collections::HashMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::core::core::PeerId;
use crate::core::error::{MeshInfinityError, Result};

/// Size constants
const SIGNATURE_SIZE: usize = 64;
const NONCE_SIZE: usize = 12;
const X25519_PUBLIC_KEY_SIZE: usize = 32;
const TAG_SIZE: usize = 16;

/// Message crypto handler for the multi-layer encryption scheme
pub struct MessageCrypto {
    /// Our Ed25519 signing key
    signing_keypair: SigningKey,

    /// Our X25519 static key for Diffie-Hellman
    static_dh_key: StaticSecret,

    /// Our X25519 public key
    static_dh_public: X25519PublicKey,

    /// Pre-derived trust-pair symmetric keys
    /// Key: peer_id, Value: 32-byte symmetric key
    trust_keys: HashMap<PeerId, Zeroizing<[u8; 32]>>,

    /// Nonce counter for replay protection
    nonce_counter: u64,
}

impl MessageCrypto {
    /// Create a new MessageCrypto instance from existing keys
    pub fn new(signing_keypair: SigningKey, dh_secret: [u8; 32]) -> Self {
        let static_dh_key = StaticSecret::from(dh_secret);
        let static_dh_public = X25519PublicKey::from(&static_dh_key);

        Self {
            signing_keypair,
            static_dh_key,
            static_dh_public,
            trust_keys: HashMap::new(),
            nonce_counter: 0,
        }
    }

    /// Generate a new MessageCrypto with random keys
    pub fn generate() -> Result<Self> {
        let signing_keypair = SigningKey::generate(&mut OsRng);

        let mut dh_secret_bytes = [0u8; 32];
        getrandom::fill(&mut dh_secret_bytes).map_err(|_| {
            MeshInfinityError::CryptoError("Failed to generate random bytes".into())
        })?;

        Ok(Self::new(signing_keypair, dh_secret_bytes))
    }

    /// Get our public signing key
    pub fn public_signing_key(&self) -> [u8; 32] {
        self.signing_keypair.verifying_key().to_bytes()
    }

    /// Get our public DH key
    pub fn public_dh_key(&self) -> [u8; 32] {
        self.static_dh_public.to_bytes()
    }

    /// Register a trust relationship with a peer
    /// Derives a symmetric key from our static DH key and their public key
    pub fn register_trust(&mut self, peer_id: PeerId, their_public_dh: &[u8; 32]) {
        let their_public = X25519PublicKey::from(*their_public_dh);
        let shared_secret = self.static_dh_key.diffie_hellman(&their_public);

        // Derive trust key using HKDF
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut trust_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"meshinfinity-trust-key-v1", trust_key.as_mut())
            .expect("HKDF expand failed");

        self.trust_keys.insert(peer_id, trust_key);
    }

    /// Remove a trust relationship
    pub fn remove_trust(&mut self, peer_id: &PeerId) {
        self.trust_keys.remove(peer_id);
    }

    /// Check if a peer is trusted
    pub fn is_trusted(&self, peer_id: &PeerId) -> bool {
        self.trust_keys.contains_key(peer_id)
    }

    /// Encrypt a message using the full 4-step scheme
    ///
    /// # Arguments
    /// * `message` - The plaintext message
    /// * `recipient_public_dh` - Recipient's X25519 public key
    /// * `recipient_peer_id` - Recipient's peer ID (for trust lookup)
    ///
    /// # Returns
    /// The encrypted message blob
    pub fn encrypt_message(
        &mut self,
        message: &[u8],
        recipient_public_dh: &[u8; 32],
        recipient_peer_id: &PeerId,
    ) -> Result<Vec<u8>> {
        // Step 1: Sign with our private key
        let inner_signature = self.signing_keypair.sign(message);
        let mut signed_message = message.to_vec();
        signed_message.extend_from_slice(&inner_signature.to_bytes());

        // Step 2: Trust-pair encryption (if trusted)
        let trust_key_opt = self.trust_keys.get(recipient_peer_id).map(|k| **k);
        let trust_encrypted = if let Some(trust_key) = trust_key_opt {
            self.aead_encrypt(&trust_key, &signed_message)?
        } else {
            // Not trusted: skip trust encryption, just pass through
            signed_message
        };

        // Step 3: Re-sign the encrypted content
        let outer_signature = self.signing_keypair.sign(&trust_encrypted);
        let mut double_signed = trust_encrypted;
        double_signed.extend_from_slice(&outer_signature.to_bytes());

        // Step 4: Encrypt with recipient's public key (ephemeral ECDH)
        let ephemeral_secret = EphemeralSecret::random_from(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        let recipient_public = X25519PublicKey::from(*recipient_public_dh);
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

        // Derive encryption key from shared secret
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut final_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"meshinfinity-message-key-v1", final_key.as_mut())
            .expect("HKDF expand failed");

        let final_ciphertext = self.aead_encrypt(&final_key, &double_signed)?;

        // Package: ephemeral_public || final_ciphertext
        let mut result = Vec::with_capacity(X25519_PUBLIC_KEY_SIZE + final_ciphertext.len());
        result.extend_from_slice(ephemeral_public.as_bytes());
        result.extend(final_ciphertext);

        Ok(result)
    }

    /// Decrypt a message using the full 4-step scheme (in reverse)
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted message blob
    /// * `sender_public_signing` - Sender's Ed25519 public key (for signature verification)
    /// * `sender_peer_id` - Sender's peer ID (for trust lookup)
    ///
    /// # Returns
    /// The decrypted plaintext message
    pub fn decrypt_message(
        &self,
        ciphertext: &[u8],
        sender_public_signing: &[u8; 32],
        sender_peer_id: &PeerId,
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < X25519_PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE {
            return Err(MeshInfinityError::CryptoError("Message too short".into()));
        }

        // Step 4 (reverse): Decrypt with our static DH key
        let mut ephemeral_public_bytes = [0u8; 32];
        ephemeral_public_bytes.copy_from_slice(&ciphertext[..X25519_PUBLIC_KEY_SIZE]);
        let ephemeral_public = X25519PublicKey::from(ephemeral_public_bytes);

        let shared_secret = self.static_dh_key.diffie_hellman(&ephemeral_public);

        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut final_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"meshinfinity-message-key-v1", final_key.as_mut())
            .expect("HKDF expand failed");

        let double_signed = self.aead_decrypt(&final_key, &ciphertext[X25519_PUBLIC_KEY_SIZE..])?;

        // Step 3 (reverse): Verify outer signature
        if double_signed.len() < SIGNATURE_SIZE {
            return Err(MeshInfinityError::CryptoError(
                "Missing outer signature".into(),
            ));
        }

        let outer_sig_start = double_signed.len() - SIGNATURE_SIZE;
        let trust_encrypted = &double_signed[..outer_sig_start];
        let outer_signature_bytes = &double_signed[outer_sig_start..];

        let sender_public = VerifyingKey::from_bytes(sender_public_signing)
            .map_err(|_| MeshInfinityError::CryptoError("Invalid sender public key".into()))?;

        let mut outer_sig_array = [0u8; SIGNATURE_LENGTH];
        outer_sig_array.copy_from_slice(outer_signature_bytes);
        let outer_signature = Signature::from_bytes(&outer_sig_array);

        sender_public
            .verify(trust_encrypted, &outer_signature)
            .map_err(|_| {
                MeshInfinityError::CryptoError("Outer signature verification failed".into())
            })?;

        // Step 2 (reverse): Trust-pair decryption (if trusted)
        let signed_message = if let Some(trust_key) = self.trust_keys.get(sender_peer_id) {
            self.aead_decrypt(trust_key, trust_encrypted)?
        } else {
            trust_encrypted.to_vec()
        };

        // Step 1 (reverse): Verify inner signature
        if signed_message.len() < SIGNATURE_SIZE {
            return Err(MeshInfinityError::CryptoError(
                "Missing inner signature".into(),
            ));
        }

        let inner_sig_start = signed_message.len() - SIGNATURE_SIZE;
        let message = &signed_message[..inner_sig_start];
        let inner_signature_bytes = &signed_message[inner_sig_start..];

        let mut inner_sig_array = [0u8; SIGNATURE_LENGTH];
        inner_sig_array.copy_from_slice(inner_signature_bytes);
        let inner_signature = Signature::from_bytes(&inner_sig_array);

        sender_public
            .verify(message, &inner_signature)
            .map_err(|_| {
                MeshInfinityError::CryptoError("Inner signature verification failed".into())
            })?;

        Ok(message.to_vec())
    }

    /// Derive a session key from a handshake for efficient ongoing encryption
    pub fn derive_session_key(
        &self,
        shared_secret: &[u8],
        session_id: &[u8],
    ) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(Some(session_id), shared_secret);
        let mut session_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"meshinfinity-session-key-v1", session_key.as_mut())
            .expect("HKDF expand failed");
        session_key
    }

    /// Encrypt data with a session key (for ongoing connections after handshake)
    pub fn session_encrypt(&mut self, session_key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        self.aead_encrypt(session_key, data)
    }

    /// Decrypt data with a session key
    pub fn session_decrypt(&self, session_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.aead_decrypt(session_key, ciphertext)
    }

    /// Internal AEAD encryption using ChaCha20-Poly1305
    fn aead_encrypt(&mut self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

        // Generate nonce from counter + random
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        getrandom::fill(&mut nonce_bytes[8..])
            .map_err(|_| MeshInfinityError::CryptoError("Failed to generate nonce".into()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| MeshInfinityError::CryptoError("Encryption failed".into()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Internal AEAD decryption
    fn aead_decrypt(&self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(MeshInfinityError::CryptoError(
                "Ciphertext too short".into(),
            ));
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

        let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let actual_ciphertext = &ciphertext[NONCE_SIZE..];

        cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|_| MeshInfinityError::CryptoError("Decryption failed".into()))
    }
}

/// Encrypted message header for routing
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// Ephemeral public key for decryption
    pub ephemeral_public: [u8; 32],
    /// Message size (encrypted)
    pub encrypted_size: usize,
}

impl MessageHeader {
    /// Parse header from encrypted message
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < X25519_PUBLIC_KEY_SIZE {
            return Err(MeshInfinityError::CryptoError(
                "Message too short for header".into(),
            ));
        }

        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[..X25519_PUBLIC_KEY_SIZE]);

        Ok(Self {
            ephemeral_public,
            encrypted_size: data.len() - X25519_PUBLIC_KEY_SIZE,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Make peer id.
    fn make_peer_id(seed: u8) -> PeerId {
        let mut id = [0u8; 32];
        id[0] = seed;
        id
    }

    /// Test case: encrypt decrypt untrusted.
    #[test]
    fn test_encrypt_decrypt_untrusted() {
        let mut sender = MessageCrypto::generate().unwrap();
        let recipient = MessageCrypto::generate().unwrap();

        let message = b"Hello, untrusted world!";
        let recipient_peer_id = make_peer_id(2);

        let ciphertext = sender
            .encrypt_message(message, &recipient.public_dh_key(), &recipient_peer_id)
            .unwrap();

        let sender_peer_id = make_peer_id(1);
        let plaintext = recipient
            .decrypt_message(&ciphertext, &sender.public_signing_key(), &sender_peer_id)
            .unwrap();

        assert_eq!(plaintext, message);
    }

    /// Test case: encrypt decrypt trusted.
    #[test]
    fn test_encrypt_decrypt_trusted() {
        let mut sender = MessageCrypto::generate().unwrap();
        let mut recipient = MessageCrypto::generate().unwrap();

        let sender_peer_id = make_peer_id(1);
        let recipient_peer_id = make_peer_id(2);

        // Establish trust relationship
        sender.register_trust(recipient_peer_id, &recipient.public_dh_key());
        recipient.register_trust(sender_peer_id, &sender.public_dh_key());

        let message = b"Hello, trusted friend!";

        let ciphertext = sender
            .encrypt_message(message, &recipient.public_dh_key(), &recipient_peer_id)
            .unwrap();

        let plaintext = recipient
            .decrypt_message(&ciphertext, &sender.public_signing_key(), &sender_peer_id)
            .unwrap();

        assert_eq!(plaintext, message);
    }

    /// Test case: session encryption.
    #[test]
    fn test_session_encryption() {
        let mut crypto = MessageCrypto::generate().unwrap();

        let shared_secret = [0x42u8; 32];
        let session_id = b"test-session";

        let session_key = crypto.derive_session_key(&shared_secret, session_id);

        let data = b"Session data to encrypt";
        let ciphertext = crypto.session_encrypt(&session_key, data).unwrap();
        let plaintext = crypto.session_decrypt(&session_key, &ciphertext).unwrap();

        assert_eq!(plaintext, data);
    }

    /// Test case: wrong key fails.
    #[test]
    fn test_wrong_key_fails() {
        let mut sender = MessageCrypto::generate().unwrap();
        let recipient = MessageCrypto::generate().unwrap();
        let wrong_recipient = MessageCrypto::generate().unwrap();

        let message = b"Secret message";
        let recipient_peer_id = make_peer_id(2);

        let ciphertext = sender
            .encrypt_message(message, &recipient.public_dh_key(), &recipient_peer_id)
            .unwrap();

        // Try to decrypt with wrong key
        let sender_peer_id = make_peer_id(1);
        let result = wrong_recipient.decrypt_message(
            &ciphertext,
            &sender.public_signing_key(),
            &sender_peer_id,
        );

        assert!(result.is_err());
    }

    /// Test case: tampered message fails.
    #[test]
    fn test_tampered_message_fails() {
        let mut sender = MessageCrypto::generate().unwrap();
        let recipient = MessageCrypto::generate().unwrap();

        let message = b"Original message";
        let recipient_peer_id = make_peer_id(2);

        let mut ciphertext = sender
            .encrypt_message(message, &recipient.public_dh_key(), &recipient_peer_id)
            .unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.get_mut(50) {
            *byte ^= 0xFF;
        }

        let sender_peer_id = make_peer_id(1);
        let result =
            recipient.decrypt_message(&ciphertext, &sender.public_signing_key(), &sender_peer_id);

        assert!(result.is_err());
    }
}
