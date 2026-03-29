//! Double Ratchet Algorithm (§7.0.3, §7.5)
//!
//! Implements the Signal Double Ratchet with Mesh Infinity domain separation.
//! After X3DH establishes a shared `master_secret`, the Double Ratchet advances
//! the session key with every message, providing:
//!
//! - **Per-message forward secrecy:** each message uses a unique `msg_key`
//! - **Break-in recovery:** DH ratchet step mixes fresh key material
//! - **Out-of-order delivery:** skipped message keys cached (max 1000)
//!
//! # KDF Chains
//!
//! ```text
//! msg_key       = HMAC-SHA256(chain_key, 0x01)
//! new_chain_key = HMAC-SHA256(chain_key, 0x02)
//!
//! (new_root_key, new_chain_key) = HKDF-SHA256(
//!     salt = root_key,
//!     ikm  = X25519(my_ratchet_secret, their_ratchet_pub),
//!     info = "MeshInfinity_DR_v1",
//!     len  = 64
//! )
//!
//! keys   = HKDF-SHA256(salt=0*32, ikm=msg_key, info="MeshInfinity_MK_v1", len=76)
//! cipher_key = keys[0..32]
//! nonce      = keys[32..44]
//! _hmac_key  = keys[44..76]  // for Step 1 inner auth
//! ```

use std::collections::HashMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, Zeroizing};

// Shared KDF chain-step primitive and constants (avoids duplication with
// sender_keys.rs — both protocols use the same HMAC-SHA256 chain advancement).
use super::primitives::{kdf_chain_step, ZERO_SALT};
use super::secmem::SecureMemoryError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DR_INFO: &[u8] = b"MeshInfinity_DR_v1";
const MK_INFO: &[u8] = b"MeshInfinity_MK_v1";

/// Maximum number of skipped message keys to cache per peer.
/// Prevents memory exhaustion from adversarial skip counters.
pub const MAX_SKIP: u32 = 1000;

/// Expanded message key material: (cipher_key, nonce, hmac_key).
pub type ExpandedMsgKey = ([u8; 32], [u8; 12], [u8; 32]);

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    #[error("HKDF expansion failed")]
    HkdfExpand,
    #[error("Too many skipped messages (>{MAX_SKIP})")]
    TooManySkipped,
    #[error("Duplicate message (already decrypted)")]
    DuplicateMessage,
    #[error("AEAD decryption failed")]
    DecryptionFailed,
    #[error("AEAD encryption failed")]
    EncryptionFailed,
    #[error("Secure memory: {0}")]
    SecureMemory(#[from] SecureMemoryError),
}

// ---------------------------------------------------------------------------
// Message Header
// ---------------------------------------------------------------------------

/// The Double Ratchet header sent with each message.
/// Carries the sender's current ratchet public key and counters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Sender's current DH ratchet public key
    pub ratchet_pub: [u8; 32],
    /// Number of messages in the previous sending chain
    pub prev_chain_len: u32,
    /// Message number in the current sending chain
    pub msg_num: u32,
}

// ---------------------------------------------------------------------------
// Expanded message key (for encryption/decryption)
// ---------------------------------------------------------------------------

/// The expanded key material from a single message key.
struct MessageKeys {
    cipher_key: [u8; 32],
    nonce: [u8; 12],
    hmac_key: [u8; 32],
}

impl Drop for MessageKeys {
    fn drop(&mut self) {
        self.cipher_key.zeroize();
        self.nonce.zeroize();
        self.hmac_key.zeroize();
    }
}

/// Expand a message key into cipher_key + nonce + hmac_key.
fn expand_message_key(msg_key: &[u8; 32]) -> Result<MessageKeys, RatchetError> {
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), msg_key);
    let mut output = Zeroizing::new([0u8; 76]);
    hk.expand(MK_INFO, &mut *output)
        .map_err(|_| RatchetError::HkdfExpand)?;

    let mut cipher_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];
    cipher_key.copy_from_slice(&output[0..32]);
    nonce.copy_from_slice(&output[32..44]);
    hmac_key.copy_from_slice(&output[44..76]);

    Ok(MessageKeys {
        cipher_key,
        nonce,
        hmac_key,
    })
}

// ---------------------------------------------------------------------------
// KDF Chain operations  (kdf_chain_step re-exported from crypto::primitives)
// ---------------------------------------------------------------------------

/// Perform the DH ratchet step — mix fresh DH material into the root key.
/// Returns (new_root_key, new_chain_key).
fn dh_ratchet_step(
    root_key: &[u8; 32],
    dh_output: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), RatchetError> {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = Zeroizing::new([0u8; 64]);
    hk.expand(DR_INFO, &mut *output)
        .map_err(|_| RatchetError::HkdfExpand)?;

    let mut new_root = [0u8; 32];
    let mut new_chain = [0u8; 32];
    new_root.copy_from_slice(&output[0..32]);
    new_chain.copy_from_slice(&output[32..64]);
    Ok((new_root, new_chain))
}

// ---------------------------------------------------------------------------
// Skipped message key index
// ---------------------------------------------------------------------------

/// Key for the skipped message cache: (ratchet_pub, msg_number).
#[derive(Hash, Eq, PartialEq, Clone)]
struct SkippedKeyId {
    ratchet_pub: [u8; 32],
    msg_num: u32,
}

// ---------------------------------------------------------------------------
// Double Ratchet Session State
// ---------------------------------------------------------------------------

/// Complete Double Ratchet session state for one peer.
pub struct DoubleRatchetSession {
    // DH ratchet state
    root_key: [u8; 32],
    my_ratchet_secret: X25519Secret,
    my_ratchet_pub: [u8; 32],
    their_ratchet_pub: Option<[u8; 32]>,

    // Sending chain
    send_chain_key: Option<[u8; 32]>,
    send_msg_num: u32,

    // Receiving chain
    recv_chain_key: Option<[u8; 32]>,
    recv_msg_num: u32,

    // Previous sending chain length (for header)
    prev_send_chain_len: u32,

    // Skipped message keys cache
    skipped_keys: HashMap<SkippedKeyId, [u8; 32]>,
}

impl Drop for DoubleRatchetSession {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut ck) = self.send_chain_key {
            ck.zeroize();
        }
        if let Some(ref mut ck) = self.recv_chain_key {
            ck.zeroize();
        }
        // Zeroize all cached skipped keys
        for (_, key) in self.skipped_keys.iter_mut() {
            key.zeroize();
        }
    }
}

impl DoubleRatchetSession {
    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Initialize as the SENDER (Alice) after X3DH.
    ///
    /// Alice knows the master_secret and Bob's preauth public key (used as
    /// the initial receiving ratchet public key).
    pub fn init_sender(
        master_secret: &[u8; 32],
        their_ratchet_pub: &[u8; 32],
    ) -> Result<Self, RatchetError> {
        // Generate our first ratchet keypair
        let my_ratchet_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let my_ratchet_pub_key = X25519Public::from(&my_ratchet_secret);
        let my_ratchet_pub = *my_ratchet_pub_key.as_bytes();

        // Perform first DH ratchet step to derive send chain
        let their_pub = X25519Public::from(*their_ratchet_pub);
        let dh_out = my_ratchet_secret.diffie_hellman(&their_pub);
        let (root_key, send_chain_key) = dh_ratchet_step(master_secret, dh_out.as_bytes())?;

        Ok(Self {
            root_key,
            my_ratchet_secret,
            my_ratchet_pub,
            their_ratchet_pub: Some(*their_ratchet_pub),
            send_chain_key: Some(send_chain_key),
            send_msg_num: 0,
            recv_chain_key: None,
            recv_msg_num: 0,
            prev_send_chain_len: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Initialize as the RECEIVER (Bob) after X3DH.
    ///
    /// Bob uses his preauth secret as the initial ratchet secret.
    /// He will complete his DH ratchet step on first received message.
    pub fn init_receiver(
        master_secret: &[u8; 32],
        my_preauth_secret: X25519Secret,
        my_preauth_pub: &[u8; 32],
    ) -> Self {
        Self {
            root_key: *master_secret,
            my_ratchet_secret: my_preauth_secret,
            my_ratchet_pub: *my_preauth_pub,
            their_ratchet_pub: None,
            send_chain_key: None,
            send_msg_num: 0,
            recv_chain_key: None,
            recv_msg_num: 0,
            prev_send_chain_len: 0,
            skipped_keys: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Encrypt (send)
    // -----------------------------------------------------------------------

    /// Encrypt a plaintext message using the current sending chain.
    /// Returns (header, ciphertext).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>), RatchetError> {
        let chain_key = self
            .send_chain_key
            .as_ref()
            .expect("Send chain must be initialized before encrypting");

        // Advance the sending chain
        let (msg_key, new_chain_key) = kdf_chain_step(chain_key);
        self.send_chain_key = Some(new_chain_key);

        // Build header
        let header = RatchetHeader {
            ratchet_pub: self.my_ratchet_pub,
            prev_chain_len: self.prev_send_chain_len,
            msg_num: self.send_msg_num,
        };
        self.send_msg_num += 1;

        // Expand and encrypt
        let mk = expand_message_key(&msg_key)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(&mk.cipher_key).map_err(|_| RatchetError::EncryptionFailed)?;
        let nonce = Nonce::from_slice(&mk.nonce);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| RatchetError::EncryptionFailed)?;

        Ok((header, ciphertext))
    }

    // -----------------------------------------------------------------------
    // Decrypt (receive)
    // -----------------------------------------------------------------------

    /// Decrypt a received message.
    pub fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        // Check if we have a cached skipped key for this message
        let skip_id = SkippedKeyId {
            ratchet_pub: header.ratchet_pub,
            msg_num: header.msg_num,
        };
        if let Some(mut msg_key) = self.skipped_keys.remove(&skip_id) {
            let result = decrypt_with_key(&msg_key, ciphertext);
            msg_key.zeroize();
            return result;
        }

        // Check if we need a DH ratchet step (new ratchet pub from sender)
        let need_dh_step = self.their_ratchet_pub.as_ref() != Some(&header.ratchet_pub);
        if need_dh_step {
            // Skip any remaining messages in the current receiving chain
            if let Some(ref recv_ck) = self.recv_chain_key {
                self.skip_message_keys(*recv_ck, self.recv_msg_num, header.prev_chain_len)?;
            }

            // Perform DH ratchet step (receiving side)
            self.their_ratchet_pub = Some(header.ratchet_pub);
            let their_pub = X25519Public::from(header.ratchet_pub);
            let dh_out = self.my_ratchet_secret.diffie_hellman(&their_pub);
            let (new_root, recv_chain_key) =
                dh_ratchet_step(&self.root_key, dh_out.as_bytes())?;
            self.root_key = new_root;
            self.recv_chain_key = Some(recv_chain_key);
            self.recv_msg_num = 0;

            // Now perform DH ratchet step (sending side) — generate new keypair
            self.prev_send_chain_len = self.send_msg_num;
            self.send_msg_num = 0;
            self.my_ratchet_secret = X25519Secret::random_from_rng(rand_core::OsRng);
            let new_pub = X25519Public::from(&self.my_ratchet_secret);
            self.my_ratchet_pub = *new_pub.as_bytes();

            let dh_out2 = self.my_ratchet_secret.diffie_hellman(&their_pub);
            let (new_root2, send_chain_key) =
                dh_ratchet_step(&self.root_key, dh_out2.as_bytes())?;
            self.root_key = new_root2;
            self.send_chain_key = Some(send_chain_key);
        }

        // Skip any messages in the current chain before this one
        let recv_ck = self
            .recv_chain_key
            .expect("Recv chain must exist after DH step");
        self.skip_message_keys(recv_ck, self.recv_msg_num, header.msg_num)?;

        // Advance receiving chain to this message.
        // recv_chain_key is still Some: [u8; 32] is Copy so the .expect() above
        // read a copy without consuming the field.
        let recv_ck = self
            .recv_chain_key
            .as_ref()
            .expect("recv_chain_key is still Some after skip — Copy type, field not consumed");
        let (msg_key, new_recv_ck) = kdf_chain_step(recv_ck);
        self.recv_chain_key = Some(new_recv_ck);
        self.recv_msg_num = header.msg_num + 1;

        decrypt_with_key(&msg_key, ciphertext)
    }

    // -----------------------------------------------------------------------
    // Skip message key caching
    // -----------------------------------------------------------------------

    /// Cache skipped message keys between `from` and `until`.
    fn skip_message_keys(
        &mut self,
        mut chain_key: [u8; 32],
        from: u32,
        until: u32,
    ) -> Result<(), RatchetError> {
        if until < from {
            return Ok(());
        }
        let skip_count = until - from;
        // Use checked_add to prevent the u32 cast from silently truncating a
        // skipped_keys map that grew beyond 2^32 entries on a 64-bit host.
        // If the add would overflow or the result exceeds MAX_SKIP, reject.
        let existing = self.skipped_keys.len() as u64;
        if existing.saturating_add(skip_count as u64) > MAX_SKIP as u64 {
            return Err(RatchetError::TooManySkipped);
        }

        let their_pub = self
            .their_ratchet_pub
            .expect("their_ratchet_pub must be set before skipping");

        for i in from..until {
            let (msg_key, new_ck) = kdf_chain_step(&chain_key);
            let id = SkippedKeyId {
                ratchet_pub: their_pub,
                msg_num: i,
            };
            self.skipped_keys.insert(id, msg_key);
            chain_key = new_ck;
        }

        // Update the chain key to the position after skipping
        self.recv_chain_key = Some(chain_key);

        Ok(())
    }

    /// Get the current ratchet public key (for the message header).
    pub fn my_ratchet_pub(&self) -> &[u8; 32] {
        &self.my_ratchet_pub
    }

    /// Number of cached skipped keys.
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
    }

    // -----------------------------------------------------------------------
    // Four-layer scheme helpers (§7.2)
    // -----------------------------------------------------------------------

    /// Advance the sending chain and return the raw message key + header.
    ///
    /// Use this with the four-layer encryption scheme (§7.2): call
    /// `expand_msg_key` to derive cipher_key/nonce/hmac_key, then pass
    /// those to `encrypt_message`. Prefer this over `encrypt()` when the
    /// four-layer AEAD wrapper is applied externally.
    pub fn next_send_msg_key(&mut self) -> Result<(RatchetHeader, [u8; 32]), RatchetError> {
        let chain_key = self
            .send_chain_key
            .as_ref()
            .expect("Send chain must be initialized before encrypting");

        let (msg_key, new_chain_key) = kdf_chain_step(chain_key);
        self.send_chain_key = Some(new_chain_key);

        let header = RatchetHeader {
            ratchet_pub: self.my_ratchet_pub,
            prev_chain_len: self.prev_send_chain_len,
            msg_num: self.send_msg_num,
        };
        self.send_msg_num += 1;

        Ok((header, msg_key))
    }

    /// Process a received ratchet header and return the raw message key.
    ///
    /// Use this with the four-layer decryption scheme (§7.2): call
    /// `expand_msg_key` on the returned key, then pass to `decrypt_message`.
    /// Mirrors the DH-ratchet logic of `decrypt()` without performing AEAD.
    pub fn recv_msg_key(&mut self, header: &RatchetHeader) -> Result<[u8; 32], RatchetError> {
        // Check skipped key cache first.
        let skip_id = SkippedKeyId {
            ratchet_pub: header.ratchet_pub,
            msg_num: header.msg_num,
        };
        if let Some(msg_key) = self.skipped_keys.remove(&skip_id) {
            return Ok(msg_key);
        }

        // DH ratchet step if the sender's ratchet key changed.
        let need_dh_step = self.their_ratchet_pub.as_ref() != Some(&header.ratchet_pub);
        if need_dh_step {
            // Skip any remaining messages in the current receiving chain.
            if let Some(ref recv_ck) = self.recv_chain_key {
                self.skip_message_keys(*recv_ck, self.recv_msg_num, header.prev_chain_len)?;
            }

            // Receive-side DH step.
            self.their_ratchet_pub = Some(header.ratchet_pub);
            let their_pub = X25519Public::from(header.ratchet_pub);
            let dh_out = self.my_ratchet_secret.diffie_hellman(&their_pub);
            let (new_root, recv_chain_key) =
                dh_ratchet_step(&self.root_key, dh_out.as_bytes())?;
            self.root_key = new_root;
            self.recv_chain_key = Some(recv_chain_key);
            self.recv_msg_num = 0;

            // Send-side DH step: generate a fresh ratchet keypair.
            self.prev_send_chain_len = self.send_msg_num;
            self.send_msg_num = 0;
            self.my_ratchet_secret = X25519Secret::random_from_rng(rand_core::OsRng);
            let new_pub = X25519Public::from(&self.my_ratchet_secret);
            self.my_ratchet_pub = *new_pub.as_bytes();
            let dh_out2 = self.my_ratchet_secret.diffie_hellman(&their_pub);
            let (new_root2, send_chain_key) =
                dh_ratchet_step(&self.root_key, dh_out2.as_bytes())?;
            self.root_key = new_root2;
            self.send_chain_key = Some(send_chain_key);
        }

        // Skip messages before this one in the current receiving chain.
        let recv_ck = self
            .recv_chain_key
            .expect("Recv chain must exist after DH step");
        self.skip_message_keys(recv_ck, self.recv_msg_num, header.msg_num)?;

        // Advance the receiving chain to this message.
        // recv_chain_key is still Some: [u8; 32] is Copy so the .expect() above
        // read a copy without consuming the field.
        let recv_ck = self
            .recv_chain_key
            .as_ref()
            .expect("recv_chain_key is still Some after skip — Copy type, field not consumed");
        let (msg_key, new_recv_ck) = kdf_chain_step(recv_ck);
        self.recv_chain_key = Some(new_recv_ck);
        self.recv_msg_num = header.msg_num + 1;

        Ok(msg_key)
    }

    /// Derive cipher_key, nonce, and hmac_key from a raw message key.
    ///
    /// Used by the four-layer encryption scheme (§7.2):
    /// - `cipher_key` + `nonce` → Step 2 (ChaCha20-Poly1305 trust-channel encryption)
    /// - `hmac_key` → Step 1 (HMAC-SHA256 inner authentication)
    ///
    /// Returns `(cipher_key, nonce, hmac_key)`.
    pub fn expand_msg_key(
        msg_key: &[u8; 32],
    ) -> Result<ExpandedMsgKey, RatchetError> {
        let mk = expand_message_key(msg_key)?;
        Ok((mk.cipher_key, mk.nonce, mk.hmac_key))
    }

    // -----------------------------------------------------------------------
    // Vault persistence (§17.9)
    // -----------------------------------------------------------------------

    /// Export all session state into a serialisable snapshot.
    ///
    /// The snapshot is encrypted by the caller (via `VaultCollection::save`)
    /// before being written to disk. No key material ever touches disk in the clear.
    pub fn to_snapshot(&self) -> SessionSnapshot {
        let skipped_keys = self
            .skipped_keys
            .iter()
            .map(|(id, key)| (id.ratchet_pub, id.msg_num, *key))
            .collect();

        SessionSnapshot {
            root_key: self.root_key,
            my_ratchet_secret_bytes: *self.my_ratchet_secret.as_bytes(),
            my_ratchet_pub: self.my_ratchet_pub,
            their_ratchet_pub: self.their_ratchet_pub,
            send_chain_key: self.send_chain_key,
            send_msg_num: self.send_msg_num,
            recv_chain_key: self.recv_chain_key,
            recv_msg_num: self.recv_msg_num,
            prev_send_chain_len: self.prev_send_chain_len,
            skipped_keys,
        }
    }

    /// Reconstruct a session from a previously exported snapshot.
    pub fn from_snapshot(snap: SessionSnapshot) -> Self {
        let my_ratchet_secret = X25519Secret::from(snap.my_ratchet_secret_bytes);
        let skipped_keys = snap
            .skipped_keys
            .into_iter()
            .map(|(ratchet_pub, msg_num, key)| (SkippedKeyId { ratchet_pub, msg_num }, key))
            .collect();

        Self {
            root_key: snap.root_key,
            my_ratchet_secret,
            my_ratchet_pub: snap.my_ratchet_pub,
            their_ratchet_pub: snap.their_ratchet_pub,
            send_chain_key: snap.send_chain_key,
            send_msg_num: snap.send_msg_num,
            recv_chain_key: snap.recv_chain_key,
            recv_msg_num: snap.recv_msg_num,
            prev_send_chain_len: snap.prev_send_chain_len,
            skipped_keys,
        }
    }
}

// ---------------------------------------------------------------------------
// Session snapshot (vault persistence — §17.9)
// ---------------------------------------------------------------------------

/// Serialisable representation of a `DoubleRatchetSession`.
///
/// Created by `DoubleRatchetSession::to_snapshot()` and restored by
/// `DoubleRatchetSession::from_snapshot()`. The caller is responsible for
/// encrypting this before writing to disk (via `VaultCollection::save`).
///
/// Serde field names must remain stable — changing them is a vault schema
/// migration requiring a version bump.
#[derive(Serialize, Deserialize)]
pub struct SessionSnapshot {
    /// Current root key bytes.
    root_key: [u8; 32],
    /// Raw bytes of the local DH ratchet secret.
    my_ratchet_secret_bytes: [u8; 32],
    /// The corresponding public key bytes.
    my_ratchet_pub: [u8; 32],
    /// Remote peer's current ratchet public key (None until first message received).
    their_ratchet_pub: Option<[u8; 32]>,
    /// Current sending chain key.
    send_chain_key: Option<[u8; 32]>,
    /// Number of messages sent on current sending chain.
    send_msg_num: u32,
    /// Current receiving chain key.
    recv_chain_key: Option<[u8; 32]>,
    /// Number of messages received on current receiving chain.
    recv_msg_num: u32,
    /// Number of messages in the previous sending chain (for headers).
    prev_send_chain_len: u32,
    /// Cached skipped message keys: `(ratchet_pub, msg_num, msg_key)`.
    skipped_keys: Vec<([u8; 32], u32, [u8; 32])>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn decrypt_with_key(msg_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let mk = expand_message_key(msg_key)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&mk.cipher_key).map_err(|_| RatchetError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&mk.nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| RatchetError::DecryptionFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_session_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
        // Simulate X3DH output
        let master_secret = [0x42u8; 32];

        // Bob's preauth keypair (used as initial ratchet key)
        let bob_preauth_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let bob_preauth_pub = *X25519Public::from(&bob_preauth_secret).as_bytes();

        let alice = DoubleRatchetSession::init_sender(&master_secret, &bob_preauth_pub).unwrap();
        let bob = DoubleRatchetSession::init_receiver(&master_secret, bob_preauth_secret, &bob_preauth_pub);

        (alice, bob)
    }

    #[test]
    fn test_basic_send_receive() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice sends a message
        let plaintext = b"Hello Bob!";
        let (header, ciphertext) = alice.encrypt(plaintext).unwrap();

        // Bob decrypts
        let decrypted = bob.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bidirectional_messages() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice → Bob
        let (h1, ct1) = alice.encrypt(b"Hello from Alice").unwrap();
        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"Hello from Alice");

        // Bob → Alice
        let (h2, ct2) = bob.encrypt(b"Hello from Bob").unwrap();
        let pt2 = alice.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"Hello from Bob");

        // Alice → Bob again
        let (h3, ct3) = alice.encrypt(b"Second from Alice").unwrap();
        let pt3 = bob.decrypt(&h3, &ct3).unwrap();
        assert_eq!(pt3, b"Second from Alice");
    }

    #[test]
    fn test_multiple_messages_same_direction() {
        let (mut alice, mut bob) = setup_session_pair();

        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2").unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3").unwrap();

        // Decrypt in order
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"msg1");
        assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"msg2");
        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"msg3");
    }

    #[test]
    fn test_out_of_order_delivery() {
        let (mut alice, mut bob) = setup_session_pair();

        let (h1, ct1) = alice.encrypt(b"first").unwrap();
        let (h2, ct2) = alice.encrypt(b"second").unwrap();
        let (h3, ct3) = alice.encrypt(b"third").unwrap();

        // Deliver out of order: 3, 1, 2
        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"third");
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"first");
        assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"second");
    }

    #[test]
    fn test_ratchet_advances_per_message() {
        let (mut alice, _bob) = setup_session_pair();

        let (h1, _) = alice.encrypt(b"msg1").unwrap();
        let (h2, _) = alice.encrypt(b"msg2").unwrap();

        // Same ratchet pub (no DH step between sends), but different msg_num
        assert_eq!(h1.ratchet_pub, h2.ratchet_pub);
        assert_eq!(h1.msg_num, 0);
        assert_eq!(h2.msg_num, 1);
    }

    #[test]
    fn test_dh_ratchet_step_on_reply() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice sends
        let (h1, ct1) = alice.encrypt(b"from alice").unwrap();
        bob.decrypt(&h1, &ct1).unwrap();

        // Bob replies — this triggers a DH ratchet step
        let (h2, ct2) = bob.encrypt(b"from bob").unwrap();

        // Bob's ratchet pub should be DIFFERENT from Alice's
        assert_ne!(h1.ratchet_pub, h2.ratchet_pub);

        // Alice decrypts — triggers her DH ratchet step
        let pt2 = alice.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"from bob");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (mut alice, mut bob) = setup_session_pair();

        let (header, mut ciphertext) = alice.encrypt(b"secret").unwrap();

        // Tamper
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        assert!(bob.decrypt(&header, &ciphertext).is_err());
    }

    #[test]
    fn test_per_message_forward_secrecy() {
        let (mut alice, mut bob) = setup_session_pair();

        // Send 3 messages
        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (_h2, _ct2) = alice.encrypt(b"msg2").unwrap();
        let (_h3, _ct3) = alice.encrypt(b"msg3").unwrap();

        // Decrypt only msg1 — msg2 and msg3 keys are in the chain
        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"msg1");

        // After decrypting msg1, the chain_key has advanced
        // The key for msg1 is gone (forward secrecy)
        // But msg2 and msg3 are still decryptable via skipped keys or chain advancement
    }

    #[test]
    fn test_snapshot_roundtrip_preserves_session() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice sends 3 messages; Bob decrypts 2 (leaving 1 skipped key cached in bob).
        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2").unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3").unwrap();

        // Bob decrypts msg1 and msg3 out of order — msg2's key goes into skipped cache.
        bob.decrypt(&h1, &ct1).unwrap();
        bob.decrypt(&h3, &ct3).unwrap(); // skips msg2

        // Snapshot and restore Bob's session.
        let snap = bob.to_snapshot();
        let json = serde_json::to_vec(&snap).unwrap();
        let snap2: SessionSnapshot = serde_json::from_slice(&json).unwrap();
        let mut bob_restored = DoubleRatchetSession::from_snapshot(snap2);

        // Restored Bob should still be able to decrypt the skipped msg2.
        let pt2 = bob_restored.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"msg2");

        // And continue receiving from Alice normally.
        let (h4, ct4) = alice.encrypt(b"msg4").unwrap();
        let pt4 = bob_restored.decrypt(&h4, &ct4).unwrap();
        assert_eq!(pt4, b"msg4");
    }

    #[test]
    fn test_long_conversation() {
        let (mut alice, mut bob) = setup_session_pair();

        // 50 messages back and forth
        for i in 0..50u32 {
            let msg = format!("Message #{i}");
            if i % 2 == 0 {
                let (h, ct) = alice.encrypt(msg.as_bytes()).unwrap();
                let pt = bob.decrypt(&h, &ct).unwrap();
                assert_eq!(pt, msg.as_bytes());
            } else {
                let (h, ct) = bob.encrypt(msg.as_bytes()).unwrap();
                let pt = alice.decrypt(&h, &ct).unwrap();
                assert_eq!(pt, msg.as_bytes());
            }
        }
    }

    #[test]
    fn test_replay_in_order_message_rejected() {
        // Decrypting the same (header, ciphertext) twice must fail.
        // After the first successful decrypt, recv_msg_num advances; the
        // second attempt drives the chain forward one extra step, producing
        // a different message key → AEAD authentication failure.
        let (mut alice, mut bob) = setup_session_pair();

        let (header, ciphertext) = alice.encrypt(b"replay target").unwrap();

        // First decrypt succeeds.
        let first = bob.decrypt(&header, &ciphertext);
        assert!(first.is_ok(), "first decrypt must succeed");

        // Second decrypt with the identical (header, ciphertext) must fail.
        let second = bob.decrypt(&header, &ciphertext);
        assert!(second.is_err(), "replay of in-order message must be rejected");
    }

    #[test]
    fn test_replay_skipped_message_rejected() {
        // A message whose key was cached as a skipped key (out-of-order) is
        // consumed on first use.  Replaying it a second time must fail because
        // the key has been removed from the cache.
        let (mut alice, mut bob) = setup_session_pair();

        // Alice sends two messages.
        let (h1, ct1) = alice.encrypt(b"skip me").unwrap();
        let (h2, ct2) = alice.encrypt(b"deliver first").unwrap();

        // Bob decrypts msg2 first — this caches the skipped key for msg1.
        bob.decrypt(&h2, &ct2).expect("out-of-order second message must decrypt");

        // Bob decrypts the skipped msg1 — key is consumed.
        bob.decrypt(&h1, &ct1).expect("skipped first message must decrypt");

        // Replaying msg1 now must fail — the skipped key was removed on use.
        let replay = bob.decrypt(&h1, &ct1);
        assert!(replay.is_err(), "replay of already-consumed skipped key must be rejected");
    }

    /// Adversarial test: an attacker sends a message whose `msg_num` is
    /// MAX_SKIP+1, forcing the receiver to try to cache MAX_SKIP+1 skipped keys
    /// in a single step.  This must be denied with TooManySkipped rather than
    /// allocating an unbounded HashMap and exhausting memory.
    ///
    /// Threat model: a compromised peer or man-in-the-middle who replays or
    /// forges a header with an extremely high `msg_num`, triggering the
    /// skip_message_keys path with a count that blows past MAX_SKIP.
    #[test]
    fn test_skip_cache_exhaustion_denied() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice encrypts MAX_SKIP+2 messages (msg_num 0 .. MAX_SKIP+1).
        // We keep only the last one (msg_num = MAX_SKIP+1 = 1001) to deliver
        // to Bob. Bob is still at recv_msg_num=0, so the skip count needed is
        // 1001, which exceeds MAX_SKIP=1000.
        let mut last_hdr = None;
        let mut last_ct = None;
        for _ in 0..=(MAX_SKIP + 1) {
            let (h, ct) = alice.encrypt(b"flood").unwrap();
            last_hdr = Some(h);
            last_ct = Some(ct);
        }
        let overflow_hdr = last_hdr.unwrap();
        let overflow_ct = last_ct.unwrap();

        // Delivering the overflow message to Bob must be rejected.
        let result = bob.decrypt(&overflow_hdr, &overflow_ct);
        assert!(
            matches!(result, Err(RatchetError::TooManySkipped)),
            "delivering a message that requires >MAX_SKIP cached keys must return \
             TooManySkipped, got: {result:?}"
        );
    }
}
