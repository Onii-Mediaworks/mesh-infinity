//! WireGuard-like Per-Hop Link Encryption (§5.2)
//!
//! Implements a simplified Noise_IK handshake for authenticated per-hop
//! encryption between directly connected peers. Every packet transmitted
//! between two nodes is encrypted with a session key derived from a
//! Diffie-Hellman key exchange.
//!
//! # Protocol
//!
//! Both peers have long-term static X25519 keypairs. When two peers connect:
//!
//! ```text
//! Initiator                               Responder
//!    |                                       |
//!    |-- HandshakeInit(eph_i_pub, enc_s) --> |  enc_s = our static pub encrypted under DH(eph_i, static_r)
//!    |<-- HandshakeResponse(eph_r_pub) ------ |
//!    |                                       |
//! Both derive session keys:
//!   ck = HKDF(DH(static_i, static_r) ||   // mutual static DH
//!              DH(eph_i, eph_r) ||          // mutual ephemeral DH (forward secrecy)
//!              psk)                          // pre-shared key (channel_key)
//!
//! send_key_i = HKDF(ck, "i→r")
//! recv_key_i = HKDF(ck, "r→i")
//! (responder inverts these)
//! ```
//!
//! # Packet Format
//!
//! `[8-byte nonce (LE u64)] [ciphertext] [16-byte Poly1305 tag]`
//!
//! # Security Properties
//!
//! - **Forward secrecy**: ephemeral keys are discarded after handshake.
//! - **Mutual authentication**: static keys proven in the handshake.
//! - **Replay protection**: 64-bit nonce with anti-replay window.
//! - **PSK mixing**: channel_key PSK provides extra layer.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
use chacha20poly1305::aead::generic_array::GenericArray;
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SESSION_KEY_SALT: &[u8] = b"meshinfinity-wireguard-session-v1";
const REPLAY_WINDOW: u64 = 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum WireGuardError {
    #[error("handshake failed: invalid peer public key")]
    InvalidPeerKey,
    #[error("decryption failed: authentication tag mismatch")]
    DecryptionFailed,
    #[error("replay attack: nonce already seen")]
    ReplayDetected,
    #[error("nonce overflow: session must be renegotiated")]
    NonceOverflow,
    #[error("key derivation failed")]
    KeyDerivation,
}

// ---------------------------------------------------------------------------
// Session Keys
// ---------------------------------------------------------------------------

struct SessionKeys {
    /// Initiator→Responder key.
    i_to_r: Zeroizing<[u8; 32]>,
    /// Responder→Initiator key.
    r_to_i: Zeroizing<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// WireGuardSession
// ---------------------------------------------------------------------------

/// An active per-hop WireGuard-like encrypted session.
pub struct WireGuardSession {
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    send_nonce: Arc<AtomicU64>,
    recv_high: std::sync::Mutex<u64>,
    recv_seen: std::sync::Mutex<std::collections::HashSet<u64>>,
    pub peer_id: PeerId,
}

impl WireGuardSession {
    fn new(keys: SessionKeys, peer_id: PeerId, is_initiator: bool) -> Self {
        let (send_key, recv_key) = if is_initiator {
            (keys.i_to_r, keys.r_to_i)
        } else {
            (keys.r_to_i, keys.i_to_r)
        };
        Self {
            send_key,
            recv_key,
            send_nonce: Arc::new(AtomicU64::new(0)),
            recv_high: std::sync::Mutex::new(0),
            recv_seen: std::sync::Mutex::new(std::collections::HashSet::new()),
            peer_id,
        }
    }

    /// Encrypt `plaintext` and return `[8-byte nonce][ciphertext][16-byte tag]`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let nonce_val = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        if nonce_val == u64::MAX {
            return Err(WireGuardError::NonceOverflow);
        }
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&*self.send_key));
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce_val.to_le_bytes());
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let mut buf = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut buf)
            .map_err(|_| WireGuardError::DecryptionFailed)?;
        let mut out = Vec::with_capacity(8 + buf.len() + 16);
        out.extend_from_slice(&nonce_val.to_le_bytes());
        out.extend_from_slice(&buf);
        out.extend_from_slice(tag.as_slice());
        Ok(out)
    }

    /// Decrypt a packet produced by `encrypt()`.
    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        if packet.len() < 8 + 16 {
            return Err(WireGuardError::DecryptionFailed);
        }
        let nonce_val = u64::from_le_bytes(packet[..8].try_into().unwrap());
        let ciphertext_with_tag = &packet[8..];

        // Anti-replay check.
        {
            let mut high = self.recv_high.lock().unwrap();
            let mut seen = self.recv_seen.lock().unwrap();
            if nonce_val < high.saturating_sub(REPLAY_WINDOW) {
                return Err(WireGuardError::ReplayDetected);
            }
            if seen.contains(&nonce_val) {
                return Err(WireGuardError::ReplayDetected);
            }
            if nonce_val > *high {
                seen.retain(|&n| n >= nonce_val.saturating_sub(REPLAY_WINDOW));
                *high = nonce_val;
            }
            seen.insert(nonce_val);
        }

        // Decrypt.
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&*self.recv_key));
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce_val.to_le_bytes());
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ct_len = ciphertext_with_tag.len() - 16;
        let mut plaintext = ciphertext_with_tag[..ct_len].to_vec();
        let tag = GenericArray::from_slice(&ciphertext_with_tag[ct_len..]);
        cipher.decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
            .map_err(|_| WireGuardError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Handshake messages
// ---------------------------------------------------------------------------

/// Sent by the initiator to start a handshake.
#[derive(Clone)]
pub struct HandshakeInit {
    /// Initiator's ephemeral X25519 public key.
    pub eph_i_pub: [u8; 32],
    /// Initiator's static public key, encrypted under DH(eph_i, static_r).
    /// 32 bytes plaintext + 16 bytes AEAD tag = 48 bytes.
    pub enc_static: [u8; 48],
}

/// Sent by the responder in reply.
#[derive(Clone)]
pub struct HandshakeResponse {
    /// Responder's ephemeral X25519 public key.
    pub eph_r_pub: [u8; 32],
}

// ---------------------------------------------------------------------------
// Initiator handshake
// ---------------------------------------------------------------------------

/// Ephemeral key pair used by the initiator.
/// Uses `StaticSecret` (not `EphemeralSecret`) so we can perform multiple
/// DH operations with the same key — needed for the eph×eph and eph×static
/// computations that happen at different handshake steps.
struct EphemeralPair {
    secret: X25519Secret,
    public: X25519Public,
}

impl EphemeralPair {
    fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        let secret = X25519Secret::from(bytes);
        let public = X25519Public::from(&secret);
        Self { secret, public }
    }
}

/// Initiator-side handshake state.
pub struct PendingInitiatorHandshake {
    eph: EphemeralPair,
    static_secret: X25519Secret,
    responder_static_pub: X25519Public,
    channel_psk: Zeroizing<[u8; 32]>,
}

impl PendingInitiatorHandshake {
    /// Start a new initiator-side handshake.
    ///
    /// Returns the handshake state and the `HandshakeInit` message to send.
    pub fn new(
        our_static_secret: X25519Secret,
        responder_static_pub: X25519Public,
        channel_psk: Zeroizing<[u8; 32]>,
    ) -> (Self, HandshakeInit) {
        let eph = EphemeralPair::generate();
        let our_static_pub = X25519Public::from(&our_static_secret);

        // Encrypt our static pub key under DH(eph_i, static_r).
        let dh_ei_sr = eph.secret.diffie_hellman(&responder_static_pub);
        let enc_static = encrypt_static_key(our_static_pub.as_bytes(), dh_ei_sr.as_bytes());

        let init = HandshakeInit {
            eph_i_pub: eph.public.to_bytes(),
            enc_static,
        };

        let state = Self { eph, static_secret: our_static_secret, responder_static_pub, channel_psk };
        (state, init)
    }

    /// Complete the handshake after receiving the responder's reply.
    pub fn complete(
        self,
        response: &HandshakeResponse,
        our_peer_id: PeerId,
        responder_peer_id: PeerId,
    ) -> Result<WireGuardSession, WireGuardError> {
        let eph_r_pub = X25519Public::from(response.eph_r_pub);

        // DH(static_i, static_r) — mutual authentication.
        let dh_ss = self.static_secret.diffie_hellman(&self.responder_static_pub);
        // DH(eph_i, eph_r) — forward secrecy.
        let dh_ee = self.eph.secret.diffie_hellman(&eph_r_pub);

        let keys = derive_session_keys(
            dh_ss.as_bytes(),
            dh_ee.as_bytes(),
            &self.channel_psk,
            our_peer_id.as_bytes(),
            responder_peer_id.as_bytes(),
        )?;

        Ok(WireGuardSession::new(keys, responder_peer_id, true))
    }
}

// ---------------------------------------------------------------------------
// Responder handshake
// ---------------------------------------------------------------------------

/// Handle an initiator's handshake initiation.
///
/// Verifies the encrypted static key, generates our ephemeral pair,
/// and derives the session keys.
pub fn respond_to_handshake(
    init: &HandshakeInit,
    our_static_secret: &X25519Secret,
    channel_psk: &Zeroizing<[u8; 32]>,
    our_peer_id: PeerId,
    initiator_peer_id: PeerId,
) -> Result<(WireGuardSession, HandshakeResponse), WireGuardError> {
    let eph_i_pub = X25519Public::from(init.eph_i_pub);

    // Decrypt initiator's static key using DH(static_r, eph_i).
    let dh_sr_ei = our_static_secret.diffie_hellman(&eph_i_pub);
    let init_static_bytes = decrypt_static_key(&init.enc_static, dh_sr_ei.as_bytes())
        .ok_or(WireGuardError::InvalidPeerKey)?;
    let init_static_pub = X25519Public::from(init_static_bytes);

    // Generate our ephemeral pair.
    let eph_r = EphemeralPair::generate();

    // DH(static_r, static_i) — must equal DH(static_i, static_r).
    let dh_ss = our_static_secret.diffie_hellman(&init_static_pub);
    // DH(eph_r, eph_i) — must equal DH(eph_i, eph_r).
    let dh_ee = eph_r.secret.diffie_hellman(&eph_i_pub);

    let keys = derive_session_keys(
        dh_ss.as_bytes(),
        dh_ee.as_bytes(),
        channel_psk,
        initiator_peer_id.as_bytes(),
        our_peer_id.as_bytes(),
    )?;

    let session = WireGuardSession::new(keys, initiator_peer_id, false);

    Ok((session, HandshakeResponse {
        eph_r_pub: eph_r.public.to_bytes(),
    }))
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive symmetric session keys from two DH outputs and a PSK.
///
/// Both sides must agree on the `peer_a` / `peer_b` ordering (lexicographic
/// by peer ID bytes) to ensure identical key derivation.
fn derive_session_keys(
    dh_ss: &[u8],
    dh_ee: &[u8],
    psk: &[u8; 32],
    peer_a: &[u8],
    peer_b: &[u8],
) -> Result<SessionKeys, WireGuardError> {
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh_ss);
    ikm.extend_from_slice(dh_ee);
    ikm.extend_from_slice(psk);

    // Sort peer IDs for deterministic info regardless of call order.
    let mut info = Vec::with_capacity(64);
    if peer_a <= peer_b {
        info.extend_from_slice(peer_a);
        info.extend_from_slice(peer_b);
    } else {
        info.extend_from_slice(peer_b);
        info.extend_from_slice(peer_a);
    }

    let hk = Hkdf::<Sha256>::new(Some(SESSION_KEY_SALT), &ikm);

    let mut i_to_r = Zeroizing::new([0u8; 32]);
    let mut r_to_i = Zeroizing::new([0u8; 32]);

    // The direction labels must NOT include peer IDs (they're in the HKDF info).
    hk.expand(b"i_to_r", &mut *i_to_r).map_err(|_| WireGuardError::KeyDerivation)?;
    hk.expand(b"r_to_i", &mut *r_to_i).map_err(|_| WireGuardError::KeyDerivation)?;

    Ok(SessionKeys { i_to_r, r_to_i })
}

/// Encrypt a 32-byte static public key under a DH output.
/// Returns 32 (ciphertext) + 16 (tag) = 48 bytes.
fn encrypt_static_key(static_pub: &[u8; 32], dh_key: &[u8]) -> [u8; 48] {
    let key = derive_aead_key(dh_key);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let mut buf = static_pub.to_vec();
    let tag = cipher.encrypt_in_place_detached(nonce, b"static-key", &mut buf).unwrap();
    let mut out = [0u8; 48];
    out[..32].copy_from_slice(&buf);
    out[32..].copy_from_slice(tag.as_slice());
    out
}

/// Decrypt a 48-byte encrypted static public key. Returns `None` on auth failure.
fn decrypt_static_key(enc: &[u8; 48], dh_key: &[u8]) -> Option<[u8; 32]> {
    let key = derive_aead_key(dh_key);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let mut buf = enc[..32].to_vec();
    let tag = GenericArray::from_slice(&enc[32..]);
    cipher.decrypt_in_place_detached(nonce, b"static-key", &mut buf, tag).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf);
    Some(out)
}

fn derive_aead_key(dh_key: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SESSION_KEY_SALT), dh_key);
    let mut key = [0u8; 32];
    hk.expand(b"aead-key", &mut key).unwrap();
    key
}

// ---------------------------------------------------------------------------
// Session Store
// ---------------------------------------------------------------------------

/// Manages active WireGuard sessions per peer.
#[derive(Default)]
pub struct WireGuardSessionStore {
    sessions: std::collections::HashMap<PeerId, WireGuardSession>,
}

impl WireGuardSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, peer_id: PeerId, session: WireGuardSession) {
        self.sessions.insert(peer_id, session);
    }

    pub fn get(&self, peer_id: &PeerId) -> Option<&WireGuardSession> {
        self.sessions.get(peer_id)
    }

    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut WireGuardSession> {
        self.sessions.get_mut(peer_id)
    }

    pub fn remove(&mut self, peer_id: &PeerId) {
        self.sessions.remove(peer_id);
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    fn peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    fn psk() -> Zeroizing<[u8; 32]> {
        Zeroizing::new([0xABu8; 32])
    }

    fn gen_static() -> X25519Secret {
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        X25519Secret::from(bytes)
    }

    fn make_session_pair() -> (WireGuardSession, WireGuardSession) {
        let init_static = gen_static();
        let resp_static = gen_static();
        let resp_static_pub = X25519Public::from(&resp_static);

        let (init_state, init_msg) = PendingInitiatorHandshake::new(
            init_static,
            resp_static_pub,
            psk(),
        );

        let (resp_session, resp_msg) = respond_to_handshake(
            &init_msg,
            &resp_static,
            &psk(),
            peer(0x02),
            peer(0x01),
        ).unwrap();

        let init_session = init_state.complete(&resp_msg, peer(0x01), peer(0x02)).unwrap();

        (init_session, resp_session)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (init_session, resp_session) = make_session_pair();
        let plaintext = b"hello wireguard";
        let encrypted = init_session.encrypt(plaintext).unwrap();
        let decrypted = resp_session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_replay_protection() {
        let (init_session, resp_session) = make_session_pair();
        let encrypted = init_session.encrypt(b"test").unwrap();
        resp_session.decrypt(&encrypted).unwrap();
        let err = resp_session.decrypt(&encrypted).unwrap_err();
        assert!(matches!(err, WireGuardError::ReplayDetected));
    }

    #[test]
    fn test_multiple_packets() {
        let (init_session, resp_session) = make_session_pair();
        for i in 0u8..20 {
            let msg = vec![i; 64];
            let enc = init_session.encrypt(&msg).unwrap();
            let dec = resp_session.decrypt(&enc).unwrap();
            assert_eq!(dec, msg);
        }
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (init_session, resp_session) = make_session_pair();
        let mut enc = init_session.encrypt(b"secret data").unwrap();
        let mid = enc.len() / 2;
        enc[mid] ^= 0xFF;
        let err = resp_session.decrypt(&enc).unwrap_err();
        assert!(matches!(err, WireGuardError::DecryptionFailed));
    }

    #[test]
    fn test_bidirectional() {
        // Both sides can send and receive.
        let (init_session, resp_session) = make_session_pair();

        let enc1 = init_session.encrypt(b"from initiator").unwrap();
        let dec1 = resp_session.decrypt(&enc1).unwrap();
        assert_eq!(dec1, b"from initiator");

        let enc2 = resp_session.encrypt(b"from responder").unwrap();
        let dec2 = init_session.decrypt(&enc2).unwrap();
        assert_eq!(dec2, b"from responder");
    }

    #[test]
    fn test_session_store() {
        let mut store = WireGuardSessionStore::new();
        let (session, _) = make_session_pair();
        let pid = peer(0x42);
        store.insert(pid, session);
        assert_eq!(store.len(), 1);
        assert!(store.get(&pid).is_some());
        store.remove(&pid);
        assert!(store.is_empty());
    }
}
