//! Trusted Channel Key and Tunnel PSK Derivation (§3.2, §5.2)
//!
//! Two related secrets live here.
//!
//! **`channel_key`** is the long-lived relationship authentication secret for
//! peers at trust Level 6+ (§3.2).  It is derived from the static X25519 DH
//! between the two peers:
//!
//! ```text
//! shared_secret = X25519(my_x25519_secret, their_x25519_public)
//! channel_key   = HKDF-SHA256(shared_secret, salt="meshinfinity-channel-v1",
//!                              info=peer_id_a || peer_id_b)
//! ```
//!
//! `channel_key` is **not** the WireGuard pre-shared key.  A static-static
//! derivation has no forward secrecy and no post-quantum margin, so §3.2 and
//! §5.2 forbid using it directly as a PSK.
//!
//! **`tunnel_psk`** is the per-epoch trusted-tunnel PSK (§5.2, "Trusted-tunnel
//! PSK").  It is derived from a fresh hybrid exchange (ephemeral X25519 plus an
//! ML-KEM-768 encapsulation, the `MI-PQXDH-1` primitives of §3.4.1) with
//! `channel_key` entering only as an additional authentication input:
//!
//! ```text
//! tunnel_psk = HKDF-SHA512(
//!     ikm  = ecdh_ss || kem_ss || channel_key,
//!     salt = "meshinfinity-tunnel-psk-v1",
//!     info = peer_id_a || peer_id_b || tunnel_epoch,
//!     len  = 32
//! )
//! ```
//!
//! The exchange that produces `ecdh_ss` and `kem_ss` lives in
//! `transport::tunnel_keys`; this module holds only the pure derivations so
//! the test vectors are independent of any transport state.
//!
//! peer_id_a and peer_id_b are sorted lexicographically in both derivations so
//! both sides derive the same key regardless of which one initiated.

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
// Securely erase key material to prevent forensic recovery.
use zeroize::Zeroizing;

use crate::identity::peer_id::PeerId;

/// Domain separator salt for channel key derivation.
// CHANNEL_SALT — protocol constant (§3.2).
// Defined by the spec; must not change without a version bump.
const CHANNEL_SALT: &[u8] = b"meshinfinity-channel-v1";

/// Domain separator salt for the per-epoch trusted-tunnel PSK (§5.2).
// TUNNEL_PSK_SALT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const TUNNEL_PSK_SALT: &[u8] = b"meshinfinity-tunnel-psk-v1";

/// Byte length of the derived tunnel PSK (§5.2: `len = 32`).
// TUNNEL_PSK_LEN — protocol constant.
pub const TUNNEL_PSK_LEN: usize = 32;

/// A tunnel epoch counter (§5.2).
///
/// Epochs are per relationship and strictly increasing: every PSK agreement
/// (first promotion, scheduled rotation, forced rotation) uses a fresh epoch,
/// so two agreements never derive the same PSK even with identical shared
/// secrets.  The epoch is encoded as 8 big-endian bytes inside the HKDF info
/// (the spec leaves the encoding to the §21.6.4 manifest; big-endian fixed
/// width is the conservative, unambiguous choice).
pub type TunnelEpoch = u64;

/// Encode a tunnel epoch for use inside the HKDF info field.
///
/// Fixed 8-byte big-endian encoding so the info field has a fixed layout and
/// no epoch value can collide with another by sharing a prefix.
pub fn encode_tunnel_epoch(epoch: TunnelEpoch) -> [u8; 8] {
    // Big-endian keeps lexicographic order equal to numeric order, which
    // makes manifest vectors easy to read and compare.
    epoch.to_be_bytes()
}

/// Concatenate two peer ids in lexicographic order.
///
/// Both §3.2 and §5.2 require the info field to be `peer_id_a || peer_id_b`
/// with the ids sorted, so initiator and responder compute identical bytes.
fn sorted_peer_ids(my_peer_id: &PeerId, their_peer_id: &PeerId) -> [u8; 64] {
    // Compare the raw 32-byte ids; the lower one goes first.
    let (id_a, id_b) = if my_peer_id.0 < their_peer_id.0 {
        (my_peer_id.as_bytes(), their_peer_id.as_bytes())
    } else {
        (their_peer_id.as_bytes(), my_peer_id.as_bytes())
    };
    // Fixed-size output: two 32-byte ids back to back.
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(id_a);
    out[32..].copy_from_slice(id_b);
    out
}

/// Derive the trusted-channel relationship key between two peers (§3.2).
///
/// Both sides independently derive the same key using their own secret
/// and the other's public key. The peer IDs are sorted lexicographically
/// to ensure deterministic derivation regardless of who initiates.
///
/// The result is an authentication input to [`derive_tunnel_psk`]; it must
/// never be installed as a WireGuard PSK on its own (§5.2).
pub fn derive_channel_key(
    // Elliptic curve Diffie-Hellman key agreement.
    my_x25519_secret: &X25519Secret,
    // Elliptic curve Diffie-Hellman key agreement.
    their_x25519_pub: &X25519Public,
    my_peer_id: &PeerId,
    their_peer_id: &PeerId,
) -> Result<Zeroizing<[u8; 32]>, ChannelKeyError> {
    // X25519 DH: the static-static shared secret.
    let shared_secret = my_x25519_secret.diffie_hellman(their_x25519_pub);

    // Sorted peer ids form the HKDF info so both sides agree.
    let info = sorted_peer_ids(my_peer_id, their_peer_id);

    // HKDF-SHA256 with the §3.2 salt.
    let hk = Hkdf::<Sha256>::new(Some(CHANNEL_SALT), shared_secret.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    // Expand the pseudorandom key to the required output length.
    hk.expand(&info, &mut *key)
        // Map the error to the local error type.
        .map_err(|_| ChannelKeyError::HkdfExpand)?;

    Ok(key)
}

/// Derive the per-epoch trusted-tunnel PSK (§5.2, "Trusted-tunnel PSK").
///
/// Inputs:
/// - `ecdh_ss`: the ephemeral-ephemeral X25519 shared secret of this epoch's
///   agreement (forward secrecy).
/// - `kem_ss`: the ML-KEM-768 shared secret of this epoch's agreement
///   (post-quantum margin).
/// - `channel_key`: the static relationship key of §3.2, used only as an
///   additional authentication input.
/// - `my_peer_id` / `their_peer_id`: sorted into the info field.
/// - `epoch`: the tunnel epoch, so successive agreements never collide.
///
/// The function is a pure KDF; the caller erases `ecdh_ss` and `kem_ss`
/// after the call so the PSK keeps the forward secrecy the spec promises.
pub fn derive_tunnel_psk(
    ecdh_ss: &[u8; 32],
    kem_ss: &[u8; 32],
    channel_key: &[u8; 32],
    my_peer_id: &PeerId,
    their_peer_id: &PeerId,
    epoch: TunnelEpoch,
) -> Result<Zeroizing<[u8; TUNNEL_PSK_LEN]>, ChannelKeyError> {
    // ikm = ecdh_ss || kem_ss || channel_key, exactly as §5.2 writes it.
    // Zeroizing so the concatenated secrets are wiped when this returns.
    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[..32].copy_from_slice(ecdh_ss);
    ikm[32..64].copy_from_slice(kem_ss);
    ikm[64..].copy_from_slice(channel_key);

    // info = peer_id_a || peer_id_b || tunnel_epoch.
    let mut info = [0u8; 72];
    info[..64].copy_from_slice(&sorted_peer_ids(my_peer_id, their_peer_id));
    info[64..].copy_from_slice(&encode_tunnel_epoch(epoch));

    // HKDF-SHA512 with the §5.2 salt; SHA-512 matches the MI-PQXDH-1 hash.
    let hk = Hkdf::<Sha512>::new(Some(TUNNEL_PSK_SALT), &*ikm);
    let mut psk = Zeroizing::new([0u8; TUNNEL_PSK_LEN]);
    // Expand to the 32-byte PSK; the only failure mode is an oversized
    // request, which a fixed 32-byte output can never trigger, but the
    // error is still surfaced as a typed error rather than unwrapped.
    hk.expand(&info, &mut *psk)
        .map_err(|_| ChannelKeyError::HkdfExpand)?;

    Ok(psk)
}

#[derive(Debug, thiserror::Error)]
// ChannelKeyError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ChannelKeyError {
    #[error("HKDF expansion failed")]
    HkdfExpand,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_derivation() {
        // Alice and Bob should derive the same channel key
        let alice_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let alice_pub = X25519Public::from(&alice_secret);
        let alice_pid = PeerId([0x01; 32]);

        let bob_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let bob_pub = X25519Public::from(&bob_secret);
        let bob_pid = PeerId([0x02; 32]);

        let key_alice = derive_channel_key(&alice_secret, &bob_pub, &alice_pid, &bob_pid).unwrap();
        let key_bob = derive_channel_key(&bob_secret, &alice_pub, &bob_pid, &alice_pid).unwrap();

        assert_eq!(*key_alice, *key_bob);
    }

    #[test]
    fn test_different_peers_different_keys() {
        let secret = X25519Secret::random_from_rng(rand_core::OsRng);

        let peer_a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let peer_a_pub = X25519Public::from(&peer_a_secret);
        let peer_a_pid = PeerId([0x01; 32]);

        let peer_b_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let peer_b_pub = X25519Public::from(&peer_b_secret);
        let peer_b_pid = PeerId([0x02; 32]);

        let my_pid = PeerId([0x03; 32]);

        let key_a = derive_channel_key(&secret, &peer_a_pub, &my_pid, &peer_a_pid).unwrap();
        let key_b = derive_channel_key(&secret, &peer_b_pub, &my_pid, &peer_b_pid).unwrap();

        assert_ne!(*key_a, *key_b);
    }

    #[test]
    fn test_deterministic() {
        let a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let b_pub = X25519Public::from(&X25519Secret::random_from_rng(rand_core::OsRng));
        let a_pid = PeerId([0x01; 32]);
        let b_pid = PeerId([0x02; 32]);

        let key1 = derive_channel_key(&a_secret, &b_pub, &a_pid, &b_pid).unwrap();
        let key2 = derive_channel_key(&a_secret, &b_pub, &a_pid, &b_pid).unwrap();

        assert_eq!(*key1, *key2);
    }

    // -----------------------------------------------------------------------
    // Tunnel PSK (§5.2)
    // -----------------------------------------------------------------------

    /// Fixed inputs shared by the tunnel PSK tests.
    fn psk_inputs() -> ([u8; 32], [u8; 32], [u8; 32], PeerId, PeerId) {
        (
            [0x11; 32],       // ecdh_ss
            [0x22; 32],       // kem_ss
            [0x33; 32],       // channel_key
            PeerId([0x01; 32]), // peer a
            PeerId([0x02; 32]), // peer b
        )
    }

    /// Same inputs, same epoch: the derivation is a pure function.
    #[test]
    fn test_tunnel_psk_deterministic() {
        let (e, k, c, a, b) = psk_inputs();
        let psk1 = derive_tunnel_psk(&e, &k, &c, &a, &b, 7).unwrap();
        let psk2 = derive_tunnel_psk(&e, &k, &c, &a, &b, 7).unwrap();
        assert_eq!(*psk1, *psk2);
    }

    /// Initiator and responder order the peer ids differently but must land
    /// on the same PSK, otherwise the re-handshake after agreement fails.
    #[test]
    fn test_tunnel_psk_symmetric_in_peer_order() {
        let (e, k, c, a, b) = psk_inputs();
        let psk_ab = derive_tunnel_psk(&e, &k, &c, &a, &b, 1).unwrap();
        let psk_ba = derive_tunnel_psk(&e, &k, &c, &b, &a, 1).unwrap();
        assert_eq!(*psk_ab, *psk_ba);
    }

    /// Every epoch must yield a distinct PSK even when the shared secrets
    /// are unchanged: a rotation that reused a PSK would defeat its purpose.
    #[test]
    fn test_tunnel_psk_differs_per_epoch() {
        let (e, k, c, a, b) = psk_inputs();
        let mut seen = std::collections::HashSet::new();
        for epoch in 0u64..16 {
            let psk = derive_tunnel_psk(&e, &k, &c, &a, &b, epoch).unwrap();
            assert!(seen.insert(*psk), "epoch {epoch} repeated a PSK");
        }
        // Adjacent large epochs must also differ (no prefix aliasing).
        let hi = derive_tunnel_psk(&e, &k, &c, &a, &b, u64::MAX).unwrap();
        let hi_minus = derive_tunnel_psk(&e, &k, &c, &a, &b, u64::MAX - 1).unwrap();
        assert_ne!(*hi, *hi_minus);
    }

    /// Each of the three ikm components must influence the output: a PSK
    /// that ignored `kem_ss` would silently lose its post-quantum margin,
    /// and one that ignored `channel_key` would lose relationship binding.
    #[test]
    fn test_tunnel_psk_every_input_matters() {
        let (e, k, c, a, b) = psk_inputs();
        let base = derive_tunnel_psk(&e, &k, &c, &a, &b, 3).unwrap();
        let other_e = derive_tunnel_psk(&[0x44; 32], &k, &c, &a, &b, 3).unwrap();
        let other_k = derive_tunnel_psk(&e, &[0x44; 32], &c, &a, &b, 3).unwrap();
        let other_c = derive_tunnel_psk(&e, &k, &[0x44; 32], &a, &b, 3).unwrap();
        let other_peer = derive_tunnel_psk(&e, &k, &c, &a, &PeerId([0x03; 32]), 3).unwrap();
        assert_ne!(*base, *other_e);
        assert_ne!(*base, *other_k);
        assert_ne!(*base, *other_c);
        assert_ne!(*base, *other_peer);
    }

    /// Pinned vector for the §21.6.4 manifest.  Any change to the salt, the
    /// info layout, the epoch encoding, or the hash breaks this test, which
    /// is the point: the derivation is a wire-compatibility commitment.
    #[test]
    fn test_tunnel_psk_vector() {
        let (e, k, c, a, b) = psk_inputs();
        let psk = derive_tunnel_psk(&e, &k, &c, &a, &b, 1).unwrap();
        assert_eq!(
            hex::encode(*psk),
            "c184b8b33b87465cd077461bdc589730a14a14e55ecc30274e19d4db1f484ca2"
        );
    }

    /// Epoch encoding is fixed-width big-endian.
    #[test]
    fn test_epoch_encoding() {
        assert_eq!(encode_tunnel_epoch(0), [0u8; 8]);
        assert_eq!(encode_tunnel_epoch(1), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(encode_tunnel_epoch(0x0102030405060708), [1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
