//! Trusted Channel Key Derivation (§3.2)
//!
//! Trusted-channel symmetric keys are derived from X25519 DH between two peers:
//!
//! ```text
//! shared_secret = X25519(my_x25519_secret, their_x25519_public)
//! channel_key   = HKDF-SHA256(shared_secret, salt="meshinfinity-channel-v1",
//!                              info=peer_id_a || peer_id_b)
//! ```
//!
//! peer_id_a and peer_id_b are sorted lexicographically so both sides derive
//! the same key. Used as WireGuard PSK for Level 6+ connections.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
// Securely erase key material to prevent forensic recovery.
use zeroize::Zeroizing;

use crate::identity::peer_id::PeerId;

/// Domain separator salt for channel key derivation.
// CHANNEL_SALT — protocol constant.
// Defined by the spec; must not change without a version bump.
// CHANNEL_SALT — protocol constant.
// Defined by the spec; must not change without a version bump.
// CHANNEL_SALT — protocol constant.
// Defined by the spec; must not change without a version bump.
// CHANNEL_SALT — protocol constant.
// Defined by the spec; must not change without a version bump.
const CHANNEL_SALT: &[u8] = b"meshinfinity-channel-v1";

/// Derive the trusted-channel symmetric key (WireGuard PSK) between two peers.
///
/// Both sides independently derive the same key using their own secret
/// and the other's public key. The peer IDs are sorted lexicographically
/// to ensure deterministic derivation regardless of who initiates.
pub fn derive_channel_key(
    // Elliptic curve Diffie-Hellman key agreement.
    my_x25519_secret: &X25519Secret,
    // Elliptic curve Diffie-Hellman key agreement.
    their_x25519_pub: &X25519Public,
    my_peer_id: &PeerId,
    their_peer_id: &PeerId,
) -> Result<Zeroizing<[u8; 32]>, ChannelKeyError> {
    // X25519 DH
    let shared_secret = my_x25519_secret.diffie_hellman(their_x25519_pub);

    // Sort peer IDs lexicographically for deterministic info
    let (id_a, id_b) = if my_peer_id.0 < their_peer_id.0 {
        // Extract the raw byte representation for wire encoding.
        (my_peer_id.as_bytes(), their_peer_id.as_bytes())
    } else {
        // Extract the raw byte representation for wire encoding.
        (their_peer_id.as_bytes(), my_peer_id.as_bytes())
    };

    // Pre-allocate the buffer to avoid repeated reallocations.
    let mut info = Vec::with_capacity(64);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    info.extend_from_slice(id_a);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    info.extend_from_slice(id_b);

    // HKDF-SHA256
    let hk = Hkdf::<Sha256>::new(Some(CHANNEL_SALT), shared_secret.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(&info, &mut *key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| ChannelKeyError::HkdfExpand)?;

    Ok(key)
}

#[derive(Debug, thiserror::Error)]
// ChannelKeyError — variant enumeration.
// Match exhaustively to handle every protocol state.
// ChannelKeyError — variant enumeration.
// Match exhaustively to handle every protocol state.
// ChannelKeyError — variant enumeration.
// Match exhaustively to handle every protocol state.
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
}
