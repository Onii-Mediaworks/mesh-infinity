//! Layer 1 — Mesh Identity (§3.1.1)
//!
//! The mesh identity is the node's always-available presence on the network.
//! - Generated fresh on each app install — never reused, never restored from backup
//! - Holds WireGuard keypairs for tunnel participation
//! - Cannot decrypt message content or access the trust graph
//! - Participates in tunnel coordination gossip (§6.10)

use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Layer 1 mesh identity — WireGuard keypair for mesh participation.
///
/// The mesh identity is the node's always-on presence. It uses X25519
/// for DH key agreement (WireGuard tunnels). Generated fresh on each
/// install — never restored from backup.
pub struct MeshIdentity {
    /// The raw secret key bytes, retained for serialization.
    ///
    /// X25519Secret doesn't expose its bytes in newer versions of
    /// x25519-dalek, so we store the original entropy separately.
    /// This is zeroized on Drop via our custom implementation.
    secret_raw: [u8; 32],

    /// WireGuard X25519 secret key (derived from secret_raw).
    secret: X25519Secret,

    /// WireGuard X25519 public key (derived from secret).
    pub public: X25519Public,
}

impl MeshIdentity {
    /// Generate a fresh mesh identity (done once at install).
    ///
    /// Uses the OS CSPRNG for entropy. The generated identity is
    /// unique and unrelated to any previous identity.
    pub fn generate() -> Self {
        // Generate 32 bytes of random entropy using the OS CSPRNG.
        let mut secret_raw = [0u8; 32];
        rand::fill(&mut secret_raw);

        // Build the X25519 keypair from the raw entropy.
        let secret = X25519Secret::from(secret_raw);
        let public = X25519Public::from(&secret);

        Self {
            secret_raw,
            secret,
            public,
        }
    }

    /// Reconstruct a mesh identity from previously stored secret bytes.
    ///
    /// Used when loading the identity from the platform keystore
    /// after device unlock.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = X25519Secret::from(bytes);
        let public = X25519Public::from(&secret);
        Self {
            secret_raw: bytes,
            secret,
            public,
        }
    }

    /// Get the public key bytes (for WireGuard config, tunnel coordination).
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Access the secret key for DH operations (WireGuard handshakes).
    pub fn secret(&self) -> &X25519Secret {
        &self.secret
    }

    /// Serialize the secret key for keystore storage.
    ///
    /// This should be stored at AfterFirstUnlock accessibility (§3.6.3).
    /// The returned bytes can be passed to `from_secret_bytes()` to
    /// reconstruct the identity.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret_raw
    }
}

impl Drop for MeshIdentity {
    fn drop(&mut self) {
        // Zeroize the raw secret bytes. X25519Secret handles its own zeroize.
        // We use volatile writes to prevent the compiler from optimizing
        // the zeroing away.
        for byte in self.secret_raw.iter_mut() {
            // SAFETY: `byte` is a valid mutable reference to a u8 within the
            // `secret_raw` Vec; write_volatile requires only that the pointer
            // is valid for a single-byte write, which a &mut u8 guarantees.
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_unique() {
        let id1 = MeshIdentity::generate();
        let id2 = MeshIdentity::generate();
        assert_ne!(id1.public_bytes(), id2.public_bytes());
    }

    #[test]
    fn test_public_key_stable() {
        let id = MeshIdentity::generate();
        let pub1 = id.public_bytes();
        let pub2 = id.public_bytes();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_secret_bytes_roundtrip() {
        // Generate an identity, serialize secret bytes, reconstruct.
        let id1 = MeshIdentity::generate();
        let secret = id1.secret_bytes();
        let pubkey = id1.public_bytes();

        // Secret bytes should NOT equal public bytes.
        assert_ne!(secret, pubkey);

        // Reconstruct from secret bytes.
        let id2 = MeshIdentity::from_secret_bytes(secret);

        // Public keys must match — same secret produces same public key.
        assert_eq!(id2.public_bytes(), pubkey);

        // Secret bytes must match.
        assert_eq!(id2.secret_bytes(), secret);
    }
}
