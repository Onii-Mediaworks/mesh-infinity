//! Layer 3 — Masks (§3.1.3, §17.2)
//!
//! Masks are contextual presentations derived from the self.
//! Each mask has its own keypair, address, profile, and group memberships.
//!
//! Types:
//! - Public mask: handles public-facing operations (endorsements, public profile)
//! - Regular masks: per-relationship or per-context presentations
//! - Anonymous masks: architecturally isolated from self (§9.5)
//!
//! Relationship-specific mask keys are derived per-peer for Step 3 signing (§7.2):
//! ```text
//! rel_key = HKDF-SHA256(
//!     salt = mask_ed25519_secret,
//!     ikm  = "meshinfinity-rel-mask-v1" || min(my_peer_id, their_peer_id)
//!                                       || max(my_peer_id, their_peer_id),
//!     len  = 32
//! )
//! ```

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use super::peer_id::PeerId;

/// Domain separator for relationship-specific mask key derivation.
const REL_MASK_DOMAIN: &[u8] = b"meshinfinity-rel-mask-v1";

/// A mask — a contextual identity presentation.
pub struct Mask {
    /// Unique mask identifier
    pub id: MaskId,
    /// Ed25519 signing key for this mask
    pub signing_key: SigningKey,
    /// X25519 secret for DH (preauth, channel key derivation)
    pub x25519_secret: X25519Secret,
    /// Derived public keys
    pub ed25519_pub: [u8; 32],
    pub x25519_pub: X25519Public,
    /// Display name for this mask
    pub name: String,
    /// Avatar color index (0-7, from kMaskAvatarColors)
    pub avatar_color: u8,
    /// Whether this is the public mask
    pub is_public: bool,
    /// Whether this is an anonymous mask (isolated from self)
    pub is_anonymous: bool,
}

/// Mask identifier (UUID-like, 16 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct MaskId(pub [u8; 16]);

impl MaskId {
    /// Generate a random mask ID.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut bytes);
        MaskId(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for MaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

use rand_core::RngCore;

/// Domain separator for mask Ed25519 key derivation from self.
const MASK_ED25519_DOMAIN: &[u8] = b"meshinfinity-mask-ed25519-v1";
/// Domain separator for mask X25519 key derivation from self.
const MASK_X25519_DOMAIN: &[u8] = b"meshinfinity-mask-x25519-v1";

impl Mask {
    /// Derive a mask's keypairs from the self identity keys via HKDF-SHA256.
    ///
    /// This is the correct derivation path for all non-anonymous masks (§3.1.3, §17.2).
    /// The mask_id acts as the salt, ensuring each mask has distinct keys.
    /// Knowing a mask's keypair reveals nothing about the self identity keys (HKDF is one-way).
    ///
    /// Derivation:
    /// ```text
    /// mask_ed25519 = HKDF-SHA256(salt=mask_id, ikm=self_ed25519_secret, info="meshinfinity-mask-ed25519-v1")
    /// mask_x25519  = HKDF-SHA256(salt=mask_id, ikm=self_x25519_secret,  info="meshinfinity-mask-x25519-v1")
    /// ```
    pub fn derive_from_self(
        self_ed25519: &SigningKey,
        self_x25519: &X25519Secret,
        mask_id: MaskId,
        name: String,
        avatar_color: u8,
        is_public: bool,
    ) -> Self {
        // Ed25519 mask key
        let hk_ed = Hkdf::<Sha256>::new(Some(&mask_id.0), &self_ed25519.to_bytes());
        let mut ed_secret_bytes = [0u8; 32];
        hk_ed.expand(MASK_ED25519_DOMAIN, &mut ed_secret_bytes)
            .expect("HKDF expand for 32 bytes");
        let signing_key = SigningKey::from_bytes(&ed_secret_bytes);
        let ed25519_pub = signing_key.verifying_key().to_bytes();
        ed_secret_bytes.iter_mut().for_each(|b| *b = 0); // zeroize

        // X25519 mask key
        let hk_x = Hkdf::<Sha256>::new(Some(&mask_id.0), &self_x25519.to_bytes());
        let mut x_secret_bytes = [0u8; 32];
        hk_x.expand(MASK_X25519_DOMAIN, &mut x_secret_bytes)
            .expect("HKDF expand for 32 bytes");
        let x25519_secret = X25519Secret::from(x_secret_bytes);
        let x25519_pub = X25519Public::from(&x25519_secret);
        x_secret_bytes.iter_mut().for_each(|b| *b = 0); // zeroize

        Self {
            id: mask_id,
            signing_key,
            x25519_secret,
            ed25519_pub,
            x25519_pub,
            name,
            avatar_color: avatar_color % 8,
            is_public,
            is_anonymous: false, // derived masks are never anonymous
        }
    }

    /// Create a new anonymous mask with fresh independent keypairs.
    ///
    /// Anonymous masks are architecturally isolated from self (§9.5).
    /// They must NOT be derived from the self identity — they use fresh random keys.
    pub fn generate_anonymous(name: String, avatar_color: u8) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_pub = signing_key.verifying_key().to_bytes();
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        let x25519_pub = X25519Public::from(&x25519_secret);

        Self {
            id: MaskId::random(),
            signing_key,
            x25519_secret,
            ed25519_pub,
            x25519_pub,
            name,
            avatar_color: avatar_color % 8,
            is_public: false,
            is_anonymous: true,
        }
    }

    /// Create a new non-anonymous mask with fresh independent keypairs.
    ///
    /// **Prefer `derive_from_self` when the self identity is available.**
    /// This constructor is provided for cases where the self identity is not
    /// available (e.g., tests, or the public mask on first boot before HKDF).
    /// In production code, call `derive_from_self` with the loaded SelfIdentity.
    pub fn generate(name: String, avatar_color: u8, is_public: bool, is_anonymous: bool) -> Self {
        if is_anonymous {
            return Self::generate_anonymous(name, avatar_color);
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_pub = signing_key.verifying_key().to_bytes();
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        let x25519_pub = X25519Public::from(&x25519_secret);

        Self {
            id: MaskId::random(),
            signing_key,
            x25519_secret,
            ed25519_pub,
            x25519_pub,
            name,
            avatar_color: avatar_color % 8,
            is_public,
            is_anonymous,
        }
    }

    /// Get the peer ID for this mask.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_ed25519_pub(&self.ed25519_pub)
    }

    /// Derive a relationship-specific signing key for a specific peer.
    ///
    /// This key is used for Step 3 outer signing (§7.2) — the signature
    /// is inside Step 4 encryption, so only the recipient sees it.
    /// Compromising one relationship key reveals nothing about other
    /// relationships or the base mask key.
    pub fn relationship_signing_key(&self, their_peer_id: &PeerId) -> SigningKey {
        let my_pid = self.peer_id();

        // Lexicographic sort for deterministic derivation
        let (min_pid, max_pid) = if my_pid.0 < their_peer_id.0 {
            (&my_pid.0[..], &their_peer_id.0[..])
        } else {
            (&their_peer_id.0[..], &my_pid.0[..])
        };

        // HKDF derivation
        let mut ikm = Vec::with_capacity(REL_MASK_DOMAIN.len() + 64);
        ikm.extend_from_slice(REL_MASK_DOMAIN);
        ikm.extend_from_slice(min_pid);
        ikm.extend_from_slice(max_pid);

        let hk = Hkdf::<Sha256>::new(Some(&self.signing_key.to_bytes()), &ikm);
        let mut derived = [0u8; 32];
        hk.expand(b"meshinfinity-rel-key-v1", &mut derived)
            .expect("HKDF expand for 32 bytes");

        SigningKey::from_bytes(&derived)
    }

    /// Get serializable metadata for this mask (non-secret fields).
    pub fn metadata(&self) -> MaskMetadata {
        MaskMetadata {
            id: self.id,
            name: self.name.clone(),
            avatar_color: self.avatar_color,
            is_public: self.is_public,
            is_anonymous: self.is_anonymous,
            ed25519_pub: hex::encode(self.ed25519_pub),
            x25519_pub: hex::encode(self.x25519_pub.as_bytes()),
            peer_id: self.peer_id().to_hex(),
        }
    }
}

/// Serializable mask metadata (no secret keys).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MaskMetadata {
    pub id: MaskId,
    pub name: String,
    pub avatar_color: u8,
    pub is_public: bool,
    pub is_anonymous: bool,
    pub ed25519_pub: String,
    pub x25519_pub: String,
    pub peer_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mask() {
        let mask = Mask::generate("Personal".into(), 0, false, false);
        assert_eq!(mask.name, "Personal");
        assert!(!mask.is_public);
        assert!(!mask.is_anonymous);
    }

    #[test]
    fn test_peer_id_deterministic() {
        let mask = Mask::generate("Test".into(), 1, false, false);
        let pid1 = mask.peer_id();
        let pid2 = mask.peer_id();
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn test_relationship_key_deterministic() {
        let mask = Mask::generate("Test".into(), 0, false, false);
        let their_pid = PeerId::from_ed25519_pub(&[0x42u8; 32]);

        let rk1 = mask.relationship_signing_key(&their_pid);
        let rk2 = mask.relationship_signing_key(&their_pid);

        assert_eq!(rk1.to_bytes(), rk2.to_bytes());
    }

    #[test]
    fn test_relationship_key_per_peer() {
        let mask = Mask::generate("Test".into(), 0, false, false);
        let peer_a = PeerId::from_ed25519_pub(&[0x01u8; 32]);
        let peer_b = PeerId::from_ed25519_pub(&[0x02u8; 32]);

        let rk_a = mask.relationship_signing_key(&peer_a);
        let rk_b = mask.relationship_signing_key(&peer_b);

        // Different peers → different relationship keys
        assert_ne!(rk_a.to_bytes(), rk_b.to_bytes());
    }

    #[test]
    fn test_relationship_key_symmetric() {
        // Both sides should derive the same relationship key
        let mask_alice = Mask::generate("Alice".into(), 0, false, false);
        let mask_bob = Mask::generate("Bob".into(), 1, false, false);

        let rk_alice = mask_alice.relationship_signing_key(&mask_bob.peer_id());
        let rk_bob = mask_bob.relationship_signing_key(&mask_alice.peer_id());

        // These won't be equal because different base mask keys — that's correct.
        // Each side has their OWN relationship key for signing.
        // The recipient verifies with the sender's relationship verifying key.
        assert_ne!(rk_alice.to_bytes(), rk_bob.to_bytes());
    }

    #[test]
    fn test_avatar_color_wraps() {
        let mask = Mask::generate("Test".into(), 15, false, false);
        assert!(mask.avatar_color < 8);
    }

    #[test]
    fn test_metadata_serialization() {
        let mask = Mask::generate("Test".into(), 2, true, false);
        let meta = mask.metadata();
        let json = serde_json::to_string(&meta).unwrap();
        let recovered: MaskMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.name, "Test");
        assert!(recovered.is_public);
    }

    #[test]
    fn test_anonymous_mask() {
        let mask = Mask::generate("Anon".into(), 0, false, true);
        assert!(mask.is_anonymous);
        assert_ne!(mask.ed25519_pub, [0u8; 32]);
    }

    #[test]
    fn test_derive_from_self_deterministic() {
        let self_id = super::super::self_identity::SelfIdentity::generate(None);
        let mask_id = MaskId([0x01u8; 16]);

        let m1 = Mask::derive_from_self(
            &self_id.ed25519_signing, &self_id.x25519_secret,
            mask_id, "Public".into(), 0, true,
        );
        let m2 = Mask::derive_from_self(
            &self_id.ed25519_signing, &self_id.x25519_secret,
            mask_id, "Public".into(), 0, true,
        );
        // Same self + same mask_id → same keypairs
        assert_eq!(m1.ed25519_pub, m2.ed25519_pub);
        assert_eq!(m1.x25519_pub.as_bytes(), m2.x25519_pub.as_bytes());
    }

    #[test]
    fn test_derive_different_masks_have_different_keys() {
        let self_id = super::super::self_identity::SelfIdentity::generate(None);
        let id_a = MaskId([0x01u8; 16]);
        let id_b = MaskId([0x02u8; 16]);

        let ma = Mask::derive_from_self(
            &self_id.ed25519_signing, &self_id.x25519_secret,
            id_a, "A".into(), 0, false,
        );
        let mb = Mask::derive_from_self(
            &self_id.ed25519_signing, &self_id.x25519_secret,
            id_b, "B".into(), 0, false,
        );
        assert_ne!(ma.ed25519_pub, mb.ed25519_pub,
            "Different mask_ids must produce different keypairs");
    }

    #[test]
    fn test_derived_mask_differs_from_self() {
        let self_id = super::super::self_identity::SelfIdentity::generate(None);
        let mask = Mask::derive_from_self(
            &self_id.ed25519_signing, &self_id.x25519_secret,
            MaskId([0xAAu8; 16]), "Test".into(), 0, false,
        );
        // Mask key must differ from self key (HKDF is one-way but produces distinct output)
        assert_ne!(mask.ed25519_pub, self_id.ed25519_pub,
            "Mask keypair must differ from self keypair");
        assert!(!mask.is_anonymous);
    }

    #[test]
    fn test_anonymous_mask_is_independent() {
        // Anonymous masks should not be derived from self — they use fresh keys
        let m1 = Mask::generate_anonymous("Anon1".into(), 0);
        let m2 = Mask::generate_anonymous("Anon2".into(), 0);
        assert!(m1.is_anonymous);
        assert!(m2.is_anonymous);
        assert_ne!(m1.ed25519_pub, m2.ed25519_pub, "Each anon mask is unique");
    }
}
