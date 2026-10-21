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
// REL_MASK_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// REL_MASK_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// REL_MASK_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
const REL_MASK_DOMAIN: &[u8] = b"meshinfinity-rel-mask-v1";

/// Derive the relationship-specific Ed25519 signing key that `base` uses
/// toward `their_peer_id` (§7.2 Step 3 derivation; §3.1.6 relationship role).
///
/// ```text
/// rel_key = HKDF-SHA256(
///     salt = base_secret,
///     ikm  = "meshinfinity-rel-mask-v1" || min(my_pid, their_pid) || max(my_pid, their_pid),
///     len  = 32
/// )
/// ```
///
/// Deterministic per (base key, peer) pair, so the §7.2 Step 3 outer
/// signature and the §7.2 Step 1 untrusted-message signature toward one
/// peer both come from this one key, and a key change of `base` (§4.6)
/// re-derives it.  One-way: compromising a relationship key reveals nothing
/// about `base` or about any other relationship.  This is the single
/// derivation for every mask — the self's public mask in the messaging
/// service calls it directly, every other mask through
/// `Mask::relationship_signing_key`.
///
/// The result is never the stable key itself: a relationship key equal to
/// `base` would be the exact misuse §3.1.6 forbids, and HKDF output cannot
/// collide with its own salt except by negligible chance.
pub fn derive_relationship_signing_key(
    base: &SigningKey,
    my_peer_id: &PeerId,
    their_peer_id: &PeerId,
) -> SigningKey {
    // Lexicographic sort so both parties derive the same ikm regardless of
    // who initiated; the base key is what makes the two results differ.
    let (min_pid, max_pid) = if my_peer_id.0 < their_peer_id.0 {
        (&my_peer_id.0[..], &their_peer_id.0[..])
    } else {
        (&their_peer_id.0[..], &my_peer_id.0[..])
    };

    // ikm = domain || min(pid) || max(pid), exactly as §7.2 writes it.
    let mut ikm = Vec::with_capacity(REL_MASK_DOMAIN.len() + 64);
    // Append the domain label first so the derivation is bound to its use.
    ikm.extend_from_slice(REL_MASK_DOMAIN);
    // Then the ordered peer-id pair.
    ikm.extend_from_slice(min_pid);
    ikm.extend_from_slice(max_pid);

    // The stable mask secret is the HKDF salt (one-way), the pair is the ikm.
    let hk = Hkdf::<Sha256>::new(Some(&base.to_bytes()), &ikm);
    let mut derived = [0u8; 32];
    // Infallible: HKDF-SHA256 expand with 32-byte output never exceeds the
    // 255 × hash_len ceiling. This is a compile-time-verifiable constant.
    hk.expand(b"meshinfinity-rel-key-v1", &mut derived).expect(
        "HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len",
    );

    // The derived 32 bytes are the Ed25519 seed of the relationship key.
    SigningKey::from_bytes(&derived)
}

/// A mask — a contextual identity presentation.
// Mask — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// Mask — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// Mask — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct Mask {
    /// Unique mask identifier
    pub id: MaskId,
    /// Ed25519 signing key for this mask
    pub signing_key: SigningKey,
    /// X25519 secret for DH (preauth, channel key derivation)
    pub x25519_secret: X25519Secret,
    /// Derived public keys
    pub ed25519_pub: [u8; 32],
    /// The x25519 pub for this instance.
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
// MaskId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MaskId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MaskId — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MaskId(pub [u8; 16]);

// MaskId implementation — core protocol logic.
// MaskId implementation — core protocol logic.
// MaskId implementation — core protocol logic.
impl MaskId {
    /// Generate a random mask ID.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        // OS-provided cryptographic random number generator.
        rand_core::OsRng.fill_bytes(&mut bytes);
        // Execute this step in the protocol sequence.
        MaskId(bytes)
    }

    pub fn to_hex(&self) -> String {
        // Invoke the associated function.
        hex::encode(self.0)
    }
}

// Implement Display for MaskId.
// Implement Display for MaskId.
// Implement Display for MaskId.
impl std::fmt::Display for MaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format the output for display or logging.
        write!(f, "{}", self.to_hex())
    }
}

use rand_core::RngCore;

/// Domain separator for mask Ed25519 key derivation from self.
// MASK_ED25519_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MASK_ED25519_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MASK_ED25519_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
const MASK_ED25519_DOMAIN: &[u8] = b"meshinfinity-mask-ed25519-v1";
/// Domain separator for mask X25519 key derivation from self.
// MASK_X25519_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MASK_X25519_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MASK_X25519_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
const MASK_X25519_DOMAIN: &[u8] = b"meshinfinity-mask-x25519-v1";

// Mask implementation — core protocol logic.
// Mask implementation — core protocol logic.
// Mask implementation — core protocol logic.
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
        // Ed25519 digital signature.
        self_ed25519: &SigningKey,
        // Elliptic curve Diffie-Hellman key agreement.
        self_x25519: &X25519Secret,
        mask_id: MaskId,
        name: String,
        avatar_color: u8,
        is_public: bool,
    ) -> Self {
        // Ed25519 mask key
        let hk_ed = Hkdf::<Sha256>::new(Some(&mask_id.0), &self_ed25519.to_bytes());
        let mut ed_secret_bytes = [0u8; 32];
        // Infallible: HKDF-SHA256 expand fails only when the output length exceeds
        // 255 × 32 = 8160 bytes. We request exactly 32 bytes, so this cannot fail.
        // HKDF expand to the target key length.
        // HKDF expand to the target key length.
        // HKDF expand to the target key length.
        hk_ed.expand(MASK_ED25519_DOMAIN, &mut ed_secret_bytes)
            .expect("HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len");
        let signing_key = SigningKey::from_bytes(&ed_secret_bytes);
        let ed25519_pub = signing_key.verifying_key().to_bytes();
        // Securely erase key material to prevent forensic recovery.
        ed_secret_bytes.iter_mut().for_each(|b| *b = 0); // zeroize

        // X25519 mask key
        let hk_x = Hkdf::<Sha256>::new(Some(&mask_id.0), &self_x25519.to_bytes());
        let mut x_secret_bytes = [0u8; 32];
        // Infallible: same reasoning as the Ed25519 derivation above — 32-byte output
        // is always within the HKDF-SHA256 legal range of 1..=8160 bytes.
        // HKDF expand to the target key length.
        // HKDF expand to the target key length.
        // HKDF expand to the target key length.
        hk_x.expand(MASK_X25519_DOMAIN, &mut x_secret_bytes)
            .expect("HKDF-SHA256 expand to 32 bytes is infallible — output length never exceeds 255 × hash_len");
        let x25519_secret = X25519Secret::from(x_secret_bytes);
        let x25519_pub = X25519Public::from(&x25519_secret);
        // Securely erase key material to prevent forensic recovery.
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
            // Invoke the associated function.
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
            // Return the result to the caller.
            return Self::generate_anonymous(name, avatar_color);
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_pub = signing_key.verifying_key().to_bytes();
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        let x25519_pub = X25519Public::from(&x25519_secret);

        Self {
            // Invoke the associated function.
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
        // Invoke the associated function.
        PeerId::from_ed25519_pub(&self.ed25519_pub)
    }

    /// Derive this mask's relationship-specific signing key toward one peer.
    ///
    /// Thin wrapper over `derive_relationship_signing_key` with this mask's
    /// own key and peer id; see that function for the derivation and the
    /// §3.1.6 role of the result.
    pub fn relationship_signing_key(&self, their_peer_id: &PeerId) -> SigningKey {
        // Identify ourselves for the ordered (min, max) peer-id pair.
        let my_pid = self.peer_id();
        // Delegate: one derivation for every mask, including the self's.
        derive_relationship_signing_key(&self.signing_key, &my_pid, their_peer_id)
    }

    /// Get serializable metadata for this mask (non-secret fields).
    pub fn metadata(&self) -> MaskMetadata {
        MaskMetadata {
            // Chain the operation on the intermediate result.
            id: self.id,
            name: self.name.clone(),
            avatar_color: self.avatar_color,
            is_public: self.is_public,
            is_anonymous: self.is_anonymous,
            // Invoke the associated function.
            ed25519_pub: hex::encode(self.ed25519_pub),
            // Extract the raw byte representation for wire encoding.
            x25519_pub: hex::encode(self.x25519_pub.as_bytes()),
            peer_id: self.peer_id().to_hex(),
        }
    }
}

/// Serializable mask metadata (no secret keys).
#[derive(Serialize, Deserialize, Debug, Clone)]
// MaskMetadata — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MaskMetadata — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MaskMetadata {
    /// The id for this instance.
    pub id: MaskId,
    /// The name for this instance.
    pub name: String,
    /// The avatar color for this instance.
    pub avatar_color: u8,
    /// The is public for this instance.
    pub is_public: bool,
    /// The is anonymous for this instance.
    pub is_anonymous: bool,
    /// The ed25519 pub for this instance.
    pub ed25519_pub: String,
    /// The x25519 pub for this instance.
    pub x25519_pub: String,
    /// The peer id for this instance.
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
            &self_id.ed25519_signing,
            &self_id.x25519_secret,
            mask_id,
            "Public".into(),
            0,
            true,
        );
        let m2 = Mask::derive_from_self(
            &self_id.ed25519_signing,
            &self_id.x25519_secret,
            mask_id,
            "Public".into(),
            0,
            true,
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
            &self_id.ed25519_signing,
            &self_id.x25519_secret,
            id_a,
            "A".into(),
            0,
            false,
        );
        let mb = Mask::derive_from_self(
            &self_id.ed25519_signing,
            &self_id.x25519_secret,
            id_b,
            "B".into(),
            0,
            false,
        );
        assert_ne!(
            ma.ed25519_pub, mb.ed25519_pub,
            "Different mask_ids must produce different keypairs"
        );
    }

    #[test]
    fn test_derived_mask_differs_from_self() {
        let self_id = super::super::self_identity::SelfIdentity::generate(None);
        let mask = Mask::derive_from_self(
            &self_id.ed25519_signing,
            &self_id.x25519_secret,
            MaskId([0xAAu8; 16]),
            "Test".into(),
            0,
            false,
        );
        // Mask key must differ from self key (HKDF is one-way but produces distinct output)
        assert_ne!(
            mask.ed25519_pub, self_id.ed25519_pub,
            "Mask keypair must differ from self keypair"
        );
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
