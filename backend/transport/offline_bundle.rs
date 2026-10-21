//! Offline Bundle: encrypt-for-recipient and decode paths (§5.28)
//!
//! # What This Module Does
//!
//! `offline.rs` handles the raw `.mib` wire format and filesystem I/O.
//! This module adds the cryptographic layer on top:
//!
//! - **Encrypt for recipient**: wrap a bundle for a specific peer using
//!   an ephemeral X25519 key exchange + ChaCha20-Poly1305 AEAD.
//! - **Decrypt from sender**: open an encrypted bundle given the recipient's
//!   X25519 private key.
//!
//! # Wire Format (EncryptedOfflineBundle)
//!
//! ```text
//! [ magic: [u8; 4] ]              — "MIOB" (Mesh Infinity Offline Bundle)
//! [ version: u8 ]                 — currently 1
//! [ ephemeral_pub: [u8; 32] ]     — sender's ephemeral X25519 public key
//! [ nonce: [u8; 12] ]             — ChaCha20-Poly1305 nonce
//! [ ciphertext_len: u32 ]         — big-endian byte count of ciphertext
//! [ ciphertext: [u8; len] ]       — ChaCha20-Poly1305( inner_bundle_bytes )
//! ```
//!
//! The inner plaintext is the raw `.mib` bundle produced by `build_bundle()`.
//! The AEAD key is derived from the ephemeral X25519 shared secret using HKDF-
//! SHA-256 with context label "OfflineBundleKey".
//!
//! # Security Properties
//!
//! - Forward secrecy: every bundle uses a fresh ephemeral key pair.
//! - Authenticity: ChaCha20-Poly1305 tags detect tampering.
//! - Recipient binding: only the holder of the recipient's X25519 private key
//!   can open the bundle.
//! - No sender authentication here — mesh packet signatures inside the bundle
//!   provide content authenticity per §5.28 security model.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::transport::offline::OfflineError;
use crate::transport::offline::{build_bundle, parse_bundle, ParsedBundle, RoutingMode};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes for the encrypted offline bundle wrapper.
/// "MIOB" = Mesh Infinity Offline Bundle (encrypted).
/// Distinct from "MIOT" (the inner plaintext header) so parsers can tell them apart.
pub const ENCRYPTED_BUNDLE_MAGIC: [u8; 4] = [0x4D, 0x49, 0x4F, 0x42];

/// Version byte for the encrypted wrapper format.
pub const ENCRYPTED_BUNDLE_VERSION: u8 = 1;

/// Minimum encrypted bundle bytes (magic + version + ephem_pub + nonce + ciphertext_len).
const MIN_ENCRYPTED_BUNDLE_LEN: usize = 4 + 1 + 32 + 12 + 4;

// ---------------------------------------------------------------------------
// OfflineBundle — the high-level type
// ---------------------------------------------------------------------------

/// A point-to-point offline bundle ready to write to physical media or external
/// storage (§5.28).
///
/// Created by `OfflineBundle::create_for_recipient()` and opened by
/// `OfflineBundle::open_as_recipient()`.
pub struct OfflineBundle {
    /// The full encrypted blob, ready to write to disk or pass over the FFI.
    pub encrypted_bytes: Vec<u8>,
    /// Bundle ID extracted from the inner header (set after open or create).
    pub bundle_id: [u8; 16],
}

impl OfflineBundle {
    /// Create an encrypted offline bundle for a specific recipient.
    ///
    /// `packets`: raw mesh packets to bundle (already encrypted by WireGuard /
    ///            the four-layer system — this function does NOT decrypt them).
    ///
    /// `source_id`: sender's peer ID (32 bytes), placed in the inner header.
    ///
    /// `dest_id`: recipient's peer ID (32 bytes), placed in the inner header.
    ///
    /// `recipient_x25519_pub`: recipient's X25519 public key for key agreement.
    ///
    /// Returns an `OfflineBundle` whose `encrypted_bytes` field can be written
    /// directly to `{bundle_id_hex}.mib`.
    pub fn create_for_recipient(
        packets: &[Vec<u8>],
        source_id: [u8; 32],
        dest_id: [u8; 32],
        recipient_x25519_pub: &[u8; 32],
    ) -> Result<Self, OfflineError> {
        // 1. Build random bundle ID.
        let mut bundle_id = [0u8; 16];
        OsRng.fill_bytes(&mut bundle_id);

        // 2. Build inner plaintext bundle.
        let inner = build_bundle(
            packets,
            RoutingMode::PointToPoint,
            source_id,
            Some(dest_id),
            bundle_id,
        )?;

        // 3. Seal it in the ECIES-style envelope for the recipient.
        let encrypted_bytes = seal_for_recipient(&inner, recipient_x25519_pub)?;

        Ok(Self {
            encrypted_bytes,
            bundle_id,
        })
    }

    /// Open an encrypted offline bundle using the recipient's X25519 secret key.
    ///
    /// `data`: raw bytes of the `.mib` file (the encrypted wrapper produced by
    ///         `create_for_recipient`).
    ///
    /// `recipient_x25519_secret`: the recipient's X25519 private key.
    ///
    /// Returns the parsed inner bundle on success, or an error if the wrapper
    /// is malformed, the AEAD tag is wrong, or the inner bundle is invalid.
    pub fn open_as_recipient(
        data: &[u8],
        recipient_x25519_secret: &[u8; 32],
    ) -> Result<(Self, ParsedBundle), OfflineError> {
        if data.len() < MIN_ENCRYPTED_BUNDLE_LEN {
            return Err(OfflineError::MalformedHeader("encrypted bundle too short"));
        }

        // Validate magic.
        if data[..4] != ENCRYPTED_BUNDLE_MAGIC {
            let mut found = [0u8; 4];
            found.copy_from_slice(&data[..4]);
            return Err(OfflineError::InvalidMagic(found));
        }

        // Validate version.
        if data[4] != ENCRYPTED_BUNDLE_VERSION {
            return Err(OfflineError::UnsupportedVersion(data[4]));
        }

        let mut pos = 5usize;

        // Read ephemeral public key.
        let mut eph_pub_bytes = [0u8; 32];
        eph_pub_bytes.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let eph_pub = X25519Public::from(eph_pub_bytes);

        // Read nonce.
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&data[pos..pos + 12]);
        pos += 12;

        // Read ciphertext length.
        let ct_len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if pos + ct_len > data.len() {
            return Err(OfflineError::MalformedHeader("ciphertext truncated"));
        }
        let ciphertext = &data[pos..pos + ct_len];

        // Derive shared secret via X25519.
        let recip_secret = X25519Secret::from(*recipient_x25519_secret);
        let shared = recip_secret.diffie_hellman(&eph_pub);

        // Derive AEAD key.
        let aead_key = hkdf_expand(shared.as_bytes(), b"OfflineBundleKey");

        // Decrypt.
        let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
            .map_err(|_| OfflineError::EncryptionError("key length error"))?;
        let nonce = Nonce::from(nonce_bytes);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| OfflineError::AuthenticationFailed)?;

        // Parse the inner bundle.
        let parsed = parse_bundle(&plaintext)?;
        let bundle_id = parsed.header.bundle_id;

        Ok((
            Self {
                encrypted_bytes: data.to_vec(),
                bundle_id,
            },
            parsed,
        ))
    }

    /// Returns the hex-encoded bundle ID suitable for use in filenames and
    /// external storage paths.
    pub fn id_hex(&self) -> String {
        hex::encode(self.bundle_id)
    }

    /// Returns the filename for this bundle: `meshinfinity_bundle_{id_hex}.mib`.
    pub fn filename(&self) -> String {
        format!("meshinfinity_bundle_{}.mib", self.id_hex())
    }
}

// ---------------------------------------------------------------------------
// Envelope sealing
// ---------------------------------------------------------------------------

/// Seal an already-built inner bundle for `recipient_x25519_pub`.
///
/// Produces the encrypted wrapper that `open_as_recipient` consumes:
/// magic ‖ version ‖ ephemeral X25519 public key ‖ nonce ‖ ciphertext length
/// ‖ ChaCha20-Poly1305 ciphertext.  Split out of `create_for_recipient` so
/// tests can seal a deliberately malformed inner bundle and prove the
/// recipient-side parser survives it — anyone holding the recipient's
/// *public* key can produce such an envelope, so the inner header is
/// attacker-controlled data.
pub(crate) fn seal_for_recipient(
    inner: &[u8],
    recipient_x25519_pub: &[u8; 32],
) -> Result<Vec<u8>, OfflineError> {
    // 1. Generate ephemeral X25519 key pair (fresh per bundle for forward secrecy).
    let eph_secret = X25519Secret::random_from_rng(OsRng);
    let eph_pub = X25519Public::from(&eph_secret);

    // 2. Derive shared secret via X25519 ECDH with recipient's public key.
    let recip_pub = X25519Public::from(*recipient_x25519_pub);
    let shared = eph_secret.diffie_hellman(&recip_pub);

    // 3. Derive AEAD key from shared secret via HKDF-SHA-256.
    let aead_key = hkdf_expand(shared.as_bytes(), b"OfflineBundleKey");

    // 4. Encrypt the inner bundle with ChaCha20-Poly1305 under a fresh nonce.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|_| OfflineError::EncryptionError("key length error"))?;
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, inner)
        .map_err(|_| OfflineError::EncryptionError("AEAD encrypt failed"))?;

    // 5. Assemble the encrypted wrapper.
    let mut out = Vec::with_capacity(MIN_ENCRYPTED_BUNDLE_LEN + ciphertext.len());
    out.extend_from_slice(&ENCRYPTED_BUNDLE_MAGIC);
    out.push(ENCRYPTED_BUNDLE_VERSION);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    let ct_len = ciphertext.len() as u32;
    out.extend_from_slice(&ct_len.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

// ---------------------------------------------------------------------------
// HKDF helper
// ---------------------------------------------------------------------------

fn hkdf_expand(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("HKDF expand failed — output length is valid");
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_x25519_pair() -> (X25519Secret, X25519Public) {
        let secret = X25519Secret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);
        (secret, public)
    }

    /// Byte offset of `packet_count` inside the inner header.
    const PACKET_COUNT_OFFSET: usize = 4 + 1 + 1 + 32 + 1 + 32 + 16 + 8 + 8;

    /// A correctly sealed envelope whose *inner* header claims `u32::MAX`
    /// packets.  Anyone with the recipient's public key can build this; the
    /// AEAD passes, and the inner parser must reject it instead of aborting
    /// on a ~96 GiB pre-allocation.
    #[test]
    fn open_rejects_inner_packet_count_u32_max() {
        let (recip_secret, recip_pub) = make_x25519_pair();
        let mut inner = crate::transport::offline::build_bundle(
            &[b"one".to_vec()],
            RoutingMode::PointToPoint,
            [0x01u8; 32],
            Some([0x02u8; 32]),
            [0x03u8; 16],
        )
        .unwrap();
        inner[PACKET_COUNT_OFFSET..PACKET_COUNT_OFFSET + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        let sealed = seal_for_recipient(&inner, recip_pub.as_bytes()).unwrap();

        let result = OfflineBundle::open_as_recipient(&sealed, &recip_secret.to_bytes());
        assert!(
            matches!(
                result,
                Err(OfflineError::TooManyPackets {
                    declared: u32::MAX,
                    ..
                })
            ),
            "expected TooManyPackets, got {:?}",
            result.err()
        );
    }

    /// Replay the committed fuzz seed corpus through `open_as_recipient`
    /// using the fuzz target's layout (first 32 bytes = recipient secret,
    /// rest = bundle bytes).  Nothing may panic; the packet-count seed must
    /// decrypt and then stop at the structural gate.
    #[test]
    fn offline_bundle_corpus_replay() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/fuzz_offline_bundle_decode");
        crate::testing::corpus::assert_corpus_dir_exists(&dir);
        let entries = crate::testing::corpus::load_corpus_entries(&dir).expect("read corpus");
        assert!(!entries.is_empty(), "corpus must have seeds");
        let mut gate_hits = 0;
        for (path, bytes) in entries {
            let Some((secret_bytes, bundle_bytes)) = bytes.split_at_checked(32) else {
                // Shorter than a secret key: the fuzz target returns early too.
                continue;
            };
            let mut secret = [0u8; 32];
            secret.copy_from_slice(secret_bytes);
            let result = OfflineBundle::open_as_recipient(bundle_bytes, &secret);
            // Committed seeds are all negative cases; none may open.
            assert!(result.is_err(), "unexpected open: {path:?}");
            if matches!(result, Err(OfflineError::TooManyPackets { .. })) {
                gate_hits += 1;
            }
        }
        // seed_02 is sealed for the deterministic secret it carries and must
        // reach the packet-count gate rather than fail the AEAD.
        assert_eq!(
            gate_hits, 1,
            "the packet-count seed must reach the parser gate"
        );
    }

    #[test]
    fn offline_bundle_roundtrip() {
        let (recip_secret, recip_pub) = make_x25519_pair();

        let source_id = [0x01u8; 32];
        let dest_id = [0x02u8; 32];
        let packets: Vec<Vec<u8>> = vec![
            b"mesh packet 1 payload".to_vec(),
            b"mesh packet 2 payload".to_vec(),
            b"mesh packet 3 payload longer data here".to_vec(),
        ];

        // Create.
        let bundle =
            OfflineBundle::create_for_recipient(&packets, source_id, dest_id, recip_pub.as_bytes())
                .expect("create_for_recipient failed");

        // Verify encrypted bytes start with magic.
        assert_eq!(&bundle.encrypted_bytes[..4], &ENCRYPTED_BUNDLE_MAGIC);

        // Open.
        let (_opened, parsed) =
            OfflineBundle::open_as_recipient(&bundle.encrypted_bytes, &recip_secret.to_bytes())
                .expect("open_as_recipient failed");

        // Verify inner bundle contents.
        assert_eq!(parsed.header.source_id, source_id);
        assert_eq!(parsed.header.dest_id, Some(dest_id));
        assert_eq!(parsed.packets.len(), 3);
        assert_eq!(parsed.packets[0], b"mesh packet 1 payload");
        assert_eq!(parsed.packets[1], b"mesh packet 2 payload");
        assert_eq!(parsed.packets[2], b"mesh packet 3 payload longer data here");
    }

    #[test]
    fn offline_bundle_rejects_tampered_ciphertext() {
        let (recip_secret, recip_pub) = make_x25519_pair();
        let packets: Vec<Vec<u8>> = vec![b"data".to_vec()];

        let mut bundle = OfflineBundle::create_for_recipient(
            &packets,
            [0u8; 32],
            [0u8; 32],
            recip_pub.as_bytes(),
        )
        .expect("create failed");

        // Flip a byte in the ciphertext region.
        let last = bundle.encrypted_bytes.len() - 1;
        bundle.encrypted_bytes[last] ^= 0xFF;

        let result =
            OfflineBundle::open_as_recipient(&bundle.encrypted_bytes, &recip_secret.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn offline_bundle_rejects_wrong_key() {
        let (_recip_secret, recip_pub) = make_x25519_pair();
        let (wrong_secret, _) = make_x25519_pair();
        let packets: Vec<Vec<u8>> = vec![b"confidential".to_vec()];

        let bundle = OfflineBundle::create_for_recipient(
            &packets,
            [0u8; 32],
            [0u8; 32],
            recip_pub.as_bytes(),
        )
        .expect("create failed");

        let result =
            OfflineBundle::open_as_recipient(&bundle.encrypted_bytes, &wrong_secret.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn offline_bundle_rejects_bad_magic() {
        let mut data = vec![0u8; 60];
        data[0] = 0xFF; // corrupt magic
        let secret = X25519Secret::random_from_rng(OsRng);
        let result = OfflineBundle::open_as_recipient(&data, &secret.to_bytes());
        assert!(matches!(result, Err(OfflineError::InvalidMagic(_))));
    }

    #[test]
    fn offline_bundle_filename_format() {
        let (_, recip_pub) = make_x25519_pair();
        let packets: Vec<Vec<u8>> = vec![b"x".to_vec()];
        let bundle = OfflineBundle::create_for_recipient(
            &packets,
            [0u8; 32],
            [0u8; 32],
            recip_pub.as_bytes(),
        )
        .expect("create failed");

        let fname = bundle.filename();
        assert!(fname.starts_with("meshinfinity_bundle_"));
        assert!(fname.ends_with(".mib"));
        // ID hex should be 32 chars (16 bytes).
        assert_eq!(bundle.id_hex().len(), 32);
    }

    #[test]
    fn offline_bundle_id_is_unique_per_call() {
        let (_, recip_pub) = make_x25519_pair();
        let packets: Vec<Vec<u8>> = vec![b"p".to_vec()];

        let b1 = OfflineBundle::create_for_recipient(
            &packets,
            [0u8; 32],
            [0u8; 32],
            recip_pub.as_bytes(),
        )
        .expect("b1 create failed");
        let b2 = OfflineBundle::create_for_recipient(
            &packets,
            [0u8; 32],
            [0u8; 32],
            recip_pub.as_bytes(),
        )
        .expect("b2 create failed");

        // Bundle IDs must be distinct (random 16-byte values).
        assert_ne!(b1.bundle_id, b2.bundle_id);
    }
}
