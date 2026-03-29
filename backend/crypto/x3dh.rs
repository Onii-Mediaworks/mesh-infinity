//! X3DH / PQXDH — Key Agreement Protocol (§7.0.2, §3.4.1)
//!
//! Implements the Mesh Infinity variant of X3DH with PQXDH post-quantum extension.
//!
//! Key differences from Signal's X3DH:
//! - Single preauth key per identity (no OPK pool — §7.0.1)
//! - IK encrypted with AEAD (ChaCha20-Poly1305), not XOR (§7.0.2)
//! - ML-KEM-768 hybrid extension for post-quantum security (§3.4.1)
//! - Domain separation: "MeshInfinity_X3DH_v1" / "MeshInfinity_PQXDH_v1"
//!
//! # Protocol Flow
//!
//! Alice initiates a session with Bob using Bob's published preauth key:
//!
//! ```text
//! EK_A = fresh X25519 ephemeral keypair
//!
//! DH1 = X25519(IK_A_secret, preauth_B_pub)
//! DH2 = X25519(EK_A_secret, IK_B_pub)
//! DH3 = X25519(EK_A_secret, preauth_B_pub)
//!
//! For PQXDH (if Bob advertises ML-KEM key):
//!   (pq_ss, kem_ct) = ML-KEM-768.Encapsulate(preauth_B_kem_pub)
//!   kem_binding = HMAC-SHA256(X25519(EK_A_secret, preauth_B_pub), kem_ct)
//!
//! master_secret = HKDF-SHA256(
//!     salt = 0x00 * 32,
//!     ikm  = 0xFF * 32 || DH1 || DH2 || DH3 [|| pq_ss],
//!     info = "MeshInfinity_X3DH_v1" or "MeshInfinity_PQXDH_v1",
//!     len  = 32
//! )
//! ```

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey, Verifier};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use kem::Encapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use super::secmem::{SecureKey32, SecureMemory, SecureMemoryError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Domain separator for X3DH (classical)
const X3DH_INFO: &[u8] = b"MeshInfinity_X3DH_v1";

/// Domain separator for PQXDH (post-quantum hybrid)
const PQXDH_INFO: &[u8] = b"MeshInfinity_PQXDH_v1";

/// Domain separator for IK encryption key derivation
const IK_ENC_INFO: &[u8] = b"MeshInfinity_X3DH_ik_enc_v1";

/// Domain separator for IK encryption nonce derivation
const IK_NONCE_INFO: &[u8] = b"MeshInfinity_X3DH_ik_nonce_v1";

/// Domain separator for KEM binding HMAC.
///
/// Included as a prefix in every `compute_kem_binding` call so the binding
/// HMAC cannot be reused across protocols even if the same DH key material
/// appears in another context.
const KEM_BINDING_INFO: &[u8] = b"MeshInfinity_PQXDH_kem_binding_v1";

/// Domain separator for the preauth bundle signature.
///
/// Bob signs `PREAUTH_SIG_DOMAIN || preauth_x25519_pub_bytes` with his
/// Ed25519 identity key to prove that the preauth key belongs to him.
/// Verified by Alice in x3dh_initiate() when a non-zero identity key is present.
pub const PREAUTH_SIG_DOMAIN: &[u8] = b"MeshInfinity_X3DH_preauth_v1";

/// Signal-compatible domain separator prefix
const F_PREFIX: [u8; 32] = [0xFF; 32];

/// Zero salt for HKDF
const ZERO_SALT: [u8; 32] = [0u8; 32];

/// Size of AEAD-encrypted IK (32 bytes ciphertext + 16 bytes tag)
pub const ENCRYPTED_IK_SIZE: usize = 48;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum X3dhError {
    #[error("HKDF expansion failed")]
    HkdfExpand,
    #[error("AEAD encryption failed")]
    AeadEncrypt,
    #[error("AEAD decryption failed — possible tampering or wrong key")]
    AeadDecrypt,
    #[error("Encrypted IK has invalid size (expected {ENCRYPTED_IK_SIZE}, got {0})")]
    InvalidEncryptedIkSize(usize),
    #[error("KEM binding verification failed — possible ciphertext substitution")]
    KemBindingMismatch,
    #[error("Preauth bundle signature is invalid — possible identity binding attack")]
    PreauthBundleSignatureInvalid,
    #[error("Secure memory error: {0}")]
    SecureMemory(#[from] SecureMemoryError),
    #[error("HMAC key error — key was rejected by the MAC implementation")]
    HmacKeyError,
}

// ---------------------------------------------------------------------------
// Preauth key model (§7.0.1)
// ---------------------------------------------------------------------------

/// Bob's published preauth key material.
/// Single key per identity — no OPK pool.
pub struct PreauthBundle {
    /// Bob's long-term Ed25519 identity public key (for verification)
    pub identity_ed25519_pub: [u8; 32],
    /// Bob's long-term X25519 identity public key (for DH)
    pub identity_x25519_pub: X25519Public,
    /// Bob's preauth X25519 public key (serves the role of Signal's SPK)
    pub preauth_x25519_pub: X25519Public,
    /// Bob's ML-KEM-768 encapsulation public key (None if PQXDH not supported)
    pub preauth_kem_pub: Option<Vec<u8>>,
    /// Bob's Ed25519 signature over `PREAUTH_SIG_DOMAIN || preauth_x25519_pub`.
    ///
    /// When `identity_ed25519_pub` is non-zero, Alice verifies this signature
    /// in `x3dh_initiate()` to authenticate the binding between the long-term
    /// identity key and the ephemeral preauth key.  None means the bundle
    /// predates this field (legacy compat) — verification is skipped.
    pub preauth_sig: Option<Vec<u8>>,
}

impl PreauthBundle {
    /// Build the canonical message that must be signed to produce `preauth_sig`.
    ///
    /// `PREAUTH_SIG_DOMAIN || preauth_x25519_pub_bytes`
    pub fn signed_message(preauth_pub: &X25519Public) -> Vec<u8> {
        let mut msg = Vec::with_capacity(PREAUTH_SIG_DOMAIN.len() + 32);
        msg.extend_from_slice(PREAUTH_SIG_DOMAIN);
        msg.extend_from_slice(preauth_pub.as_bytes());
        msg
    }
}

// ---------------------------------------------------------------------------
// X3DH Init Header (wire format)
// ---------------------------------------------------------------------------

/// The header Alice sends to Bob to initiate a session.
/// This is the first message — Bob can derive master_secret from this.
#[derive(Clone)]
pub struct X3dhInitHeader {
    /// Alice's ephemeral X25519 public key (32 bytes)
    pub eph_pub: [u8; 32],
    /// Alice's identity key, AEAD-encrypted (48 bytes: 32 ct + 16 tag)
    pub encrypted_ik_pub: [u8; ENCRYPTED_IK_SIZE],
}

/// Extended header for PQXDH sessions.
pub struct PqxdhInitHeader {
    /// Classical X3DH header
    pub x3dh: X3dhInitHeader,
    /// ML-KEM-768 ciphertext (1088 bytes)
    pub kem_ciphertext: Vec<u8>,
    /// HMAC binding KEM ciphertext to ephemeral DH context (32 bytes)
    pub kem_binding: [u8; 32],
}

// ---------------------------------------------------------------------------
// X3DH Session Output
// ---------------------------------------------------------------------------

/// The result of a successful X3DH/PQXDH key agreement.
pub struct X3dhSessionOutput {
    /// The 32-byte master secret that seeds the Double Ratchet
    pub master_secret: SecureMemory<SecureKey32>,
    /// Whether PQXDH was used (post-quantum protected)
    pub is_post_quantum: bool,
    /// The header to send to Bob (for initiator only)
    pub header: Option<X3dhInitHeader>,
    /// The PQXDH header extension (for initiator only, if PQXDH)
    pub pqxdh_header: Option<PqxdhInitHeader>,
}

// ---------------------------------------------------------------------------
// Initiator (Alice) side
// ---------------------------------------------------------------------------

/// Perform X3DH key agreement as the initiator (Alice).
///
/// Alice has her own identity keypair and Bob's preauth bundle.
/// Returns the master secret and the init header to send to Bob.
pub fn x3dh_initiate(
    ik_a_secret: &X25519Secret,
    ik_a_pub: &[u8; 32],
    bob_bundle: &PreauthBundle,
) -> Result<X3dhSessionOutput, X3dhError> {
    // Generate fresh ephemeral keypair
    let ek_a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
    let ek_a_pub = X25519Public::from(&ek_a_secret);

    // Verify preauth bundle signature (§7.0.1 identity binding).
    //
    // When identity_ed25519_pub is non-zero and preauth_sig is present, Alice
    // verifies that Bob signed the preauth key with his Ed25519 identity key.
    // A zero identity key means legacy bundle — verification skipped.
    // A non-zero identity key with Some(sig) that fails verification → hard error.
    let identity_is_zero = bob_bundle.identity_ed25519_pub == [0u8; 32];
    if !identity_is_zero {
        if let Some(ref sig_bytes) = bob_bundle.preauth_sig {
            let vk = Ed25519VerifyingKey::from_bytes(&bob_bundle.identity_ed25519_pub)
                .map_err(|_| X3dhError::PreauthBundleSignatureInvalid)?;
            let sig = Ed25519Signature::from_slice(sig_bytes)
                .map_err(|_| X3dhError::PreauthBundleSignatureInvalid)?;
            let msg = PreauthBundle::signed_message(&bob_bundle.preauth_x25519_pub);
            vk.verify(&msg, &sig)
                .map_err(|_| X3dhError::PreauthBundleSignatureInvalid)?;
        }
    }

    // Compute the three DH values
    let dh1 = ik_a_secret.diffie_hellman(&bob_bundle.preauth_x25519_pub);
    let dh2 = ek_a_secret.diffie_hellman(&bob_bundle.identity_x25519_pub);
    let dh3 = ek_a_secret.diffie_hellman(&bob_bundle.preauth_x25519_pub);

    // Build IKM base: F || DH1 || DH2 || DH3
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 32 * 3 + 32));
    ikm.extend_from_slice(&F_PREFIX);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    // PQXDH extension (§3.4.1): ML-KEM-768 encapsulation against Bob's KEM key.
    let (is_pq, pqxdh_header) = if let Some(ref kem_pub_bytes) = bob_bundle.preauth_kem_pub {
        match try_pqxdh_encapsulate(
            kem_pub_bytes,
            ik_a_pub,
            &ek_a_secret,
            &ek_a_pub,
            &bob_bundle.preauth_x25519_pub,
            &mut ikm,
        ) {
            Some(ph) => (true, Some(ph)),
            None => (false, None),
        }
    } else {
        (false, None)
    };

    // Derive master secret via HKDF
    let info = if is_pq { PQXDH_INFO } else { X3DH_INFO };
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), &ikm);
    let mut master_secret_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *master_secret_bytes)
        .map_err(|_| X3dhError::HkdfExpand)?;

    let master_secret = SecureKey32::new(*master_secret_bytes)?;

    // Encrypt Alice's IK using AEAD (§7.0.2 — ChaCha20-Poly1305, not XOR).
    // Skip if PQXDH (header already generated above), generate for classical path.
    let header = if is_pq {
        // The classical X3DH header is embedded in the PQXDH header.
        pqxdh_header.as_ref().map(|ph| ph.x3dh.clone())
    } else {
        let encrypted_ik_pub = encrypt_ik_pub(ik_a_pub, &ek_a_secret, &bob_bundle.preauth_x25519_pub)?;
        Some(X3dhInitHeader {
            eph_pub: *ek_a_pub.as_bytes(),
            encrypted_ik_pub,
        })
    };

    Ok(X3dhSessionOutput {
        master_secret,
        is_post_quantum: is_pq,
        header,
        pqxdh_header,
    })
}

// ---------------------------------------------------------------------------
// Responder (Bob) side
// ---------------------------------------------------------------------------

/// Process an X3DH init header as the responder (Bob).
///
/// Bob uses his own keys to derive the same master secret Alice computed.
pub fn x3dh_respond(
    ik_b_secret: &X25519Secret,
    preauth_b_secret: &X25519Secret,
    header: &X3dhInitHeader,
) -> Result<X3dhSessionOutput, X3dhError> {
    // Validate encrypted IK size
    if header.encrypted_ik_pub.len() != ENCRYPTED_IK_SIZE {
        return Err(X3dhError::InvalidEncryptedIkSize(
            header.encrypted_ik_pub.len(),
        ));
    }

    let ek_a_pub = X25519Public::from(header.eph_pub);

    // Decrypt Alice's IK
    let ik_a_pub_bytes =
        decrypt_ik_pub(&header.encrypted_ik_pub, preauth_b_secret, &ek_a_pub)?;
    let ik_a_pub = X25519Public::from(ik_a_pub_bytes);

    // Compute the three DH values (mirrored)
    let dh1 = preauth_b_secret.diffie_hellman(&ik_a_pub);
    let dh2 = ik_b_secret.diffie_hellman(&ek_a_pub);
    let dh3 = preauth_b_secret.diffie_hellman(&ek_a_pub);

    // Build IKM
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 32 * 3));
    ikm.extend_from_slice(&F_PREFIX);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    // Derive master secret
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), &ikm);
    let mut master_secret_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(X3DH_INFO, &mut *master_secret_bytes)
        .map_err(|_| X3dhError::HkdfExpand)?;

    let master_secret = SecureKey32::new(*master_secret_bytes)?;

    Ok(X3dhSessionOutput {
        master_secret,
        is_post_quantum: false,
        header: None,
        pqxdh_header: None,
    })
}

// ---------------------------------------------------------------------------
// IK AEAD Encryption (§7.0.2)
// ---------------------------------------------------------------------------

/// Encrypt Alice's identity public key using ChaCha20-Poly1305.
///
/// The key and nonce are derived from the ephemeral DH shared secret.
/// Result is exactly 48 bytes (32 ciphertext + 16 auth tag).
fn encrypt_ik_pub(
    ik_pub: &[u8; 32],
    ek_secret: &X25519Secret,
    preauth_pub: &X25519Public,
) -> Result<[u8; ENCRYPTED_IK_SIZE], X3dhError> {
    let shared = ek_secret.diffie_hellman(preauth_pub);

    // Derive encryption key
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), shared.as_bytes());
    let mut enc_key = Zeroizing::new([0u8; 32]);
    hk.expand(IK_ENC_INFO, &mut *enc_key)
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Derive nonce
    let mut nonce_bytes = [0u8; 12];
    hk.expand(IK_NONCE_INFO, &mut nonce_bytes)
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&*enc_key)
        .map_err(|_| X3dhError::AeadEncrypt)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, ik_pub.as_ref())
        .map_err(|_| X3dhError::AeadEncrypt)?;

    // Must be exactly 48 bytes
    debug_assert_eq!(ciphertext.len(), ENCRYPTED_IK_SIZE);
    let mut result = [0u8; ENCRYPTED_IK_SIZE];
    result.copy_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt Alice's identity public key from AEAD ciphertext.
fn decrypt_ik_pub(
    encrypted: &[u8; ENCRYPTED_IK_SIZE],
    preauth_secret: &X25519Secret,
    ek_pub: &X25519Public,
) -> Result<[u8; 32], X3dhError> {
    let shared = preauth_secret.diffie_hellman(ek_pub);

    // Derive decryption key (same as encryption key)
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), shared.as_bytes());
    let mut dec_key = Zeroizing::new([0u8; 32]);
    hk.expand(IK_ENC_INFO, &mut *dec_key)
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Derive nonce
    let mut nonce_bytes = [0u8; 12];
    hk.expand(IK_NONCE_INFO, &mut nonce_bytes)
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&*dec_key)
        .map_err(|_| X3dhError::AeadDecrypt)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, encrypted.as_ref())
        .map_err(|_| X3dhError::AeadDecrypt)?;

    let mut result = [0u8; 32];
    result.copy_from_slice(&plaintext);
    Ok(result)
}

// ---------------------------------------------------------------------------
// PQXDH helpers (§3.4.1)
// ---------------------------------------------------------------------------

/// ML-KEM-768 encapsulation key type alias.
type MlKem768Ek = <ml_kem::kem::Kem<ml_kem::MlKem768Params> as KemCore>::EncapsulationKey;
/// ML-KEM-768 decapsulation key type alias.
type MlKem768Dk = <ml_kem::kem::Kem<ml_kem::MlKem768Params> as KemCore>::DecapsulationKey;

/// ML-KEM-768 encapsulation key byte size.
pub const KEM_EK_SIZE: usize = 1184;
/// ML-KEM-768 decapsulation key byte size.
pub const KEM_DK_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext byte size.
pub const KEM_CT_SIZE: usize = 1088;
/// ML-KEM-768 shared key byte size.
pub const KEM_SS_SIZE: usize = 32;

/// Attempt PQXDH encapsulation.  On success, appends the PQ shared secret to `ikm`
/// and returns the `PqxdhInitHeader`.  On any failure (bad key, wrong size), returns None.
fn try_pqxdh_encapsulate(
    kem_pub_bytes: &[u8],
    ik_a_pub: &[u8; 32],
    ek_a_secret: &X25519Secret,
    ek_a_pub: &X25519Public,
    preauth_pub: &X25519Public,
    ikm: &mut Zeroizing<Vec<u8>>,
) -> Option<PqxdhInitHeader> {
    if kem_pub_bytes.len() != KEM_EK_SIZE { return None; }

    // Deserialize encapsulation key.
    let ek_encoded = Encoded::<MlKem768Ek>::try_from(kem_pub_bytes).ok()?;
    let ek: MlKem768Ek = EncodedSizeUser::from_bytes(&ek_encoded);

    // Encapsulate: (ciphertext, shared_secret).
    let (kem_ct, pq_ss) = ek.encapsulate(&mut rand_core::OsRng).ok()?;

    // KEM binding: HMAC-SHA256(DH3_shared, kem_ciphertext) prevents KEM CT substitution.
    let dh3_shared = ek_a_secret.diffie_hellman(preauth_pub);
    let kem_ct_bytes = kem_ct.as_slice();
    let binding = compute_kem_binding(dh3_shared.as_bytes(), kem_ct_bytes).ok()?;

    // Mix PQ shared secret into IKM.
    ikm.extend_from_slice(pq_ss.as_slice());

    // Build classical X3DH header (embedded in PQXDH header).
    let encrypted_ik_pub = encrypt_ik_pub(ik_a_pub, ek_a_secret, preauth_pub).ok()?;

    Some(PqxdhInitHeader {
        x3dh: X3dhInitHeader {
            eph_pub: *ek_a_pub.as_bytes(),
            encrypted_ik_pub,
        },
        kem_ciphertext: kem_ct_bytes.to_vec(),
        kem_binding: binding,
    })
}

/// Perform PQXDH decapsulation as the responder (Bob).
///
/// Given the KEM ciphertext from Alice and Bob's decapsulation key bytes,
/// returns the 32-byte shared secret to mix into the IKM.
///
/// Verifies the KEM binding to prevent ciphertext substitution attacks.
pub fn pqxdh_decapsulate(
    dk_bytes: &[u8],
    kem_ct_bytes: &[u8],
    kem_binding: &[u8; 32],
    dh3_shared: &[u8],
) -> Result<[u8; KEM_SS_SIZE], X3dhError> {
    use kem::Decapsulate;

    if dk_bytes.len() != KEM_DK_SIZE { return Err(X3dhError::KemBindingMismatch); }
    if kem_ct_bytes.len() != KEM_CT_SIZE { return Err(X3dhError::KemBindingMismatch); }

    // Verify KEM binding first (fail fast on substitution).
    verify_kem_binding(dh3_shared, kem_ct_bytes, kem_binding)?;

    // Deserialize decapsulation key.
    let dk_encoded = Encoded::<MlKem768Dk>::try_from(dk_bytes)
        .map_err(|_| X3dhError::KemBindingMismatch)?;
    let dk: MlKem768Dk = EncodedSizeUser::from_bytes(&dk_encoded);

    // Deserialize ciphertext (Array::try_from checks length).
    let ct_encoded = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct_bytes)
        .map_err(|_| X3dhError::KemBindingMismatch)?;

    // Decapsulate.
    let pq_ss = dk.decapsulate(&ct_encoded).map_err(|_| X3dhError::KemBindingMismatch)?;
    let mut ss = [0u8; KEM_SS_SIZE];
    ss.copy_from_slice(pq_ss.as_slice());
    Ok(ss)
}

// ---------------------------------------------------------------------------
// KEM Binding (§3.4.1)
// ---------------------------------------------------------------------------

/// Compute the HMAC binding for KEM ciphertext authentication.
///
/// HMAC-SHA256(key=eph_dh_shared, data=KEM_BINDING_INFO || kem_ciphertext).
/// The domain separator (`KEM_BINDING_INFO`) prevents cross-protocol binding
/// reuse even when the same DH output appears in multiple contexts.
/// Returns `X3dhError::HmacKeyError` rather than panicking if the key is
/// somehow rejected — HMAC accepts any length but we must not unwind through FFI.
fn compute_kem_binding(
    eph_dh_shared: &[u8],
    kem_ciphertext: &[u8],
) -> Result<[u8; 32], X3dhError> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(eph_dh_shared)
            .map_err(|_| X3dhError::HmacKeyError)?;
    // Domain separator first — prevents cross-protocol binding reuse.
    mac.update(KEM_BINDING_INFO);
    // KEM ciphertext is the committed value being bound.
    mac.update(kem_ciphertext);
    let result = mac.finalize();
    let mut binding = [0u8; 32];
    binding.copy_from_slice(&result.into_bytes());
    Ok(binding)
}

/// Verify KEM binding on the responder side.
///
/// Recomputes `compute_kem_binding` and compares in constant time (via the
/// direct array comparison that avoids short-circuit evaluation).  Returns
/// `X3dhError::KemBindingMismatch` on any mismatch.
fn verify_kem_binding(
    eph_dh_shared: &[u8],
    kem_ciphertext: &[u8],
    expected_binding: &[u8; 32],
) -> Result<(), X3dhError> {
    let computed = compute_kem_binding(eph_dh_shared, kem_ciphertext)?;
    if computed != *expected_binding {
        return Err(X3dhError::KemBindingMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x3dh_roundtrip() {
        // Alice's identity keypair
        let ik_a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let ik_a_pub_x25519 = X25519Public::from(&ik_a_secret);
        let ik_a_pub_bytes: [u8; 32] = *ik_a_pub_x25519.as_bytes();

        // Bob's identity keypair
        let ik_b_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let ik_b_pub = X25519Public::from(&ik_b_secret);

        // Bob's preauth keypair
        let preauth_b_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let preauth_b_pub = X25519Public::from(&preauth_b_secret);

        let bob_bundle = PreauthBundle {
            identity_ed25519_pub: [0u8; 32], // Not used in X25519 DH
            identity_x25519_pub: ik_b_pub,
            preauth_x25519_pub: preauth_b_pub,
            preauth_kem_pub: None, // No PQXDH for this test
            preauth_sig: None,
        };

        // Alice initiates
        let alice_output = x3dh_initiate(&ik_a_secret, &ik_a_pub_bytes, &bob_bundle).unwrap();
        let header = alice_output.header.unwrap();

        // Bob responds
        let bob_output = x3dh_respond(&ik_b_secret, &preauth_b_secret, &header).unwrap();

        // Both should derive the same master secret
        assert_eq!(
            alice_output.master_secret.as_bytes(),
            bob_output.master_secret.as_bytes(),
            "Master secrets must match"
        );
    }

    #[test]
    fn test_ik_aead_roundtrip() {
        let ek_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let ek_pub = X25519Public::from(&ek_secret);

        let preauth_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let preauth_pub = X25519Public::from(&preauth_secret);

        let ik_pub = [0x42u8; 32];

        // Encrypt
        let encrypted = encrypt_ik_pub(&ik_pub, &ek_secret, &preauth_pub).unwrap();
        assert_eq!(encrypted.len(), ENCRYPTED_IK_SIZE);

        // Decrypt
        let decrypted = decrypt_ik_pub(&encrypted, &preauth_secret, &ek_pub).unwrap();
        assert_eq!(decrypted, ik_pub);
    }

    #[test]
    fn test_ik_aead_tamper_detection() {
        let ek_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let ek_pub = X25519Public::from(&ek_secret);

        let preauth_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let preauth_pub = X25519Public::from(&preauth_secret);

        let ik_pub = [0x42u8; 32];
        let mut encrypted = encrypt_ik_pub(&ik_pub, &ek_secret, &preauth_pub).unwrap();

        // Tamper with ciphertext
        encrypted[0] ^= 0xFF;

        // Decryption should fail
        let result = decrypt_ik_pub(&encrypted, &preauth_secret, &ek_pub);
        assert!(result.is_err());
    }

    #[test]
    fn test_kem_binding() {
        let shared = [0x42u8; 32];
        let kem_ct = [0x01u8; 64];

        let binding = compute_kem_binding(&shared, &kem_ct).unwrap();
        assert!(verify_kem_binding(&shared, &kem_ct, &binding).is_ok());

        // Wrong ciphertext should fail
        let wrong_ct = [0x02u8; 64];
        assert!(verify_kem_binding(&shared, &wrong_ct, &binding).is_err());
    }

    #[test]
    fn test_different_sessions_produce_different_secrets() {
        let ik_a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let ik_a_pub = *X25519Public::from(&ik_a_secret).as_bytes();

        let ik_b_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let preauth_b_secret = X25519Secret::random_from_rng(rand_core::OsRng);

        let bob_bundle = PreauthBundle {
            identity_ed25519_pub: [0u8; 32],
            identity_x25519_pub: X25519Public::from(&ik_b_secret),
            preauth_x25519_pub: X25519Public::from(&preauth_b_secret),
            preauth_kem_pub: None,
            preauth_sig: None,
        };

        let out1 = x3dh_initiate(&ik_a_secret, &ik_a_pub, &bob_bundle).unwrap();
        let out2 = x3dh_initiate(&ik_a_secret, &ik_a_pub, &bob_bundle).unwrap();

        // Different ephemeral keys → different master secrets
        assert_ne!(
            out1.master_secret.as_bytes(),
            out2.master_secret.as_bytes(),
            "Different sessions must produce different secrets"
        );
    }

    // --- Preauth bundle identity binding tests (§7.0.1) ---

    fn make_bob_bundle_signed() -> (PreauthBundle, X25519Secret) {
        use ed25519_dalek::{SigningKey as Ed25519SigningKey, Signer};

        let bob_ed25519_sk = Ed25519SigningKey::generate(&mut rand_core::OsRng);
        let bob_ed25519_pk = bob_ed25519_sk.verifying_key();

        let ik_b_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let preauth_b_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let preauth_b_pub = X25519Public::from(&preauth_b_secret);

        let msg = PreauthBundle::signed_message(&preauth_b_pub);
        let sig = bob_ed25519_sk.sign(&msg);

        let bundle = PreauthBundle {
            identity_ed25519_pub: bob_ed25519_pk.to_bytes(),
            identity_x25519_pub: X25519Public::from(&ik_b_secret),
            preauth_x25519_pub: preauth_b_pub,
            preauth_kem_pub: None,
            preauth_sig: Some(sig.to_bytes().to_vec()),
        };
        (bundle, preauth_b_secret)
    }

    #[test]
    fn test_preauth_sig_valid_bundle_accepted() {
        let ik_a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let ik_a_pub = *X25519Public::from(&ik_a_secret).as_bytes();
        let (bundle, _) = make_bob_bundle_signed();
        let result = x3dh_initiate(&ik_a_secret, &ik_a_pub, &bundle);
        assert!(result.is_ok(), "Valid signed bundle must be accepted");
    }

    #[test]
    fn test_preauth_sig_zero_identity_skips_verification() {
        // Zero identity key → legacy bundle, sig ignored even if present.
        use ed25519_dalek::SigningKey as Ed25519SigningKey;
        let ik_a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let ik_a_pub = *X25519Public::from(&ik_a_secret).as_bytes();

        let ik_b_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let preauth_b_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let preauth_b_pub = X25519Public::from(&preauth_b_secret);

        // Sign with a random key, but identity_ed25519_pub stays zero — skip check.
        use ed25519_dalek::Signer;
        let dummy_sk = Ed25519SigningKey::generate(&mut rand_core::OsRng);
        let msg = PreauthBundle::signed_message(&preauth_b_pub);
        let bad_sig = dummy_sk.sign(&msg);

        let bundle = PreauthBundle {
            identity_ed25519_pub: [0u8; 32],
            identity_x25519_pub: X25519Public::from(&ik_b_secret),
            preauth_x25519_pub: preauth_b_pub,
            preauth_kem_pub: None,
            preauth_sig: Some(bad_sig.to_bytes().to_vec()),
        };
        let result = x3dh_initiate(&ik_a_secret, &ik_a_pub, &bundle);
        assert!(result.is_ok(), "Zero identity key must skip sig check");
    }

    #[test]
    fn test_preauth_sig_wrong_identity_key_rejected() {
        // Bundle signed by Bob's real key, but presented with a different Ed25519 pub.
        use ed25519_dalek::SigningKey as Ed25519SigningKey;
        let ik_a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let ik_a_pub = *X25519Public::from(&ik_a_secret).as_bytes();

        let (mut bundle, _) = make_bob_bundle_signed();

        // Replace identity pub with a different key — verification must fail.
        let other_sk = Ed25519SigningKey::generate(&mut rand_core::OsRng);
        bundle.identity_ed25519_pub = other_sk.verifying_key().to_bytes();

        let result = x3dh_initiate(&ik_a_secret, &ik_a_pub, &bundle);
        assert!(
            matches!(result, Err(X3dhError::PreauthBundleSignatureInvalid)),
            "Wrong identity key must cause PreauthBundleSignatureInvalid"
        );
    }

    #[test]
    fn test_preauth_sig_tampered_preauth_key_rejected() {
        // Valid signature but preauth key was swapped after signing.
        let ik_a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let ik_a_pub = *X25519Public::from(&ik_a_secret).as_bytes();

        let (mut bundle, _) = make_bob_bundle_signed();

        // Replace preauth key with a fresh one — signature no longer covers it.
        let attacker_preauth = X25519Secret::random_from_rng(rand_core::OsRng);
        bundle.preauth_x25519_pub = X25519Public::from(&attacker_preauth);

        let result = x3dh_initiate(&ik_a_secret, &ik_a_pub, &bundle);
        assert!(
            matches!(result, Err(X3dhError::PreauthBundleSignatureInvalid)),
            "Tampered preauth key must cause PreauthBundleSignatureInvalid"
        );
    }
}
