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
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    aead::{Aead, KeyInit},
    // AEAD cipher for authenticated encryption.
    // Execute this protocol step.
    // Execute this protocol step.
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey, Verifier};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use kem::Encapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
// Securely erase key material to prevent forensic recovery.
use zeroize::Zeroizing;

use super::secmem::{SecureKey32, SecureMemory, SecureMemoryError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Domain separator for X3DH (classical)
// X3DH_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
// X3DH_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
const X3DH_INFO: &[u8] = b"MeshInfinity_X3DH_v1";

/// Domain separator for PQXDH (post-quantum hybrid)
// PQXDH_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
// PQXDH_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
const PQXDH_INFO: &[u8] = b"MeshInfinity_PQXDH_v1";

/// Domain separator for IK encryption key derivation
// IK_ENC_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
// IK_ENC_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
const IK_ENC_INFO: &[u8] = b"MeshInfinity_X3DH_ik_enc_v1";

/// Domain separator for IK encryption nonce derivation
// IK_NONCE_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
// IK_NONCE_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
const IK_NONCE_INFO: &[u8] = b"MeshInfinity_X3DH_ik_nonce_v1";

/// Domain separator for KEM binding HMAC.
///
/// Included as a prefix in every `compute_kem_binding` call so the binding
/// HMAC cannot be reused across protocols even if the same DH key material
/// appears in another context.
// KEM_BINDING_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
// KEM_BINDING_INFO — protocol constant.
// Defined by the spec; must not change without a version bump.
const KEM_BINDING_INFO: &[u8] = b"MeshInfinity_PQXDH_kem_binding_v1";

/// Domain separator for the preauth bundle signature.
///
/// Bob signs `PREAUTH_SIG_DOMAIN || preauth_x25519_pub_bytes` with his
/// Ed25519 identity key to prove that the preauth key belongs to him.
/// Verified by Alice in x3dh_initiate() when a non-zero identity key is present.
// PREAUTH_SIG_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// PREAUTH_SIG_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PREAUTH_SIG_DOMAIN: &[u8] = b"MeshInfinity_X3DH_preauth_v1";

/// Signal-compatible domain separator prefix
// F_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// F_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
const F_PREFIX: [u8; 32] = [0xFF; 32];

/// Zero salt for HKDF
// ZERO_SALT — protocol constant.
// Defined by the spec; must not change without a version bump.
// ZERO_SALT — protocol constant.
// Defined by the spec; must not change without a version bump.
const ZERO_SALT: [u8; 32] = [0u8; 32];

/// Size of AEAD-encrypted IK (32 bytes ciphertext + 16 bytes tag)
// ENCRYPTED_IK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// ENCRYPTED_IK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const ENCRYPTED_IK_SIZE: usize = 48;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
// Begin the block scope.
// X3dhError — variant enumeration.
// Match exhaustively to handle every protocol state.
// X3dhError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum X3dhError {
    #[error("HKDF expansion failed")]
    // Execute this protocol step.
    // Execute this protocol step.
    HkdfExpand,
    #[error("AEAD encryption failed")]
    // Execute this protocol step.
    // Execute this protocol step.
    AeadEncrypt,
    #[error("AEAD decryption failed — possible tampering or wrong key")]
    // Execute this protocol step.
    // Execute this protocol step.
    AeadDecrypt,
    #[error("Encrypted IK has invalid size (expected {ENCRYPTED_IK_SIZE}, got {0})")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    InvalidEncryptedIkSize(usize),
    #[error("KEM binding verification failed — possible ciphertext substitution")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    KemBindingMismatch,
    #[error("Preauth bundle signature is invalid — possible identity binding attack")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    PreauthBundleSignatureInvalid,
    #[error("Secure memory error: {0}")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SecureMemory(#[from] SecureMemoryError),
    #[error("HMAC key error — key was rejected by the MAC implementation")]
    // Execute this protocol step.
    // Execute this protocol step.
    HmacKeyError,
}

// ---------------------------------------------------------------------------
// Preauth key model (§7.0.1)
// ---------------------------------------------------------------------------

/// Bob's published preauth key material.
/// Single key per identity — no OPK pool.
// PreauthBundle — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PreauthBundle — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PreauthBundle {
    /// Bob's long-term Ed25519 identity public key (for verification)
    // Execute this protocol step.
    // Execute this protocol step.
    pub identity_ed25519_pub: [u8; 32],
    /// Bob's long-term X25519 identity public key (for DH)
    // Execute this protocol step.
    // Execute this protocol step.
    pub identity_x25519_pub: X25519Public,
    /// Bob's preauth X25519 public key (serves the role of Signal's SPK)
    // Execute this protocol step.
    // Execute this protocol step.
    pub preauth_x25519_pub: X25519Public,
    /// Bob's ML-KEM-768 encapsulation public key (None if PQXDH not supported)
    // Execute this protocol step.
    // Execute this protocol step.
    pub preauth_kem_pub: Option<Vec<u8>>,
    /// Bob's Ed25519 signature over `PREAUTH_SIG_DOMAIN || preauth_x25519_pub`.
    ///
    /// When `identity_ed25519_pub` is non-zero, Alice verifies this signature
    /// in `x3dh_initiate()` to authenticate the binding between the long-term
    /// identity key and the ephemeral preauth key.  None means the bundle
    /// predates this field (legacy compat) — verification is skipped.
    // Execute this protocol step.
    // Execute this protocol step.
    pub preauth_sig: Option<Vec<u8>>,
}

// Begin the block scope.
// PreauthBundle implementation — core protocol logic.
// PreauthBundle implementation — core protocol logic.
impl PreauthBundle {
    /// Build the canonical message that must be signed to produce `preauth_sig`.
    ///
    /// `PREAUTH_SIG_DOMAIN || preauth_x25519_pub_bytes`
    // Perform the 'signed message' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'signed message' operation.
    // Errors are propagated to the caller via Result.
    pub fn signed_message(preauth_pub: &X25519Public) -> Vec<u8> {
        // Pre-allocate the buffer to avoid repeated reallocations.
        // Compute msg for this protocol step.
        // Compute msg for this protocol step.
        let mut msg = Vec::with_capacity(PREAUTH_SIG_DOMAIN.len() + 32);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        msg.extend_from_slice(PREAUTH_SIG_DOMAIN);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
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
// Begin the block scope.
// X3dhInitHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// X3dhInitHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct X3dhInitHeader {
    /// Alice's ephemeral X25519 public key (32 bytes)
    // Execute this protocol step.
    // Execute this protocol step.
    pub eph_pub: [u8; 32],
    /// Alice's identity key, AEAD-encrypted (48 bytes: 32 ct + 16 tag)
    // Execute this protocol step.
    // Execute this protocol step.
    pub encrypted_ik_pub: [u8; ENCRYPTED_IK_SIZE],
}

/// Extended header for PQXDH sessions.
// PqxdhInitHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PqxdhInitHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PqxdhInitHeader {
    /// Classical X3DH header
    // Execute this protocol step.
    // Execute this protocol step.
    pub x3dh: X3dhInitHeader,
    /// ML-KEM-768 ciphertext (1088 bytes)
    // Execute this protocol step.
    // Execute this protocol step.
    pub kem_ciphertext: Vec<u8>,
    /// HMAC binding KEM ciphertext to ephemeral DH context (32 bytes)
    // Execute this protocol step.
    // Execute this protocol step.
    pub kem_binding: [u8; 32],
}

// ---------------------------------------------------------------------------
// X3DH Session Output
// ---------------------------------------------------------------------------

/// The result of a successful X3DH/PQXDH key agreement.
// X3dhSessionOutput — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// X3dhSessionOutput — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct X3dhSessionOutput {
    /// The 32-byte master secret that seeds the Double Ratchet
    // Execute this protocol step.
    // Execute this protocol step.
    pub master_secret: SecureMemory<SecureKey32>,
    /// Whether PQXDH was used (post-quantum protected)
    // Execute this protocol step.
    // Execute this protocol step.
    pub is_post_quantum: bool,
    /// The header to send to Bob (for initiator only)
    // Execute this protocol step.
    // Execute this protocol step.
    pub header: Option<X3dhInitHeader>,
    /// The PQXDH header extension (for initiator only, if PQXDH)
    // Execute this protocol step.
    // Execute this protocol step.
    pub pqxdh_header: Option<PqxdhInitHeader>,
}

// ---------------------------------------------------------------------------
// Initiator (Alice) side
// ---------------------------------------------------------------------------

/// Perform X3DH key agreement as the initiator (Alice).
///
/// Alice has her own identity keypair and Bob's preauth bundle.
/// Returns the master secret and the init header to send to Bob.
// Perform the 'x3dh initiate' operation.
// Errors are propagated to the caller via Result.
// Perform the 'x3dh initiate' operation.
// Errors are propagated to the caller via Result.
pub fn x3dh_initiate(
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    ik_a_secret: &X25519Secret,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ik_a_pub: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    bob_bundle: &PreauthBundle,
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> Result<X3dhSessionOutput, X3dhError> {
    // Generate fresh ephemeral keypair
    // Compute ek a secret for this protocol step.
    // Compute ek a secret for this protocol step.
    let ek_a_secret = X25519Secret::random_from_rng(rand_core::OsRng);
    // Key material — must be zeroized when no longer needed.
    // Compute ek a pub for this protocol step.
    // Compute ek a pub for this protocol step.
    let ek_a_pub = X25519Public::from(&ek_a_secret);

    // Verify preauth bundle signature (§7.0.1 identity binding).
    //
    // When identity_ed25519_pub is non-zero and preauth_sig is present, Alice
    // verifies that Bob signed the preauth key with his Ed25519 identity key.
    // A zero identity key means legacy bundle — verification skipped.
    // A non-zero identity key with Some(sig) that fails verification → hard error.
    // Compute identity is zero for this protocol step.
    // Compute identity is zero for this protocol step.
    let identity_is_zero = bob_bundle.identity_ed25519_pub == [0u8; 32];
    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if !identity_is_zero {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(ref sig_bytes) = bob_bundle.preauth_sig {
            // Key material — must be zeroized when no longer needed.
            // Compute vk for this protocol step.
            // Compute vk for this protocol step.
            let vk = Ed25519VerifyingKey::from_bytes(&bob_bundle.identity_ed25519_pub)
                // Transform the result, mapping errors to the local error type.
                // Map the error to the local error type.
                // Map the error to the local error type.
                .map_err(|_| X3dhError::PreauthBundleSignatureInvalid)?;
            // Ed25519 signature for authentication and integrity.
            // Compute sig for this protocol step.
            // Compute sig for this protocol step.
            let sig = Ed25519Signature::from_slice(sig_bytes)
                // Transform the result, mapping errors to the local error type.
                // Map the error to the local error type.
                // Map the error to the local error type.
                .map_err(|_| X3dhError::PreauthBundleSignatureInvalid)?;
            // Invoke the associated function.
            // Compute msg for this protocol step.
            // Compute msg for this protocol step.
            let msg = PreauthBundle::signed_message(&bob_bundle.preauth_x25519_pub);
            // Verify the signature against the claimed public key.
            // Verify the cryptographic signature.
            // Verify the cryptographic signature.
            vk.verify(&msg, &sig)
                // Transform the result, mapping errors to the local error type.
                // Map the error to the local error type.
                // Map the error to the local error type.
                .map_err(|_| X3dhError::PreauthBundleSignatureInvalid)?;
        }
    }

    // Compute the three DH values
    // Compute dh1 for this protocol step.
    // Compute dh1 for this protocol step.
    let dh1 = ik_a_secret.diffie_hellman(&bob_bundle.preauth_x25519_pub);
    // Key material — must be zeroized when no longer needed.
    // Compute dh2 for this protocol step.
    // Compute dh2 for this protocol step.
    let dh2 = ek_a_secret.diffie_hellman(&bob_bundle.identity_x25519_pub);
    // Key material — must be zeroized when no longer needed.
    // Compute dh3 for this protocol step.
    // Compute dh3 for this protocol step.
    let dh3 = ek_a_secret.diffie_hellman(&bob_bundle.preauth_x25519_pub);

    // Build IKM base: F || DH1 || DH2 || DH3
    // Compute ikm for this protocol step.
    // Compute ikm for this protocol step.
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 32 * 3 + 32));
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    ikm.extend_from_slice(&F_PREFIX);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    ikm.extend_from_slice(dh1.as_bytes());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    ikm.extend_from_slice(dh2.as_bytes());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    ikm.extend_from_slice(dh3.as_bytes());

    // PQXDH extension (§3.4.1): ML-KEM-768 encapsulation against Bob's KEM key.
    // Compute Some for this protocol step.
    // Compute Some for this protocol step.
    let (is_pq, pqxdh_header) = if let Some(ref kem_pub_bytes) = bob_bundle.preauth_kem_pub {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match try_pqxdh_encapsulate(
            // Execute this protocol step.
            // Execute this protocol step.
            kem_pub_bytes,
            // Execute this protocol step.
            // Execute this protocol step.
            ik_a_pub,
            // Execute this protocol step.
            // Execute this protocol step.
            &ek_a_secret,
            // Execute this protocol step.
            // Execute this protocol step.
            &ek_a_pub,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            &bob_bundle.preauth_x25519_pub,
            // Execute this protocol step.
            // Execute this protocol step.
            &mut ikm,
        // Begin the block scope.
        ) {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(ph) => (true, Some(ph)),
            // Update the local state.
            // No value available.
            // No value available.
            None => (false, None),
        }
    // Begin the block scope.
    // Fallback when the guard was not satisfied.
    // Fallback when the guard was not satisfied.
    } else {
        // Execute this step in the protocol sequence.
        // Execute this protocol step.
        // Execute this protocol step.
        (false, None)
    };

    // Derive master secret via HKDF
    // Compute info for this protocol step.
    // Compute info for this protocol step.
    let info = if is_pq { PQXDH_INFO } else { X3DH_INFO };
    // Set up the HKDF context for domain-separated key derivation.
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), &ikm);
    // Key material — must be zeroized when no longer needed.
    // Compute master secret bytes for this protocol step.
    // Compute master secret bytes for this protocol step.
    let mut master_secret_bytes = Zeroizing::new([0u8; 32]);
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(info, &mut *master_secret_bytes)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Key material — must be zeroized when no longer needed.
    // Compute master secret for this protocol step.
    // Compute master secret for this protocol step.
    let master_secret = SecureKey32::new(*master_secret_bytes)?;

    // Encrypt Alice's IK using AEAD (§7.0.2 — ChaCha20-Poly1305, not XOR).
    // Skip if PQXDH (header already generated above), generate for classical path.
    // Compute header for this protocol step.
    // Compute header for this protocol step.
    let header = if is_pq {
        // The classical X3DH header is embedded in the PQXDH header.
        // Transform each element.
        // Transform each element.
        pqxdh_header.as_ref().map(|ph| ph.x3dh.clone())
    // Begin the block scope.
    // Fallback when the guard was not satisfied.
    // Fallback when the guard was not satisfied.
    } else {
        // Key material — must be zeroized when no longer needed.
        // Compute encrypted ik pub for this protocol step.
        // Compute encrypted ik pub for this protocol step.
        let encrypted_ik_pub = encrypt_ik_pub(ik_a_pub, &ek_a_secret, &bob_bundle.preauth_x25519_pub)?;
        // Wrap the found value for the caller.
        // Wrap the found value.
        // Wrap the found value.
        Some(X3dhInitHeader {
            // Extract the raw byte representation for wire encoding.
            // Execute this protocol step.
            // Execute this protocol step.
            eph_pub: *ek_a_pub.as_bytes(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            encrypted_ik_pub,
        })
    };

    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(X3dhSessionOutput {
        // Execute this protocol step.
        // Execute this protocol step.
        master_secret,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        is_post_quantum: is_pq,
        header,
        // Execute this protocol step.
        // Execute this protocol step.
        pqxdh_header,
    })
}

// ---------------------------------------------------------------------------
// Responder (Bob) side
// ---------------------------------------------------------------------------

/// Process an X3DH init header as the responder (Bob).
///
/// Bob uses his own keys to derive the same master secret Alice computed.
// Perform the 'x3dh respond' operation.
// Errors are propagated to the caller via Result.
// Perform the 'x3dh respond' operation.
// Errors are propagated to the caller via Result.
pub fn x3dh_respond(
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    ik_b_secret: &X25519Secret,
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    preauth_b_secret: &X25519Secret,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    header: &X3dhInitHeader,
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> Result<X3dhSessionOutput, X3dhError> {
    // Validate encrypted IK size
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if header.encrypted_ik_pub.len() != ENCRYPTED_IK_SIZE {
        // Reject with an explicit error for the caller to handle.
        // Return to the caller.
        // Return to the caller.
        return Err(X3dhError::InvalidEncryptedIkSize(
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            header.encrypted_ik_pub.len(),
        ));
    }

    // Invoke the associated function.
    // Compute ek a pub for this protocol step.
    // Compute ek a pub for this protocol step.
    let ek_a_pub = X25519Public::from(header.eph_pub);

    // Decrypt Alice's IK
    // Compute ik a pub bytes for this protocol step.
    // Compute ik a pub bytes for this protocol step.
    let ik_a_pub_bytes =
        // Propagate errors via the ? operator — callers handle failures.
        // Propagate errors via ?.
        // Propagate errors via ?.
        decrypt_ik_pub(&header.encrypted_ik_pub, preauth_b_secret, &ek_a_pub)?;
    // Invoke the associated function.
    // Compute ik a pub for this protocol step.
    // Compute ik a pub for this protocol step.
    let ik_a_pub = X25519Public::from(ik_a_pub_bytes);

    // Compute the three DH values (mirrored)
    // Compute dh1 for this protocol step.
    // Compute dh1 for this protocol step.
    let dh1 = preauth_b_secret.diffie_hellman(&ik_a_pub);
    // Key material — must be zeroized when no longer needed.
    // Compute dh2 for this protocol step.
    // Compute dh2 for this protocol step.
    let dh2 = ik_b_secret.diffie_hellman(&ek_a_pub);
    // Key material — must be zeroized when no longer needed.
    // Compute dh3 for this protocol step.
    // Compute dh3 for this protocol step.
    let dh3 = preauth_b_secret.diffie_hellman(&ek_a_pub);

    // Build IKM
    // Compute ikm for this protocol step.
    // Compute ikm for this protocol step.
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 32 * 3));
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    ikm.extend_from_slice(&F_PREFIX);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    ikm.extend_from_slice(dh1.as_bytes());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    ikm.extend_from_slice(dh2.as_bytes());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    ikm.extend_from_slice(dh3.as_bytes());

    // Derive master secret
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), &ikm);
    // Key material — must be zeroized when no longer needed.
    // Compute master secret bytes for this protocol step.
    // Compute master secret bytes for this protocol step.
    let mut master_secret_bytes = Zeroizing::new([0u8; 32]);
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(X3DH_INFO, &mut *master_secret_bytes)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Key material — must be zeroized when no longer needed.
    // Compute master secret for this protocol step.
    // Compute master secret for this protocol step.
    let master_secret = SecureKey32::new(*master_secret_bytes)?;

    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(X3dhSessionOutput {
        // Execute this protocol step.
        // Execute this protocol step.
        master_secret,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        is_post_quantum: false,
        // Execute this protocol step.
        // Execute this protocol step.
        header: None,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
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
// Perform the 'encrypt ik pub' operation.
// Errors are propagated to the caller via Result.
// Perform the 'encrypt ik pub' operation.
// Errors are propagated to the caller via Result.
fn encrypt_ik_pub(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ik_pub: &[u8; 32],
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    ek_secret: &X25519Secret,
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    preauth_pub: &X25519Public,
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> Result<[u8; ENCRYPTED_IK_SIZE], X3dhError> {
    // Key material — must be zeroized when no longer needed.
    // Compute shared for this protocol step.
    // Compute shared for this protocol step.
    let shared = ek_secret.diffie_hellman(preauth_pub);

    // Derive encryption key
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), shared.as_bytes());
    // Key material — must be zeroized when no longer needed.
    // Compute enc key for this protocol step.
    // Compute enc key for this protocol step.
    let mut enc_key = Zeroizing::new([0u8; 32]);
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(IK_ENC_INFO, &mut *enc_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Derive nonce
    // Compute nonce bytes for this protocol step.
    // Compute nonce bytes for this protocol step.
    let mut nonce_bytes = [0u8; 12];
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(IK_NONCE_INFO, &mut nonce_bytes)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Encrypt with ChaCha20-Poly1305
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    let cipher = ChaCha20Poly1305::new_from_slice(&*enc_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::AeadEncrypt)?;
    // Fresh nonce — must never be reused with the same key.
    // Compute nonce for this protocol step.
    // Compute nonce for this protocol step.
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Initialize the AEAD cipher with the derived key material.
    // Compute ciphertext for this protocol step.
    // Compute ciphertext for this protocol step.
    let ciphertext = cipher
        // Encrypt the plaintext under the current session key.
        // AEAD-encrypt the plaintext.
        // AEAD-encrypt the plaintext.
        .encrypt(nonce, ik_pub.as_ref())
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::AeadEncrypt)?;

    // Must be exactly 48 bytes
    // Invariant check.
    // Invariant check.
    debug_assert_eq!(ciphertext.len(), ENCRYPTED_IK_SIZE);
    // Capture the operation result for subsequent validation.
    // Compute result for this protocol step.
    // Compute result for this protocol step.
    let mut result = [0u8; ENCRYPTED_IK_SIZE];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    result.copy_from_slice(&ciphertext);
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(result)
}

/// Decrypt Alice's identity public key from AEAD ciphertext.
// Perform the 'decrypt ik pub' operation.
// Errors are propagated to the caller via Result.
// Perform the 'decrypt ik pub' operation.
// Errors are propagated to the caller via Result.
fn decrypt_ik_pub(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    encrypted: &[u8; ENCRYPTED_IK_SIZE],
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    preauth_secret: &X25519Secret,
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    ek_pub: &X25519Public,
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> Result<[u8; 32], X3dhError> {
    // Key material — must be zeroized when no longer needed.
    // Compute shared for this protocol step.
    // Compute shared for this protocol step.
    let shared = preauth_secret.diffie_hellman(ek_pub);

    // Derive decryption key (same as encryption key)
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), shared.as_bytes());
    // Key material — must be zeroized when no longer needed.
    // Compute dec key for this protocol step.
    // Compute dec key for this protocol step.
    let mut dec_key = Zeroizing::new([0u8; 32]);
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(IK_ENC_INFO, &mut *dec_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Derive nonce
    // Compute nonce bytes for this protocol step.
    // Compute nonce bytes for this protocol step.
    let mut nonce_bytes = [0u8; 12];
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(IK_NONCE_INFO, &mut nonce_bytes)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::HkdfExpand)?;

    // Decrypt
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    let cipher = ChaCha20Poly1305::new_from_slice(&*dec_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::AeadDecrypt)?;
    // Fresh nonce — must never be reused with the same key.
    // Compute nonce for this protocol step.
    // Compute nonce for this protocol step.
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Initialize the AEAD cipher with the derived key material.
    // Compute plaintext for this protocol step.
    // Compute plaintext for this protocol step.
    let plaintext = cipher
        // Decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        .decrypt(nonce, encrypted.as_ref())
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::AeadDecrypt)?;

    // Capture the operation result for subsequent validation.
    // Compute result for this protocol step.
    // Compute result for this protocol step.
    let mut result = [0u8; 32];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    result.copy_from_slice(&plaintext);
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(result)
}

// ---------------------------------------------------------------------------
// PQXDH helpers (§3.4.1)
// ---------------------------------------------------------------------------

/// ML-KEM-768 encapsulation key type alias.
// Type alias for protocol readability.
// Type alias for protocol readability.
type MlKem768Ek = <ml_kem::kem::Kem<ml_kem::MlKem768Params> as KemCore>::EncapsulationKey;
/// ML-KEM-768 decapsulation key type alias.
// Type alias for protocol readability.
// Type alias for protocol readability.
type MlKem768Dk = <ml_kem::kem::Kem<ml_kem::MlKem768Params> as KemCore>::DecapsulationKey;

/// ML-KEM-768 encapsulation key byte size.
// KEM_EK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// KEM_EK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KEM_EK_SIZE: usize = 1184;
/// ML-KEM-768 decapsulation key byte size.
// KEM_DK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// KEM_DK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KEM_DK_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext byte size.
// KEM_CT_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// KEM_CT_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KEM_CT_SIZE: usize = 1088;
/// ML-KEM-768 shared key byte size.
// KEM_SS_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// KEM_SS_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KEM_SS_SIZE: usize = 32;

/// Attempt PQXDH encapsulation.  On success, appends the PQ shared secret to `ikm`
/// and returns the `PqxdhInitHeader`.  On any failure (bad key, wrong size), returns None.
// Perform the 'try pqxdh encapsulate' operation.
// Errors are propagated to the caller via Result.
// Perform the 'try pqxdh encapsulate' operation.
// Errors are propagated to the caller via Result.
fn try_pqxdh_encapsulate(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    kem_pub_bytes: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ik_a_pub: &[u8; 32],
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    ek_a_secret: &X25519Secret,
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    ek_a_pub: &X25519Public,
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    preauth_pub: &X25519Public,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ikm: &mut Zeroizing<Vec<u8>>,
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> Option<PqxdhInitHeader> {
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if kem_pub_bytes.len() != KEM_EK_SIZE { return None; }

    // Deserialize encapsulation key.
    // Compute ek encoded for this protocol step.
    // Compute ek encoded for this protocol step.
    let ek_encoded = Encoded::<MlKem768Ek>::try_from(kem_pub_bytes).ok()?;
    // Track the count for threshold and bounds checking.
    // Compute ek for this protocol step.
    // Compute ek for this protocol step.
    let ek: MlKem768Ek = EncodedSizeUser::from_bytes(&ek_encoded);

    // Encapsulate: (ciphertext, shared_secret).
    // Bind the intermediate result.
    // Bind the intermediate result.
    let (kem_ct, pq_ss) = ek.encapsulate(&mut rand_core::OsRng).ok()?;

    // KEM binding: HMAC-SHA256(DH3_shared, kem_ciphertext) prevents KEM CT substitution.
    // Compute dh3 shared for this protocol step.
    // Compute dh3 shared for this protocol step.
    let dh3_shared = ek_a_secret.diffie_hellman(preauth_pub);
    // Execute the operation and bind the result.
    // Compute kem ct bytes for this protocol step.
    // Compute kem ct bytes for this protocol step.
    let kem_ct_bytes = kem_ct.as_slice();
    // Check the operation outcome without consuming the error.
    // Compute binding for this protocol step.
    // Compute binding for this protocol step.
    let binding = compute_kem_binding(dh3_shared.as_bytes(), kem_ct_bytes).ok()?;

    // Mix PQ shared secret into IKM.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    ikm.extend_from_slice(pq_ss.as_slice());

    // Build classical X3DH header (embedded in PQXDH header).
    // Compute encrypted ik pub for this protocol step.
    // Compute encrypted ik pub for this protocol step.
    let encrypted_ik_pub = encrypt_ik_pub(ik_a_pub, ek_a_secret, preauth_pub).ok()?;

    // Wrap the found value for the caller.
    // Wrap the found value.
    // Wrap the found value.
    Some(PqxdhInitHeader {
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        x3dh: X3dhInitHeader {
            // Extract the raw byte representation for wire encoding.
            // Execute this protocol step.
            // Execute this protocol step.
            eph_pub: *ek_a_pub.as_bytes(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            encrypted_ik_pub,
        },
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        kem_ciphertext: kem_ct_bytes.to_vec(),
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        kem_binding: binding,
    })
}

/// Perform PQXDH decapsulation as the responder (Bob).
///
/// Given the KEM ciphertext from Alice and Bob's decapsulation key bytes,
/// returns the 32-byte shared secret to mix into the IKM.
///
/// Verifies the KEM binding to prevent ciphertext substitution attacks.
// Perform the 'pqxdh decapsulate' operation.
// Errors are propagated to the caller via Result.
// Perform the 'pqxdh decapsulate' operation.
// Errors are propagated to the caller via Result.
pub fn pqxdh_decapsulate(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    dk_bytes: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    kem_ct_bytes: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    kem_binding: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    dh3_shared: &[u8],
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> Result<[u8; KEM_SS_SIZE], X3dhError> {
    use kem::Decapsulate;

    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if dk_bytes.len() != KEM_DK_SIZE { return Err(X3dhError::KemBindingMismatch); }
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if kem_ct_bytes.len() != KEM_CT_SIZE { return Err(X3dhError::KemBindingMismatch); }

    // Verify KEM binding first (fail fast on substitution).
    // Propagate errors via ?.
    // Propagate errors via ?.
    verify_kem_binding(dh3_shared, kem_ct_bytes, kem_binding)?;

    // Deserialize decapsulation key.
    // Compute dk encoded for this protocol step.
    // Compute dk encoded for this protocol step.
    let dk_encoded = Encoded::<MlKem768Dk>::try_from(dk_bytes)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::KemBindingMismatch)?;
    // Track the count for threshold and bounds checking.
    // Compute dk for this protocol step.
    // Compute dk for this protocol step.
    let dk: MlKem768Dk = EncodedSizeUser::from_bytes(&dk_encoded);

    // Deserialize ciphertext (Array::try_from checks length).
    // Compute ct encoded for this protocol step.
    // Compute ct encoded for this protocol step.
    let ct_encoded = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct_bytes)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| X3dhError::KemBindingMismatch)?;

    // Decapsulate.
    // Compute pq ss for this protocol step.
    // Compute pq ss for this protocol step.
    let pq_ss = dk.decapsulate(&ct_encoded).map_err(|_| X3dhError::KemBindingMismatch)?;
    // Track the count for threshold and bounds checking.
    // Compute ss for this protocol step.
    // Compute ss for this protocol step.
    let mut ss = [0u8; KEM_SS_SIZE];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    ss.copy_from_slice(pq_ss.as_slice());
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
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
// Perform the 'compute kem binding' operation.
// Errors are propagated to the caller via Result.
// Perform the 'compute kem binding' operation.
// Errors are propagated to the caller via Result.
fn compute_kem_binding(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    eph_dh_shared: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    kem_ciphertext: &[u8],
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> Result<[u8; 32], X3dhError> {
    // Initialize the MAC for authentication tag computation.
    // Compute mac for this protocol step.
    // Compute mac for this protocol step.
    let mut mac =
        // SHA-256 cryptographic hash.
        // Execute this protocol step.
        // Execute this protocol step.
        <Hmac<Sha256> as Mac>::new_from_slice(eph_dh_shared)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| X3dhError::HmacKeyError)?;
    // Domain separator first — prevents cross-protocol binding reuse.
    // Feed data into the running computation.
    // Feed data into the running computation.
    mac.update(KEM_BINDING_INFO);
    // KEM ciphertext is the committed value being bound.
    // Feed data into the running computation.
    // Feed data into the running computation.
    mac.update(kem_ciphertext);
    // Initialize the MAC for authentication tag computation.
    // Compute result for this protocol step.
    // Compute result for this protocol step.
    let result = mac.finalize();
    // Execute the operation and bind the result.
    // Compute binding for this protocol step.
    // Compute binding for this protocol step.
    let mut binding = [0u8; 32];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    binding.copy_from_slice(&result.into_bytes());
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(binding)
}

/// Verify KEM binding on the responder side.
///
/// Recomputes `compute_kem_binding` and compares in constant time (via the
/// direct array comparison that avoids short-circuit evaluation).  Returns
/// `X3dhError::KemBindingMismatch` on any mismatch.
// Perform the 'verify kem binding' operation.
// Errors are propagated to the caller via Result.
// Perform the 'verify kem binding' operation.
// Errors are propagated to the caller via Result.
fn verify_kem_binding(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    eph_dh_shared: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    kem_ciphertext: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    expected_binding: &[u8; 32],
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> Result<(), X3dhError> {
    // Initialize the AEAD cipher with the derived key material.
    // Compute computed for this protocol step.
    // Compute computed for this protocol step.
    let computed = compute_kem_binding(eph_dh_shared, kem_ciphertext)?;
    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if computed != *expected_binding {
        // Reject with an explicit error for the caller to handle.
        // Return to the caller.
        // Return to the caller.
        return Err(X3dhError::KemBindingMismatch);
    }
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
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
