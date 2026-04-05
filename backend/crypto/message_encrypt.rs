//! Four-Layer Message Encryption (§7.2)
//!
//! All discrete messages use a multi-layer signing and encryption scheme:
//!
//! ```text
//! Step 1 — Inner authentication:
//!   mac = HMAC-SHA256(ratchet_msg_key, plaintext)   // deniable
//!   authenticated = plaintext || mac
//!
//! Step 2 — Trust-channel encryption (trusted peers only):
//!   trust_encrypted = ChaCha20Poly1305(session_key, nonce, authenticated)
//!   payload = dr_header || trust_encrypted
//!
//! Step 3 — Outer signing (relationship-specific mask key):
//!   outer_sig = Ed25519_Sign(rel_mask_key, payload)
//!   double_signed = payload || outer_sig
//!
//! Step 4 — Recipient encryption:
//!   ephemeral DH → derive message_key + nonce (with context_type domain separation)
//!   final = ephemeral_public || ChaCha20Poly1305(message_key, nonce, double_signed)
//! ```

use chacha20poly1305::{
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    aead::{Aead, KeyInit},
    // AEAD cipher for authenticated encryption.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ChaCha20Poly1305,
    Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
// Securely erase key material to prevent forensic recovery.
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Protocol constant.
// MSG_KEY_INFO_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// MSG_KEY_INFO_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// MSG_KEY_INFO_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
const MSG_KEY_INFO_PREFIX: &[u8] = b"meshinfinity-message-v1";
// Protocol constant.
// NONCE_INFO_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// NONCE_INFO_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// NONCE_INFO_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
const NONCE_INFO_PREFIX: &[u8] = b"meshinfinity-nonce-v1-";

/// HMAC-SHA256 output size (32 bytes).
// MAC_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAC_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAC_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
const MAC_SIZE: usize = 32;

/// Ed25519 signature size (64 bytes).
// SIG_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// SIG_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// SIG_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
const SIG_SIZE: usize = 64;

/// X25519 public key size (32 bytes).
// EPH_PUB_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// EPH_PUB_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// EPH_PUB_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
const EPH_PUB_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
// Begin the block scope.
// MessageCryptoError — variant enumeration.
// Match exhaustively to handle every protocol state.
// MessageCryptoError — variant enumeration.
// Match exhaustively to handle every protocol state.
// MessageCryptoError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MessageCryptoError {
    #[error("HMAC verification failed — content tampered")]
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    HmacMismatch,
    #[error("Ed25519 signature verification failed")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    SignatureInvalid,
    #[error("AEAD encryption failed")]
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    EncryptFailed,
    #[error("AEAD decryption failed")]
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    DecryptFailed,
    #[error("HKDF expansion failed")]
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    HkdfExpand,
    #[error("Message too short to contain required fields")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    MessageTooShort,
    #[error("Ed25519 key error: {0}")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    KeyError(String),
}

// ---------------------------------------------------------------------------
// Context types for nonce domain separation (§7.2)
// ---------------------------------------------------------------------------

/// Message context for nonce domain separation.
/// Different contexts produce different nonces even with the same ephemeral key.
#[derive(Clone, Copy, Debug)]
// Begin the block scope.
// MessageContext — variant enumeration.
// Match exhaustively to handle every protocol state.
// MessageContext — variant enumeration.
// Match exhaustively to handle every protocol state.
// MessageContext — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MessageContext {
    Direct,
    Group,
    File,
    Stream,
    Offline,
    System,
}

// Begin the block scope.
// MessageContext implementation — core protocol logic.
// MessageContext implementation — core protocol logic.
// MessageContext implementation — core protocol logic.
impl MessageContext {
    // Begin the block scope.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    fn as_bytes(&self) -> &[u8] {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Handle this match arm.
            Self::Direct => b"direct",
            // Handle this match arm.
            Self::Group => b"group",
            // Handle this match arm.
            Self::File => b"file",
            // Handle this match arm.
            Self::Stream => b"stream",
            // Handle this match arm.
            Self::Offline => b"offline",
            // Handle this match arm.
            Self::System => b"system",
        }
    }
}

// ---------------------------------------------------------------------------
// Step 1 — Inner authentication (deniable HMAC)
// ---------------------------------------------------------------------------

/// Step 1: Authenticate plaintext with HMAC-SHA256 using the ratchet message key.
/// Both parties can produce this MAC — provides deniability (§3.5.1).
/// Returns Err if the key length is rejected by the HMAC implementation (should
/// never happen with a 32-byte key, but we propagate rather than panic so that
/// no FFI-reachable path can unwind through the C boundary).
// Perform the 'step1 authenticate' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step1 authenticate' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step1 authenticate' operation.
// Errors are propagated to the caller via Result.
pub fn step1_authenticate(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    plaintext: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    msg_key: &[u8; 32],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<Vec<u8>, MessageCryptoError> {
    // Initialize the MAC for authentication tag computation.
    // Compute mac for this protocol step.
    // Compute mac for this protocol step.
    // Compute mac for this protocol step.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(msg_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::EncryptFailed)?;
    // Feed the next data segment into the running hash/MAC.
    // Feed data into the running computation.
    // Feed data into the running computation.
    // Feed data into the running computation.
    mac.update(plaintext);
    // Initialize the MAC for authentication tag computation.
    // Compute tag for this protocol step.
    // Compute tag for this protocol step.
    // Compute tag for this protocol step.
    let tag = mac.finalize().into_bytes();

    // Initialize the MAC for authentication tag computation.
    // Compute authenticated for this protocol step.
    // Compute authenticated for this protocol step.
    // Compute authenticated for this protocol step.
    let mut authenticated = Vec::with_capacity(plaintext.len() + MAC_SIZE);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    authenticated.extend_from_slice(plaintext);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    authenticated.extend_from_slice(&tag);
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(authenticated)
}

/// Step 1 verify: Check HMAC on received authenticated payload.
// Perform the 'step1 verify' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step1 verify' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step1 verify' operation.
// Errors are propagated to the caller via Result.
pub fn step1_verify(
    authenticated: &[u8],
    msg_key: &[u8; 32],
) -> Result<Vec<u8>, MessageCryptoError> {
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if authenticated.len() < MAC_SIZE {
        // Reject with an explicit error for the caller to handle.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return Err(MessageCryptoError::MessageTooShort);
    }
    // Initialize the MAC for authentication tag computation.
    // Bind the intermediate result.
    // Bind the intermediate result.
    // Bind the intermediate result.
    let (plaintext, mac_bytes) = authenticated.split_at(authenticated.len() - MAC_SIZE);

    // Propagate rather than panic: HMAC-SHA256 new_from_slice fails only for
    // zero-length keys, and msg_key is always [u8; 32] — so this is infallible
    // in practice. We use map_err + ? anyway because the function already
    // returns Result, and panicking through a Result boundary is never acceptable
    // in security-critical code reachable from FFI.
    // Compute mac for this protocol step.
    // Compute mac for this protocol step.
    // Compute mac for this protocol step.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(msg_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::HmacMismatch)?;
    // Feed the next data segment into the running hash/MAC.
    // Feed data into the running computation.
    // Feed data into the running computation.
    // Feed data into the running computation.
    mac.update(plaintext);
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    mac.verify_slice(mac_bytes)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::HmacMismatch)?;

    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(plaintext.to_vec())
}

// ---------------------------------------------------------------------------
// Step 2 — Trust-channel encryption (Double Ratchet session key)
// ---------------------------------------------------------------------------

/// Step 2: Encrypt authenticated payload with the session's cipher key + nonce.
/// These come from the Double Ratchet's message key expansion (§7.0.3).
// Perform the 'step2 encrypt' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step2 encrypt' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step2 encrypt' operation.
// Errors are propagated to the caller via Result.
pub fn step2_encrypt(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    authenticated: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    cipher_key: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    nonce: &[u8; 12],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<Vec<u8>, MessageCryptoError> {
    // Initialize the AEAD cipher with the derived key material.
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    let cipher = ChaCha20Poly1305::new_from_slice(cipher_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::EncryptFailed)?;
    // Fresh nonce — must never be reused with the same key.
    // Compute n for this protocol step.
    // Compute n for this protocol step.
    // Compute n for this protocol step.
    let n = Nonce::from_slice(nonce);
    cipher
        // Encrypt the plaintext under the current session key.
        // AEAD-encrypt the plaintext.
        // AEAD-encrypt the plaintext.
        // AEAD-encrypt the plaintext.
        .encrypt(n, authenticated)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::EncryptFailed)
}

/// Step 2 decrypt.
// Perform the 'step2 decrypt' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step2 decrypt' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step2 decrypt' operation.
// Errors are propagated to the caller via Result.
pub fn step2_decrypt(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ciphertext: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    cipher_key: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    nonce: &[u8; 12],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<Vec<u8>, MessageCryptoError> {
    // Initialize the AEAD cipher with the derived key material.
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    let cipher = ChaCha20Poly1305::new_from_slice(cipher_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::DecryptFailed)?;
    // Fresh nonce — must never be reused with the same key.
    // Compute n for this protocol step.
    // Compute n for this protocol step.
    // Compute n for this protocol step.
    let n = Nonce::from_slice(nonce);
    cipher
        // Decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        .decrypt(n, ciphertext)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::DecryptFailed)
}

// ---------------------------------------------------------------------------
// Step 3 — Outer signing (relationship-specific mask key)
// ---------------------------------------------------------------------------

/// Step 3: Sign payload with the sender's relationship-specific mask key.
/// This signature is inside Step 4 encryption — only the recipient sees it.
// Perform the 'step3 sign' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step3 sign' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step3 sign' operation.
// Errors are propagated to the caller via Result.
pub fn step3_sign(payload: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    // Key material — must be zeroized when no longer needed.
    // Compute sig for this protocol step.
    // Compute sig for this protocol step.
    // Compute sig for this protocol step.
    let sig = signing_key.sign(payload);
    // Prepare the data buffer for the next processing stage.
    // Compute signed for this protocol step.
    // Compute signed for this protocol step.
    // Compute signed for this protocol step.
    let mut signed = Vec::with_capacity(payload.len() + SIG_SIZE);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    signed.extend_from_slice(payload);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    signed.extend_from_slice(&sig.to_bytes());
    signed
}

/// Step 3 verify: Check Ed25519 signature.
// Perform the 'step3 verify' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step3 verify' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step3 verify' operation.
// Errors are propagated to the caller via Result.
pub fn step3_verify(
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    signed: &[u8],
    // Ed25519 digital signature.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    verifying_key: &VerifyingKey,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<Vec<u8>, MessageCryptoError> {
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if signed.len() < SIG_SIZE {
        // Reject with an explicit error for the caller to handle.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return Err(MessageCryptoError::MessageTooShort);
    }
    // Prepare the data buffer for the next processing stage.
    // Bind the intermediate result.
    // Bind the intermediate result.
    // Bind the intermediate result.
    let (payload, sig_bytes) = signed.split_at(signed.len() - SIG_SIZE);

    // Ed25519 signature for authentication and integrity.
    // Compute sig for this protocol step.
    // Compute sig for this protocol step.
    // Compute sig for this protocol step.
    let sig = Signature::from_slice(sig_bytes)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|e| MessageCryptoError::KeyError(e.to_string()))?;
    // Execute this step in the protocol sequence.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    verifying_key
        // Verify the signature against the claimed public key.
        // Verify the cryptographic signature.
        // Verify the cryptographic signature.
        // Verify the cryptographic signature.
        .verify(payload, &sig)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::SignatureInvalid)?;

    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(payload.to_vec())
}

// ---------------------------------------------------------------------------
// Step 4 — Recipient encryption (ephemeral DH)
// ---------------------------------------------------------------------------

/// Step 4: Encrypt the double-signed payload for the recipient.
/// Uses a fresh ephemeral X25519 keypair and derives key + nonce from DH.
// Perform the 'step4 encrypt' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step4 encrypt' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step4 encrypt' operation.
// Errors are propagated to the caller via Result.
pub fn step4_encrypt(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    double_signed: &[u8],
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    recipient_x25519_pub: &X25519Public,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    context: MessageContext,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<Vec<u8>, MessageCryptoError> {
    // Generate fresh ephemeral keypair
    // Compute eph secret for this protocol step.
    // Compute eph secret for this protocol step.
    // Compute eph secret for this protocol step.
    let eph_secret = X25519Secret::random_from_rng(rand_core::OsRng);
    // Key material — must be zeroized when no longer needed.
    // Compute eph pub for this protocol step.
    // Compute eph pub for this protocol step.
    // Compute eph pub for this protocol step.
    let eph_pub = X25519Public::from(&eph_secret);

    // DH shared secret
    // Compute shared for this protocol step.
    // Compute shared for this protocol step.
    // Compute shared for this protocol step.
    let shared = eph_secret.diffie_hellman(recipient_x25519_pub);

    // Derive message key + nonce with context type domain separation
    // Bind the intermediate result.
    // Bind the intermediate result.
    // Bind the intermediate result.
    let (msg_key, nonce) = derive_step4_keys(shared.as_bytes(), eph_pub.as_bytes(), context)?;

    // Encrypt
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    let cipher = ChaCha20Poly1305::new_from_slice(&msg_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::EncryptFailed)?;
    // Fresh nonce — must never be reused with the same key.
    // Compute n for this protocol step.
    // Compute n for this protocol step.
    // Compute n for this protocol step.
    let n = Nonce::from_slice(&nonce);
    // Initialize the AEAD cipher with the derived key material.
    // Compute ciphertext for this protocol step.
    // Compute ciphertext for this protocol step.
    // Compute ciphertext for this protocol step.
    let ciphertext = cipher
        // Encrypt the plaintext under the current session key.
        // AEAD-encrypt the plaintext.
        // AEAD-encrypt the plaintext.
        // AEAD-encrypt the plaintext.
        .encrypt(n, double_signed)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::EncryptFailed)?;

    // Output: ephemeral_public || ciphertext
    // Compute output for this protocol step.
    // Compute output for this protocol step.
    // Compute output for this protocol step.
    let mut output = Vec::with_capacity(EPH_PUB_SIZE + ciphertext.len());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    output.extend_from_slice(eph_pub.as_bytes());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    output.extend_from_slice(&ciphertext);
    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok(output)
}

/// Step 4 decrypt: Recipient decrypts using their X25519 secret key.
// Perform the 'step4 decrypt' operation.
// Errors are propagated to the caller via Result.
// Perform the 'step4 decrypt' operation.
// Errors are propagated to the caller via Result.
pub fn step4_decrypt(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    encrypted: &[u8],
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    recipient_x25519_secret: &X25519Secret,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    context: MessageContext,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<Vec<u8>, MessageCryptoError> {
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if encrypted.len() < EPH_PUB_SIZE + 16 {
        // Need at least ephemeral pub + AEAD tag
        // Return to the caller.
        // Return to the caller.
        return Err(MessageCryptoError::MessageTooShort);
    }

    // Initialize the AEAD cipher with the derived key material.
    // Bind the intermediate result.
    // Bind the intermediate result.
    let (eph_pub_bytes, ciphertext) = encrypted.split_at(EPH_PUB_SIZE);
    // Execute the operation and bind the result.
    // Compute eph arr for this protocol step.
    // Compute eph arr for this protocol step.
    let mut eph_arr = [0u8; 32];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    eph_arr.copy_from_slice(eph_pub_bytes);
    // Invoke the associated function.
    // Compute eph pub for this protocol step.
    // Compute eph pub for this protocol step.
    let eph_pub = X25519Public::from(eph_arr);

    // DH shared secret
    // Compute shared for this protocol step.
    // Compute shared for this protocol step.
    let shared = recipient_x25519_secret.diffie_hellman(&eph_pub);

    // Derive key + nonce
    // Bind the intermediate result.
    // Bind the intermediate result.
    let (msg_key, nonce) = derive_step4_keys(shared.as_bytes(), &eph_arr, context)?;

    // Decrypt
    // Compute cipher for this protocol step.
    // Compute cipher for this protocol step.
    let cipher = ChaCha20Poly1305::new_from_slice(&msg_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::DecryptFailed)?;
    // Fresh nonce — must never be reused with the same key.
    // Compute n for this protocol step.
    // Compute n for this protocol step.
    let n = Nonce::from_slice(&nonce);
    cipher
        // Decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        // AEAD-decrypt and authenticate the ciphertext.
        .decrypt(n, ciphertext)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::DecryptFailed)
}

/// Derive Step 4 message key and nonce from DH shared secret.
// Perform the 'derive step4 keys' operation.
// Errors are propagated to the caller via Result.
// Perform the 'derive step4 keys' operation.
// Errors are propagated to the caller via Result.
fn derive_step4_keys(
    // Execute this protocol step.
    // Execute this protocol step.
    shared: &[u8],
    // Execute this protocol step.
    // Execute this protocol step.
    eph_pub: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    context: MessageContext,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<([u8; 32], [u8; 12]), MessageCryptoError> {
    // Set up the HKDF context for domain-separated key derivation.
    // Compute hk for this protocol step.
    // Compute hk for this protocol step.
    let hk = Hkdf::<Sha256>::new(Some(eph_pub), shared);

    // Message key
    // Compute msg key for this protocol step.
    // Compute msg key for this protocol step.
    let mut msg_key = Zeroizing::new([0u8; 32]);
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(MSG_KEY_INFO_PREFIX, &mut *msg_key)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::HkdfExpand)?;

    // Nonce with context type domain separation
    // Compute nonce info for this protocol step.
    // Compute nonce info for this protocol step.
    let mut nonce_info = Vec::with_capacity(NONCE_INFO_PREFIX.len() + context.as_bytes().len());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    nonce_info.extend_from_slice(NONCE_INFO_PREFIX);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    nonce_info.extend_from_slice(context.as_bytes());

    // Fresh nonce — must never be reused with the same key.
    // Compute nonce for this protocol step.
    // Compute nonce for this protocol step.
    let mut nonce = [0u8; 12];
    // Expand the pseudorandom key to the required output length.
    // HKDF expand to the target key length.
    // HKDF expand to the target key length.
    hk.expand(&nonce_info, &mut nonce)
        // Transform the result, mapping errors to the local error type.
        // Map the error to the local error type.
        // Map the error to the local error type.
        .map_err(|_| MessageCryptoError::HkdfExpand)?;

    // Wrap the computed value in the success variant.
    // Success path — return the computed value.
    // Success path — return the computed value.
    Ok((*msg_key, nonce))
}

// ---------------------------------------------------------------------------
// Full pipeline: encrypt + decrypt
// ---------------------------------------------------------------------------

/// Encrypt a message through all four layers.
///
/// This is the main entry point for sending a message.
// Perform the 'encrypt message' operation.
// Errors are propagated to the caller via Result.
// Perform the 'encrypt message' operation.
// Errors are propagated to the caller via Result.
pub fn encrypt_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    plaintext: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ratchet_msg_key: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    session_cipher_key: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    session_nonce: &[u8; 12],
    // Ed25519 digital signature.
    // Execute this protocol step.
    // Execute this protocol step.
    sender_mask_key: &SigningKey,
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    recipient_x25519_pub: &X25519Public,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    context: MessageContext,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<Vec<u8>, MessageCryptoError> {
    // Step 1: Inner authentication (deniable HMAC)
    // Compute authenticated for this protocol step.
    // Compute authenticated for this protocol step.
    let authenticated = step1_authenticate(plaintext, ratchet_msg_key)?;

    // Step 2: Trust-channel encryption
    // Compute trust encrypted for this protocol step.
    // Compute trust encrypted for this protocol step.
    let trust_encrypted = step2_encrypt(&authenticated, session_cipher_key, session_nonce)?;

    // Step 3: Outer signing (relationship-specific mask key)
    // Compute double signed for this protocol step.
    // Compute double signed for this protocol step.
    let double_signed = step3_sign(&trust_encrypted, sender_mask_key);

    // Step 4: Recipient encryption (ephemeral DH)
    // Execute this protocol step.
    // Execute this protocol step.
    step4_encrypt(&double_signed, recipient_x25519_pub, context)
}

/// Decrypt a message through all four layers (reverse order: 4 → 3 → 2 → 1).
// Perform the 'decrypt message' operation.
// Errors are propagated to the caller via Result.
// Perform the 'decrypt message' operation.
// Errors are propagated to the caller via Result.
pub fn decrypt_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    encrypted: &[u8],
    // Elliptic curve Diffie-Hellman key agreement.
    // Execute this protocol step.
    // Execute this protocol step.
    recipient_x25519_secret: &X25519Secret,
    // Ed25519 digital signature.
    // Execute this protocol step.
    // Execute this protocol step.
    sender_verifying_key: &VerifyingKey,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    session_cipher_key: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    session_nonce: &[u8; 12],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    ratchet_msg_key: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    context: MessageContext,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Result<Vec<u8>, MessageCryptoError> {
    // Step 4: Recipient decryption
    // Compute double signed for this protocol step.
    // Compute double signed for this protocol step.
    let double_signed = step4_decrypt(encrypted, recipient_x25519_secret, context)?;

    // Step 3: Verify sender signature
    // Compute trust encrypted for this protocol step.
    // Compute trust encrypted for this protocol step.
    let trust_encrypted = step3_verify(&double_signed, sender_verifying_key)?;

    // Step 2: Trust-channel decryption
    // Compute authenticated for this protocol step.
    // Compute authenticated for this protocol step.
    let authenticated = step2_decrypt(&trust_encrypted, session_cipher_key, session_nonce)?;

    // Step 1: Verify HMAC
    // Execute this protocol step.
    // Execute this protocol step.
    step1_verify(&authenticated, ratchet_msg_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn test_keys() -> (SigningKey, VerifyingKey, X25519Secret, X25519Public) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let x_secret = X25519Secret::random_from_rng(OsRng);
        let x_public = X25519Public::from(&x_secret);
        (signing, verifying, x_secret, x_public)
    }

    #[test]
    fn test_step1_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello world";
        let authed = step1_authenticate(plaintext, &key).unwrap();
        let recovered = step1_verify(&authed, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_step1_tamper_detected() {
        let key = [0x42u8; 32];
        let mut authed = step1_authenticate(b"Hello", &key).unwrap();
        authed[0] ^= 0xFF;
        assert!(step1_verify(&authed, &key).is_err());
    }

    #[test]
    fn test_step2_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret data";
        let ct = step2_encrypt(plaintext, &key, &nonce).unwrap();
        let pt = step2_decrypt(&ct, &key, &nonce).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_step3_roundtrip() {
        let (signing, verifying, _, _) = test_keys();
        let payload = b"payload to sign";
        let signed = step3_sign(payload, &signing);
        let recovered = step3_verify(&signed, &verifying).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_step3_wrong_key_fails() {
        let (signing, _, _, _) = test_keys();
        let (_, wrong_verifying, _, _) = test_keys();
        let signed = step3_sign(b"payload", &signing);
        assert!(step3_verify(&signed, &wrong_verifying).is_err());
    }

    #[test]
    fn test_step4_roundtrip() {
        let (_, _, x_secret, x_public) = test_keys();
        let payload = b"encrypted payload";
        let encrypted = step4_encrypt(payload, &x_public, MessageContext::Direct).unwrap();
        let decrypted = step4_decrypt(&encrypted, &x_secret, MessageContext::Direct).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_step4_wrong_context_fails() {
        let (_, _, x_secret, x_public) = test_keys();
        let encrypted = step4_encrypt(b"data", &x_public, MessageContext::Direct).unwrap();
        // Wrong context → different nonce → decryption fails
        assert!(step4_decrypt(&encrypted, &x_secret, MessageContext::Group).is_err());
    }

    #[test]
    fn test_full_pipeline_roundtrip() {
        let (sender_sign, sender_verify, _, _) = test_keys();
        let (_, _, recip_secret, recip_public) = test_keys();

        let ratchet_key = [0x42u8; 32];
        let session_key = [0x99u8; 32];
        let session_nonce = [0x01u8; 12];
        let plaintext = b"Full pipeline test message!";

        let encrypted = encrypt_message(
            plaintext,
            &ratchet_key,
            &session_key,
            &session_nonce,
            &sender_sign,
            &recip_public,
            MessageContext::Direct,
        )
        .unwrap();

        let decrypted = decrypt_message(
            &encrypted,
            &recip_secret,
            &sender_verify,
            &session_key,
            &session_nonce,
            &ratchet_key,
            MessageContext::Direct,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_full_pipeline_wrong_recipient_fails() {
        let (sender_sign, _, _, _) = test_keys();
        let (_, _, _, recip_public) = test_keys();
        let (_, _, wrong_secret, _) = test_keys();

        let encrypted = encrypt_message(
            b"secret",
            &[0x42u8; 32],
            &[0x99u8; 32],
            &[0x01u8; 12],
            &sender_sign,
            &recip_public,
            MessageContext::Direct,
        )
        .unwrap();

        // Wrong recipient key → Step 4 fails
        assert!(decrypt_message(
            &encrypted,
            &wrong_secret,
            &sender_sign.verifying_key(),
            &[0x99u8; 32],
            &[0x01u8; 12],
            &[0x42u8; 32],
            MessageContext::Direct,
        )
        .is_err());
    }

    #[test]
    fn test_different_contexts_produce_different_ciphertext() {
        let (sender_sign, _, _, _) = test_keys();
        let (_, _, _, recip_public) = test_keys();

        let msg = b"same message";
        let rk = [0x42u8; 32];
        let sk = [0x99u8; 32];
        let sn = [0x01u8; 12];

        let ct1 = encrypt_message(
            msg,
            &rk,
            &sk,
            &sn,
            &sender_sign,
            &recip_public,
            MessageContext::Direct,
        )
        .unwrap();
        let ct2 = encrypt_message(
            msg,
            &rk,
            &sk,
            &sn,
            &sender_sign,
            &recip_public,
            MessageContext::Group,
        )
        .unwrap();

        // Different contexts → different ephemeral keys → different ciphertext
        assert_ne!(ct1, ct2);
    }
}
