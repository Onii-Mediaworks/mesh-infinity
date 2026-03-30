//! AOS (Abe-Ohkubo-Suzuki) Ring Signatures over Curve25519 (Spec SS 3.5.2)
//!
//! # What is a ring signature?
//!
//! A ring signature allows a member of a group (the "ring") to sign a message
//! proving they are ONE of the members, WITHOUT revealing WHICH member they are.
//! Any verifier can confirm that the signature was produced by someone in the
//! ring, but cannot determine which specific member signed.
//!
//! # Why does Mesh Infinity need this?
//!
//! Ring signatures enable privacy-preserving group operations:
//! - **Anonymous polls**: vote without revealing your identity to the group.
//! - **Whistleblower channels**: prove group membership without attribution.
//! - **Privacy-preserving moderation**: take action as "a moderator" without
//!   revealing which moderator acted.
//!
//! # Algorithm: AOS ring signatures
//!
//! The AOS construction (Abe, Ohkubo, Suzuki 2002) works as follows:
//!
//! 1. The signer knows one secret key `x` corresponding to public key `P = xG`
//!    at position `s` in the ring `{P_0, P_1, ..., P_{n-1}}`.
//!
//! 2. A "key image" `I = x * H_p(P_s)` is computed, where `H_p` hashes the
//!    public key to a curve point. This key image is deterministic for a given
//!    key, enabling **linkability detection** (same signer produces the same
//!    key image across different messages) without deanonymization.
//!
//! 3. The signer picks a random scalar `alpha` and computes commitments:
//!    - `L_s = alpha * G`  (the "left" commitment at the signer's position)
//!    - `R_s = alpha * H_p(P_s)`  (the "right" commitment using the hash point)
//!
//! 4. For all other positions `i != s`, the signer picks random challenge `c_i`
//!    and response `r_i` values, and computes the corresponding commitments:
//!    - `L_i = r_i * G + c_i * P_i`
//!    - `R_i = r_i * H_p(P_i) + c_i * I`
//!
//! 5. The ring is "closed" by computing the signer's challenge and response
//!    such that the hash of all commitments forms a consistent ring.
//!
//! # Linkability
//!
//! The key image `I` is the same for all signatures by the same key, regardless
//! of message or ring composition. This allows detecting when the same signer
//! signs twice (e.g., double-voting) without revealing who that signer is.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during ring signature operations.
///
/// Each variant captures a specific failure mode so callers can
/// distinguish between "bad input" and "crypto failure" without
/// inspecting error messages.
#[derive(Debug, Error)]
pub enum RingSignatureError {
    /// The ring has fewer than 2 members.  A singleton ring would
    /// trivially identify the signer, defeating the purpose of
    /// ring signatures entirely.
    #[error("ring must contain at least 2 public keys (got {0})")]
    RingTooSmall(usize),

    /// The signer's public key (derived from the secret key) is not
    /// present in the ring.  The signer MUST be a member of the ring
    /// to produce a valid signature.
    #[error("signer's public key not found in the ring")]
    SignerNotInRing,

    /// A public key in the ring could not be decompressed to a valid
    /// Ed25519 curve point.  This means the key bytes do not represent
    /// a point on the curve.
    #[error("invalid public key at ring position {0}")]
    InvalidPublicKey(usize),

    /// The hash-to-point operation produced the identity element,
    /// which would make the key image trivially zero and break
    /// the linkability property.
    #[error("hash-to-point produced the identity element")]
    HashToPointIdentity,
}

// ---------------------------------------------------------------------------
// Ring signature structure
// ---------------------------------------------------------------------------

/// A ring signature proving the signer is one of the public keys in the ring,
/// without revealing which one.
///
/// The signature consists of `n` challenge-response pairs (one per ring member)
/// plus a key image that enables linkability detection.
///
/// # Size
///
/// For a ring of `n` members:
/// - `c`: n * 32 bytes (one 32-byte challenge per member)
/// - `r`: n * 32 bytes (one 32-byte response per member)
/// - `key_image`: 32 bytes (compressed Edwards point)
/// - Total: 64n + 32 bytes
#[derive(Clone, Debug)]
pub struct RingSignature {
    /// The challenge values, one per ring member.
    ///
    /// These form a "chain" where each challenge depends on the previous
    /// member's commitment.  The chain must wrap around consistently
    /// (the last challenge leads back to the first) for the signature
    /// to be valid.
    pub c: Vec<[u8; 32]>,

    /// The response values, one per ring member.
    ///
    /// For the real signer, the response is computed to "close" the ring.
    /// For all other positions, responses are random values chosen by the
    /// signer during signature generation.
    pub r: Vec<[u8; 32]>,

    /// Key image: a per-signer tag that is deterministic for a given secret key.
    ///
    /// Computed as `I = x * H_p(P)` where `x` is the secret key and `P` is the
    /// corresponding public key.  Because `x` is fixed and `H_p(P)` is
    /// deterministic, the key image is the same across all signatures by the
    /// same key.  This enables **double-vote detection**: if two signatures
    /// share the same key image, they were produced by the same signer —
    /// without revealing which ring member that signer is.
    pub key_image: [u8; 32],
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Hash a public key to a curve point using the "try-and-increment" method.
///
/// This is `H_p` in the AOS construction.  We need a function that maps
/// an arbitrary public key to a "random-looking" point on the Ed25519 curve
/// such that nobody knows the discrete logarithm of the output relative to
/// the standard base point G.
///
/// # Method: hash-and-try
///
/// 1. Hash the public key with a counter: `h = SHA-512("meshinfinity-ring-hp-v1" || key || counter)`
/// 2. Interpret the first 32 bytes as a compressed Edwards Y coordinate.
/// 3. Attempt to decompress.  If it fails (not all Y coordinates correspond
///    to valid curve points), increment the counter and try again.
/// 4. Multiply by the cofactor (8) to ensure the result is in the prime-order
///    subgroup.  This prevents small-subgroup attacks where a malicious ring
///    member could craft a key whose hash-point has a small-order component.
///
/// # Why SHA-512?
///
/// We need 32 bytes of output that look uniformly random.  SHA-512 gives us
/// 64 bytes; we take the first 32 as a candidate Y coordinate.  Using SHA-256
/// would also work, but SHA-512 provides more bits of entropy to draw from.
fn hash_to_point(public_key: &[u8; 32]) -> Result<EdwardsPoint, RingSignatureError> {
    /// Domain separator for the hash-to-point function.
    /// Prevents cross-protocol attacks where a hash computed for another
    /// purpose could be reinterpreted as a hash-to-point output.
    const DOMAIN: &[u8] = b"meshinfinity-ring-hp-v1";

    // Try successive counter values until we find a valid curve point.
    // In practice this almost always succeeds on the first try (~50% of
    // random 32-byte strings are valid compressed Edwards Y coordinates).
    for counter in 0u32..256 {
        // Hash: domain || public_key || counter (little-endian).
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN);
        hasher.update(public_key);
        hasher.update(counter.to_le_bytes());
        let hash_output = hasher.finalize();

        // Take the first 32 bytes as a candidate compressed Y coordinate.
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&hash_output[..32]);

        // Attempt to decompress to a curve point.
        let compressed = CompressedEdwardsY(candidate);
        if let Some(point) = compressed.decompress() {
            // Multiply by the cofactor (8) to project into the prime-order subgroup.
            // This is CRITICAL for security: without cofactor clearing, a malicious
            // ring member could submit a public key whose hash-point has a small-order
            // component, leaking information about the signer's secret key.
            let cofactored = point.mul_by_cofactor();

            // Reject the identity element — it would make the key image zero,
            // which is the same for all signers and breaks linkability.
            if cofactored.is_identity() {
                continue;
            }

            return Ok(cofactored);
        }
    }

    // If we tried 256 counter values and none produced a valid point,
    // something is seriously wrong with the input key.
    Err(RingSignatureError::HashToPointIdentity)
}

/// Compute the challenge hash for one step of the ring.
///
/// This is the hash function `H` used in the ring construction:
/// `c_{i+1} = H(message, L_i, R_i)`
///
/// where L_i and R_i are the left and right commitments at position i.
///
/// # Domain separation
///
/// The hash includes a domain separator to prevent cross-protocol attacks.
/// It also includes the full message so the signature is bound to the
/// specific message being signed — changing the message invalidates the
/// entire ring.
fn challenge_hash(message: &[u8], l_point: &EdwardsPoint, r_point: &EdwardsPoint) -> Scalar {
    /// Domain separator for the challenge hash.
    const DOMAIN: &[u8] = b"meshinfinity-ring-challenge-v1";

    let mut hasher = Sha256::new();

    // Include the domain separator first (standard practice for domain separation).
    hasher.update(DOMAIN);

    // Include the message — this binds the signature to the message.
    // Changing the message changes all challenge values, invalidating the ring.
    hasher.update((message.len() as u64).to_le_bytes());
    hasher.update(message);

    // Include the left commitment point (compressed to 32 bytes).
    hasher.update(l_point.compress().as_bytes());

    // Include the right commitment point (compressed to 32 bytes).
    hasher.update(r_point.compress().as_bytes());

    // Reduce the 256-bit hash output to a scalar modulo the curve order.
    // SHA-256 produces exactly 32 bytes, which we interpret as a little-endian
    // integer and reduce mod l (the order of the Ed25519 base point).
    let hash_bytes = hasher.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash_bytes);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive the Ed25519 public key (as an Edwards point) from a 32-byte secret key.
///
/// Ed25519 key derivation: hash the secret key with SHA-512, take the lower
/// 32 bytes, clamp them (clear low 3 bits, set bit 254, clear bit 255),
/// and multiply by the base point G.
///
/// This matches the standard Ed25519 key derivation used by ed25519-dalek,
/// ensuring that the public keys in the ring (which come from Ed25519 keypairs)
/// are consistent with the secret key provided for signing.
fn secret_to_public_point(secret_key: &[u8; 32]) -> (Scalar, EdwardsPoint) {
    // Hash the secret key with SHA-512 (standard Ed25519 derivation).
    let mut hasher = Sha512::new();
    hasher.update(secret_key);
    let hash = hasher.finalize();

    // Take the lower 32 bytes and apply Ed25519 clamping.
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);

    // Clamping: these three operations are mandated by the Ed25519 spec.
    // - Clear the lowest 3 bits: ensures the scalar is a multiple of 8
    //   (the cofactor), preventing small-subgroup attacks.
    // - Set bit 254: ensures the scalar has a fixed bit length, preventing
    //   timing side-channels in variable-time scalar multiplication.
    // - Clear bit 255: ensures the scalar fits in 255 bits (the curve order
    //   is slightly less than 2^255).
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;

    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);

    // Compute the public key point: P = scalar * G.
    let public_point = &*ED25519_BASEPOINT_TABLE * &scalar;

    (scalar, public_point)
}

/// Convert an Edwards point to its 32-byte compressed representation.
///
/// This is used to compare public keys in the ring with the signer's
/// derived public key.  Comparison is done on compressed bytes rather
/// than curve points to avoid constant-time comparison issues with
/// the EdwardsPoint type.
fn point_to_bytes(point: &EdwardsPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sign `message` as one of the members in `ring`.
///
/// # Arguments
///
/// * `secret_key` - The signer's Ed25519 secret key (32 bytes).  This is the
///   raw secret key, NOT the expanded/hashed form.  The function derives the
///   corresponding public key internally.
///
/// * `ring` - The set of public keys forming the ring.  Each key is a 32-byte
///   compressed Edwards Y coordinate (the standard Ed25519 public key format).
///   The signer's public key MUST be included in this set.
///
/// * `message` - The message to sign.  Can be empty (the ring signature still
///   covers the message hash, which for an empty message is the hash of the
///   empty string).
///
/// # Returns
///
/// A `RingSignature` that can be verified against the full ring using
/// `ring_verify`.  The signature does not reveal which ring member signed.
///
/// # Errors
///
/// - `RingTooSmall` if the ring has fewer than 2 members.
/// - `SignerNotInRing` if the signer's public key is not in the ring.
/// - `InvalidPublicKey` if any ring member's key is not a valid curve point.
/// - `HashToPointIdentity` if hash-to-point fails (extremely unlikely).
pub fn ring_sign(
    secret_key: &[u8; 32],
    ring: &[[u8; 32]],
    message: &[u8],
) -> Result<RingSignature, RingSignatureError> {
    let n = ring.len();

    // --- Validate ring size -------------------------------------------------
    // A ring of size 0 or 1 provides no anonymity.  Size 1 trivially reveals
    // the signer (there's only one possible signer).  We require at least 2.
    if n < 2 {
        return Err(RingSignatureError::RingTooSmall(n));
    }

    // --- Derive signer's keypair -------------------------------------------
    // Compute the signer's public key from the secret key using standard
    // Ed25519 derivation, so we can find the signer's position in the ring.
    let (signer_scalar, signer_point) = secret_to_public_point(secret_key);
    let signer_public_bytes = point_to_bytes(&signer_point);

    // --- Find signer's position in the ring --------------------------------
    // Linear scan through the ring to find which position matches the signer's
    // public key.  This is O(n) but ring sizes are typically small (< 100).
    let signer_index = ring
        .iter()
        .position(|pk| *pk == signer_public_bytes)
        .ok_or(RingSignatureError::SignerNotInRing)?;

    // --- Decompress all ring public keys to curve points --------------------
    // We need the actual curve points for the ring computation, not just
    // compressed bytes.  Validate each key while decompressing.
    let mut ring_points = Vec::with_capacity(n);
    for (i, pk_bytes) in ring.iter().enumerate() {
        let compressed = CompressedEdwardsY(*pk_bytes);
        let point = compressed
            .decompress()
            .ok_or(RingSignatureError::InvalidPublicKey(i))?;
        ring_points.push(point);
    }

    // --- Compute hash-to-point for each ring member -------------------------
    // H_p(P_i) is needed for the "right side" commitments R_i.
    // Pre-computing these avoids redundant hashing in the ring loop.
    let mut hp_points = Vec::with_capacity(n);
    for pk_bytes in ring.iter() {
        hp_points.push(hash_to_point(pk_bytes)?);
    }

    // --- Compute key image --------------------------------------------------
    // I = signer_scalar * H_p(P_signer)
    // This is deterministic: the same secret key always produces the same
    // key image regardless of the message or ring composition.
    let key_image = signer_scalar * hp_points[signer_index];

    // --- Generate the signer's random commitment ----------------------------
    // Pick a random scalar `alpha` for the signer's position.  This is the
    // "real" randomness that the signer knows — all other positions use
    // simulated values.
    let alpha = Scalar::random(&mut rand_core::OsRng);

    // L_s = alpha * G  (left commitment at signer's position)
    let l_signer = &*ED25519_BASEPOINT_TABLE * &alpha;

    // R_s = alpha * H_p(P_s)  (right commitment at signer's position)
    let r_signer = alpha * hp_points[signer_index];

    // --- Initialize challenge and response arrays ---------------------------
    let mut c_scalars: Vec<Scalar> = vec![Scalar::ZERO; n];
    let mut r_scalars: Vec<Scalar> = vec![Scalar::ZERO; n];

    // --- Compute the challenge at position (signer_index + 1) mod n ---------
    // This is the first "real" challenge derived from the signer's commitment.
    let next_index = (signer_index + 1) % n;
    c_scalars[next_index] = challenge_hash(message, &l_signer, &r_signer);

    // --- Fill in the rest of the ring (simulated positions) ------------------
    // Starting from the position after the signer, we go around the ring,
    // picking random responses and computing the corresponding challenges.
    // This works because for non-signer positions we can freely choose both
    // the challenge and response (they just need to be consistent).
    let mut current = next_index;
    while current != signer_index {
        // Pick a random response for this position.
        let r_i = Scalar::random(&mut rand_core::OsRng);
        r_scalars[current] = r_i;

        // Compute L_i = r_i * G + c_i * P_i
        // This is the verification equation for position i.
        // We know both r_i (we just chose it) and c_i (computed from the
        // previous position's hash), so we can compute L_i directly.
        let l_i = &*ED25519_BASEPOINT_TABLE * &r_i + c_scalars[current] * ring_points[current];

        // Compute R_i = r_i * H_p(P_i) + c_i * I
        // Same idea, but using the hash-point and key image.
        let r_point_i = r_i * hp_points[current] + c_scalars[current] * key_image;

        // Derive the challenge for the next position from this position's commitments.
        let next = (current + 1) % n;
        c_scalars[next] = challenge_hash(message, &l_i, &r_point_i);

        current = next;
    }

    // --- Close the ring at the signer's position ----------------------------
    // At this point, c_scalars[signer_index] has been filled in by the
    // wrap-around from the last simulated position.  We need to compute
    // r_scalars[signer_index] such that the verification equation holds:
    //
    //   L_s = r_s * G + c_s * P_s  (must equal alpha * G)
    //
    // Solving for r_s:
    //   alpha * G = r_s * G + c_s * (signer_scalar * G)
    //   alpha = r_s + c_s * signer_scalar
    //   r_s = alpha - c_s * signer_scalar
    r_scalars[signer_index] = alpha - c_scalars[signer_index] * signer_scalar;

    // --- Convert scalars to byte arrays for the output ----------------------
    let c_bytes: Vec<[u8; 32]> = c_scalars.iter().map(|s| s.to_bytes()).collect();
    let r_bytes: Vec<[u8; 32]> = r_scalars.iter().map(|s| s.to_bytes()).collect();
    let key_image_bytes = point_to_bytes(&key_image);

    Ok(RingSignature {
        c: c_bytes,
        r: r_bytes,
        key_image: key_image_bytes,
    })
}

/// Verify a ring signature against a set of public keys.
///
/// # Arguments
///
/// * `ring` - The set of public keys forming the ring (same set used during signing).
/// * `message` - The original message that was signed.
/// * `signature` - The ring signature to verify.
///
/// # Returns
///
/// `true` if the signature is valid for the given ring and message, `false` otherwise.
///
/// # Verification algorithm
///
/// For each ring position `i`, reconstruct the commitments:
///   - `L_i = r_i * G + c_i * P_i`
///   - `R_i = r_i * H_p(P_i) + c_i * I`
///
/// Then verify that `c_{i+1} = H(message, L_i, R_i)` for all positions.
/// The ring is valid if and only if all challenges are consistent — i.e.,
/// starting from `c_0` and going around the ring, we arrive back at `c_0`.
pub fn ring_verify(ring: &[[u8; 32]], message: &[u8], signature: &RingSignature) -> bool {
    let n = ring.len();

    // --- Basic structural checks --------------------------------------------
    // The signature must have exactly as many challenges and responses as
    // there are ring members.  A size mismatch is always invalid.
    if n < 2 || signature.c.len() != n || signature.r.len() != n {
        return false;
    }

    // --- Decompress all ring public keys ------------------------------------
    let mut ring_points = Vec::with_capacity(n);
    for pk_bytes in ring.iter() {
        let compressed = CompressedEdwardsY(*pk_bytes);
        match compressed.decompress() {
            Some(point) => ring_points.push(point),
            // Invalid public key in ring — signature cannot be valid.
            None => return false,
        }
    }

    // --- Decompress the key image -------------------------------------------
    let key_image = match CompressedEdwardsY(signature.key_image).decompress() {
        Some(point) => point,
        // Invalid key image — signature cannot be valid.
        None => return false,
    };

    // --- Compute hash-to-point for each ring member -------------------------
    let mut hp_points = Vec::with_capacity(n);
    for pk_bytes in ring.iter() {
        match hash_to_point(pk_bytes) {
            Ok(point) => hp_points.push(point),
            // If hash-to-point fails for any ring member, verification fails.
            Err(_) => return false,
        }
    }

    // --- Reconstruct the ring and verify consistency ------------------------
    // Start from c_0 and verify that each step produces the expected next
    // challenge.  If the ring is consistent, we should arrive back at c_0
    // after going through all n positions.
    //
    // We store the initial c_0 and compare it with the computed c_0 at the end.
    let c_0 = Scalar::from_bytes_mod_order(signature.c[0]);

    let mut current_c = c_0;

    for i in 0..n {
        // Parse the response scalar for this position.
        let r_i = Scalar::from_bytes_mod_order(signature.r[i]);

        // Parse the challenge scalar for this position (should match current_c).
        let expected_c = Scalar::from_bytes_mod_order(signature.c[i]);

        // Verify that the current challenge matches the expected value.
        // For i == 0 this is trivially true (we started with c_0).
        // For subsequent positions, this verifies the chain is consistent.
        if current_c != expected_c {
            return false;
        }

        // Reconstruct L_i = r_i * G + c_i * P_i
        let l_i = &*ED25519_BASEPOINT_TABLE * &r_i + current_c * ring_points[i];

        // Reconstruct R_i = r_i * H_p(P_i) + c_i * I
        let r_point_i = r_i * hp_points[i] + current_c * key_image;

        // Compute the next challenge from this position's commitments.
        current_c = challenge_hash(message, &l_i, &r_point_i);
    }

    // --- Verify the ring closes ---------------------------------------------
    // After processing all n positions, current_c should equal c_0.
    // This is the fundamental ring property: the chain of challenges
    // wraps around to its starting point.
    current_c == c_0
}

/// Check if two ring signatures were produced by the same signer.
///
/// This function compares the key images of two ring signatures.  Because the
/// key image is deterministic for a given secret key (`I = x * H_p(P)`),
/// two signatures with the same key image MUST have been produced by the
/// same secret key — even if the rings or messages are different.
///
/// # Use cases
///
/// - **Double-vote detection**: in an anonymous poll, if two votes share a
///   key image, the second vote is a duplicate and should be rejected.
/// - **Rate limiting**: limit how many times a group member can perform a
///   certain action without knowing which member it is.
///
/// # Privacy guarantee
///
/// Linkability only reveals that two actions were by the SAME person.
/// It does NOT reveal WHICH person.  The anonymity set (the ring)
/// is preserved even when signatures are linked.
pub fn ring_signatures_linked(sig1: &RingSignature, sig2: &RingSignature) -> bool {
    // Constant-time comparison would be ideal here, but since key images are
    // public values (included in the signature), timing leaks on comparison
    // do not reveal any secret information.
    sig1.key_image == sig2.key_image
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate an Ed25519 keypair and return (secret_key, public_key).
    ///
    /// Uses ed25519-dalek to ensure the keys are in the standard Ed25519
    /// format that the rest of the codebase uses.
    fn generate_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        // Create a deterministic secret key from the seed byte (for test reproducibility).
        let secret = [seed; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let public = signing_key.verifying_key().to_bytes();
        (secret, public)
    }

    /// Helper: generate a ring of `n` keypairs and return
    /// (secrets, publics) where secrets[i] corresponds to publics[i].
    fn generate_ring(n: usize) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let mut secrets = Vec::with_capacity(n);
        let mut publics = Vec::with_capacity(n);
        for i in 0..n {
            // Use different seed bytes to get distinct keypairs.
            // Adding 1 avoids seed=0 which produces an all-zero secret.
            let (secret, public) = generate_keypair((i + 1) as u8);
            secrets.push(secret);
            publics.push(public);
        }
        (secrets, publics)
    }

    // -----------------------------------------------------------------------
    // Basic sign and verify
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_verify_ring_size_2() {
        let (secrets, publics) = generate_ring(2);
        let message = b"hello ring size 2";

        // Sign as the first member.
        let sig = ring_sign(&secrets[0], &publics, message).expect("signing failed");

        // Verify should succeed.
        assert!(ring_verify(&publics, message, &sig), "verification failed for ring size 2");
    }

    #[test]
    fn test_sign_verify_ring_size_3() {
        let (secrets, publics) = generate_ring(3);
        let message = b"hello ring size 3";

        // Sign as the second member (index 1).
        let sig = ring_sign(&secrets[1], &publics, message).expect("signing failed");
        assert!(ring_verify(&publics, message, &sig), "verification failed for ring size 3");
    }

    #[test]
    fn test_sign_verify_ring_size_5() {
        let (secrets, publics) = generate_ring(5);
        let message = b"hello ring size 5";

        // Sign as the last member (index 4).
        let sig = ring_sign(&secrets[4], &publics, message).expect("signing failed");
        assert!(ring_verify(&publics, message, &sig), "verification failed for ring size 5");
    }

    #[test]
    fn test_sign_verify_ring_size_10() {
        let (secrets, publics) = generate_ring(10);
        let message = b"hello ring size 10";

        // Sign as a middle member (index 5).
        let sig = ring_sign(&secrets[5], &publics, message).expect("signing failed");
        assert!(ring_verify(&publics, message, &sig), "verification failed for ring size 10");
    }

    #[test]
    fn test_all_positions_can_sign() {
        // Verify that signing works from EVERY position in the ring,
        // not just a specific position.  This catches off-by-one errors
        // in the ring closure logic.
        let (secrets, publics) = generate_ring(5);
        let message = b"test all positions";

        for i in 0..5 {
            let sig = ring_sign(&secrets[i], &publics, message)
                .unwrap_or_else(|e| panic!("signing failed at position {}: {}", i, e));
            assert!(
                ring_verify(&publics, message, &sig),
                "verification failed when signing from position {}",
                i
            );
        }
    }

    // -----------------------------------------------------------------------
    // Invalid signature detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_wrong_message_fails_verification() {
        let (secrets, publics) = generate_ring(3);
        let sig = ring_sign(&secrets[0], &publics, b"correct message").expect("signing failed");

        // Verifying with a different message must fail.
        assert!(
            !ring_verify(&publics, b"wrong message", &sig),
            "verification should fail for wrong message"
        );
    }

    #[test]
    fn test_wrong_ring_fails_verification() {
        let (secrets, publics) = generate_ring(3);
        let message = b"test wrong ring";
        let sig = ring_sign(&secrets[0], &publics, message).expect("signing failed");

        // Create a different ring with completely different keys (shifted seeds).
        let other_publics: Vec<[u8; 32]> = (0..3)
            .map(|i| generate_keypair((i + 50) as u8).1)
            .collect();

        // Verifying against the wrong ring must fail.
        assert!(
            !ring_verify(&other_publics, message, &sig),
            "verification should fail for wrong ring"
        );
    }

    #[test]
    fn test_tampered_challenge_fails() {
        let (secrets, publics) = generate_ring(3);
        let message = b"test tampered challenge";
        let mut sig = ring_sign(&secrets[0], &publics, message).expect("signing failed");

        // Tamper with one of the challenge values.
        sig.c[1][0] ^= 0xFF;

        assert!(
            !ring_verify(&publics, message, &sig),
            "verification should fail with tampered challenge"
        );
    }

    #[test]
    fn test_tampered_response_fails() {
        let (secrets, publics) = generate_ring(3);
        let message = b"test tampered response";
        let mut sig = ring_sign(&secrets[0], &publics, message).expect("signing failed");

        // Tamper with one of the response values.
        sig.r[0][0] ^= 0xFF;

        assert!(
            !ring_verify(&publics, message, &sig),
            "verification should fail with tampered response"
        );
    }

    #[test]
    fn test_tampered_key_image_fails() {
        let (secrets, publics) = generate_ring(3);
        let message = b"test tampered key image";
        let mut sig = ring_sign(&secrets[0], &publics, message).expect("signing failed");

        // Tamper with the key image.
        sig.key_image[0] ^= 0xFF;

        assert!(
            !ring_verify(&publics, message, &sig),
            "verification should fail with tampered key image"
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_ring_rejected() {
        let (secrets, _) = generate_ring(1);
        let result = ring_sign(&secrets[0], &[], b"message");
        assert!(
            matches!(result, Err(RingSignatureError::RingTooSmall(0))),
            "empty ring should be rejected"
        );
    }

    #[test]
    fn test_singleton_ring_rejected() {
        let (secrets, publics) = generate_ring(1);
        let result = ring_sign(&secrets[0], &publics, b"message");
        assert!(
            matches!(result, Err(RingSignatureError::RingTooSmall(1))),
            "singleton ring should be rejected"
        );
    }

    #[test]
    fn test_signer_not_in_ring() {
        let (_, publics) = generate_ring(3);
        // Generate a keypair that is NOT in the ring.
        let (outsider_secret, _) = generate_keypair(0xFF);

        let result = ring_sign(&outsider_secret, &publics, b"message");
        assert!(
            matches!(result, Err(RingSignatureError::SignerNotInRing)),
            "signer not in ring should be rejected"
        );
    }

    #[test]
    fn test_empty_message_allowed() {
        let (secrets, publics) = generate_ring(3);

        // Empty message is a valid input — the signature covers the hash
        // of the empty string, which is well-defined.
        let sig = ring_sign(&secrets[0], &publics, b"").expect("signing empty message failed");
        assert!(
            ring_verify(&publics, b"", &sig),
            "verification of empty message failed"
        );
    }

    #[test]
    fn test_verify_wrong_size_signature_fails() {
        let (secrets, publics) = generate_ring(3);
        let message = b"test wrong size";
        let mut sig = ring_sign(&secrets[0], &publics, message).expect("signing failed");

        // Remove a challenge entry to create a size mismatch.
        sig.c.pop();

        assert!(
            !ring_verify(&publics, message, &sig),
            "verification should fail with wrong-size signature"
        );
    }

    // -----------------------------------------------------------------------
    // Linkability
    // -----------------------------------------------------------------------

    #[test]
    fn test_same_signer_linked() {
        let (secrets, publics) = generate_ring(5);

        // Same signer signs two different messages.
        let sig1 = ring_sign(&secrets[2], &publics, b"message 1").expect("sign 1 failed");
        let sig2 = ring_sign(&secrets[2], &publics, b"message 2").expect("sign 2 failed");

        // Both signatures should be valid.
        assert!(ring_verify(&publics, b"message 1", &sig1));
        assert!(ring_verify(&publics, b"message 2", &sig2));

        // They should be linked (same key image).
        assert!(
            ring_signatures_linked(&sig1, &sig2),
            "signatures by the same signer should be linked"
        );
    }

    #[test]
    fn test_different_signers_not_linked() {
        let (secrets, publics) = generate_ring(5);

        // Different signers sign the same message.
        let sig1 = ring_sign(&secrets[0], &publics, b"same message").expect("sign 1 failed");
        let sig2 = ring_sign(&secrets[1], &publics, b"same message").expect("sign 2 failed");

        // Both signatures should be valid.
        assert!(ring_verify(&publics, b"same message", &sig1));
        assert!(ring_verify(&publics, b"same message", &sig2));

        // They should NOT be linked (different key images).
        assert!(
            !ring_signatures_linked(&sig1, &sig2),
            "signatures by different signers should not be linked"
        );
    }

    #[test]
    fn test_key_image_consistency_across_multiple_signatures() {
        let (secrets, publics) = generate_ring(4);

        // Same signer signs multiple messages — key image should be identical
        // across ALL of them.
        let sig_a = ring_sign(&secrets[1], &publics, b"msg a").expect("sign a failed");
        let sig_b = ring_sign(&secrets[1], &publics, b"msg b").expect("sign b failed");
        let sig_c = ring_sign(&secrets[1], &publics, b"msg c").expect("sign c failed");

        // All key images should be identical.
        assert_eq!(
            sig_a.key_image, sig_b.key_image,
            "key image should be consistent (a vs b)"
        );
        assert_eq!(
            sig_b.key_image, sig_c.key_image,
            "key image should be consistent (b vs c)"
        );

        // All should be linked to each other.
        assert!(ring_signatures_linked(&sig_a, &sig_b));
        assert!(ring_signatures_linked(&sig_b, &sig_c));
        assert!(ring_signatures_linked(&sig_a, &sig_c));
    }

    #[test]
    fn test_key_image_stable_across_different_rings() {
        // The key image depends only on the signer's key, NOT on the ring
        // composition.  Signing with the same key in two different rings
        // should produce the same key image.
        let (secrets, _) = generate_ring(5);

        // Ring 1: members 0, 1, 2
        let ring1 = vec![
            generate_keypair(1).1,
            generate_keypair(2).1,
            generate_keypair(3).1,
        ];

        // Ring 2: members 0, 3, 4 (different ring, same signer at index 0)
        let ring2 = vec![
            generate_keypair(1).1,
            generate_keypair(4).1,
            generate_keypair(5).1,
        ];

        let sig1 = ring_sign(&secrets[0], &ring1, b"msg").expect("sign in ring1 failed");
        let sig2 = ring_sign(&secrets[0], &ring2, b"msg").expect("sign in ring2 failed");

        // Key images should be the same (same signer).
        assert!(
            ring_signatures_linked(&sig1, &sig2),
            "key image should be stable across different rings"
        );
    }

    #[test]
    fn test_no_false_linkability() {
        // Ensure that ALL distinct signers in a ring produce distinct key images.
        let (secrets, publics) = generate_ring(5);
        let message = b"uniqueness test";

        let mut key_images = Vec::with_capacity(5);
        for i in 0..5 {
            let sig = ring_sign(&secrets[i], &publics, message).expect("signing failed");
            key_images.push(sig.key_image);
        }

        // Verify all key images are distinct.
        for i in 0..key_images.len() {
            for j in (i + 1)..key_images.len() {
                assert_ne!(
                    key_images[i], key_images[j],
                    "signers {} and {} produced the same key image",
                    i, j
                );
            }
        }
    }
}
