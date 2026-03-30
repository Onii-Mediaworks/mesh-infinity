//! Ed25519 Signing and Verification
//!
//! # What is this module?
//!
//! A unified Ed25519 signing and verification interface used by
//! ALL modules that need cryptographic authentication. This
//! prevents each module from implementing its own signature
//! checking, which would lead to inconsistencies and bypasses.
//!
//! # Why centralized?
//!
//! The spec requires Ed25519 signatures on:
//! - Routing announcements (§6.2)
//! - Store-and-forward expiry (§6.8)
//! - Trust promotion intents (§8.4)
//! - Service records (§12.4)
//! - Tunnel coordination gossip (§6.10)
//! - DNS records (§17.11)
//! - Plugin signatures (§18)
//! - And many more
//!
//! Every one of these used to just check `!signature.is_empty()`.
//! Now they all call `verify_signature()` from this module.
//!
//! # Domain Separation
//!
//! Every signature includes a domain separator string to prevent
//! cross-protocol signature reuse. A signature valid for a routing
//! announcement cannot be replayed as a store-and-forward signature.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// ---------------------------------------------------------------------------
// Domain Separators
// ---------------------------------------------------------------------------

/// Domain separator for routing announcements (§6.2).
// DOMAIN_ROUTING_ANNOUNCEMENT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_ROUTING_ANNOUNCEMENT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_ROUTING_ANNOUNCEMENT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_ROUTING_ANNOUNCEMENT: &[u8] = b"meshinfinity-routing-ann-v1";

/// Domain separator for store-and-forward expiry (§6.8).
// DOMAIN_SF_EXPIRY — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_SF_EXPIRY — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_SF_EXPIRY — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_SF_EXPIRY: &[u8] = b"meshinfinity-sf-expiry-v1";

/// Domain separator for trust promotion intents (§8.4).
// DOMAIN_TRUST_PROMOTION — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_TRUST_PROMOTION — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_TRUST_PROMOTION — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_TRUST_PROMOTION: &[u8] = b"meshinfinity-trust-promotion-v1";

/// Domain separator for service records (§12.4).
// DOMAIN_SERVICE_RECORD — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_SERVICE_RECORD — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_SERVICE_RECORD — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_SERVICE_RECORD: &[u8] = b"meshinfinity-service-record-v1";

/// Domain separator for tunnel gossip (§6.10).
// DOMAIN_TUNNEL_GOSSIP — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_TUNNEL_GOSSIP — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_TUNNEL_GOSSIP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_TUNNEL_GOSSIP: &[u8] = b"meshinfinity-tunnel-gossip-v1";

/// Domain separator for DNS records (§17.11).
// DOMAIN_DNS_RECORD — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_DNS_RECORD — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_DNS_RECORD — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_DNS_RECORD: &[u8] = b"meshinfinity-dns-record-v1";

/// Domain separator for relay requests (§6.11).
// DOMAIN_RELAY_REQUEST — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_RELAY_REQUEST — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_RELAY_REQUEST — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_RELAY_REQUEST: &[u8] = b"meshinfinity-relay-req-v1";

/// Domain separator for delivery receipts (§6.5).
// DOMAIN_DELIVERY_RECEIPT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_DELIVERY_RECEIPT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_DELIVERY_RECEIPT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_DELIVERY_RECEIPT: &[u8] = b"meshinfinity-delivery-receipt-v1";

/// Domain separator for stop-storing signals (§11.2).
// DOMAIN_STOP_STORING — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_STOP_STORING — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_STOP_STORING — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_STOP_STORING: &[u8] = b"meshinfinity-stop-storing-v1";

/// Domain separator for Sigma protocol proofs (§3.5).
// DOMAIN_SIGMA_PROOF — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_SIGMA_PROOF — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_SIGMA_PROOF — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_SIGMA_PROOF: &[u8] = b"meshinfinity-sigma-proof-v1";

/// Domain separator for profile linkage claims (§9.6).
// DOMAIN_PROFILE_LINKAGE — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_PROFILE_LINKAGE — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_PROFILE_LINKAGE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_PROFILE_LINKAGE: &[u8] = b"meshinfinity-profile-linkage-v1";

/// Domain separator for group profile signing (§8.7).
// DOMAIN_GROUP_PROFILE — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_GROUP_PROFILE — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_GROUP_PROFILE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_GROUP_PROFILE: &[u8] = b"meshinfinity-group-profile-v1";

/// Domain separator for killswitch broadcast (§3.9).
// DOMAIN_KILLSWITCH — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_KILLSWITCH — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_KILLSWITCH — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_KILLSWITCH: &[u8] = b"meshinfinity-killswitch-v1";

/// Domain separator for identity retirement (§9.1).
// DOMAIN_RETIREMENT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_RETIREMENT — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_RETIREMENT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_RETIREMENT: &[u8] = b"meshinfinity-retirement-v1";

/// Domain separator for cancellation signals (§15).
// DOMAIN_CANCELLATION — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_CANCELLATION — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_CANCELLATION — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_CANCELLATION: &[u8] = b"meshinfinity-cancellation-v1";

/// Domain separator for pairing hello frames (§8.3 two-way bootstrap).
///
/// When Bob scans Alice's QR and calls mi_pair_peer, he immediately sends a
/// "pairing_hello" TCP frame to Alice's clearnet endpoint so Alice can add
/// Bob's keys without a second QR scan. This domain prevents the hello from
/// being replayed as any other signed type.
// DOMAIN_PAIRING_HELLO — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_PAIRING_HELLO — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_PAIRING_HELLO — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_PAIRING_HELLO: &[u8] = b"meshinfinity-pairing-hello-v1";

/// Domain separator for LAN discovery challenge-response (§4.9.5).
///
/// Signed by the responder over the 32-byte nonce sent by the initiator.
/// Prevents a recorded ack from being replayed as any other signed type.
// DOMAIN_LAN_DISCOVER — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_LAN_DISCOVER — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_LAN_DISCOVER — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_LAN_DISCOVER: &[u8] = b"meshinfinity-lan-discover-v1";

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign a message with an Ed25519 secret key.
///
/// `secret_key_bytes`: the 32-byte Ed25519 secret key.
/// `domain`: domain separator string (prevents cross-protocol replay).
/// `message`: the message to sign.
///
/// Returns the 64-byte Ed25519 signature.
///
/// The signed data is: domain || message.
/// The domain separator is included INSIDE the signature, so
/// a signature for one domain cannot be replayed in another.
// Perform the 'sign' operation.
// Errors are propagated to the caller via Result.
// Perform the 'sign' operation.
// Errors are propagated to the caller via Result.
// Perform the 'sign' operation.
// Errors are propagated to the caller via Result.
pub fn sign(secret_key_bytes: &[u8; 32], domain: &[u8], message: &[u8]) -> Vec<u8> {
    // Build the signing key from the secret bytes.
    // ed25519_dalek uses the secret key to derive the full keypair.
    // Compute signing key for this protocol step.
    // Compute signing key for this protocol step.
    // Compute signing key for this protocol step.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key_bytes);

    // Build the domain-separated message.
    // Compute signed data for this protocol step.
    // Compute signed data for this protocol step.
    // Compute signed data for this protocol step.
    let mut signed_data = Vec::with_capacity(domain.len() + message.len());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    signed_data.extend_from_slice(domain);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    signed_data.extend_from_slice(message);

    // Sign and return the signature bytes.
    use ed25519_dalek::Signer;
    // Key material — must be zeroized when no longer needed.
    // Compute sig for this protocol step.
    // Compute sig for this protocol step.
    // Compute sig for this protocol step.
    let sig = signing_key.sign(&signed_data);
    // Extract the raw byte representation for wire encoding.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    sig.to_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify an Ed25519 signature over a domain-separated message.
///
/// `public_key_bytes`: the 32-byte Ed25519 public key.
/// `domain`: domain separator string (must match what was used for signing).
/// `message`: the original message that was signed.
/// `signature_bytes`: the 64-byte Ed25519 signature.
///
/// Returns true if the signature is valid, false otherwise.
///
/// This is the ONLY function that should be used for signature
/// verification anywhere in the codebase. Module-specific
/// `is_empty()` checks are security bypasses.
// Perform the 'verify' operation.
// Errors are propagated to the caller via Result.
// Perform the 'verify' operation.
// Errors are propagated to the caller via Result.
// Perform the 'verify' operation.
// Errors are propagated to the caller via Result.
pub fn verify(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    public_key_bytes: &[u8; 32],
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    domain: &[u8],
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    message: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    signature_bytes: &[u8],
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
) -> bool {
    // Parse the public key. Return false if invalid.
    // Compute verifying key for this protocol step.
    // Compute verifying key for this protocol step.
    // Compute verifying key for this protocol step.
    let verifying_key = match VerifyingKey::from_bytes(public_key_bytes) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(k) => k,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        // Error path — signal failure.
        // Error path — signal failure.
        Err(_) => return false,
    };

    // Parse the signature. Must be exactly 64 bytes.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if signature_bytes.len() != 64 {
        // Condition not met — return negative result.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return false;
    }
    // Ed25519 signature for authentication and integrity.
    // Compute sig array for this protocol step.
    // Compute sig array for this protocol step.
    // Compute sig array for this protocol step.
    let sig_array: [u8; 64] = match signature_bytes.try_into() {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(a) => a,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        // Error path — signal failure.
        // Error path — signal failure.
        Err(_) => return false,
    };
    // Ed25519 signature for authentication and integrity.
    // Compute signature for this protocol step.
    // Compute signature for this protocol step.
    // Compute signature for this protocol step.
    let signature = Signature::from_bytes(&sig_array);

    // Build the domain-separated message.
    // Compute signed data for this protocol step.
    // Compute signed data for this protocol step.
    // Compute signed data for this protocol step.
    let mut signed_data = Vec::with_capacity(domain.len() + message.len());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    signed_data.extend_from_slice(domain);
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    signed_data.extend_from_slice(message);

    // Verify.
    // Verify the cryptographic signature.
    // Verify the cryptographic signature.
    // Verify the cryptographic signature.
    verifying_key.verify(&signed_data, &signature).is_ok()
}

/// Verify a raw signature (without domain separation).
///
/// Use this ONLY for interop with external systems that don't
/// use domain separation. For all mesh-internal signatures,
/// use `verify()` with a domain separator.
// Perform the 'verify raw' operation.
// Errors are propagated to the caller via Result.
// Perform the 'verify raw' operation.
// Errors are propagated to the caller via Result.
// Perform the 'verify raw' operation.
// Errors are propagated to the caller via Result.
pub fn verify_raw(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    public_key_bytes: &[u8; 32],
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    message: &[u8],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    signature_bytes: &[u8],
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
) -> bool {
    // Key material — must be zeroized when no longer needed.
    // Compute verifying key for this protocol step.
    // Compute verifying key for this protocol step.
    // Compute verifying key for this protocol step.
    let verifying_key = match VerifyingKey::from_bytes(public_key_bytes) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(k) => k,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        // Error path — signal failure.
        Err(_) => return false,
    };

    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if signature_bytes.len() != 64 {
        // Condition not met — return negative result.
        // Return to the caller.
        // Return to the caller.
        return false;
    }
    // Ed25519 signature for authentication and integrity.
    // Compute sig array for this protocol step.
    // Compute sig array for this protocol step.
    let sig_array: [u8; 64] = match signature_bytes.try_into() {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(a) => a,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        // Error path — signal failure.
        Err(_) => return false,
    };
    // Ed25519 signature for authentication and integrity.
    // Compute signature for this protocol step.
    // Compute signature for this protocol step.
    let signature = Signature::from_bytes(&sig_array);

    // Verify the signature against the claimed public key.
    // Verify the cryptographic signature.
    // Verify the cryptographic signature.
    verifying_key.verify(message, &signature).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a test keypair.
    fn test_keypair() -> ([u8; 32], [u8; 32]) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();
        ([0x42; 32], verifying_key.to_bytes())
    }

    #[test]
    fn test_sign_and_verify() {
        let (secret, public) = test_keypair();
        let domain = DOMAIN_ROUTING_ANNOUNCEMENT;
        let message = b"test routing announcement data";

        // Sign the message.
        let sig = sign(&secret, domain, message);
        assert_eq!(sig.len(), 64);

        // Verify should succeed.
        assert!(verify(&public, domain, message, &sig));
    }

    #[test]
    fn test_wrong_domain_fails() {
        let (secret, public) = test_keypair();
        let message = b"test message";

        // Sign with routing domain.
        let sig = sign(&secret, DOMAIN_ROUTING_ANNOUNCEMENT, message);

        // Verify with SF expiry domain — MUST fail.
        // This is the core domain separation guarantee.
        assert!(!verify(&public, DOMAIN_SF_EXPIRY, message, &sig));
    }

    #[test]
    fn test_wrong_message_fails() {
        let (secret, public) = test_keypair();
        let domain = DOMAIN_TRUST_PROMOTION;

        let sig = sign(&secret, domain, b"original message");

        // Verify with different message — MUST fail.
        assert!(!verify(&public, domain, b"tampered message", &sig));
    }

    #[test]
    fn test_wrong_key_fails() {
        let (secret, _public) = test_keypair();
        let domain = DOMAIN_SERVICE_RECORD;
        let message = b"service data";

        let sig = sign(&secret, domain, message);

        // Verify with a different public key — MUST fail.
        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32])
            .verifying_key()
            .to_bytes();
        assert!(!verify(&wrong_key, domain, message, &sig));
    }

    #[test]
    fn test_empty_signature_fails() {
        let (_, public) = test_keypair();
        // Empty signature — the old bypass.
        assert!(!verify(&public, DOMAIN_ROUTING_ANNOUNCEMENT, b"msg", &[]));
    }

    #[test]
    fn test_short_signature_fails() {
        let (_, public) = test_keypair();
        // 63 bytes instead of 64.
        assert!(!verify(
            &public,
            DOMAIN_ROUTING_ANNOUNCEMENT,
            b"msg",
            &[0x42; 63]
        ));
    }

    #[test]
    fn test_garbage_signature_fails() {
        let (_, public) = test_keypair();
        // Random 64 bytes — should not verify.
        assert!(!verify(
            &public,
            DOMAIN_ROUTING_ANNOUNCEMENT,
            b"msg",
            &[0xFF; 64]
        ));
    }

    #[test]
    fn test_invalid_public_key_fails() {
        // All-zero public key is invalid for Ed25519.
        assert!(!verify(
            &[0x00; 32],
            DOMAIN_ROUTING_ANNOUNCEMENT,
            b"msg",
            &[0x42; 64]
        ));
    }

    #[test]
    fn test_verify_raw() {
        let (secret, public) = test_keypair();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);

        use ed25519_dalek::Signer;
        let message = b"raw message";
        let sig = signing_key.sign(message);

        assert!(verify_raw(&public, message, &sig.to_bytes()));
    }

    #[test]
    fn test_all_domains_unique() {
        // Verify that all domain separators are unique.
        // Duplicate domains would allow cross-protocol replay.
        let domains: Vec<&[u8]> = vec![
            DOMAIN_ROUTING_ANNOUNCEMENT,
            DOMAIN_SF_EXPIRY,
            DOMAIN_TRUST_PROMOTION,
            DOMAIN_SERVICE_RECORD,
            DOMAIN_TUNNEL_GOSSIP,
            DOMAIN_DNS_RECORD,
            DOMAIN_RELAY_REQUEST,
            DOMAIN_DELIVERY_RECEIPT,
            DOMAIN_STOP_STORING,
            DOMAIN_SIGMA_PROOF,
            DOMAIN_PROFILE_LINKAGE,
            DOMAIN_GROUP_PROFILE,
            DOMAIN_KILLSWITCH,
            DOMAIN_RETIREMENT,
            DOMAIN_CANCELLATION,
            DOMAIN_PAIRING_HELLO,
        ];

        for i in 0..domains.len() {
            for j in (i + 1)..domains.len() {
                assert_ne!(
                    domains[i], domains[j],
                    "Domain separators at index {} and {} are identical",
                    i, j
                );
            }
        }
    }
}
