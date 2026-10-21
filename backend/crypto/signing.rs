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
///
/// v2: the signed preimage now includes the §8.3 `pairing_token` from the
/// scanned payload, so a hello is bound to one pairing session Alice issued
/// and an unsolicited hello from a stranger cannot create a contact.
// DOMAIN_PAIRING_HELLO — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_PAIRING_HELLO: &[u8] = b"meshinfinity-pairing-hello-v2";

/// Domain separator for the authenticated link handshake (§5.1 `MI-LINK-1`).
///
/// Both ends of a framed TCP link sign the counterpart's fresh nonce and
/// peer id under this domain before the connection is keyed on a peer id.
/// See `transport::link_auth` for the transcript layout.
// DOMAIN_LINK_AUTH — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_LINK_AUTH: &[u8] = b"meshinfinity-link-auth-v1";

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

/// Domain separator for group governance votes (§8.10).
pub const DOMAIN_GROUP_GOVERNANCE: &[u8] = b"meshinfinity-group-governance-v1";

/// Domain separator for key change validation signatures (§4.6).
pub const DOMAIN_KEY_CHANGE: &[u8] = b"meshinfinity-key-change-v1";

/// Domain separator for Garden (community) identity signatures (§10.2).
/// Used when signing Garden creation proofs and administrative actions.
pub const DOMAIN_GARDEN: &[u8] = b"meshinfinity-garden-v1";

/// Domain separator for plugin package signatures (§18).
/// Used when verifying that a plugin binary was signed by its claimed author.
/// Prevents replay of other signed types as plugin signatures.
// DOMAIN_PLUGIN_SIGNATURE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_PLUGIN_SIGNATURE: &[u8] = b"meshinfinity-plugin-sig-v1";

/// Domain separator for PQXDH KEM encapsulation key signatures (§3.4.1).
///
/// Used when signing `DOMAIN_PQXDH_KEM || kem_encapsulation_key` with the
/// Ed25519 identity key to bind the ML-KEM-768 public key to the identity.
/// Without this signature, an attacker could strip or substitute the KEM key
/// in a preauth bundle, silently downgrading the session from post-quantum
/// to classical X3DH without either party detecting the change.
// DOMAIN_PQXDH_KEM — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_PQXDH_KEM: &[u8] = b"meshinfinity-pqxdh-kem-v1";

/// Domain separator for signed tunnel-key bindings (§5.2, "Tunnel key
/// lifecycle").
///
/// A binding ties a role-scoped WireGuard static key and tunnel KEM prekey
/// to the mask's stable map identity key.  Without the domain, a signature
/// over another record type could be replayed as a binding.
// DOMAIN_TUNNEL_KEY_BINDING — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_TUNNEL_KEY_BINDING: &[u8] = b"meshinfinity-tunnel-key-binding-v1";

/// Domain separator for trusted-tunnel PSK agreement messages (§5.2,
/// "Trusted-tunnel PSK").
///
/// Both agreement messages are signed by the relationship mask keys; the
/// domain keeps them distinct from every other signed record.
// DOMAIN_TUNNEL_PSK — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_TUNNEL_PSK: &[u8] = b"meshinfinity-tunnel-psk-agreement-v1";

/// Domain separator for the untrusted-channel first message (§7.2 Step 1,
/// "For untrusted messages"; §10.1.1 message requests).
///
/// Signed by the sender's relationship-specific mask key for the recipient —
/// the §3.1.6 relationship role — never by the stable mask identity key, so
/// the signature is meaningful only inside that one relationship and is not
/// portable proof of authorship (§7.3).  The same relationship key produces
/// the undomained Step 3 outer signature, so this separator is what keeps a
/// request signature from ever being presented as a Step 3 signature, or a
/// Step 3 signature as a request.
// DOMAIN_MESSAGE_REQUEST — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_MESSAGE_REQUEST: &[u8] = b"meshinfinity-message-request-v1";

// ---------------------------------------------------------------------------
// Key roles (§3.1.6 Key Role Separation)
// ---------------------------------------------------------------------------

/// The role of the key that may produce a signature under a given domain.
///
/// §3.1.6 gives every key exactly one role and forbids using a key outside
/// that role unless a section of the spec explicitly says so.  Every
/// `DOMAIN_*` separator in this module is bound to exactly one role in
/// `KEY_ROLES_BY_DOMAIN`; `key_role_for_domain` looks that binding up, and the
/// tests enforce that no separator exists without a binding.
///
/// Only Ed25519 domains appear in the table.  The ratchet, tunnel and
/// ephemeral roles are still listed here so the enum is the complete §3.1.6
/// vocabulary and callers can name them, but no signing domain may bind to
/// `RatchetSession` or `Tunnel`: those roles authenticate with symmetric
/// keys (HMAC / AEAD), never with a signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRole {
    /// Stable identity keys: mask Ed25519 keys, the Layer 1 mesh identity
    /// key, and their PQXDH protocol-identity bindings.  They sign identity
    /// bindings, key rotations and revocations, map and routing entries,
    /// service records, release metadata, prekey bundles and tunnel-key
    /// bindings.  They MUST NOT sign conversation payloads, message
    /// requests, presence, or any other per-message structure.
    StableIdentity,
    /// Relationship keys: the relationship-specific mask key of §7.2 Step 3
    /// and the `channel_key` of §3.2.  They authenticate one relationship to
    /// its other party only, and are never disclosed outside it.
    Relationship,
    /// Ratchet and session keys (§7.0.3, §7.4): the primary conversation
    /// authentication.  Symmetric, so both parties can produce it and
    /// neither can prove to a third party that the other did.
    RatchetSession,
    /// Tunnel keys (§5.2): per-hop plumbing only; derive nothing above the
    /// tunnel.
    Tunnel,
    /// Ephemeral keys (§3.3, §7.2 Step 4, §15 cancellation keypairs): live
    /// for one session or one message and are destroyed afterwards.
    Ephemeral,
}

/// Every domain separator in this module, bound to the single key role that
/// may sign under it (§3.1.6).
///
/// The first element is the constant's own name so the table test can match
/// the table against this source file: a new `DOMAIN_*` constant without a
/// row here, or a row naming a constant that no longer exists, fails
/// `test_every_domain_has_exactly_one_key_role`.  The table is the single
/// list of separators; the uniqueness test iterates it too.
pub const KEY_ROLES_BY_DOMAIN: &[(&str, &[u8], KeyRole)] = &[
    // Routing announcements are map entries signed by the announcing node's
    // stable identity (§6.2, §4.5).
    (
        "DOMAIN_ROUTING_ANNOUNCEMENT",
        DOMAIN_ROUTING_ANNOUNCEMENT,
        KeyRole::StableIdentity,
    ),
    // §6.8 states the expiry is "signed by the sender's Ed25519 key"; the
    // section names the key explicitly, which §3.1.6 allows.
    (
        "DOMAIN_SF_EXPIRY",
        DOMAIN_SF_EXPIRY,
        KeyRole::StableIdentity,
    ),
    // A trust promotion intent is a trust-graph binding by the promoting
    // mask (§8.4).
    (
        "DOMAIN_TRUST_PROMOTION",
        DOMAIN_TRUST_PROMOTION,
        KeyRole::StableIdentity,
    ),
    // Service records are named in §3.1.6 as a stable-key structure (§12.4).
    (
        "DOMAIN_SERVICE_RECORD",
        DOMAIN_SERVICE_RECORD,
        KeyRole::StableIdentity,
    ),
    // Tunnel coordination gossip is signed by the Layer 1 mesh identity
    // (§6.10).
    (
        "DOMAIN_TUNNEL_GOSSIP",
        DOMAIN_TUNNEL_GOSSIP,
        KeyRole::StableIdentity,
    ),
    // DNS records are published, long-lived bindings (§17.11).
    (
        "DOMAIN_DNS_RECORD",
        DOMAIN_DNS_RECORD,
        KeyRole::StableIdentity,
    ),
    // A relay request is the requesting node's stable identity asking for
    // service (§6.11).
    (
        "DOMAIN_RELAY_REQUEST",
        DOMAIN_RELAY_REQUEST,
        KeyRole::StableIdentity,
    ),
    // A delivery receipt is a per-message acknowledgement visible to the
    // sender only; §3.1.6 forbids a stable key on any per-message structure.
    (
        "DOMAIN_DELIVERY_RECEIPT",
        DOMAIN_DELIVERY_RECEIPT,
        KeyRole::Relationship,
    ),
    // A stop-storing signal is "signed by publisher" (§11.2.7).
    (
        "DOMAIN_STOP_STORING",
        DOMAIN_STOP_STORING,
        KeyRole::StableIdentity,
    ),
    // A Sigma proof demonstrates ownership of a mask identity key (§3.5).
    (
        "DOMAIN_SIGMA_PROOF",
        DOMAIN_SIGMA_PROOF,
        KeyRole::StableIdentity,
    ),
    // Profile linkage claims bind identities to each other (§9.6).
    (
        "DOMAIN_PROFILE_LINKAGE",
        DOMAIN_PROFILE_LINKAGE,
        KeyRole::StableIdentity,
    ),
    // Group profiles are signed by the group's identity key (§8.7).
    (
        "DOMAIN_GROUP_PROFILE",
        DOMAIN_GROUP_PROFILE,
        KeyRole::StableIdentity,
    ),
    // Killswitch and retirement are identity lifecycle events (§3.9, §9.1).
    (
        "DOMAIN_KILLSWITCH",
        DOMAIN_KILLSWITCH,
        KeyRole::StableIdentity,
    ),
    (
        "DOMAIN_RETIREMENT",
        DOMAIN_RETIREMENT,
        KeyRole::StableIdentity,
    ),
    // Cancellation signals are signed by an ephemeral cancellation keypair
    // that is unlinkable to the sender's identity (§15, dead man's switch).
    (
        "DOMAIN_CANCELLATION",
        DOMAIN_CANCELLATION,
        KeyRole::Ephemeral,
    ),
    // Pairing binds two identities; the hello is signed by the stable key
    // the scanner is about to add (§8.3).
    (
        "DOMAIN_PAIRING_HELLO",
        DOMAIN_PAIRING_HELLO,
        KeyRole::StableIdentity,
    ),
    // The link handshake proves ownership of the peer id the link is keyed
    // on, which is an identity binding (§5.1 `MI-LINK-1`).
    (
        "DOMAIN_LINK_AUTH",
        DOMAIN_LINK_AUTH,
        KeyRole::StableIdentity,
    ),
    // LAN discovery acks prove the responder holds the identity it
    // advertises (§4.9.5).
    (
        "DOMAIN_LAN_DISCOVER",
        DOMAIN_LAN_DISCOVER,
        KeyRole::StableIdentity,
    ),
    // Governance votes are cast by member mask identities (§8.10).
    (
        "DOMAIN_GROUP_GOVERNANCE",
        DOMAIN_GROUP_GOVERNANCE,
        KeyRole::StableIdentity,
    ),
    // Key change: the old stable key authorises the new one (§4.6).
    (
        "DOMAIN_KEY_CHANGE",
        DOMAIN_KEY_CHANGE,
        KeyRole::StableIdentity,
    ),
    // Garden creation proofs and admin actions (§10.2).
    ("DOMAIN_GARDEN", DOMAIN_GARDEN, KeyRole::StableIdentity),
    // Plugin packages are signed by the author's stable key (§18).
    (
        "DOMAIN_PLUGIN_SIGNATURE",
        DOMAIN_PLUGIN_SIGNATURE,
        KeyRole::StableIdentity,
    ),
    // Prekey bundles are a stable-key structure in §3.1.6 (§3.4.1, §7.0.1).
    (
        "DOMAIN_PQXDH_KEM",
        DOMAIN_PQXDH_KEM,
        KeyRole::StableIdentity,
    ),
    // Tunnel-key bindings are named in §3.1.6 as a stable-key structure
    // (§5.2).
    (
        "DOMAIN_TUNNEL_KEY_BINDING",
        DOMAIN_TUNNEL_KEY_BINDING,
        KeyRole::StableIdentity,
    ),
    // Both PSK agreement messages are signed by the relationship mask keys
    // (§5.2 "Trusted-tunnel PSK").
    (
        "DOMAIN_TUNNEL_PSK",
        DOMAIN_TUNNEL_PSK,
        KeyRole::Relationship,
    ),
    // The untrusted-channel first message is signed by the relationship
    // mask key for the recipient (§7.2 Step 1, §7.3).
    (
        "DOMAIN_MESSAGE_REQUEST",
        DOMAIN_MESSAGE_REQUEST,
        KeyRole::Relationship,
    ),
];

/// The key role bound to `domain`, or `None` for a separator this module
/// does not define.
///
/// Callers that choose a signing key by role can assert the choice against
/// this lookup, so an out-of-role key is caught at the call site rather
/// than by convention (§3.1.6 "enforce the invariant in the key-handle
/// layer, not by convention").
pub fn key_role_for_domain(domain: &[u8]) -> Option<KeyRole> {
    // Linear scan: the table is a few dozen entries and this is never on a
    // per-packet hot path.
    KEY_ROLES_BY_DOMAIN
        .iter()
        .find(|(_, bound, _)| *bound == domain)
        .map(|(_, _, role)| *role)
}

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
pub fn sign(secret_key_bytes: &[u8; 32], domain: &[u8], message: &[u8]) -> Vec<u8> {
    // Build the signing key from the secret bytes.
    // ed25519_dalek uses the secret key to derive the full keypair.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key_bytes);

    // Build the domain-separated message.
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
    let sig = signing_key.sign(&signed_data);
    // Extract the raw byte representation for wire encoding.
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
pub fn verify(
    public_key_bytes: &[u8; 32],
    domain: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    // Parse the public key. Return false if invalid.
    let verifying_key = match VerifyingKey::from_bytes(public_key_bytes) {
        Ok(k) => k,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        // Error path — signal failure.
        // Error path — signal failure.
        Err(_) => return false,
    };

    // Parse the signature. Must be exactly 64 bytes.
    if signature_bytes.len() != 64 {
        return false;
    }
    // Ed25519 signature for authentication and integrity.
    let sig_array: [u8; 64] = match signature_bytes.try_into() {
        Ok(a) => a,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        // Error path — signal failure.
        // Error path — signal failure.
        Err(_) => return false,
    };
    // Ed25519 signature for authentication and integrity.
    let signature = Signature::from_bytes(&sig_array);

    // Build the domain-separated message.
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
pub fn verify_raw(public_key_bytes: &[u8; 32], message: &[u8], signature_bytes: &[u8]) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(public_key_bytes) {
        Ok(k) => k,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        // Error path — signal failure.
        Err(_) => return false,
    };

    // Validate the input length to prevent out-of-bounds access.
    if signature_bytes.len() != 64 {
        return false;
    }
    // Ed25519 signature for authentication and integrity.
    let sig_array: [u8; 64] = match signature_bytes.try_into() {
        Ok(a) => a,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        // Error path — signal failure.
        Err(_) => return false,
    };
    // Ed25519 signature for authentication and integrity.
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
        // Every separator in the role table must be distinct: a duplicate
        // would let a signature under one domain verify under another.
        let domains: Vec<&[u8]> = KEY_ROLES_BY_DOMAIN.iter().map(|(_, d, _)| *d).collect();

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

    /// Every `pub const DOMAIN_*` declared in this source file, by name.
    ///
    /// Parsed from the file itself so the invariant table cannot drift from
    /// the constants: adding a separator without classifying its key role
    /// (§3.1.6) fails the test below.
    fn declared_domain_names() -> Vec<String> {
        // The file is embedded at compile time; no filesystem access at test
        // run time, so the test is hermetic.
        let source = include_str!("signing.rs");
        source
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("pub const DOMAIN_"))
            // Only byte-string separators count: the `: &[u8]` annotation
            // excludes the role table itself and any mention in a comment.
            .filter_map(|rest| rest.split_once(": &[u8]"))
            // `strip_prefix` dropped the "DOMAIN_" prefix; put it back.
            .map(|(name, _)| format!("DOMAIN_{}", name.trim()))
            .collect()
    }

    /// §3.1.6 invariant table: every domain separator defined here is bound
    /// to exactly one key role, and every row names a real constant.
    #[test]
    fn test_every_domain_has_exactly_one_key_role() {
        let declared = declared_domain_names();
        assert!(
            !declared.is_empty(),
            "source scan found no DOMAIN_* constants"
        );

        // Direction 1: every declared constant has exactly one table row.
        for name in &declared {
            let rows = KEY_ROLES_BY_DOMAIN
                .iter()
                .filter(|(row_name, _, _)| row_name == name)
                .count();
            assert_eq!(
                rows, 1,
                "{} must have exactly one key-role row (§3.1.6), found {}",
                name, rows
            );
        }

        // Direction 2: every table row names a declared constant, so a
        // renamed or deleted constant cannot leave a stale row behind.
        for (row_name, _, _) in KEY_ROLES_BY_DOMAIN {
            assert!(
                declared.iter().any(|name| name == row_name),
                "table row {} names a constant that is not declared",
                row_name
            );
        }
        assert_eq!(KEY_ROLES_BY_DOMAIN.len(), declared.len());
    }

    /// Symmetric roles never sign: no Ed25519 domain may be bound to the
    /// ratchet-session or tunnel role (§3.1.6).
    #[test]
    fn test_symmetric_roles_bind_no_signing_domain() {
        for (name, _, role) in KEY_ROLES_BY_DOMAIN {
            assert!(
                !matches!(role, KeyRole::RatchetSession | KeyRole::Tunnel),
                "{} binds a signing domain to symmetric role {:?}",
                name,
                role
            );
        }
    }

    /// The per-message structures of §7.2 / §7.3 are relationship-keyed and
    /// the identity-binding structures are stable-keyed; the lookup must
    /// return the role the spec assigns, and nothing for a foreign domain.
    #[test]
    fn test_key_role_lookup_matches_spec() {
        assert_eq!(
            key_role_for_domain(DOMAIN_MESSAGE_REQUEST),
            Some(KeyRole::Relationship)
        );
        assert_eq!(
            key_role_for_domain(DOMAIN_TUNNEL_PSK),
            Some(KeyRole::Relationship)
        );
        assert_eq!(
            key_role_for_domain(DOMAIN_DELIVERY_RECEIPT),
            Some(KeyRole::Relationship)
        );
        assert_eq!(
            key_role_for_domain(DOMAIN_KEY_CHANGE),
            Some(KeyRole::StableIdentity)
        );
        assert_eq!(
            key_role_for_domain(DOMAIN_TUNNEL_KEY_BINDING),
            Some(KeyRole::StableIdentity)
        );
        assert_eq!(
            key_role_for_domain(DOMAIN_CANCELLATION),
            Some(KeyRole::Ephemeral)
        );
        assert_eq!(key_role_for_domain(b"meshinfinity-not-a-domain"), None);
    }
}
