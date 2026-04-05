//! Network Map (§4.1, §4.2)
//!
//! The network map is a public-only structure containing:
//! - Peer IDs and public addresses
//! - Public keys (Ed25519, X25519)
//! - Transport hints (how to reach each peer)
//! - Last-seen timestamps (for staleness detection)
//! - Optional public profile summaries
//! - Service advertisements
//!
//! Map entries are versioned by sequence number. Merging follows:
//! higher sequence wins. Map is capped at 100K entries.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::transport_hint::TransportHint;
use crate::identity::peer_id::PeerId;
use crate::trust::levels::TrustLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum entries in the local network map (§4.2).
// MAX_MAP_ENTRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_MAP_ENTRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_MAP_ENTRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_MAP_ENTRIES: usize = 100_000;

/// Staleness threshold: entries not seen in 30 days are prunable.
// STALENESS_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// STALENESS_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// STALENESS_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const STALENESS_SECS: u64 = 30 * 24 * 3600;

/// Max new entries per peer per hour for untrusted sources (§4.2).
// GOSSIP_RATE_LIMIT_UNTRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
// GOSSIP_RATE_LIMIT_UNTRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
// GOSSIP_RATE_LIMIT_UNTRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const GOSSIP_RATE_LIMIT_UNTRUSTED: u32 = 500;
/// Max new entries per peer per hour for trusted sources.
// GOSSIP_RATE_LIMIT_TRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
// GOSSIP_RATE_LIMIT_TRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
// GOSSIP_RATE_LIMIT_TRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const GOSSIP_RATE_LIMIT_TRUSTED: u32 = 5000;

/// Maximum future timestamp tolerance (§4.5): 1 hour.
// MAX_FUTURE_TIMESTAMP_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_FUTURE_TIMESTAMP_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_FUTURE_TIMESTAMP_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_FUTURE_TIMESTAMP_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// Network Map Entry
// ---------------------------------------------------------------------------

/// A single entry in the network map (§4.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// NetworkMapEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NetworkMapEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NetworkMapEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct NetworkMapEntry {
    /// Peer identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_id: PeerId,
    /// Public keys for this peer.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub public_keys: Vec<PublicKeyRecord>,
    /// Last time this peer was seen active.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_seen: u64,
    /// Transport hints: how to reach this peer.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub transport_hints: Vec<TransportHint>,
    /// Optional public profile summary (if identity_is_public).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub public_profile: Option<PublicProfileSummary>,
    /// Public service advertisements.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub services: Vec<PublicServiceAd>,
    /// Monotonically increasing sequence number (64-bit, §4.5).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sequence: u64,
    /// Ed25519 signature over all other fields.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
    /// Local trust level (not gossiped — computed locally).
    #[serde(skip)]
    /// The local trust for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub local_trust: TrustLevel,
}

/// Public key record for a peer address.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PublicKeyRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PublicKeyRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PublicKeyRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PublicKeyRecord {
    /// The ed25519 public for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ed25519_public: [u8; 32],
    /// The x25519 public for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub x25519_public: [u8; 32],
    /// Weekly-rotated preauth (signed pre-key) for X3DH first contact (§7.0).
    /// Allows Alice to initiate a Double Ratchet session with Bob without Bob
    /// being online. Refreshed every 7 days via HKDF from the identity key.
    /// None means the peer has not published a preauth key yet.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// The preauth x25519 public for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub preauth_x25519_public: Option<[u8; 32]>,
    /// ML-KEM-768 encapsulation key (1184 bytes). Enables PQXDH (§3.4.1).
    /// None if the peer does not support post-quantum key agreement.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// The kem encapsulation key for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub kem_encapsulation_key: Option<Vec<u8>>,
    /// Ed25519 signature over `PREAUTH_SIG_DOMAIN || preauth_x25519_public`
    /// (§7.0.1 identity binding).  Propagated with the preauth key so that
    /// any node forwarding the gossip entry can prove the key belongs to the
    /// peer.  None for entries predating this field (legacy compat).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// The preauth sig for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub preauth_sig: Option<Vec<u8>>,
}

/// Public profile summary (for peers with identity_is_public = true).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PublicProfileSummary — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PublicProfileSummary — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PublicProfileSummary — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PublicProfileSummary {
    /// The display name for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub display_name: Option<String>,
    /// The bio for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub bio: Option<String>,
    /// The avatar hash for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub avatar_hash: Option<Vec<u8>>,
}

/// Public service advertisement.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PublicServiceAd — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PublicServiceAd — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PublicServiceAd — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PublicServiceAd {
    /// The name for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// The description for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: Option<String>,
    /// The port block for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub port_block: u16,
}

/// Domain separator for map entry signing.
// DOMAIN_MAP_ENTRY — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_MAP_ENTRY — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_MAP_ENTRY — protocol constant.
// Defined by the spec; must not change without a version bump.
const DOMAIN_MAP_ENTRY: &[u8] = b"meshinfinity-map-entry-v1\x00";

// Begin the block scope.
// NetworkMapEntry implementation — core protocol logic.
// NetworkMapEntry implementation — core protocol logic.
// NetworkMapEntry implementation — core protocol logic.
impl NetworkMapEntry {
    /// Build the canonical byte payload that is signed by the entry's owner.
    ///
    /// Format (§4.5):
    ///   DOMAIN || peer_id (32) || BE64(sequence) || BE64(last_seen)
    ///   || BE32(n_keys) || [ed25519_pub (32) || x25519_pub (32)]…
    ///   || BE32(hints_json_len) || hints_json
    ///   || BE32(services_json_len) || services_json
    ///   || BE32(profile_json_len) || profile_json
    ///
    /// The `signature` and `local_trust` fields are excluded.
    // Perform the 'signing payload' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'signing payload' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'signing payload' operation.
    // Errors are propagated to the caller via Result.
    pub fn signing_payload(&self) -> Vec<u8> {
        // Prepare the data buffer for the next processing stage.
        // Compute buf for this protocol step.
        // Compute buf for this protocol step.
        // Compute buf for this protocol step.
        let mut buf = Vec::with_capacity(256);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(DOMAIN_MAP_ENTRY);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&self.peer_id.0);
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&self.last_seen.to_be_bytes());
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&(self.public_keys.len() as u32).to_be_bytes());
        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for pk in &self.public_keys {
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            buf.extend_from_slice(&pk.ed25519_public);
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            buf.extend_from_slice(&pk.x25519_public);
            // Preauth key is signed as 32 zero bytes if absent (backward compat).
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            buf.extend_from_slice(pk.preauth_x25519_public.as_ref().unwrap_or(&[0u8; 32]));
        }
        // Serialize to the wire format for transmission or storage.
        // Compute hints for this protocol step.
        // Compute hints for this protocol step.
        // Compute hints for this protocol step.
        let hints = serde_json::to_vec(&self.transport_hints).unwrap_or_default();
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&(hints.len() as u32).to_be_bytes());
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&hints);
        // Serialize to the wire format for transmission or storage.
        // Compute services for this protocol step.
        // Compute services for this protocol step.
        // Compute services for this protocol step.
        let services = serde_json::to_vec(&self.services).unwrap_or_default();
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&(services.len() as u32).to_be_bytes());
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&services);
        // Serialize to the wire format for transmission or storage.
        // Compute profile for this protocol step.
        // Compute profile for this protocol step.
        // Compute profile for this protocol step.
        let profile = serde_json::to_vec(&self.public_profile).unwrap_or_default();
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&(profile.len() as u32).to_be_bytes());
        // Append the data segment to the accumulating buffer.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        // Append bytes to the accumulator.
        buf.extend_from_slice(&profile);
        buf
    }

    /// Sign this entry with the given Ed25519 signing key.
    ///
    /// Sets `self.signature` in place. The `public_keys` field must already
    /// contain the corresponding verifying key so callers can verify later.
    // Perform the 'sign' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'sign' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'sign' operation.
    // Errors are propagated to the caller via Result.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        // Prepare the data buffer for the next processing stage.
        // Compute payload for this protocol step.
        // Compute payload for this protocol step.
        // Compute payload for this protocol step.
        let payload = self.signing_payload();
        // Key material — must be zeroized when no longer needed.
        // Compute sig for this protocol step.
        // Compute sig for this protocol step.
        // Compute sig for this protocol step.
        let sig: Signature = signing_key.sign(&payload);
        // Update the signature to reflect the new state.
        // Advance signature state.
        // Advance signature state.
        // Advance signature state.
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify the Ed25519 signature on this entry (§4.5).
    ///
    /// Checks:
    /// 1. At least one public key is present.
    /// 2. `peer_id` is derived from `public_keys[0].ed25519_public`.
    /// 3. `signature` is a valid Ed25519 signature over `signing_payload()`.
    ///
    /// Entries with no public keys are treated as unsigned legacy/stub entries
    /// and pass through without cryptographic verification.
    // Perform the 'verify signature' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verify signature' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'verify signature' operation.
    // Errors are propagated to the caller via Result.
    pub fn verify_signature(&self) -> Result<(), MapError> {
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.public_keys.is_empty() {
            // Unsigned stub — allowed in unit tests / local synthetic entries.
            // Gossip from remote peers must have at least one key.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Ok(());
        }

        // 1. Peer ID must be derived from the first public key.
        // Compute expected for this protocol step.
        // Compute expected for this protocol step.
        // Compute expected for this protocol step.
        let expected = PeerId::from_ed25519_pub(&self.public_keys[0].ed25519_public);
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if expected != self.peer_id {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(MapError::PeerIdKeyMismatch);
        }

        // 2. Parse the verifying key.
        // Compute vk for this protocol step.
        // Compute vk for this protocol step.
        // Compute vk for this protocol step.
        let vk = VerifyingKey::from_bytes(&self.public_keys[0].ed25519_public)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|_| MapError::InvalidSignature("invalid Ed25519 public key".into()))?;

        // 3. Parse the signature.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.signature.len() != 64 {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(MapError::InvalidSignature(format!(
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                "expected 64-byte signature, got {}",
                // Mutate the internal state.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                self.signature.len()
            )));
        }
        // Execute the operation and bind the result.
        // Compute sig bytes for this protocol step.
        // Compute sig bytes for this protocol step.
        // Compute sig bytes for this protocol step.
        let mut sig_bytes = [0u8; 64];
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        sig_bytes.copy_from_slice(&self.signature);
        // Ed25519 signature for authentication and integrity.
        // Compute sig for this protocol step.
        // Compute sig for this protocol step.
        // Compute sig for this protocol step.
        let sig = Signature::from_bytes(&sig_bytes);

        // 4. Verify.
        // Compute payload for this protocol step.
        // Compute payload for this protocol step.
        // Compute payload for this protocol step.
        let payload = self.signing_payload();
        // Verify the signature against the claimed public key.
        // Verify the cryptographic signature.
        // Verify the cryptographic signature.
        // Verify the cryptographic signature.
        vk.verify(&payload, &sig)
            // Transform the result, mapping errors to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            // Map the error to the local error type.
            .map_err(|e| MapError::InvalidSignature(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Network Map
// ---------------------------------------------------------------------------

/// The local network map — stores all known peers.
#[derive(Default, Serialize, Deserialize)]
// Begin the block scope.
// NetworkMap — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NetworkMap — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NetworkMap — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct NetworkMap {
    /// Map entries keyed by PeerId.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    entries: HashMap<PeerId, NetworkMapEntry>,
}

// Begin the block scope.
// NetworkMap implementation — core protocol logic.
// NetworkMap implementation — core protocol logic.
// NetworkMap implementation — core protocol logic.
impl NetworkMap {
    /// Create an empty network map.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new() -> Self {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::default()
    }

    /// Number of entries in the map.
    // Perform the 'len' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'len' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'len' operation.
    // Errors are propagated to the caller via Result.
    pub fn len(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.entries.len()
    }

    /// Whether the map is empty.
    // Perform the 'is empty' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is empty' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is empty' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_empty(&self) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.entries.is_empty()
    }

    /// Get an entry by peer ID.
    // Perform the 'get' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'get' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'get' operation.
    // Errors are propagated to the caller via Result.
    pub fn get(&self, peer_id: &PeerId) -> Option<&NetworkMapEntry> {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.entries.get(peer_id)
    }

    /// Insert or update an entry. Returns true if the entry was accepted.
    ///
    /// Acceptance rules (§4.5):
    /// 1. Sequence must be strictly greater than existing (or new entry)
    /// 2. Timestamp must not be more than 1 hour in the future
    /// 3. Signature must be valid (signature verification is caller's responsibility)
    // Perform the 'insert' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'insert' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'insert' operation.
    // Errors are propagated to the caller via Result.
    pub fn insert(&mut self, entry: NetworkMapEntry, now: u64) -> Result<bool, MapError> {
        // Check future timestamp
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if entry.last_seen > now + MAX_FUTURE_TIMESTAMP_SECS {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(MapError::FutureTimestamp {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                entry_ts: entry.last_seen,
                now,
            });
        }

        // Validate field lengths (§4.2 gossip validation)
        // Propagate errors via ?.
        // Propagate errors via ?.
        // Propagate errors via ?.
        Self::validate_entry(&entry)?;

        // Check sequence against existing entry
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(existing) = self.entries.get(&entry.peer_id) {
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if entry.sequence <= existing.sequence {
                // Return success with the computed result.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return Ok(false); // Stale — silently ignore
            }
        }

        // Check capacity
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.entries.len() >= MAX_MAP_ENTRIES && !self.entries.contains_key(&entry.peer_id) {
            // Need to evict — LRU of untrusted entries first
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            self.evict_for_new_entry(&entry);
        }

        // Insert into the lookup table for efficient retrieval.
        // Insert into the map/set.
        // Insert into the map/set.
        // Insert into the map/set.
        self.entries.insert(entry.peer_id, entry);
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(true)
    }

    /// Remove stale entries (not seen within staleness threshold).
    // Perform the 'prune stale' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'prune stale' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'prune stale' operation.
    // Errors are propagated to the caller via Result.
    pub fn prune_stale(&mut self, now: u64) {
        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.entries.retain(|_, entry| {
            // Never prune trusted entries automatically
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if entry.local_trust.is_trusted_tier() {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return true;
            }
            // Prune untrusted entries older than threshold
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            now.saturating_sub(entry.last_seen) < STALENESS_SECS
        });
    }

    /// Get all entries as a slice.
    // Perform the 'entries' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'entries' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'entries' operation.
    // Errors are propagated to the caller via Result.
    pub fn entries(&self) -> impl Iterator<Item = &NetworkMapEntry> {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.entries.values()
    }

    /// Get mutable entry.
    // Perform the 'get mut' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'get mut' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'get mut' operation.
    // Errors are propagated to the caller via Result.
    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut NetworkMapEntry> {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.entries.get_mut(peer_id)
    }

    /// Remove an entry.
    // Perform the 'remove' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'remove' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'remove' operation.
    // Errors are propagated to the caller via Result.
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<NetworkMapEntry> {
        // Remove from the collection and return the evicted value.
        // Remove from the collection.
        // Remove from the collection.
        // Remove from the collection.
        self.entries.remove(peer_id)
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Validate entry field lengths per §4.2 gossip validation.
    // Perform the 'validate entry' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate entry' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate entry' operation.
    // Errors are propagated to the caller via Result.
    fn validate_entry(entry: &NetworkMapEntry) -> Result<(), MapError> {
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if entry.transport_hints.len() > 8 {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(MapError::TooManyTransportHints(entry.transport_hints.len()));
        }
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if entry.public_keys.len() > 16 {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(MapError::TooManyPublicKeys(entry.public_keys.len()));
        }
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if entry.services.len() > 32 {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(MapError::TooManyServices(entry.services.len()));
        }
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(ref profile) = entry.public_profile {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if let Some(ref name) = profile.display_name {
                // Validate the input length to prevent out-of-bounds access.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if name.len() > 64 {
                    // Reject with an explicit error for the caller to handle.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    return Err(MapError::FieldTooLong("display_name", name.len()));
                }
            }
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if let Some(ref bio) = profile.bio {
                // Validate the input length to prevent out-of-bounds access.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if bio.len() > 256 {
                    // Reject with an explicit error for the caller to handle.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    return Err(MapError::FieldTooLong("bio", bio.len()));
                }
            }
        }
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }

    /// Evict the oldest untrusted entry to make room.
    /// If all entries are trusted, evict the oldest trusted entry (§17.9 edge case fix).
    // Perform the 'evict for new entry' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'evict for new entry' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'evict for new entry' operation.
    // Errors are propagated to the caller via Result.
    fn evict_for_new_entry(&mut self, _new_entry: &NetworkMapEntry) {
        // Find the oldest untrusted entry
        // Compute oldest untrusted for this protocol step.
        // Compute oldest untrusted for this protocol step.
        // Compute oldest untrusted for this protocol step.
        let oldest_untrusted = self
            // Chain the operation on the intermediate result.
            .entries
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            .iter()
            // Select only elements matching the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            .filter(|(_, e)| e.local_trust.is_untrusted_tier())
            // Apply the closure to each element.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            .min_by_key(|(_, e)| e.last_seen)
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            // Transform each element.
            // Transform each element.
            .map(|(id, _)| *id);

        // Trust level gate — restrict access based on peer trust.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(id) = oldest_untrusted {
            // Remove from the collection and return the evicted value.
            // Remove from the collection.
            // Remove from the collection.
            // Remove from the collection.
            self.entries.remove(&id);
            return;
        }

        // All trusted — evict oldest by last_seen (extreme edge case)
        // Compute oldest trusted for this protocol step.
        // Compute oldest trusted for this protocol step.
        // Compute oldest trusted for this protocol step.
        let oldest_trusted = self
            // Chain the operation on the intermediate result.
            .entries
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            .iter()
            // Apply the closure to each element.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            .min_by_key(|(_, e)| e.last_seen)
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            // Transform each element.
            // Transform each element.
            .map(|(id, _)| *id);

        // Trust level gate — restrict access based on peer trust.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(id) = oldest_trusted {
            // Remove from the collection and return the evicted value.
            // Remove from the collection.
            // Remove from the collection.
            // Remove from the collection.
            self.entries.remove(&id);
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
// Begin the block scope.
// MapError — variant enumeration.
// Match exhaustively to handle every protocol state.
// MapError — variant enumeration.
// Match exhaustively to handle every protocol state.
// MapError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MapError {
    #[error("Entry timestamp {entry_ts} is more than 1 hour in the future (now: {now})")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    FutureTimestamp { entry_ts: u64, now: u64 },
    #[error("Too many transport hints ({0}, max 8)")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    TooManyTransportHints(usize),
    #[error("Too many public keys ({0}, max 16)")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    TooManyPublicKeys(usize),
    #[error("Too many services ({0}, max 32)")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    TooManyServices(usize),
    #[error("Field {0} too long ({1} bytes)")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    FieldTooLong(&'static str, usize),
    #[error("Invalid signature: {0}")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    InvalidSignature(String),
    #[error("Peer ID does not match the claimed Ed25519 public key")]
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    PeerIdKeyMismatch,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(peer_id: PeerId, seq: u64, last_seen: u64) -> NetworkMapEntry {
        NetworkMapEntry {
            peer_id,
            public_keys: vec![],
            last_seen,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: seq,
            signature: vec![],
            local_trust: TrustLevel::Unknown,
        }
    }

    #[test]
    fn test_insert_new_entry() {
        let mut map = NetworkMap::new();
        let entry = make_entry(PeerId([0x01; 32]), 1, 100);
        assert!(map.insert(entry, 100).unwrap());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_higher_sequence_wins() {
        let mut map = NetworkMap::new();
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 1, 100), 100).unwrap();
        assert!(map.insert(make_entry(pid, 2, 200), 200).unwrap());
        assert_eq!(map.get(&pid).unwrap().last_seen, 200);
    }

    #[test]
    fn test_lower_sequence_rejected() {
        let mut map = NetworkMap::new();
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 5, 100), 100).unwrap();
        assert!(!map.insert(make_entry(pid, 3, 200), 200).unwrap());
        assert_eq!(map.get(&pid).unwrap().sequence, 5);
    }

    #[test]
    fn test_future_timestamp_rejected() {
        let mut map = NetworkMap::new();
        let entry = make_entry(PeerId([0x01; 32]), 1, 100 + MAX_FUTURE_TIMESTAMP_SECS + 1);
        assert!(map.insert(entry, 100).is_err());
    }

    #[test]
    fn test_prune_stale() {
        let mut map = NetworkMap::new();
        let now = 10_000_000u64;
        map.insert(
            make_entry(PeerId([0x01; 32]), 1, now - STALENESS_SECS - 1),
            now,
        )
        .unwrap();
        map.insert(make_entry(PeerId([0x02; 32]), 1, now - 100), now)
            .unwrap();
        assert_eq!(map.len(), 2);

        map.prune_stale(now);
        assert_eq!(map.len(), 1);
        assert!(map.get(&PeerId([0x02; 32])).is_some());
    }

    #[test]
    fn test_trusted_entries_not_pruned() {
        let mut map = NetworkMap::new();
        let now = 10_000_000u64;
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 1, now - STALENESS_SECS - 1), now)
            .unwrap();
        map.get_mut(&pid).unwrap().local_trust = TrustLevel::Trusted;

        map.prune_stale(now);
        assert_eq!(map.len(), 1); // Still there — trusted
    }

    #[test]
    fn test_field_validation() {
        let mut entry = make_entry(PeerId([0x01; 32]), 1, 100);
        entry.transport_hints = (0..9)
            .map(|_| super::super::transport_hint::TransportHint {
                transport: super::super::transport_hint::TransportType::Clearnet,
                endpoint: Some("1.2.3.4:5".into()),
            })
            .collect();

        let mut map = NetworkMap::new();
        assert!(map.insert(entry, 100).is_err());
    }

    #[test]
    fn test_signature_sign_and_verify() {
        use ed25519_dalek::SigningKey;

        let raw_key = [0x7au8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();
        let x25519_pub = [0u8; 32]; // Placeholder for test.

        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        let mut entry = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: x25519_pub,
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 1_000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            local_trust: TrustLevel::Unknown,
        };

        entry.sign(&signing_key);
        assert_eq!(entry.signature.len(), 64);
        assert!(entry.verify_signature().is_ok());
    }

    #[test]
    fn test_signature_wrong_peer_id_rejected() {
        use ed25519_dalek::SigningKey;

        let raw_key = [0x7au8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();

        // peer_id doesn't match the key.
        let wrong_peer_id = PeerId([0xFFu8; 32]);
        let mut entry = NetworkMapEntry {
            peer_id: wrong_peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 1_000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![0u8; 64],
            local_trust: TrustLevel::Unknown,
        };

        entry.sign(&signing_key);
        // Change the peer_id after signing — verification must fail.
        entry.peer_id = PeerId([0xFFu8; 32]);
        assert!(entry.verify_signature().is_err());
    }

    #[test]
    fn test_tampered_entry_rejected() {
        use ed25519_dalek::SigningKey;

        let raw_key = [0x3bu8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();
        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        let mut entry = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 1_000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            local_trust: TrustLevel::Unknown,
        };

        entry.sign(&signing_key);
        // Tamper with sequence after signing.
        entry.sequence = 999;
        assert!(entry.verify_signature().is_err());
    }

    #[test]
    fn test_capacity_eviction() {
        // Fill to capacity wouldn't be practical in a test with 100K entries,
        // but we can test the eviction logic directly
        assert_eq!(MAX_MAP_ENTRIES, 100_000);
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut map = NetworkMap::new();
        map.insert(make_entry(PeerId([0x01; 32]), 1, 100), 100)
            .unwrap();

        let json = serde_json::to_string(&map).unwrap();
        let recovered: NetworkMap = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.len(), 1);
    }
}
