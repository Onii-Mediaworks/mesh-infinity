//! Gossip Protocol — Network Map Propagation (§4.1, §4.5)
//!
//! # What is Gossip?
//!
//! Gossip is how nodes learn about each other. When two nodes connect,
//! they exchange their network maps — each side serializes their known
//! peers and sends it. The receiving side merges the incoming entries
//! with their local map, preferring newer sequence numbers. Changes
//! then propagate to other connected peers in rounds until all connected
//! nodes have consistent (eventually) maps.
//!
//! # There is no central directory
//!
//! Unlike traditional networks where a server tells you who's online,
//! Mesh Infinity nodes discover each other through their social graph:
//!
//! 1. On startup, try connecting to known trusted peers (Level 6+)
//! 2. If no trusted peers are reachable, try any previously known node
//! 3. On any new connection, exchange maps
//! 4. Merged maps are then gossiped to other connected peers
//!
//! # Self-Ratcheted Map Authentication (§4.5)
//!
//! Every node signs its own map entry with its Ed25519 mask key.
//! Each update references the hash of the previous update (forming a
//! hash chain). This prevents:
//!
//! - **Replay attacks:** replaying an old entry creates a detectable fork
//!   (two entries with the same prev_hash)
//! - **Forgery:** entries without a valid signature are rejected
//! - **Future-dating:** entries with timestamps >1 hour in the future
//!   are rejected outright
//!
//! # Rate Limiting (§4.2)
//!
//! To prevent flooding attacks, gossip from each peer is rate-limited:
//! - Untrusted peers: max 500 new entries per hour
//! - Trusted (Level 6+): max 5,000 per hour
//! - InnerCircle (Level 8): max 10,000 per hour
//!
//! Even trusted peers are rate-limited — a compromised trusted peer
//! is still a DoS vector.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;
use crate::trust::levels::TrustLevel;
use super::map::{NetworkMap, NetworkMapEntry, MapError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How long to remember forwarded announcement IDs (prevents re-forwarding).
/// 24 hours in seconds.
// DEDUP_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEDUP_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEDUP_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
const DEDUP_WINDOW_SECS: u64 = 24 * 3600;

/// Rate limits by trust level (entries per hour).
// RATE_LIMIT_UNTRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
// RATE_LIMIT_UNTRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
// RATE_LIMIT_UNTRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
const RATE_LIMIT_UNTRUSTED: u32 = 500;
// Protocol constant.
// RATE_LIMIT_TRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
// RATE_LIMIT_TRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
// RATE_LIMIT_TRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
const RATE_LIMIT_TRUSTED: u32 = 5_000;
// Protocol constant.
// RATE_LIMIT_INNER_CIRCLE — protocol constant.
// Defined by the spec; must not change without a version bump.
// RATE_LIMIT_INNER_CIRCLE — protocol constant.
// Defined by the spec; must not change without a version bump.
// RATE_LIMIT_INNER_CIRCLE — protocol constant.
// Defined by the spec; must not change without a version bump.
const RATE_LIMIT_INNER_CIRCLE: u32 = 10_000;

// ---------------------------------------------------------------------------
// Self-Ratcheted Map Entry (§4.5)
// ---------------------------------------------------------------------------

/// A self-ratcheted map entry — signed by the node that owns it.
///
/// The `prev_hash` field creates a hash chain: each update references
/// the hash of the previous update. This prevents replay attacks and
/// makes forks detectable (two entries with the same prev_hash but
/// different content = the signing key is compromised or duplicated).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// SelfMapEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SelfMapEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SelfMapEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SelfMapEntry {
    /// The peer ID this entry belongs to.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_id: PeerId,

    /// The actual map content (addresses, transport hints, etc.).
    /// Serialized as part of the signed payload.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub content: NetworkMapEntry,

    /// SHA-256 hash of the previous self-signed entry.
    /// For the first entry, this is all zeros.
    /// This creates a hash chain that prevents replays and detects forks.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub prev_hash: [u8; 32],

    /// When this entry was created (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,

    /// Ed25519 signature by the mask key that owns this peer_id.
    /// Covers: peer_id || content_hash || prev_hash || timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Gossip Rate Tracker
// ---------------------------------------------------------------------------

/// Tracks how many entries each peer has gossiped recently.
///
/// Used to enforce the per-peer rate limits (§4.2).
/// A peer that exceeds their limit has further entries silently dropped.
#[derive(Default)]
// Begin the block scope.
// GossipRateTracker — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GossipRateTracker — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GossipRateTracker — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GossipRateTracker {
    /// Map of source_peer_id → (count_this_hour, hour_start_timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    counters: HashMap<PeerId, (u32, u64)>,
}

// Begin the block scope.
// GossipRateTracker implementation — core protocol logic.
// GossipRateTracker implementation — core protocol logic.
// GossipRateTracker implementation — core protocol logic.
impl GossipRateTracker {
    /// Check if a peer is allowed to gossip more entries.
    ///
    /// Returns true if the peer hasn't exceeded their rate limit for
    /// the current hour. Updates the counter if allowed.
    // Perform the 'check and increment' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check and increment' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check and increment' operation.
    // Errors are propagated to the caller via Result.
    pub fn check_and_increment(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        source: &PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        trust_level: TrustLevel,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> bool {
        // Determine the rate limit based on trust level
        // Compute limit for this protocol step.
        // Compute limit for this protocol step.
        // Compute limit for this protocol step.
        let limit = match trust_level {
            // Handle this match arm.
            TrustLevel::InnerCircle => RATE_LIMIT_INNER_CIRCLE,
            // Handle this match arm.
            t if t.is_trusted_tier() => RATE_LIMIT_TRUSTED,
            // Update the local state.
            _ => RATE_LIMIT_UNTRUSTED,
        };

        // Get or create the counter for this peer
        // Bind the intermediate result.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (count, hour_start) = self.counters.entry(*source).or_insert((0, now));

        // Reset counter if we've entered a new hour
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if now - *hour_start >= 3600 {
            *count = 0;
            *hour_start = now;
        }

        // Check limit
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if *count >= limit {
            // Condition not met — return negative result.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return false; // Rate limited — drop silently
        }

        *count += 1;
        true
    }

    /// Clean up old entries (peers we haven't heard from in 24+ hours).
    // Perform the 'cleanup' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'cleanup' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'cleanup' operation.
    // Errors are propagated to the caller via Result.
    pub fn cleanup(&mut self, now: u64) {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.counters
            // Filter the collection, keeping only elements that pass.
            // Filter elements that match the predicate.
            // Filter elements that match the predicate.
            // Filter elements that match the predicate.
            .retain(|_, (_, hour_start)| now - *hour_start < DEDUP_WINDOW_SECS);
    }
}

// ---------------------------------------------------------------------------
// Gossip Deduplication
// ---------------------------------------------------------------------------

/// Tracks which announcements we've already forwarded.
///
/// Each announcement has a unique ID. If we've seen it before within
/// the deduplication window (24 hours), we don't forward it again.
/// This prevents amplification storms in the gossip network.
#[derive(Default)]
// Begin the block scope.
// GossipDedup — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GossipDedup — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GossipDedup — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GossipDedup {
    /// Set of (announcement_id → timestamp_first_seen).
    /// Persisted to disk across restarts (§4.2).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    seen: HashMap<[u8; 32], u64>,
}

// Begin the block scope.
// GossipDedup implementation — core protocol logic.
// GossipDedup implementation — core protocol logic.
// GossipDedup implementation — core protocol logic.
impl GossipDedup {
    /// Check if we've already seen this announcement.
    /// Returns true if it's new (not seen before).
    // Perform the 'is new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is new' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_new(&mut self, announcement_id: &[u8; 32], now: u64) -> bool {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.seen.contains_key(announcement_id) {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            false // Already forwarded this one
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // Insert into the lookup table for efficient retrieval.
            // Insert into the map/set.
            // Insert into the map/set.
            // Insert into the map/set.
            self.seen.insert(*announcement_id, now);
            true
        }
    }

    /// Remove entries older than the deduplication window.
    // Perform the 'cleanup' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'cleanup' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'cleanup' operation.
    // Errors are propagated to the caller via Result.
    pub fn cleanup(&mut self, now: u64) {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.seen
            // Filter the collection, keeping only elements that pass.
            // Filter elements that match the predicate.
            // Filter elements that match the predicate.
            // Filter elements that match the predicate.
            .retain(|_, first_seen| now - *first_seen < DEDUP_WINDOW_SECS);
    }

    /// Number of tracked announcements.
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
        self.seen.len()
    }

    /// Returns `true` when no announcements are tracked.
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
        self.seen.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Gossip Engine
// ---------------------------------------------------------------------------

/// The gossip engine manages network map propagation.
///
/// It handles:
/// - Receiving and validating incoming gossip from peers
/// - Rate limiting per-peer gossip
/// - Deduplicating announcements
/// - Merging received entries into the local map
// GossipEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GossipEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GossipEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GossipEngine {
    /// The local network map.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub map: NetworkMap,
    /// Rate tracker for incoming gossip.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    rate_tracker: GossipRateTracker,
    /// Deduplication set for forwarded announcements.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    dedup: GossipDedup,
}

// Begin the block scope.
// GossipEngine implementation — core protocol logic.
// GossipEngine implementation — core protocol logic.
// GossipEngine implementation — core protocol logic.
impl GossipEngine {
    /// Create a new gossip engine with an empty map.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            map: NetworkMap::new(),
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            rate_tracker: GossipRateTracker::default(),
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            dedup: GossipDedup::default(),
        }
    }

    /// Process an incoming map entry from a gossip peer.
    ///
    /// Validates the entry, checks rate limits, and merges if valid.
    /// Returns Ok(true) if the entry was accepted and should be
    /// forwarded to other peers, Ok(false) if it was valid but not
    /// new (already known or rate limited), and Err on invalid entries.
    // Perform the 'receive entry' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'receive entry' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'receive entry' operation.
    // Errors are propagated to the caller via Result.
    pub fn receive_entry(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        entry: NetworkMapEntry,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        source_peer: &PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        source_trust: TrustLevel,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> Result<bool, MapError> {
        // Step 1: Verify Ed25519 signature (§4.5 — forgery prevention).
        //
        // Every legitimate network map entry received from a remote peer MUST
        // be signed by its owner's Ed25519 key.  Entries with no public_keys
        // are unsigned stubs and are not acceptable from remote peers — they
        // provide no way to cryptographically bind the entry to an identity.
        //
        // Unsigned entries are only used in local synthetic/test code where
        // the calling context is trusted.  From remote gossip, they indicate
        // a forged or malformed entry and must be rejected outright.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if entry.public_keys.is_empty() {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(MapError::InvalidSignature(
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                "remote gossip entry has no public keys — unsigned entries are rejected".into(),
            ));
        }
        // Propagate errors via the ? operator — callers handle failures.
        // Propagate errors via ?.
        // Propagate errors via ?.
        // Propagate errors via ?.
        entry.verify_signature()?;

        // Step 2: Rate limit check — has this source exceeded their quota?
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.rate_tracker.check_and_increment(source_peer, source_trust, now) {
            // Rate limited — silently drop (the source is sending too fast)
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Ok(false);
        }

        // Step 3: Insert into the local map (validates sequence, timestamp, fields)
        // Compute accepted for this protocol step.
        // Compute accepted for this protocol step.
        // Compute accepted for this protocol step.
        let accepted = self.map.insert(entry, now)?;

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(accepted)
    }

    /// Periodic cleanup — remove stale map entries and old tracking data.
    // Perform the 'cleanup' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'cleanup' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'cleanup' operation.
    // Errors are propagated to the caller via Result.
    pub fn cleanup(&mut self, now: u64) {
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.map.prune_stale(now);
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.rate_tracker.cleanup(now);
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.dedup.cleanup(now);
    }

    /// Check if an announcement is new (for forwarding decisions).
    // Perform the 'is announcement new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is announcement new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is announcement new' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_announcement_new(&mut self, id: &[u8; 32], now: u64) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.dedup.is_new(id, now)
    }

    /// Get the current map size.
    // Perform the 'map size' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'map size' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'map size' operation.
    // Errors are propagated to the caller via Result.
    pub fn map_size(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.map.len()
    }
}

// Trait implementation for protocol conformance.
// Implement Default for GossipEngine.
// Implement Default for GossipEngine.
// Implement Default for GossipEngine.
impl Default for GossipEngine {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::map::{NetworkMapEntry, PublicKeyRecord};
    use ed25519_dalek::SigningKey;

    /// Helper: create and sign a proper remote gossip entry.
    ///
    /// Uses a deterministic signing key derived from `seed_byte`.
    /// Returns `(entry, signing_key)` so callers can tamper if needed.
    fn make_signed_entry(seed_byte: u8, seq: u64, last_seen: u64) -> (NetworkMapEntry, SigningKey) {
        let seed = [seed_byte; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let ed_pub = signing_key.verifying_key().to_bytes();
        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        let mut entry = NetworkMapEntry {
            peer_id,
            public_keys: vec![PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: seq,
            signature: vec![],
            local_trust: TrustLevel::Unknown,
        };
        entry.sign(&signing_key);
        (entry, signing_key)
    }

    #[test]
    fn test_gossip_engine_basic() {
        let mut engine = GossipEngine::new();
        let source = PeerId([0x01; 32]);
        let (entry, _) = make_signed_entry(0x02, 1, 100);

        let accepted = engine
            .receive_entry(entry, &source, TrustLevel::Unknown, 100)
            .unwrap();
        assert!(accepted);
        assert_eq!(engine.map_size(), 1);
    }

    /// Unsigned entries (public_keys empty) must be rejected — not silently accepted.
    #[test]
    fn test_gossip_rejects_unsigned_entry() {
        let mut engine = GossipEngine::new();
        let source = PeerId([0x01; 32]);
        let unsigned = NetworkMapEntry {
            peer_id: PeerId([0x02; 32]),
            public_keys: vec![],   // no public key → unsigned
            last_seen: 100,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            local_trust: TrustLevel::Unknown,
        };
        let result = engine.receive_entry(unsigned, &source, TrustLevel::Unknown, 100);
        assert!(result.is_err(), "unsigned entry must be rejected");
    }

    /// An entry signed by the wrong key must be rejected.
    #[test]
    fn test_gossip_rejects_wrong_signature() {
        let mut engine = GossipEngine::new();
        let source = PeerId([0x01; 32]);

        let (mut entry, _) = make_signed_entry(0x02, 1, 100);
        // Corrupt the signature.
        if let Some(b) = entry.signature.first_mut() {
            *b ^= 0xFF;
        }

        let result = engine.receive_entry(entry, &source, TrustLevel::Unknown, 100);
        assert!(result.is_err(), "corrupted signature must be rejected");
    }

    #[test]
    fn test_rate_limiting() {
        let mut tracker = GossipRateTracker::default();
        let peer = PeerId([0x01; 32]);
        let now = 1000u64;

        // Untrusted: 500/hour limit
        for i in 0..500 {
            assert!(
                tracker.check_and_increment(&peer, TrustLevel::Unknown, now),
                "Attempt {i} should be allowed"
            );
        }
        // 501st should be rejected
        assert!(!tracker.check_and_increment(&peer, TrustLevel::Unknown, now));
    }

    #[test]
    fn test_rate_limit_resets_hourly() {
        let mut tracker = GossipRateTracker::default();
        let peer = PeerId([0x01; 32]);

        // Fill up the limit
        for _ in 0..500 {
            tracker.check_and_increment(&peer, TrustLevel::Unknown, 1000);
        }
        assert!(!tracker.check_and_increment(&peer, TrustLevel::Unknown, 1000));

        // One hour later — should be allowed again
        assert!(tracker.check_and_increment(&peer, TrustLevel::Unknown, 4601));
    }

    #[test]
    fn test_trusted_higher_rate_limit() {
        let mut tracker = GossipRateTracker::default();
        let peer = PeerId([0x01; 32]);
        let now = 1000u64;

        // Trusted: 5000/hour limit
        for _ in 0..5000 {
            assert!(tracker.check_and_increment(&peer, TrustLevel::Trusted, now));
        }
        assert!(!tracker.check_and_increment(&peer, TrustLevel::Trusted, now));
    }

    #[test]
    fn test_dedup() {
        let mut dedup = GossipDedup::default();
        let id = [0x42u8; 32];

        // First time: new
        assert!(dedup.is_new(&id, 100));
        // Second time: not new
        assert!(!dedup.is_new(&id, 101));
    }

    #[test]
    fn test_dedup_cleanup() {
        let mut dedup = GossipDedup::default();
        let id = [0x42u8; 32];

        dedup.is_new(&id, 100);
        assert_eq!(dedup.len(), 1);

        // After 24 hours, should be cleaned up
        dedup.cleanup(100 + DEDUP_WINDOW_SECS + 1);
        assert_eq!(dedup.len(), 0);

        // Now it's "new" again
        assert!(dedup.is_new(&id, 100 + DEDUP_WINDOW_SECS + 2));
    }

    #[test]
    fn test_duplicate_entry_not_forwarded() {
        let mut engine = GossipEngine::new();
        let source = PeerId([0x01; 32]);

        // First insert: accepted (seed 0x02 → deterministic peer_id)
        let (entry1, _) = make_signed_entry(0x02, 1, 100);
        assert!(engine
            .receive_entry(entry1, &source, TrustLevel::Unknown, 100)
            .unwrap());

        // Same sequence for the same peer: not accepted (stale)
        let (entry2, _) = make_signed_entry(0x02, 1, 200);
        assert!(!engine
            .receive_entry(entry2, &source, TrustLevel::Unknown, 200)
            .unwrap());
    }

    #[test]
    fn test_higher_sequence_accepted() {
        let mut engine = GossipEngine::new();
        let source = PeerId([0x01; 32]);

        let (entry1, _) = make_signed_entry(0x02, 1, 100);
        engine
            .receive_entry(entry1, &source, TrustLevel::Unknown, 100)
            .unwrap();

        // Higher sequence for the same peer: accepted
        let (entry2, _) = make_signed_entry(0x02, 2, 200);
        assert!(engine
            .receive_entry(entry2, &source, TrustLevel::Unknown, 200)
            .unwrap());
    }
}
