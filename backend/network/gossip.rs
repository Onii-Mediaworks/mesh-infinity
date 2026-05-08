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
//!
//! # Source Diversity (§4.1 — map size-scaled validation threshold)
//!
//! Map entries can be spoofed by a single malicious peer.  To resist
//! this, once the local map is large enough to attract Sybil attacks,
//! the engine requires corroboration from multiple independent sources
//! before promoting a pending entry:
//!
//! - Map < 100 entries:  1 source sufficient (startup / small network)
//! - Map 100–999:        2 independent sources required
//! - Map ≥ 1000:         3 independent sources required
//!
//! While an entry is awaiting enough corroboration it is held in a
//! pending buffer.  The source that provides the final corroboration
//! triggers the insert.  Entries older than 24 hours are evicted from
//! the buffer without being promoted.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::map::{MapError, NetworkMap, NetworkMapEntry};
use crate::identity::peer_id::PeerId;
use crate::trust::levels::TrustLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How long to remember forwarded announcement IDs (prevents re-forwarding).
/// 24 hours in seconds.
const DEDUP_WINDOW_SECS: u64 = 24 * 3600;

/// Rate limits by trust level (entries per hour).
const RATE_LIMIT_UNTRUSTED: u32 = 500;
const RATE_LIMIT_TRUSTED: u32 = 5_000;
const RATE_LIMIT_INNER_CIRCLE: u32 = 10_000;

/// Map size thresholds for source diversity (§4.1).
const DIVERSITY_THRESHOLD_MEDIUM: usize = 100;
const DIVERSITY_THRESHOLD_LARGE: usize = 1_000;

/// Required independent sources at each size band.
const SOURCES_REQUIRED_SMALL: usize = 1;
const SOURCES_REQUIRED_MEDIUM: usize = 2;
const SOURCES_REQUIRED_LARGE: usize = 3;

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
pub struct SelfMapEntry {
    /// The peer ID this entry belongs to.
    pub peer_id: PeerId,

    /// The actual map content (addresses, transport hints, etc.).
    /// Serialized as part of the signed payload.
    pub content: NetworkMapEntry,

    /// SHA-256 hash of the previous self-signed entry.
    /// For the first entry, this is all zeros.
    /// This creates a hash chain that prevents replays and detects forks.
    pub prev_hash: [u8; 32],

    /// When this entry was created (Unix timestamp).
    pub timestamp: u64,

    /// Ed25519 signature by the mask key that owns this peer_id.
    /// Covers: peer_id || content_hash || prev_hash || timestamp.
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
pub struct GossipRateTracker {
    /// Map of source_peer_id → (count_this_hour, hour_start_timestamp).
    counters: HashMap<PeerId, (u32, u64)>,
}

impl GossipRateTracker {
    /// Check if a peer is allowed to gossip more entries.
    ///
    /// Returns true if the peer hasn't exceeded their rate limit for
    /// the current hour. Updates the counter if allowed.
    pub fn check_and_increment(
        &mut self,
        source: &PeerId,
        trust_level: TrustLevel,
        now: u64,
    ) -> bool {
        let limit = match trust_level {
            TrustLevel::InnerCircle => RATE_LIMIT_INNER_CIRCLE,
            t if t.is_trusted_tier() => RATE_LIMIT_TRUSTED,
            _ => RATE_LIMIT_UNTRUSTED,
        };

        let (count, hour_start) = self.counters.entry(*source).or_insert((0, now));

        // Reset counter on hour boundary.
        if now - *hour_start >= 3600 {
            *count = 0;
            *hour_start = now;
        }

        if *count >= limit {
            return false;
        }

        *count += 1;
        true
    }

    /// Clean up old entries (peers we haven't heard from in 24+ hours).
    pub fn cleanup(&mut self, now: u64) {
        self.counters
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
pub struct GossipDedup {
    /// Set of (announcement_id → timestamp_first_seen).
    /// Persisted to disk across restarts (§4.2).
    seen: HashMap<[u8; 32], u64>,
}

impl GossipDedup {
    /// Check if we've already seen this announcement.
    /// Returns true if it's new (not seen before).
    pub fn is_new(&mut self, announcement_id: &[u8; 32], now: u64) -> bool {
        if self.seen.contains_key(announcement_id) {
            false
        } else {
            self.seen.insert(*announcement_id, now);
            true
        }
    }

    /// Remove entries older than the deduplication window.
    pub fn cleanup(&mut self, now: u64) {
        self.seen
            .retain(|_, first_seen| now - *first_seen < DEDUP_WINDOW_SECS);
    }

    /// Number of tracked announcements.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns `true` when no announcements are tracked.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Source Diversity Buffer (§4.1 — map size-scaled validation threshold)
// ---------------------------------------------------------------------------

/// A pending entry waiting for enough independent source corroboration.
struct PendingEntry {
    /// The entry itself (kept for insertion once quorum is met).
    entry: NetworkMapEntry,
    /// Distinct peer IDs that have sent us this entry.
    sources: Vec<PeerId>,
    /// Timestamp when first seen (for eviction).
    first_seen: u64,
}

/// Holds entries that have not yet met the source diversity requirement.
///
/// An entry graduates to the live map once `sources.len() >=
/// required_sources(map_size)`.  Entries older than 24 hours are
/// evicted without being promoted.
#[derive(Default)]
pub struct SourceDiversityBuffer {
    /// Keyed by (peer_id, sequence) so different versions are tracked separately.
    pending: HashMap<([u8; 32], u64), PendingEntry>,
}

impl SourceDiversityBuffer {
    /// Record a corroboration from `source` for this entry.
    ///
    /// Returns `Some(entry)` when the entry has reached the required number
    /// of independent sources and should be promoted to the live map.
    /// Returns `None` if more corroboration is still needed.
    pub fn record(
        &mut self,
        entry: NetworkMapEntry,
        source: &PeerId,
        map_size: usize,
        now: u64,
    ) -> Option<NetworkMapEntry> {
        let key = (entry.peer_id.0, entry.sequence);
        let required = required_sources(map_size);

        let pending = self.pending.entry(key).or_insert_with(|| PendingEntry {
            entry: entry.clone(),
            sources: Vec::new(),
            first_seen: now,
        });

        // Track unique sources only.
        if !pending.sources.contains(source) {
            pending.sources.push(*source);
        }

        if pending.sources.len() >= required {
            // Quorum reached — remove from buffer and return for insertion.
            let promoted = self.pending.remove(&key)?;
            Some(promoted.entry)
        } else {
            None
        }
    }

    /// Evict entries that have been pending for longer than 24 hours.
    pub fn cleanup(&mut self, now: u64) {
        self.pending
            .retain(|_, p| now - p.first_seen < DEDUP_WINDOW_SECS);
    }

    /// Number of entries currently awaiting corroboration.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Required independent sources given the current map size (§4.1).
pub fn required_sources(map_size: usize) -> usize {
    if map_size >= DIVERSITY_THRESHOLD_LARGE {
        SOURCES_REQUIRED_LARGE
    } else if map_size >= DIVERSITY_THRESHOLD_MEDIUM {
        SOURCES_REQUIRED_MEDIUM
    } else {
        SOURCES_REQUIRED_SMALL
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
///
/// Source diversity (§4.1 map size-scaled validation threshold) is enforced
/// by `NetworkMap::insert_gossiped` — the engine feeds each corroborating
/// source through separately so the map can count them.
pub struct GossipEngine {
    /// The local network map.
    pub map: NetworkMap,
    /// Rate tracker for incoming gossip.
    rate_tracker: GossipRateTracker,
    /// Deduplication set for forwarded announcements.
    dedup: GossipDedup,
}

impl GossipEngine {
    /// Create a new gossip engine with an empty map.
    pub fn new() -> Self {
        Self {
            map: NetworkMap::new(),
            rate_tracker: GossipRateTracker::default(),
            dedup: GossipDedup::default(),
        }
    }

    /// Process an incoming map entry from a gossip peer.
    ///
    /// Validates the entry, checks rate limits, and merges into the local
    /// map.  Source diversity quorum is enforced by `NetworkMap::insert_gossiped`.
    ///
    /// Returns `Ok(true)` if the entry was accepted into the live map and
    /// should be forwarded to other peers, `Ok(false)` if it was valid but
    /// not yet promoted (awaiting more sources, rate limited, or already
    /// known), and `Err` on invalid entries.
    pub fn receive_entry(
        &mut self,
        entry: NetworkMapEntry,
        source_peer: &PeerId,
        source_trust: TrustLevel,
        now: u64,
    ) -> Result<bool, MapError> {
        // Unsigned entries are only used in local synthetic/test code.
        // From remote gossip they indicate forgery and must be rejected.
        if entry.public_keys.is_empty() {
            return Err(MapError::InvalidSignature(
                "remote gossip entry has no public keys — unsigned entries are rejected".into(),
            ));
        }
        entry.verify_signature()?;

        // Silently drop entries from peers that are sending too fast.
        if !self
            .rate_tracker
            .check_and_increment(source_peer, source_trust, now)
        {
            return Ok(false);
        }

        // Delegate to the map — it handles source diversity staging internally.
        let accepted = self.map.insert_gossiped(entry, source_peer, now)?;
        Ok(accepted)
    }

    /// Periodic cleanup — remove stale map entries and old tracking data.
    pub fn cleanup(&mut self, now: u64) {
        self.map.prune_stale(now);
        self.rate_tracker.cleanup(now);
        self.dedup.cleanup(now);
    }

    /// Check if an announcement is new (for forwarding decisions).
    pub fn is_announcement_new(&mut self, id: &[u8; 32], now: u64) -> bool {
        self.dedup.is_new(id, now)
    }

    /// Get the current map size.
    pub fn map_size(&self) -> usize {
        self.map.len()
    }
}

impl Default for GossipEngine {
    fn default() -> Self {
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
            prev_hash: None,
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
            public_keys: vec![],
            last_seen: 100,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            local_trust: TrustLevel::Unknown,
            prev_hash: None,
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

        for i in 0..500 {
            assert!(
                tracker.check_and_increment(&peer, TrustLevel::Unknown, now),
                "Attempt {i} should be allowed"
            );
        }
        assert!(!tracker.check_and_increment(&peer, TrustLevel::Unknown, now));
    }

    #[test]
    fn test_rate_limit_resets_hourly() {
        let mut tracker = GossipRateTracker::default();
        let peer = PeerId([0x01; 32]);

        for _ in 0..500 {
            tracker.check_and_increment(&peer, TrustLevel::Unknown, 1000);
        }
        assert!(!tracker.check_and_increment(&peer, TrustLevel::Unknown, 1000));

        // One hour later — should be allowed again.
        assert!(tracker.check_and_increment(&peer, TrustLevel::Unknown, 4601));
    }

    #[test]
    fn test_trusted_higher_rate_limit() {
        let mut tracker = GossipRateTracker::default();
        let peer = PeerId([0x01; 32]);
        let now = 1000u64;

        for _ in 0..5000 {
            assert!(tracker.check_and_increment(&peer, TrustLevel::Trusted, now));
        }
        assert!(!tracker.check_and_increment(&peer, TrustLevel::Trusted, now));
    }

    #[test]
    fn test_dedup() {
        let mut dedup = GossipDedup::default();
        let id = [0x42u8; 32];

        assert!(dedup.is_new(&id, 100));
        assert!(!dedup.is_new(&id, 101));
    }

    #[test]
    fn test_dedup_cleanup() {
        let mut dedup = GossipDedup::default();
        let id = [0x42u8; 32];

        dedup.is_new(&id, 100);
        assert_eq!(dedup.len(), 1);

        dedup.cleanup(100 + DEDUP_WINDOW_SECS + 1);
        assert_eq!(dedup.len(), 0);

        assert!(dedup.is_new(&id, 100 + DEDUP_WINDOW_SECS + 2));
    }

    #[test]
    fn test_duplicate_entry_not_forwarded() {
        let mut engine = GossipEngine::new();
        let source = PeerId([0x01; 32]);

        let (entry1, _) = make_signed_entry(0x02, 1, 100);
        assert!(engine
            .receive_entry(entry1, &source, TrustLevel::Unknown, 100)
            .unwrap());

        // Same sequence for the same peer: not accepted (stale).
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

        // Higher sequence for the same peer: accepted.
        let (entry2, _) = make_signed_entry(0x02, 2, 200);
        assert!(engine
            .receive_entry(entry2, &source, TrustLevel::Unknown, 200)
            .unwrap());
    }

    // ------------------------------------------------------------------
    // T2-C: Source diversity (§4.1 — map size-scaled validation threshold)
    // ------------------------------------------------------------------

    /// required_sources() returns correct thresholds at all size bands.
    #[test]
    fn source_diversity_thresholds_are_correct() {
        assert_eq!(required_sources(0), 1);
        assert_eq!(required_sources(99), 1);
        assert_eq!(required_sources(100), 2);
        assert_eq!(required_sources(999), 2);
        assert_eq!(required_sources(1_000), 3);
        assert_eq!(required_sources(1_000_000), 3);
    }

    /// A single source is sufficient below the 100-entry threshold.
    #[test]
    fn source_diversity_single_source_below_threshold() {
        let mut buf = SourceDiversityBuffer::default();
        let (entry, _) = make_signed_entry(0x10, 1, 1000);
        let source = PeerId([0x01; 32]);

        // map_size = 50 → requires 1 source
        let result = buf.record(entry, &source, 50, 1000);
        assert!(result.is_some(), "single source should be enough below 100");
    }

    /// Two independent sources are required at the medium band (100–999 entries).
    #[test]
    fn source_diversity_two_sources_required_at_medium_band() {
        let mut buf = SourceDiversityBuffer::default();
        let (entry, _) = make_signed_entry(0x11, 1, 1000);
        let source_a = PeerId([0x01; 32]);
        let source_b = PeerId([0x02; 32]);

        // First source at map_size = 150 → not enough yet.
        let first = buf.record(entry.clone(), &source_a, 150, 1000);
        assert!(first.is_none(), "one source should not be enough at size 150");

        // Second independent source → quorum reached.
        let second = buf.record(entry, &source_b, 150, 1001);
        assert!(
            second.is_some(),
            "two independent sources should satisfy medium-band quorum"
        );
    }

    /// Three independent sources are required at the large band (≥ 1000 entries).
    #[test]
    fn source_diversity_three_sources_required_at_large_band() {
        let mut buf = SourceDiversityBuffer::default();
        let (entry, _) = make_signed_entry(0x12, 1, 1000);
        let source_a = PeerId([0x01; 32]);
        let source_b = PeerId([0x02; 32]);
        let source_c = PeerId([0x03; 32]);

        assert!(buf.record(entry.clone(), &source_a, 1_000, 1000).is_none());
        assert!(buf.record(entry.clone(), &source_b, 1_000, 1001).is_none());
        let third = buf.record(entry, &source_c, 1_000, 1002);
        assert!(
            third.is_some(),
            "three independent sources should satisfy large-band quorum"
        );
    }

    /// Duplicate reports from the same source do not count as independent.
    #[test]
    fn source_diversity_same_source_not_double_counted() {
        let mut buf = SourceDiversityBuffer::default();
        let (entry, _) = make_signed_entry(0x13, 1, 1000);
        let source = PeerId([0x01; 32]);

        // Both records are from the same peer — should not satisfy the
        // medium-band requirement of 2 independent sources.
        assert!(buf.record(entry.clone(), &source, 150, 1000).is_none());
        assert!(
            buf.record(entry, &source, 150, 1001).is_none(),
            "same source twice must not count as two independent sources"
        );
    }

    /// Pending entries older than 24 hours are evicted.
    #[test]
    fn source_diversity_buffer_cleanup_evicts_stale_entries() {
        let mut buf = SourceDiversityBuffer::default();
        let (entry, _) = make_signed_entry(0x14, 1, 1000);
        let source = PeerId([0x01; 32]);

        // Add at time 1000 but don't complete the quorum.
        buf.record(entry, &source, 150, 1000);
        assert_eq!(buf.pending_count(), 1);

        // After 24h + 1s the entry should be evicted.
        buf.cleanup(1000 + DEDUP_WINDOW_SECS + 1);
        assert_eq!(buf.pending_count(), 0);
    }

    /// GossipEngine enforces source diversity at the medium band via map.insert_gossiped.
    ///
    /// Each call to receive_entry passes the entry and its source peer down into
    /// NetworkMap::insert_gossiped which maintains its own staging buffer.  Two
    /// independent sources at map_size=100 are required before the entry
    /// is promoted to the live map.
    #[test]
    fn gossip_engine_buffers_entries_when_map_is_medium_size() {
        let mut engine = GossipEngine::new();

        // Populate the engine with 100 distinct entries (seeds 0x10–0x73).
        // All arrive from source_a while the map is < 100 (single-source OK).
        let seeder_source = PeerId([0x01; 32]);
        for seed in 0x10u8..=0x73u8 {
            let (e, _) = make_signed_entry(seed, 1, 1000);
            engine
                .receive_entry(e, &seeder_source, TrustLevel::Unknown, 1000)
                .unwrap();
        }
        assert_eq!(engine.map_size(), 100);

        // Now map has 100 entries → 2 independent sources required.
        let (entry, _) = make_signed_entry(0x80, 1, 2000);
        let source_a = PeerId([0xA0; 32]);
        let accepted_a = engine
            .receive_entry(entry.clone(), &source_a, TrustLevel::Unknown, 2000)
            .unwrap();
        assert!(
            !accepted_a,
            "single source at map_size=100 must not insert immediately"
        );
        assert_eq!(engine.map_size(), 100, "map must not grow from single source");

        // Second independent source completes the quorum.
        let source_b = PeerId([0xB0; 32]);
        let accepted_b = engine
            .receive_entry(entry, &source_b, TrustLevel::Unknown, 2001)
            .unwrap();
        assert!(
            accepted_b,
            "second independent source must complete quorum and insert"
        );
        assert_eq!(engine.map_size(), 101);
    }
}
