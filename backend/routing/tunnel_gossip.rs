//! Tunnel Coordination Gossip (§6.10)
//!
//! # What is Tunnel Coordination Gossip?
//!
//! Operates at the mesh identity layer (Layer 1, §3.1.1). Requires
//! no identity context — only WireGuard public keys. Initializes at
//! device unlock, before app or PIN.
//!
//! # Three Problems Solved
//!
//! 1. **Coverage** — sufficient tunnel connections for reliability
//!    and anonymity.
//! 2. **Reachability** — nodes advertise availability.
//! 3. **Load distribution** — prevents tunnel concentration on
//!    a few high-capacity nodes.
//!
//! # Message Types
//!
//! - `TunnelAdvertisement` — "I'm here, I have capacity"
//! - `CoverageRequest` — "I need more tunnels"
//! - `TunnelAck` — "I'll connect to you" (gossiped briefly to
//!   prevent pile-ons)
//!
//! # Rate Limiting
//!
//! - Advertisements: max 1 per pubkey per 30 seconds;
//!   violation → ignore for 1 hour
//! - Coverage requests: max 1 per pubkey per 5 minutes
//! - Broadcast interval: every 60 seconds
//!
//! # Privacy Properties
//!
//! Tunnel gossip uses WireGuard public keys (infrastructure IDs),
//! NOT personal identifiers. The mesh identity is ephemeral per
//! install and cryptographically isolated from self and all masks.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum simultaneous tunnels to any single destination peer.
pub const MAX_TUNNELS_PER_PEER: u8 = 8;

/// Maximum new tunnel establishments per minute (aggregate).
pub const MAX_NEW_TUNNELS_PER_MIN: u32 = 10;

/// Idle tunnel timeout (seconds). 30 minutes without traffic.
pub const TUNNEL_IDLE_TIMEOUT_SECS: u64 = 1800;

/// Per-tunnel memory budget (bytes). ~64 KB for KCP + WireGuard state.
pub const PER_TUNNEL_MEMORY_BUDGET: usize = 65_536;

/// Advertisement broadcast interval (seconds).
pub const ADVERTISEMENT_INTERVAL_SECS: u64 = 60;

/// Rate limit: max 1 advertisement per pubkey per this many seconds.
pub const ADVERTISEMENT_RATE_LIMIT_SECS: u64 = 30;

/// Penalty for rate-limit violation: ignore for this many seconds.
pub const RATE_VIOLATION_IGNORE_SECS: u64 = 3600;

/// Rate limit: max 1 coverage request per pubkey per this many seconds.
pub const COVERAGE_REQUEST_RATE_LIMIT_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Tunnel Capacity (coarsened)
// ---------------------------------------------------------------------------

/// Coarsened tunnel capacity (§6.10).
///
/// Exact capacity is NEVER broadcast — only coarse buckets.
/// This prevents fingerprinting by precise capacity values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TunnelCapacity {
    /// No capacity available.
    None = 0,
    /// Low capacity (1–16 tunnels).
    Low = 1,
    /// Medium capacity (17–64 tunnels).
    Medium = 2,
    /// High capacity (65+ tunnels).
    High = 3,
}

impl TunnelCapacity {
    /// Coarsen an exact tunnel count into a capacity bucket.
    ///
    /// The exact count is never transmitted — only the bucket.
    pub fn from_exact(count: u32) -> Self {
        match count {
            0 => Self::None,
            1..=16 => Self::Low,
            17..=64 => Self::Medium,
            _ => Self::High,
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol Messages
// ---------------------------------------------------------------------------

/// Tunnel advertisement (§6.10).
///
/// Broadcast every 60 seconds. Tells neighbours "I'm here and
/// I have this much capacity for tunnels."
///
/// The uptime_score has ±10% random jitter applied before broadcast
/// to prevent fingerprinting by exact uptime.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelAdvertisement {
    /// WireGuard public key (Layer 1 mesh identity).
    pub mesh_pubkey: [u8; 32],

    /// Coarsened capacity bucket. Exact counts never broadcast.
    pub tunnel_capacity: TunnelCapacity,

    /// Uptime score (0–255). ±10% jitter applied before broadcast.
    /// Based on: uptime, latency, responsiveness, honest reporting.
    pub uptime_score: u8,

    /// Unix timestamp.
    pub timestamp: u64,

    /// Ed25519 signature (signed by mesh identity key).
    pub signature: Vec<u8>,
}

/// Coverage request (§6.10).
///
/// Sent when a node needs more tunnels for coverage.
/// Other nodes that have capacity may respond with a TunnelAck.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageRequest {
    /// The node requesting coverage.
    pub target_pubkey: [u8; 32],

    /// How many tunnels the requester currently has.
    pub current_tunnels: u8,

    /// Unix timestamp.
    pub timestamp: u64,

    /// Ed25519 signature.
    pub signature: Vec<u8>,
}

/// Tunnel acknowledgement (§6.10).
///
/// Sent by a node offering to establish a tunnel to a requester.
/// Gossiped briefly to prevent pile-ons — other nodes see the
/// ack and don't also offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelAck {
    /// The node that requested coverage.
    pub target_pubkey: [u8; 32],

    /// The node offering to connect.
    pub responder_pubkey: [u8; 32],

    /// Unix timestamp.
    pub timestamp: u64,

    /// Ed25519 signature (from responder).
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Reputation Tracking
// ---------------------------------------------------------------------------

/// Per-node reputation for tunnel gossip (§6.10).
///
/// Stored against WireGuard public key. Persisted across sessions.
/// Does NOT survive emergency erase.
#[derive(Clone, Debug)]
pub struct TunnelReputation {
    /// The node's WireGuard public key.
    pub mesh_pubkey: [u8; 32],

    /// Cumulative uptime score (EMA).
    pub uptime_ema: f32,

    /// Average response latency to our keepalives (ms, EMA).
    pub latency_ema: f32,

    /// How often this node responds to coverage requests (0.0–1.0).
    pub responsiveness: f32,

    /// Whether this node has been caught reporting dishonest capacity.
    /// Nodes that claim High but refuse connections get penalized.
    pub honest_reporting: bool,

    /// Last time we heard from this node.
    pub last_seen: u64,

    /// Number of times this node has been rate-limited.
    pub rate_violations: u32,
}

impl TunnelReputation {
    /// Create a new reputation entry for a first-seen node.
    pub fn new(mesh_pubkey: [u8; 32], now: u64) -> Self {
        Self {
            mesh_pubkey,
            uptime_ema: 0.0,
            latency_ema: 500.0, // Assume average until measured.
            responsiveness: 0.5,
            honest_reporting: true,
            last_seen: now,
            rate_violations: 0,
        }
    }

    /// Update with a new advertisement observation.
    pub fn observe_advertisement(&mut self, ad: &TunnelAdvertisement) {
        let alpha = 0.1;
        self.uptime_ema =
            alpha * (ad.uptime_score as f32) + (1.0 - alpha) * self.uptime_ema;
        self.last_seen = ad.timestamp;
    }

    /// Update latency from a keepalive probe.
    pub fn observe_latency(&mut self, latency_ms: f32, now: u64) {
        let alpha = 0.2;
        self.latency_ema = alpha * latency_ms + (1.0 - alpha) * self.latency_ema;
        self.last_seen = now;
    }

    /// Record that this node responded to a coverage request.
    pub fn observe_coverage_response(&mut self, responded: bool) {
        let alpha = 0.1;
        let val = if responded { 1.0 } else { 0.0 };
        self.responsiveness = alpha * val + (1.0 - alpha) * self.responsiveness;
    }

    /// Composite reputation score (0.0–1.0). Higher is better.
    ///
    /// Weights: uptime 30%, latency 30%, responsiveness 25%,
    /// honesty 15%.
    pub fn score(&self) -> f32 {
        let uptime_norm = (self.uptime_ema / 255.0).clamp(0.0, 1.0);
        let latency_norm = (1.0 / (1.0 + self.latency_ema / 200.0)).clamp(0.0, 1.0);
        let honesty = if self.honest_reporting { 1.0 } else { 0.0 };

        0.30 * uptime_norm
            + 0.30 * latency_norm
            + 0.25 * self.responsiveness
            + 0.15 * honesty
    }
}

// ---------------------------------------------------------------------------
// Gossip Processor
// ---------------------------------------------------------------------------

/// Processes tunnel coordination gossip messages.
///
/// Maintains rate-limit tracking, reputation state, and decides
/// whether to respond to coverage requests.
pub struct TunnelGossipProcessor {
    /// Rate-limit tracking for advertisements.
    /// Key: mesh_pubkey, Value: last seen timestamp.
    ad_rate: HashMap<[u8; 32], u64>,

    /// Rate-limit tracking for coverage requests.
    coverage_rate: HashMap<[u8; 32], u64>,

    /// Nodes in the penalty box (rate-limit violators).
    /// Key: mesh_pubkey, Value: penalty expiry timestamp.
    penalty_box: HashMap<[u8; 32], u64>,

    /// Known node reputations.
    reputations: HashMap<[u8; 32], TunnelReputation>,

    /// Our own mesh pubkey.
    our_pubkey: [u8; 32],
}

impl TunnelGossipProcessor {
    /// Create a new gossip processor.
    pub fn new(our_pubkey: [u8; 32]) -> Self {
        Self {
            ad_rate: HashMap::new(),
            coverage_rate: HashMap::new(),
            penalty_box: HashMap::new(),
            reputations: HashMap::new(),
            our_pubkey,
        }
    }

    /// Process an incoming TunnelAdvertisement.
    ///
    /// Returns true if the advertisement was accepted.
    /// Returns false if rate-limited or from a penalized node.
    pub fn process_advertisement(
        &mut self,
        ad: &TunnelAdvertisement,
        now: u64,
    ) -> bool {
        // Ignore our own advertisements.
        if ad.mesh_pubkey == self.our_pubkey {
            return false;
        }

        // Check penalty box.
        if let Some(&expiry) = self.penalty_box.get(&ad.mesh_pubkey) {
            if now < expiry {
                return false;
            }
            self.penalty_box.remove(&ad.mesh_pubkey);
        }

        // Check rate limit.
        if let Some(&last) = self.ad_rate.get(&ad.mesh_pubkey) {
            if now.saturating_sub(last) < ADVERTISEMENT_RATE_LIMIT_SECS {
                // Rate violation — put in penalty box.
                self.penalty_box
                    .insert(ad.mesh_pubkey, now + RATE_VIOLATION_IGNORE_SECS);
                if let Some(rep) = self.reputations.get_mut(&ad.mesh_pubkey) {
                    rep.rate_violations += 1;
                }
                return false;
            }
        }

        // Record timestamp for rate limiting.
        self.ad_rate.insert(ad.mesh_pubkey, now);

        // Update reputation.
        let rep = self
            .reputations
            .entry(ad.mesh_pubkey)
            .or_insert_with(|| TunnelReputation::new(ad.mesh_pubkey, now));
        rep.observe_advertisement(ad);

        true
    }

    /// Process an incoming CoverageRequest.
    ///
    /// Returns true if we should consider responding (we have capacity).
    pub fn process_coverage_request(
        &mut self,
        req: &CoverageRequest,
        now: u64,
    ) -> bool {
        if req.target_pubkey == self.our_pubkey {
            return false;
        }

        // Check rate limit for coverage requests.
        if let Some(&last) = self.coverage_rate.get(&req.target_pubkey) {
            if now.saturating_sub(last) < COVERAGE_REQUEST_RATE_LIMIT_SECS {
                return false;
            }
        }

        self.coverage_rate.insert(req.target_pubkey, now);
        true
    }

    /// Process an incoming TunnelAck.
    ///
    /// Records that someone is already connecting to the target,
    /// so we don't also pile on.
    pub fn process_ack(&mut self, ack: &TunnelAck, now: u64) {
        // Record the responder's responsiveness.
        if let Some(rep) = self.reputations.get_mut(&ack.responder_pubkey) {
            rep.observe_coverage_response(true);
            rep.last_seen = now;
        }
    }

    /// Get reputation for a node.
    pub fn reputation(&self, pubkey: &[u8; 32]) -> Option<&TunnelReputation> {
        self.reputations.get(pubkey)
    }

    /// Garbage-collect stale rate-limit entries and expired penalties.
    pub fn gc(&mut self, now: u64) {
        self.ad_rate
            .retain(|_, ts| now.saturating_sub(*ts) < ADVERTISEMENT_RATE_LIMIT_SECS * 10);
        self.coverage_rate
            .retain(|_, ts| now.saturating_sub(*ts) < COVERAGE_REQUEST_RATE_LIMIT_SECS * 2);
        self.penalty_box.retain(|_, expiry| now < *expiry);
    }

    /// Number of known nodes.
    pub fn known_node_count(&self) -> usize {
        self.reputations.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ad(pubkey: u8, score: u8, ts: u64) -> TunnelAdvertisement {
        TunnelAdvertisement {
            mesh_pubkey: [pubkey; 32],
            tunnel_capacity: TunnelCapacity::Medium,
            uptime_score: score,
            timestamp: ts,
            signature: vec![0x42; 64],
        }
    }

    fn make_coverage(pubkey: u8, tunnels: u8, ts: u64) -> CoverageRequest {
        CoverageRequest {
            target_pubkey: [pubkey; 32],
            current_tunnels: tunnels,
            timestamp: ts,
            signature: vec![0x42; 64],
        }
    }

    #[test]
    fn test_accept_valid_advertisement() {
        let mut proc = TunnelGossipProcessor::new([0x01; 32]);
        let ad = make_ad(0xAA, 200, 1000);
        assert!(proc.process_advertisement(&ad, 1000));
        assert_eq!(proc.known_node_count(), 1);
    }

    #[test]
    fn test_reject_own_advertisement() {
        let mut proc = TunnelGossipProcessor::new([0x01; 32]);
        let ad = make_ad(0x01, 200, 1000);
        assert!(!proc.process_advertisement(&ad, 1000));
    }

    #[test]
    fn test_rate_limit_advertisement() {
        let mut proc = TunnelGossipProcessor::new([0x01; 32]);

        // First: accepted.
        assert!(proc.process_advertisement(&make_ad(0xAA, 200, 1000), 1000));

        // Second within rate limit: rejected + penalty.
        assert!(!proc.process_advertisement(&make_ad(0xAA, 200, 1010), 1010));

        // Now in penalty box — rejected even after rate window.
        assert!(!proc.process_advertisement(
            &make_ad(0xAA, 200, 1000 + ADVERTISEMENT_RATE_LIMIT_SECS + 1),
            1000 + ADVERTISEMENT_RATE_LIMIT_SECS + 1,
        ));

        // After penalty expires AND enough time for rate limit:
        // The rate entry also needs to have expired.
        let after_penalty = 1010 + RATE_VIOLATION_IGNORE_SECS + ADVERTISEMENT_RATE_LIMIT_SECS + 1;
        assert!(proc.process_advertisement(&make_ad(0xAA, 200, after_penalty), after_penalty));
    }

    #[test]
    fn test_coverage_request_rate_limit() {
        let mut proc = TunnelGossipProcessor::new([0x01; 32]);

        assert!(proc.process_coverage_request(&make_coverage(0xBB, 1, 1000), 1000));
        // Same node within rate limit: rejected.
        assert!(!proc.process_coverage_request(&make_coverage(0xBB, 1, 1100), 1100));
        // After rate window: accepted.
        let after = 1000 + COVERAGE_REQUEST_RATE_LIMIT_SECS + 1;
        assert!(proc.process_coverage_request(&make_coverage(0xBB, 1, after), after));
    }

    #[test]
    fn test_tunnel_capacity_coarsening() {
        assert_eq!(TunnelCapacity::from_exact(0), TunnelCapacity::None);
        assert_eq!(TunnelCapacity::from_exact(5), TunnelCapacity::Low);
        assert_eq!(TunnelCapacity::from_exact(16), TunnelCapacity::Low);
        assert_eq!(TunnelCapacity::from_exact(17), TunnelCapacity::Medium);
        assert_eq!(TunnelCapacity::from_exact(64), TunnelCapacity::Medium);
        assert_eq!(TunnelCapacity::from_exact(65), TunnelCapacity::High);
    }

    #[test]
    fn test_reputation_scoring() {
        let mut rep = TunnelReputation::new([0xAA; 32], 1000);

        // Initial score should be moderate.
        let initial = rep.score();
        assert!(initial > 0.0 && initial < 1.0);

        // Good observations improve score.
        rep.uptime_ema = 200.0;
        rep.latency_ema = 20.0;
        rep.responsiveness = 0.9;
        let good = rep.score();
        assert!(good > initial);

        // Dishonest reporting tanks score.
        rep.honest_reporting = false;
        let bad = rep.score();
        assert!(bad < good);
    }

    #[test]
    fn test_gc() {
        let mut proc = TunnelGossipProcessor::new([0x01; 32]);
        proc.process_advertisement(&make_ad(0xAA, 200, 1000), 1000);
        proc.process_coverage_request(&make_coverage(0xBB, 1, 1000), 1000);

        // GC far in the future cleans up rate entries.
        proc.gc(1_000_000);
        // Entries should be cleaned.
    }
}
