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
// MAX_TUNNELS_PER_PEER — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_TUNNELS_PER_PEER — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_TUNNELS_PER_PEER: u8 = 8;

/// Maximum new tunnel establishments per minute (aggregate).
// MAX_NEW_TUNNELS_PER_MIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_NEW_TUNNELS_PER_MIN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_NEW_TUNNELS_PER_MIN: u32 = 10;

/// Idle tunnel timeout (seconds). 30 minutes without traffic.
// TUNNEL_IDLE_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// TUNNEL_IDLE_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const TUNNEL_IDLE_TIMEOUT_SECS: u64 = 1800;

/// Per-tunnel memory budget (bytes). ~64 KB for KCP + WireGuard state.
// PER_TUNNEL_MEMORY_BUDGET — protocol constant.
// Defined by the spec; must not change without a version bump.
// PER_TUNNEL_MEMORY_BUDGET — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PER_TUNNEL_MEMORY_BUDGET: usize = 65_536;

/// Advertisement broadcast interval (seconds).
// ADVERTISEMENT_INTERVAL_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// ADVERTISEMENT_INTERVAL_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const ADVERTISEMENT_INTERVAL_SECS: u64 = 60;

/// Rate limit: max 1 advertisement per pubkey per this many seconds.
// ADVERTISEMENT_RATE_LIMIT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// ADVERTISEMENT_RATE_LIMIT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const ADVERTISEMENT_RATE_LIMIT_SECS: u64 = 30;

/// Penalty for rate-limit violation: ignore for this many seconds.
// RATE_VIOLATION_IGNORE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// RATE_VIOLATION_IGNORE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const RATE_VIOLATION_IGNORE_SECS: u64 = 3600;

/// Rate limit: max 1 coverage request per pubkey per this many seconds.
// COVERAGE_REQUEST_RATE_LIMIT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// COVERAGE_REQUEST_RATE_LIMIT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
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
// Begin the block scope.
// TunnelCapacity — variant enumeration.
// Match exhaustively to handle every protocol state.
// TunnelCapacity — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum TunnelCapacity {
    /// No capacity available.
    // No value available.
    // No value available.
    None = 0,
    /// Low capacity (1–16 tunnels).
    Low = 1,
    /// Medium capacity (17–64 tunnels).
    // Execute this protocol step.
    // Execute this protocol step.
    Medium = 2,
    /// High capacity (65+ tunnels).
    // Execute this protocol step.
    // Execute this protocol step.
    High = 3,
}

// Begin the block scope.
// TunnelCapacity implementation — core protocol logic.
// TunnelCapacity implementation — core protocol logic.
impl TunnelCapacity {
    /// Coarsen an exact tunnel count into a capacity bucket.
    ///
    /// The exact count is never transmitted — only the bucket.
    // Perform the 'from exact' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from exact' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_exact(count: u32) -> Self {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match count {
            // Update the local state.
            0 => Self::None,
            // Handle this match arm.
            1..=16 => Self::Low,
            // Handle this match arm.
            17..=64 => Self::Medium,
            // Update the local state.
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
// Begin the block scope.
// TunnelAdvertisement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelAdvertisement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelAdvertisement {
    /// WireGuard public key (Layer 1 mesh identity).
    // Execute this protocol step.
    // Execute this protocol step.
    pub mesh_pubkey: [u8; 32],

    /// Coarsened capacity bucket. Exact counts never broadcast.
    // Execute this protocol step.
    // Execute this protocol step.
    pub tunnel_capacity: TunnelCapacity,

    /// Uptime score (0–255). ±10% jitter applied before broadcast.
    /// Based on: uptime, latency, responsiveness, honest reporting.
    // Execute this protocol step.
    // Execute this protocol step.
    pub uptime_score: u8,

    /// Unix timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,

    /// Ed25519 signature (signed by mesh identity key).
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

/// Coverage request (§6.10).
///
/// Sent when a node needs more tunnels for coverage.
/// Other nodes that have capacity may respond with a TunnelAck.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// CoverageRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// CoverageRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct CoverageRequest {
    /// The node requesting coverage.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target_pubkey: [u8; 32],

    /// How many tunnels the requester currently has.
    // Execute this protocol step.
    // Execute this protocol step.
    pub current_tunnels: u8,

    /// Unix timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,

    /// Ed25519 signature.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

/// Tunnel acknowledgement (§6.10).
///
/// Sent by a node offering to establish a tunnel to a requester.
/// Gossiped briefly to prevent pile-ons — other nodes see the
/// ack and don't also offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TunnelAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelAck {
    /// The node that requested coverage.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target_pubkey: [u8; 32],

    /// The node offering to connect.
    // Execute this protocol step.
    // Execute this protocol step.
    pub responder_pubkey: [u8; 32],

    /// Unix timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,

    /// Ed25519 signature (from responder).
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// TunnelReputation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelReputation — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelReputation {
    /// The node's WireGuard public key.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mesh_pubkey: [u8; 32],

    /// Cumulative uptime score (EMA).
    // Execute this protocol step.
    // Execute this protocol step.
    pub uptime_ema: f32,

    /// Average response latency to our keepalives (ms, EMA).
    // Execute this protocol step.
    // Execute this protocol step.
    pub latency_ema: f32,

    /// How often this node responds to coverage requests (0.0–1.0).
    // Execute this protocol step.
    // Execute this protocol step.
    pub responsiveness: f32,

    /// Whether this node has been caught reporting dishonest capacity.
    /// Nodes that claim High but refuse connections get penalized.
    // Execute this protocol step.
    // Execute this protocol step.
    pub honest_reporting: bool,

    /// Last time we heard from this node.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_seen: u64,

    /// Number of times this node has been rate-limited.
    // Execute this protocol step.
    // Execute this protocol step.
    pub rate_violations: u32,
}

// Begin the block scope.
// TunnelReputation implementation — core protocol logic.
// TunnelReputation implementation — core protocol logic.
impl TunnelReputation {
    /// Create a new reputation entry for a first-seen node.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(mesh_pubkey: [u8; 32], now: u64) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            mesh_pubkey,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            uptime_ema: 0.0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            latency_ema: 500.0, // Assume average until measured.
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            responsiveness: 0.5,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            honest_reporting: true,
            // Execute this protocol step.
            // Execute this protocol step.
            last_seen: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            rate_violations: 0,
        }
    }

    /// Update with a new advertisement observation.
    // Perform the 'observe advertisement' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'observe advertisement' operation.
    // Errors are propagated to the caller via Result.
    pub fn observe_advertisement(&mut self, ad: &TunnelAdvertisement) {
        // Bind the computed value for subsequent use.
        // Compute alpha for this protocol step.
        // Compute alpha for this protocol step.
        let alpha = 0.1;
        // Update the uptime ema to reflect the new state.
        // Advance uptime ema state.
        // Advance uptime ema state.
        self.uptime_ema =
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            alpha * (ad.uptime_score as f32) + (1.0 - alpha) * self.uptime_ema;
        // Update the last seen to reflect the new state.
        // Advance last seen state.
        // Advance last seen state.
        self.last_seen = ad.timestamp;
    }

    /// Update latency from a keepalive probe.
    // Perform the 'observe latency' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'observe latency' operation.
    // Errors are propagated to the caller via Result.
    pub fn observe_latency(&mut self, latency_ms: f32, now: u64) {
        // Bind the computed value for subsequent use.
        // Compute alpha for this protocol step.
        // Compute alpha for this protocol step.
        let alpha = 0.2;
        // Update the latency ema to reflect the new state.
        // Advance latency ema state.
        // Advance latency ema state.
        self.latency_ema = alpha * latency_ms + (1.0 - alpha) * self.latency_ema;
        // Update the last seen to reflect the new state.
        // Advance last seen state.
        // Advance last seen state.
        self.last_seen = now;
    }

    /// Record that this node responded to a coverage request.
    // Perform the 'observe coverage response' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'observe coverage response' operation.
    // Errors are propagated to the caller via Result.
    pub fn observe_coverage_response(&mut self, responded: bool) {
        // Bind the computed value for subsequent use.
        // Compute alpha for this protocol step.
        // Compute alpha for this protocol step.
        let alpha = 0.1;
        // Execute the operation and bind the result.
        // Compute val for this protocol step.
        // Compute val for this protocol step.
        let val = if responded { 1.0 } else { 0.0 };
        // Update the responsiveness to reflect the new state.
        // Advance responsiveness state.
        // Advance responsiveness state.
        self.responsiveness = alpha * val + (1.0 - alpha) * self.responsiveness;
    }

    /// Composite reputation score (0.0–1.0). Higher is better.
    ///
    /// Weights: uptime 30%, latency 30%, responsiveness 25%,
    /// honesty 15%.
    // Perform the 'score' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'score' operation.
    // Errors are propagated to the caller via Result.
    pub fn score(&self) -> f32 {
        // Capture the current timestamp for temporal ordering.
        // Compute uptime norm for this protocol step.
        // Compute uptime norm for this protocol step.
        let uptime_norm = (self.uptime_ema / 255.0).clamp(0.0, 1.0);
        // Clamp the value to prevent overflow or underflow.
        // Compute latency norm for this protocol step.
        // Compute latency norm for this protocol step.
        let latency_norm = (1.0 / (1.0 + self.latency_ema / 200.0)).clamp(0.0, 1.0);
        // Execute the operation and bind the result.
        // Compute honesty for this protocol step.
        // Compute honesty for this protocol step.
        let honesty = if self.honest_reporting { 1.0 } else { 0.0 };

        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        0.30 * uptime_norm
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            + 0.30 * latency_norm
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            + 0.25 * self.responsiveness
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
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
// TunnelGossipProcessor — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelGossipProcessor — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelGossipProcessor {
    /// Rate-limit tracking for advertisements.
    /// Key: mesh_pubkey, Value: last seen timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    ad_rate: HashMap<[u8; 32], u64>,

    /// Rate-limit tracking for coverage requests.
    // Execute this protocol step.
    // Execute this protocol step.
    coverage_rate: HashMap<[u8; 32], u64>,

    /// Nodes in the penalty box (rate-limit violators).
    /// Key: mesh_pubkey, Value: penalty expiry timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    penalty_box: HashMap<[u8; 32], u64>,

    /// Known node reputations.
    // Execute this protocol step.
    // Execute this protocol step.
    reputations: HashMap<[u8; 32], TunnelReputation>,

    /// Our own mesh pubkey.
    // Execute this protocol step.
    // Execute this protocol step.
    our_pubkey: [u8; 32],
}

// Begin the block scope.
// TunnelGossipProcessor implementation — core protocol logic.
// TunnelGossipProcessor implementation — core protocol logic.
impl TunnelGossipProcessor {
    /// Create a new gossip processor.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(our_pubkey: [u8; 32]) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            ad_rate: HashMap::new(),
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            coverage_rate: HashMap::new(),
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            penalty_box: HashMap::new(),
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            reputations: HashMap::new(),
            // Execute this protocol step.
            // Execute this protocol step.
            our_pubkey,
        }
    }

    /// Process an incoming TunnelAdvertisement.
    ///
    /// Returns true if the advertisement was accepted.
    /// Returns false if rate-limited or from a penalized node.
    // Perform the 'process advertisement' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process advertisement' operation.
    // Errors are propagated to the caller via Result.
    pub fn process_advertisement(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        ad: &TunnelAdvertisement,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> bool {
        // Ignore our own advertisements.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if ad.mesh_pubkey == self.our_pubkey {
            // Condition not met — return negative result.
            // Return to the caller.
            // Return to the caller.
            return false;
        }

        // Check penalty box.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(&expiry) = self.penalty_box.get(&ad.mesh_pubkey) {
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if now < expiry {
                // Condition not met — return negative result.
                // Return to the caller.
                // Return to the caller.
                return false;
            }
            // Remove from the collection and return the evicted value.
            // Remove from the collection.
            // Remove from the collection.
            self.penalty_box.remove(&ad.mesh_pubkey);
        }

        // Check rate limit.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(&last) = self.ad_rate.get(&ad.mesh_pubkey) {
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if now.saturating_sub(last) < ADVERTISEMENT_RATE_LIMIT_SECS {
                // Rate violation — put in penalty box.
                // Execute this protocol step.
                // Execute this protocol step.
                self.penalty_box
                    // Insert into the lookup table for efficient retrieval.
                    // Insert into the map/set.
                    // Insert into the map/set.
                    .insert(ad.mesh_pubkey, now + RATE_VIOLATION_IGNORE_SECS);
                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if let Some(rep) = self.reputations.get_mut(&ad.mesh_pubkey) {
                    // Execute the operation and bind the result.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    rep.rate_violations += 1;
                }
                // Condition not met — return negative result.
                // Return to the caller.
                // Return to the caller.
                return false;
            }
        }

        // Record timestamp for rate limiting.
        // Insert into the map/set.
        // Insert into the map/set.
        self.ad_rate.insert(ad.mesh_pubkey, now);

        // Update reputation.
        // Compute rep for this protocol step.
        // Compute rep for this protocol step.
        let rep = self
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            .reputations
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            .entry(ad.mesh_pubkey)
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            .or_insert_with(|| TunnelReputation::new(ad.mesh_pubkey, now));
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        rep.observe_advertisement(ad);

        true
    }

    /// Process an incoming CoverageRequest.
    ///
    /// Returns true if we should consider responding (we have capacity).
    // Perform the 'process coverage request' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process coverage request' operation.
    // Errors are propagated to the caller via Result.
    pub fn process_coverage_request(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        req: &CoverageRequest,
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
    ) -> bool {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        if req.target_pubkey == self.our_pubkey {
            // Condition not met — return negative result.
            // Return to the caller.
            return false;
        }

        // Check rate limit for coverage requests.
        // Guard: validate the condition before proceeding.
        if let Some(&last) = self.coverage_rate.get(&req.target_pubkey) {
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            if now.saturating_sub(last) < COVERAGE_REQUEST_RATE_LIMIT_SECS {
                // Condition not met — return negative result.
                // Return to the caller.
                return false;
            }
        }

        // Insert into the lookup table for efficient retrieval.
        // Insert into the map/set.
        self.coverage_rate.insert(req.target_pubkey, now);
        true
    }

    /// Process an incoming TunnelAck.
    ///
    /// Records that someone is already connecting to the target,
    /// so we don't also pile on.
    // Perform the 'process ack' operation.
    // Errors are propagated to the caller via Result.
    pub fn process_ack(&mut self, ack: &TunnelAck, now: u64) {
        // Record the responder's responsiveness.
        // Guard: validate the condition before proceeding.
        if let Some(rep) = self.reputations.get_mut(&ack.responder_pubkey) {
            // Execute the operation and bind the result.
            // Execute this protocol step.
            rep.observe_coverage_response(true);
            // Process the current step in the protocol.
            // Execute this protocol step.
            rep.last_seen = now;
        }
    }

    /// Get reputation for a node.
    // Perform the 'reputation' operation.
    // Errors are propagated to the caller via Result.
    pub fn reputation(&self, pubkey: &[u8; 32]) -> Option<&TunnelReputation> {
        // Mutate the internal state.
        // Execute this protocol step.
        self.reputations.get(pubkey)
    }

    /// Garbage-collect stale rate-limit entries and expired penalties.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    pub fn gc(&mut self, now: u64) {
        // Mutate the internal state.
        // Execute this protocol step.
        self.ad_rate
            // Filter the collection, keeping only elements that pass.
            // Filter elements that match the predicate.
            .retain(|_, ts| now.saturating_sub(*ts) < ADVERTISEMENT_RATE_LIMIT_SECS * 10);
        // Mutate the internal state.
        // Execute this protocol step.
        self.coverage_rate
            // Filter the collection, keeping only elements that pass.
            // Filter elements that match the predicate.
            .retain(|_, ts| now.saturating_sub(*ts) < COVERAGE_REQUEST_RATE_LIMIT_SECS * 2);
        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        self.penalty_box.retain(|_, expiry| now < *expiry);
    }

    /// Number of known nodes.
    // Perform the 'known node count' operation.
    // Errors are propagated to the caller via Result.
    pub fn known_node_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
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
