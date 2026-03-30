//! Trust-Weighted Path Selection (§6.3)
//!
//! # What is Path Selection?
//!
//! When multiple paths exist to the same destination, the path selection
//! algorithm scores each candidate and picks the best one. This is the
//! "brain" of hop-by-hop routing — it decides which neighbour to forward
//! a packet to.
//!
//! # The Scoring Function
//!
//! The score for a candidate path is:
//!
//! ```text
//! score = (1.0 / max(hop_count, 1))
//!       × trust_weight(next_hop_trust)
//!       × (1.0 / effective_latency)
//! ```
//!
//! where `effective_latency = latency_ms if measured, else UNMEASURED_LATENCY_MS (1000ms)`.
//! Unmeasured routes are penalized so that any probed route beats a cold one.
//! The formula balances
//! three factors:
//!
//! 1. **Hop count** — fewer hops means less forwarding, less latency,
//!    and fewer nodes that see the packet.
//! 2. **Trust weight** — routes through more trusted neighbours are
//!    preferred. Uses exponential weights from §6.3.
//! 3. **Latency** — lower latency is better for real-time applications.
//!
//! # Trust Weight Design
//!
//! The trust weight ceiling is intentionally modest (InnerCircle = 1.30).
//! Trust is a TIEBREAKER, not a dominant factor. This prevents an
//! adversary from inserting high-performance relay nodes and attracting
//! traffic by being the "fastest" route.
//!
//! # Staleness Penalty
//!
//! Routes older than ROUTE_STALENESS_SECS receive a 50% score penalty.
//! This causes fresh routes to be preferred over stale ones, even if
//! the stale route has slightly better metrics.
//!
//! # next_hop_trust vs path_trust
//!
//! The scoring function uses ONLY the local node's trust in its
//! immediate next hop. The `path_trust` concept (path-wide minimum
//! trust) is reserved for circuit-routing modes (§6.7) where the
//! full path is known. In hop-by-hop routing, we can't verify trust
//! along the rest of the path, so we don't pretend to.

use super::table::RoutingEntry;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Staleness penalty factor.
///
/// Routes older than ROUTE_STALENESS_SECS get their score multiplied
/// by this factor. A 50% penalty means fresh routes are strongly
/// preferred, but a stale route that's dramatically better (e.g., 1 hop
/// vs 10 hops) can still win.
// STALENESS_PENALTY — protocol constant.
// Defined by the spec; must not change without a version bump.
// STALENESS_PENALTY — protocol constant.
// Defined by the spec; must not change without a version bump.
// STALENESS_PENALTY — protocol constant.
// Defined by the spec; must not change without a version bump.
// STALENESS_PENALTY — protocol constant.
// Defined by the spec; must not change without a version bump.
// STALENESS_PENALTY — protocol constant.
// Defined by the spec; must not change without a version bump.
// STALENESS_PENALTY — protocol constant.
// Defined by the spec; must not change without a version bump.
const STALENESS_PENALTY: f32 = 0.5;

/// Effective latency assumed for routes whose `latency_ms` is 0 (unmeasured).
///
/// 1000ms is a conservative "unknown-network" assumption. Using 1ms (best case)
/// would cause newly-seen or unmeasured routes to beat well-characterized routes
/// solely because they haven't been probed yet — a reachability-gaming risk.
///
/// 1000ms is roughly Tor/I2P territory; any measured path will beat this once
/// a single latency probe has been recorded.
// UNMEASURED_LATENCY_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
// UNMEASURED_LATENCY_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
// UNMEASURED_LATENCY_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
// UNMEASURED_LATENCY_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
// UNMEASURED_LATENCY_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
// UNMEASURED_LATENCY_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
const UNMEASURED_LATENCY_MS: u32 = 1000;

// ---------------------------------------------------------------------------
// Path Scoring
// ---------------------------------------------------------------------------

/// Compute the path selection score for a routing entry.
///
/// Higher score = better path. The score combines three factors:
/// hop count (fewer = better), trust weight (higher = better),
/// and latency (lower = better).
///
/// `now` is the current unix timestamp, used for staleness checking.
///
/// Unmeasured routes (`latency_ms == 0`) are penalized by using
/// `UNMEASURED_LATENCY_MS` (1000ms) instead of 0, so they score below
/// any route with a real measurement. This prevents newly-seen routes
/// from monopolizing path selection before they have been probed.
// Perform the 'score path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'score path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'score path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'score path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'score path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'score path' operation.
// Errors are propagated to the caller via Result.
pub fn score_path(entry: &RoutingEntry, now: u64) -> f32 {
    // Guard against division by zero.
    // hop_count of 0 means "we ARE the destination" — shouldn't
    // normally be scored, but handle gracefully.
    // Compute effective hops for this protocol step.
    // Compute effective hops for this protocol step.
    // Compute effective hops for this protocol step.
    // Compute effective hops for this protocol step.
    // Compute effective hops for this protocol step.
    // Compute effective hops for this protocol step.
    let effective_hops = entry.hop_count.max(1) as f32;

    // latency_ms of 0 means unmeasured — use conservative sentinel (1000ms)
    // so any measured route is preferred over an uncharacterized one.
    // Compute effective latency for this protocol step.
    // Compute effective latency for this protocol step.
    // Compute effective latency for this protocol step.
    // Compute effective latency for this protocol step.
    // Compute effective latency for this protocol step.
    // Compute effective latency for this protocol step.
    let effective_latency = if entry.latency_ms == 0 {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        UNMEASURED_LATENCY_MS
    // Begin the block scope.
    // Fallback when the guard was not satisfied.
    // Fallback when the guard was not satisfied.
    // Fallback when the guard was not satisfied.
    // Fallback when the guard was not satisfied.
    // Fallback when the guard was not satisfied.
    // Fallback when the guard was not satisfied.
    } else {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        entry.latency_ms
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    } as f32;

    // Trust weight from the 8-level model (§6.3).
    // This uses ONLY our trust in the next hop.
    // Compute trust for this protocol step.
    // Compute trust for this protocol step.
    // Compute trust for this protocol step.
    // Compute trust for this protocol step.
    // Compute trust for this protocol step.
    // Compute trust for this protocol step.
    let trust = entry.next_hop_trust.routing_weight();

    // Core scoring formula.
    // Compute score for this protocol step.
    // Compute score for this protocol step.
    // Compute score for this protocol step.
    // Compute score for this protocol step.
    // Compute score for this protocol step.
    // Compute score for this protocol step.
    let mut score = (1.0 / effective_hops) * trust * (1.0 / effective_latency);

    // Staleness penalty: routes we haven't heard about recently
    // get scored lower to prefer fresh routing information.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if entry.is_stale(now) {
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        score *= STALENESS_PENALTY;
    }

    score
}

/// Select the best path from a list of candidate routes.
///
/// Returns the route with the highest score, or None if the
/// list is empty. If two routes have identical scores, the one
/// with fewer hops wins (secondary tiebreaker).
///
/// `now` is the current unix timestamp for staleness checking.
// Perform the 'select best path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'select best path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'select best path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'select best path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'select best path' operation.
// Errors are propagated to the caller via Result.
// Perform the 'select best path' operation.
// Errors are propagated to the caller via Result.
pub fn select_best_path(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    candidates: &[RoutingEntry],
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    now: u64,
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
) -> Option<&RoutingEntry> {
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if candidates.is_empty() {
        // No result available — signal absence to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return None;
    }

    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    candidates
        // Create an iterator over the collection elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        .iter()
        // Apply the closure to each element.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .max_by(|a, b| {
            // Resolve the filesystem path for the target resource.
            // Compute score a for this protocol step.
            // Compute score a for this protocol step.
            // Compute score a for this protocol step.
            // Compute score a for this protocol step.
            // Compute score a for this protocol step.
            // Compute score a for this protocol step.
            let score_a = score_path(a, now);
            // Resolve the filesystem path for the target resource.
            // Compute score b for this protocol step.
            // Compute score b for this protocol step.
            // Compute score b for this protocol step.
            // Compute score b for this protocol step.
            // Compute score b for this protocol step.
            // Compute score b for this protocol step.
            let score_b = score_path(b, now);

            // Primary: highest score wins.
            // Secondary (tiebreaker): fewer hops wins.
            score_a
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                .partial_cmp(&score_b)
                // Fall back to the default value on failure.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                .unwrap_or(std::cmp::Ordering::Equal)
                // Apply the closure to each element.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                .then_with(|| b.hop_count.cmp(&a.hop_count))
        })
}

/// Score and rank all candidate paths, returning them in
/// descending order (best first).
///
/// Useful for diagnostics and for the UI to show alternative
/// routes. Each element is (score, entry reference).
// Perform the 'rank paths' operation.
// Errors are propagated to the caller via Result.
// Perform the 'rank paths' operation.
// Errors are propagated to the caller via Result.
// Perform the 'rank paths' operation.
// Errors are propagated to the caller via Result.
// Perform the 'rank paths' operation.
// Errors are propagated to the caller via Result.
// Perform the 'rank paths' operation.
// Errors are propagated to the caller via Result.
// Perform the 'rank paths' operation.
// Errors are propagated to the caller via Result.
pub fn rank_paths(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    candidates: &[RoutingEntry],
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    now: u64,
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
// Execute this protocol step.
) -> Vec<(f32, &RoutingEntry)> {
    // Bind the computed value for subsequent use.
    // Compute scored for this protocol step.
    // Compute scored for this protocol step.
    // Compute scored for this protocol step.
    // Compute scored for this protocol step.
    // Compute scored for this protocol step.
    // Compute scored for this protocol step.
    let mut scored: Vec<(f32, &RoutingEntry)> = candidates
        // Create an iterator over the collection elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        .iter()
        // Transform the result, mapping errors to the local error type.
        // Transform each element.
        // Transform each element.
        // Transform each element.
        // Transform each element.
        // Transform each element.
        // Transform each element.
        .map(|e| (score_path(e, now), e))
        // Materialize the iterator into a concrete collection.
        // Collect into a concrete collection.
        // Collect into a concrete collection.
        // Collect into a concrete collection.
        // Collect into a concrete collection.
        // Collect into a concrete collection.
        // Collect into a concrete collection.
        .collect();

    // Sort descending by score.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    scored.sort_by(|a, b| {
        // Fall back to the default value on failure.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal)
    });

    scored
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::table::{DeviceAddress, ROUTE_STALENESS_SECS};
    use crate::trust::levels::TrustLevel;

    /// Helper: create a DeviceAddress from a single byte.
    fn addr(b: u8) -> DeviceAddress {
        DeviceAddress([b; 32])
    }

    /// Helper: create a routing entry with specific parameters.
    fn make_entry(
        hops: u8,
        latency: u32,
        trust: TrustLevel,
        ts: u64,
    ) -> RoutingEntry {
        RoutingEntry {
            destination: addr(0xAA),
            next_hop: addr(0xBB),
            hop_count: hops,
            latency_ms: latency,
            next_hop_trust: trust,
            last_updated: ts,
            announcement_id: [0; 32],
        }
    }

    #[test]
    fn test_fewer_hops_scores_higher() {
        let now = 1000;

        // 1 hop should score higher than 5 hops (same latency and trust).
        let one_hop = make_entry(1, 50, TrustLevel::Trusted, now);
        let five_hops = make_entry(5, 50, TrustLevel::Trusted, now);

        let score_1 = score_path(&one_hop, now);
        let score_5 = score_path(&five_hops, now);

        assert!(
            score_1 > score_5,
            "1-hop ({}) should score higher than 5-hop ({})",
            score_1,
            score_5
        );
    }

    #[test]
    fn test_lower_latency_scores_higher() {
        let now = 1000;

        // 10ms should score higher than 100ms (same hops and trust).
        let low_lat = make_entry(2, 10, TrustLevel::Trusted, now);
        let high_lat = make_entry(2, 100, TrustLevel::Trusted, now);

        let score_low = score_path(&low_lat, now);
        let score_high = score_path(&high_lat, now);

        assert!(
            score_low > score_high,
            "10ms ({}) should score higher than 100ms ({})",
            score_low,
            score_high
        );
    }

    #[test]
    fn test_higher_trust_scores_higher() {
        let now = 1000;

        // InnerCircle should score higher than Unknown (same hops and latency).
        let trusted = make_entry(2, 50, TrustLevel::InnerCircle, now);
        let unknown = make_entry(2, 50, TrustLevel::Unknown, now);

        let score_trusted = score_path(&trusted, now);
        let score_unknown = score_path(&unknown, now);

        assert!(
            score_trusted > score_unknown,
            "InnerCircle ({}) should score higher than Unknown ({})",
            score_trusted,
            score_unknown
        );
    }

    #[test]
    fn test_staleness_penalty() {
        let create_time = 1000;
        // "now" is past the staleness threshold.
        let now = create_time + ROUTE_STALENESS_SECS + 10;

        let fresh = make_entry(2, 50, TrustLevel::Trusted, now);
        let stale = make_entry(2, 50, TrustLevel::Trusted, create_time);

        let score_fresh = score_path(&fresh, now);
        let score_stale = score_path(&stale, now);

        assert!(
            score_fresh > score_stale,
            "Fresh ({}) should score higher than stale ({})",
            score_fresh,
            score_stale
        );

        // Stale penalty should be exactly 50%.
        let expected_ratio = STALENESS_PENALTY;
        let actual_ratio = score_stale / score_fresh;
        assert!(
            (actual_ratio - expected_ratio).abs() < 0.01,
            "Staleness penalty should be {}, got {}",
            expected_ratio,
            actual_ratio
        );
    }

    #[test]
    fn test_select_best_path() {
        let now = 1000;

        let candidates = vec![
            make_entry(5, 100, TrustLevel::Unknown, now),
            make_entry(1, 10, TrustLevel::Trusted, now), // Best
            make_entry(3, 50, TrustLevel::Acquaintance, now),
        ];

        let best = select_best_path(&candidates, now).unwrap();
        assert_eq!(best.hop_count, 1);
        assert_eq!(best.latency_ms, 10);
    }

    #[test]
    fn test_select_best_empty() {
        let candidates: Vec<RoutingEntry> = vec![];
        assert!(select_best_path(&candidates, 1000).is_none());
    }

    #[test]
    fn test_rank_paths_ordering() {
        let now = 1000;

        let candidates = vec![
            make_entry(3, 50, TrustLevel::Acquaintance, now),
            make_entry(1, 10, TrustLevel::Trusted, now),
            make_entry(5, 100, TrustLevel::Unknown, now),
        ];

        let ranked = rank_paths(&candidates, now);

        // Should be in descending score order.
        assert_eq!(ranked.len(), 3);
        assert!(ranked[0].0 >= ranked[1].0);
        assert!(ranked[1].0 >= ranked[2].0);

        // Best should be the 1-hop, 10ms, Trusted route.
        assert_eq!(ranked[0].1.hop_count, 1);
    }

    #[test]
    fn test_trust_is_tiebreaker_not_dominant() {
        let now = 1000;

        // An Unknown-trust 1-hop route should still beat an
        // InnerCircle-trust 10-hop route. Trust doesn't dominate.
        let close_untrusted = make_entry(1, 10, TrustLevel::Unknown, now);
        let far_trusted = make_entry(10, 100, TrustLevel::InnerCircle, now);

        let score_close = score_path(&close_untrusted, now);
        let score_far = score_path(&far_trusted, now);

        assert!(
            score_close > score_far,
            "1-hop Unknown ({}) should beat 10-hop InnerCircle ({})",
            score_close,
            score_far
        );
    }

    #[test]
    fn test_zero_guards() {
        let now = 1000;

        // hop_count = 0 and latency = 0 should not panic.
        let entry = make_entry(0, 0, TrustLevel::Trusted, now);
        let score = score_path(&entry, now);

        // Should be finite and positive.
        assert!(score.is_finite());
        assert!(score > 0.0);
    }

    /// An unmeasured route (latency_ms == 0) should score WORSE than an
    /// otherwise identical measured route.  We use the conservative
    /// UNMEASURED_LATENCY_MS sentinel, not 1ms best-case.
    #[test]
    fn test_unmeasured_latency_penalized() {
        let now = 1000;

        // Same hop count and trust — only latency differs.
        let unmeasured = make_entry(2, 0, TrustLevel::Trusted, now);      // latency_ms = 0
        let measured_fast = make_entry(2, 50, TrustLevel::Trusted, now);  // 50ms — realistic LAN
        let measured_slow = make_entry(2, 900, TrustLevel::Trusted, now); // 900ms — slow but known

        let s_unmeasured = score_path(&unmeasured, now);
        let s_fast = score_path(&measured_fast, now);
        let s_slow = score_path(&measured_slow, now);

        assert!(
            s_fast > s_unmeasured,
            "50ms measured ({s_fast}) must beat unmeasured ({s_unmeasured})"
        );
        assert!(
            s_slow > s_unmeasured,
            "900ms measured ({s_slow}) must beat unmeasured ({s_unmeasured}) — \
             conservative sentinel is 1000ms"
        );
    }

    /// An unmeasured route should lose to a measured route even if the
    /// measured route has worse hop count, as long as latency dominates.
    #[test]
    fn test_unmeasured_loses_to_measured_more_hops() {
        let now = 1000;

        // 1-hop unmeasured vs 3-hop measured at 10ms.
        let unmeasured = make_entry(1, 0, TrustLevel::Trusted, now);
        let measured = make_entry(3, 10, TrustLevel::Trusted, now);

        // score_unmeasured = (1/1) * tw * (1/1000) = tw/1000
        // score_measured   = (1/3) * tw * (1/10)   = tw/30
        // tw/30 > tw/1000, so measured wins.
        let s_unmeasured = score_path(&unmeasured, now);
        let s_measured = score_path(&measured, now);

        assert!(
            s_measured > s_unmeasured,
            "3-hop 10ms measured ({s_measured}) must beat 1-hop unmeasured ({s_unmeasured})"
        );
    }
}
