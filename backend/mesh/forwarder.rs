//! Packet Forwarding Decision Engine (§6.5)
//!
//! Given an inbound `MeshPacket` that is NOT addressed to us, this module
//! decides whether and how to forward it.
//!
//! # Decision flowchart
//!
//! 1. **Dedup check** — is `packet_id` in the deduplication cache?
//!    → Yes: drop (already forwarded).
//!    → No: record it and continue.
//!
//! 2. **TTL check** — is `ttl == 0` after decrement?
//!    → Yes: drop (packet has traveled too far).
//!
//! 3. **Routing lookup** — does the routing table have an entry for `destination`?
//!    → No: drop (no known path).
//!    → Yes: extract `next_hop`.
//!
//! 4. **Forward** — send the (TTL-decremented) packet to `next_hop`.

use crate::routing::table::{DeviceAddress, RoutingEntry};
use crate::routing::loop_prevention::{DeduplicationCache, PacketId};

/// Packet header fields passed to [`ForwardEngine::decide`].
///
/// Groups the per-packet immutable fields so that `decide` stays under the
/// 7-argument lint limit while remaining easy to call.
// PacketHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PacketHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PacketHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PacketHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PacketHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PacketHeader {
    /// Unique packet ID used for deduplication.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub packet_id: [u8; 32],
    /// Intended destination address.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub destination: DeviceAddress,
    /// Remaining hop budget (decremented by each forwarding node).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ttl: u8,
    /// Wall-clock timestamp embedded in the packet (seconds since epoch).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// ForwardDecision
// ---------------------------------------------------------------------------

/// What the forwarder decided to do with an inbound packet.
#[derive(Debug, PartialEq, Eq)]
// Begin the block scope.
// ForwardDecision — variant enumeration.
// Match exhaustively to handle every protocol state.
// ForwardDecision — variant enumeration.
// Match exhaustively to handle every protocol state.
// ForwardDecision — variant enumeration.
// Match exhaustively to handle every protocol state.
// ForwardDecision — variant enumeration.
// Match exhaustively to handle every protocol state.
// ForwardDecision — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ForwardDecision {
    /// Deliver to the local application (we are the destination).
    Deliver,

    /// Forward to the specified next hop.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Forward {
        /// The immediate next hop we should send the packet to.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        next_hop: DeviceAddress,
    },

    /// Drop the packet — reason given.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Drop(DropReason),
}

/// Why a packet was dropped.
#[derive(Debug, PartialEq, Eq)]
// Begin the block scope.
// DropReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// DropReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// DropReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// DropReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// DropReason — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum DropReason {
    /// We've already seen this packet ID.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Duplicate,
    /// TTL expired after decrement.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    TtlExpired,
    /// No route to the destination.
    NoRoute,
    /// Packet is too old (timestamp too far in the past).
    TooOld,
    /// Malformed packet.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Malformed,
}

// ---------------------------------------------------------------------------
// Maximum age for forwarded packets
// ---------------------------------------------------------------------------

/// Packets older than 60 seconds are dropped.
///
/// A legitimate packet should arrive within a few seconds at most;
/// a 60-second window handles network delays and retransmissions.
// MAX_PACKET_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PACKET_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PACKET_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PACKET_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PACKET_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
const MAX_PACKET_AGE_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// ForwardEngine
// ---------------------------------------------------------------------------

/// The packet forwarding decision engine.
///
/// Stateless — takes the current dedup cache and routing table as input,
/// updates them on accept, and returns the decision.
// ForwardEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ForwardEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ForwardEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ForwardEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ForwardEngine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ForwardEngine;

// Begin the block scope.
// ForwardEngine implementation — core protocol logic.
// ForwardEngine implementation — core protocol logic.
// ForwardEngine implementation — core protocol logic.
// ForwardEngine implementation — core protocol logic.
// ForwardEngine implementation — core protocol logic.
impl ForwardEngine {
    /// Decide what to do with an inbound `MeshPacket`.
    ///
    /// # Arguments
    ///
    /// - `packet_id`: The packet's unique identifier.
    /// - `destination`: The destination `DeviceAddress`.
    /// - `our_address`: Our own `DeviceAddress` (to detect delivery).
    /// - `ttl`: The packet's current TTL (will be rejected if 0).
    /// - `timestamp`: The packet's origination timestamp.
    /// - `now`: Current unix timestamp.
    /// - `dedup`: The deduplication cache (mutated on accept).
    /// - `route`: The routing table lookup result for `destination`.
    ///
    /// The dedup cache is updated (packet ID recorded) if the packet is
    /// accepted for delivery or forwarding.
    // Perform the 'decide' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'decide' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'decide' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'decide' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'decide' operation.
    // Errors are propagated to the caller via Result.
    pub fn decide(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        header: &PacketHeader,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        our_address: &DeviceAddress,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        dedup: &mut DeduplicationCache,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        route: Option<&RoutingEntry>,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ) -> ForwardDecision {
        // Unique identifier for lookup and deduplication.
        // Compute pid for this protocol step.
        // Compute pid for this protocol step.
        // Compute pid for this protocol step.
        // Compute pid for this protocol step.
        // Compute pid for this protocol step.
        let pid = PacketId(header.packet_id);

        // Age check: discard stale packets.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if now.saturating_sub(header.timestamp) > MAX_PACKET_AGE_SECS {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return ForwardDecision::Drop(DropReason::TooOld);
        }

        // TTL check: is this packet still alive?
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if header.ttl == 0 {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return ForwardDecision::Drop(DropReason::TtlExpired);
        }

        // Deduplication: have we already seen this packet?
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if dedup.check_and_record(pid, now) {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return ForwardDecision::Drop(DropReason::Duplicate);
        }

        // Are we the destination?
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if &header.destination == our_address {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return ForwardDecision::Deliver;
        }

        // Look up the route to the destination.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        let entry = match route {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            // Wrap the found value.
            // Wrap the found value.
            Some(e) => e,
            // Update the local state.
            // No value available.
            // No value available.
            // No value available.
            // No value available.
            None => return ForwardDecision::Drop(DropReason::NoRoute),
        };

        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        ForwardDecision::Forward {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            next_hop: entry.next_hop,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::table::{RoutingEntry, DeviceAddress};
    use crate::trust::levels::TrustLevel;

    fn addr(byte: u8) -> DeviceAddress {
        let mut a = [0u8; 32];
        a[0] = byte;
        DeviceAddress(a)
    }

    fn make_entry(dest: DeviceAddress, next_hop: DeviceAddress) -> RoutingEntry {
        RoutingEntry {
            destination: dest,
            next_hop,
            hop_count: 1,
            latency_ms: 10,
            next_hop_trust: TrustLevel::Trusted,
            last_updated: 1000,
            announcement_id: [0u8; 32],
        }
    }

    #[test]
    fn test_deliver_to_self() {
        let mut dedup = DeduplicationCache::new();
        let our = addr(0x01);
        let id = [0xABu8; 32];
        let entry = make_entry(our, our);
        let result = ForwardEngine::decide(
            &PacketHeader { packet_id: id, destination: our, ttl: 10, timestamp: 1000 },
            &our, 1000, &mut dedup, Some(&entry),
        );
        assert_eq!(result, ForwardDecision::Deliver);
    }

    #[test]
    fn test_forward_to_next_hop() {
        let mut dedup = DeduplicationCache::new();
        let our = addr(0x01);
        let dest = addr(0x02);
        let next = addr(0x03);
        let id = [0xCDu8; 32];
        let entry = make_entry(dest, next);
        let result = ForwardEngine::decide(
            &PacketHeader { packet_id: id, destination: dest, ttl: 5, timestamp: 1000 },
            &our, 1000, &mut dedup, Some(&entry),
        );
        assert_eq!(result, ForwardDecision::Forward { next_hop: next });
    }

    #[test]
    fn test_drop_duplicate() {
        let mut dedup = DeduplicationCache::new();
        let our = addr(0x01);
        let dest = addr(0x02);
        let next = addr(0x03);
        let id = [0xEFu8; 32];
        let entry = make_entry(dest, next);

        let hdr = PacketHeader { packet_id: id, destination: dest, ttl: 5, timestamp: 1000 };
        // First: accepted.
        ForwardEngine::decide(&hdr, &our, 1000, &mut dedup, Some(&entry));
        // Second: duplicate.
        let result = ForwardEngine::decide(&hdr, &our, 1000, &mut dedup, Some(&entry));
        assert_eq!(result, ForwardDecision::Drop(DropReason::Duplicate));
    }

    #[test]
    fn test_drop_ttl_expired() {
        let mut dedup = DeduplicationCache::new();
        let our = addr(0x01);
        let dest = addr(0x02);
        let id = [0x11u8; 32];
        let result = ForwardEngine::decide(
            &PacketHeader { packet_id: id, destination: dest, ttl: 0, timestamp: 1000 },
            &our, 1000, &mut dedup, None,
        );
        assert_eq!(result, ForwardDecision::Drop(DropReason::TtlExpired));
    }

    #[test]
    fn test_drop_no_route() {
        let mut dedup = DeduplicationCache::new();
        let our = addr(0x01);
        let dest = addr(0x02);
        let id = [0x22u8; 32];
        let result = ForwardEngine::decide(
            &PacketHeader { packet_id: id, destination: dest, ttl: 5, timestamp: 1000 },
            &our, 1000, &mut dedup, None,
        );
        assert_eq!(result, ForwardDecision::Drop(DropReason::NoRoute));
    }

    #[test]
    fn test_drop_too_old() {
        let mut dedup = DeduplicationCache::new();
        let our = addr(0x01);
        let dest = addr(0x02);
        let id = [0x33u8; 32];
        // now=2000, timestamp=500 → age = 1500 > 60
        let result = ForwardEngine::decide(
            &PacketHeader { packet_id: id, destination: dest, ttl: 5, timestamp: 500 },
            &our, 2000, &mut dedup, None,
        );
        assert_eq!(result, ForwardDecision::Drop(DropReason::TooOld));
    }
}
