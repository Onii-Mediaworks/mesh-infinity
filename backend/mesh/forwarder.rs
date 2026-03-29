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
pub struct PacketHeader {
    /// Unique packet ID used for deduplication.
    pub packet_id: [u8; 32],
    /// Intended destination address.
    pub destination: DeviceAddress,
    /// Remaining hop budget (decremented by each forwarding node).
    pub ttl: u8,
    /// Wall-clock timestamp embedded in the packet (seconds since epoch).
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// ForwardDecision
// ---------------------------------------------------------------------------

/// What the forwarder decided to do with an inbound packet.
#[derive(Debug, PartialEq, Eq)]
pub enum ForwardDecision {
    /// Deliver to the local application (we are the destination).
    Deliver,

    /// Forward to the specified next hop.
    Forward {
        /// The immediate next hop we should send the packet to.
        next_hop: DeviceAddress,
    },

    /// Drop the packet — reason given.
    Drop(DropReason),
}

/// Why a packet was dropped.
#[derive(Debug, PartialEq, Eq)]
pub enum DropReason {
    /// We've already seen this packet ID.
    Duplicate,
    /// TTL expired after decrement.
    TtlExpired,
    /// No route to the destination.
    NoRoute,
    /// Packet is too old (timestamp too far in the past).
    TooOld,
    /// Malformed packet.
    Malformed,
}

// ---------------------------------------------------------------------------
// Maximum age for forwarded packets
// ---------------------------------------------------------------------------

/// Packets older than 60 seconds are dropped.
///
/// A legitimate packet should arrive within a few seconds at most;
/// a 60-second window handles network delays and retransmissions.
const MAX_PACKET_AGE_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// ForwardEngine
// ---------------------------------------------------------------------------

/// The packet forwarding decision engine.
///
/// Stateless — takes the current dedup cache and routing table as input,
/// updates them on accept, and returns the decision.
pub struct ForwardEngine;

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
    pub fn decide(
        header: &PacketHeader,
        our_address: &DeviceAddress,
        now: u64,
        dedup: &mut DeduplicationCache,
        route: Option<&RoutingEntry>,
    ) -> ForwardDecision {
        let pid = PacketId(header.packet_id);

        // Age check: discard stale packets.
        if now.saturating_sub(header.timestamp) > MAX_PACKET_AGE_SECS {
            return ForwardDecision::Drop(DropReason::TooOld);
        }

        // TTL check: is this packet still alive?
        if header.ttl == 0 {
            return ForwardDecision::Drop(DropReason::TtlExpired);
        }

        // Deduplication: have we already seen this packet?
        if dedup.check_and_record(pid, now) {
            return ForwardDecision::Drop(DropReason::Duplicate);
        }

        // Are we the destination?
        if &header.destination == our_address {
            return ForwardDecision::Deliver;
        }

        // Look up the route to the destination.
        let entry = match route {
            Some(e) => e,
            None => return ForwardDecision::Drop(DropReason::NoRoute),
        };

        ForwardDecision::Forward {
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
