//! Fast Routing Mode (§6.7)
//!
//! # What is Fast Routing?
//!
//! An opt-in mode that trades anonymity for latency. Instead of
//! hop-by-hop routing (where each node makes independent forwarding
//! decisions), fast routing computes the full path upfront using
//! Dijkstra's algorithm and encodes it in the packet header.
//!
//! # Privacy Tradeoffs (§6.7)
//!
//! - The originator knows the full network topology
//! - Each intermediate node knows both previous and next hop
//! - A network observer watching multiple nodes can reconstruct
//!   the full path
//!
//! # Ambient Traffic Threshold (§6.7)
//!
//! Fast routing is only available when ambient traffic is sufficient
//! to make a shorter path statistically indistinguishable. Below
//! threshold, fast routing is ABSENT from the UI — not disabled.
//! The threshold is NOT user-reducible.
//!
//! # Appropriate For
//!
//! High-throughput local mesh scenarios where all participants
//! trust each other (e.g., a home or office network).

use serde::{Deserialize, Serialize};

use super::table::DeviceAddress;

// ---------------------------------------------------------------------------
// Fast Routing Header
// ---------------------------------------------------------------------------

/// A source-routed packet header for fast routing mode (§6.7).
///
/// The originator computes the full path using Dijkstra's and
/// encodes it here. Each intermediate node pops its entry and
/// forwards to the next hop.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastRoutingHeader {
    /// The full path from source to destination.
    /// Each entry is a device address. The packet is forwarded
    /// along this path in order.
    pub path: Vec<DeviceAddress>,

    /// Current position in the path (which hop we're at).
    /// Incremented by each forwarder.
    pub current_hop: u8,

    /// Whether the originator requests quality-of-service handling
    /// (lower jitter, priority queuing).
    pub qos_requested: bool,
}

impl FastRoutingHeader {
    /// Create a new fast routing header.
    pub fn new(path: Vec<DeviceAddress>) -> Self {
        Self {
            path,
            current_hop: 0,
            qos_requested: false,
        }
    }

    /// Get the next hop address, or None if we've reached the end.
    pub fn next_hop(&self) -> Option<&DeviceAddress> {
        self.path.get(self.current_hop as usize + 1)
    }

    /// Get the final destination.
    pub fn destination(&self) -> Option<&DeviceAddress> {
        self.path.last()
    }

    /// Advance to the next hop.
    pub fn advance(&mut self) {
        self.current_hop += 1;
    }

    /// Total hops in the path.
    pub fn total_hops(&self) -> usize {
        self.path.len().saturating_sub(1)
    }

    /// Whether we've reached the destination.
    pub fn is_at_destination(&self) -> bool {
        self.current_hop as usize >= self.path.len().saturating_sub(1)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> DeviceAddress {
        DeviceAddress([b; 32])
    }

    #[test]
    fn test_header_navigation() {
        let mut header = FastRoutingHeader::new(vec![
            addr(0x01), // Source.
            addr(0x02), // Hop 1.
            addr(0x03), // Destination.
        ]);

        assert_eq!(header.total_hops(), 2);
        assert!(!header.is_at_destination());
        assert_eq!(*header.next_hop().unwrap(), addr(0x02));

        header.advance();
        assert_eq!(*header.next_hop().unwrap(), addr(0x03));

        header.advance();
        assert!(header.is_at_destination());
    }

    #[test]
    fn test_destination() {
        let header = FastRoutingHeader::new(vec![addr(0x01), addr(0xFF)]);
        assert_eq!(*header.destination().unwrap(), addr(0xFF));
    }
}
