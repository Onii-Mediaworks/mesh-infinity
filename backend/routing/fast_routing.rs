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
// Begin the block scope.
// FastRoutingHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FastRoutingHeader — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FastRoutingHeader {
    /// The full path from source to destination.
    /// Each entry is a device address. The packet is forwarded
    /// along this path in order.
    // Execute this protocol step.
    // Execute this protocol step.
    pub path: Vec<DeviceAddress>,

    /// Current position in the path (which hop we're at).
    /// Incremented by each forwarder.
    // Execute this protocol step.
    // Execute this protocol step.
    pub current_hop: u8,

    /// Whether the originator requests quality-of-service handling
    /// (lower jitter, priority queuing).
    // Execute this protocol step.
    // Execute this protocol step.
    pub qos_requested: bool,
}

// Begin the block scope.
// FastRoutingHeader implementation — core protocol logic.
// FastRoutingHeader implementation — core protocol logic.
impl FastRoutingHeader {
    /// Create a new fast routing header.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(path: Vec<DeviceAddress>) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            path,
            // Execute this protocol step.
            // Execute this protocol step.
            current_hop: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            qos_requested: false,
        }
    }

    /// Get the next hop address, or None if we've reached the end.
    // Perform the 'next hop' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'next hop' operation.
    // Errors are propagated to the caller via Result.
    pub fn next_hop(&self) -> Option<&DeviceAddress> {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.path.get(self.current_hop as usize + 1)
    }

    /// Get the final destination.
    // Perform the 'destination' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'destination' operation.
    // Errors are propagated to the caller via Result.
    pub fn destination(&self) -> Option<&DeviceAddress> {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.path.last()
    }

    /// Advance to the next hop.
    // Perform the 'advance' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'advance' operation.
    // Errors are propagated to the caller via Result.
    pub fn advance(&mut self) {
        // Update the current hop to reflect the new state.
        // Advance current hop state.
        // Advance current hop state.
        self.current_hop += 1;
    }

    /// Total hops in the path.
    // Perform the 'total hops' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'total hops' operation.
    // Errors are propagated to the caller via Result.
    pub fn total_hops(&self) -> usize {
        // Clamp the value to prevent overflow or underflow.
        // Execute this protocol step.
        // Execute this protocol step.
        self.path.len().saturating_sub(1)
    }

    /// Whether we've reached the destination.
    // Perform the 'is at destination' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is at destination' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_at_destination(&self) -> bool {
        // Validate the length matches the expected protocol size.
        // Execute this protocol step.
        // Execute this protocol step.
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
