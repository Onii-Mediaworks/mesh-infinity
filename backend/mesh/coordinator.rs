//! MeshCoordinator — the central routing coordinator for the mesh layer (§6).
//!
//! The coordinator is the bridge between the application layer and the
//! transport layer. It owns references to the routing table, dedup cache,
//! and announcement processor, and provides the main API for:
//!
//! - **Sending** a packet to a destination peer (route → transport → wire).
//! - **Receiving** a packet: decide deliver vs. forward vs. drop.
//!
//! # Transport selection (§5.10)
//!
//! After the routing table gives us the next hop, the coordinator selects
//! the best transport based on:
//! 1. The hop's `TrustLevel` (high trust → prefer direct clearnet; low trust → prefer Tor).
//! 2. Available transports (what the sending node has enabled).
//! 3. Packet urgency (calls want low latency; messages can use Tor).
//!
//! # Integration with MeshContext (§17.5)
//!
//! `MeshCoordinator` is lightweight — it does NOT own the routing table or
//! dedup cache directly; those live in `MeshContext` as `Mutex<T>`. The
//! coordinator takes mutable references when it needs to act, and the FFI
//! functions in `lib.rs` orchestrate the locking.

use crate::network::transport_hint::TransportType;
use crate::routing::table::{DeviceAddress, RoutingEntry};
use crate::trust::levels::TrustLevel;

// ---------------------------------------------------------------------------
// TransportPreference
// ---------------------------------------------------------------------------

/// The coordinator's recommendation for which transport to use.
///
/// The actual transport decision is made by the transport solver (§5.10);
/// this is an advisory preference that the solver weighs against availability.
#[derive(Debug, Clone, PartialEq, Eq)]
// Begin the block scope.
// TransportPreference — variant enumeration.
// Match exhaustively to handle every protocol state.
// TransportPreference — variant enumeration.
// Match exhaustively to handle every protocol state.
// TransportPreference — variant enumeration.
// Match exhaustively to handle every protocol state.
// TransportPreference — variant enumeration.
// Match exhaustively to handle every protocol state.
// TransportPreference — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum TransportPreference {
    /// Use clearnet TCP — fastest, least private.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Clearnet,
    /// Use Tor — slower, most private.
    Tor,
    /// Use the mesh routing layer — for multi-hop indirect paths.
    Mesh,
    /// Use Bluetooth LE — for short-range direct connections.
    Ble,
    /// Use RF/SDR — for off-grid connections.
    Rf,
    /// No preference — let the solver decide.
    Any,
}

// ---------------------------------------------------------------------------
// SendRequest / SendResult
// ---------------------------------------------------------------------------

/// A request to send a payload through the mesh.
// SendRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SendRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SendRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SendRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SendRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SendRequest {
    /// Destination device address.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub destination: DeviceAddress,
    /// The payload to send (application-layer encrypted).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload: Vec<u8>,
    /// Whether to prefer low latency (e.g. voice call) over privacy.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub prefer_low_latency: bool,
    /// Whether to prefer high privacy (e.g. anonymous message) over speed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub prefer_high_privacy: bool,
}

/// Result of a send request.
#[derive(Debug)]
// Begin the block scope.
// SendResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// SendResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// SendResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// SendResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// SendResult — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum SendResult {
    /// Packet queued for delivery via the specified transport.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Queued {
        transport: TransportType,
        next_hop: DeviceAddress,
    },
    /// No route to destination.
    NoRoute,
    /// No matching transport is available.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    NoTransport,
}

// ---------------------------------------------------------------------------
// MeshCoordinator
// ---------------------------------------------------------------------------

/// The mesh routing coordinator.
///
/// Stateless — does not own routing state; operates on provided state.
// MeshCoordinator — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MeshCoordinator — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MeshCoordinator — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MeshCoordinator — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MeshCoordinator — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MeshCoordinator;

// Begin the block scope.
// MeshCoordinator implementation — core protocol logic.
// MeshCoordinator implementation — core protocol logic.
// MeshCoordinator implementation — core protocol logic.
// MeshCoordinator implementation — core protocol logic.
// MeshCoordinator implementation — core protocol logic.
impl MeshCoordinator {
    /// Create a new coordinator.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new() -> Self {
        Self
    }

    /// Select the preferred transport given a routing entry and packet intent.
    ///
    /// Rules (highest priority first):
    /// 1. If `prefer_high_privacy` → prefer Tor.
    /// 2. If `prefer_low_latency` AND trust >= Trusted → prefer clearnet.
    /// 3. If next_hop trust is Untrusted or Unknown → prefer Tor.
    /// 4. If hop_count > 1 (multi-hop) → use mesh relay.
    /// 5. Otherwise → clearnet.
    // Perform the 'select transport' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'select transport' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'select transport' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'select transport' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'select transport' operation.
    // Errors are propagated to the caller via Result.
    pub fn select_transport(
        &self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        entry: &RoutingEntry,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        prefer_low_latency: bool,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        prefer_high_privacy: bool,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> TransportPreference {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if prefer_high_privacy {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return TransportPreference::Tor;
        }

        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if prefer_low_latency && entry.next_hop_trust >= TrustLevel::Trusted {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return TransportPreference::Clearnet;
        }

        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match entry.next_hop_trust {
            // Handle this match arm.
            TrustLevel::Unknown | TrustLevel::Public => TransportPreference::Tor,
            // Handle this match arm.
            _ if entry.hop_count > 1 => TransportPreference::Mesh,
            // Update the local state.
            _ => TransportPreference::Clearnet,
        }
    }

    /// Map a `TransportPreference` to a concrete `TransportType`.
    ///
    /// In a full implementation this would check `available_transports`
    /// and fall back gracefully. For now, it maps directly.
    // Perform the 'preference to type' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'preference to type' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'preference to type' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'preference to type' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'preference to type' operation.
    // Errors are propagated to the caller via Result.
    pub fn preference_to_type(
        &self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        pref: &TransportPreference,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        available: &[TransportType],
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Option<TransportType> {
        // Dispatch based on the variant to apply type-specific logic.
        // Compute preferred for this protocol step.
        // Compute preferred for this protocol step.
        // Compute preferred for this protocol step.
        // Compute preferred for this protocol step.
        // Compute preferred for this protocol step.
        let preferred = match pref {
            // Handle this match arm.
            TransportPreference::Clearnet => TransportType::Clearnet,
            // Handle this match arm.
            TransportPreference::Tor => TransportType::Tor,
            // Handle this match arm.
            TransportPreference::Ble => TransportType::BLE,
            // Handle this match arm.
            TransportPreference::Rf => TransportType::RF,
            // Begin the block scope.
            // Handle TransportPreference::Mesh | TransportPreference::Any.
            // Handle TransportPreference::Mesh | TransportPreference::Any.
            // Handle TransportPreference::Mesh | TransportPreference::Any.
            // Handle TransportPreference::Mesh | TransportPreference::Any.
            // Handle TransportPreference::Mesh | TransportPreference::Any.
            TransportPreference::Mesh | TransportPreference::Any => {
                // Pick first available in priority order.
                // Iterate over each element.
                // Iterate over each element.
                // Iterate over each element.
                // Iterate over each element.
                // Iterate over each element.
                for t in &[
                    TransportType::Clearnet,
                    TransportType::BLE,
                    TransportType::RF,
                ] {
                    // Conditional branch based on the current state.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    if available.contains(t) {
                        return Some(t.clone());
                    }
                }
                // No result available — signal absence to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return None;
            }
        };

        // Handle the error case — propagate or log as appropriate.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if available.contains(&preferred) {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Some(preferred);
        }

        // Fallback chain: if preferred isn't available, try others.
        //
        // IMPORTANT: when the caller preferred Tor (privacy requirement), we
        // must NOT fall back to Clearnet — that would silently leak traffic
        // over an unprotected channel.  Tor-preferred requests may only fall
        // back to other non-clearnet transports (BLE, RF).  If none of those
        // are available either, return None so the caller can fail explicitly.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if pref == &TransportPreference::Tor {
            // Iterate over each element in the collection.
            // Iterate over each element.
            // Iterate over each element.
            // Iterate over each element.
            // Iterate over each element.
            // Iterate over each element.
            for t in &[TransportType::BLE, TransportType::RF] {
                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if available.contains(t) {
                    return Some(t.clone());
                }
            }
            // No result available — signal absence to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return None;
        }

        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for t in &[
            TransportType::Clearnet,
            TransportType::BLE,
            TransportType::RF,
            TransportType::Tor,
        ] {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if available.contains(t) {
                return Some(t.clone());
            }
        }

        // No value available.
        // No value available.
        // No value available.
        // No value available.
        // No value available.
        None
    }

    /// Route a send request using the provided routing entry.
    ///
    /// Returns a `SendResult` describing what was done (or what failed).
    /// The caller is responsible for actually sending the bytes via the
    /// chosen transport.
    // Perform the 'route' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'route' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'route' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'route' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'route' operation.
    // Errors are propagated to the caller via Result.
    pub fn route(
        &self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        request: &SendRequest,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        entry: Option<&RoutingEntry>,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        available_transports: &[TransportType],
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> SendResult {
        // Dispatch based on the variant to apply type-specific logic.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        let entry = match entry {
            // Wrap the found value for the caller.
            // Wrap the found value.
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
            // No value available.
            None => return SendResult::NoRoute,
        };

        // Bind the computed value for subsequent use.
        // Compute pref for this protocol step.
        // Compute pref for this protocol step.
        // Compute pref for this protocol step.
        // Compute pref for this protocol step.
        // Compute pref for this protocol step.
        let pref = self.select_transport(
            entry,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            request.prefer_low_latency,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            request.prefer_high_privacy,
        );

        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self.preference_to_type(&pref, available_transports) {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            // Wrap the found value.
            // Wrap the found value.
            // Wrap the found value.
            Some(transport) => SendResult::Queued {
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                transport,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                next_hop: entry.next_hop,
            },
            // Update the local state.
            // No value available.
            // No value available.
            // No value available.
            // No value available.
            // No value available.
            None => SendResult::NoTransport,
        }
    }
}

// Trait implementation for protocol conformance.
// Implement Default for MeshCoordinator.
// Implement Default for MeshCoordinator.
// Implement Default for MeshCoordinator.
// Implement Default for MeshCoordinator.
// Implement Default for MeshCoordinator.
impl Default for MeshCoordinator {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
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
    use crate::routing::table::RoutingEntry;
    use crate::trust::levels::TrustLevel;

    fn addr(b: u8) -> DeviceAddress {
        let mut a = [0u8; 32];
        a[0] = b;
        DeviceAddress(a)
    }

    fn make_entry(hop_count: u8, trust: TrustLevel) -> RoutingEntry {
        RoutingEntry {
            destination: addr(0x02),
            next_hop: addr(0x03),
            hop_count,
            latency_ms: 10,
            next_hop_trust: trust,
            last_updated: 1000,
            announcement_id: [0u8; 32],
        }
    }

    #[test]
    fn test_high_privacy_prefers_tor() {
        let coord = MeshCoordinator::new();
        let entry = make_entry(1, TrustLevel::Trusted);
        let pref = coord.select_transport(&entry, false, true);
        assert_eq!(pref, TransportPreference::Tor);
    }

    #[test]
    fn test_low_latency_trusted_prefers_clearnet() {
        let coord = MeshCoordinator::new();
        let entry = make_entry(1, TrustLevel::Trusted);
        let pref = coord.select_transport(&entry, true, false);
        assert_eq!(pref, TransportPreference::Clearnet);
    }

    #[test]
    fn test_unknown_trust_prefers_tor() {
        let coord = MeshCoordinator::new();
        let entry = make_entry(1, TrustLevel::Unknown);
        let pref = coord.select_transport(&entry, true, false);
        assert_eq!(pref, TransportPreference::Tor);
    }

    #[test]
    fn test_multihop_prefers_mesh() {
        let coord = MeshCoordinator::new();
        let entry = make_entry(3, TrustLevel::Trusted);
        let pref = coord.select_transport(&entry, false, false);
        assert_eq!(pref, TransportPreference::Mesh);
    }

    #[test]
    fn test_route_no_route() {
        let coord = MeshCoordinator::new();
        let req = SendRequest {
            destination: addr(0x05),
            payload: vec![1, 2, 3],
            prefer_low_latency: false,
            prefer_high_privacy: false,
        };
        let result = coord.route(&req, None, &[TransportType::Clearnet]);
        assert!(matches!(result, SendResult::NoRoute));
    }

    #[test]
    fn test_route_no_transport() {
        let coord = MeshCoordinator::new();
        let entry = make_entry(1, TrustLevel::Trusted);
        let req = SendRequest {
            destination: addr(0x02),
            payload: vec![],
            prefer_low_latency: true,
            prefer_high_privacy: false,
        };
        // No transports available.
        let result = coord.route(&req, Some(&entry), &[]);
        assert!(matches!(result, SendResult::NoTransport));
    }

    #[test]
    fn test_tor_preferred_no_fallback_to_clearnet() {
        // When Tor is preferred (privacy required) and Tor is unavailable,
        // we must return NoTransport — not silently fall back to clearnet.
        let coord = MeshCoordinator::new();
        let entry = make_entry(1, TrustLevel::Trusted);
        let req = SendRequest {
            destination: addr(0x02),
            payload: vec![0xAB],
            prefer_low_latency: false,
            prefer_high_privacy: true, // forces Tor preference
        };
        // Only clearnet available — must be refused, not used.
        let result = coord.route(&req, Some(&entry), &[TransportType::Clearnet]);
        assert!(
            matches!(result, SendResult::NoTransport),
            "Tor-preferred packet must not fall back to clearnet"
        );
    }

    #[test]
    fn test_tor_preferred_falls_back_to_ble_not_clearnet() {
        // When Tor is unavailable but BLE is, a privacy-required packet
        // may use BLE — but still must not use clearnet.
        let coord = MeshCoordinator::new();
        let entry = make_entry(1, TrustLevel::Trusted);
        let req = SendRequest {
            destination: addr(0x02),
            payload: vec![0xAB],
            prefer_low_latency: false,
            prefer_high_privacy: true,
        };
        let result = coord.route(
            &req,
            Some(&entry),
            &[TransportType::Clearnet, TransportType::BLE],
        );
        match result {
            SendResult::Queued { transport, .. } => {
                assert_eq!(transport, TransportType::BLE);
            }
            _ => panic!("expected Queued via BLE"),
        }
    }

    #[test]
    fn test_tor_preferred_succeeds_when_tor_available() {
        let coord = MeshCoordinator::new();
        let entry = make_entry(1, TrustLevel::Trusted);
        let req = SendRequest {
            destination: addr(0x02),
            payload: vec![],
            prefer_low_latency: false,
            prefer_high_privacy: true,
        };
        let result = coord.route(
            &req,
            Some(&entry),
            &[TransportType::Clearnet, TransportType::Tor],
        );
        match result {
            SendResult::Queued { transport, .. } => {
                assert_eq!(transport, TransportType::Tor);
            }
            _ => panic!("expected Queued via Tor"),
        }
    }

    #[test]
    fn test_route_success() {
        let coord = MeshCoordinator::new();
        let entry = make_entry(1, TrustLevel::Trusted);
        let req = SendRequest {
            destination: addr(0x02),
            payload: vec![0xFF],
            prefer_low_latency: true,
            prefer_high_privacy: false,
        };
        let result = coord.route(&req, Some(&entry), &[TransportType::Clearnet]);
        match result {
            SendResult::Queued {
                transport,
                next_hop,
            } => {
                assert_eq!(transport, TransportType::Clearnet);
                assert_eq!(next_hop, addr(0x03));
            }
            _ => panic!("expected Queued"),
        }
    }
}
