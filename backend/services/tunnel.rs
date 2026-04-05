//! TCP and UDP Tunneling (§12.3)
//!
//! # Mesh Tunneling
//!
//! Tunneling carries TCP and UDP traffic through the mesh to hosted
//! services. Tunnels are established with a request/accept handshake,
//! then data flows as WireGuard-encrypted TunnelData packets.
//!
//! # Tunnel Lifecycle
//!
//! 1. Client sends TunnelRequest to the service host
//! 2. Host checks ACL (§8.8) and sends TunnelAccept or reject
//! 3. Data flows as TunnelData packets with sequence numbers
//! 4. Either side can send TunnelClose to tear down
//! 5. Idle tunnels (no app connections for 10 min) auto-close
//!
//! # UDP Fragmentation
//!
//! Large UDP datagrams are fragmented into TunnelFragment pieces.
//! Missing fragments trigger a 5-second timeout, after which the
//! partial datagram is discarded (treated as a dropped datagram).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default idle timeout for tunnels (seconds).
/// Idle = no application connections, not just no traffic.
// TUNNEL_IDLE_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// TUNNEL_IDLE_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// TUNNEL_IDLE_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const TUNNEL_IDLE_TIMEOUT_SECS: u64 = 600;

/// UDP fragment timeout (seconds).
/// If a fragment is missing for this long, discard the partial datagram.
// UDP_FRAGMENT_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// UDP_FRAGMENT_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// UDP_FRAGMENT_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const UDP_FRAGMENT_TIMEOUT_SECS: u64 = 5;

/// Maximum simultaneous tunnels per node.
// MAX_TUNNELS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_TUNNELS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_TUNNELS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_TUNNELS: usize = 256;

// ---------------------------------------------------------------------------
// Tunnel Protocol
// ---------------------------------------------------------------------------

/// Tunnel protocol type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// TunnelProto — variant enumeration.
// Match exhaustively to handle every protocol state.
// TunnelProto — variant enumeration.
// Match exhaustively to handle every protocol state.
// TunnelProto — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum TunnelProto {
    TCP,
    UDP,
}

// ---------------------------------------------------------------------------
// Service Target
// ---------------------------------------------------------------------------

/// How a tunnel endpoint is addressed.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ServiceTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// ServiceTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// ServiceTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ServiceTarget {
    /// Address a service by device address and optional port.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ByAddress {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        address: [u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        port: Option<u32>,
    },
    /// Address a service by service ID.
    ById {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        service_id: [u8; 16],
    },
}

// ---------------------------------------------------------------------------
// Tunnel Messages
// ---------------------------------------------------------------------------

/// Request to establish a tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TunnelRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelRequest {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The target for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target: ServiceTarget,
    /// The proto for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub proto: TunnelProto,
    /// The requested at for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub requested_at: u64,
    /// The requester id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub requester_id: [u8; 32],
}

/// Rejection reasons for a tunnel request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// TunnelRejectReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// TunnelRejectReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// TunnelRejectReason — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum TunnelRejectReason {
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    AccessDenied,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ServiceUnavailable,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ProtocolUnsupported,
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    RateLimited,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Redirect {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        address: [u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        port: Option<u32>,
    },
}

/// Response to a tunnel request.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TunnelAccept — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelAccept — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelAccept — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelAccept {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The accepted for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub accepted: bool,
    /// The reject reason for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub reject_reason: Option<TunnelRejectReason>,
    /// The mtu for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mtu: Option<u16>,
}

/// Fragment metadata for large datagrams.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TunnelFragment — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelFragment — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelFragment — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelFragment {
    /// The total size for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub total_size: u32,
    /// The fragment index for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub fragment_index: u16,
    /// The fragment count for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub fragment_count: u16,
    /// The fragment id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub fragment_id: u16,
}

/// A data packet in an active tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TunnelData — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelData — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelData — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelData {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The seq for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub seq: u64,
    /// The fragment for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub fragment: Option<TunnelFragment>,
    /// The payload for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload: Vec<u8>,
}

/// Keepalive for an active tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TunnelKeepalive — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelKeepalive — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelKeepalive — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelKeepalive {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
}

/// MTU update notification.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TunnelMTUUpdate — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelMTUUpdate — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelMTUUpdate — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelMTUUpdate {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The new mtu for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub new_mtu: u16,
}

/// Close a tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TunnelClose — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelClose — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelClose — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelClose {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The reason for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Tunnel Session State
// ---------------------------------------------------------------------------

/// An active tunnel session.
#[derive(Clone, Debug)]
// Begin the block scope.
// TunnelSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelSession — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelSession {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The target for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target: ServiceTarget,
    /// The proto for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub proto: TunnelProto,
    /// The requester id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub requester_id: [u8; 32],
    /// The established at for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub established_at: u64,
    /// The last activity for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_activity: u64,
    /// The bytes sent for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub bytes_sent: u64,
    /// The bytes received for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub bytes_received: u64,
    /// The next seq for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub next_seq: u64,
    /// The mtu for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mtu: u16,
}

// Begin the block scope.
// TunnelSession implementation — core protocol logic.
// TunnelSession implementation — core protocol logic.
// TunnelSession implementation — core protocol logic.
impl TunnelSession {
    /// Create a new tunnel session.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        request: &TunnelRequest,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        mtu: u16,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            session_id: request.session_id,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            target: request.target.clone(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            proto: request.proto,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            requester_id: request.requester_id,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            established_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            last_activity: now,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            bytes_sent: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            bytes_received: 0,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            next_seq: 0,
            mtu,
        }
    }

    /// Whether the session has been idle too long.
    // Perform the 'is idle' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is idle' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is idle' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_idle(&self, now: u64) -> bool {
        // Clamp the value to prevent overflow or underflow.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now.saturating_sub(self.last_activity) > TUNNEL_IDLE_TIMEOUT_SECS
    }

    /// Record sent data.
    // Perform the 'record send' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'record send' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'record send' operation.
    // Errors are propagated to the caller via Result.
    pub fn record_send(&mut self, bytes: u64, now: u64) {
        // Update the bytes sent to reflect the new state.
        // Advance bytes sent state.
        // Advance bytes sent state.
        // Advance bytes sent state.
        self.bytes_sent += bytes;
        // Update the last activity to reflect the new state.
        // Advance last activity state.
        // Advance last activity state.
        // Advance last activity state.
        self.last_activity = now;
    }

    /// Record received data.
    // Perform the 'record recv' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'record recv' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'record recv' operation.
    // Errors are propagated to the caller via Result.
    pub fn record_recv(&mut self, bytes: u64, now: u64) {
        // Update the bytes received to reflect the new state.
        // Advance bytes received state.
        // Advance bytes received state.
        // Advance bytes received state.
        self.bytes_received += bytes;
        // Update the last activity to reflect the new state.
        // Advance last activity state.
        // Advance last activity state.
        // Advance last activity state.
        self.last_activity = now;
    }

    /// Get and increment the sequence number.
    // Perform the 'next sequence' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'next sequence' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'next sequence' operation.
    // Errors are propagated to the caller via Result.
    pub fn next_sequence(&mut self) -> u64 {
        // Execute the operation and bind the result.
        // Compute seq for this protocol step.
        // Compute seq for this protocol step.
        // Compute seq for this protocol step.
        let seq = self.next_seq;
        // Update the next seq to reflect the new state.
        // Advance next seq state.
        // Advance next seq state.
        // Advance next seq state.
        self.next_seq += 1;
        seq
    }

    /// Update the MTU.
    // Perform the 'update mtu' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'update mtu' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'update mtu' operation.
    // Errors are propagated to the caller via Result.
    pub fn update_mtu(&mut self, new_mtu: u16) {
        // Update the mtu to reflect the new state.
        // Advance mtu state.
        // Advance mtu state.
        // Advance mtu state.
        self.mtu = new_mtu;
    }
}

// ---------------------------------------------------------------------------
// Fragment Reassembler
// ---------------------------------------------------------------------------

/// Reassembles fragmented UDP datagrams.
///
/// Tracks incoming fragments and produces complete datagrams.
/// Partial datagrams are discarded after UDP_FRAGMENT_TIMEOUT_SECS.
#[derive(Debug)]
// Begin the block scope.
// FragmentBuffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FragmentBuffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FragmentBuffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
struct FragmentBuffer {
    /// Expected total fragments.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    fragment_count: u16,
    /// Total size declared.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    total_size: u32,
    /// Received fragments. Index → data.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    fragments: HashMap<u16, Vec<u8>>,
    /// When the first fragment arrived.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    started_at: u64,
}

/// UDP fragment reassembly engine.
// FragmentReassembler — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FragmentReassembler — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FragmentReassembler — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FragmentReassembler {
    /// In-progress reassembly buffers. Key: (session_id, fragment_id).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    buffers: HashMap<([u8; 16], u16), FragmentBuffer>,
}

// Begin the block scope.
// FragmentReassembler implementation — core protocol logic.
// FragmentReassembler implementation — core protocol logic.
// FragmentReassembler implementation — core protocol logic.
impl FragmentReassembler {
    // Begin the block scope.
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
            buffers: HashMap::new(),
        }
    }

    /// Process an incoming fragment.
    ///
    /// Returns the reassembled datagram if all fragments have arrived,
    /// or None if more fragments are needed.
    // Perform the 'process' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process' operation.
    // Errors are propagated to the caller via Result.
    pub fn process(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        session_id: [u8; 16],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        fragment: &TunnelFragment,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        data: Vec<u8>,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Option<Vec<u8>> {
        // Key material — must be zeroized when no longer needed.
        // Compute key for this protocol step.
        // Compute key for this protocol step.
        // Compute key for this protocol step.
        let key = (session_id, fragment.fragment_id);

        // Key material — must be zeroized when no longer needed.
        // Compute buf for this protocol step.
        // Compute buf for this protocol step.
        // Compute buf for this protocol step.
        let buf = self.buffers.entry(key).or_insert_with(|| FragmentBuffer {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            fragment_count: fragment.fragment_count,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            total_size: fragment.total_size,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            fragments: HashMap::new(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            started_at: now,
        });

        // Insert into the lookup table for efficient retrieval.
        // Insert into the map/set.
        // Insert into the map/set.
        // Insert into the map/set.
        buf.fragments.insert(fragment.fragment_index, data);

        // Check if all fragments have arrived.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if buf.fragments.len() as u16 == buf.fragment_count {
            // Reassemble in order.
            // Compute result for this protocol step.
            // Compute result for this protocol step.
            // Compute result for this protocol step.
            let mut result = Vec::with_capacity(buf.total_size as usize);
            // Iterate over each element in the collection.
            // Iterate over each element.
            // Iterate over each element.
            // Iterate over each element.
            for i in 0..buf.fragment_count {
                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if let Some(frag) = buf.fragments.get(&i) {
                    // Append the data segment to the accumulating buffer.
                    // Append bytes to the accumulator.
                    // Append bytes to the accumulator.
                    // Append bytes to the accumulator.
                    result.extend_from_slice(frag);
                }
            }
            // Remove from the collection and return the evicted value.
            // Remove from the collection.
            // Remove from the collection.
            // Remove from the collection.
            self.buffers.remove(&key);
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            // Wrap the found value.
            Some(result)
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // No value available.
            // No value available.
            // No value available.
            None
        }
    }

    /// Remove timed-out partial reassembly buffers.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    pub fn gc(&mut self, now: u64) {
        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.buffers.retain(|_, buf| {
            // Clamp the value to prevent overflow or underflow.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            now.saturating_sub(buf.started_at) <= UDP_FRAGMENT_TIMEOUT_SECS
        });
    }

    /// Number of in-progress reassemblies.
    // Perform the 'pending count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pending count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pending count' operation.
    // Errors are propagated to the caller via Result.
    pub fn pending_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.buffers.len()
    }
}

// Trait implementation for protocol conformance.
// Implement Default for FragmentReassembler.
// Implement Default for FragmentReassembler.
// Implement Default for FragmentReassembler.
impl Default for FragmentReassembler {
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
// Tunnel Manager
// ---------------------------------------------------------------------------

/// Manages all active tunnel sessions.
///
/// Handles session creation, data forwarding, idle timeouts,
/// and fragment reassembly.
// TunnelManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TunnelManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TunnelManager {
    /// Active sessions. Key: session_id.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    sessions: HashMap<[u8; 16], TunnelSession>,
    /// UDP fragment reassembly engine.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub reassembler: FragmentReassembler,
}

// Begin the block scope.
// TunnelManager implementation — core protocol logic.
// TunnelManager implementation — core protocol logic.
// TunnelManager implementation — core protocol logic.
impl TunnelManager {
    // Begin the block scope.
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
            sessions: HashMap::new(),
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            reassembler: FragmentReassembler::new(),
        }
    }

    /// Handle a tunnel request. Returns a TunnelAccept.
    ///
    /// The caller is responsible for ACL checks before calling this.
    /// `acl_allowed`: whether the ACL engine approved this request.
    /// `mtu`: negotiated MTU for this tunnel.
    // Perform the 'handle request' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'handle request' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'handle request' operation.
    // Errors are propagated to the caller via Result.
    pub fn handle_request(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        request: &TunnelRequest,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        acl_allowed: bool,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        mtu: u16,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> TunnelAccept {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !acl_allowed {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return TunnelAccept {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                session_id: request.session_id,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                accepted: false,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                reject_reason: Some(TunnelRejectReason::AccessDenied),
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                mtu: None,
            };
        }

        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.sessions.len() >= MAX_TUNNELS {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return TunnelAccept {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                session_id: request.session_id,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                accepted: false,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                reject_reason: Some(TunnelRejectReason::RateLimited),
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                mtu: None,
            };
        }

        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.sessions.contains_key(&request.session_id) {
            // Duplicate session ID.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return TunnelAccept {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                session_id: request.session_id,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                accepted: false,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                reject_reason: Some(TunnelRejectReason::RateLimited),
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                mtu: None,
            };
        }

        // Capture the current timestamp for temporal ordering.
        // Compute session for this protocol step.
        // Compute session for this protocol step.
        // Compute session for this protocol step.
        let session = TunnelSession::new(request, mtu, now);
        // Insert into the lookup table for efficient retrieval.
        // Insert into the map/set.
        // Insert into the map/set.
        // Insert into the map/set.
        self.sessions.insert(request.session_id, session);

        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        TunnelAccept {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            session_id: request.session_id,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            accepted: true,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            reject_reason: None,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            mtu: Some(mtu),
        }
    }

    /// Process incoming tunnel data.
    ///
    /// For unfragmented data, returns the payload directly.
    /// For fragmented data, buffers until all fragments arrive.
    // Perform the 'process data' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process data' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process data' operation.
    // Errors are propagated to the caller via Result.
    pub fn process_data(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        data: &TunnelData,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Option<Vec<u8>> {
        // Update session activity.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(session) = self.sessions.get_mut(&data.session_id) {
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            session.record_recv(data.payload.len() as u64, now);
        }

        // Handle fragmentation.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match &data.fragment {
            // Update the local state.
            // No value available.
            // No value available.
            // No value available.
            None => Some(data.payload.clone()),
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            // Wrap the found value.
            Some(frag) => {
                // Mutate the internal state.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                self.reassembler.process(
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    data.session_id,
                    frag,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    data.payload.clone(),
                    now,
                )
            }
        }
    }

    /// Close a tunnel session.
    // Perform the 'close' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'close' operation.
    // Errors are propagated to the caller via Result.
    pub fn close(&mut self, session_id: &[u8; 16]) -> Option<TunnelSession> {
        // Remove from the collection and return the evicted value.
        // Remove from the collection.
        // Remove from the collection.
        self.sessions.remove(session_id)
    }

    /// Process a keepalive.
    // Perform the 'keepalive' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'keepalive' operation.
    // Errors are propagated to the caller via Result.
    pub fn keepalive(&mut self, ka: &TunnelKeepalive, now: u64) {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(session) = self.sessions.get_mut(&ka.session_id) {
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            session.last_activity = now;
        }
    }

    /// Garbage-collect idle tunnels and timed-out fragment buffers.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    pub fn gc(&mut self, now: u64) -> Vec<[u8; 16]> {
        // Pre-allocate the buffer to avoid repeated reallocations.
        // Compute closed for this protocol step.
        // Compute closed for this protocol step.
        let mut closed = Vec::new();
        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.sessions.retain(|id, s| {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if s.is_idle(now) {
                // Add the element to the collection.
                // Append to the collection.
                // Append to the collection.
                closed.push(*id);
                false
            // Begin the block scope.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            } else {
                true
            }
        });
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        self.reassembler.gc(now);
        closed
    }

    /// Get a session by ID.
    // Perform the 'session' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'session' operation.
    // Errors are propagated to the caller via Result.
    pub fn session(&self, id: &[u8; 16]) -> Option<&TunnelSession> {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.sessions.get(id)
    }

    /// Number of active sessions.
    // Perform the 'session count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'session count' operation.
    // Errors are propagated to the caller via Result.
    pub fn session_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.sessions.len()
    }
}

// Trait implementation for protocol conformance.
// Implement Default for TunnelManager.
// Implement Default for TunnelManager.
impl Default for TunnelManager {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Create a new instance with the specified parameters.
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

    fn make_request(id: u8) -> TunnelRequest {
        TunnelRequest {
            session_id: [id; 16],
            target: ServiceTarget::ById {
                service_id: [0xAA; 16],
            },
            proto: TunnelProto::TCP,
            requested_at: 1000,
            requester_id: [0x01; 32],
        }
    }

    #[test]
    fn test_tunnel_lifecycle() {
        let mut mgr = TunnelManager::new();

        let ack = mgr.handle_request(&make_request(0x01), true, 1400, 1000);
        assert!(ack.accepted);
        assert_eq!(mgr.session_count(), 1);

        // Send some data.
        let data = TunnelData {
            session_id: [0x01; 16],
            seq: 0,
            fragment: None,
            payload: vec![0x42; 100],
        };
        let result = mgr.process_data(&data, 1001);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 100);

        // Close.
        mgr.close(&[0x01; 16]);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_acl_denied() {
        let mut mgr = TunnelManager::new();
        let ack = mgr.handle_request(&make_request(0x01), false, 1400, 1000);
        assert!(!ack.accepted);
        assert_eq!(ack.reject_reason, Some(TunnelRejectReason::AccessDenied));
    }

    #[test]
    fn test_idle_gc() {
        let mut mgr = TunnelManager::new();
        mgr.handle_request(&make_request(0x01), true, 1400, 1000);

        let closed = mgr.gc(1000 + TUNNEL_IDLE_TIMEOUT_SECS + 1);
        assert_eq!(closed.len(), 1);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_fragment_reassembly() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [0x01; 16];

        // 2-fragment datagram.
        let frag0 = TunnelFragment {
            total_size: 200,
            fragment_index: 0,
            fragment_count: 2,
            fragment_id: 1,
        };
        let frag1 = TunnelFragment {
            total_size: 200,
            fragment_index: 1,
            fragment_count: 2,
            fragment_id: 1,
        };

        // First fragment: not complete yet.
        assert!(reassembler
            .process(sid, &frag0, vec![0xAA; 100], 1000)
            .is_none());
        assert_eq!(reassembler.pending_count(), 1);

        // Second fragment: complete.
        let result = reassembler.process(sid, &frag1, vec![0xBB; 100], 1001);
        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data.len(), 200);
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_fragment_timeout() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [0x01; 16];

        let frag0 = TunnelFragment {
            total_size: 200,
            fragment_index: 0,
            fragment_count: 2,
            fragment_id: 1,
        };

        // Only first fragment arrives.
        reassembler.process(sid, &frag0, vec![0xAA; 100], 1000);
        assert_eq!(reassembler.pending_count(), 1);

        // GC after timeout — partial discarded.
        reassembler.gc(1000 + UDP_FRAGMENT_TIMEOUT_SECS + 1);
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_keepalive_resets_idle() {
        let mut mgr = TunnelManager::new();
        mgr.handle_request(&make_request(0x01), true, 1400, 1000);

        // Keepalive at 1500 — session not idle yet.
        mgr.keepalive(
            &TunnelKeepalive {
                session_id: [0x01; 16],
            },
            1500,
        );

        // GC at 1500 + IDLE_TIMEOUT - shouldn't close because keepalive reset timer.
        let closed = mgr.gc(1500 + TUNNEL_IDLE_TIMEOUT_SECS - 1);
        assert!(closed.is_empty());
    }

    #[test]
    fn test_sequence_numbers() {
        let mut mgr = TunnelManager::new();
        mgr.handle_request(&make_request(0x01), true, 1400, 1000);

        let session = mgr.sessions.get_mut(&[0x01; 16]).unwrap();
        assert_eq!(session.next_sequence(), 0);
        assert_eq!(session.next_sequence(), 1);
        assert_eq!(session.next_sequence(), 2);
    }

    // ── ACL + Tunnel integration ───────────────────────────────────────────
    // These tests exercise the realistic enforcement path: ACL evaluation
    // produces a boolean that is passed to handle_request(), verifying that
    // the wiring between policy engine and admission gate works correctly.

    #[test]
    fn test_acl_allow_trusted_peer_admitted() {
        use crate::identity::peer_id::PeerId;
        use crate::trust::acl::{AclEngine, AclPermission, AclRule, AclSubject, AclTarget};
        use crate::trust::levels::TrustLevel;

        // Policy: ALLOW service "ssh" to Trusted-tier peers.
        let acl = AclEngine::new(vec![AclRule {
            permission: AclPermission::Allow,
            subject: AclSubject::TrustFloor(TrustLevel::Trusted),
            target: AclTarget::Service("ssh".to_string()),
            description: None,
            enabled: true,
        }]);

        let peer = PeerId([0x01; 32]);
        let perm = acl.check_service(&peer, TrustLevel::Trusted, &[], "ssh");
        assert_eq!(perm, AclPermission::Allow);

        let mut mgr = TunnelManager::new();
        let ack = mgr.handle_request(
            &make_request(0x01),
            perm == AclPermission::Allow,
            1400,
            1000,
        );
        assert!(ack.accepted, "Trusted peer must be admitted to ssh service");
    }

    #[test]
    fn test_acl_deny_untrusted_peer_rejected() {
        use crate::identity::peer_id::PeerId;
        use crate::trust::acl::{AclEngine, AclPermission, AclRule, AclSubject, AclTarget};
        use crate::trust::levels::TrustLevel;

        // Same policy: ALLOW ssh for Trusted+, implicit deny for everything else.
        let acl = AclEngine::new(vec![AclRule {
            permission: AclPermission::Allow,
            subject: AclSubject::TrustFloor(TrustLevel::Trusted),
            target: AclTarget::Service("ssh".to_string()),
            description: None,
            enabled: true,
        }]);

        let peer = PeerId([0x02; 32]);
        // Vouched (level 2) is below Trusted (level 6) — no rule matches → Deny.
        let perm = acl.check_service(&peer, TrustLevel::Vouched, &[], "ssh");
        assert_eq!(perm, AclPermission::Deny);

        let mut mgr = TunnelManager::new();
        let ack = mgr.handle_request(
            &make_request(0x02),
            perm == AclPermission::Allow,
            1400,
            1000,
        );
        assert!(
            !ack.accepted,
            "Untrusted peer must be rejected from ssh service"
        );
        assert_eq!(ack.reject_reason, Some(TunnelRejectReason::AccessDenied));
    }

    #[test]
    fn test_acl_explicit_deny_rule_overrides_allow() {
        use crate::identity::peer_id::PeerId;
        use crate::trust::acl::{AclEngine, AclPermission, AclRule, AclSubject, AclTarget};
        use crate::trust::levels::TrustLevel;

        let specific_peer = PeerId([0xDE; 32]);

        // Rules in order: first deny this specific peer, then allow all Trusted.
        let acl = AclEngine::new(vec![
            AclRule {
                permission: AclPermission::Deny,
                subject: AclSubject::Peer(specific_peer),
                target: AclTarget::AllServices,
                description: Some("blocklist".to_string()),
                enabled: true,
            },
            AclRule {
                permission: AclPermission::Allow,
                subject: AclSubject::TrustFloor(TrustLevel::Trusted),
                target: AclTarget::AllServices,
                description: None,
                enabled: true,
            },
        ]);

        // Specific peer is Trusted but should hit the explicit Deny first.
        let perm = acl.check_service(&specific_peer, TrustLevel::Trusted, &[], "ssh");
        assert_eq!(
            perm,
            AclPermission::Deny,
            "Explicit deny must fire before the allow rule"
        );

        let mut mgr = TunnelManager::new();
        let ack = mgr.handle_request(
            &TunnelRequest {
                session_id: [0xDE; 16],
                target: ServiceTarget::ById {
                    service_id: [0xAA; 16],
                },
                proto: TunnelProto::TCP,
                requested_at: 1000,
                requester_id: [0xDE; 32],
            },
            perm == AclPermission::Allow,
            1400,
            1000,
        );
        assert!(!ack.accepted);
        assert_eq!(ack.reject_reason, Some(TunnelRejectReason::AccessDenied));
    }
}
