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
pub const TUNNEL_IDLE_TIMEOUT_SECS: u64 = 600;

/// UDP fragment timeout (seconds).
/// If a fragment is missing for this long, discard the partial datagram.
pub const UDP_FRAGMENT_TIMEOUT_SECS: u64 = 5;

/// Maximum simultaneous tunnels per node.
pub const MAX_TUNNELS: usize = 256;

// ---------------------------------------------------------------------------
// Tunnel Protocol
// ---------------------------------------------------------------------------

/// Tunnel protocol type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelProto {
    TCP,
    UDP,
}

// ---------------------------------------------------------------------------
// Service Target
// ---------------------------------------------------------------------------

/// How a tunnel endpoint is addressed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServiceTarget {
    /// Address a service by device address and optional port.
    ByAddress {
        address: [u8; 32],
        port: Option<u32>,
    },
    /// Address a service by service ID.
    ById {
        service_id: [u8; 16],
    },
}

// ---------------------------------------------------------------------------
// Tunnel Messages
// ---------------------------------------------------------------------------

/// Request to establish a tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelRequest {
    pub session_id: [u8; 16],
    pub target: ServiceTarget,
    pub proto: TunnelProto,
    pub requested_at: u64,
    pub requester_id: [u8; 32],
}

/// Rejection reasons for a tunnel request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelRejectReason {
    AccessDenied,
    ServiceUnavailable,
    ProtocolUnsupported,
    RateLimited,
    Redirect {
        address: [u8; 32],
        port: Option<u32>,
    },
}

/// Response to a tunnel request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelAccept {
    pub session_id: [u8; 16],
    pub accepted: bool,
    pub reject_reason: Option<TunnelRejectReason>,
    pub mtu: Option<u16>,
}

/// Fragment metadata for large datagrams.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelFragment {
    pub total_size: u32,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub fragment_id: u16,
}

/// A data packet in an active tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelData {
    pub session_id: [u8; 16],
    pub seq: u64,
    pub fragment: Option<TunnelFragment>,
    pub payload: Vec<u8>,
}

/// Keepalive for an active tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelKeepalive {
    pub session_id: [u8; 16],
}

/// MTU update notification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelMTUUpdate {
    pub session_id: [u8; 16],
    pub new_mtu: u16,
}

/// Close a tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelClose {
    pub session_id: [u8; 16],
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Tunnel Session State
// ---------------------------------------------------------------------------

/// An active tunnel session.
#[derive(Clone, Debug)]
pub struct TunnelSession {
    pub session_id: [u8; 16],
    pub target: ServiceTarget,
    pub proto: TunnelProto,
    pub requester_id: [u8; 32],
    pub established_at: u64,
    pub last_activity: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub next_seq: u64,
    pub mtu: u16,
}

impl TunnelSession {
    /// Create a new tunnel session.
    pub fn new(
        request: &TunnelRequest,
        mtu: u16,
        now: u64,
    ) -> Self {
        Self {
            session_id: request.session_id,
            target: request.target.clone(),
            proto: request.proto,
            requester_id: request.requester_id,
            established_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            next_seq: 0,
            mtu,
        }
    }

    /// Whether the session has been idle too long.
    pub fn is_idle(&self, now: u64) -> bool {
        now.saturating_sub(self.last_activity) > TUNNEL_IDLE_TIMEOUT_SECS
    }

    /// Record sent data.
    pub fn record_send(&mut self, bytes: u64, now: u64) {
        self.bytes_sent += bytes;
        self.last_activity = now;
    }

    /// Record received data.
    pub fn record_recv(&mut self, bytes: u64, now: u64) {
        self.bytes_received += bytes;
        self.last_activity = now;
    }

    /// Get and increment the sequence number.
    pub fn next_sequence(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// Update the MTU.
    pub fn update_mtu(&mut self, new_mtu: u16) {
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
struct FragmentBuffer {
    /// Expected total fragments.
    fragment_count: u16,
    /// Total size declared.
    total_size: u32,
    /// Received fragments. Index → data.
    fragments: HashMap<u16, Vec<u8>>,
    /// When the first fragment arrived.
    started_at: u64,
}

/// UDP fragment reassembly engine.
pub struct FragmentReassembler {
    /// In-progress reassembly buffers. Key: (session_id, fragment_id).
    buffers: HashMap<([u8; 16], u16), FragmentBuffer>,
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
        }
    }

    /// Process an incoming fragment.
    ///
    /// Returns the reassembled datagram if all fragments have arrived,
    /// or None if more fragments are needed.
    pub fn process(
        &mut self,
        session_id: [u8; 16],
        fragment: &TunnelFragment,
        data: Vec<u8>,
        now: u64,
    ) -> Option<Vec<u8>> {
        let key = (session_id, fragment.fragment_id);

        let buf = self.buffers.entry(key).or_insert_with(|| FragmentBuffer {
            fragment_count: fragment.fragment_count,
            total_size: fragment.total_size,
            fragments: HashMap::new(),
            started_at: now,
        });

        buf.fragments.insert(fragment.fragment_index, data);

        // Check if all fragments have arrived.
        if buf.fragments.len() as u16 == buf.fragment_count {
            // Reassemble in order.
            let mut result = Vec::with_capacity(buf.total_size as usize);
            for i in 0..buf.fragment_count {
                if let Some(frag) = buf.fragments.get(&i) {
                    result.extend_from_slice(frag);
                }
            }
            self.buffers.remove(&key);
            Some(result)
        } else {
            None
        }
    }

    /// Remove timed-out partial reassembly buffers.
    pub fn gc(&mut self, now: u64) {
        self.buffers.retain(|_, buf| {
            now.saturating_sub(buf.started_at) <= UDP_FRAGMENT_TIMEOUT_SECS
        });
    }

    /// Number of in-progress reassemblies.
    pub fn pending_count(&self) -> usize {
        self.buffers.len()
    }
}

impl Default for FragmentReassembler {
    fn default() -> Self {
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
pub struct TunnelManager {
    /// Active sessions. Key: session_id.
    sessions: HashMap<[u8; 16], TunnelSession>,
    /// UDP fragment reassembly engine.
    pub reassembler: FragmentReassembler,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            reassembler: FragmentReassembler::new(),
        }
    }

    /// Handle a tunnel request. Returns a TunnelAccept.
    ///
    /// The caller is responsible for ACL checks before calling this.
    /// `acl_allowed`: whether the ACL engine approved this request.
    /// `mtu`: negotiated MTU for this tunnel.
    pub fn handle_request(
        &mut self,
        request: &TunnelRequest,
        acl_allowed: bool,
        mtu: u16,
        now: u64,
    ) -> TunnelAccept {
        if !acl_allowed {
            return TunnelAccept {
                session_id: request.session_id,
                accepted: false,
                reject_reason: Some(TunnelRejectReason::AccessDenied),
                mtu: None,
            };
        }

        if self.sessions.len() >= MAX_TUNNELS {
            return TunnelAccept {
                session_id: request.session_id,
                accepted: false,
                reject_reason: Some(TunnelRejectReason::RateLimited),
                mtu: None,
            };
        }

        if self.sessions.contains_key(&request.session_id) {
            // Duplicate session ID.
            return TunnelAccept {
                session_id: request.session_id,
                accepted: false,
                reject_reason: Some(TunnelRejectReason::RateLimited),
                mtu: None,
            };
        }

        let session = TunnelSession::new(request, mtu, now);
        self.sessions.insert(request.session_id, session);

        TunnelAccept {
            session_id: request.session_id,
            accepted: true,
            reject_reason: None,
            mtu: Some(mtu),
        }
    }

    /// Process incoming tunnel data.
    ///
    /// For unfragmented data, returns the payload directly.
    /// For fragmented data, buffers until all fragments arrive.
    pub fn process_data(
        &mut self,
        data: &TunnelData,
        now: u64,
    ) -> Option<Vec<u8>> {
        // Update session activity.
        if let Some(session) = self.sessions.get_mut(&data.session_id) {
            session.record_recv(data.payload.len() as u64, now);
        }

        // Handle fragmentation.
        match &data.fragment {
            None => Some(data.payload.clone()),
            Some(frag) => {
                self.reassembler.process(
                    data.session_id,
                    frag,
                    data.payload.clone(),
                    now,
                )
            }
        }
    }

    /// Close a tunnel session.
    pub fn close(&mut self, session_id: &[u8; 16]) -> Option<TunnelSession> {
        self.sessions.remove(session_id)
    }

    /// Process a keepalive.
    pub fn keepalive(&mut self, ka: &TunnelKeepalive, now: u64) {
        if let Some(session) = self.sessions.get_mut(&ka.session_id) {
            session.last_activity = now;
        }
    }

    /// Garbage-collect idle tunnels and timed-out fragment buffers.
    pub fn gc(&mut self, now: u64) -> Vec<[u8; 16]> {
        let mut closed = Vec::new();
        self.sessions.retain(|id, s| {
            if s.is_idle(now) {
                closed.push(*id);
                false
            } else {
                true
            }
        });
        self.reassembler.gc(now);
        closed
    }

    /// Get a session by ID.
    pub fn session(&self, id: &[u8; 16]) -> Option<&TunnelSession> {
        self.sessions.get(id)
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for TunnelManager {
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

    fn make_request(id: u8) -> TunnelRequest {
        TunnelRequest {
            session_id: [id; 16],
            target: ServiceTarget::ById { service_id: [0xAA; 16] },
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
        assert!(reassembler.process(sid, &frag0, vec![0xAA; 100], 1000).is_none());
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
        mgr.keepalive(&TunnelKeepalive { session_id: [0x01; 16] }, 1500);

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
        assert!(!ack.accepted, "Untrusted peer must be rejected from ssh service");
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
        assert_eq!(perm, AclPermission::Deny, "Explicit deny must fire before the allow rule");

        let mut mgr = TunnelManager::new();
        let ack = mgr.handle_request(
            &TunnelRequest {
                session_id: [0xDE; 16],
                target: ServiceTarget::ById { service_id: [0xAA; 16] },
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
