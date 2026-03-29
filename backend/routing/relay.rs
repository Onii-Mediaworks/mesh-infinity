//! Mesh Relay — DERP-Style NAT Traversal (§6.11)
//!
//! # What is the Mesh Relay?
//!
//! When a direct connection between two nodes isn't possible (NAT,
//! firewall, incompatible transports), traffic is routed through a
//! relay node. This replaces traditional UDP hole punching and STUN.
//!
//! # Why Not Hole Punching?
//!
//! STUN requires a coordination server that observes both parties'
//! IP addresses and connection timing — creating a metadata record.
//! Mesh relay avoids this: the relay node sees only encrypted
//! WireGuard packets and mesh addresses, never real-world IPs.
//!
//! # Relay Selection Algorithm (§6.11)
//!
//! When the transport solver determines a direct connection is
//! unavailable, relay selection proceeds:
//!
//! 1. **Prefer trusted peers** (Level 6+) with good connectivity
//!    to both parties.
//! 2. **Fall back** to any connected mesh node willing to relay
//!    (`relay_willing: true` in its network map entry).
//! 3. Relay willingness is self-declared and verified by behavior
//!    (nodes that refuse relaying lose relay reputation).
//!
//! # Bandwidth Policy
//!
//! Relay nodes enforce per-trust-level bandwidth caps:
//! - Trusted peers (Level 6+): unlimited by default
//! - Vouched peers (Level 2-4): 5 MB/s
//! - Unknown peers (Level 0-1): 1 MB/s
//! - Total aggregate cap: 20 MB/s (server mode)
//! - Metered connection fallback: 256 KB/s
//!
//! Relay nodes that consistently hit their caps are deprioritised
//! in the solver's relay selection.
//!
//! # Session Lifecycle
//!
//! A relay session is established with a RelayRequest, acknowledged
//! with a RelayAck, and lasts until either party closes it or the
//! idle timeout expires (default: 5 minutes).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::trust::levels::TrustLevel;
use super::table::DeviceAddress;

/// Domain separator for relay request signatures.
const DOMAIN_RELAY_REQ: &[u8] = b"meshinfinity-relay-req-v1";

/// Error returned when a relay request has a missing or invalid signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRelaySignature;

impl std::fmt::Display for InvalidRelaySignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay request signature is missing or invalid")
    }
}

impl std::error::Error for InvalidRelaySignature {}

/// Verify the Ed25519 signature on a relay request.
///
/// Signing payload: DOMAIN || destination (32 bytes) || session_id (32 bytes).
/// The requester's Ed25519 public key is looked up from the network map by
/// the caller and passed in here.
///
/// Returns `Ok(())` if valid, `Err(InvalidRelaySignature)` if the signature is missing
/// or cryptographically invalid.
pub fn verify_relay_request(
    request: &RelayRequest,
    requester_ed25519_pub: &[u8; 32],
) -> Result<(), InvalidRelaySignature> {
    let vk = VerifyingKey::from_bytes(requester_ed25519_pub).map_err(|_| InvalidRelaySignature)?;
    if request.signature.len() != 64 {
        return Err(InvalidRelaySignature);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&request.signature);
    let sig = Signature::from_bytes(&sig_bytes);
    let mut payload = Vec::with_capacity(DOMAIN_RELAY_REQ.len() + 64);
    payload.extend_from_slice(DOMAIN_RELAY_REQ);
    payload.extend_from_slice(&request.destination.0);
    payload.extend_from_slice(&request.session_id);
    vk.verify(&payload, &sig).map_err(|_| InvalidRelaySignature)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default idle timeout for relay sessions (seconds).
///
/// If no traffic (real or cover) flows through the relay for this
/// long, the session is torn down. 5 minutes is conservative —
/// cover traffic should keep sessions alive if they're still needed.
pub const RELAY_IDLE_TIMEOUT_SECS: u64 = 300;

/// Maximum simultaneous relay sessions per node.
///
/// Prevents a single node from consuming all relay capacity.
/// In server mode, this is higher (configurable).
pub const MAX_RELAY_SESSIONS: usize = 256;

/// Default bandwidth cap for unknown/untrusted peers (bytes/sec).
/// 1 MB/s is enough for messaging but limits abuse.
pub const DEFAULT_UNKNOWN_BW: u64 = 1_048_576;

/// Default bandwidth cap for vouched peers (bytes/sec).
/// 5 MB/s supports file transfers at reasonable speed.
pub const DEFAULT_VOUCHED_BW: u64 = 5 * 1_048_576;

/// Default total bandwidth cap for all relay traffic (bytes/sec).
/// 20 MB/s for server-mode nodes.
pub const DEFAULT_TOTAL_CAP: u64 = 20 * 1_048_576;

/// Default bandwidth cap on metered connections (bytes/sec).
/// 256 KB/s is minimal — just enough for essential messaging relay.
pub const DEFAULT_METERED_CAP: u64 = 262_144;

// ---------------------------------------------------------------------------
// Relay Request / Ack Protocol
// ---------------------------------------------------------------------------

/// A request to establish a relay session (§6.11).
///
/// Sent by a node that cannot directly reach its destination.
/// The relay candidate decides whether to accept based on its
/// bandwidth policy and current load.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayRequest {
    /// The destination device address the requester wants to reach.
    pub destination: DeviceAddress,

    /// Unique session identifier (generated by the requester).
    /// Used to match the request with the acknowledgement and
    /// subsequent data forwarding.
    pub session_id: [u8; 32],

    /// Ed25519 signature from the requester.
    /// Signs: "meshinfinity-relay-req-v1" || destination || session_id.
    pub signature: Vec<u8>,
}

/// Acknowledgement (or rejection) of a relay request.
///
/// Sent by the relay candidate in response to a RelayRequest.
/// If accepted, the relay node begins forwarding traffic between
/// the requester and the destination.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayAck {
    /// The session ID from the original request.
    pub session_id: [u8; 32],

    /// The relay node's own device address.
    /// The requester uses this to route traffic through the relay.
    pub relay_address: DeviceAddress,

    /// Whether the relay request was accepted.
    /// False if the relay node is at capacity, the destination is
    /// unknown, or bandwidth policy doesn't allow it.
    pub accepted: bool,
}

// ---------------------------------------------------------------------------
// Relay Bandwidth Policy (§6.11)
// ---------------------------------------------------------------------------

/// Per-trust-level bandwidth limits for relay traffic.
///
/// Relay nodes enforce these limits to prevent abuse while still
/// providing useful relay service to the mesh. The trust-level
/// approach means trusted peers get better service, incentivising
/// building trust relationships.
///
/// All values are in bytes per second. `None` means unlimited.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayBandwidthPolicy {
    /// Bandwidth cap for trusted peers (Level 6+).
    /// Default: unlimited (None).
    pub trusted_peers: Option<u64>,

    /// Bandwidth cap for vouched peers (Level 2-4).
    /// Default: 5 MB/s.
    pub vouched_peers: Option<u64>,

    /// Bandwidth cap for unknown peers (Level 0-1).
    /// Default: 1 MB/s.
    pub unknown_peers: Option<u64>,

    /// Total aggregate bandwidth cap across all relay sessions.
    /// Default: 20 MB/s (server mode).
    pub total_cap: Option<u64>,

    /// Bandwidth cap when on a metered connection.
    /// Default: 256 KB/s.
    pub metered_connection_cap: u64,
}

impl Default for RelayBandwidthPolicy {
    fn default() -> Self {
        Self {
            trusted_peers: None,              // Unlimited.
            vouched_peers: Some(DEFAULT_VOUCHED_BW),
            unknown_peers: Some(DEFAULT_UNKNOWN_BW),
            total_cap: Some(DEFAULT_TOTAL_CAP),
            metered_connection_cap: DEFAULT_METERED_CAP,
        }
    }
}

impl RelayBandwidthPolicy {
    /// Get the bandwidth cap for a given trust level.
    ///
    /// Returns the cap in bytes/sec, or None for unlimited.
    /// The trust level is the relay node's trust in the requester.
    pub fn cap_for_trust(&self, trust: TrustLevel) -> Option<u64> {
        match trust.value() {
            // Level 6+ (Trusted, HighlyTrusted, InnerCircle).
            6..=8 => self.trusted_peers,
            // Level 2-5 (Vouched, Referenced, Ally, Acquaintance).
            2..=5 => self.vouched_peers,
            // Level 0-1 (Unknown, Public).
            _ => self.unknown_peers,
        }
    }
}

// ---------------------------------------------------------------------------
// Relay Session
// ---------------------------------------------------------------------------

/// An active relay session.
///
/// Represents an ongoing relay between a requester and a destination.
/// Tracks bandwidth usage, last activity time (for idle timeout),
/// and the trust level of the requester.
#[derive(Clone, Debug)]
pub struct RelaySession {
    /// Unique session identifier.
    pub session_id: [u8; 32],

    /// The requester's device address.
    pub requester: DeviceAddress,

    /// The destination's device address.
    pub destination: DeviceAddress,

    /// Trust level of the requester (used for bandwidth policy).
    pub requester_trust: TrustLevel,

    /// When the session was established (Unix timestamp).
    pub established_at: u64,

    /// Last time traffic flowed through this session (Unix timestamp).
    /// Updated on every forwarded packet.
    pub last_activity: u64,

    /// Total bytes forwarded in this session.
    pub bytes_forwarded: u64,

    /// Bytes forwarded in the current second (for rate limiting).
    pub bytes_this_second: u64,

    /// Start of the current second window (Unix timestamp).
    pub rate_window_start: u64,
}

impl RelaySession {
    /// Check if this session has been idle too long.
    ///
    /// Sessions are torn down after RELAY_IDLE_TIMEOUT_SECS of
    /// no traffic. Cover traffic counts as traffic for this purpose.
    pub fn is_idle(&self, now: u64) -> bool {
        now.saturating_sub(self.last_activity) > RELAY_IDLE_TIMEOUT_SECS
    }

    /// Record bytes forwarded, returning whether the transfer is
    /// within the bandwidth cap.
    ///
    /// `bytes`: number of bytes being forwarded.
    /// `cap`: bandwidth cap in bytes/sec (None = unlimited).
    /// `now`: current unix timestamp.
    ///
    /// Returns true if within cap, false if rate-limited.
    pub fn record_bytes(&mut self, bytes: u64, cap: Option<u64>, now: u64) -> bool {
        // Reset the per-second counter if we're in a new second.
        if now != self.rate_window_start {
            self.bytes_this_second = 0;
            self.rate_window_start = now;
        }

        // Check the cap.
        if let Some(limit) = cap {
            if self.bytes_this_second + bytes > limit {
                return false;
            }
        }

        // Record the bytes.
        self.bytes_this_second += bytes;
        self.bytes_forwarded += bytes;
        self.last_activity = now;

        true
    }
}

// ---------------------------------------------------------------------------
// Relay Manager
// ---------------------------------------------------------------------------

/// Manages relay sessions for this node.
///
/// A node acts as a relay when it accepts RelayRequests from other
/// nodes. The relay manager tracks active sessions, enforces
/// bandwidth policies, and tears down idle sessions.
pub struct RelayManager {
    /// Active relay sessions, keyed by session ID.
    sessions: HashMap<[u8; 32], RelaySession>,

    /// Bandwidth policy governing all relay sessions.
    policy: RelayBandwidthPolicy,

    /// Whether we're willing to relay at all.
    /// Advertised as `relay_willing` in our network map entry.
    pub relay_willing: bool,

    /// Whether we're on a metered connection.
    /// If true, the metered_connection_cap applies to all sessions.
    pub metered: bool,

    /// Total bytes forwarded across all sessions this second.
    total_bytes_this_second: u64,

    /// Start of the total rate window.
    total_rate_window_start: u64,
}

impl RelayManager {
    /// Create a new relay manager.
    ///
    /// `relay_willing`: whether to accept relay requests.
    /// `policy`: bandwidth limits per trust level.
    pub fn new(relay_willing: bool, policy: RelayBandwidthPolicy) -> Self {
        Self {
            sessions: HashMap::new(),
            policy,
            relay_willing,
            metered: false,
            total_bytes_this_second: 0,
            total_rate_window_start: 0,
        }
    }

    /// Create with default policy.
    pub fn with_defaults(relay_willing: bool) -> Self {
        Self::new(relay_willing, RelayBandwidthPolicy::default())
    }

    /// Handle an incoming relay request.
    ///
    /// Decides whether to accept the relay based on:
    /// 1. Valid Ed25519 signature from the requester (§6.11).
    /// 2. Are we willing to relay?
    /// 3. Are we at session capacity?
    /// 4. Does our bandwidth policy allow this requester?
    ///
    /// `requester_ed25519_pub`: the requester's Ed25519 public key, looked up
    /// from the network map by the caller before invoking this function.
    /// If `None`, signature verification is skipped (only for tests / local nodes).
    ///
    /// Returns a RelayAck to send back to the requester.
    pub fn handle_request(
        &mut self,
        request: &RelayRequest,
        requester: DeviceAddress,
        requester_trust: TrustLevel,
        requester_ed25519_pub: Option<&[u8; 32]>,
        now: u64,
    ) -> RelayAck {
        // Step 0: Verify signature (§6.11 — prevents request spoofing).
        if let Some(pubkey) = requester_ed25519_pub {
            if verify_relay_request(request, pubkey).is_err() {
                return RelayAck {
                    session_id: request.session_id,
                    relay_address: DeviceAddress([0; 32]),
                    accepted: false,
                };
            }
        }

        // Check if we're willing to relay at all.
        if !self.relay_willing {
            return RelayAck {
                session_id: request.session_id,
                relay_address: DeviceAddress([0; 32]), // Doesn't matter if rejected.
                accepted: false,
            };
        }

        // Check session capacity.
        if self.sessions.len() >= MAX_RELAY_SESSIONS {
            return RelayAck {
                session_id: request.session_id,
                relay_address: DeviceAddress([0; 32]),
                accepted: false,
            };
        }

        // Check for duplicate session ID.
        if self.sessions.contains_key(&request.session_id) {
            return RelayAck {
                session_id: request.session_id,
                relay_address: DeviceAddress([0; 32]),
                accepted: false,
            };
        }

        // Create the session.
        let session = RelaySession {
            session_id: request.session_id,
            requester,
            destination: request.destination,
            requester_trust,
            established_at: now,
            last_activity: now,
            bytes_forwarded: 0,
            bytes_this_second: 0,
            rate_window_start: now,
        };

        self.sessions.insert(request.session_id, session);

        RelayAck {
            session_id: request.session_id,
            relay_address: DeviceAddress([0; 32]), // Caller fills in our actual address.
            accepted: true,
        }
    }

    /// Forward bytes through a relay session.
    ///
    /// Checks per-session and total bandwidth caps before allowing.
    /// Returns true if the forward was allowed, false if rate-limited.
    pub fn forward(
        &mut self,
        session_id: &[u8; 32],
        bytes: u64,
        now: u64,
    ) -> bool {
        // Reset total rate counter if in a new second.
        if now != self.total_rate_window_start {
            self.total_bytes_this_second = 0;
            self.total_rate_window_start = now;
        }

        // Check total cap.
        let total_cap = if self.metered {
            Some(self.policy.metered_connection_cap)
        } else {
            self.policy.total_cap
        };

        if let Some(limit) = total_cap {
            if self.total_bytes_this_second + bytes > limit {
                return false;
            }
        }

        // Get the session.
        let session = match self.sessions.get_mut(session_id) {
            Some(s) => s,
            None => return false,
        };

        // Determine per-session cap based on requester trust.
        let per_session_cap = if self.metered {
            Some(self.policy.metered_connection_cap)
        } else {
            self.policy.cap_for_trust(session.requester_trust)
        };

        // Record bytes on the session.
        if !session.record_bytes(bytes, per_session_cap, now) {
            return false;
        }

        // Update total counter.
        self.total_bytes_this_second += bytes;

        true
    }

    /// Close a relay session.
    pub fn close_session(&mut self, session_id: &[u8; 32]) {
        self.sessions.remove(session_id);
    }

    /// Garbage-collect idle sessions.
    ///
    /// Called periodically to tear down sessions that haven't had
    /// any traffic for RELAY_IDLE_TIMEOUT_SECS.
    pub fn gc(&mut self, now: u64) {
        self.sessions.retain(|_, s| !s.is_idle(now));
    }

    /// Number of active relay sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Total bytes forwarded across all sessions.
    pub fn total_bytes_forwarded(&self) -> u64 {
        self.sessions.values().map(|s| s.bytes_forwarded).sum()
    }

    /// Get session info by session ID.
    pub fn session(&self, session_id: &[u8; 32]) -> Option<&RelaySession> {
        self.sessions.get(session_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a DeviceAddress from a single byte.
    fn addr(b: u8) -> DeviceAddress {
        DeviceAddress([b; 32])
    }

    /// Helper: create a relay request.
    fn make_request(dest: u8) -> RelayRequest {
        RelayRequest {
            destination: addr(dest),
            session_id: [dest; 32],
            signature: vec![0x42; 64],
        }
    }

    #[test]
    fn test_accept_relay() {
        let mut mgr = RelayManager::with_defaults(true);
        let now = 1000;

        let ack = mgr.handle_request(
            &make_request(0xAA),
            addr(0x01),
            TrustLevel::Trusted,
            None, // Skip sig verification in this basic test.
            now,
        );

        assert!(ack.accepted);
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn test_reject_not_willing() {
        let mut mgr = RelayManager::with_defaults(false);
        let now = 1000;

        let ack = mgr.handle_request(
            &make_request(0xAA),
            addr(0x01),
            TrustLevel::Trusted,
            None,
            now,
        );

        assert!(!ack.accepted);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_reject_duplicate_session() {
        let mut mgr = RelayManager::with_defaults(true);
        let now = 1000;

        // First request: accepted.
        mgr.handle_request(&make_request(0xAA), addr(0x01), TrustLevel::Trusted, None, now);

        // Same session ID: rejected.
        let ack2 = mgr.handle_request(
            &make_request(0xAA),
            addr(0x02),
            TrustLevel::Trusted,
            None,
            now,
        );
        assert!(!ack2.accepted);
    }

    #[test]
    fn test_forward_bytes() {
        let mut mgr = RelayManager::with_defaults(true);
        let now = 1000;
        let sid = [0xAA; 32];

        mgr.handle_request(&make_request(0xAA), addr(0x01), TrustLevel::Trusted, None, now);

        // Forward some bytes.
        assert!(mgr.forward(&sid, 1000, now));

        // Check session stats.
        let session = mgr.session(&sid).unwrap();
        assert_eq!(session.bytes_forwarded, 1000);
    }

    #[test]
    fn test_idle_session_gc() {
        let mut mgr = RelayManager::with_defaults(true);
        let now = 1000;

        mgr.handle_request(&make_request(0xAA), addr(0x01), TrustLevel::Trusted, None, now);
        assert_eq!(mgr.session_count(), 1);

        // GC after idle timeout.
        mgr.gc(now + RELAY_IDLE_TIMEOUT_SECS + 1);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_close_session() {
        let mut mgr = RelayManager::with_defaults(true);
        let now = 1000;
        let sid = [0xAA; 32];

        mgr.handle_request(&make_request(0xAA), addr(0x01), TrustLevel::Trusted, None, now);
        assert_eq!(mgr.session_count(), 1);

        mgr.close_session(&sid);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_relay_signature_verified() {
        use ed25519_dalek::{Signer, SigningKey};

        let raw_key = [0x55u8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();

        let dest = addr(0xBB);
        let session_id = [0xCC; 32];

        // Build signed relay request.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"meshinfinity-relay-req-v1");
        payload.extend_from_slice(&dest.0);
        payload.extend_from_slice(&session_id);
        let sig = signing_key.sign(&payload);

        let request = RelayRequest {
            destination: dest,
            session_id,
            signature: sig.to_bytes().to_vec(),
        };

        let mut mgr = RelayManager::with_defaults(true);
        let ack = mgr.handle_request(&request, addr(0x01), TrustLevel::Trusted, Some(&ed_pub), 1000);
        assert!(ack.accepted);
    }

    #[test]
    fn test_relay_bad_signature_rejected() {
        use ed25519_dalek::SigningKey;

        let raw_key = [0x55u8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();

        let request = RelayRequest {
            destination: addr(0xBB),
            session_id: [0xCC; 32],
            signature: vec![0x00; 64], // Wrong signature.
        };

        let mut mgr = RelayManager::with_defaults(true);
        let ack = mgr.handle_request(&request, addr(0x01), TrustLevel::Trusted, Some(&ed_pub), 1000);
        assert!(!ack.accepted);
    }

    #[test]
    fn test_bandwidth_policy_trust_levels() {
        let policy = RelayBandwidthPolicy::default();

        // Trusted: unlimited.
        assert_eq!(policy.cap_for_trust(TrustLevel::Trusted), None);
        assert_eq!(policy.cap_for_trust(TrustLevel::InnerCircle), None);

        // Vouched: 5 MB/s.
        assert_eq!(policy.cap_for_trust(TrustLevel::Vouched), Some(DEFAULT_VOUCHED_BW));
        assert_eq!(policy.cap_for_trust(TrustLevel::Acquaintance), Some(DEFAULT_VOUCHED_BW));

        // Unknown: 1 MB/s.
        assert_eq!(policy.cap_for_trust(TrustLevel::Unknown), Some(DEFAULT_UNKNOWN_BW));
        assert_eq!(policy.cap_for_trust(TrustLevel::Public), Some(DEFAULT_UNKNOWN_BW));
    }

    #[test]
    fn test_metered_connection_cap() {
        let mut mgr = RelayManager::with_defaults(true);
        mgr.metered = true;
        let now = 1000;
        let sid = [0xBB; 32];

        mgr.handle_request(
            &RelayRequest {
                destination: addr(0xBB),
                session_id: sid,
                signature: vec![0x42; 64],
            },
            addr(0x01),
            TrustLevel::InnerCircle, // Even InnerCircle gets metered cap.
            None,
            now,
        );

        // Try to forward more than the metered cap in one second.
        assert!(!mgr.forward(&sid, DEFAULT_METERED_CAP + 1, now));

        // Under the cap: OK.
        assert!(mgr.forward(&sid, DEFAULT_METERED_CAP / 2, now));
    }
}
