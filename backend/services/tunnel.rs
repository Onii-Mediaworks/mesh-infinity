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
//! # Fragmentation and reassembly limits
//!
//! Payloads larger than the negotiated MTU are split into TunnelFragment
//! pieces that share a `fragment_id`. Reassembly is never an unbounded
//! allocation promise: every fragment header is validated before any byte
//! is retained, each session has an in-flight set cap and a byte budget,
//! the global table is capped, and stale sets are evicted (30 s for TCP,
//! 5 s for UDP). Rejections carry a typed [`TunnelError`] so the caller can
//! account abuse (§12.3 "Reassembly and backpressure limits").

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default idle timeout for tunnels (seconds).
/// Idle = no application connections, not just no traffic.
// Protocol constant defined by the spec (§12.3 session lifecycle step 4);
// must not change without a version bump.
pub const TUNNEL_IDLE_TIMEOUT_SECS: u64 = 600;

/// UDP fragment timeout (seconds).
/// If a fragment is missing for this long, discard the partial datagram.
// Protocol constant defined by the spec (§12.3 "Fragmentation");
// must not change without a version bump.
pub const UDP_FRAGMENT_TIMEOUT_SECS: u64 = 5;

/// TCP fragment timeout (seconds).
/// TCP tunnels tolerate a longer stall because the stream is reliable and
/// the sender will retransmit; the spec fixes this at 30 seconds.
// Protocol constant defined by the spec (§12.3 "Slow-reader protection");
// must not change without a version bump.
pub const TCP_FRAGMENT_TIMEOUT_SECS: u64 = 30;

/// Maximum simultaneous tunnels per node.
// Protocol constant defined by the spec; must not change without a
// version bump.
pub const MAX_TUNNELS: usize = 256;

/// Conservative default MTU used when `TunnelAccept.mtu` is `None`.
/// `None` means "use the default", never "unconstrained" (§12.3).
// Protocol constant defined by the spec (§12.3 "Reassembly and
// backpressure limits"); must not change without a version bump.
pub const DEFAULT_TUNNEL_MTU: u16 = 1200;

/// Default maximum reassembled payload size (1 MiB) when the accept
/// message carries no explicit `max_reassembly_bytes`.
// Protocol constant defined by the spec (§12.3); must not change without
// a version bump.
pub const DEFAULT_MAX_REASSEMBLY_BYTES: u32 = 1 << 20;

/// Hard ceiling (16 MiB) on `max_reassembly_bytes` for generic tunnels.
/// A peer advertising more than this without an application-specific
/// authenticated policy is rejected at limit resolution time.
// Protocol constant defined by the spec (§12.3); must not change without
// a version bump.
pub const MAX_REASSEMBLY_BYTES_CEILING: u32 = 16 << 20;

/// Default number of incomplete logical payloads a session may hold.
// Protocol constant defined by the spec (§12.3); must not change without
// a version bump.
pub const DEFAULT_MAX_INFLIGHT_REASSEMBLIES: u16 = 32;

/// Total reassembly memory budget per tunnel session (4 MiB).
/// Counts retained payload bytes plus a fixed per-slot overhead so an
/// attacker cannot hide behind thousands of one-byte fragments.
// Protocol constant defined by the spec (§12.3); must not change without
// a version bump.
pub const REASSEMBLY_BUDGET_BYTES: usize = 4 << 20;

/// Global cap on in-progress reassembly sets across all sessions.
/// Equal to the session cap times the default per-session in-flight cap, so
/// the table can never grow past what the spec defaults already allow.
// Derived bound: MAX_TUNNELS * DEFAULT_MAX_INFLIGHT_REASSEMBLIES.
pub const MAX_REASSEMBLY_BUFFERS_TOTAL: usize =
    MAX_TUNNELS * DEFAULT_MAX_INFLIGHT_REASSEMBLIES as usize;

/// Bytes charged to the session budget for each retained fragment on top of
/// its payload length. Approximates the map slot, key and Vec header so the
/// budget reflects real memory rather than only payload bytes.
const FRAGMENT_SLOT_OVERHEAD: usize = 64;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a tunnel operation was refused.
///
/// Every variant is plain data. Variants where `is_abuse()` is true are the
/// spec's MUST-reject fragment conditions and the caller should count them
/// against the peer's abuse score; the remaining variants are resource or
/// state outcomes that a well-behaved peer can also trigger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TunnelError {
    /// Data arrived for a session id that is not open.
    #[error("unknown tunnel session")]
    UnknownSession,
    /// `fragment_count == 0` (§12.3 MUST reject).
    #[error("fragment_count is zero")]
    ZeroFragmentCount,
    /// `fragment_index >= fragment_count` (§12.3 MUST reject).
    #[error("fragment_index {index} is not below fragment_count {count}")]
    IndexOutOfRange {
        /// The offending index.
        index: u16,
        /// The declared fragment count.
        count: u16,
    },
    /// `total_size > max_reassembly_bytes` (§12.3 MUST reject).
    #[error("total_size {total_size} exceeds max_reassembly_bytes {limit}")]
    TotalSizeTooLarge {
        /// The declared logical payload size.
        total_size: u32,
        /// The negotiated ceiling.
        limit: u32,
    },
    /// A fragment payload exceeds the negotiated MTU (§12.3 MUST reject).
    #[error("payload of {len} bytes exceeds mtu {mtu}")]
    PayloadExceedsMtu {
        /// The payload length received.
        len: usize,
        /// The negotiated MTU.
        mtu: u16,
    },
    /// A fragment carried no bytes; a sender never produces one, and
    /// accepting it would let a peer fill the index table for free.
    #[error("empty fragment payload")]
    EmptyFragment,
    /// More fragments were declared than there are bytes to carry.
    #[error("fragment_count {count} exceeds total_size {total_size}")]
    CountExceedsTotal {
        /// The declared fragment count.
        count: u16,
        /// The declared logical payload size.
        total_size: u32,
    },
    /// A later fragment disagreed with the first on `total_size` or
    /// `fragment_count` (§12.3 MUST reject). The whole set is dropped.
    #[error("fragment header disagrees with the first fragment of the set")]
    HeaderMismatch,
    /// The same index arrived twice with identical bytes. Not abuse (a UDP
    /// retransmit looks like this); the copy is ignored and the timeout is
    /// not extended.
    #[error("duplicate fragment")]
    DuplicateFragment,
    /// The same index arrived twice with different bytes. The set is
    /// contradictory and is dropped.
    #[error("overlapping fragment with different bytes")]
    OverlappingFragment,
    /// Held bytes plus this fragment exceed the declared `total_size`.
    #[error("fragments exceed declared total_size")]
    TotalSizeExceeded,
    /// All fragments arrived but their lengths do not sum to `total_size`.
    #[error("reassembled {got} bytes but total_size declared {total_size}")]
    TotalSizeMismatch {
        /// Bytes actually held.
        got: usize,
        /// Bytes the header promised.
        total_size: u32,
    },
    /// The session already holds `max_inflight_reassemblies` open sets.
    #[error("too many in-flight reassemblies for this session")]
    InflightLimit,
    /// Retaining this fragment would exceed the per-session byte budget.
    #[error("per-session reassembly budget exhausted")]
    BudgetExceeded,
    /// The global reassembly table is full.
    #[error("global reassembly table full")]
    TableFull,
    /// The sender's sequence space is exhausted.
    #[error("tunnel sequence space exhausted")]
    SeqExhausted,
    /// A negotiated limit is zero or above the spec ceiling.
    #[error("invalid negotiated tunnel limits")]
    InvalidLimits,
}

impl TunnelError {
    /// Whether this rejection is one the spec says to account as abuse.
    ///
    /// Resource outcomes (`InflightLimit`, `BudgetExceeded`, `TableFull`),
    /// benign duplicates, unknown sessions and local configuration errors
    /// are not abuse: a correct peer can hit them too.
    pub fn is_abuse(&self) -> bool {
        // Enumerate explicitly so adding a variant forces a decision here.
        match self {
            Self::ZeroFragmentCount
            | Self::IndexOutOfRange { .. }
            | Self::TotalSizeTooLarge { .. }
            | Self::PayloadExceedsMtu { .. }
            | Self::EmptyFragment
            | Self::CountExceedsTotal { .. }
            | Self::HeaderMismatch
            | Self::OverlappingFragment
            | Self::TotalSizeExceeded
            | Self::TotalSizeMismatch { .. } => true,
            Self::UnknownSession
            | Self::DuplicateFragment
            | Self::InflightLimit
            | Self::BudgetExceeded
            | Self::TableFull
            | Self::SeqExhausted
            | Self::InvalidLimits => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tunnel Protocol
// ---------------------------------------------------------------------------

/// Tunnel protocol type. One tunnel carries exactly one protocol.
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
    ById { service_id: [u8; 16] },
}

// ---------------------------------------------------------------------------
// Tunnel Messages
// ---------------------------------------------------------------------------

/// Request to establish a tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelRequest {
    /// Random id identifying this tunnel session.
    pub session_id: [u8; 16],
    /// What we are connecting to.
    pub target: ServiceTarget,
    /// TCP or UDP; one tunnel carries one protocol.
    pub proto: TunnelProto,
    /// Unix seconds when the request was made.
    pub requested_at: u64,
    /// Mesh peer id of the requester (§3).
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
///
/// The three `Option` limits follow the spec rule that `None` means "the
/// conservative default", never "unbounded"; see [`ReassemblyLimits`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelAccept {
    /// Echo of the request's session id.
    pub session_id: [u8; 16],
    /// Whether the tunnel was admitted.
    pub accepted: bool,
    /// Why not, when `accepted == false`.
    pub reject_reason: Option<TunnelRejectReason>,
    /// Maximum TunnelData payload bytes for this path segment.
    pub mtu: Option<u16>,
    /// Maximum logical payload size accepted after reassembly.
    pub max_reassembly_bytes: Option<u32>,
    /// Maximum incomplete logical payloads per session.
    pub max_inflight_reassemblies: Option<u16>,
}

/// Fragment metadata for large payloads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelFragment {
    /// Total reassembled payload size in bytes.
    pub total_size: u32,
    /// 0-based index of this fragment.
    pub fragment_index: u16,
    /// Total number of fragments in the set.
    pub fragment_count: u16,
    /// Groups fragments of one logical payload; wraps at `u16::MAX`.
    pub fragment_id: u16,
}

/// A data packet in an active tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelData {
    /// The session this frame belongs to.
    pub session_id: [u8; 16],
    /// Monotonically increasing per session. `u128` so multi-year tunnels
    /// never wrap; serde encodes it compactly when the upper bytes are zero.
    pub seq: u128,
    /// `None` = unfragmented; `Some` = one piece of a fragmented payload.
    pub fragment: Option<TunnelFragment>,
    /// Raw payload bytes, bounded by the negotiated MTU.
    pub payload: Vec<u8>,
}

/// Keepalive for an active tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelKeepalive {
    /// The session whose idle timer is reset.
    pub session_id: [u8; 16],
}

/// MTU update notification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelMTUUpdate {
    /// The session whose path MTU changed.
    pub session_id: [u8; 16],
    /// The sender must not exceed this from now on.
    pub new_mtu: u16,
}

/// Close a tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelClose {
    /// The session being closed.
    pub session_id: [u8; 16],
    /// Optional human-readable reason.
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Negotiated limits
// ---------------------------------------------------------------------------

/// The host's negotiable reassembly values, mirroring `TunnelAccept`.
///
/// `None` resolves to the spec default. Validation happens in
/// [`ReassemblyLimits::resolve`], so a policy is only ever data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TunnelPolicy {
    /// Path MTU to advertise; `None` = `DEFAULT_TUNNEL_MTU`.
    pub mtu: Option<u16>,
    /// Reassembly ceiling; `None` = `DEFAULT_MAX_REASSEMBLY_BYTES`.
    pub max_reassembly_bytes: Option<u32>,
    /// In-flight set cap; `None` = `DEFAULT_MAX_INFLIGHT_REASSEMBLIES`.
    pub max_inflight_reassemblies: Option<u16>,
}

/// Validated, fully-resolved reassembly limits for one session.
///
/// Fields are private so a value can only exist after validation: no zero
/// MTU, no zero ceilings, and no `max_reassembly_bytes` above the 16 MiB
/// spec ceiling. The timeout is derived from the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReassemblyLimits {
    /// Maximum bytes in one TunnelData payload.
    mtu: u16,
    /// Maximum reassembled logical payload size.
    max_reassembly_bytes: u32,
    /// Maximum incomplete sets held at once for the session.
    max_inflight_reassemblies: u16,
    /// Seconds a partial set may wait for its missing pieces.
    timeout_secs: u64,
}

impl ReassemblyLimits {
    /// Resolve a policy (ours, or a peer's accept) into validated limits.
    ///
    /// Peer-supplied values reach this function through
    /// [`ReassemblyLimits::from_accept`], so every bound check here is a
    /// wire-boundary check as well as a configuration check.
    pub fn resolve(proto: TunnelProto, policy: &TunnelPolicy) -> Result<Self, TunnelError> {
        // `None` is the conservative default, never "unbounded".
        let mtu = policy.mtu.unwrap_or(DEFAULT_TUNNEL_MTU);
        let max_reassembly_bytes = policy
            .max_reassembly_bytes
            .unwrap_or(DEFAULT_MAX_REASSEMBLY_BYTES);
        let max_inflight_reassemblies = policy
            .max_inflight_reassemblies
            .unwrap_or(DEFAULT_MAX_INFLIGHT_REASSEMBLIES);
        // A zero MTU or zero cap would reject every frame; above the spec
        // ceiling is a resource promise generic tunnels must not make.
        if mtu == 0 || max_inflight_reassemblies == 0 {
            return Err(TunnelError::InvalidLimits);
        }
        if max_reassembly_bytes == 0 || max_reassembly_bytes > MAX_REASSEMBLY_BYTES_CEILING {
            return Err(TunnelError::InvalidLimits);
        }
        // TCP streams are reliable and retransmit, so they get the longer
        // stall allowance; UDP partial datagrams are simply dropped sooner.
        let timeout_secs = match proto {
            TunnelProto::TCP => TCP_FRAGMENT_TIMEOUT_SECS,
            TunnelProto::UDP => UDP_FRAGMENT_TIMEOUT_SECS,
        };
        Ok(Self {
            mtu,
            max_reassembly_bytes,
            max_inflight_reassemblies,
            timeout_secs,
        })
    }

    /// Resolve the limits a peer advertised in its `TunnelAccept`.
    pub fn from_accept(accept: &TunnelAccept, proto: TunnelProto) -> Result<Self, TunnelError> {
        // The accept's three options are exactly a policy; validate them
        // the same way we validate our own configuration.
        Self::resolve(
            proto,
            &TunnelPolicy {
                mtu: accept.mtu,
                max_reassembly_bytes: accept.max_reassembly_bytes,
                max_inflight_reassemblies: accept.max_inflight_reassemblies,
            },
        )
    }

    /// Maximum bytes in one TunnelData payload.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Maximum reassembled logical payload size.
    pub fn max_reassembly_bytes(&self) -> u32 {
        self.max_reassembly_bytes
    }

    /// Maximum incomplete sets held at once.
    pub fn max_inflight_reassemblies(&self) -> u16 {
        self.max_inflight_reassemblies
    }

    /// Seconds a partial set may wait before eviction.
    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    /// Apply a `TunnelMTUUpdate`. A zero MTU is refused.
    pub fn set_mtu(&mut self, new_mtu: u16) -> Result<(), TunnelError> {
        if new_mtu == 0 {
            return Err(TunnelError::InvalidLimits);
        }
        self.mtu = new_mtu;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tunnel Session State
// ---------------------------------------------------------------------------

/// An active tunnel session.
#[derive(Clone, Debug)]
pub struct TunnelSession {
    /// Random id shared with the peer.
    pub session_id: [u8; 16],
    /// What this tunnel connects to.
    pub target: ServiceTarget,
    /// TCP or UDP.
    pub proto: TunnelProto,
    /// Mesh peer id of the requester.
    pub requester_id: [u8; 32],
    /// Unix seconds when the session was admitted.
    pub established_at: u64,
    /// Unix seconds of the last data or keepalive.
    pub last_activity: u64,
    /// Bytes sent on this session.
    pub bytes_sent: u64,
    /// Bytes received on this session.
    pub bytes_received: u64,
    /// Next outbound sequence number (`u128`, see `TunnelData::seq`).
    pub next_seq: u128,
    /// Validated reassembly limits in force for this session.
    pub limits: ReassemblyLimits,
}

impl TunnelSession {
    /// Create a new tunnel session.
    pub fn new(request: &TunnelRequest, limits: ReassemblyLimits, now: u64) -> Self {
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
            limits,
        }
    }

    /// Whether the session has been idle too long.
    pub fn is_idle(&self, now: u64) -> bool {
        // Saturate so a clock that moves backwards never underflows.
        now.saturating_sub(self.last_activity) > TUNNEL_IDLE_TIMEOUT_SECS
    }

    /// Record sent data.
    pub fn record_send(&mut self, bytes: u64, now: u64) {
        // Counters saturate rather than wrap: a statistic must never panic
        // or turn negative because a tunnel outlived expectations.
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
        self.last_activity = now;
    }

    /// Record received data.
    pub fn record_recv(&mut self, bytes: u64, now: u64) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
        self.last_activity = now;
    }

    /// Take the next outbound sequence number.
    ///
    /// Returns `SeqExhausted` instead of wrapping: a wrapped sequence would
    /// look like a replay to the receiver, so the tunnel must close instead.
    pub fn next_sequence(&mut self) -> Result<u128, TunnelError> {
        // Reserve the successor first so the state is untouched on failure.
        let next = self
            .next_seq
            .checked_add(1)
            .ok_or(TunnelError::SeqExhausted)?;
        let seq = self.next_seq;
        self.next_seq = next;
        Ok(seq)
    }

    /// Current MTU.
    pub fn mtu(&self) -> u16 {
        self.limits.mtu()
    }

    /// Apply a `TunnelMTUUpdate`.
    pub fn update_mtu(&mut self, new_mtu: u16) -> Result<(), TunnelError> {
        self.limits.set_mtu(new_mtu)
    }
}

// ---------------------------------------------------------------------------
// Fragment Reassembler
// ---------------------------------------------------------------------------

/// One in-progress logical payload.
#[derive(Debug)]
struct FragmentBuffer {
    /// Fragment count declared by the first fragment of the set.
    fragment_count: u16,
    /// Total size declared by the first fragment of the set.
    total_size: u32,
    /// Received fragments, index -> bytes. Indices are < `fragment_count`.
    fragments: HashMap<u16, Vec<u8>>,
    /// Sum of held payload lengths; always <= `total_size`.
    received_bytes: usize,
    /// Bytes charged against the session budget for this set.
    charged_bytes: usize,
    /// When the first fragment arrived. Duplicates never move this.
    started_at: u64,
    /// Protocol-specific stall allowance captured at creation.
    timeout_secs: u64,
}

impl FragmentBuffer {
    /// Whether this partial set has waited past its allowance.
    fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.started_at) > self.timeout_secs
    }
}

/// Per-session accounting so limits are O(1) to check.
#[derive(Debug, Default)]
struct SessionAccount {
    /// Open reassembly sets for the session.
    inflight: usize,
    /// Bytes (payload + slot overhead) retained for the session.
    charged_bytes: usize,
}

/// Key of one reassembly set: the session and its per-payload id.
type SetKey = ([u8; 16], u16);

/// Fragment reassembly engine with spec-mandated bounds.
///
/// Tracks incoming fragments and produces complete payloads. Partial sets
/// are evicted after the protocol timeout, when the owning session closes,
/// or when a limit check needs the room they are wasting.
pub struct FragmentReassembler {
    /// In-progress sets keyed by `(session_id, fragment_id)`.
    buffers: HashMap<SetKey, FragmentBuffer>,
    /// In-flight count and byte charge per session.
    accounts: HashMap<[u8; 16], SessionAccount>,
}

/// Stateless header checks that must pass before any byte is retained.
///
/// These are the §12.3 MUST-reject conditions plus two derived ones (empty
/// fragments, more fragments than bytes) that close the index-table gap.
fn validate_fragment(
    fragment: &TunnelFragment,
    len: usize,
    limits: &ReassemblyLimits,
) -> Result<(), TunnelError> {
    if fragment.fragment_count == 0 {
        return Err(TunnelError::ZeroFragmentCount);
    }
    if fragment.fragment_index >= fragment.fragment_count {
        return Err(TunnelError::IndexOutOfRange {
            index: fragment.fragment_index,
            count: fragment.fragment_count,
        });
    }
    if fragment.total_size > limits.max_reassembly_bytes() {
        return Err(TunnelError::TotalSizeTooLarge {
            total_size: fragment.total_size,
            limit: limits.max_reassembly_bytes(),
        });
    }
    // Every fragment carries at least one byte, so the count can never
    // exceed the size; this also rejects `total_size == 0`.
    if u32::from(fragment.fragment_count) > fragment.total_size {
        return Err(TunnelError::CountExceedsTotal {
            count: fragment.fragment_count,
            total_size: fragment.total_size,
        });
    }
    if len > usize::from(limits.mtu()) {
        return Err(TunnelError::PayloadExceedsMtu {
            len,
            mtu: limits.mtu(),
        });
    }
    if len == 0 {
        return Err(TunnelError::EmptyFragment);
    }
    // `total_size` is at most 16 MiB here, so the widening cast is exact.
    if len > fragment.total_size as usize {
        return Err(TunnelError::TotalSizeExceeded);
    }
    Ok(())
}

/// Consistency checks of a fragment against the set it joins.
///
/// `DuplicateFragment` leaves the set intact; every other error means the
/// caller drops the whole set because it is contradictory.
fn check_existing(
    buf: &FragmentBuffer,
    fragment: &TunnelFragment,
    data: &[u8],
) -> Result<(), TunnelError> {
    // Repeated fragments for one (session_id, fragment_id) must agree.
    if buf.fragment_count != fragment.fragment_count || buf.total_size != fragment.total_size {
        return Err(TunnelError::HeaderMismatch);
    }
    // Same index twice: identical bytes is a retransmit, different bytes
    // is a contradiction.
    if let Some(held) = buf.fragments.get(&fragment.fragment_index) {
        if held.as_slice() == data {
            return Err(TunnelError::DuplicateFragment);
        }
        return Err(TunnelError::OverlappingFragment);
    }
    // Keep the running sum inside the declared size before retaining.
    if buf.received_bytes.saturating_add(data.len()) > buf.total_size as usize {
        return Err(TunnelError::TotalSizeExceeded);
    }
    Ok(())
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
            accounts: HashMap::new(),
        }
    }

    /// Process an incoming fragment.
    ///
    /// Returns `Ok(Some(payload))` once every fragment of the set has
    /// arrived, `Ok(None)` while more are needed, and a typed error when the
    /// fragment is rejected. Nothing is retained for a rejected fragment,
    /// and no allocation is sized from a peer-supplied number.
    pub fn process(
        &mut self,
        session_id: [u8; 16],
        fragment: &TunnelFragment,
        data: Vec<u8>,
        limits: &ReassemblyLimits,
        now: u64,
    ) -> Result<Option<Vec<u8>>, TunnelError> {
        // Header validity first: nothing below runs for a malformed frame.
        validate_fragment(fragment, data.len(), limits)?;
        let key: SetKey = (session_id, fragment.fragment_id);
        // What this fragment will cost the session if retained.
        let charge = data.len().saturating_add(FRAGMENT_SLOT_OVERHEAD);

        // Decide what to do with the existing set, if any, without holding
        // the borrow across the mutations below.
        let existing = self
            .buffers
            .get(&key)
            .map(|buf| check_existing(buf, fragment, &data));
        match existing {
            None => {
                // A new set must fit the in-flight and global caps.
                self.admit_new_set(session_id, limits, now)?;
                self.buffers.insert(
                    key,
                    FragmentBuffer {
                        fragment_count: fragment.fragment_count,
                        total_size: fragment.total_size,
                        fragments: HashMap::new(),
                        received_bytes: 0,
                        charged_bytes: 0,
                        started_at: now,
                        timeout_secs: limits.timeout_secs(),
                    },
                );
                self.accounts.entry(session_id).or_default().inflight += 1;
            }
            Some(Ok(())) => {}
            // A benign retransmit: ignore the copy, keep the set and its
            // original deadline.
            Some(Err(TunnelError::DuplicateFragment)) => {
                return Err(TunnelError::DuplicateFragment);
            }
            // Contradictory set: drop everything held for it.
            Some(Err(err)) => {
                self.drop_set(&key);
                return Err(err);
            }
        }

        // Charge the byte budget; evict the session's stale sets first.
        if !self.reserve(session_id, charge, now) {
            // Do not leave an empty set behind on a budget refusal.
            let empty = self
                .buffers
                .get(&key)
                .is_some_and(|buf| buf.fragments.is_empty());
            if empty {
                self.drop_set(&key);
            }
            return Err(TunnelError::BudgetExceeded);
        }

        let Some(buf) = self.buffers.get_mut(&key) else {
            // Unreachable in practice (inserted or found above); typed
            // rather than a panic path per the byte-boundary rule.
            return Err(TunnelError::UnknownSession);
        };
        buf.received_bytes = buf.received_bytes.saturating_add(data.len());
        buf.charged_bytes = buf.charged_bytes.saturating_add(charge);
        buf.fragments.insert(fragment.fragment_index, data);

        // Indices are unique and below the count, so count reached means
        // every index 0..count is present.
        if buf.fragments.len() < usize::from(buf.fragment_count) {
            return Ok(None);
        }
        let total_size = buf.total_size;
        let got = buf.received_bytes;
        if got != total_size as usize {
            // Complete but short of the promise: the header lied.
            self.drop_set(&key);
            return Err(TunnelError::TotalSizeMismatch { got, total_size });
        }
        // Capacity comes from bytes we already hold, never from the peer's
        // header; `got` was bounded by `max_reassembly_bytes` above.
        let mut out = Vec::with_capacity(got);
        for index in 0..buf.fragment_count {
            if let Some(part) = buf.fragments.get(&index) {
                out.extend_from_slice(part);
            }
        }
        self.drop_set(&key);
        Ok(Some(out))
    }

    /// Check the per-session in-flight cap and the global table cap for a
    /// new set, evicting stale sets before refusing.
    fn admit_new_set(
        &mut self,
        session_id: [u8; 16],
        limits: &ReassemblyLimits,
        now: u64,
    ) -> Result<(), TunnelError> {
        let cap = usize::from(limits.max_inflight_reassemblies());
        if self.session_inflight(&session_id) >= cap {
            // The peer's own expired sets should not block its fresh ones.
            self.evict_expired_for(&session_id, now);
            if self.session_inflight(&session_id) >= cap {
                return Err(TunnelError::InflightLimit);
            }
        }
        if self.buffers.len() >= MAX_REASSEMBLY_BUFFERS_TOTAL {
            self.gc(now);
            if self.buffers.len() >= MAX_REASSEMBLY_BUFFERS_TOTAL {
                return Err(TunnelError::TableFull);
            }
        }
        Ok(())
    }

    /// Charge `charge` bytes to the session budget if it fits, evicting the
    /// session's stale sets first. Returns false when it does not fit.
    fn reserve(&mut self, session_id: [u8; 16], charge: usize, now: u64) -> bool {
        if self.session_bytes_held(&session_id).saturating_add(charge) > REASSEMBLY_BUDGET_BYTES {
            self.evict_expired_for(&session_id, now);
            if self.session_bytes_held(&session_id).saturating_add(charge)
                > REASSEMBLY_BUDGET_BYTES
            {
                return false;
            }
        }
        let account = self.accounts.entry(session_id).or_default();
        account.charged_bytes = account.charged_bytes.saturating_add(charge);
        true
    }

    /// Remove one set and return its charge to the session account.
    fn drop_set(&mut self, key: &SetKey) {
        let Some(buf) = self.buffers.remove(key) else {
            return;
        };
        // Update the account in its own scope so the borrow ends before the
        // possible removal of the account entry.
        let account_empty = match self.accounts.get_mut(&key.0) {
            Some(account) => {
                account.inflight = account.inflight.saturating_sub(1);
                account.charged_bytes = account.charged_bytes.saturating_sub(buf.charged_bytes);
                account.inflight == 0
            }
            None => false,
        };
        if account_empty {
            self.accounts.remove(&key.0);
        }
    }

    /// Evict every expired set belonging to one session.
    fn evict_expired_for(&mut self, session_id: &[u8; 16], now: u64) {
        let expired: Vec<SetKey> = self
            .buffers
            .iter()
            .filter(|(key, buf)| key.0 == *session_id && buf.is_expired(now))
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.drop_set(&key);
        }
    }

    /// Remove timed-out partial sets across all sessions, each judged by
    /// the timeout of its own protocol.
    pub fn gc(&mut self, now: u64) {
        let expired: Vec<SetKey> = self
            .buffers
            .iter()
            .filter(|(_, buf)| buf.is_expired(now))
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.drop_set(&key);
        }
    }

    /// Drop every set a session holds; called when the session closes so
    /// a closed tunnel can never pin reassembly memory.
    pub fn clear_session(&mut self, session_id: &[u8; 16]) {
        let keys: Vec<SetKey> = self
            .buffers
            .keys()
            .filter(|key| key.0 == *session_id)
            .copied()
            .collect();
        for key in keys {
            self.drop_set(&key);
        }
    }

    /// Number of in-progress sets across all sessions.
    pub fn pending_count(&self) -> usize {
        self.buffers.len()
    }

    /// Number of in-progress sets for one session.
    pub fn session_inflight(&self, session_id: &[u8; 16]) -> usize {
        self.accounts
            .get(session_id)
            .map_or(0, |account| account.inflight)
    }

    /// Bytes currently charged to one session's budget.
    pub fn session_bytes_held(&self, session_id: &[u8; 16]) -> usize {
        self.accounts
            .get(session_id)
            .map_or(0, |account| account.charged_bytes)
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
    /// Fragment reassembly engine shared by all sessions.
    pub reassembler: FragmentReassembler,
}

/// Build a non-accepting `TunnelAccept` with no limits advertised.
fn reject_accept(session_id: [u8; 16], reason: TunnelRejectReason) -> TunnelAccept {
    TunnelAccept {
        session_id,
        accepted: false,
        reject_reason: Some(reason),
        mtu: None,
        max_reassembly_bytes: None,
        max_inflight_reassemblies: None,
    }
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            reassembler: FragmentReassembler::new(),
        }
    }

    /// Handle a tunnel request. Returns the `TunnelAccept` to send back.
    ///
    /// The caller is responsible for ACL checks before calling this.
    /// `acl_allowed`: whether the ACL engine approved this request.
    /// `policy`: the host's negotiable limits (`None` fields = defaults).
    /// `Err` only reports an invalid local policy; peer-facing outcomes are
    /// carried inside the returned accept.
    pub fn handle_request(
        &mut self,
        request: &TunnelRequest,
        acl_allowed: bool,
        policy: &TunnelPolicy,
        now: u64,
    ) -> Result<TunnelAccept, TunnelError> {
        if !acl_allowed {
            return Ok(reject_accept(
                request.session_id,
                TunnelRejectReason::AccessDenied,
            ));
        }
        // Resource exhaustion and duplicate ids both surface as the coarse
        // RateLimited outcome so the peer learns nothing about our tables.
        if self.sessions.len() >= MAX_TUNNELS || self.sessions.contains_key(&request.session_id)
        {
            return Ok(reject_accept(
                request.session_id,
                TunnelRejectReason::RateLimited,
            ));
        }
        // Resolve and validate the limits this session will enforce.
        let limits = ReassemblyLimits::resolve(request.proto, policy)?;
        let session = TunnelSession::new(request, limits, now);
        self.sessions.insert(request.session_id, session);
        // Advertise the resolved values explicitly rather than echoing
        // `None`, so both sides enforce the same numbers.
        Ok(TunnelAccept {
            session_id: request.session_id,
            accepted: true,
            reject_reason: None,
            mtu: Some(limits.mtu()),
            max_reassembly_bytes: Some(limits.max_reassembly_bytes()),
            max_inflight_reassemblies: Some(limits.max_inflight_reassemblies()),
        })
    }

    /// Process incoming tunnel data.
    ///
    /// For unfragmented data, returns the payload directly. For fragmented
    /// data, buffers until all fragments arrive. Frames for unknown
    /// sessions and payloads above the session MTU are rejected before any
    /// byte is retained.
    pub fn process_data(
        &mut self,
        data: &TunnelData,
        now: u64,
    ) -> Result<Option<Vec<u8>>, TunnelError> {
        let session = self
            .sessions
            .get_mut(&data.session_id)
            .ok_or(TunnelError::UnknownSession)?;
        // Copy the limits out so the session borrow ends before the
        // reassembler is touched.
        let limits = session.limits;
        // The MTU bound applies to every frame, fragmented or not.
        if data.payload.len() > usize::from(limits.mtu()) {
            return Err(TunnelError::PayloadExceedsMtu {
                len: data.payload.len(),
                mtu: limits.mtu(),
            });
        }
        session.record_recv(data.payload.len() as u64, now);

        match &data.fragment {
            None => Ok(Some(data.payload.clone())),
            Some(fragment) => self.reassembler.process(
                data.session_id,
                fragment,
                data.payload.clone(),
                &limits,
                now,
            ),
        }
    }

    /// Close a tunnel session and release its reassembly memory.
    pub fn close(&mut self, session_id: &[u8; 16]) -> Option<TunnelSession> {
        self.reassembler.clear_session(session_id);
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
        self.sessions.retain(|id, session| {
            if session.is_idle(now) {
                closed.push(*id);
                false
            } else {
                true
            }
        });
        // A closed session must not keep partial sets alive.
        for id in &closed {
            self.reassembler.clear_session(id);
        }
        self.reassembler.gc(now);
        closed
    }

    /// Get a session by ID.
    pub fn session(&self, id: &[u8; 16]) -> Option<&TunnelSession> {
        self.sessions.get(id)
    }

    /// Get a mutable session by ID (sender-side sequence and MTU updates).
    pub fn session_mut(&mut self, id: &[u8; 16]) -> Option<&mut TunnelSession> {
        self.sessions.get_mut(id)
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
// Fuzz / corpus driver
// ---------------------------------------------------------------------------

/// Outcome tallies from [`drive_fragment_input`].
#[cfg(any(test, feature = "fuzzing"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FragmentDriveReport {
    /// Complete payloads handed to the application.
    pub delivered: usize,
    /// Frames rejected for any reason.
    pub rejected: usize,
    /// Rejections the spec counts as abuse.
    pub abuse: usize,
    /// False if any bound was observed violated after a step.
    pub invariants_ok: bool,
}

/// Number of decoded steps per driver run; bounds fuzz execution time.
#[cfg(any(test, feature = "fuzzing"))]
const DRIVE_STEPS: usize = 48;

/// Upper bound (exclusive) on decoded payload lengths, chosen above the
/// default MTU so the fuzzer can exercise the MTU rejection.
#[cfg(any(test, feature = "fuzzing"))]
const DRIVE_PAYLOAD_MODULUS: u16 = 1400;

/// Decode arbitrary bytes into a bounded tunnel action sequence and run it
/// through a `TunnelManager`, checking the reassembly bounds after every
/// step. Shared by the `fuzz_tunnel_fragment` harness and the in-tree
/// corpus replay test so committed seeds are decoded by exactly one layout.
///
/// Layout: the whole input is first tried as a JSON `TunnelData` frame,
/// then read as a step list. Each step starts with an opcode byte
/// (`op % 7`): 0 stop; 1 fragment on the open session; 2 fragment on an
/// unknown session; 3 unfragmented frame; 4 advance the clock by one byte
/// of seconds; 5 gc; 6 close and reopen the session. A fragment step reads
/// `total_size` (u32 LE), `fragment_index`, `fragment_count`, `fragment_id`,
/// payload length (u16 LE each) and one fill byte; an unfragmented step
/// reads only the length and fill byte.
#[cfg(any(test, feature = "fuzzing"))]
pub fn drive_fragment_input(data: &[u8]) -> FragmentDriveReport {
    use crate::testing::arbitrary::ByteCursor;

    /// The one session the driver keeps open.
    const OPEN: [u8; 16] = [0x01; 16];
    /// A session id that is never opened.
    const UNKNOWN: [u8; 16] = [0x02; 16];

    fn take_u16(cursor: &mut ByteCursor<'_>) -> u16 {
        u16::from_le_bytes([cursor.take_u8(), cursor.take_u8()])
    }

    fn take_u32(cursor: &mut ByteCursor<'_>) -> u32 {
        u32::from_le_bytes([
            cursor.take_u8(),
            cursor.take_u8(),
            cursor.take_u8(),
            cursor.take_u8(),
        ])
    }

    /// Payload of a decoded length (below the modulus) and a fill byte.
    fn take_payload(cursor: &mut ByteCursor<'_>) -> Vec<u8> {
        let len = take_u16(cursor) % DRIVE_PAYLOAD_MODULUS;
        let fill = cursor.take_u8();
        vec![fill; usize::from(len)]
    }

    fn open_session(mgr: &mut TunnelManager, now: u64) -> bool {
        let request = TunnelRequest {
            session_id: OPEN,
            target: ServiceTarget::ById {
                service_id: [0xAA; 16],
            },
            proto: TunnelProto::TCP,
            requested_at: now,
            requester_id: [0x01; 32],
        };
        matches!(
            mgr.handle_request(&request, true, &TunnelPolicy::default(), now),
            Ok(accept) if accept.accepted
        )
    }

    /// Tally one frame outcome and check the delivered-size invariant.
    fn tally(
        report: &mut FragmentDriveReport,
        frame: &TunnelData,
        outcome: Result<Option<Vec<u8>>, TunnelError>,
    ) {
        match outcome {
            Ok(Some(payload)) => {
                report.delivered += 1;
                // A delivered payload can never exceed the ceiling, and a
                // reassembled one must be exactly what the header declared.
                if payload.len() > DEFAULT_MAX_REASSEMBLY_BYTES as usize {
                    report.invariants_ok = false;
                }
                if let Some(fragment) = &frame.fragment {
                    if payload.len() != fragment.total_size as usize {
                        report.invariants_ok = false;
                    }
                }
            }
            Ok(None) => {}
            Err(err) => {
                report.rejected += 1;
                if err.is_abuse() {
                    report.abuse += 1;
                }
            }
        }
    }

    /// Bounds that must hold after every step.
    fn bounds_hold(mgr: &TunnelManager) -> bool {
        mgr.session_count() <= 1
            && mgr.reassembler.pending_count() <= usize::from(DEFAULT_MAX_INFLIGHT_REASSEMBLIES)
            && mgr.reassembler.session_bytes_held(&OPEN) <= REASSEMBLY_BUDGET_BYTES
    }

    let mut report = FragmentDriveReport {
        invariants_ok: true,
        ..FragmentDriveReport::default()
    };
    let mut mgr = TunnelManager::new();
    let mut now: u64 = 1_000;
    if !open_session(&mut mgr, now) {
        report.invariants_ok = false;
        return report;
    }

    // The serde decoder is itself a byte boundary: feed the raw input
    // through it before the structured walk.
    if let Ok(frame) = serde_json::from_slice::<TunnelData>(data) {
        let outcome = mgr.process_data(&frame, now);
        tally(&mut report, &frame, outcome);
    }

    let mut cursor = ByteCursor::new(data);
    for _ in 0..DRIVE_STEPS {
        match cursor.take_u8() % 7 {
            0 => break,
            op @ (1 | 2) => {
                let fragment = TunnelFragment {
                    total_size: take_u32(&mut cursor),
                    fragment_index: take_u16(&mut cursor),
                    fragment_count: take_u16(&mut cursor),
                    fragment_id: take_u16(&mut cursor),
                };
                let frame = TunnelData {
                    session_id: if op == 1 { OPEN } else { UNKNOWN },
                    seq: 0,
                    fragment: Some(fragment),
                    payload: take_payload(&mut cursor),
                };
                let outcome = mgr.process_data(&frame, now);
                tally(&mut report, &frame, outcome);
            }
            3 => {
                let frame = TunnelData {
                    session_id: OPEN,
                    seq: 0,
                    fragment: None,
                    payload: take_payload(&mut cursor),
                };
                let outcome = mgr.process_data(&frame, now);
                tally(&mut report, &frame, outcome);
            }
            4 => now = now.saturating_add(u64::from(cursor.take_u8())),
            5 => {
                mgr.gc(now);
            }
            _ => {
                mgr.close(&OPEN);
                if !open_session(&mut mgr, now) {
                    report.invariants_ok = false;
                }
            }
        }
        if !bounds_hold(&mgr) {
            report.invariants_ok = false;
        }
    }
    report
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

    fn policy(mtu: u16) -> TunnelPolicy {
        TunnelPolicy {
            mtu: Some(mtu),
            ..TunnelPolicy::default()
        }
    }

    fn limits(proto: TunnelProto) -> ReassemblyLimits {
        ReassemblyLimits::resolve(proto, &TunnelPolicy::default()).unwrap()
    }

    fn frag(total_size: u32, index: u16, count: u16, id: u16) -> TunnelFragment {
        TunnelFragment {
            total_size,
            fragment_index: index,
            fragment_count: count,
            fragment_id: id,
        }
    }

    #[test]
    fn test_tunnel_lifecycle() {
        let mut mgr = TunnelManager::new();

        let ack = mgr
            .handle_request(&make_request(0x01), true, &policy(1400), 1000)
            .unwrap();
        assert!(ack.accepted);
        assert_eq!(ack.mtu, Some(1400));
        assert_eq!(ack.max_reassembly_bytes, Some(DEFAULT_MAX_REASSEMBLY_BYTES));
        assert_eq!(
            ack.max_inflight_reassemblies,
            Some(DEFAULT_MAX_INFLIGHT_REASSEMBLIES)
        );
        assert_eq!(mgr.session_count(), 1);

        let data = TunnelData {
            session_id: [0x01; 16],
            seq: 0,
            fragment: None,
            payload: vec![0x42; 100],
        };
        let result = mgr.process_data(&data, 1001).unwrap();
        assert_eq!(result.map(|p| p.len()), Some(100));

        mgr.close(&[0x01; 16]);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_acl_denied() {
        let mut mgr = TunnelManager::new();
        let ack = mgr
            .handle_request(&make_request(0x01), false, &policy(1400), 1000)
            .unwrap();
        assert!(!ack.accepted);
        assert_eq!(ack.reject_reason, Some(TunnelRejectReason::AccessDenied));
        assert_eq!(ack.max_reassembly_bytes, None);
    }

    #[test]
    fn test_idle_gc() {
        let mut mgr = TunnelManager::new();
        mgr.handle_request(&make_request(0x01), true, &policy(1400), 1000)
            .unwrap();

        let closed = mgr.gc(1000 + TUNNEL_IDLE_TIMEOUT_SECS + 1);
        assert_eq!(closed.len(), 1);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_fragment_reassembly() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [0x01; 16];
        let lim = limits(TunnelProto::UDP);

        // First fragment: not complete yet.
        assert_eq!(
            reassembler.process(sid, &frag(200, 0, 2, 1), vec![0xAA; 100], &lim, 1000),
            Ok(None)
        );
        assert_eq!(reassembler.pending_count(), 1);
        assert_eq!(reassembler.session_inflight(&sid), 1);
        assert_eq!(
            reassembler.session_bytes_held(&sid),
            100 + FRAGMENT_SLOT_OVERHEAD
        );

        // Second fragment: complete, in index order, accounting released.
        let data = reassembler
            .process(sid, &frag(200, 1, 2, 1), vec![0xBB; 100], &lim, 1001)
            .unwrap()
            .unwrap();
        assert_eq!(data.len(), 200);
        assert_eq!(&data[..100], &[0xAA; 100]);
        assert_eq!(&data[100..], &[0xBB; 100]);
        assert_eq!(reassembler.pending_count(), 0);
        assert_eq!(reassembler.session_inflight(&sid), 0);
        assert_eq!(reassembler.session_bytes_held(&sid), 0);
    }

    #[test]
    fn test_out_of_order_fragments_reassemble_in_index_order() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [0x01; 16];
        let lim = limits(TunnelProto::UDP);
        assert_eq!(
            reassembler.process(sid, &frag(3, 2, 3, 7), vec![3], &lim, 1000),
            Ok(None)
        );
        assert_eq!(
            reassembler.process(sid, &frag(3, 0, 3, 7), vec![1], &lim, 1000),
            Ok(None)
        );
        assert_eq!(
            reassembler.process(sid, &frag(3, 1, 3, 7), vec![2], &lim, 1000),
            Ok(Some(vec![1, 2, 3]))
        );
    }

    #[test]
    fn test_fragment_count_zero_rejected() {
        let mut reassembler = FragmentReassembler::new();
        let lim = limits(TunnelProto::UDP);
        let err = reassembler
            .process([1; 16], &frag(200, 0, 0, 1), vec![0xAA; 100], &lim, 1000)
            .unwrap_err();
        assert_eq!(err, TunnelError::ZeroFragmentCount);
        assert!(err.is_abuse());
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_fragment_index_out_of_range_rejected() {
        let mut reassembler = FragmentReassembler::new();
        let lim = limits(TunnelProto::UDP);
        let err = reassembler
            .process([1; 16], &frag(200, 2, 2, 1), vec![0xAA; 100], &lim, 1000)
            .unwrap_err();
        assert_eq!(err, TunnelError::IndexOutOfRange { index: 2, count: 2 });
        assert!(err.is_abuse());
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_oversized_total_rejected_before_any_retention() {
        let mut reassembler = FragmentReassembler::new();
        let lim = limits(TunnelProto::UDP);
        // The old code would have reached `with_capacity(0xFFFF_FFFF)` once
        // this set completed; now the header is refused on arrival.
        let err = reassembler
            .process(
                [1; 16],
                &frag(u32::MAX, 0, 2, 1),
                vec![0xAA; 100],
                &lim,
                1000,
            )
            .unwrap_err();
        assert_eq!(
            err,
            TunnelError::TotalSizeTooLarge {
                total_size: u32::MAX,
                limit: DEFAULT_MAX_REASSEMBLY_BYTES,
            }
        );
        assert!(err.is_abuse());
        assert_eq!(reassembler.pending_count(), 0);
        assert_eq!(reassembler.session_bytes_held(&[1; 16]), 0);
        // One byte over the ceiling is rejected too; the ceiling itself is
        // not.
        assert!(reassembler
            .process(
                [1; 16],
                &frag(DEFAULT_MAX_REASSEMBLY_BYTES + 1, 0, 2, 2),
                vec![0xAA; 100],
                &lim,
                1000
            )
            .is_err());
        assert_eq!(
            reassembler.process(
                [1; 16],
                &frag(DEFAULT_MAX_REASSEMBLY_BYTES, 0, 2, 3),
                vec![0xAA; 100],
                &lim,
                1000
            ),
            Ok(None)
        );
    }

    #[test]
    fn test_payload_over_mtu_rejected() {
        let mut reassembler = FragmentReassembler::new();
        let lim = limits(TunnelProto::UDP);
        let len = usize::from(DEFAULT_TUNNEL_MTU) + 1;
        let err = reassembler
            .process([1; 16], &frag(4000, 0, 4, 1), vec![0xAA; len], &lim, 1000)
            .unwrap_err();
        assert_eq!(
            err,
            TunnelError::PayloadExceedsMtu {
                len,
                mtu: DEFAULT_TUNNEL_MTU,
            }
        );
        assert!(err.is_abuse());
        // Exactly the MTU is fine.
        assert_eq!(
            reassembler.process(
                [1; 16],
                &frag(4000, 0, 4, 1),
                vec![0xAA; usize::from(DEFAULT_TUNNEL_MTU)],
                &lim,
                1000
            ),
            Ok(None)
        );
    }

    #[test]
    fn test_manager_rejects_unfragmented_payload_over_mtu() {
        let mut mgr = TunnelManager::new();
        mgr.handle_request(&make_request(0x01), true, &policy(100), 1000)
            .unwrap();
        let data = TunnelData {
            session_id: [0x01; 16],
            seq: 0,
            fragment: None,
            payload: vec![0x42; 101],
        };
        assert_eq!(
            mgr.process_data(&data, 1001),
            Err(TunnelError::PayloadExceedsMtu { len: 101, mtu: 100 })
        );
        // The rejected frame was not counted as received traffic.
        assert_eq!(mgr.session(&[0x01; 16]).unwrap().bytes_received, 0);
    }

    #[test]
    fn test_empty_and_overcounted_fragments_rejected() {
        let mut reassembler = FragmentReassembler::new();
        let lim = limits(TunnelProto::UDP);
        assert_eq!(
            reassembler.process([1; 16], &frag(200, 0, 2, 1), vec![], &lim, 1000),
            Err(TunnelError::EmptyFragment)
        );
        // 300 fragments cannot carry 200 bytes one byte each.
        assert_eq!(
            reassembler.process([1; 16], &frag(200, 0, 300, 1), vec![1], &lim, 1000),
            Err(TunnelError::CountExceedsTotal {
                count: 300,
                total_size: 200,
            })
        );
        // A zero total with any count is caught by the same check.
        assert_eq!(
            reassembler.process([1; 16], &frag(0, 0, 1, 1), vec![1], &lim, 1000),
            Err(TunnelError::CountExceedsTotal {
                count: 1,
                total_size: 0,
            })
        );
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_header_mismatch_drops_whole_set() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [1; 16];
        let lim = limits(TunnelProto::UDP);
        assert_eq!(
            reassembler.process(sid, &frag(300, 0, 3, 1), vec![0xAA; 100], &lim, 1000),
            Ok(None)
        );
        // Same id, different count: contradictory, the set is dropped and
        // its bytes are released.
        let err = reassembler
            .process(sid, &frag(300, 1, 4, 1), vec![0xBB; 100], &lim, 1000)
            .unwrap_err();
        assert_eq!(err, TunnelError::HeaderMismatch);
        assert!(err.is_abuse());
        assert_eq!(reassembler.pending_count(), 0);
        assert_eq!(reassembler.session_bytes_held(&sid), 0);
        // Same id, different total_size: likewise.
        assert_eq!(
            reassembler.process(sid, &frag(300, 0, 3, 2), vec![0xAA; 100], &lim, 1000),
            Ok(None)
        );
        assert_eq!(
            reassembler.process(sid, &frag(301, 1, 3, 2), vec![0xBB; 100], &lim, 1000),
            Err(TunnelError::HeaderMismatch)
        );
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_duplicate_fragment_ignored_and_timeout_not_extended() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [1; 16];
        let lim = limits(TunnelProto::UDP);
        assert_eq!(
            reassembler.process(sid, &frag(200, 0, 2, 1), vec![0xAA; 100], &lim, 1000),
            Ok(None)
        );
        let held = reassembler.session_bytes_held(&sid);
        // An identical retransmit is dropped without abuse and without
        // charging the budget twice.
        let err = reassembler
            .process(sid, &frag(200, 0, 2, 1), vec![0xAA; 100], &lim, 1004)
            .unwrap_err();
        assert_eq!(err, TunnelError::DuplicateFragment);
        assert!(!err.is_abuse());
        assert_eq!(reassembler.pending_count(), 1);
        assert_eq!(reassembler.session_bytes_held(&sid), held);
        // The deadline still counts from the first arrival at 1000.
        reassembler.gc(1000 + UDP_FRAGMENT_TIMEOUT_SECS + 1);
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_overlapping_fragment_drops_set() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [1; 16];
        let lim = limits(TunnelProto::UDP);
        assert_eq!(
            reassembler.process(sid, &frag(200, 0, 2, 1), vec![0xAA; 100], &lim, 1000),
            Ok(None)
        );
        // Same index, different bytes: the set is contradictory.
        let err = reassembler
            .process(sid, &frag(200, 0, 2, 1), vec![0xCC; 100], &lim, 1000)
            .unwrap_err();
        assert_eq!(err, TunnelError::OverlappingFragment);
        assert!(err.is_abuse());
        assert_eq!(reassembler.pending_count(), 0);
        assert_eq!(reassembler.session_bytes_held(&sid), 0);
    }

    #[test]
    fn test_fragments_exceeding_total_rejected() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [1; 16];
        let lim = limits(TunnelProto::UDP);
        // Single fragment larger than the declared total: stateless check.
        assert_eq!(
            reassembler.process(sid, &frag(50, 0, 2, 1), vec![0xAA; 100], &lim, 1000),
            Err(TunnelError::TotalSizeExceeded)
        );
        // Running sum crossing the total: stateful check drops the set.
        assert_eq!(
            reassembler.process(sid, &frag(150, 0, 2, 2), vec![0xAA; 100], &lim, 1000),
            Ok(None)
        );
        assert_eq!(
            reassembler.process(sid, &frag(150, 1, 2, 2), vec![0xBB; 100], &lim, 1000),
            Err(TunnelError::TotalSizeExceeded)
        );
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_undersized_total_rejected_on_completion() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [1; 16];
        let lim = limits(TunnelProto::UDP);
        assert_eq!(
            reassembler.process(sid, &frag(300, 0, 2, 1), vec![0xAA; 100], &lim, 1000),
            Ok(None)
        );
        let err = reassembler
            .process(sid, &frag(300, 1, 2, 1), vec![0xBB; 100], &lim, 1000)
            .unwrap_err();
        assert_eq!(
            err,
            TunnelError::TotalSizeMismatch {
                got: 200,
                total_size: 300,
            }
        );
        assert!(err.is_abuse());
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_inflight_flood_capped_per_session() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [1; 16];
        let lim = limits(TunnelProto::UDP);
        // Open the maximum number of partial sets.
        for id in 0..DEFAULT_MAX_INFLIGHT_REASSEMBLIES {
            assert_eq!(
                reassembler.process(sid, &frag(200, 0, 2, id), vec![0xAA; 100], &lim, 1000),
                Ok(None)
            );
        }
        // The next distinct id is refused and retains nothing.
        let err = reassembler
            .process(
                sid,
                &frag(200, 0, 2, DEFAULT_MAX_INFLIGHT_REASSEMBLIES),
                vec![0xAA; 100],
                &lim,
                1000,
            )
            .unwrap_err();
        assert_eq!(err, TunnelError::InflightLimit);
        assert!(!err.is_abuse());
        assert_eq!(
            reassembler.pending_count(),
            usize::from(DEFAULT_MAX_INFLIGHT_REASSEMBLIES)
        );
        // Another session is unaffected by this one's flood.
        assert_eq!(
            reassembler.process([2; 16], &frag(200, 0, 2, 0), vec![0xAA; 100], &lim, 1000),
            Ok(None)
        );
        // Completing one set frees a slot for the flooding session.
        assert!(reassembler
            .process(sid, &frag(200, 1, 2, 0), vec![0xBB; 100], &lim, 1000)
            .unwrap()
            .is_some());
        assert_eq!(
            reassembler.process(
                sid,
                &frag(200, 0, 2, DEFAULT_MAX_INFLIGHT_REASSEMBLIES),
                vec![0xAA; 100],
                &lim,
                1000
            ),
            Ok(None)
        );
    }

    #[test]
    fn test_byte_budget_capped_per_session() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [1; 16];
        let lim = limits(TunnelProto::TCP);
        let mtu = usize::from(DEFAULT_TUNNEL_MTU);
        // Each set declares the full 1 MiB and is left one fragment short,
        // so the attacker holds as much as the per-set ceiling allows.
        let per_set = (DEFAULT_MAX_REASSEMBLY_BYTES as usize) / mtu;
        let count = u16::try_from(per_set + 1).unwrap();
        let mut first_err = None;
        'sets: for id in 0..8u16 {
            for index in 0..u16::try_from(per_set).unwrap() {
                let outcome = reassembler.process(
                    sid,
                    &frag(DEFAULT_MAX_REASSEMBLY_BYTES, index, count, id),
                    vec![0xAA; mtu],
                    &lim,
                    1000,
                );
                if let Err(err) = outcome {
                    first_err = Some(err);
                    break 'sets;
                }
            }
        }
        assert_eq!(first_err, Some(TunnelError::BudgetExceeded));
        assert!(reassembler.session_bytes_held(&sid) <= REASSEMBLY_BUDGET_BYTES);
        // Well under the in-flight cap: the byte budget bit first.
        assert!(reassembler.pending_count() < usize::from(DEFAULT_MAX_INFLIGHT_REASSEMBLIES));
        // A fresh session still has its own full budget.
        assert_eq!(
            reassembler.process([2; 16], &frag(200, 0, 2, 0), vec![0xAA; 100], &lim, 1000),
            Ok(None)
        );
    }

    #[test]
    fn test_global_table_cap() {
        let mut reassembler = FragmentReassembler::new();
        let lim = limits(TunnelProto::TCP);
        // Fill every session's in-flight allowance across MAX_TUNNELS ids.
        for session in 0..MAX_TUNNELS {
            let mut sid = [0u8; 16];
            sid[0] = (session & 0xFF) as u8;
            sid[1] = (session >> 8) as u8;
            for id in 0..DEFAULT_MAX_INFLIGHT_REASSEMBLIES {
                assert_eq!(
                    reassembler.process(sid, &frag(2, 0, 2, id), vec![1], &lim, 1000),
                    Ok(None)
                );
            }
        }
        assert_eq!(reassembler.pending_count(), MAX_REASSEMBLY_BUFFERS_TOTAL);
        // One more session cannot open a set until something expires.
        let extra = [0xFF; 16];
        assert_eq!(
            reassembler.process(extra, &frag(2, 0, 2, 0), vec![1], &lim, 1000),
            Err(TunnelError::TableFull)
        );
        // Once the table's sets have expired the cap check evicts them.
        assert_eq!(
            reassembler.process(
                extra,
                &frag(2, 0, 2, 0),
                vec![1],
                &lim,
                1000 + TCP_FRAGMENT_TIMEOUT_SECS + 1
            ),
            Ok(None)
        );
        assert_eq!(reassembler.pending_count(), 1);
    }

    #[test]
    fn test_stale_eviction_frees_inflight_slots() {
        let mut reassembler = FragmentReassembler::new();
        let sid = [1; 16];
        let lim = limits(TunnelProto::TCP);
        for id in 0..DEFAULT_MAX_INFLIGHT_REASSEMBLIES {
            assert_eq!(
                reassembler.process(sid, &frag(200, 0, 2, id), vec![0xAA; 100], &lim, 1000),
                Ok(None)
            );
        }
        // Before the TCP timeout the slots are still taken.
        assert_eq!(
            reassembler.process(
                sid,
                &frag(200, 0, 2, 100),
                vec![0xAA; 100],
                &lim,
                1000 + TCP_FRAGMENT_TIMEOUT_SECS
            ),
            Err(TunnelError::InflightLimit)
        );
        // Past it, the stale sets are evicted on demand without a gc call.
        assert_eq!(
            reassembler.process(
                sid,
                &frag(200, 0, 2, 100),
                vec![0xAA; 100],
                &lim,
                1000 + TCP_FRAGMENT_TIMEOUT_SECS + 1
            ),
            Ok(None)
        );
        assert_eq!(reassembler.pending_count(), 1);
        assert_eq!(
            reassembler.session_bytes_held(&sid),
            100 + FRAGMENT_SLOT_OVERHEAD
        );
    }

    #[test]
    fn test_gc_uses_protocol_timeout() {
        let mut reassembler = FragmentReassembler::new();
        let udp = limits(TunnelProto::UDP);
        let tcp = limits(TunnelProto::TCP);
        assert_eq!(
            reassembler.process([1; 16], &frag(200, 0, 2, 1), vec![0xAA; 100], &udp, 1000),
            Ok(None)
        );
        assert_eq!(
            reassembler.process([2; 16], &frag(200, 0, 2, 1), vec![0xAA; 100], &tcp, 1000),
            Ok(None)
        );
        // Just past the UDP timeout only the UDP set goes.
        reassembler.gc(1000 + UDP_FRAGMENT_TIMEOUT_SECS + 1);
        assert_eq!(reassembler.pending_count(), 1);
        assert_eq!(reassembler.session_inflight(&[2; 16]), 1);
        // At the TCP timeout the TCP set is still held; one past, it goes.
        reassembler.gc(1000 + TCP_FRAGMENT_TIMEOUT_SECS);
        assert_eq!(reassembler.pending_count(), 1);
        reassembler.gc(1000 + TCP_FRAGMENT_TIMEOUT_SECS + 1);
        assert_eq!(reassembler.pending_count(), 0);
        assert_eq!(reassembler.session_bytes_held(&[2; 16]), 0);
    }

    #[test]
    fn test_unknown_session_rejected() {
        let mut mgr = TunnelManager::new();
        let data = TunnelData {
            session_id: [0x09; 16],
            seq: 0,
            fragment: Some(frag(200, 0, 2, 1)),
            payload: vec![0x42; 100],
        };
        let err = mgr.process_data(&data, 1001).unwrap_err();
        assert_eq!(err, TunnelError::UnknownSession);
        assert!(!err.is_abuse());
        assert_eq!(mgr.reassembler.pending_count(), 0);
    }

    #[test]
    fn test_close_and_idle_gc_release_reassembly_memory() {
        let mut mgr = TunnelManager::new();
        mgr.handle_request(&make_request(0x01), true, &policy(1400), 1000)
            .unwrap();
        mgr.handle_request(&make_request(0x02), true, &policy(1400), 1000)
            .unwrap();
        for id in [0x01u8, 0x02] {
            let data = TunnelData {
                session_id: [id; 16],
                seq: 0,
                fragment: Some(frag(200, 0, 2, 1)),
                payload: vec![0x42; 100],
            };
            assert_eq!(mgr.process_data(&data, 1001), Ok(None));
        }
        assert_eq!(mgr.reassembler.pending_count(), 2);
        // Explicit close drops the session's partial set.
        mgr.close(&[0x01; 16]);
        assert_eq!(mgr.reassembler.pending_count(), 1);
        assert_eq!(mgr.reassembler.session_bytes_held(&[0x01; 16]), 0);
        // Idle collection drops the other one along with its session.
        let closed = mgr.gc(1001 + TUNNEL_IDLE_TIMEOUT_SECS + 1);
        assert_eq!(closed, vec![[0x02; 16]]);
        assert_eq!(mgr.reassembler.pending_count(), 0);
    }

    #[test]
    fn test_limits_resolution_and_ceiling() {
        // Defaults when nothing is advertised.
        let lim = ReassemblyLimits::resolve(TunnelProto::UDP, &TunnelPolicy::default()).unwrap();
        assert_eq!(lim.mtu(), DEFAULT_TUNNEL_MTU);
        assert_eq!(lim.max_reassembly_bytes(), DEFAULT_MAX_REASSEMBLY_BYTES);
        assert_eq!(
            lim.max_inflight_reassemblies(),
            DEFAULT_MAX_INFLIGHT_REASSEMBLIES
        );
        assert_eq!(lim.timeout_secs(), UDP_FRAGMENT_TIMEOUT_SECS);
        assert_eq!(
            limits(TunnelProto::TCP).timeout_secs(),
            TCP_FRAGMENT_TIMEOUT_SECS
        );
        // A peer advertising above the 16 MiB ceiling is refused.
        let accept = TunnelAccept {
            session_id: [1; 16],
            accepted: true,
            reject_reason: None,
            mtu: None,
            max_reassembly_bytes: Some(MAX_REASSEMBLY_BYTES_CEILING + 1),
            max_inflight_reassemblies: None,
        };
        assert_eq!(
            ReassemblyLimits::from_accept(&accept, TunnelProto::TCP),
            Err(TunnelError::InvalidLimits)
        );
        // The ceiling itself is accepted.
        let at_ceiling = TunnelAccept {
            max_reassembly_bytes: Some(MAX_REASSEMBLY_BYTES_CEILING),
            ..accept.clone()
        };
        assert_eq!(
            ReassemblyLimits::from_accept(&at_ceiling, TunnelProto::TCP)
                .unwrap()
                .max_reassembly_bytes(),
            MAX_REASSEMBLY_BYTES_CEILING
        );
        // Zero values are never "unbounded".
        for bad in [
            TunnelPolicy {
                mtu: Some(0),
                ..TunnelPolicy::default()
            },
            TunnelPolicy {
                max_reassembly_bytes: Some(0),
                ..TunnelPolicy::default()
            },
            TunnelPolicy {
                max_inflight_reassemblies: Some(0),
                ..TunnelPolicy::default()
            },
        ] {
            assert_eq!(
                ReassemblyLimits::resolve(TunnelProto::TCP, &bad),
                Err(TunnelError::InvalidLimits)
            );
        }
        // An invalid local policy surfaces as an error, not an accept.
        let mut mgr = TunnelManager::new();
        assert_eq!(
            mgr.handle_request(&make_request(0x01), true, &policy(0), 1000)
                .unwrap_err(),
            TunnelError::InvalidLimits
        );
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_keepalive_resets_idle() {
        let mut mgr = TunnelManager::new();
        mgr.handle_request(&make_request(0x01), true, &policy(1400), 1000)
            .unwrap();

        mgr.keepalive(
            &TunnelKeepalive {
                session_id: [0x01; 16],
            },
            1500,
        );

        let closed = mgr.gc(1500 + TUNNEL_IDLE_TIMEOUT_SECS - 1);
        assert!(closed.is_empty());
    }

    #[test]
    fn test_sequence_numbers_and_overflow() {
        let mut mgr = TunnelManager::new();
        mgr.handle_request(&make_request(0x01), true, &policy(1400), 1000)
            .unwrap();

        let session = mgr.session_mut(&[0x01; 16]).unwrap();
        assert_eq!(session.next_sequence(), Ok(0));
        assert_eq!(session.next_sequence(), Ok(1));
        assert_eq!(session.next_sequence(), Ok(2));
        // The u128 space is practically infinite; at its end the tunnel
        // reports exhaustion instead of wrapping to a replay-looking 0.
        session.next_seq = u128::MAX - 1;
        assert_eq!(session.next_sequence(), Ok(u128::MAX - 1));
        assert_eq!(session.next_sequence(), Err(TunnelError::SeqExhausted));
        assert_eq!(session.next_seq, u128::MAX);
    }

    #[test]
    fn test_seq_u128_round_trips_through_serde() {
        let data = TunnelData {
            session_id: [0x01; 16],
            seq: u128::from(u64::MAX) + 7,
            fragment: None,
            payload: vec![1, 2, 3],
        };
        let json = serde_json::to_vec(&data).unwrap();
        let back: TunnelData = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.seq, data.seq);
        assert_eq!(back.payload, data.payload);
    }

    #[test]
    fn test_mtu_update() {
        let mut mgr = TunnelManager::new();
        mgr.handle_request(&make_request(0x01), true, &policy(1400), 1000)
            .unwrap();
        let session = mgr.session_mut(&[0x01; 16]).unwrap();
        assert_eq!(session.update_mtu(0), Err(TunnelError::InvalidLimits));
        assert_eq!(session.mtu(), 1400);
        assert_eq!(session.update_mtu(900), Ok(()));
        assert_eq!(session.mtu(), 900);
    }

    /// Replay the committed fuzz seed corpus through the shared driver
    /// (TESTING_METHODOLOGY "corpus replay test coverage"). Every seed must
    /// run without a panic and without a bound violation, and the seeds'
    /// known outcomes must still be produced.
    #[test]
    fn test_tunnel_fragment_corpus_replay() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/fuzz_tunnel_fragment");
        crate::testing::corpus::assert_corpus_dir_exists(&dir);
        let entries = crate::testing::corpus::load_corpus_entries(&dir).expect("read corpus");
        assert!(!entries.is_empty(), "corpus must have seeds");
        let mut totals = FragmentDriveReport::default();
        for (path, bytes) in entries {
            let report = drive_fragment_input(&bytes);
            assert!(report.invariants_ok, "bound violated by {path:?}");
            totals.delivered += report.delivered;
            totals.rejected += report.rejected;
            totals.abuse += report.abuse;
        }
        // seed_01 delivers one payload; seeds 02-04 are abuse (oversized
        // total, index out of range, over-MTU frame); seed_05's duplicate
        // and seed_06's unknown session are rejected but not abuse.
        assert_eq!(totals.delivered, 1);
        assert_eq!(totals.abuse, 3);
        assert_eq!(totals.rejected, 5);
    }

    #[test]
    fn test_driver_is_total_over_hostile_shapes() {
        // Exhausted, all-zero, all-0xFF and alternating inputs must all run
        // to completion with the bounds intact.
        for input in [
            Vec::new(),
            vec![0u8; 64],
            vec![0xFFu8; 512],
            (0..=255u8).cycle().take(4096).collect(),
        ] {
            assert!(drive_fragment_input(&input).invariants_ok);
        }
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
        let ack = mgr
            .handle_request(
                &make_request(0x01),
                perm == AclPermission::Allow,
                &policy(1400),
                1000,
            )
            .unwrap();
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
        let ack = mgr
            .handle_request(
                &make_request(0x02),
                perm == AclPermission::Allow,
                &policy(1400),
                1000,
            )
            .unwrap();
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
        let ack = mgr
            .handle_request(
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
                &policy(1400),
                1000,
            )
            .unwrap();
        assert!(!ack.accepted);
        assert_eq!(ack.reject_reason, Some(TunnelRejectReason::AccessDenied));
    }
}
