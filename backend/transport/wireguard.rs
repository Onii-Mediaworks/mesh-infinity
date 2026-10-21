//! WireGuard-like Per-Hop Link Encryption (§5.1, §5.2)
//!
//! Implements the Noise_IK-shaped handshake that authenticates every direct
//! link between two mesh peers and derives the per-hop packet keys.  Every
//! packet transmitted between two nodes is encrypted with a session key that
//! is bound to both tunnel static keys, both ephemeral keys and — for
//! trusted-tier peers — the per-epoch tunnel PSK of §5.2.
//!
//! # Fixed suite (§5.1)
//!
//! There is no cipher negotiation.  Every handshake message starts with a
//! three-byte header `[version_major, version_minor, suite_id]` that declares
//! protocol v1.6 and suite `MI-LINK-1` (ChaCha20-Poly1305, X25519, SHA-256
//! HKDF).  The header is authenticated: it is additional data for every AEAD
//! in the handshake and part of the HKDF info for the session keys, so an
//! on-path attacker cannot substitute either value without breaking the
//! handshake.  A peer that declares any other suite or version is rejected
//! with a typed error and surfaced as an incompatible peer; there is no
//! fallback to another suite and never to plaintext.
//!
//! # Protocol
//!
//! Both peers hold a tunnel static X25519 keypair.  The initiator also knows
//! the responder's static public key (from the map or a signed tunnel-key
//! binding, see `tunnel_keys`), and the responder knows which static key to
//! expect from the initiator.
//!
//! ```text
//! Initiator                                             Responder
//!    |                                                     |
//!    |-- Init(hdr, eph_i_pub, enc_static, enc_timestamp) ->|
//!    |                                                     |
//!    |<-- Response(hdr, eph_r_pub, confirm_tag) -----------|
//!    |                                                     |
//! es = DH(eph_i, static_r)      ss = DH(static_i, static_r)
//! ee = DH(eph_i, eph_r)         se = DH(static_i, eph_r)
//!
//! enc_static     = AEAD(KDF(es),           aad = hdr,            static_i_pub)
//! enc_timestamp  = AEAD(KDF(es || ss || psk), aad = hdr || eph_i || enc_static, timestamp)
//! ck             = HKDF(es || ss || ee || se || psk, info = ids || transcript)
//! confirm_tag    = AEAD(ck["resp-confirm"], aad = transcript, "")
//! send/recv keys = ck["i_to_r"], ck["r_to_i"]  (responder inverts)
//! ```
//!
//! `enc_timestamp` is the initiator's key confirmation: only a party holding
//! `static_i` (and the PSK, when one is installed) can produce it, so a
//! forged Init is rejected before any session state is touched.  The
//! timestamp is strictly monotonic per initiator; a replayed Init with an
//! old timestamp is rejected.  `confirm_tag` is the responder's key
//! confirmation: only a party holding `static_r` and `eph_r` can produce it,
//! so a forged Response neither consumes the pending state nor installs a
//! session.
//!
//! # Packet Format
//!
//! `[8-byte nonce (LE u64)] [ciphertext] [16-byte Poly1305 tag]`
//!
//! # Layer limits (§5.2)
//!
//! This layer is authenticated per-hop plumbing and nothing more.  It is
//! classical (no post-quantum margin in the handshake itself; the trusted
//! PSK adds that margin), it is not identity-hiding against later compromise
//! of a responder static key, it is not obfuscated, and it is not deniable.
//! Nothing here derives, wraps or transmits identity keys, ratchet state or
//! trust state: compromise of a tunnel key compromises only tunnel traffic.
//!
//! # Security Properties
//!
//! - **Mutual authentication with key confirmation**: both messages carry an
//!   AEAD under keys only the genuine party can derive.
//! - **Forward secrecy** (classical): ephemeral keys are discarded after the
//!   handshake.
//! - **Replay protection**: 64-bit packet nonce with a sliding window that is
//!   committed only after the tag verifies; monotonic handshake timestamps.
//! - **PSK mixing**: the per-epoch tunnel PSK (§5.2) is mixed into the
//!   chaining key; `psk_present()` tells the service layer whether
//!   trusted-tier features may run over the session.
//! - **Endpoint pinning**: in high-assurance modes a validly keyed packet
//!   from a new endpoint never moves the peer (§5.2, "Endpoint pinning").

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::crypto::channel_key::{encode_tunnel_epoch, TunnelEpoch, TUNNEL_PSK_LEN};
use crate::identity::peer_id::PeerId;
use crate::network::threat_context::ThreatContext;
use crate::routing::losec::ConnectionMode;
use crate::trust::levels::TrustLevel;

// ---------------------------------------------------------------------------
// Fixed suite constants (§5.1)
// ---------------------------------------------------------------------------

/// Protocol version carried in every handshake message: major part (v1.x).
// LINK_VERSION_MAJOR — protocol constant (§5.1).
// Defined by the spec; a new suite arrives only with a new version.
pub const LINK_VERSION_MAJOR: u8 = 1;

/// Protocol version carried in every handshake message: minor part (v1.6).
// LINK_VERSION_MINOR — protocol constant (§5.1).
pub const LINK_VERSION_MINOR: u8 = 6;

/// Suite id of `MI-LINK-1`, the only suite protocol v1.6 speaks (§5.1).
///
/// ChaCha20-Poly1305, X25519 (hybrid with ML-KEM-768 for the trusted PSK),
/// Ed25519, SHA-256/SHA-512 HKDF.  Any other value in the handshake header
/// is an incompatible peer, never a negotiation.
// LINK_SUITE_MI_LINK_1 — protocol constant (§5.1).
pub const LINK_SUITE_MI_LINK_1: u8 = 0x01;

/// Human-readable suite name for diagnostics and the §21.6.4 manifest.
pub const LINK_SUITE_NAME: &str = "MI-LINK-1";

/// The three-byte authenticated handshake header `[major, minor, suite]`.
// LINK_HEADER — protocol constant; bound into every handshake AEAD.
pub const LINK_HEADER: [u8; 3] = [LINK_VERSION_MAJOR, LINK_VERSION_MINOR, LINK_SUITE_MI_LINK_1];

/// Byte length of the handshake header.
pub const LINK_HEADER_LEN: usize = 3;

/// Wire length of `HandshakeInit`:
/// header (3) + eph_i_pub (32) + enc_static (48) + enc_timestamp (24).
pub const HANDSHAKE_INIT_LEN: usize = LINK_HEADER_LEN + 32 + 48 + 24;

/// Wire length of `HandshakeResponse`:
/// header (3) + eph_r_pub (32) + confirm_tag (16).
pub const HANDSHAKE_RESPONSE_LEN: usize = LINK_HEADER_LEN + 32 + 16;

// ---------------------------------------------------------------------------
// Other constants
// ---------------------------------------------------------------------------

/// Domain-separation salt for HKDF.  Ensures that key material derived
/// for link sessions is cryptographically independent from keys derived
/// for other purposes even if the same DH outputs appear elsewhere.  The
/// version suffix changes with the protocol version, never in-band.
const SESSION_KEY_SALT: &[u8] = b"meshinfinity-wireguard-session-v1";

/// Anti-replay window size (in nonces).  A sliding window of 1024 nonces
/// allows up to 1024 out-of-order packets to be accepted.  This is the
/// same window size WireGuard uses, balancing memory cost (a small HashSet)
/// against tolerance for packet reordering on mesh multi-hop paths.
const REPLAY_WINDOW: u64 = 1024;

/// AEAD tag length (Poly1305).
const TAG_LEN: usize = 16;

/// Default keepalive interval used by the roaming re-handshake rule when the
/// caller has no transport-specific value (§5.2: "within the next keepalive
/// interval").  25 seconds is WireGuard's conventional persistent keepalive.
pub const DEFAULT_KEEPALIVE_SECS: u64 = 25;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed failures of the link handshake and packet layer.
///
/// Every variant is a hard failure: there is no fallback suite, no
/// unauthenticated session, and no plaintext path (§5.1).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireGuardError {
    /// The peer's static key could not be decrypted or did not match the key
    /// the caller expected for this peer.
    #[error("handshake failed: invalid peer public key")]
    InvalidPeerKey,
    /// The initiator's key-confirmation AEAD failed: the sender does not hold
    /// the claimed static key (or the installed PSK).
    #[error("handshake failed: initiator key confirmation rejected")]
    InitiatorUnconfirmed,
    /// The responder's confirmation tag failed: the reply was not produced by
    /// the holder of the responder's static key.
    #[error("handshake failed: responder key confirmation rejected")]
    ResponderUnconfirmed,
    /// The handshake timestamp is not newer than the last accepted one from
    /// this initiator: a replayed or reordered Init.
    #[error("handshake replay: timestamp {timestamp} not after {last_accepted}")]
    HandshakeReplay { timestamp: u64, last_accepted: u64 },
    /// The peer declared a cipher suite other than `MI-LINK-1` (§5.1).
    #[error("incompatible peer: unsupported link suite id {declared:#04x}")]
    UnsupportedSuite { declared: u8 },
    /// The peer declared a protocol version this node does not implement.
    #[error("incompatible peer: unsupported link protocol version {major}.{minor}")]
    IncompatibleVersion { major: u8, minor: u8 },
    /// A handshake message had the wrong length (truncated or padded).
    #[error("malformed handshake message: expected {expected} bytes, got {actual}")]
    MalformedHandshake { expected: usize, actual: usize },
    /// Packet authentication failed.
    #[error("decryption failed: authentication tag mismatch")]
    DecryptionFailed,
    /// Packet nonce already seen or outside the replay window.
    #[error("replay attack: nonce already seen")]
    ReplayDetected,
    /// The send counter is exhausted; the session must be re-handshaken.
    #[error("nonce overflow: session must be renegotiated")]
    NonceOverflow,
    /// HKDF or AEAD setup failed (cannot happen with fixed-size inputs, but
    /// surfaced as a typed error rather than a panic).
    #[error("key derivation failed")]
    KeyDerivation,
}

// ---------------------------------------------------------------------------
// Tunnel PSK (§5.2)
// ---------------------------------------------------------------------------

/// The pre-shared key input to a link handshake.
///
/// `None` is a no-PSK tunnel: lower-trust peers, or a trusted peer whose
/// per-epoch PSK agreement has not completed.  `Epoch` carries the PSK of
/// one tunnel epoch produced by `tunnel_keys::psk_*` from the hybrid
/// exchange of §5.2.  The static `channel_key` is never wrapped here
/// directly: §5.2 forbids using it as a PSK.
#[derive(Clone)]
pub enum TunnelPsk {
    /// No PSK is installed; trusted-tier features are withheld (§5.2).
    None,
    /// A per-epoch PSK from the hybrid agreement.
    Epoch {
        /// The 32-byte PSK; wiped on drop.
        key: Zeroizing<[u8; TUNNEL_PSK_LEN]>,
        /// The epoch the PSK belongs to; mixed into the KDF info.
        epoch: TunnelEpoch,
    },
}

/// Redacting `Debug`: shows presence and epoch, never key bytes, so a PSK
/// can appear in test assertions and diagnostics without leaking.
impl std::fmt::Debug for TunnelPsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("TunnelPsk::None"),
            Self::Epoch { epoch, .. } => write!(f, "TunnelPsk::Epoch {{ epoch: {epoch}, key: <redacted> }}"),
        }
    }
}

impl TunnelPsk {
    /// Whether a PSK is installed.
    pub fn is_present(&self) -> bool {
        matches!(self, Self::Epoch { .. })
    }

    /// The epoch of the installed PSK, if any.
    pub fn epoch(&self) -> Option<TunnelEpoch> {
        match self {
            Self::None => None,
            Self::Epoch { epoch, .. } => Some(*epoch),
        }
    }

    /// The raw key bytes mixed into the chaining key: all zeros when no PSK
    /// is installed (matching WireGuard's zero PSK), the epoch key otherwise.
    /// The presence flag and epoch are additionally mixed into the HKDF info,
    /// so a no-PSK tunnel and an (impossible) all-zero PSK still differ.
    fn key_bytes(&self) -> Zeroizing<[u8; TUNNEL_PSK_LEN]> {
        match self {
            Self::None => Zeroizing::new([0u8; TUNNEL_PSK_LEN]),
            Self::Epoch { key, .. } => key.clone(),
        }
    }

    /// Nine bytes of PSK context for HKDF info / AEAD aad:
    /// `[present_flag][epoch be64]`.
    fn context_bytes(&self) -> [u8; 9] {
        let mut out = [0u8; 9];
        if let Self::Epoch { epoch, .. } = self {
            out[0] = 1;
            out[1..].copy_from_slice(&encode_tunnel_epoch(*epoch));
        }
        out
    }
}

/// Whether trusted-tier features may run over a session (§5.2).
///
/// Trusted-tier features need both a trusted-tier relationship (Level 6+)
/// and a tunnel whose PSK agreement completed.  A trusted peer on a no-PSK
/// tunnel is served as an ordinary peer until the agreement succeeds.
pub fn trusted_tier_enabled(level: TrustLevel, psk_present: bool) -> bool {
    level.is_trusted_tier() && psk_present
}

// ---------------------------------------------------------------------------
// Static key provenance (§5.2, "Tunnel key lifecycle")
// ---------------------------------------------------------------------------

/// Which static key a session was handshaken with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticKeySource {
    /// The stable map identity key was used directly (first-contact
    /// bootstrap against a pinned key, §4.1).  Such a tunnel MUST be re-keyed
    /// to a role-scoped tunnel key once the signed binding is available.
    IdentityBootstrap,
    /// A role-scoped tunnel key of the given generation (`tunnel_keys`).
    RoleScoped { generation: u64 },
}

impl StaticKeySource {
    /// Whether the spec requires this session to be re-keyed.
    pub fn rekey_required(self) -> bool {
        matches!(self, Self::IdentityBootstrap)
    }
}

// ---------------------------------------------------------------------------
// Endpoint pinning (§5.2, "Endpoint pinning in high-assurance modes")
// ---------------------------------------------------------------------------

/// How a session treats a validly keyed packet from a new endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointPolicy {
    /// The peer endpoint is pinned for the session's lifetime.  A packet
    /// from another endpoint never moves the peer; a full re-handshake from
    /// the new endpoint is required and the change is a security event.
    Pinned,
    /// Roaming is allowed, but a path change must be followed by a
    /// re-handshake within `keepalive_secs` so an on-path attacker cannot
    /// redirect the tunnel indefinitely without holding its keys.
    Roaming { keepalive_secs: u64 },
}

impl EndpointPolicy {
    /// Derive the policy the spec mandates for a connection.
    ///
    /// Pinned in `ThreatContext::Elevated` and above, in LoSec sessions and
    /// on Direct connections; roaming with forced re-handshake otherwise.
    pub fn for_context(threat: ThreatContext, mode: ConnectionMode, keepalive_secs: u64) -> Self {
        // Any of the three high-assurance conditions pins the endpoint.
        let high_assurance = threat != ThreatContext::Normal
            || matches!(mode, ConnectionMode::LoSec | ConnectionMode::Direct);
        if high_assurance {
            Self::Pinned
        } else {
            Self::Roaming { keepalive_secs }
        }
    }
}

/// Result of observing the source endpoint of a validly keyed packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointVerdict {
    /// Same endpoint as before (or the first one seen): nothing to do.
    Accepted,
    /// Roaming policy: the peer moved; a re-handshake is due by the given
    /// time (seconds, same clock as `now`).
    Moved { rehandshake_by: u64 },
    /// Pinned policy: the packet came from a different endpoint.  The peer
    /// is not moved; the caller must demand a full re-handshake from the new
    /// endpoint and record a security event (§22.43).
    Rejected { pinned: String, observed: String },
}

// ---------------------------------------------------------------------------
// Session Keys
// ---------------------------------------------------------------------------

/// Directional session keys — separate keys for each direction prevent
/// a reflected-packet attack where an adversary replays a sender's packet
/// back to them.  Both keys are derived from the same HKDF output but with
/// different info labels ("i_to_r" / "r_to_i"), ensuring cryptographic
/// independence.  `Zeroizing` ensures keys are scrubbed from memory on drop.
struct SessionKeys {
    i_to_r: Zeroizing<[u8; 32]>,
    r_to_i: Zeroizing<[u8; 32]>,
    /// Key for the responder's confirmation tag.
    resp_confirm: Zeroizing<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// WireGuardSession
// ---------------------------------------------------------------------------

/// Mutable endpoint-tracking state, guarded by one mutex.
struct EndpointState {
    /// Last endpoint the peer was reached from, in the transport's own
    /// encoding (see `trait_transport`), once known.
    endpoint: Option<String>,
    /// Deadline for the re-handshake a roaming path change demands.
    rehandshake_due: Option<u64>,
}

/// An active per-hop link session.
pub struct WireGuardSession {
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    send_nonce: Arc<AtomicU64>,
    recv_high: Mutex<u64>,
    recv_seen: Mutex<std::collections::HashSet<u64>>,
    /// Epoch of the PSK this session was handshaken with, if any.
    psk_epoch: Option<TunnelEpoch>,
    /// Provenance of the static key used for this session.
    key_source: StaticKeySource,
    /// Endpoint policy in force for this session.
    policy: EndpointPolicy,
    /// Endpoint tracking state.
    endpoint: Mutex<EndpointState>,
    pub peer_id: PeerId,
}

/// Redacting `Debug`: identifies the session without exposing any key or
/// counter state.
impl std::fmt::Debug for WireGuardSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardSession")
            .field("peer_id", &self.peer_id.to_hex())
            .field("psk_epoch", &self.psk_epoch)
            .field("key_source", &self.key_source)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl WireGuardSession {
    /// Build a session from derived keys.
    ///
    /// The session starts with the conservative defaults — `Pinned`
    /// endpoint policy and `IdentityBootstrap` key provenance — and the
    /// caller relaxes them with `set_endpoint_policy` / `set_key_source`
    /// when it knows better.  Fail-closed defaults mean a call site that
    /// forgets to configure the session gets the strictest behaviour.
    fn new(keys: SessionKeys, peer_id: PeerId, is_initiator: bool, psk_epoch: Option<TunnelEpoch>) -> Self {
        let (send_key, recv_key) = if is_initiator {
            (keys.i_to_r, keys.r_to_i)
        } else {
            (keys.r_to_i, keys.i_to_r)
        };
        Self {
            send_key,
            recv_key,
            send_nonce: Arc::new(AtomicU64::new(0)),
            recv_high: Mutex::new(0),
            recv_seen: Mutex::new(std::collections::HashSet::new()),
            psk_epoch,
            key_source: StaticKeySource::IdentityBootstrap,
            policy: EndpointPolicy::Pinned,
            endpoint: Mutex::new(EndpointState {
                endpoint: None,
                rehandshake_due: None,
            }),
            peer_id,
        }
    }

    /// Whether this session was handshaken with a tunnel PSK (§5.2).
    pub fn psk_present(&self) -> bool {
        self.psk_epoch.is_some()
    }

    /// The PSK epoch of this session, if a PSK was used.
    pub fn psk_epoch(&self) -> Option<TunnelEpoch> {
        self.psk_epoch
    }

    /// Record which static key this session was handshaken with.
    pub fn set_key_source(&mut self, source: StaticKeySource) {
        self.key_source = source;
    }

    /// Provenance of the static key used for this session.
    pub fn key_source(&self) -> StaticKeySource {
        self.key_source
    }

    /// Install the endpoint policy for this session.
    pub fn set_endpoint_policy(&mut self, policy: EndpointPolicy) {
        self.policy = policy;
    }

    /// The endpoint policy in force.
    pub fn endpoint_policy(&self) -> EndpointPolicy {
        self.policy
    }

    /// The last endpoint the peer was reached from, once known.
    pub fn endpoint(&self) -> Option<String> {
        self.endpoint
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .endpoint
            .clone()
    }

    /// Observe the source endpoint of a packet that **already passed**
    /// `decrypt`.  Call it only for authenticated packets: an unauthenticated
    /// packet must never influence endpoint state.
    ///
    /// Applies the §5.2 endpoint rules: pinned sessions reject the move,
    /// roaming sessions accept it and schedule a re-handshake deadline.
    pub fn observe_endpoint(&self, observed: &str, now: u64) -> EndpointVerdict {
        let mut state = self.endpoint.lock().unwrap_or_else(|e| e.into_inner());
        match state.endpoint.as_deref() {
            // First sighting: adopt the endpoint under either policy.
            None => {
                state.endpoint = Some(observed.to_string());
                EndpointVerdict::Accepted
            }
            // Same path as before: nothing changes.
            Some(current) if current == observed => EndpointVerdict::Accepted,
            // Path change: the policy decides.
            Some(current) => match self.policy {
                EndpointPolicy::Pinned => EndpointVerdict::Rejected {
                    pinned: current.to_string(),
                    observed: observed.to_string(),
                },
                EndpointPolicy::Roaming { keepalive_secs } => {
                    // Move the peer, but demand a re-handshake within one
                    // keepalive interval so a redirect cannot persist.
                    let deadline = now.saturating_add(keepalive_secs);
                    state.endpoint = Some(observed.to_string());
                    state.rehandshake_due = Some(deadline);
                    EndpointVerdict::Moved {
                        rehandshake_by: deadline,
                    }
                }
            },
        }
    }

    /// Whether a roaming re-handshake deadline has passed without a new
    /// handshake.  The caller should then drop the session.
    pub fn rehandshake_overdue(&self, now: u64) -> bool {
        let state = self.endpoint.lock().unwrap_or_else(|e| e.into_inner());
        matches!(state.rehandshake_due, Some(due) if now > due)
    }

    /// Whether a re-handshake is pending (deadline set, not yet expired).
    pub fn rehandshake_pending(&self) -> bool {
        let state = self.endpoint.lock().unwrap_or_else(|e| e.into_inner());
        state.rehandshake_due.is_some()
    }

    /// Encrypt `plaintext` and return `[8-byte nonce][ciphertext][16-byte tag]`.
    ///
    /// The nonce is an atomically-incremented 64-bit counter, placed in the
    /// last 8 bytes of the 12-byte ChaCha20 nonce (first 4 bytes zeroed).
    /// This matches WireGuard's nonce construction and ensures uniqueness
    /// without coordination.  At u64::MAX the session MUST be renegotiated
    /// to avoid nonce reuse, which would catastrophically break ChaCha20's
    /// security — though in practice 2^64 packets is unreachable.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let nonce_val = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        if nonce_val == u64::MAX {
            return Err(WireGuardError::NonceOverflow);
        }
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&*self.send_key));
        // ChaCha20-Poly1305 requires a 96-bit (12-byte) nonce.  The first 4
        // bytes are fixed at zero; the last 8 carry the counter.  This is
        // safe because each key is used with a monotonic counter, guaranteeing
        // nonce uniqueness without any randomness.
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce_val.to_le_bytes());
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let mut buf = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buf)
            .map_err(|_| WireGuardError::KeyDerivation)?;
        let mut out = Vec::with_capacity(8 + buf.len() + TAG_LEN);
        out.extend_from_slice(&nonce_val.to_le_bytes());
        out.extend_from_slice(&buf);
        out.extend_from_slice(tag.as_slice());
        Ok(out)
    }

    /// Decrypt a packet produced by `encrypt()`.
    ///
    /// The anti-replay window is only *tested* before authentication and
    /// *committed* after the tag verifies (RFC 4303 §3.4.3 order).  A forged
    /// packet with an arbitrary nonce therefore cannot poison the window:
    /// it neither advances the high-water mark nor marks its nonce as seen.
    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        if packet.len() < 8 + TAG_LEN {
            return Err(WireGuardError::DecryptionFailed);
        }
        // Length checked above, so this slice is exactly 8 bytes.
        let mut nonce_raw = [0u8; 8];
        nonce_raw.copy_from_slice(&packet[..8]);
        let nonce_val = u64::from_le_bytes(nonce_raw);
        let ciphertext_with_tag = &packet[8..];

        // Phase 1 — test the window without mutating it.
        //
        // The window is anchored at `recv_high` (highest nonce accepted).
        // Any nonce older than `recv_high - REPLAY_WINDOW` is rejected
        // outright; nonces inside the window are rejected if already seen.
        {
            let high = self.recv_high.lock().unwrap_or_else(|e| e.into_inner());
            let seen = self.recv_seen.lock().unwrap_or_else(|e| e.into_inner());
            if nonce_val < high.saturating_sub(REPLAY_WINDOW) {
                return Err(WireGuardError::ReplayDetected);
            }
            if seen.contains(&nonce_val) {
                return Err(WireGuardError::ReplayDetected);
            }
        }

        // Phase 2 — authenticate and decrypt.
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&*self.recv_key));
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce_val.to_le_bytes());
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ct_len = ciphertext_with_tag.len() - TAG_LEN;
        let mut plaintext = ciphertext_with_tag[..ct_len].to_vec();
        let tag = GenericArray::from_slice(&ciphertext_with_tag[ct_len..]);
        cipher
            .decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
            .map_err(|_| WireGuardError::DecryptionFailed)?;

        // Phase 3 — commit the nonce now that the packet is authentic.
        //
        // Nonces within the window are tracked individually to handle
        // out-of-order delivery on multi-hop mesh paths.  When a new
        // high-water mark is set, old entries are pruned to keep memory
        // bounded at O(REPLAY_WINDOW).  Two packets with the same nonce
        // racing through phase 1 cannot both commit: the second re-check
        // under the lock catches it.
        {
            let mut high = self.recv_high.lock().unwrap_or_else(|e| e.into_inner());
            let mut seen = self.recv_seen.lock().unwrap_or_else(|e| e.into_inner());
            if !seen.insert(nonce_val) {
                return Err(WireGuardError::ReplayDetected);
            }
            if nonce_val > *high {
                seen.retain(|&n| n >= nonce_val.saturating_sub(REPLAY_WINDOW));
                *high = nonce_val;
            }
        }
        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Handshake messages
// ---------------------------------------------------------------------------

/// Sent by the initiator to start a handshake.
///
/// Wire layout (`HANDSHAKE_INIT_LEN` bytes):
/// `header(3) || eph_i_pub(32) || enc_static(48) || enc_timestamp(24)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeInit {
    /// Initiator's ephemeral X25519 public key.
    pub eph_i_pub: [u8; 32],
    /// Initiator's static public key, encrypted under DH(eph_i, static_r).
    /// 32 bytes plaintext + 16 bytes AEAD tag = 48 bytes.
    pub enc_static: [u8; 48],
    /// Initiator's key confirmation: the handshake timestamp encrypted under
    /// a key that mixes DH(eph_i, static_r), DH(static_i, static_r) and the
    /// PSK.  8 bytes plaintext + 16 bytes tag = 24 bytes.
    pub enc_timestamp: [u8; 24],
}

impl HandshakeInit {
    /// Serialise to the fixed wire layout, header first.
    pub fn to_bytes(&self) -> [u8; HANDSHAKE_INIT_LEN] {
        let mut out = [0u8; HANDSHAKE_INIT_LEN];
        out[..3].copy_from_slice(&LINK_HEADER);
        out[3..35].copy_from_slice(&self.eph_i_pub);
        out[35..83].copy_from_slice(&self.enc_static);
        out[83..].copy_from_slice(&self.enc_timestamp);
        out
    }

    /// Parse the wire layout.  Length is checked first, then the header is
    /// validated (version before suite, so an old peer is reported as a
    /// version mismatch rather than a suite mismatch).  Untrusted input:
    /// every failure is a typed error, never a panic.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireGuardError> {
        if bytes.len() != HANDSHAKE_INIT_LEN {
            return Err(WireGuardError::MalformedHandshake {
                expected: HANDSHAKE_INIT_LEN,
                actual: bytes.len(),
            });
        }
        check_header(&bytes[..3])?;
        let mut eph_i_pub = [0u8; 32];
        eph_i_pub.copy_from_slice(&bytes[3..35]);
        let mut enc_static = [0u8; 48];
        enc_static.copy_from_slice(&bytes[35..83]);
        let mut enc_timestamp = [0u8; 24];
        enc_timestamp.copy_from_slice(&bytes[83..]);
        Ok(Self {
            eph_i_pub,
            enc_static,
            enc_timestamp,
        })
    }
}

/// Sent by the responder in reply.
///
/// Wire layout (`HANDSHAKE_RESPONSE_LEN` bytes):
/// `header(3) || eph_r_pub(32) || confirm_tag(16)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// Responder's ephemeral X25519 public key.
    pub eph_r_pub: [u8; 32],
    /// Responder's key confirmation: AEAD tag over the full transcript under
    /// the derived chaining key.
    pub confirm_tag: [u8; 16],
}

impl HandshakeResponse {
    /// Serialise to the fixed wire layout, header first.
    pub fn to_bytes(&self) -> [u8; HANDSHAKE_RESPONSE_LEN] {
        let mut out = [0u8; HANDSHAKE_RESPONSE_LEN];
        out[..3].copy_from_slice(&LINK_HEADER);
        out[3..35].copy_from_slice(&self.eph_r_pub);
        out[35..].copy_from_slice(&self.confirm_tag);
        out
    }

    /// Parse the wire layout with the same checks as `HandshakeInit`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireGuardError> {
        if bytes.len() != HANDSHAKE_RESPONSE_LEN {
            return Err(WireGuardError::MalformedHandshake {
                expected: HANDSHAKE_RESPONSE_LEN,
                actual: bytes.len(),
            });
        }
        check_header(&bytes[..3])?;
        let mut eph_r_pub = [0u8; 32];
        eph_r_pub.copy_from_slice(&bytes[3..35]);
        let mut confirm_tag = [0u8; 16];
        confirm_tag.copy_from_slice(&bytes[35..]);
        Ok(Self {
            eph_r_pub,
            confirm_tag,
        })
    }
}

/// Validate a declared `[major, minor, suite]` header against the fixed
/// suite.  Version is checked before suite so the error names the actual
/// incompatibility a user would need to resolve.  Shared with the PSK
/// agreement messages of `tunnel_keys`, which carry the same header.
pub(crate) fn check_header(header: &[u8]) -> Result<(), WireGuardError> {
    // Caller guarantees three bytes; guard anyway so this is total.
    if header.len() != LINK_HEADER_LEN {
        return Err(WireGuardError::MalformedHandshake {
            expected: LINK_HEADER_LEN,
            actual: header.len(),
        });
    }
    if header[0] != LINK_VERSION_MAJOR || header[1] != LINK_VERSION_MINOR {
        return Err(WireGuardError::IncompatibleVersion {
            major: header[0],
            minor: header[1],
        });
    }
    if header[2] != LINK_SUITE_MI_LINK_1 {
        return Err(WireGuardError::UnsupportedSuite {
            declared: header[2],
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Initiator handshake
// ---------------------------------------------------------------------------

/// Ephemeral key pair used by either side.
/// Uses `StaticSecret` (not `EphemeralSecret`) so we can perform multiple
/// DH operations with the same key — needed for the eph×eph and eph×static
/// computations that happen at different handshake steps.
struct EphemeralPair {
    secret: X25519Secret,
    public: X25519Public,
}

impl EphemeralPair {
    fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        let secret = X25519Secret::from(bytes);
        let public = X25519Public::from(&secret);
        Self { secret, public }
    }
}

/// Initiator-side handshake state.
///
/// Held until the responder's reply verifies.  `complete` borrows rather
/// than consumes the state so a forged reply leaves it intact and the
/// genuine reply can still complete the handshake.
pub struct PendingInitiatorHandshake {
    eph: EphemeralPair,
    static_secret: X25519Secret,
    responder_static_pub: X25519Public,
    psk: TunnelPsk,
    /// The Init message as sent, kept for transcript binding.
    init: HandshakeInit,
}

impl PendingInitiatorHandshake {
    /// Start a new initiator-side handshake.
    ///
    /// `timestamp` is the initiator's handshake clock (seconds); it must be
    /// strictly greater than any value this initiator previously sent to the
    /// same responder, which the responder enforces.
    ///
    /// Returns the handshake state and the `HandshakeInit` message to send.
    pub fn new(
        our_static_secret: X25519Secret,
        responder_static_pub: X25519Public,
        psk: TunnelPsk,
        timestamp: u64,
    ) -> Result<(Self, HandshakeInit), WireGuardError> {
        Self::build(
            our_static_secret,
            responder_static_pub,
            psk,
            timestamp,
            EphemeralPair::generate(),
        )
    }

    /// Deterministic variant for tests and fuzz corpora: the ephemeral key
    /// is supplied rather than drawn from the OS RNG.  Never used in
    /// production builds.
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn new_with_ephemeral(
        our_static_secret: X25519Secret,
        responder_static_pub: X25519Public,
        psk: TunnelPsk,
        timestamp: u64,
        ephemeral: [u8; 32],
    ) -> Result<(Self, HandshakeInit), WireGuardError> {
        Self::build(
            our_static_secret,
            responder_static_pub,
            psk,
            timestamp,
            EphemeralPair::from_bytes(ephemeral),
        )
    }

    fn build(
        our_static_secret: X25519Secret,
        responder_static_pub: X25519Public,
        psk: TunnelPsk,
        timestamp: u64,
        eph: EphemeralPair,
    ) -> Result<(Self, HandshakeInit), WireGuardError> {
        let our_static_pub = X25519Public::from(&our_static_secret);

        // es = DH(eph_i, static_r): hides our static key from passive
        // observers.
        let dh_es = eph.secret.diffie_hellman(&responder_static_pub);
        let enc_static = encrypt_static_key(our_static_pub.as_bytes(), dh_es.as_bytes())?;

        // ss = DH(static_i, static_r): proves we hold static_i.
        let dh_ss = our_static_secret.diffie_hellman(&responder_static_pub);
        let enc_timestamp = encrypt_timestamp(
            timestamp,
            dh_es.as_bytes(),
            dh_ss.as_bytes(),
            &psk,
            &eph.public.to_bytes(),
            &enc_static,
        )?;

        let init = HandshakeInit {
            eph_i_pub: eph.public.to_bytes(),
            enc_static,
            enc_timestamp,
        };

        let state = Self {
            eph,
            static_secret: our_static_secret,
            responder_static_pub,
            psk,
            init: init.clone(),
        };
        Ok((state, init))
    }

    /// Complete the handshake after receiving the responder's reply.
    ///
    /// Verifies the responder's confirmation tag before returning a session.
    /// On failure the pending state is untouched, so the caller keeps it for
    /// the genuine reply and only discards it after success or timeout.
    pub fn complete(
        &self,
        response: &HandshakeResponse,
        our_peer_id: PeerId,
        responder_peer_id: PeerId,
    ) -> Result<WireGuardSession, WireGuardError> {
        let eph_r_pub = X25519Public::from(response.eph_r_pub);

        // The four Noise_IK DH outputs, initiator view.
        let dh_es = self.eph.secret.diffie_hellman(&self.responder_static_pub);
        let dh_ss = self.static_secret.diffie_hellman(&self.responder_static_pub);
        let dh_ee = self.eph.secret.diffie_hellman(&eph_r_pub);
        let dh_se = self.static_secret.diffie_hellman(&eph_r_pub);

        let transcript = transcript_bytes(&self.init, &response.eph_r_pub, &self.psk);
        let dh = DhOutputs {
            es: dh_es.as_bytes(),
            ss: dh_ss.as_bytes(),
            ee: dh_ee.as_bytes(),
            se: dh_se.as_bytes(),
        };
        let keys = derive_session_keys(
            &dh,
            &self.psk,
            our_peer_id.as_bytes(),
            responder_peer_id.as_bytes(),
            &transcript,
        )?;

        // Responder key confirmation: the tag must verify under the derived
        // chaining key, which only the holder of static_r can compute.
        verify_confirm_tag(&keys.resp_confirm, &transcript, &response.confirm_tag)?;

        Ok(WireGuardSession::new(
            keys,
            responder_peer_id,
            true,
            self.psk.epoch(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Responder handshake
// ---------------------------------------------------------------------------

/// Handle an initiator's handshake initiation.
///
/// Steps, in fail-fast order:
/// 1. Decrypt the initiator's static key and compare it with
///    `expected_initiator_static_pub` — the key the caller knows for this
///    peer.  A mismatch is `InvalidPeerKey`.
/// 2. Verify the initiator's key confirmation (`enc_timestamp`) under
///    DH(eph_i, static_r) || DH(static_i, static_r) || PSK.  Failure is
///    `InitiatorUnconfirmed`; nothing has been derived or stored yet.
/// 3. Reject a timestamp not strictly newer than `last_init_timestamp`
///    (`HandshakeReplay`).
/// 4. Generate our ephemeral, derive the session, and build the reply with
///    our confirmation tag.
///
/// Returns the session, the response to send, and the accepted timestamp
/// which the caller must persist as the new `last_init_timestamp`.
pub fn respond_to_handshake(
    init: &HandshakeInit,
    our_static_secret: &X25519Secret,
    expected_initiator_static_pub: &X25519Public,
    psk: &TunnelPsk,
    our_peer_id: PeerId,
    initiator_peer_id: PeerId,
    last_init_timestamp: Option<u64>,
) -> Result<(WireGuardSession, HandshakeResponse, u64), WireGuardError> {
    let eph_r = EphemeralPair::generate();
    let eph_i_pub = X25519Public::from(init.eph_i_pub);

    // es = DH(static_r, eph_i): decrypt the initiator's static key.
    let dh_es = our_static_secret.diffie_hellman(&eph_i_pub);
    let init_static_bytes =
        decrypt_static_key(&init.enc_static, dh_es.as_bytes()).ok_or(WireGuardError::InvalidPeerKey)?;
    // The decrypted key must be the key we know for this peer.  Anyone can
    // encrypt arbitrary 32 bytes under es, so this comparison (and the
    // confirmation below) is what actually authenticates the initiator.
    if init_static_bytes != *expected_initiator_static_pub.as_bytes() {
        return Err(WireGuardError::InvalidPeerKey);
    }
    let init_static_pub = X25519Public::from(init_static_bytes);

    // ss = DH(static_r, static_i): only the real initiator can have mixed
    // this into enc_timestamp.
    let dh_ss = our_static_secret.diffie_hellman(&init_static_pub);
    let timestamp = decrypt_timestamp(
        &init.enc_timestamp,
        dh_es.as_bytes(),
        dh_ss.as_bytes(),
        psk,
        &init.eph_i_pub,
        &init.enc_static,
    )
    .ok_or(WireGuardError::InitiatorUnconfirmed)?;

    // Monotonic timestamp: a replayed Init cannot install a fresh session.
    if let Some(last) = last_init_timestamp {
        if timestamp <= last {
            return Err(WireGuardError::HandshakeReplay {
                timestamp,
                last_accepted: last,
            });
        }
    }

    // ee = DH(eph_r, eph_i), se = DH(eph_r, static_i).
    let dh_ee = eph_r.secret.diffie_hellman(&eph_i_pub);
    let dh_se = eph_r.secret.diffie_hellman(&init_static_pub);

    let eph_r_pub = eph_r.public.to_bytes();
    let transcript = transcript_bytes(init, &eph_r_pub, psk);
    let dh = DhOutputs {
        es: dh_es.as_bytes(),
        ss: dh_ss.as_bytes(),
        ee: dh_ee.as_bytes(),
        se: dh_se.as_bytes(),
    };
    let keys = derive_session_keys(
        &dh,
        psk,
        initiator_peer_id.as_bytes(),
        our_peer_id.as_bytes(),
        &transcript,
    )?;

    // Our key confirmation over the whole transcript.
    let confirm_tag = make_confirm_tag(&keys.resp_confirm, &transcript)?;

    let session = WireGuardSession::new(keys, initiator_peer_id, false, psk.epoch());

    Ok((
        session,
        HandshakeResponse {
            eph_r_pub,
            confirm_tag,
        },
        timestamp,
    ))
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// The authenticated transcript both sides bind into the chaining key and
/// the responder's confirmation tag:
/// `init bytes || header || eph_r_pub || psk context`.
fn transcript_bytes(init: &HandshakeInit, eph_r_pub: &[u8; 32], psk: &TunnelPsk) -> Vec<u8> {
    let mut t = Vec::with_capacity(HANDSHAKE_INIT_LEN + LINK_HEADER_LEN + 32 + 9);
    t.extend_from_slice(&init.to_bytes());
    t.extend_from_slice(&LINK_HEADER);
    t.extend_from_slice(eph_r_pub);
    t.extend_from_slice(&psk.context_bytes());
    t
}

/// The four Noise_IK Diffie-Hellman outputs, in chaining order.
struct DhOutputs<'a> {
    /// DH(eph_i, static_r) — hides the initiator's static key.
    es: &'a [u8],
    /// DH(static_i, static_r) — mutual authentication.
    ss: &'a [u8],
    /// DH(eph_i, eph_r) — forward secrecy.
    ee: &'a [u8],
    /// DH(static_i, eph_r) — binds the initiator's identity to this session.
    se: &'a [u8],
}

/// Derive symmetric session keys from the four DH outputs and the PSK.
///
/// The IKM (input keying material) is `es || ss || ee || se || psk`, where
/// the PSK is the per-epoch trusted-tunnel key (zeros if none).
///
/// Peer IDs are sorted lexicographically for the HKDF info parameter,
/// ensuring both sides compute identical keys regardless of which one
/// is the initiator.  The transcript (header, both ephemerals, encrypted
/// fields, PSK context) follows, so the keys are bound to exactly the
/// messages that were exchanged.
fn derive_session_keys(
    dh: &DhOutputs<'_>,
    psk: &TunnelPsk,
    peer_a: &[u8],
    peer_b: &[u8],
    transcript: &[u8],
) -> Result<SessionKeys, WireGuardError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(160));
    ikm.extend_from_slice(dh.es);
    ikm.extend_from_slice(dh.ss);
    ikm.extend_from_slice(dh.ee);
    ikm.extend_from_slice(dh.se);
    ikm.extend_from_slice(&*psk.key_bytes());

    // Sort peer IDs for deterministic info regardless of call order.
    let mut info = Vec::with_capacity(64 + transcript.len());
    if peer_a <= peer_b {
        info.extend_from_slice(peer_a);
        info.extend_from_slice(peer_b);
    } else {
        info.extend_from_slice(peer_b);
        info.extend_from_slice(peer_a);
    }
    info.extend_from_slice(transcript);

    let hk = Hkdf::<Sha256>::new(Some(SESSION_KEY_SALT), &ikm);

    let mut i_to_r = Zeroizing::new([0u8; 32]);
    let mut r_to_i = Zeroizing::new([0u8; 32]);
    let mut resp_confirm = Zeroizing::new([0u8; 32]);

    // Each output is expanded with the full info plus a direction label so
    // the three keys are independent.
    expand_labelled(&hk, &info, b"i_to_r", &mut i_to_r)?;
    expand_labelled(&hk, &info, b"r_to_i", &mut r_to_i)?;
    expand_labelled(&hk, &info, b"resp-confirm", &mut resp_confirm)?;

    Ok(SessionKeys {
        i_to_r,
        r_to_i,
        resp_confirm,
    })
}

/// HKDF-Expand with `info || label` into a 32-byte output.
fn expand_labelled(
    hk: &Hkdf<Sha256>,
    info: &[u8],
    label: &[u8],
    out: &mut [u8; 32],
) -> Result<(), WireGuardError> {
    let mut full = Vec::with_capacity(info.len() + label.len());
    full.extend_from_slice(info);
    full.extend_from_slice(label);
    hk.expand(&full, out)
        .map_err(|_| WireGuardError::KeyDerivation)
}

/// AAD for the static-key AEAD: purpose label plus the authenticated
/// header, so the ciphertext is bound to the declared version and suite.
fn static_key_aad() -> [u8; 10 + LINK_HEADER_LEN] {
    let mut aad = [0u8; 10 + LINK_HEADER_LEN];
    aad[..10].copy_from_slice(b"static-key");
    aad[10..].copy_from_slice(&LINK_HEADER);
    aad
}

/// Encrypt a 32-byte static public key under a DH output.
/// Returns 32 (ciphertext) + 16 (tag) = 48 bytes.
///
/// The static key is encrypted during the handshake to prevent passive
/// observers from learning the initiator's long-term identity.  This
/// is the same identity-hiding property that Noise_IK provides: an
/// eavesdropper sees only ephemeral keys in the clear.
///
/// The zero nonce is safe here because each DH output is unique per
/// handshake (it involves an ephemeral key), so the (key, nonce) pair
/// is never reused.
fn encrypt_static_key(static_pub: &[u8; 32], dh_key: &[u8]) -> Result<[u8; 48], WireGuardError> {
    let key = derive_aead_key(dh_key, b"aead-key")?;
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&*key));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let mut buf = static_pub.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, &static_key_aad(), &mut buf)
        .map_err(|_| WireGuardError::KeyDerivation)?;
    let mut out = [0u8; 48];
    out[..32].copy_from_slice(&buf);
    out[32..].copy_from_slice(tag.as_slice());
    Ok(out)
}

/// Decrypt a 48-byte encrypted static public key. Returns `None` on auth failure.
fn decrypt_static_key(enc: &[u8; 48], dh_key: &[u8]) -> Option<[u8; 32]> {
    let key = derive_aead_key(dh_key, b"aead-key").ok()?;
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&*key));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let mut buf = enc[..32].to_vec();
    let tag = GenericArray::from_slice(&enc[32..]);
    cipher
        .decrypt_in_place_detached(nonce, &static_key_aad(), &mut buf, tag)
        .ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf);
    Some(out)
}

/// AAD for the initiator's key-confirmation AEAD: everything that precedes
/// it on the wire plus the PSK context, so the confirmation is bound to this
/// exact Init.
fn timestamp_aad(eph_i_pub: &[u8; 32], enc_static: &[u8; 48], psk: &TunnelPsk) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LINK_HEADER_LEN + 32 + 48 + 9);
    aad.extend_from_slice(&LINK_HEADER);
    aad.extend_from_slice(eph_i_pub);
    aad.extend_from_slice(enc_static);
    aad.extend_from_slice(&psk.context_bytes());
    aad
}

/// Key for the initiator's confirmation AEAD: HKDF over es || ss || psk.
fn confirm_key(dh_es: &[u8], dh_ss: &[u8], psk: &TunnelPsk) -> Result<Zeroizing<[u8; 32]>, WireGuardError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(dh_es);
    ikm.extend_from_slice(dh_ss);
    ikm.extend_from_slice(&*psk.key_bytes());
    derive_aead_key(&ikm, b"init-confirm")
}

/// Produce the initiator's `enc_timestamp` field.
fn encrypt_timestamp(
    timestamp: u64,
    dh_es: &[u8],
    dh_ss: &[u8],
    psk: &TunnelPsk,
    eph_i_pub: &[u8; 32],
    enc_static: &[u8; 48],
) -> Result<[u8; 24], WireGuardError> {
    let key = confirm_key(dh_es, dh_ss, psk)?;
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&*key));
    // Zero nonce: the key includes a fresh ephemeral DH per handshake.
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let mut buf = timestamp.to_be_bytes().to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, &timestamp_aad(eph_i_pub, enc_static, psk), &mut buf)
        .map_err(|_| WireGuardError::KeyDerivation)?;
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(&buf);
    out[8..].copy_from_slice(tag.as_slice());
    Ok(out)
}

/// Verify and open the initiator's `enc_timestamp`. `None` on any failure.
fn decrypt_timestamp(
    enc: &[u8; 24],
    dh_es: &[u8],
    dh_ss: &[u8],
    psk: &TunnelPsk,
    eph_i_pub: &[u8; 32],
    enc_static: &[u8; 48],
) -> Option<u64> {
    let key = confirm_key(dh_es, dh_ss, psk).ok()?;
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&*key));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let mut buf = enc[..8].to_vec();
    let tag = GenericArray::from_slice(&enc[8..]);
    cipher
        .decrypt_in_place_detached(nonce, &timestamp_aad(eph_i_pub, enc_static, psk), &mut buf, tag)
        .ok()?;
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&buf);
    Some(u64::from_be_bytes(ts))
}

/// Produce the responder's 16-byte confirmation tag: an AEAD over the empty
/// string with the transcript as associated data.
fn make_confirm_tag(key: &[u8; 32], transcript: &[u8]) -> Result<[u8; 16], WireGuardError> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let mut empty = Vec::new();
    let tag = cipher
        .encrypt_in_place_detached(nonce, transcript, &mut empty)
        .map_err(|_| WireGuardError::KeyDerivation)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    Ok(out)
}

/// Verify the responder's confirmation tag.
fn verify_confirm_tag(key: &[u8; 32], transcript: &[u8], tag: &[u8; 16]) -> Result<(), WireGuardError> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let mut empty = Vec::new();
    cipher
        .decrypt_in_place_detached(nonce, transcript, &mut empty, GenericArray::from_slice(tag))
        .map_err(|_| WireGuardError::ResponderUnconfirmed)
}

/// Derive an AEAD encryption key from raw DH shared-secret material.
///
/// Raw DH outputs should never be used directly as encryption keys
/// because they have non-uniform distribution (not all 256 values are
/// equally likely per byte).  HKDF extracts the entropy from the DH
/// output and expands it into a uniformly distributed key suitable
/// for ChaCha20-Poly1305.  `label` separates the handshake's AEAD keys.
fn derive_aead_key(ikm: &[u8], label: &[u8]) -> Result<Zeroizing<[u8; 32]>, WireGuardError> {
    let hk = Hkdf::<Sha256>::new(Some(SESSION_KEY_SALT), ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(label, &mut *key)
        .map_err(|_| WireGuardError::KeyDerivation)?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Session Store
// ---------------------------------------------------------------------------

/// Manages active link sessions per peer, plus the per-initiator handshake
/// timestamp high-water mark that makes a replayed Init rejectable.
#[derive(Default)]
pub struct WireGuardSessionStore {
    sessions: std::collections::HashMap<PeerId, WireGuardSession>,
    /// Highest accepted Init timestamp per initiator peer.
    last_init_ts: std::collections::HashMap<PeerId, u64>,
}

impl WireGuardSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a confirmed session, replacing any previous one for the peer.
    /// Only call after the handshake's key confirmation succeeded.
    pub fn insert(&mut self, peer_id: PeerId, session: WireGuardSession) {
        self.sessions.insert(peer_id, session);
    }

    pub fn get(&self, peer_id: &PeerId) -> Option<&WireGuardSession> {
        self.sessions.get(peer_id)
    }

    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut WireGuardSession> {
        self.sessions.get_mut(peer_id)
    }

    pub fn remove(&mut self, peer_id: &PeerId) {
        self.sessions.remove(peer_id);
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Whether the session with `peer_id` carries a tunnel PSK (§5.2).
    /// `false` when there is no session at all: no tunnel, no trusted tier.
    pub fn psk_present(&self, peer_id: &PeerId) -> bool {
        self.sessions
            .get(peer_id)
            .map(WireGuardSession::psk_present)
            .unwrap_or(false)
    }

    /// Highest Init timestamp accepted from `peer_id`, for
    /// `respond_to_handshake`'s replay check.
    pub fn last_init_timestamp(&self, peer_id: &PeerId) -> Option<u64> {
        self.last_init_ts.get(peer_id).copied()
    }

    /// Record the timestamp of an Init that passed confirmation.
    pub fn record_init_timestamp(&mut self, peer_id: PeerId, timestamp: u64) {
        let slot = self.last_init_ts.entry(peer_id).or_insert(0);
        if timestamp > *slot {
            *slot = timestamp;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    fn peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    fn psk() -> TunnelPsk {
        TunnelPsk::Epoch {
            key: Zeroizing::new([0xABu8; 32]),
            epoch: 1,
        }
    }

    fn gen_static() -> X25519Secret {
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        X25519Secret::from(bytes)
    }

    /// Full handshake with a PSK; returns both sessions.
    fn make_session_pair() -> (WireGuardSession, WireGuardSession) {
        make_pair_with_psk(psk(), psk())
    }

    fn make_pair_with_psk(init_psk: TunnelPsk, resp_psk: TunnelPsk) -> (WireGuardSession, WireGuardSession) {
        let init_static = gen_static();
        let init_static_pub = X25519Public::from(&init_static);
        let resp_static = gen_static();
        let resp_static_pub = X25519Public::from(&resp_static);

        let (init_state, init_msg) =
            PendingInitiatorHandshake::new(init_static, resp_static_pub, init_psk, 1000).unwrap();

        let (resp_session, resp_msg, ts) = respond_to_handshake(
            &init_msg,
            &resp_static,
            &init_static_pub,
            &resp_psk,
            peer(0x02),
            peer(0x01),
            None,
        )
        .unwrap();
        assert_eq!(ts, 1000);

        let init_session = init_state
            .complete(&resp_msg, peer(0x01), peer(0x02))
            .unwrap();

        (init_session, resp_session)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (init_session, resp_session) = make_session_pair();
        let plaintext = b"hello wireguard";
        let encrypted = init_session.encrypt(plaintext).unwrap();
        let decrypted = resp_session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_no_psk_roundtrip_and_flag() {
        let (a, b) = make_pair_with_psk(TunnelPsk::None, TunnelPsk::None);
        assert!(!a.psk_present());
        assert!(!b.psk_present());
        let enc = a.encrypt(b"no psk").unwrap();
        assert_eq!(b.decrypt(&enc).unwrap(), b"no psk");
        let (c, _) = make_session_pair();
        assert!(c.psk_present());
        assert_eq!(c.psk_epoch(), Some(1));
    }

    #[test]
    fn test_replay_protection() {
        let (init_session, resp_session) = make_session_pair();
        let encrypted = init_session.encrypt(b"test").unwrap();
        resp_session.decrypt(&encrypted).unwrap();
        let err = resp_session.decrypt(&encrypted).unwrap_err();
        assert!(matches!(err, WireGuardError::ReplayDetected));
    }

    #[test]
    fn test_multiple_packets() {
        let (init_session, resp_session) = make_session_pair();
        for i in 0u8..20 {
            let msg = vec![i; 64];
            let enc = init_session.encrypt(&msg).unwrap();
            let dec = resp_session.decrypt(&enc).unwrap();
            assert_eq!(dec, msg);
        }
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (init_session, resp_session) = make_session_pair();
        let mut enc = init_session.encrypt(b"secret data").unwrap();
        let mid = enc.len() / 2;
        enc[mid] ^= 0xFF;
        let err = resp_session.decrypt(&enc).unwrap_err();
        assert!(matches!(err, WireGuardError::DecryptionFailed));
    }

    /// Adversarial (finding 2026-10-21-wireguard-replay-window-updated-before-auth):
    /// a forged packet with a huge nonce and a bad tag must not advance the
    /// window; the genuine packets that follow must still decrypt.
    #[test]
    fn test_forged_nonce_does_not_poison_replay_window() {
        let (init_session, resp_session) = make_session_pair();
        // Forged packet: nonce near u64::MAX, garbage body.
        let mut forged = Vec::new();
        forged.extend_from_slice(&(u64::MAX - 1).to_le_bytes());
        forged.extend_from_slice(&[0x5Au8; 40]);
        assert_eq!(resp_session.decrypt(&forged), Err(WireGuardError::DecryptionFailed));
        // Forged packet with the *next genuine* nonce (0) and a bad tag.
        let mut forged_next = Vec::new();
        forged_next.extend_from_slice(&0u64.to_le_bytes());
        forged_next.extend_from_slice(&[0x00u8; 40]);
        assert_eq!(resp_session.decrypt(&forged_next), Err(WireGuardError::DecryptionFailed));
        // Window untouched: genuine nonce 0 and later nonces decrypt.
        for i in 0..5u8 {
            let enc = init_session.encrypt(&[i; 8]).unwrap();
            assert_eq!(resp_session.decrypt(&enc).unwrap(), vec![i; 8]);
        }
        assert_eq!(*resp_session.recv_high.lock().unwrap(), 4);
    }

    /// Packets far behind the window are rejected; packets reordered within
    /// the window are accepted exactly once.
    #[test]
    fn test_window_reordering_and_expiry() {
        let (init_session, resp_session) = make_session_pair();
        let packets: Vec<Vec<u8>> = (0..(REPLAY_WINDOW as usize + 10))
            .map(|i| init_session.encrypt(&(i as u32).to_le_bytes()).unwrap())
            .collect();
        // Deliver the newest first to push the high-water mark.
        resp_session.decrypt(packets.last().unwrap()).unwrap();
        // Nonce 0 is now older than high - WINDOW: rejected.
        assert_eq!(resp_session.decrypt(&packets[0]), Err(WireGuardError::ReplayDetected));
        // A packet inside the window arrives late: accepted once.
        let inside = &packets[REPLAY_WINDOW as usize];
        resp_session.decrypt(inside).unwrap();
        assert_eq!(resp_session.decrypt(inside), Err(WireGuardError::ReplayDetected));
    }

    #[test]
    fn test_bidirectional() {
        // Both sides can send and receive.
        let (init_session, resp_session) = make_session_pair();

        let enc1 = init_session.encrypt(b"from initiator").unwrap();
        let dec1 = resp_session.decrypt(&enc1).unwrap();
        assert_eq!(dec1, b"from initiator");

        let enc2 = resp_session.encrypt(b"from responder").unwrap();
        let dec2 = init_session.decrypt(&enc2).unwrap();
        assert_eq!(dec2, b"from responder");
    }

    #[test]
    fn test_session_store() {
        let mut store = WireGuardSessionStore::new();
        let (session, _) = make_session_pair();
        let pid = peer(0x42);
        store.insert(pid, session);
        assert_eq!(store.len(), 1);
        assert!(store.get(&pid).is_some());
        assert!(store.psk_present(&pid));
        assert!(!store.psk_present(&peer(0x43)));
        store.record_init_timestamp(pid, 50);
        store.record_init_timestamp(pid, 40); // never moves backwards
        assert_eq!(store.last_init_timestamp(&pid), Some(50));
        store.remove(&pid);
        assert!(store.is_empty());
    }

    // -----------------------------------------------------------------------
    // Fixed suite (§5.1)
    // -----------------------------------------------------------------------

    /// A peer that declares any other suite id is rejected with a typed
    /// error and never reaches the cryptographic steps.
    #[test]
    fn test_foreign_suite_id_rejected() {
        let init_static = gen_static();
        let resp_static = gen_static();
        let (_, init_msg) = PendingInitiatorHandshake::new(
            init_static,
            X25519Public::from(&resp_static),
            TunnelPsk::None,
            1,
        )
        .unwrap();
        let mut bytes = init_msg.to_bytes();
        for foreign in [0x00u8, 0x02, 0x7F, 0xFF] {
            bytes[2] = foreign;
            assert_eq!(
                HandshakeInit::from_bytes(&bytes),
                Err(WireGuardError::UnsupportedSuite { declared: foreign })
            );
        }
        // Responses are checked the same way.
        let mut resp = [0u8; HANDSHAKE_RESPONSE_LEN];
        resp[..3].copy_from_slice(&LINK_HEADER);
        resp[2] = 0x02;
        assert_eq!(
            HandshakeResponse::from_bytes(&resp),
            Err(WireGuardError::UnsupportedSuite { declared: 0x02 })
        );
    }

    /// A different protocol version is an incompatible peer, reported
    /// before the suite byte is even looked at.
    #[test]
    fn test_foreign_version_rejected() {
        let mut bytes = [0u8; HANDSHAKE_INIT_LEN];
        bytes[..3].copy_from_slice(&LINK_HEADER);
        bytes[1] = 7;
        bytes[2] = 0x55; // would be an unsupported suite too
        assert_eq!(
            HandshakeInit::from_bytes(&bytes),
            Err(WireGuardError::IncompatibleVersion { major: 1, minor: 7 })
        );
        bytes[0] = 2;
        bytes[1] = LINK_VERSION_MINOR;
        assert_eq!(
            HandshakeInit::from_bytes(&bytes),
            Err(WireGuardError::IncompatibleVersion { major: 2, minor: 6 })
        );
    }

    /// The header is authenticated: flipping it after the fact breaks the
    /// static-key AEAD even if the parser were bypassed.
    #[test]
    fn test_header_bound_into_handshake_aead() {
        let init_static = gen_static();
        let init_static_pub = X25519Public::from(&init_static);
        let resp_static = gen_static();
        let (_, mut init_msg) = PendingInitiatorHandshake::new(
            init_static,
            X25519Public::from(&resp_static),
            TunnelPsk::None,
            1,
        )
        .unwrap();
        // Simulate a peer that encrypted under a different header by
        // re-encrypting the static key with a wrong aad: tamper a byte.
        init_msg.enc_static[0] ^= 1;
        let err = respond_to_handshake(
            &init_msg,
            &resp_static,
            &init_static_pub,
            &TunnelPsk::None,
            peer(2),
            peer(1),
            None,
        )
        .unwrap_err();
        assert_eq!(err, WireGuardError::InvalidPeerKey);
    }

    /// Wire round trips and length negatives for both messages.
    #[test]
    fn test_wire_roundtrip_and_truncation() {
        let (init_session_state, init_msg) = PendingInitiatorHandshake::new(
            gen_static(),
            X25519Public::from(&gen_static()),
            psk(),
            9,
        )
        .unwrap();
        let bytes = init_msg.to_bytes();
        assert_eq!(bytes.len(), HANDSHAKE_INIT_LEN);
        assert_eq!(HandshakeInit::from_bytes(&bytes).unwrap(), init_msg);
        for cut in [0usize, 1, 3, 35, 83, HANDSHAKE_INIT_LEN - 1] {
            assert_eq!(
                HandshakeInit::from_bytes(&bytes[..cut]),
                Err(WireGuardError::MalformedHandshake {
                    expected: HANDSHAKE_INIT_LEN,
                    actual: cut
                })
            );
        }
        let mut padded = bytes.to_vec();
        padded.push(0);
        assert!(matches!(
            HandshakeInit::from_bytes(&padded),
            Err(WireGuardError::MalformedHandshake { .. })
        ));
        let resp = HandshakeResponse {
            eph_r_pub: [7u8; 32],
            confirm_tag: [8u8; 16],
        };
        let rb = resp.to_bytes();
        assert_eq!(HandshakeResponse::from_bytes(&rb).unwrap(), resp);
        assert!(matches!(
            HandshakeResponse::from_bytes(&rb[..HANDSHAKE_RESPONSE_LEN - 1]),
            Err(WireGuardError::MalformedHandshake { .. })
        ));
        drop(init_session_state);
    }

    // -----------------------------------------------------------------------
    // Key confirmation (finding 2026-10-21-wireguard-handshake-no-key-confirmation)
    // -----------------------------------------------------------------------

    /// A forged Init from someone who knows only the responder's public key
    /// (and claims the victim's static key) is rejected: the decrypted
    /// static key is checked and the key confirmation fails.
    #[test]
    fn test_forged_init_rejected() {
        let victim_static = gen_static();
        let victim_pub = X25519Public::from(&victim_static);
        let resp_static = gen_static();
        let resp_pub = X25519Public::from(&resp_static);

        // Attacker uses their own static key: the decrypted key mismatches.
        let (_, forged) =
            PendingInitiatorHandshake::new(gen_static(), resp_pub, TunnelPsk::None, 1).unwrap();
        assert_eq!(
            respond_to_handshake(&forged, &resp_static, &victim_pub, &TunnelPsk::None, peer(2), peer(1), None)
                .unwrap_err(),
            WireGuardError::InvalidPeerKey
        );

        // Attacker encrypts the victim's public key under es (which anyone
        // can compute) but cannot produce the ss-bound confirmation.
        let (_, genuine) =
            PendingInitiatorHandshake::new(victim_static, resp_pub, TunnelPsk::None, 1).unwrap();
        let attacker_eph = EphemeralPair::generate();
        let dh_es = attacker_eph.secret.diffie_hellman(&resp_pub);
        let enc_static = encrypt_static_key(victim_pub.as_bytes(), dh_es.as_bytes()).unwrap();
        let spliced = HandshakeInit {
            eph_i_pub: attacker_eph.public.to_bytes(),
            enc_static,
            enc_timestamp: genuine.enc_timestamp, // copied from a real Init
        };
        assert_eq!(
            respond_to_handshake(&spliced, &resp_static, &victim_pub, &TunnelPsk::None, peer(2), peer(1), None)
                .unwrap_err(),
            WireGuardError::InitiatorUnconfirmed
        );
    }

    /// A trusted-tier handshake fails when the initiator lacks the PSK: the
    /// confirmation key mixes the PSK, so "public key only" cannot complete.
    #[test]
    fn test_psk_mismatch_rejected() {
        let init_static = gen_static();
        let init_pub = X25519Public::from(&init_static);
        let resp_static = gen_static();
        let (_, init_msg) = PendingInitiatorHandshake::new(
            init_static,
            X25519Public::from(&resp_static),
            TunnelPsk::None,
            1,
        )
        .unwrap();
        assert_eq!(
            respond_to_handshake(&init_msg, &resp_static, &init_pub, &psk(), peer(2), peer(1), None)
                .unwrap_err(),
            WireGuardError::InitiatorUnconfirmed
        );
    }

    /// A forged Response does not complete the handshake and leaves the
    /// pending state usable for the genuine Response.
    #[test]
    fn test_forged_response_does_not_consume_pending() {
        let init_static = gen_static();
        let init_pub = X25519Public::from(&init_static);
        let resp_static = gen_static();
        let (pending, init_msg) = PendingInitiatorHandshake::new(
            init_static,
            X25519Public::from(&resp_static),
            TunnelPsk::None,
            1,
        )
        .unwrap();
        let forged = HandshakeResponse {
            eph_r_pub: [0x42; 32],
            confirm_tag: [0; 16],
        };
        assert_eq!(
            pending.complete(&forged, peer(1), peer(2)).unwrap_err(),
            WireGuardError::ResponderUnconfirmed
        );
        // Genuine reply still completes.
        let (resp_session, resp_msg, _) = respond_to_handshake(
            &init_msg,
            &resp_static,
            &init_pub,
            &TunnelPsk::None,
            peer(2),
            peer(1),
            None,
        )
        .unwrap();
        let init_session = pending.complete(&resp_msg, peer(1), peer(2)).unwrap();
        let enc = init_session.encrypt(b"ok").unwrap();
        assert_eq!(resp_session.decrypt(&enc).unwrap(), b"ok");
        // A tampered genuine reply also fails.
        let mut tampered = resp_msg.clone();
        tampered.confirm_tag[3] ^= 1;
        assert_eq!(
            pending.complete(&tampered, peer(1), peer(2)).unwrap_err(),
            WireGuardError::ResponderUnconfirmed
        );
    }

    /// Replayed Init: the same bytes presented again, or an older timestamp,
    /// are rejected once the first timestamp has been recorded.
    #[test]
    fn test_replayed_init_rejected() {
        let init_static = gen_static();
        let init_pub = X25519Public::from(&init_static);
        let resp_static = gen_static();
        let resp_pub = X25519Public::from(&resp_static);
        let (_, first) =
            PendingInitiatorHandshake::new(X25519Secret::from(init_static.to_bytes()), resp_pub, TunnelPsk::None, 100).unwrap();
        let mut store = WireGuardSessionStore::new();
        let (session, _, ts) = respond_to_handshake(
            &first, &resp_static, &init_pub, &TunnelPsk::None, peer(2), peer(1),
            store.last_init_timestamp(&peer(1)),
        )
        .unwrap();
        store.insert(peer(1), session);
        store.record_init_timestamp(peer(1), ts);
        // Exact replay.
        assert_eq!(
            respond_to_handshake(
                &first, &resp_static, &init_pub, &TunnelPsk::None, peer(2), peer(1),
                store.last_init_timestamp(&peer(1)),
            )
            .unwrap_err(),
            WireGuardError::HandshakeReplay { timestamp: 100, last_accepted: 100 }
        );
        // Older timestamp from the genuine initiator.
        let (_, older) =
            PendingInitiatorHandshake::new(X25519Secret::from(init_static.to_bytes()), resp_pub, TunnelPsk::None, 99).unwrap();
        assert!(matches!(
            respond_to_handshake(
                &older, &resp_static, &init_pub, &TunnelPsk::None, peer(2), peer(1),
                store.last_init_timestamp(&peer(1)),
            ),
            Err(WireGuardError::HandshakeReplay { .. })
        ));
        // Newer timestamp succeeds.
        let (_, newer) =
            PendingInitiatorHandshake::new(init_static, resp_pub, TunnelPsk::None, 101).unwrap();
        assert!(respond_to_handshake(
            &newer, &resp_static, &init_pub, &TunnelPsk::None, peer(2), peer(1),
            store.last_init_timestamp(&peer(1)),
        )
        .is_ok());
    }

    // -----------------------------------------------------------------------
    // Trusted-tier gate and key provenance
    // -----------------------------------------------------------------------

    #[test]
    fn test_trusted_tier_requires_psk() {
        assert!(trusted_tier_enabled(TrustLevel::Trusted, true));
        assert!(trusted_tier_enabled(TrustLevel::InnerCircle, true));
        assert!(!trusted_tier_enabled(TrustLevel::Trusted, false));
        assert!(!trusted_tier_enabled(TrustLevel::Acquaintance, true));
    }

    #[test]
    fn test_key_source_default_requires_rekey() {
        let (mut s, _) = make_session_pair();
        assert!(s.key_source().rekey_required());
        s.set_key_source(StaticKeySource::RoleScoped { generation: 3 });
        assert!(!s.key_source().rekey_required());
    }

    // -----------------------------------------------------------------------
    // Endpoint pinning (§5.2)
    // -----------------------------------------------------------------------

    #[test]
    fn test_endpoint_policy_for_context() {
        let n = ThreatContext::Normal;
        assert_eq!(
            EndpointPolicy::for_context(n, ConnectionMode::Standard, 25),
            EndpointPolicy::Roaming { keepalive_secs: 25 }
        );
        assert_eq!(EndpointPolicy::for_context(n, ConnectionMode::LoSec, 25), EndpointPolicy::Pinned);
        assert_eq!(EndpointPolicy::for_context(n, ConnectionMode::Direct, 25), EndpointPolicy::Pinned);
        assert_eq!(
            EndpointPolicy::for_context(ThreatContext::Elevated, ConnectionMode::Standard, 25),
            EndpointPolicy::Pinned
        );
        assert_eq!(
            EndpointPolicy::for_context(ThreatContext::Critical, ConnectionMode::Standard, 25),
            EndpointPolicy::Pinned
        );
    }

    /// Pinned: a path change never moves the peer; the default policy is
    /// pinned so an unconfigured session fails closed.
    #[test]
    fn test_pinned_endpoint_rejects_move() {
        let (s, _) = make_session_pair();
        assert_eq!(s.endpoint_policy(), EndpointPolicy::Pinned);
        assert_eq!(s.observe_endpoint("tcp:10.0.0.1:1", 1), EndpointVerdict::Accepted);
        assert_eq!(s.observe_endpoint("tcp:10.0.0.1:1", 2), EndpointVerdict::Accepted);
        assert_eq!(
            s.observe_endpoint("tcp:10.0.0.9:1", 3),
            EndpointVerdict::Rejected {
                pinned: "tcp:10.0.0.1:1".into(),
                observed: "tcp:10.0.0.9:1".into()
            }
        );
        assert_eq!(s.endpoint().as_deref(), Some("tcp:10.0.0.1:1"));
        assert!(!s.rehandshake_pending());
    }

    /// Roaming: the peer moves, a re-handshake is due within one keepalive,
    /// and the session is overdue once that passes.
    #[test]
    fn test_roaming_endpoint_moves_and_demands_rehandshake() {
        let (mut s, _) = make_session_pair();
        s.set_endpoint_policy(EndpointPolicy::Roaming { keepalive_secs: 25 });
        assert_eq!(s.observe_endpoint("a", 100), EndpointVerdict::Accepted);
        assert_eq!(
            s.observe_endpoint("b", 110),
            EndpointVerdict::Moved { rehandshake_by: 135 }
        );
        assert_eq!(s.endpoint().as_deref(), Some("b"));
        assert!(s.rehandshake_pending());
        assert!(!s.rehandshake_overdue(135));
        assert!(s.rehandshake_overdue(136));
    }

    // -----------------------------------------------------------------------
    // Corpus replay (TESTING_METHODOLOGY.md)
    // -----------------------------------------------------------------------

    /// The fixed keys the corpus seeds were generated from.  Any seed that
    /// starts with a valid header is fed through the parser and the
    /// responder; only `seed_01_valid_init` may yield a session.
    pub(super) const CORPUS_INIT_STATIC: [u8; 32] = [0xAA; 32];
    pub(super) const CORPUS_RESP_STATIC: [u8; 32] = [0xBB; 32];
    pub(super) const CORPUS_EPHEMERAL: [u8; 32] = [0xCC; 32];
    pub(super) const CORPUS_TIMESTAMP: u64 = 1_700_000_000;

    /// Regenerate the deterministic valid Init the corpus commits.
    pub(super) fn corpus_valid_init() -> HandshakeInit {
        let (_, init) = PendingInitiatorHandshake::new_with_ephemeral(
            X25519Secret::from(CORPUS_INIT_STATIC),
            X25519Public::from(&X25519Secret::from(CORPUS_RESP_STATIC)),
            TunnelPsk::None,
            CORPUS_TIMESTAMP,
            CORPUS_EPHEMERAL,
        )
        .unwrap();
        init
    }

    #[test]
    fn test_handshake_corpus_replay() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/fuzz_wireguard_handshake");
        crate::testing::corpus::assert_corpus_dir_exists(&dir);
        let entries = crate::testing::corpus::load_corpus_entries(&dir).expect("read corpus");
        assert!(!entries.is_empty(), "corpus must have seeds");

        let resp_static = X25519Secret::from(CORPUS_RESP_STATIC);
        let init_pub = X25519Public::from(&X25519Secret::from(CORPUS_INIT_STATIC));
        let expected_valid = corpus_valid_init().to_bytes();
        let mut sessions = 0;
        for (path, bytes) in entries {
            // Every seed must parse-or-fail without panicking; the harness
            // mirrors fuzz_wireguard_handshake exactly.
            let Ok(init) = HandshakeInit::from_bytes(&bytes) else {
                let _ = HandshakeResponse::from_bytes(&bytes);
                continue;
            };
            if let Ok((session, response, ts)) = respond_to_handshake(
                &init,
                &resp_static,
                &init_pub,
                &TunnelPsk::None,
                PeerId([0x22; 32]),
                PeerId([0x11; 32]),
                None,
            ) {
                sessions += 1;
                assert_eq!(ts, CORPUS_TIMESTAMP, "unexpected pass: {path:?}");
                assert_eq!(bytes, expected_valid, "unexpected pass: {path:?}");
                // The seed's own response must parse and the session work.
                let rb = response.to_bytes();
                assert!(HandshakeResponse::from_bytes(&rb).is_ok());
                assert!(session.encrypt(b"x").is_ok());
            }
        }
        // Exactly one seed is the valid Init.
        assert_eq!(sessions, 1);
    }

    /// Emits the valid seed bytes for regeneration of the corpus after a
    /// deliberate wire-format change.  Run with `--nocapture` to read them.
    #[test]
    fn test_print_corpus_valid_init() {
        println!("seed_01_valid_init = {}", hex::encode(corpus_valid_init().to_bytes()));
    }
}
