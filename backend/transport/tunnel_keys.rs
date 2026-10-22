//! Tunnel Key Lifecycle and Trusted-Tunnel PSK Agreement (§5.2)
//!
//! Two pieces of §5.2 live here, both of them state that sits *beside* the
//! link handshake in `wireguard.rs` rather than inside it.
//!
//! # Tunnel key lifecycle
//!
//! A keypair used as a WireGuard static key is role-scoped to tunnel use
//! (§3.1.6).  For mask-level connections it is a separate keypair bound to
//! the mask's stable map identity key by a signed [`TunnelKeyBinding`].  A
//! [`TunnelKeyRing`] owns the current generation and, during an overlap
//! window, the previous one:
//!
//! - rotation every `interval_secs` (default 7 days), jittered so the
//!   cadence is not a fingerprint — the jitter only *shortens* the interval,
//!   so a key never lives longer than the default;
//! - immediate rotation on trust-level change, ThreatContext escalation or
//!   suspected compromise ([`RotationReason`]);
//! - the previous generation stays usable for `overlap_secs` (default 24
//!   hours) so live tunnels migrate, then is deleted — except after
//!   suspected compromise, where it is deleted at once.
//!
//! Each generation also carries the tunnel KEM prekey (ML-KEM-768) that the
//! PSK agreement encapsulates against.  The binding signs both keys, and the
//! binding is published only over the trusted channel, never in the map.
//!
//! # Trusted-tunnel PSK agreement
//!
//! For Level 6+ peers the PSK is derived per tunnel epoch from a fresh hybrid
//! exchange using the `MI-PQXDH-1` primitives:
//!
//! ```text
//! Initiator                                             Responder
//!    |-- PskInit(epoch, gen, eph_i, kem_ct, sig_i) ------->|
//!    |<-- PskResponse(epoch, eph_r, sig_r) ----------------|
//!
//! ecdh_ss    = X25519(eph_i, eph_r)
//! kem_ss     = ML-KEM-768 encaps/decaps against the responder's tunnel KEM prekey
//! tunnel_psk = HKDF-SHA512(ecdh_ss || kem_ss || channel_key, ...)   (crypto::channel_key)
//! ```
//!
//! Both messages are signed by the relationship (mask) Ed25519 keys and run
//! over an existing tunnel; the tunnel is then re-handshaken with the new
//! PSK.  Ephemeral secrets are erased after derivation.  If the agreement
//! cannot complete the tunnel stays a no-PSK tunnel and trusted-tier
//! features are withheld (`wireguard::trusted_tier_enabled`); the static
//! `channel_key` is never used as a PSK.
//!
//! # Untrusted input
//!
//! `TunnelKeyBinding::from_bytes`, `PskInit::from_bytes` and
//! `PskResponse::from_bytes` parse peer-supplied bytes.  They are total
//! functions over arbitrary input (typed errors, no panics) and are driven
//! by the `fuzz_wireguard_handshake` target together with the link
//! handshake parsers.

use kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand_core::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::crypto::channel_key::{derive_tunnel_psk, encode_tunnel_epoch, TunnelEpoch};
use crate::crypto::signing::{self, DOMAIN_TUNNEL_KEY_BINDING, DOMAIN_TUNNEL_PSK};
use crate::crypto::x3dh::{MlKem768Dk, MlKem768Ek, KEM_CT_SIZE, KEM_EK_SIZE};
use crate::identity::peer_id::PeerId;
use crate::transport::wireguard::{
    check_header, TunnelPsk, WireGuardError, LINK_HEADER, LINK_HEADER_LEN,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default tunnel key rotation interval: 7 days (§5.2).
// DEFAULT_ROTATION_SECS — spec default.
pub const DEFAULT_ROTATION_SECS: u64 = 7 * 24 * 60 * 60;

/// Default overlap during which the previous key stays valid: 24 hours.
// DEFAULT_OVERLAP_SECS — spec default.
pub const DEFAULT_OVERLAP_SECS: u64 = 24 * 60 * 60;

/// Default maximum jitter subtracted from the rotation interval: 12 hours.
///
/// The spec requires jitter without fixing its size.  Subtracting (never
/// adding) up to half a day keeps every key within the 7-day default while
/// spreading rotations across a wide enough window to defeat correlation.
// DEFAULT_MAX_JITTER_SECS — conservative implementation choice.
pub const DEFAULT_MAX_JITTER_SECS: u64 = 12 * 60 * 60;

/// Ed25519 signature length.
const SIG_LEN: usize = 64;

/// Wire length of a `TunnelKeyBinding`:
/// identity_pub(32) || tunnel_pub(32) || generation(8) || created_at(8) ||
/// kem_ek(1184) || signature(64).
pub const BINDING_LEN: usize = 32 + 32 + 8 + 8 + KEM_EK_SIZE + SIG_LEN;

/// Message-type byte of `PskInit`.
const PSK_MSG_INIT: u8 = 0x01;
/// Message-type byte of `PskResponse`.
const PSK_MSG_RESPONSE: u8 = 0x02;

/// Wire length of a `PskInit`:
/// header(3) || type(1) || epoch(8) || generation(8) || eph_pub(32) ||
/// kem_ct(1088) || signature(64).
pub const PSK_INIT_LEN: usize = LINK_HEADER_LEN + 1 + 8 + 8 + 32 + KEM_CT_SIZE + SIG_LEN;

/// Wire length of a `PskResponse`:
/// header(3) || type(1) || epoch(8) || eph_pub(32) || signature(64).
pub const PSK_RESPONSE_LEN: usize = LINK_HEADER_LEN + 1 + 8 + 32 + SIG_LEN;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed failures of the key lifecycle and PSK agreement.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TunnelKeyError {
    /// A message had the wrong length.
    #[error("malformed tunnel-key message: expected {expected} bytes, got {actual}")]
    Malformed { expected: usize, actual: usize },
    /// A message carried an unexpected type byte.
    #[error("unexpected tunnel-key message type {found:#04x}")]
    WrongMessageType { found: u8 },
    /// The link header was not `MI-LINK-1` / v1.6.
    #[error("link header rejected: {0}")]
    Link(#[from] WireGuardError),
    /// An Ed25519 signature did not verify.
    #[error("tunnel-key signature rejected")]
    BadSignature,
    /// The binding names a different identity than expected.
    #[error("tunnel-key binding is for another identity")]
    IdentityMismatch,
    /// The KEM prekey in a binding has the wrong size or is not a valid key.
    #[error("tunnel KEM prekey rejected")]
    BadKemKey,
    /// ML-KEM encapsulation or decapsulation failed.
    #[error("ML-KEM operation failed")]
    Kem,
    /// The initiator targeted a key generation we no longer (or never) hold.
    #[error("unknown or retired tunnel key generation {generation}")]
    UnknownGeneration { generation: u64 },
    /// The epoch is not newer than the last one agreed: replay.
    #[error("tunnel PSK epoch {epoch} not after {last}")]
    EpochReplay { epoch: u64, last: u64 },
    /// The response names a different epoch than the pending init.
    #[error("tunnel PSK response epoch mismatch")]
    EpochMismatch,
    /// Key generation or derivation failed.
    #[error("tunnel key derivation failed")]
    Derivation,
}

// ---------------------------------------------------------------------------
// Rotation schedule
// ---------------------------------------------------------------------------

/// Rotation timing parameters (§5.2, "Tunnel key lifecycle").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationSchedule {
    /// Nominal interval between scheduled rotations.
    pub interval_secs: u64,
    /// How long the previous generation stays valid after a rotation.
    pub overlap_secs: u64,
    /// Upper bound of the jitter subtracted from `interval_secs`.
    pub max_jitter_secs: u64,
}

impl Default for RotationSchedule {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_ROTATION_SECS,
            overlap_secs: DEFAULT_OVERLAP_SECS,
            max_jitter_secs: DEFAULT_MAX_JITTER_SECS,
        }
    }
}

impl RotationSchedule {
    /// Compute the next scheduled rotation time from `now`.
    ///
    /// `draw` is a random value; the jitter is `draw % (max_jitter + 1)` and
    /// is subtracted so the next rotation is never later than `interval`.
    /// The jitter is capped at the interval so the result is never before
    /// `now`.
    fn next_due(&self, now: u64, draw: u64) -> u64 {
        let jitter = draw % self.max_jitter_secs.saturating_add(1);
        let effective = self
            .interval_secs
            .saturating_sub(jitter.min(self.interval_secs));
        now.saturating_add(effective)
    }
}

/// Why a rotation happened.  The spec lists every trigger explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationReason {
    /// The scheduled (jittered) interval elapsed.
    Scheduled,
    /// The peer's trust level changed.
    TrustChange,
    /// ThreatContext was escalated.
    ThreatEscalation,
    /// Compromise of the current key is suspected: no overlap is granted.
    SuspectedCompromise,
    /// A bootstrap tunnel keyed with the identity key is being re-keyed.
    BootstrapRekey,
}

// ---------------------------------------------------------------------------
// Key generations
// ---------------------------------------------------------------------------

/// One generation of role-scoped tunnel key material.
pub struct TunnelKeyGeneration {
    /// Monotonic generation number, starting at 1.
    pub generation: u64,
    /// The X25519 tunnel static secret (WireGuard static key).
    x25519_secret: X25519Secret,
    /// Its public key.
    pub x25519_public: [u8; 32],
    /// ML-KEM-768 decapsulation key for the tunnel KEM prekey.
    kem_dk: Zeroizing<Vec<u8>>,
    /// ML-KEM-768 encapsulation key (the published tunnel KEM prekey).
    pub kem_ek: Vec<u8>,
    /// When this generation was created.
    pub created_at: u64,
    /// When this generation stops being accepted (set once superseded).
    pub retire_at: Option<u64>,
}

impl TunnelKeyGeneration {
    /// Generate fresh key material from the OS RNG.
    fn generate(generation: u64, now: u64) -> Self {
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        let x25519_secret = X25519Secret::from(bytes);
        let x25519_public = X25519Public::from(&x25519_secret).to_bytes();
        // ML-KEM-768 keypair via the FIPS 203 library API (§3.4.1).
        let (dk, ek) = MlKem768::generate(&mut rand_core::OsRng);
        Self {
            generation,
            x25519_secret,
            x25519_public,
            kem_dk: Zeroizing::new(dk.as_bytes().to_vec()),
            kem_ek: ek.as_bytes().to_vec(),
            created_at: now,
            retire_at: None,
        }
    }

    /// The X25519 static secret, for the link handshake.
    pub fn x25519_secret(&self) -> &X25519Secret {
        &self.x25519_secret
    }

    /// Whether this generation is still accepted at `now`.
    fn accepted_at(&self, now: u64) -> bool {
        self.retire_at.is_none_or(|t| now < t)
    }
}

// ---------------------------------------------------------------------------
// Signed binding
// ---------------------------------------------------------------------------

/// A signed binding of a tunnel key generation to a map identity key.
///
/// Exchanged in connection setup (over the trusted channel for the KEM
/// prekey); never published in the public map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelKeyBinding {
    /// The mask's stable Ed25519 map identity key.
    pub identity_pub: [u8; 32],
    /// The role-scoped X25519 tunnel static public key.
    pub tunnel_pub: [u8; 32],
    /// The ML-KEM-768 tunnel KEM prekey.
    pub kem_ek: Vec<u8>,
    /// Generation number of the bound keys.
    pub generation: u64,
    /// Creation time of the bound keys.
    pub created_at: u64,
    /// Ed25519 signature by `identity_pub` over the fields above.
    pub signature: Vec<u8>,
}

impl TunnelKeyBinding {
    /// The bytes covered by the signature.
    fn signed_message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(BINDING_LEN - SIG_LEN);
        m.extend_from_slice(&self.identity_pub);
        m.extend_from_slice(&self.tunnel_pub);
        m.extend_from_slice(&self.generation.to_be_bytes());
        m.extend_from_slice(&self.created_at.to_be_bytes());
        m.extend_from_slice(&self.kem_ek);
        m
    }

    /// Serialise to the fixed wire layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signed_message();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse the wire layout.  Only structure is checked here; call
    /// `verify_for` before trusting the contents.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TunnelKeyError> {
        if bytes.len() != BINDING_LEN {
            return Err(TunnelKeyError::Malformed {
                expected: BINDING_LEN,
                actual: bytes.len(),
            });
        }
        let mut identity_pub = [0u8; 32];
        identity_pub.copy_from_slice(&bytes[..32]);
        let mut tunnel_pub = [0u8; 32];
        tunnel_pub.copy_from_slice(&bytes[32..64]);
        let generation = u64::from_be_bytes(fixed8(&bytes[64..72]));
        let created_at = u64::from_be_bytes(fixed8(&bytes[72..80]));
        let kem_end = 80 + KEM_EK_SIZE;
        Ok(Self {
            identity_pub,
            tunnel_pub,
            kem_ek: bytes[80..kem_end].to_vec(),
            generation,
            created_at,
            signature: bytes[kem_end..].to_vec(),
        })
    }

    /// Verify the binding against the identity key we expect for the peer.
    ///
    /// Checks, in order: the binding names that identity, the signature
    /// verifies under it, and the KEM prekey is a well-formed ML-KEM-768
    /// encapsulation key.
    pub fn verify_for(&self, expected_identity_pub: &[u8; 32]) -> Result<(), TunnelKeyError> {
        if self.identity_pub != *expected_identity_pub {
            return Err(TunnelKeyError::IdentityMismatch);
        }
        if !signing::verify(
            &self.identity_pub,
            DOMAIN_TUNNEL_KEY_BINDING,
            &self.signed_message(),
            &self.signature,
        ) {
            return Err(TunnelKeyError::BadSignature);
        }
        // A binding with an unusable prekey is rejected up front rather than
        // at agreement time.
        parse_kem_ek(&self.kem_ek).map(|_| ())
    }
}

/// Copy an 8-byte slice into an array (caller guarantees the length).
fn fixed8(slice: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(slice);
    out
}

/// Deserialise an ML-KEM-768 encapsulation key.
fn parse_kem_ek(bytes: &[u8]) -> Result<MlKem768Ek, TunnelKeyError> {
    if bytes.len() != KEM_EK_SIZE {
        return Err(TunnelKeyError::BadKemKey);
    }
    let encoded = Encoded::<MlKem768Ek>::try_from(bytes).map_err(|_| TunnelKeyError::BadKemKey)?;
    Ok(EncodedSizeUser::from_bytes(&encoded))
}

// ---------------------------------------------------------------------------
// Key ring
// ---------------------------------------------------------------------------

/// The local node's tunnel key generations and rotation state.
pub struct TunnelKeyRing {
    current: TunnelKeyGeneration,
    previous: Option<TunnelKeyGeneration>,
    schedule: RotationSchedule,
    /// Time of the next scheduled rotation (jittered).
    next_rotation_at: u64,
}

impl TunnelKeyRing {
    /// Create a ring with a fresh first generation.
    pub fn new(now: u64, schedule: RotationSchedule) -> Self {
        let current = TunnelKeyGeneration::generate(1, now);
        let next_rotation_at = schedule.next_due(now, rand_core::OsRng.next_u64());
        Self {
            current,
            previous: None,
            schedule,
            next_rotation_at,
        }
    }

    /// The current generation.
    pub fn current(&self) -> &TunnelKeyGeneration {
        &self.current
    }

    /// The previous generation, if it is still inside its overlap window.
    pub fn previous(&self, now: u64) -> Option<&TunnelKeyGeneration> {
        self.previous.as_ref().filter(|g| g.accepted_at(now))
    }

    /// Every generation that may still complete a handshake at `now`:
    /// current first, then the overlapping previous one.
    pub fn accepted(&self, now: u64) -> Vec<&TunnelKeyGeneration> {
        let mut v = vec![&self.current];
        if let Some(p) = self.previous(now) {
            v.push(p);
        }
        v
    }

    /// Look up an accepted generation by number.
    pub fn generation(&self, generation: u64, now: u64) -> Option<&TunnelKeyGeneration> {
        self.accepted(now)
            .into_iter()
            .find(|g| g.generation == generation)
    }

    /// When the next scheduled rotation is due.
    pub fn next_rotation_at(&self) -> u64 {
        self.next_rotation_at
    }

    /// The schedule in force.
    pub fn schedule(&self) -> RotationSchedule {
        self.schedule
    }

    /// Rotate now for `reason`.  Returns the new generation number.
    ///
    /// The superseded generation becomes `previous` with
    /// `retire_at = now + overlap`, except on suspected compromise, where it
    /// is deleted immediately.  Any older previous generation is dropped
    /// (and zeroized) regardless.
    pub fn rotate(&mut self, now: u64, reason: RotationReason) -> u64 {
        let next_gen = self.current.generation.saturating_add(1);
        let fresh = TunnelKeyGeneration::generate(next_gen, now);
        let mut old = std::mem::replace(&mut self.current, fresh);
        // Dropping the older previous generation zeroizes its secrets.
        self.previous = None;
        if reason != RotationReason::SuspectedCompromise {
            old.retire_at = Some(now.saturating_add(self.schedule.overlap_secs));
            self.previous = Some(old);
        }
        self.next_rotation_at = self.schedule.next_due(now, rand_core::OsRng.next_u64());
        next_gen
    }

    /// Advance the clock: perform a scheduled rotation if due and delete
    /// the previous generation once its overlap ends.  Returns the reason
    /// if a rotation happened.
    pub fn tick(&mut self, now: u64) -> Option<RotationReason> {
        // Prune first so a rotation at the same instant never keeps two
        // retired generations around.
        if self.previous.as_ref().is_some_and(|g| !g.accepted_at(now)) {
            self.previous = None;
        }
        if now >= self.next_rotation_at {
            self.rotate(now, RotationReason::Scheduled);
            return Some(RotationReason::Scheduled);
        }
        None
    }

    /// Produce the signed binding of the current generation to the mask's
    /// identity key.
    pub fn binding(
        &self,
        identity_signing_secret: &[u8; 32],
        identity_pub: [u8; 32],
    ) -> TunnelKeyBinding {
        let mut binding = TunnelKeyBinding {
            identity_pub,
            tunnel_pub: self.current.x25519_public,
            kem_ek: self.current.kem_ek.clone(),
            generation: self.current.generation,
            created_at: self.current.created_at,
            signature: Vec::new(),
        };
        binding.signature = signing::sign(
            identity_signing_secret,
            DOMAIN_TUNNEL_KEY_BINDING,
            &binding.signed_message(),
        );
        binding
    }
}

// ---------------------------------------------------------------------------
// PSK agreement messages
// ---------------------------------------------------------------------------

/// Everything both agreement messages need to know about the two peers.
pub struct PskPeerContext {
    /// Our relationship (mask) Ed25519 signing secret.
    pub our_signing_secret: [u8; 32],
    /// The peer's relationship (mask) Ed25519 public key.
    pub their_signing_pub: [u8; 32],
    /// Our peer id.
    pub our_peer_id: PeerId,
    /// The peer's peer id.
    pub their_peer_id: PeerId,
}

impl PskPeerContext {
    /// Sorted peer ids, appended to every signed agreement message so a
    /// message cannot be replayed between relationships.
    fn sorted_ids(&self) -> [u8; 64] {
        let (a, b) = if self.our_peer_id.0 < self.their_peer_id.0 {
            (&self.our_peer_id, &self.their_peer_id)
        } else {
            (&self.their_peer_id, &self.our_peer_id)
        };
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(a.as_bytes());
        out[32..].copy_from_slice(b.as_bytes());
        out
    }
}

/// First agreement message, initiator to responder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskInit {
    /// The epoch being agreed.
    pub epoch: TunnelEpoch,
    /// The responder key generation whose KEM prekey was encapsulated to.
    pub target_generation: u64,
    /// Initiator's ephemeral X25519 public key.
    pub eph_pub: [u8; 32],
    /// ML-KEM-768 ciphertext against the responder's tunnel KEM prekey.
    pub kem_ct: Vec<u8>,
    /// Initiator's signature over the fields above plus the peer ids.
    pub signature: Vec<u8>,
}

impl PskInit {
    /// The message prefix (everything but the signature).
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(PSK_INIT_LEN - SIG_LEN);
        m.extend_from_slice(&LINK_HEADER);
        m.push(PSK_MSG_INIT);
        m.extend_from_slice(&encode_tunnel_epoch(self.epoch));
        m.extend_from_slice(&self.target_generation.to_be_bytes());
        m.extend_from_slice(&self.eph_pub);
        m.extend_from_slice(&self.kem_ct);
        m
    }

    /// The bytes the initiator signs: prefix plus sorted peer ids.
    fn signed_message(&self, ctx: &PskPeerContext) -> Vec<u8> {
        let mut m = self.unsigned_bytes();
        m.extend_from_slice(&ctx.sorted_ids());
        m
    }

    /// Serialise to the fixed wire layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.unsigned_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse the wire layout: length, then header, then type byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TunnelKeyError> {
        if bytes.len() != PSK_INIT_LEN {
            return Err(TunnelKeyError::Malformed {
                expected: PSK_INIT_LEN,
                actual: bytes.len(),
            });
        }
        check_header(&bytes[..LINK_HEADER_LEN])?;
        if bytes[3] != PSK_MSG_INIT {
            return Err(TunnelKeyError::WrongMessageType { found: bytes[3] });
        }
        let epoch = u64::from_be_bytes(fixed8(&bytes[4..12]));
        let target_generation = u64::from_be_bytes(fixed8(&bytes[12..20]));
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(&bytes[20..52]);
        let ct_end = 52 + KEM_CT_SIZE;
        Ok(Self {
            epoch,
            target_generation,
            eph_pub,
            kem_ct: bytes[52..ct_end].to_vec(),
            signature: bytes[ct_end..].to_vec(),
        })
    }
}

/// Second agreement message, responder to initiator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskResponse {
    /// The epoch being agreed (must equal the init's).
    pub epoch: TunnelEpoch,
    /// Responder's ephemeral X25519 public key.
    pub eph_pub: [u8; 32],
    /// Responder's signature over the init bytes, these fields and the ids.
    pub signature: Vec<u8>,
}

impl PskResponse {
    /// The message prefix (everything but the signature).
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(PSK_RESPONSE_LEN - SIG_LEN);
        m.extend_from_slice(&LINK_HEADER);
        m.push(PSK_MSG_RESPONSE);
        m.extend_from_slice(&encode_tunnel_epoch(self.epoch));
        m.extend_from_slice(&self.eph_pub);
        m
    }

    /// The bytes the responder signs: the full init as received, then this
    /// message's prefix, then the sorted peer ids.  Binding the init means a
    /// response cannot be transplanted onto a different init.
    fn signed_message(&self, init_bytes: &[u8], ctx: &PskPeerContext) -> Vec<u8> {
        let mut m = Vec::with_capacity(init_bytes.len() + PSK_RESPONSE_LEN + 64);
        m.extend_from_slice(init_bytes);
        m.extend_from_slice(&self.unsigned_bytes());
        m.extend_from_slice(&ctx.sorted_ids());
        m
    }

    /// Serialise to the fixed wire layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.unsigned_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse the wire layout.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TunnelKeyError> {
        if bytes.len() != PSK_RESPONSE_LEN {
            return Err(TunnelKeyError::Malformed {
                expected: PSK_RESPONSE_LEN,
                actual: bytes.len(),
            });
        }
        check_header(&bytes[..LINK_HEADER_LEN])?;
        if bytes[3] != PSK_MSG_RESPONSE {
            return Err(TunnelKeyError::WrongMessageType { found: bytes[3] });
        }
        let epoch = u64::from_be_bytes(fixed8(&bytes[4..12]));
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(&bytes[12..44]);
        Ok(Self {
            epoch,
            eph_pub,
            signature: bytes[44..].to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// PSK agreement — initiator
// ---------------------------------------------------------------------------

/// Initiator-side agreement state, held until the response verifies.
pub struct PskInitiator {
    eph_secret: X25519Secret,
    kem_ss: Zeroizing<[u8; 32]>,
    channel_key: Zeroizing<[u8; 32]>,
    epoch: TunnelEpoch,
    /// The init as sent, for the response's transcript binding.
    init_bytes: Vec<u8>,
}

/// Redacting `Debug`: the epoch only, never the ephemeral or KEM secrets.
impl std::fmt::Debug for PskInitiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PskInitiator {{ epoch: {}, secrets: <redacted> }}",
            self.epoch
        )
    }
}

/// Start a PSK agreement against the peer's verified tunnel-key binding.
///
/// `their_binding` must already have passed `verify_for`; it is re-verified
/// here anyway so a caller cannot skip the check.  `epoch` must be strictly
/// greater than every epoch previously agreed with this peer.
pub fn psk_initiate(
    ctx: &PskPeerContext,
    their_binding: &TunnelKeyBinding,
    channel_key: Zeroizing<[u8; 32]>,
    epoch: TunnelEpoch,
) -> Result<(PskInitiator, PskInit), TunnelKeyError> {
    their_binding.verify_for(&ctx.their_signing_pub)?;
    let ek = parse_kem_ek(&their_binding.kem_ek)?;

    // ML-KEM-768 encapsulation against the tunnel KEM prekey.
    let (kem_ct, kem_ss_raw) = ek
        .encapsulate(&mut rand_core::OsRng)
        .map_err(|_| TunnelKeyError::Kem)?;
    let mut kem_ss = Zeroizing::new([0u8; 32]);
    kem_ss.copy_from_slice(kem_ss_raw.as_slice());

    // Fresh ephemeral X25519 key.
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let eph_secret = X25519Secret::from(bytes);
    let eph_pub = X25519Public::from(&eph_secret).to_bytes();

    let mut init = PskInit {
        epoch,
        target_generation: their_binding.generation,
        eph_pub,
        kem_ct: kem_ct.as_slice().to_vec(),
        signature: Vec::new(),
    };
    init.signature = signing::sign(
        &ctx.our_signing_secret,
        DOMAIN_TUNNEL_PSK,
        &init.signed_message(ctx),
    );

    let state = PskInitiator {
        eph_secret,
        kem_ss,
        channel_key,
        epoch,
        init_bytes: init.to_bytes(),
    };
    Ok((state, init))
}

impl PskInitiator {
    /// The epoch this agreement is for.
    pub fn epoch(&self) -> TunnelEpoch {
        self.epoch
    }

    /// Verify the response and derive the PSK.  Consumes the state so the
    /// ephemeral secret and KEM secret are dropped (zeroized) exactly once.
    pub fn complete(
        self,
        response: &PskResponse,
        ctx: &PskPeerContext,
    ) -> Result<TunnelPsk, TunnelKeyError> {
        if response.epoch != self.epoch {
            return Err(TunnelKeyError::EpochMismatch);
        }
        if !signing::verify(
            &ctx.their_signing_pub,
            DOMAIN_TUNNEL_PSK,
            &response.signed_message(&self.init_bytes, ctx),
            &response.signature,
        ) {
            return Err(TunnelKeyError::BadSignature);
        }
        // ecdh_ss = X25519(my_ephemeral_secret, their_ephemeral_public).
        let ecdh = self
            .eph_secret
            .diffie_hellman(&X25519Public::from(response.eph_pub));
        let ecdh_ss = Zeroizing::new(*ecdh.as_bytes());
        let key = derive_tunnel_psk(
            &ecdh_ss,
            &self.kem_ss,
            &self.channel_key,
            &ctx.our_peer_id,
            &ctx.their_peer_id,
            self.epoch,
        )
        .map_err(|_| TunnelKeyError::Derivation)?;
        Ok(TunnelPsk::Epoch {
            key,
            epoch: self.epoch,
        })
    }
}

// ---------------------------------------------------------------------------
// PSK agreement — responder
// ---------------------------------------------------------------------------

/// Responder inputs that are not part of the peer context.
pub struct PskResponderInputs<'a> {
    /// Our tunnel key ring (holds the KEM decapsulation keys).
    pub ring: &'a TunnelKeyRing,
    /// The static relationship key of §3.2.
    pub channel_key: Zeroizing<[u8; 32]>,
    /// The last epoch agreed with this peer, for replay rejection.
    pub last_epoch: Option<TunnelEpoch>,
    /// Current time, for generation acceptance.
    pub now: u64,
}

/// Verify a `PskInit`, derive the PSK and build the signed response.
///
/// Order: signature, epoch monotonicity, generation lookup, decapsulation,
/// derivation.  Nothing is derived before the init is authenticated.
pub fn psk_respond(
    init: &PskInit,
    ctx: &PskPeerContext,
    inputs: PskResponderInputs<'_>,
) -> Result<(TunnelPsk, PskResponse), TunnelKeyError> {
    if !signing::verify(
        &ctx.their_signing_pub,
        DOMAIN_TUNNEL_PSK,
        &init.signed_message(ctx),
        &init.signature,
    ) {
        return Err(TunnelKeyError::BadSignature);
    }
    if let Some(last) = inputs.last_epoch {
        if init.epoch <= last {
            return Err(TunnelKeyError::EpochReplay {
                epoch: init.epoch,
                last,
            });
        }
    }
    let generation = inputs
        .ring
        .generation(init.target_generation, inputs.now)
        .ok_or(TunnelKeyError::UnknownGeneration {
            generation: init.target_generation,
        })?;

    // ML-KEM-768 decapsulation with the generation's decapsulation key.
    if init.kem_ct.len() != KEM_CT_SIZE {
        return Err(TunnelKeyError::Kem);
    }
    let dk_encoded = Encoded::<MlKem768Dk>::try_from(generation.kem_dk.as_slice())
        .map_err(|_| TunnelKeyError::Kem)?;
    let dk: MlKem768Dk = EncodedSizeUser::from_bytes(&dk_encoded);
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(init.kem_ct.as_slice())
        .map_err(|_| TunnelKeyError::Kem)?;
    let kem_ss_raw = dk.decapsulate(&ct).map_err(|_| TunnelKeyError::Kem)?;
    let mut kem_ss = Zeroizing::new([0u8; 32]);
    kem_ss.copy_from_slice(kem_ss_raw.as_slice());

    // Our ephemeral X25519 key and the ecdh shared secret.
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let eph_secret = X25519Secret::from(bytes);
    let eph_pub = X25519Public::from(&eph_secret).to_bytes();
    let ecdh = eph_secret.diffie_hellman(&X25519Public::from(init.eph_pub));
    let ecdh_ss = Zeroizing::new(*ecdh.as_bytes());

    let key = derive_tunnel_psk(
        &ecdh_ss,
        &kem_ss,
        &inputs.channel_key,
        &ctx.our_peer_id,
        &ctx.their_peer_id,
        init.epoch,
    )
    .map_err(|_| TunnelKeyError::Derivation)?;

    let mut response = PskResponse {
        epoch: init.epoch,
        eph_pub,
        signature: Vec::new(),
    };
    response.signature = signing::sign(
        &ctx.our_signing_secret,
        DOMAIN_TUNNEL_PSK,
        &response.signed_message(&init.to_bytes(), ctx),
    );
    Ok((
        TunnelPsk::Epoch {
            key,
            epoch: init.epoch,
        },
        response,
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 60 * 60;

    fn schedule_no_jitter() -> RotationSchedule {
        RotationSchedule {
            interval_secs: 7 * DAY,
            overlap_secs: DAY,
            max_jitter_secs: 0,
        }
    }

    fn ed25519_pair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = [seed; 32];
        let pubkey = ed25519_dalek::SigningKey::from_bytes(&secret)
            .verifying_key()
            .to_bytes();
        (secret, pubkey)
    }

    /// Two peers with signing keys, ids and a shared channel key.
    fn peers() -> (PskPeerContext, PskPeerContext) {
        let (a_sec, a_pub) = ed25519_pair(0x01);
        let (b_sec, b_pub) = ed25519_pair(0x02);
        let a_id = PeerId([0xA1; 32]);
        let b_id = PeerId([0xB2; 32]);
        (
            PskPeerContext {
                our_signing_secret: a_sec,
                their_signing_pub: b_pub,
                our_peer_id: a_id,
                their_peer_id: b_id,
            },
            PskPeerContext {
                our_signing_secret: b_sec,
                their_signing_pub: a_pub,
                our_peer_id: b_id,
                their_peer_id: a_id,
            },
        )
    }

    fn channel_key() -> Zeroizing<[u8; 32]> {
        Zeroizing::new([0x33; 32])
    }

    // -- lifecycle ----------------------------------------------------------

    #[test]
    fn test_ring_scheduled_rotation_and_overlap() {
        let mut ring = TunnelKeyRing::new(0, schedule_no_jitter());
        assert_eq!(ring.current().generation, 1);
        assert_eq!(ring.next_rotation_at(), 7 * DAY);
        // Before the interval: nothing happens.
        assert_eq!(ring.tick(7 * DAY - 1), None);
        assert_eq!(ring.current().generation, 1);
        assert!(ring.previous(7 * DAY - 1).is_none());
        // At the interval: rotate, keep generation 1 for one overlap.
        assert_eq!(ring.tick(7 * DAY), Some(RotationReason::Scheduled));
        assert_eq!(ring.current().generation, 2);
        assert_eq!(ring.previous(7 * DAY).map(|g| g.generation), Some(1));
        assert_eq!(ring.accepted(7 * DAY).len(), 2);
        assert_eq!(ring.next_rotation_at(), 14 * DAY);
        // Inside the overlap both are accepted; at its end only current.
        assert!(ring.generation(1, 7 * DAY + DAY - 1).is_some());
        assert!(ring.generation(1, 8 * DAY).is_none());
        assert_eq!(ring.tick(8 * DAY), None);
        assert!(ring.previous(8 * DAY).is_none());
        assert_eq!(ring.accepted(8 * DAY).len(), 1);
    }

    #[test]
    fn test_ring_forced_rotation_reasons() {
        let mut ring = TunnelKeyRing::new(100, schedule_no_jitter());
        assert_eq!(ring.rotate(200, RotationReason::TrustChange), 2);
        assert_eq!(ring.previous(200).map(|g| g.generation), Some(1));
        // Next scheduled rotation is re-anchored at the forced rotation.
        assert_eq!(ring.next_rotation_at(), 200 + 7 * DAY);
        assert_eq!(ring.rotate(300, RotationReason::ThreatEscalation), 3);
        // Only one previous generation is ever kept.
        assert_eq!(ring.accepted(300).len(), 2);
        assert_eq!(ring.previous(300).map(|g| g.generation), Some(2));
        // Suspected compromise grants no overlap at all.
        assert_eq!(ring.rotate(400, RotationReason::SuspectedCompromise), 4);
        assert!(ring.previous(400).is_none());
        assert_eq!(ring.accepted(400).len(), 1);
    }

    #[test]
    fn test_ring_jitter_only_shortens_interval() {
        let schedule = RotationSchedule::default();
        for draw in [0u64, 1, 12 * 60 * 60, u64::MAX, 123_456_789] {
            let due = schedule.next_due(1_000, draw);
            assert!(due <= 1_000 + DEFAULT_ROTATION_SECS);
            assert!(due >= 1_000 + DEFAULT_ROTATION_SECS - DEFAULT_MAX_JITTER_SECS);
        }
        // Live rings draw from the RNG; the bound must still hold.
        for _ in 0..8 {
            let ring = TunnelKeyRing::new(50, schedule);
            assert!(ring.next_rotation_at() <= 50 + DEFAULT_ROTATION_SECS);
            assert!(
                ring.next_rotation_at() >= 50 + DEFAULT_ROTATION_SECS - DEFAULT_MAX_JITTER_SECS
            );
        }
    }

    #[test]
    fn test_default_schedule_matches_spec() {
        let s = RotationSchedule::default();
        assert_eq!(s.interval_secs, 7 * DAY);
        assert_eq!(s.overlap_secs, DAY);
    }

    // -- binding ------------------------------------------------------------

    #[test]
    fn test_binding_roundtrip_verify_and_tamper() {
        let (a, _) = peers();
        let (_, a_pub) = ed25519_pair(0x01);
        let ring = TunnelKeyRing::new(10, schedule_no_jitter());
        let binding = ring.binding(&a.our_signing_secret, a_pub);
        let bytes = binding.to_bytes();
        assert_eq!(bytes.len(), BINDING_LEN);
        let parsed = TunnelKeyBinding::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, binding);
        parsed.verify_for(&a_pub).unwrap();
        // Wrong expected identity.
        let (_, b_pub) = ed25519_pair(0x02);
        assert_eq!(
            parsed.verify_for(&b_pub),
            Err(TunnelKeyError::IdentityMismatch)
        );
        // Tampered tunnel key.
        let mut t = parsed.clone();
        t.tunnel_pub[0] ^= 1;
        assert_eq!(t.verify_for(&a_pub), Err(TunnelKeyError::BadSignature));
        // Tampered KEM prekey.
        let mut k = parsed.clone();
        k.kem_ek[5] ^= 1;
        assert_eq!(k.verify_for(&a_pub), Err(TunnelKeyError::BadSignature));
        // Truncated.
        assert!(matches!(
            TunnelKeyBinding::from_bytes(&bytes[..BINDING_LEN - 1]),
            Err(TunnelKeyError::Malformed { .. })
        ));
    }

    // -- PSK agreement ------------------------------------------------------

    /// Run one full agreement; returns both PSKs.
    fn agree(
        epoch: u64,
        last_epoch: Option<u64>,
        now: u64,
        ring_b: &TunnelKeyRing,
    ) -> Result<(TunnelPsk, TunnelPsk), TunnelKeyError> {
        let (a, b) = peers();
        let binding_b = ring_b.binding(&b.our_signing_secret, a.their_signing_pub);
        let (state, init) = psk_initiate(&a, &binding_b, channel_key(), epoch)?;
        // Wire round trip of the init.
        let init = PskInit::from_bytes(&init.to_bytes())?;
        let (psk_b, response) = psk_respond(
            &init,
            &b,
            PskResponderInputs {
                ring: ring_b,
                channel_key: channel_key(),
                last_epoch,
                now,
            },
        )?;
        let response = PskResponse::from_bytes(&response.to_bytes())?;
        let psk_a = state.complete(&response, &a)?;
        Ok((psk_a, psk_b))
    }

    fn key_of(p: &TunnelPsk) -> [u8; 32] {
        match p {
            TunnelPsk::Epoch { key, .. } => **key,
            TunnelPsk::None => panic!("expected an epoch PSK"),
        }
    }

    #[test]
    fn test_psk_agreement_roundtrip_and_epoch_separation() {
        let ring_b = TunnelKeyRing::new(0, schedule_no_jitter());
        let (a1, b1) = agree(1, None, 0, &ring_b).unwrap();
        assert_eq!(key_of(&a1), key_of(&b1));
        assert_eq!(a1.epoch(), Some(1));
        let (a2, b2) = agree(2, Some(1), 0, &ring_b).unwrap();
        assert_eq!(key_of(&a2), key_of(&b2));
        assert_ne!(key_of(&a1), key_of(&a2));
    }

    #[test]
    fn test_psk_epoch_replay_rejected() {
        let ring_b = TunnelKeyRing::new(0, schedule_no_jitter());
        assert_eq!(
            agree(1, Some(1), 0, &ring_b).unwrap_err(),
            TunnelKeyError::EpochReplay { epoch: 1, last: 1 }
        );
        assert!(matches!(
            agree(3, Some(5), 0, &ring_b),
            Err(TunnelKeyError::EpochReplay { .. })
        ));
    }

    #[test]
    fn test_psk_previous_generation_only_during_overlap() {
        let mut ring_b = TunnelKeyRing::new(0, schedule_no_jitter());
        let (_, b) = peers();
        let (a, _) = peers();
        let old_binding = ring_b.binding(&b.our_signing_secret, a.their_signing_pub);
        ring_b.rotate(100, RotationReason::TrustChange);
        // The initiator still holds the old binding: accepted inside overlap.
        let (state, init) = psk_initiate(&a, &old_binding, channel_key(), 1).unwrap();
        let (psk_b, resp) = psk_respond(
            &init,
            &b,
            PskResponderInputs {
                ring: &ring_b,
                channel_key: channel_key(),
                last_epoch: None,
                now: 100 + DAY - 1,
            },
        )
        .unwrap();
        assert_eq!(key_of(&state.complete(&resp, &a).unwrap()), key_of(&psk_b));
        // After the overlap the old generation is unknown.
        let (_, init2) = psk_initiate(&a, &old_binding, channel_key(), 2).unwrap();
        assert_eq!(
            psk_respond(
                &init2,
                &b,
                PskResponderInputs {
                    ring: &ring_b,
                    channel_key: channel_key(),
                    last_epoch: Some(1),
                    now: 100 + DAY,
                },
            )
            .unwrap_err(),
            TunnelKeyError::UnknownGeneration { generation: 1 }
        );
    }

    #[test]
    fn test_psk_forged_messages_rejected() {
        let ring_b = TunnelKeyRing::new(0, schedule_no_jitter());
        let (a, b) = peers();
        let binding_b = ring_b.binding(&b.our_signing_secret, a.their_signing_pub);
        let (state, init) = psk_initiate(&a, &binding_b, channel_key(), 1).unwrap();
        let inputs = || PskResponderInputs {
            ring: &ring_b,
            channel_key: channel_key(),
            last_epoch: None,
            now: 0,
        };
        // Tampered init signature / fields.
        let mut bad_sig = init.clone();
        bad_sig.signature[0] ^= 1;
        assert_eq!(
            psk_respond(&bad_sig, &b, inputs()).unwrap_err(),
            TunnelKeyError::BadSignature
        );
        let mut bad_ct = init.clone();
        bad_ct.kem_ct[0] ^= 1;
        assert_eq!(
            psk_respond(&bad_ct, &b, inputs()).unwrap_err(),
            TunnelKeyError::BadSignature
        );
        // Init signed by a stranger.
        let (stranger_sec, _) = ed25519_pair(0x09);
        let stranger = PskPeerContext {
            our_signing_secret: stranger_sec,
            ..PskPeerContext {
                our_signing_secret: a.our_signing_secret,
                their_signing_pub: a.their_signing_pub,
                our_peer_id: a.our_peer_id,
                their_peer_id: a.their_peer_id,
            }
        };
        let (_, forged_init) = psk_initiate(&stranger, &binding_b, channel_key(), 1).unwrap();
        assert_eq!(
            psk_respond(&forged_init, &b, inputs()).unwrap_err(),
            TunnelKeyError::BadSignature
        );
        // Genuine response, then tamper it on the way back.
        let (_, response) = psk_respond(&init, &b, inputs()).unwrap();
        let mut bad_resp = response.clone();
        bad_resp.eph_pub[0] ^= 1;
        assert_eq!(
            state.complete(&bad_resp, &a).unwrap_err(),
            TunnelKeyError::BadSignature
        );
        let mut wrong_epoch = response.clone();
        wrong_epoch.epoch = 2;
        // Consume state at the end: use a fresh initiator for the epoch case.
        let (state2, _) = psk_initiate(&a, &binding_b, channel_key(), 1).unwrap();
        assert_eq!(
            state2.complete(&wrong_epoch, &a).unwrap_err(),
            TunnelKeyError::EpochMismatch
        );
        // Binding from a different identity is refused before encapsulation.
        let (c_sec, c_pub) = ed25519_pair(0x07);
        let binding_c = ring_b.binding(&c_sec, c_pub);
        assert_eq!(
            psk_initiate(&a, &binding_c, channel_key(), 1).unwrap_err(),
            TunnelKeyError::IdentityMismatch
        );
    }

    #[test]
    fn test_psk_wire_negatives() {
        let ring_b = TunnelKeyRing::new(0, schedule_no_jitter());
        let (a, b) = peers();
        let binding_b = ring_b.binding(&b.our_signing_secret, a.their_signing_pub);
        let (_, init) = psk_initiate(&a, &binding_b, channel_key(), 1).unwrap();
        let bytes = init.to_bytes();
        assert_eq!(bytes.len(), PSK_INIT_LEN);
        assert!(matches!(
            PskInit::from_bytes(&bytes[..10]),
            Err(TunnelKeyError::Malformed { .. })
        ));
        let mut foreign_suite = bytes.clone();
        foreign_suite[2] = 0x09;
        assert_eq!(
            PskInit::from_bytes(&foreign_suite),
            Err(TunnelKeyError::Link(WireGuardError::UnsupportedSuite {
                declared: 0x09
            }))
        );
        let mut wrong_type = bytes.clone();
        wrong_type[3] = PSK_MSG_RESPONSE;
        assert_eq!(
            PskInit::from_bytes(&wrong_type),
            Err(TunnelKeyError::WrongMessageType {
                found: PSK_MSG_RESPONSE
            })
        );
        let mut resp_bytes = vec![0u8; PSK_RESPONSE_LEN];
        resp_bytes[..3].copy_from_slice(&LINK_HEADER);
        resp_bytes[3] = PSK_MSG_INIT;
        assert_eq!(
            PskResponse::from_bytes(&resp_bytes),
            Err(TunnelKeyError::WrongMessageType {
                found: PSK_MSG_INIT
            })
        );
        resp_bytes[3] = PSK_MSG_RESPONSE;
        assert!(PskResponse::from_bytes(&resp_bytes).is_ok());
        assert!(matches!(
            PskResponse::from_bytes(&[]),
            Err(TunnelKeyError::Malformed { .. })
        ));
    }
}
