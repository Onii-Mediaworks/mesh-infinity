//! Administrative mesh commands (§3.9.3 remote killswitch).
//!
//! # What this is
//!
//! A `MeshPacket` of kind `AdminCommand` carries a JSON command that can make
//! the receiving device do something privileged — today, erase itself.  The
//! packet envelope itself is unsigned: `MeshPacket::source` is whatever the
//! last hop wrote there.  So the command payload must carry its own proof,
//! and that proof is the only thing this module trusts.
//!
//! # Trust rule
//!
//! A remote killswitch is authorised by exactly one thing: an Ed25519
//! signature under `DOMAIN_KILLSWITCH`, verified against the identity key the
//! *local contact store* holds for a peer the user placed at InnerCircle.
//! The requester id in the payload, the packet source, and anything else a
//! peer can write are consistency inputs, never authority.
//!
//! # Replay
//!
//! The signed request binds `target_peer_id` (so one signature wipes one
//! device), carries a timestamp bounded by `KILLSWITCH_MAX_AGE_SECS` /
//! `KILLSWITCH_MAX_SKEW_SECS`, and the signature itself is remembered in a
//! bounded `KillswitchReplayCache` so a captured request cannot be presented
//! twice.  Freshness is generous on purpose: §3.9.3 says the killswitch fires
//! on first verified delivery, and a stolen device may be offline for days.
//!
//! This module is pure (parse, sign, verify); the trust lookup and the wipe
//! itself live in `service::pairing_ops` / `service::identity_ops`.

use std::collections::VecDeque;
use std::fmt;

use serde_json::Value;

use crate::crypto::signing::{self, DOMAIN_KILLSWITCH};
use crate::identity::peer_id::PeerId;

/// Largest admin command payload accepted, in bytes.
///
/// A killswitch request is ~300 bytes of hex JSON; anything larger is not a
/// command this version understands and is dropped before parsing.
pub const MAX_ADMIN_COMMAND_BYTES: usize = 1024;

/// Oldest request timestamp still honoured (seven days).
///
/// Delivery may be delayed by store-and-forward while the target is offline;
/// a week covers that without making a leaked signature valid forever.
pub const KILLSWITCH_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Furthest-future request timestamp tolerated (clock skew allowance).
pub const KILLSWITCH_MAX_SKEW_SECS: u64 = 5 * 60;

/// Number of accepted or verified-but-rejected signatures remembered.
pub const KILLSWITCH_REPLAY_CAPACITY: usize = 256;

/// The `type` value of a remote killswitch command.
pub const KILLSWITCH_COMMAND_TYPE: &str = "killswitch";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an admin command was not executed.
///
/// Every variant means "drop the packet, change nothing".  The variants are
/// surfaced to the local UI as a rejection reason; they are never sent back
/// to the network (§7.2 error-silence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCommandError {
    /// Payload exceeds `MAX_ADMIN_COMMAND_BYTES`.
    PayloadTooLarge,
    /// Payload is not a JSON object.
    MalformedJson,
    /// A required field is absent.
    MissingField(&'static str),
    /// A field is present but has the wrong type or hex length.
    MalformedField(&'static str),
    /// The `type` field names a command this version does not know.
    UnknownCommand,
    /// `MeshPacket::source` differs from the signed `requester_id`.
    SourceMismatch,
    /// `target_peer_id` is not this device.
    WrongTarget,
    /// The requester is not in the local contact store.
    UnknownRequester,
    /// The requester is a contact but below InnerCircle.
    InsufficientTrust,
    /// The user has not enabled remote wipe on this device.
    RemoteWipeDisabled,
    /// The request timestamp is older than `KILLSWITCH_MAX_AGE_SECS`.
    StaleTimestamp,
    /// The request timestamp is further ahead than `KILLSWITCH_MAX_SKEW_SECS`.
    FutureTimestamp,
    /// This exact signature was already seen.
    Replayed,
    /// The signature does not verify under the contact's stored key.
    BadSignature,
}

impl fmt::Display for AdminCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "admin command payload too large"),
            Self::MalformedJson => write!(f, "admin command is not a JSON object"),
            Self::MissingField(name) => write!(f, "admin command missing `{name}`"),
            Self::MalformedField(name) => write!(f, "admin command field `{name}` malformed"),
            Self::UnknownCommand => write!(f, "unknown admin command type"),
            Self::SourceMismatch => write!(f, "packet source does not match signed requester"),
            Self::WrongTarget => write!(f, "killswitch target is not this device"),
            Self::UnknownRequester => write!(f, "requester is not a known contact"),
            Self::InsufficientTrust => write!(f, "requester is below InnerCircle trust"),
            Self::RemoteWipeDisabled => write!(f, "remote wipe is not enabled on this device"),
            Self::StaleTimestamp => write!(f, "killswitch request timestamp too old"),
            Self::FutureTimestamp => write!(f, "killswitch request timestamp in the future"),
            Self::Replayed => write!(f, "killswitch request already seen"),
            Self::BadSignature => write!(f, "killswitch request signature invalid"),
        }
    }
}

impl std::error::Error for AdminCommandError {}

// ---------------------------------------------------------------------------
// Remote killswitch request (§3.9.3)
// ---------------------------------------------------------------------------

/// A signed remote killswitch request, exactly the §3.9.3 record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteKillswitchRequest {
    /// The device that must erase itself.
    pub target_peer_id: PeerId,
    /// The InnerCircle contact asking for the erase.
    pub requester_id: PeerId,
    /// Unix seconds when the requester signed.
    pub timestamp: u64,
    /// Ed25519 signature by the requester's identity key over
    /// `signing_preimage`, under `DOMAIN_KILLSWITCH`.
    pub signature: [u8; 64],
}

impl RemoteKillswitchRequest {
    /// Bytes the requester signs: `target (32) || requester (32) || BE64(timestamp)`.
    ///
    /// Fixed-width fields only, so the encoding needs no separators and
    /// cannot be reinterpreted by shifting a boundary.
    pub fn signing_preimage(target: &PeerId, requester: &PeerId, timestamp: u64) -> [u8; 72] {
        let mut msg = [0u8; 72];
        msg[..32].copy_from_slice(&target.0);
        msg[32..64].copy_from_slice(&requester.0);
        msg[64..].copy_from_slice(&timestamp.to_be_bytes());
        msg
    }

    /// Create and sign a request with the requester's Ed25519 signing seed.
    ///
    /// The requester id is derived from the public key matching `signing_key`
    /// so a caller cannot sign on behalf of an id it does not hold.
    pub fn sign(
        target: &PeerId,
        requester_ed25519_public: &[u8; 32],
        signing_key: &[u8; 32],
        timestamp: u64,
    ) -> Self {
        let requester_id = PeerId::from_ed25519_pub(requester_ed25519_public);
        let msg = Self::signing_preimage(target, &requester_id, timestamp);
        let sig = signing::sign(signing_key, DOMAIN_KILLSWITCH, &msg);
        let mut signature = [0u8; 64];
        // `signing::sign` always yields 64 bytes; copy defensively anyway.
        signature.copy_from_slice(&sig[..64]);
        Self {
            target_peer_id: *target,
            requester_id,
            timestamp,
            signature,
        }
    }

    /// Serialise as the JSON payload of an `AdminCommand` packet.
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "type":           KILLSWITCH_COMMAND_TYPE,
            "target_peer_id": self.target_peer_id.to_hex(),
            "requester_id":   self.requester_id.to_hex(),
            "timestamp":      self.timestamp,
            "signature":      hex::encode(self.signature),
        })
    }

    /// Parse the fields of a `killswitch` command object.
    fn from_json(cmd: &Value) -> Result<Self, AdminCommandError> {
        let target_peer_id = PeerId(hex_field(cmd, "target_peer_id")?);
        let requester_id = PeerId(hex_field(cmd, "requester_id")?);
        let timestamp = cmd
            .get("timestamp")
            .ok_or(AdminCommandError::MissingField("timestamp"))?
            .as_u64()
            .ok_or(AdminCommandError::MalformedField("timestamp"))?;
        let signature = hex_field(cmd, "signature")?;
        Ok(Self {
            target_peer_id,
            requester_id,
            timestamp,
            signature,
        })
    }

    /// Check the timestamp against the acceptance window.
    pub fn check_freshness(&self, now: u64) -> Result<(), AdminCommandError> {
        if self.timestamp > now.saturating_add(KILLSWITCH_MAX_SKEW_SECS) {
            return Err(AdminCommandError::FutureTimestamp);
        }
        if now.saturating_sub(self.timestamp) > KILLSWITCH_MAX_AGE_SECS {
            return Err(AdminCommandError::StaleTimestamp);
        }
        Ok(())
    }

    /// Verify the signature under the key the local contact store holds for
    /// the requester.  The key is the caller's responsibility: it must come
    /// from local trusted state, never from the packet.
    pub fn verify(&self, requester_ed25519_public: &[u8; 32]) -> Result<(), AdminCommandError> {
        // A request whose requester id does not match the stored key would
        // only reach here through a contact-store lookup by that same id, so
        // this recomputation is belt-and-braces against a corrupted store.
        if PeerId::from_ed25519_pub(requester_ed25519_public) != self.requester_id {
            return Err(AdminCommandError::BadSignature);
        }
        let msg = Self::signing_preimage(&self.target_peer_id, &self.requester_id, self.timestamp);
        if signing::verify(
            requester_ed25519_public,
            DOMAIN_KILLSWITCH,
            &msg,
            &self.signature,
        ) {
            Ok(())
        } else {
            Err(AdminCommandError::BadSignature)
        }
    }
}

/// Decode a hex string field into a fixed-size array.
fn hex_field<const N: usize>(
    cmd: &Value,
    name: &'static str,
) -> Result<[u8; N], AdminCommandError> {
    let text = cmd
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or(AdminCommandError::MissingField(name))?;
    let bytes = hex::decode(text).map_err(|_| AdminCommandError::MalformedField(name))?;
    bytes
        .try_into()
        .map_err(|_| AdminCommandError::MalformedField(name))
}

// ---------------------------------------------------------------------------
// Command envelope
// ---------------------------------------------------------------------------

/// A parsed admin command.  One variant today; the enum keeps future
/// commands from being dispatched on a bare string compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCommand {
    /// §3.9.3 remote killswitch.
    Killswitch(RemoteKillswitchRequest),
}

/// Parse the payload bytes of an `AdminCommand` packet.
///
/// Length is checked before JSON parsing so an oversized payload is never
/// allocated into a `Value`.  A `killswitch` object without a signature is a
/// malformed command, not a legacy one: there is no unsigned form.
pub fn parse_admin_command(payload: &[u8]) -> Result<AdminCommand, AdminCommandError> {
    if payload.len() > MAX_ADMIN_COMMAND_BYTES {
        return Err(AdminCommandError::PayloadTooLarge);
    }
    let cmd: Value =
        serde_json::from_slice(payload).map_err(|_| AdminCommandError::MalformedJson)?;
    if !cmd.is_object() {
        return Err(AdminCommandError::MalformedJson);
    }
    let kind = cmd
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or(AdminCommandError::MissingField("type"))?;
    match kind {
        KILLSWITCH_COMMAND_TYPE => Ok(AdminCommand::Killswitch(
            RemoteKillswitchRequest::from_json(&cmd)?,
        )),
        _ => Err(AdminCommandError::UnknownCommand),
    }
}

// ---------------------------------------------------------------------------
// Replay cache
// ---------------------------------------------------------------------------

/// Bounded FIFO of killswitch signatures already presented to this device.
///
/// Sized by `KILLSWITCH_REPLAY_CAPACITY`; the oldest entry is evicted first.
/// Only requests that reached signature verification are recorded, so an
/// attacker cannot flush the cache with garbage.
#[derive(Debug, Default)]
pub struct KillswitchReplayCache {
    /// Signatures in arrival order.
    seen: VecDeque<[u8; 64]>,
}

impl KillswitchReplayCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `signature`; returns `false` if it was already present.
    pub fn record(&mut self, signature: &[u8; 64]) -> bool {
        if self.seen.contains(signature) {
            return false;
        }
        if self.seen.len() >= KILLSWITCH_REPLAY_CAPACITY {
            self.seen.pop_front();
        }
        self.seen.push_back(*signature);
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::self_identity::SelfIdentity;

    /// A signed request from a fresh requester to a fixed target.
    fn signed_request(now: u64) -> (SelfIdentity, PeerId, RemoteKillswitchRequest) {
        let requester = SelfIdentity::generate(None);
        let target = PeerId([0x11u8; 32]);
        let req = RemoteKillswitchRequest::sign(
            &target,
            &requester.ed25519_pub,
            &requester.ed25519_signing.to_bytes(),
            now,
        );
        (requester, target, req)
    }

    /// Sign, serialise, parse, verify: the round trip holds.
    #[test]
    fn signed_request_round_trips_and_verifies() {
        let (requester, _target, req) = signed_request(1_000);
        let bytes = serde_json::to_vec(&req.to_json()).unwrap();
        let AdminCommand::Killswitch(parsed) = parse_admin_command(&bytes).unwrap();
        assert_eq!(parsed, req);
        assert_eq!(parsed.verify(&requester.ed25519_pub), Ok(()));
        assert_eq!(parsed.check_freshness(1_000), Ok(()));
    }

    /// The legacy unsigned `{"type":"killswitch"}` is a malformed command.
    #[test]
    fn unsigned_killswitch_is_rejected_at_parse() {
        assert_eq!(
            parse_admin_command(br#"{"type":"killswitch"}"#),
            Err(AdminCommandError::MissingField("target_peer_id"))
        );
    }

    /// Wrong key, altered target and altered timestamp all fail verification.
    #[test]
    fn tampered_requests_fail_verification() {
        let (requester, _target, req) = signed_request(1_000);
        let other = SelfIdentity::generate(None);
        assert_eq!(
            req.verify(&other.ed25519_pub),
            Err(AdminCommandError::BadSignature)
        );
        let mut retargeted = req.clone();
        retargeted.target_peer_id = PeerId([0x22u8; 32]);
        assert_eq!(
            retargeted.verify(&requester.ed25519_pub),
            Err(AdminCommandError::BadSignature)
        );
        let mut redated = req;
        redated.timestamp += 1;
        assert_eq!(
            redated.verify(&requester.ed25519_pub),
            Err(AdminCommandError::BadSignature)
        );
    }

    /// Freshness window: too old and too far ahead are rejected, edges pass.
    #[test]
    fn freshness_window_is_enforced() {
        let (_r, _t, req) = signed_request(10_000);
        assert_eq!(
            req.check_freshness(10_000 + KILLSWITCH_MAX_AGE_SECS),
            Ok(())
        );
        assert_eq!(
            req.check_freshness(10_000 + KILLSWITCH_MAX_AGE_SECS + 1),
            Err(AdminCommandError::StaleTimestamp)
        );
        assert_eq!(
            req.check_freshness(10_000 - KILLSWITCH_MAX_SKEW_SECS),
            Ok(())
        );
        assert_eq!(
            req.check_freshness(10_000 - KILLSWITCH_MAX_SKEW_SECS - 1),
            Err(AdminCommandError::FutureTimestamp)
        );
    }

    /// Malformed inputs yield typed errors, never panics.
    #[test]
    fn malformed_payloads_are_typed_errors() {
        assert_eq!(
            parse_admin_command(&vec![b'{'; MAX_ADMIN_COMMAND_BYTES + 1]),
            Err(AdminCommandError::PayloadTooLarge)
        );
        assert_eq!(
            parse_admin_command(b"not json"),
            Err(AdminCommandError::MalformedJson)
        );
        assert_eq!(
            parse_admin_command(b"[]"),
            Err(AdminCommandError::MalformedJson)
        );
        assert_eq!(
            parse_admin_command(br#"{"type":"reboot"}"#),
            Err(AdminCommandError::UnknownCommand)
        );
        assert_eq!(
            parse_admin_command(
                br#"{"type":"killswitch","target_peer_id":"00","requester_id":"00","timestamp":1,"signature":"00"}"#
            ),
            Err(AdminCommandError::MalformedField("target_peer_id"))
        );
        assert_eq!(
            parse_admin_command(
                br#"{"type":"killswitch","target_peer_id":"","requester_id":"","timestamp":-1,"signature":""}"#
            ),
            Err(AdminCommandError::MalformedField("target_peer_id"))
        );
    }

    /// The replay cache rejects a repeat and evicts in FIFO order at capacity.
    #[test]
    fn replay_cache_rejects_repeats_and_bounds_memory() {
        let mut cache = KillswitchReplayCache::new();
        let first = [1u8; 64];
        assert!(cache.record(&first));
        assert!(!cache.record(&first));
        for i in 0..KILLSWITCH_REPLAY_CAPACITY {
            let mut sig = [0u8; 64];
            sig[..8].copy_from_slice(&(i as u64 + 2).to_be_bytes());
            assert!(cache.record(&sig));
        }
        // `first` was the oldest entry and has been evicted.
        assert!(cache.seen.len() <= KILLSWITCH_REPLAY_CAPACITY);
        assert!(cache.record(&first));
    }
}
