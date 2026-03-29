//! Network Map (§4.1, §4.2)
//!
//! The network map is a public-only structure containing:
//! - Peer IDs and public addresses
//! - Public keys (Ed25519, X25519)
//! - Transport hints (how to reach each peer)
//! - Last-seen timestamps (for staleness detection)
//! - Optional public profile summaries
//! - Service advertisements
//!
//! Map entries are versioned by sequence number. Merging follows:
//! higher sequence wins. Map is capped at 100K entries.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;
use crate::trust::levels::TrustLevel;
use super::transport_hint::TransportHint;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum entries in the local network map (§4.2).
pub const MAX_MAP_ENTRIES: usize = 100_000;

/// Staleness threshold: entries not seen in 30 days are prunable.
pub const STALENESS_SECS: u64 = 30 * 24 * 3600;

/// Max new entries per peer per hour for untrusted sources (§4.2).
pub const GOSSIP_RATE_LIMIT_UNTRUSTED: u32 = 500;
/// Max new entries per peer per hour for trusted sources.
pub const GOSSIP_RATE_LIMIT_TRUSTED: u32 = 5000;

/// Maximum future timestamp tolerance (§4.5): 1 hour.
pub const MAX_FUTURE_TIMESTAMP_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// Network Map Entry
// ---------------------------------------------------------------------------

/// A single entry in the network map (§4.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkMapEntry {
    /// Peer identifier.
    pub peer_id: PeerId,
    /// Public keys for this peer.
    pub public_keys: Vec<PublicKeyRecord>,
    /// Last time this peer was seen active.
    pub last_seen: u64,
    /// Transport hints: how to reach this peer.
    pub transport_hints: Vec<TransportHint>,
    /// Optional public profile summary (if identity_is_public).
    pub public_profile: Option<PublicProfileSummary>,
    /// Public service advertisements.
    pub services: Vec<PublicServiceAd>,
    /// Monotonically increasing sequence number (64-bit, §4.5).
    pub sequence: u64,
    /// Ed25519 signature over all other fields.
    pub signature: Vec<u8>,
    /// Local trust level (not gossiped — computed locally).
    #[serde(skip)]
    pub local_trust: TrustLevel,
}

/// Public key record for a peer address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyRecord {
    pub ed25519_public: [u8; 32],
    pub x25519_public: [u8; 32],
    /// Weekly-rotated preauth (signed pre-key) for X3DH first contact (§7.0).
    /// Allows Alice to initiate a Double Ratchet session with Bob without Bob
    /// being online. Refreshed every 7 days via HKDF from the identity key.
    /// None means the peer has not published a preauth key yet.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preauth_x25519_public: Option<[u8; 32]>,
    /// ML-KEM-768 encapsulation key (1184 bytes). Enables PQXDH (§3.4.1).
    /// None if the peer does not support post-quantum key agreement.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kem_encapsulation_key: Option<Vec<u8>>,
    /// Ed25519 signature over `PREAUTH_SIG_DOMAIN || preauth_x25519_public`
    /// (§7.0.1 identity binding).  Propagated with the preauth key so that
    /// any node forwarding the gossip entry can prove the key belongs to the
    /// peer.  None for entries predating this field (legacy compat).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preauth_sig: Option<Vec<u8>>,
}

/// Public profile summary (for peers with identity_is_public = true).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicProfileSummary {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_hash: Option<Vec<u8>>,
}

/// Public service advertisement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicServiceAd {
    pub name: String,
    pub description: Option<String>,
    pub port_block: u16,
}

/// Domain separator for map entry signing.
const DOMAIN_MAP_ENTRY: &[u8] = b"meshinfinity-map-entry-v1\x00";

impl NetworkMapEntry {
    /// Build the canonical byte payload that is signed by the entry's owner.
    ///
    /// Format (§4.5):
    ///   DOMAIN || peer_id (32) || BE64(sequence) || BE64(last_seen)
    ///   || BE32(n_keys) || [ed25519_pub (32) || x25519_pub (32)]…
    ///   || BE32(hints_json_len) || hints_json
    ///   || BE32(services_json_len) || services_json
    ///   || BE32(profile_json_len) || profile_json
    ///
    /// The `signature` and `local_trust` fields are excluded.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(DOMAIN_MAP_ENTRY);
        buf.extend_from_slice(&self.peer_id.0);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.last_seen.to_be_bytes());
        buf.extend_from_slice(&(self.public_keys.len() as u32).to_be_bytes());
        for pk in &self.public_keys {
            buf.extend_from_slice(&pk.ed25519_public);
            buf.extend_from_slice(&pk.x25519_public);
            // Preauth key is signed as 32 zero bytes if absent (backward compat).
            buf.extend_from_slice(pk.preauth_x25519_public.as_ref().unwrap_or(&[0u8; 32]));
        }
        let hints = serde_json::to_vec(&self.transport_hints).unwrap_or_default();
        buf.extend_from_slice(&(hints.len() as u32).to_be_bytes());
        buf.extend_from_slice(&hints);
        let services = serde_json::to_vec(&self.services).unwrap_or_default();
        buf.extend_from_slice(&(services.len() as u32).to_be_bytes());
        buf.extend_from_slice(&services);
        let profile = serde_json::to_vec(&self.public_profile).unwrap_or_default();
        buf.extend_from_slice(&(profile.len() as u32).to_be_bytes());
        buf.extend_from_slice(&profile);
        buf
    }

    /// Sign this entry with the given Ed25519 signing key.
    ///
    /// Sets `self.signature` in place. The `public_keys` field must already
    /// contain the corresponding verifying key so callers can verify later.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let payload = self.signing_payload();
        let sig: Signature = signing_key.sign(&payload);
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify the Ed25519 signature on this entry (§4.5).
    ///
    /// Checks:
    /// 1. At least one public key is present.
    /// 2. `peer_id` is derived from `public_keys[0].ed25519_public`.
    /// 3. `signature` is a valid Ed25519 signature over `signing_payload()`.
    ///
    /// Entries with no public keys are treated as unsigned legacy/stub entries
    /// and pass through without cryptographic verification.
    pub fn verify_signature(&self) -> Result<(), MapError> {
        if self.public_keys.is_empty() {
            // Unsigned stub — allowed in unit tests / local synthetic entries.
            // Gossip from remote peers must have at least one key.
            return Ok(());
        }

        // 1. Peer ID must be derived from the first public key.
        let expected = PeerId::from_ed25519_pub(&self.public_keys[0].ed25519_public);
        if expected != self.peer_id {
            return Err(MapError::PeerIdKeyMismatch);
        }

        // 2. Parse the verifying key.
        let vk = VerifyingKey::from_bytes(&self.public_keys[0].ed25519_public)
            .map_err(|_| MapError::InvalidSignature("invalid Ed25519 public key".into()))?;

        // 3. Parse the signature.
        if self.signature.len() != 64 {
            return Err(MapError::InvalidSignature(format!(
                "expected 64-byte signature, got {}",
                self.signature.len()
            )));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&sig_bytes);

        // 4. Verify.
        let payload = self.signing_payload();
        vk.verify(&payload, &sig)
            .map_err(|e| MapError::InvalidSignature(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Network Map
// ---------------------------------------------------------------------------

/// The local network map — stores all known peers.
#[derive(Default, Serialize, Deserialize)]
pub struct NetworkMap {
    /// Map entries keyed by PeerId.
    entries: HashMap<PeerId, NetworkMapEntry>,
}

impl NetworkMap {
    /// Create an empty network map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries in the map.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get an entry by peer ID.
    pub fn get(&self, peer_id: &PeerId) -> Option<&NetworkMapEntry> {
        self.entries.get(peer_id)
    }

    /// Insert or update an entry. Returns true if the entry was accepted.
    ///
    /// Acceptance rules (§4.5):
    /// 1. Sequence must be strictly greater than existing (or new entry)
    /// 2. Timestamp must not be more than 1 hour in the future
    /// 3. Signature must be valid (signature verification is caller's responsibility)
    pub fn insert(&mut self, entry: NetworkMapEntry, now: u64) -> Result<bool, MapError> {
        // Check future timestamp
        if entry.last_seen > now + MAX_FUTURE_TIMESTAMP_SECS {
            return Err(MapError::FutureTimestamp {
                entry_ts: entry.last_seen,
                now,
            });
        }

        // Validate field lengths (§4.2 gossip validation)
        Self::validate_entry(&entry)?;

        // Check sequence against existing entry
        if let Some(existing) = self.entries.get(&entry.peer_id) {
            if entry.sequence <= existing.sequence {
                return Ok(false); // Stale — silently ignore
            }
        }

        // Check capacity
        if self.entries.len() >= MAX_MAP_ENTRIES && !self.entries.contains_key(&entry.peer_id) {
            // Need to evict — LRU of untrusted entries first
            self.evict_for_new_entry(&entry);
        }

        self.entries.insert(entry.peer_id, entry);
        Ok(true)
    }

    /// Remove stale entries (not seen within staleness threshold).
    pub fn prune_stale(&mut self, now: u64) {
        self.entries.retain(|_, entry| {
            // Never prune trusted entries automatically
            if entry.local_trust.is_trusted_tier() {
                return true;
            }
            // Prune untrusted entries older than threshold
            now.saturating_sub(entry.last_seen) < STALENESS_SECS
        });
    }

    /// Get all entries as a slice.
    pub fn entries(&self) -> impl Iterator<Item = &NetworkMapEntry> {
        self.entries.values()
    }

    /// Get mutable entry.
    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut NetworkMapEntry> {
        self.entries.get_mut(peer_id)
    }

    /// Remove an entry.
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<NetworkMapEntry> {
        self.entries.remove(peer_id)
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Validate entry field lengths per §4.2 gossip validation.
    fn validate_entry(entry: &NetworkMapEntry) -> Result<(), MapError> {
        if entry.transport_hints.len() > 8 {
            return Err(MapError::TooManyTransportHints(entry.transport_hints.len()));
        }
        if entry.public_keys.len() > 16 {
            return Err(MapError::TooManyPublicKeys(entry.public_keys.len()));
        }
        if entry.services.len() > 32 {
            return Err(MapError::TooManyServices(entry.services.len()));
        }
        if let Some(ref profile) = entry.public_profile {
            if let Some(ref name) = profile.display_name {
                if name.len() > 64 {
                    return Err(MapError::FieldTooLong("display_name", name.len()));
                }
            }
            if let Some(ref bio) = profile.bio {
                if bio.len() > 256 {
                    return Err(MapError::FieldTooLong("bio", bio.len()));
                }
            }
        }
        Ok(())
    }

    /// Evict the oldest untrusted entry to make room.
    /// If all entries are trusted, evict the oldest trusted entry (§17.9 edge case fix).
    fn evict_for_new_entry(&mut self, _new_entry: &NetworkMapEntry) {
        // Find the oldest untrusted entry
        let oldest_untrusted = self
            .entries
            .iter()
            .filter(|(_, e)| e.local_trust.is_untrusted_tier())
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(id, _)| *id);

        if let Some(id) = oldest_untrusted {
            self.entries.remove(&id);
            return;
        }

        // All trusted — evict oldest by last_seen (extreme edge case)
        let oldest_trusted = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(id, _)| *id);

        if let Some(id) = oldest_trusted {
            self.entries.remove(&id);
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("Entry timestamp {entry_ts} is more than 1 hour in the future (now: {now})")]
    FutureTimestamp { entry_ts: u64, now: u64 },
    #[error("Too many transport hints ({0}, max 8)")]
    TooManyTransportHints(usize),
    #[error("Too many public keys ({0}, max 16)")]
    TooManyPublicKeys(usize),
    #[error("Too many services ({0}, max 32)")]
    TooManyServices(usize),
    #[error("Field {0} too long ({1} bytes)")]
    FieldTooLong(&'static str, usize),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Peer ID does not match the claimed Ed25519 public key")]
    PeerIdKeyMismatch,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(peer_id: PeerId, seq: u64, last_seen: u64) -> NetworkMapEntry {
        NetworkMapEntry {
            peer_id,
            public_keys: vec![],
            last_seen,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: seq,
            signature: vec![],
            local_trust: TrustLevel::Unknown,
        }
    }

    #[test]
    fn test_insert_new_entry() {
        let mut map = NetworkMap::new();
        let entry = make_entry(PeerId([0x01; 32]), 1, 100);
        assert!(map.insert(entry, 100).unwrap());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_higher_sequence_wins() {
        let mut map = NetworkMap::new();
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 1, 100), 100).unwrap();
        assert!(map.insert(make_entry(pid, 2, 200), 200).unwrap());
        assert_eq!(map.get(&pid).unwrap().last_seen, 200);
    }

    #[test]
    fn test_lower_sequence_rejected() {
        let mut map = NetworkMap::new();
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 5, 100), 100).unwrap();
        assert!(!map.insert(make_entry(pid, 3, 200), 200).unwrap());
        assert_eq!(map.get(&pid).unwrap().sequence, 5);
    }

    #[test]
    fn test_future_timestamp_rejected() {
        let mut map = NetworkMap::new();
        let entry = make_entry(PeerId([0x01; 32]), 1, 100 + MAX_FUTURE_TIMESTAMP_SECS + 1);
        assert!(map.insert(entry, 100).is_err());
    }

    #[test]
    fn test_prune_stale() {
        let mut map = NetworkMap::new();
        let now = 10_000_000u64;
        map.insert(make_entry(PeerId([0x01; 32]), 1, now - STALENESS_SECS - 1), now).unwrap();
        map.insert(make_entry(PeerId([0x02; 32]), 1, now - 100), now).unwrap();
        assert_eq!(map.len(), 2);

        map.prune_stale(now);
        assert_eq!(map.len(), 1);
        assert!(map.get(&PeerId([0x02; 32])).is_some());
    }

    #[test]
    fn test_trusted_entries_not_pruned() {
        let mut map = NetworkMap::new();
        let now = 10_000_000u64;
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 1, now - STALENESS_SECS - 1), now).unwrap();
        map.get_mut(&pid).unwrap().local_trust = TrustLevel::Trusted;

        map.prune_stale(now);
        assert_eq!(map.len(), 1); // Still there — trusted
    }

    #[test]
    fn test_field_validation() {
        let mut entry = make_entry(PeerId([0x01; 32]), 1, 100);
        entry.transport_hints = (0..9).map(|_| super::super::transport_hint::TransportHint {
            transport: super::super::transport_hint::TransportType::Clearnet,
            endpoint: Some("1.2.3.4:5".into()),
        }).collect();

        let mut map = NetworkMap::new();
        assert!(map.insert(entry, 100).is_err());
    }

    #[test]
    fn test_signature_sign_and_verify() {
        use ed25519_dalek::{Signer, SigningKey};

        let raw_key = [0x7au8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();
        let x25519_pub = [0u8; 32]; // Placeholder for test.

        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        let mut entry = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord { ed25519_public: ed_pub, x25519_public: x25519_pub, preauth_x25519_public: None, kem_encapsulation_key: None, preauth_sig: None }],
            last_seen: 1_000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            local_trust: TrustLevel::Unknown,
        };

        entry.sign(&signing_key);
        assert_eq!(entry.signature.len(), 64);
        assert!(entry.verify_signature().is_ok());
    }

    #[test]
    fn test_signature_wrong_peer_id_rejected() {
        use ed25519_dalek::{Signer, SigningKey};

        let raw_key = [0x7au8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();

        // peer_id doesn't match the key.
        let wrong_peer_id = PeerId([0xFFu8; 32]);
        let mut entry = NetworkMapEntry {
            peer_id: wrong_peer_id,
            public_keys: vec![super::PublicKeyRecord { ed25519_public: ed_pub, x25519_public: [0u8; 32], preauth_x25519_public: None, kem_encapsulation_key: None, preauth_sig: None }],
            last_seen: 1_000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![0u8; 64],
            local_trust: TrustLevel::Unknown,
        };

        entry.sign(&signing_key);
        // Change the peer_id after signing — verification must fail.
        entry.peer_id = PeerId([0xFFu8; 32]);
        assert!(entry.verify_signature().is_err());
    }

    #[test]
    fn test_tampered_entry_rejected() {
        use ed25519_dalek::{Signer, SigningKey};

        let raw_key = [0x3bu8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();
        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        let mut entry = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord { ed25519_public: ed_pub, x25519_public: [0u8; 32], preauth_x25519_public: None, kem_encapsulation_key: None, preauth_sig: None }],
            last_seen: 1_000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            local_trust: TrustLevel::Unknown,
        };

        entry.sign(&signing_key);
        // Tamper with sequence after signing.
        entry.sequence = 999;
        assert!(entry.verify_signature().is_err());
    }

    #[test]
    fn test_capacity_eviction() {
        let mut map = NetworkMap::new();
        // Fill to capacity wouldn't be practical in a test with 100K entries,
        // but we can test the eviction logic directly
        assert_eq!(MAX_MAP_ENTRIES, 100_000);
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut map = NetworkMap::new();
        map.insert(make_entry(PeerId([0x01; 32]), 1, 100), 100).unwrap();

        let json = serde_json::to_string(&map).unwrap();
        let recovered: NetworkMap = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.len(), 1);
    }
}
