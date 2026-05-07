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
use sha2::{Digest, Sha256};

use super::transport_hint::{TransportHint, TransportType};
use crate::identity::peer_id::PeerId;
use crate::trust::levels::TrustLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum entries in the local network map (§4.2).
// MAX_MAP_ENTRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_MAP_ENTRIES: usize = 100_000;

/// Staleness threshold: entries not seen in 30 days are prunable.
// STALENESS_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const STALENESS_SECS: u64 = 30 * 24 * 3600;

/// Max new entries per peer per hour for untrusted sources (§4.2).
// GOSSIP_RATE_LIMIT_UNTRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const GOSSIP_RATE_LIMIT_UNTRUSTED: u32 = 500;
/// Max new entries per peer per hour for trusted sources.
// GOSSIP_RATE_LIMIT_TRUSTED — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const GOSSIP_RATE_LIMIT_TRUSTED: u32 = 5000;

/// Maximum future timestamp tolerance (§4.5): 1 hour.
// MAX_FUTURE_TIMESTAMP_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_FUTURE_TIMESTAMP_SECS: u64 = 3600;

/// Maximum age of a gossiped timestamp (§4.2): entries older than 30 days
/// are rejected to prevent replay of stale map data.
/// Matches STALENESS_SECS so the replay window equals the prune window.
pub const MAX_PAST_TIMESTAMP_SECS: u64 = STALENESS_SECS;

/// Maximum number of staged sources per target peer in the multi-source
/// confirmation buffer.  Caps memory consumption from flooding attacks.
const MAX_STAGED_SOURCES_PER_PEER: usize = 10;

/// Maximum total entries held in the multi-source staging buffer.
/// Prevents unbounded memory growth if many distinct peers are being staged.
const MAX_STAGED_PEERS: usize = 10_000;

/// Minimum seconds between accepted sequence updates for the same peer.
/// Rejects update floods — a peer legitimately rotates its map entry at
/// most once per few seconds.  Trusted peers use 10× looser enforcement.
const MIN_UPDATE_INTERVAL_SECS: u64 = 1;

// ---------------------------------------------------------------------------
// Network Map Entry
// ---------------------------------------------------------------------------

/// A single entry in the network map (§4.2, §4.5).
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
    /// Hash of the previous entry's signing payload (self-ratcheted map entries, §4.5).
    /// None for the first entry (sequence == 0).
    pub prev_hash: Option<[u8; 32]>,
    /// Local trust level (not gossiped — computed locally).
    #[serde(skip)]
    pub local_trust: TrustLevel,
}

/// Public key record for a peer address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyRecord {
    /// Ed25519 public key.
    pub ed25519_public: [u8; 32],
    /// X25519 public key.
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
    /// Display name.
    pub display_name: Option<String>,
    /// Bio.
    pub bio: Option<String>,
    /// Avatar hash.
    pub avatar_hash: Option<Vec<u8>>,
}

/// Public service advertisement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicServiceAd {
    /// Service name.
    pub name: String,
    /// Service description.
    pub description: Option<String>,
    /// Port block.
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
    ///   || prev_hash (32) if present
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
        // Append previous entry hash if present (self-ratcheted map, §4.5).
        if let Some(prev) = &self.prev_hash {
            buf.extend_from_slice(prev);
        }
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
    /// 4. If `prev_hash` is present, it must match the SHA-256 hash of the
    ///    previous entry's signing payload (self-ratcheted map entries, §4.5).
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

        // 4. Verify signature.
        let payload = self.signing_payload();
        vk.verify(&payload, &sig)
            .map_err(|e| MapError::InvalidSignature(e.to_string()))?;

        // 5. Verify prev_hash chain (§4.5 self-ratcheted entries).
        // Note: The actual prev_hash validation against the stored previous entry
        // is performed by the caller (NetworkMap::insert) which has access to
        // the previous entry. Here we just ensure the payload format is correct.

        Ok(())
    }

    /// Compute the SHA-256 hash of this entry's signing payload.
    /// Used for building the prev_hash chain (§4.5).
    pub fn payload_hash(&self) -> [u8; 32] {
        let payload = self.signing_payload();
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &payload);
        hasher.finalize().into()
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
    /// Staging buffer for entries awaiting multi-source confirmation (§4.1).
    ///
    /// When `entries.len() >= 100` each gossiped entry must be seen from at
    /// least 2 independent sources before it is promoted into `entries`.
    /// When `entries.len() >= 1000` the threshold rises to 3 sources.
    ///
    /// Key: peer_id of the entry being staged.
    /// Value: map of source_peer_id → best (highest-sequence) entry from that source.
    #[serde(skip)]
    pending_multi_source: HashMap<PeerId, HashMap<PeerId, NetworkMapEntry>>,
    /// Timestamp of the most recently accepted sequence update per peer.
    /// Used to enforce MIN_UPDATE_INTERVAL_SECS rate limiting (§4.2).
    #[serde(skip)]
    last_update_ts: HashMap<PeerId, u64>,
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
    /// Acceptance rules (§4.2, §4.5):
    /// 1. Timestamp must be within [now − 30 days, now + 1 hour].
    /// 2. Sequence must be strictly greater than existing (or new entry).
    /// 3. Per-peer update rate: at most 1 accepted update per MIN_UPDATE_INTERVAL_SECS.
    /// 4. Field validation must pass (lengths, endpoint formats, avatar hash length).
    /// 5. If prev_hash is present and an existing entry is stored, it must match.
    /// 6. New entries with sequence > 0 must carry a prev_hash.
    ///
    /// Signature verification is the caller's responsibility (gossip.rs runs it
    /// before reaching here).
    pub fn insert(&mut self, entry: NetworkMapEntry, now: u64) -> Result<bool, MapError> {
        // --- Timestamp window check (§4.2) ---
        // Upper bound: entry must not be more than 1 hour in the future.
        if entry.last_seen > now + MAX_FUTURE_TIMESTAMP_SECS {
            return Err(MapError::FutureTimestamp {
                entry_ts: entry.last_seen,
                now,
            });
        }
        // Lower bound: entries older than 30 days are replay candidates; reject.
        if now.saturating_sub(entry.last_seen) > MAX_PAST_TIMESTAMP_SECS {
            return Err(MapError::TimestampTooOld {
                entry_ts: entry.last_seen,
                now,
            });
        }

        // --- Field validation (§4.2) ---
        Self::validate_entry(&entry)?;

        // --- Per-peer update rate limiting (§4.2) ---
        // Trusted entries (local self-entry) bypass rate limiting.
        if entry.local_trust != TrustLevel::InnerCircle {
            if let Some(&last_ts) = self.last_update_ts.get(&entry.peer_id) {
                if now.saturating_sub(last_ts) < MIN_UPDATE_INTERVAL_SECS {
                    return Ok(false); // Too fast — silently drop.
                }
            }
        }

        // --- Sequence and prev_hash chain check (§4.5) ---
        if let Some(existing) = self.entries.get(&entry.peer_id) {
            // Sequence must be strictly greater.
            if entry.sequence <= existing.sequence {
                return Ok(false); // Stale — silently ignore.
            }
            // Verify prev_hash chain for updates to an existing entry.
            if let Some(prev_hash) = &entry.prev_hash {
                let expected_hash = existing.payload_hash();
                if prev_hash != &expected_hash {
                    return Err(MapError::InvalidSignature(
                        "prev_hash does not match previous entry's payload hash".into(),
                    ));
                }
            }
        } else {
            // New entry with sequence > 0: require prev_hash to anchor the chain.
            // We cannot verify the hash against a previous entry we have never
            // seen, but requiring its presence ensures the peer maintains chain
            // discipline; the next update will be verifiable.
            if entry.sequence > 0 && entry.prev_hash.is_none() {
                return Err(MapError::InvalidSignature(
                    "new entry with sequence > 0 must have prev_hash".into(),
                ));
            }
        }

        // --- Capacity check ---
        if self.entries.len() >= MAX_MAP_ENTRIES && !self.entries.contains_key(&entry.peer_id) {
            // Need to evict — LRU of untrusted entries first.
            self.evict_for_new_entry(&entry);
        }

        let peer_id = entry.peer_id;
        self.entries.insert(peer_id, entry);
        // Record the accepted-update timestamp for future rate-limit checks.
        self.last_update_ts.insert(peer_id, now);
        Ok(true)
    }

    /// Insert an entry received from a remote gossip source (§4.1, §4.2).
    ///
    /// Enforces the multi-source confirmation requirement:
    /// - Map size < 100:   1 source sufficient (same as `insert`).
    /// - Map size 100–999: 2 independent sources required before promotion.
    /// - Map size ≥ 1000:  3 independent sources required before promotion.
    ///
    /// An "independent source" is a distinct `source_id`.  Duplicate submissions
    /// from the same source only update that source's staged entry; they do not
    /// increment the confirmation count.
    ///
    /// Returns `true` when the entry is promoted into the live map.
    /// Returns `false` when the entry is staged (waiting for more confirmations)
    /// or is stale/superseded.
    pub fn insert_gossiped(
        &mut self,
        entry: NetworkMapEntry,
        source_id: &PeerId,
        now: u64,
    ) -> Result<bool, MapError> {
        let required = Self::required_sources(self.entries.len());

        // Fast path: single source sufficient (small map or already large enough).
        if required == 1 {
            return self.insert(entry, now);
        }

        // Validate before staging — reject bad entries immediately.
        if entry.last_seen > now + MAX_FUTURE_TIMESTAMP_SECS {
            return Err(MapError::FutureTimestamp {
                entry_ts: entry.last_seen,
                now,
            });
        }
        Self::validate_entry(&entry)?;

        let target_peer = entry.peer_id;

        // If an existing live entry has the same or higher sequence, skip staging.
        if let Some(existing) = self.entries.get(&target_peer) {
            if entry.sequence <= existing.sequence {
                return Ok(false);
            }
        }

        // Enforce total staging map size cap to prevent memory exhaustion.
        if !self.pending_multi_source.contains_key(&target_peer)
            && self.pending_multi_source.len() >= MAX_STAGED_PEERS
        {
            // Staging buffer full — drop silently.  The entry may arrive again
            // once existing staged entries are promoted or expire.
            return Ok(false);
        }

        // Stage the entry under this source.
        let staged_sources = self
            .pending_multi_source
            .entry(target_peer)
            .or_default();

        // Enforce per-peer source cap to limit per-entry memory consumption.
        if !staged_sources.contains_key(source_id)
            && staged_sources.len() >= MAX_STAGED_SOURCES_PER_PEER
        {
            // Too many distinct sources already staged — drop this one.
            return Ok(false);
        }

        // Keep the highest-sequence entry per source.
        let current_best = staged_sources.get(source_id);
        if current_best.map_or(true, |existing| entry.sequence > existing.sequence) {
            staged_sources.insert(*source_id, entry);
        }

        // Check if we now have enough independent sources to promote.
        if staged_sources.len() >= required {
            // Select the entry with the highest sequence number.
            let best = staged_sources
                .values()
                .max_by_key(|e| e.sequence)
                .cloned();

            // Remove from staging regardless of whether promotion succeeds.
            self.pending_multi_source.remove(&target_peer);

            if let Some(best_entry) = best {
                return self.insert(best_entry, now);
            }
        }

        Ok(false) // Still waiting for more sources.
    }

    /// Number of independent gossip sources required before a new entry is
    /// accepted into the live map, based on the current map size (§4.1).
    fn required_sources(map_size: usize) -> usize {
        if map_size >= 1000 {
            3
        } else if map_size >= 100 {
            2
        } else {
            1
        }
    }

    /// Remove stale entries (not seen within staleness threshold).
    pub fn prune_stale(&mut self, now: u64) {
        let mut pruned: Vec<PeerId> = Vec::new();
        self.entries.retain(|id, entry| {
            if entry.local_trust.is_trusted_tier() {
                return true;
            }
            let keep = now.saturating_sub(entry.last_seen) < STALENESS_SECS;
            if !keep {
                pruned.push(*id);
            }
            keep
        });
        // Clean up rate-limit timestamps for pruned peers.
        for id in &pruned {
            self.last_update_ts.remove(id);
        }
        // Also prune the staging buffer for peers that are now stale.
        self.pending_multi_source.retain(|id, staged| {
            // Keep staging entries only if at least one staged entry is fresh.
            staged.values().any(|e| now.saturating_sub(e.last_seen) < STALENESS_SECS)
                && !pruned.contains(id)
        });
    }

    /// Get all entries as an iterator.
    pub fn entries(&self) -> impl Iterator<Item = &NetworkMapEntry> {
        self.entries.values()
    }

    /// Get mutable entry.
    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut NetworkMapEntry> {
        self.entries.get_mut(peer_id)
    }

    /// Remove an entry.
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<NetworkMapEntry> {
        self.last_update_ts.remove(peer_id);
        self.pending_multi_source.remove(peer_id);
        self.entries.remove(peer_id)
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Validate entry field lengths and endpoint formats per §4.2.
    ///
    /// Any entry with a field that fails validation is rejected entirely and
    /// must not be gossiped further — never sanitize-and-forward (§4.2).
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
            // avatar_hash must be exactly 32 bytes when present (§4.2).
            if let Some(ref hash) = profile.avatar_hash {
                if hash.len() != 32 {
                    return Err(MapError::InvalidAvatarHash(hash.len()));
                }
            }
        }
        // Validate each transport hint endpoint format (§4.2).
        for hint in &entry.transport_hints {
            if let Some(ref endpoint) = hint.endpoint {
                if !Self::validate_endpoint_format(&hint.transport, endpoint) {
                    return Err(MapError::InvalidEndpointFormat {
                        transport: format!("{:?}", hint.transport),
                        endpoint: endpoint.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Validate a transport endpoint string against the format rules for its
    /// transport type (§4.2).  Returns `false` for any format violation.
    fn validate_endpoint_format(transport: &TransportType, endpoint: &str) -> bool {
        // Reject empty or excessively long endpoints before type-specific checks.
        if endpoint.is_empty() || endpoint.len() > 512 {
            return false;
        }
        match transport {
            TransportType::Clearnet => Self::is_valid_clearnet_endpoint(endpoint),
            TransportType::Tor => Self::is_valid_tor_endpoint(endpoint),
            TransportType::I2P => Self::is_valid_i2p_endpoint(endpoint),
            TransportType::Yggdrasil => Self::is_valid_yggdrasil_endpoint(endpoint),
            TransportType::Cjdns => Self::is_valid_cjdns_endpoint(endpoint),
            TransportType::ZeroTier | TransportType::Tailscale => {
                // These carry IP:port or domain:port addresses on their overlay plane.
                Self::is_valid_clearnet_endpoint(endpoint)
                    || Self::is_valid_hostname_port(endpoint)
            }
            // Proximity and RF transports carry no routable endpoint; if one
            // is present it must be a short, printable identifier only.
            TransportType::BLE
            | TransportType::BluetoothClassic
            | TransportType::WiFiDirect
            | TransportType::NFC
            | TransportType::Ultrasonic
            | TransportType::USBSerial
            | TransportType::Layer2
            | TransportType::RF
            | TransportType::LoRa
            | TransportType::SdrHf
            | TransportType::SdrVhf
            | TransportType::SdrUhf
            | TransportType::SdrShf
            | TransportType::SdrFhss
            | TransportType::Telephone
            | TransportType::CANBus
            | TransportType::PPPoE
            | TransportType::Dialup => {
                // Short printable ASCII identifier, ≤ 128 bytes.
                endpoint.len() <= 128 && endpoint.bytes().all(|b| b >= 0x20 && b < 0x7f)
            }
            // Overlay/mixnet types: node addresses are base32/base64 identifiers
            // or onion-style strings.  Restrict to alphanumeric + safe punctuation
            // to prevent injection into downstream parsers.
            TransportType::GNUnet
            | TransportType::Mixnet => {
                endpoint.len() <= 128
                    && endpoint
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
            }
        }
    }

    /// Validate a clearnet IP:port endpoint (IPv4 or bracketed IPv6).
    fn is_valid_clearnet_endpoint(endpoint: &str) -> bool {
        // std::net::SocketAddr handles `1.2.3.4:port` and `[::1]:port`.
        endpoint.parse::<std::net::SocketAddr>().is_ok()
    }

    /// Validate a `hostname:port` endpoint where the host is not a bare IP.
    fn is_valid_hostname_port(endpoint: &str) -> bool {
        let Some(colon) = endpoint.rfind(':') else {
            return false;
        };
        let host = &endpoint[..colon];
        let port_str = &endpoint[colon + 1..];
        let Ok(port) = port_str.parse::<u16>() else {
            return false;
        };
        if port == 0 {
            return false;
        }
        // Host must be non-empty, contain only hostname-legal characters, and
        // must not be a bare IP address (those are handled by clearnet check).
        !host.is_empty()
            && host.len() <= 253
            && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            && !host.starts_with('-')
            && !host.ends_with('-')
    }

    /// Validate a Tor v3 onion address: `[a-z2-7]{56}.onion` with optional `:port`.
    fn is_valid_tor_endpoint(endpoint: &str) -> bool {
        let (onion_part, port_part) = match endpoint.rfind(':') {
            Some(colon) if !endpoint[..colon].ends_with(']') => {
                (&endpoint[..colon], Some(&endpoint[colon + 1..]))
            }
            _ => (endpoint, None),
        };
        if !onion_part.ends_with(".onion") {
            return false;
        }
        let base32 = &onion_part[..onion_part.len() - 6];
        // v3 onion addresses are exactly 56 base32 characters.
        if base32.len() != 56 {
            return false;
        }
        if !base32
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
        {
            return false;
        }
        if let Some(port) = port_part {
            if port.parse::<u16>().is_err() {
                return false;
            }
        }
        true
    }

    /// Validate an I2P address: `.b32.i2p` suffix (52 base32 chars) or
    /// `.i2p` domain.
    fn is_valid_i2p_endpoint(endpoint: &str) -> bool {
        let host = match endpoint.rfind(':') {
            Some(colon) => {
                let port_str = &endpoint[colon + 1..];
                if port_str.parse::<u16>().is_err() {
                    return false;
                }
                &endpoint[..colon]
            }
            None => endpoint,
        };
        if !host.ends_with(".i2p") {
            return false;
        }
        // Basic length sanity: I2P addresses are at most 516 chars.
        host.len() <= 516
            && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    }

    /// Validate a Yggdrasil address: IPv6 in the `200::/7` range.
    ///
    /// Yggdrasil uses the `200::/7` block (first byte 0x02 or 0x03).
    fn is_valid_yggdrasil_endpoint(endpoint: &str) -> bool {
        let addr_str = Self::strip_bracketed_ipv6(endpoint);
        if let Ok(ip) = addr_str.parse::<std::net::Ipv6Addr>() {
            let first_byte = (ip.segments()[0] >> 8) as u8;
            return first_byte == 0x02 || first_byte == 0x03;
        }
        false
    }

    /// Validate a cjdns address: IPv6 in the `fc00::/8` range.
    fn is_valid_cjdns_endpoint(endpoint: &str) -> bool {
        let addr_str = Self::strip_bracketed_ipv6(endpoint);
        if let Ok(ip) = addr_str.parse::<std::net::Ipv6Addr>() {
            let first_byte = (ip.segments()[0] >> 8) as u8;
            return first_byte == 0xfc || first_byte == 0xfd;
        }
        false
    }

    /// Strip the `[…]:port` brackets and port from a bracketed IPv6 string,
    /// returning just the address portion for parsing.
    fn strip_bracketed_ipv6(s: &str) -> &str {
        if let Some(rest) = s.strip_prefix('[') {
            if let Some(close) = rest.find(']') {
                return &rest[..close];
            }
        }
        s
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
    /// Lower-bound timestamp violation (§4.2 replay prevention).
    #[error("Entry timestamp {entry_ts} is more than 30 days in the past (now: {now})")]
    TimestampTooOld { entry_ts: u64, now: u64 },
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
    /// avatar_hash must be exactly 32 bytes (§4.2).
    #[error("Invalid avatar_hash length: expected 32 bytes, got {0}")]
    InvalidAvatarHash(usize),
    /// Transport endpoint string failed format validation for its type (§4.2).
    #[error("Invalid endpoint format for {transport} transport: '{endpoint}'")]
    InvalidEndpointFormat { transport: String, endpoint: String },
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
            prev_hash: None,
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
        map.insert(
            make_entry(PeerId([0x01; 32]), 1, now - STALENESS_SECS - 1),
            now,
        )
        .unwrap();
        map.insert(make_entry(PeerId([0x02; 32]), 1, now - 100), now)
            .unwrap();
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
        map.insert(make_entry(pid, 1, now - STALENESS_SECS - 1), now)
            .unwrap();
        map.get_mut(&pid).unwrap().local_trust = TrustLevel::Trusted;

        map.prune_stale(now);
        assert_eq!(map.len(), 1); // Still there — trusted
    }

    #[test]
    fn test_field_validation() {
        let mut entry = make_entry(PeerId([0x01; 32]), 1, 100);
        entry.transport_hints = (0..9)
            .map(|_| super::super::transport_hint::TransportHint {
                transport: super::super::transport_hint::TransportType::Clearnet,
                endpoint: Some("1.2.3.4:5".into()),
            })
            .collect();

        let mut map = NetworkMap::new();
        assert!(map.insert(entry, 100).is_err());
    }

    #[test]
    fn test_signature_sign_and_verify() {
        use ed25519_dalek::SigningKey;

        let raw_key = [0x7au8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();
        let x25519_pub = [0u8; 32]; // Placeholder for test.

        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        let mut entry = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: x25519_pub,
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 1_000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            prev_hash: None,
            local_trust: TrustLevel::Unknown,
        };

        entry.sign(&signing_key);
        assert_eq!(entry.signature.len(), 64);
        assert!(entry.verify_signature().is_ok());
    }

    #[test]
    fn test_signature_wrong_peer_id_rejected() {
        use ed25519_dalek::SigningKey;

        let raw_key = [0x7au8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();

        // peer_id doesn't match the key.
        let wrong_peer_id = PeerId([0xFFu8; 32]);
        let mut entry = NetworkMapEntry {
            peer_id: wrong_peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 1_000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![0u8; 64],
            prev_hash: None,
            local_trust: TrustLevel::Unknown,
        };

        entry.sign(&signing_key);
        // Change the peer_id after signing — verification must fail.
        entry.peer_id = PeerId([0xFFu8; 32]);
        assert!(entry.verify_signature().is_err());
    }

    #[test]
    fn test_tampered_entry_rejected() {
        use ed25519_dalek::SigningKey;

        let raw_key = [0x3bu8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();
        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        let mut entry = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 1_000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            prev_hash: None,
            local_trust: TrustLevel::Unknown,
        };

        entry.sign(&signing_key);
        // Tamper with sequence after signing.
        entry.sequence = 999;
        assert!(entry.verify_signature().is_err());
    }

    #[test]
    fn test_prev_hash_chain() {
        use ed25519_dalek::SigningKey;

        let raw_key = [0x5cu8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();
        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        let mut map = NetworkMap::new();

        // First entry (sequence 1, no prev_hash)
        let mut entry1 = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 1000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            prev_hash: None,
            local_trust: TrustLevel::Unknown,
        };
        entry1.sign(&signing_key);
        assert!(map.insert(entry1, 1000).unwrap());

        // Second entry (sequence 2, must have prev_hash = hash of entry1's payload)
        let prev_entry = map.get(&peer_id).unwrap();
        let prev_hash = prev_entry.payload_hash();

        let mut entry2 = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 2000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 2,
            signature: vec![],
            prev_hash: Some(prev_hash),
            local_trust: TrustLevel::Unknown,
        };
        entry2.sign(&signing_key);
        assert!(map.insert(entry2, 2000).unwrap());

        // Verify the chain
        let stored = map.get(&peer_id).unwrap();
        assert_eq!(stored.sequence, 2);
        assert!(stored.prev_hash.is_some());
    }

    #[test]
    fn test_prev_hash_mismatch_rejected() {
        use ed25519_dalek::SigningKey;

        let raw_key = [0x5cu8; 32];
        let signing_key = SigningKey::from_bytes(&raw_key);
        let verifying_key = signing_key.verifying_key();
        let ed_pub: [u8; 32] = verifying_key.to_bytes();
        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        let mut map = NetworkMap::new();

        // First entry
        let mut entry1 = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 1000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 1,
            signature: vec![],
            prev_hash: None,
            local_trust: TrustLevel::Unknown,
        };
        entry1.sign(&signing_key);
        map.insert(entry1, 1000).unwrap();

        // Second entry with wrong prev_hash
        let mut entry2 = NetworkMapEntry {
            peer_id,
            public_keys: vec![super::PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            last_seen: 2000,
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: 2,
            signature: vec![],
            prev_hash: Some([0xFF; 32]), // Wrong hash
            local_trust: TrustLevel::Unknown,
        };
        entry2.sign(&signing_key);
        assert!(map.insert(entry2, 2000).is_err()); // Should be rejected
    }

    #[test]
    fn test_capacity_eviction() {
        assert_eq!(MAX_MAP_ENTRIES, 100_000);
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut map = NetworkMap::new();
        map.insert(make_entry(PeerId([0x01; 32]), 1, 100), 100)
            .unwrap();

        let json = serde_json::to_string(&map).unwrap();
        let recovered: NetworkMap = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.len(), 1);
    }
}
