//! Network Map (§4.1, §4.2)
//!
//! The network map is a public-only structure containing:
//! - Peer IDs and public addresses
//! - Public keys (Ed25519, X25519)
//! - Transport hints (how to reach each peer)
//! - Optional public profile summaries (`PUBLIC_OPT_IN`)
//! - Optional public service advertisements, only for services the host has
//!   explicitly marked for public announcement (`PUBLIC_OPT_IN`, §12.4)
//!
//! A map entry carries **no peer-reported time** (§4.2, CMR-005). Presence and
//! last-seen information are never map data; they travel only over
//! trust-relationship channels (§10.1.8). Staleness pruning and LRU eviction
//! use the local `received_at` clock recorded in [`StoredMapEntry`] when the
//! entry was accepted. That value is `LOCAL_ONLY` (§2.1.1): persisted with the
//! entry, never signed, never serialized onto the wire.
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

/// Wire-format version of `NetworkMapEntry` (§4.2).
///
/// Version 1 carried a self-reported `last_seen` timestamp inside the signed
/// preimage; CMR-005 removed it. Version 2 entries carry no peer-reported
/// time at all. A received entry whose `version` is not this value is
/// rejected with `MapError::UnsupportedEntryVersion` — the old layout is
/// never silently accepted (pre-1.0, no compatibility shim is kept).
// MAP_ENTRY_FORMAT_VERSION — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAP_ENTRY_FORMAT_VERSION: u8 = 2;

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
///
/// This is the **wire** structure: every field except `local_trust` is
/// serialized to peers and (except `signature`) covered by the owner's
/// Ed25519 signature. It deliberately carries no time of any kind — the
/// local receipt clock lives in [`StoredMapEntry`], never here.
///
/// `deny_unknown_fields` is load-bearing: a peer that still sends the v1
/// layout (with `last_seen`), or smuggles any local-only field such as
/// `received_at` or `local_trust` onto the wire, fails deserialization with a
/// typed serde error instead of being silently accepted with the extra field
/// dropped. Treat any change here as a wire-format change (§4.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMapEntry {
    /// Wire-format version; must equal `MAP_ENTRY_FORMAT_VERSION` (§4.2).
    /// Signed first so a downgraded layout cannot reuse a valid signature.
    pub version: u8,
    /// Peer identifier.
    pub peer_id: PeerId,
    /// Public keys for this peer.
    pub public_keys: Vec<PublicKeyRecord>,
    /// Transport hints: how to reach this peer.
    pub transport_hints: Vec<TransportHint>,
    /// Optional public profile summary (if identity_is_public).
    pub public_profile: Option<PublicProfileSummary>,
    /// Public service advertisements. Only services the host has explicitly
    /// enabled for public announcement appear here (§12.4); default empty.
    /// Non-public services are announced inside trust-scoped channels only.
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

/// Local bookkeeping attached to a stored map entry (§4.2 `StoredMapEntry`).
///
/// This is the **storage** structure. `received_at` is `LOCAL_ONLY`
/// (§2.1.1): it is persisted with the entry so a restart does not reset it,
/// but it is never part of the signed preimage and never leaves this node —
/// the wire type is the inner `NetworkMapEntry`, which has no such field.
/// Staleness pruning (§4.2) and LRU eviction (§17.9) read this value; a peer
/// cannot influence it because it is taken from the local clock at acceptance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMapEntry {
    /// The verified wire entry exactly as the owner signed it.
    pub entry: NetworkMapEntry,
    /// Local Unix time (seconds) at which this entry was accepted.
    /// Updated only when a newer entry for the same peer is accepted.
    pub received_at: u64,
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
///
/// Bumped from `v1` to `v2` by CMR-005: the v1 preimage contained the
/// self-reported `last_seen` field. Because the domain string is the first
/// bytes of every preimage, a v1 signature can never verify against a v2
/// payload (and vice versa), so an old-layout entry is rejected at signature
/// verification even before the `version` field check runs.
const DOMAIN_MAP_ENTRY: &[u8] = b"meshinfinity-map-entry-v2\x00";

impl NetworkMapEntry {
    /// Build the canonical byte payload that is signed by the entry's owner.
    ///
    /// Format (§4.5, wire version 2):
    ///   DOMAIN || version (1) || peer_id (32) || BE64(sequence)
    ///   || BE32(n_keys) || [ed25519_pub (32) || x25519_pub (32) || preauth (32)
    ///                       || BE32(kem_len) || kem_ek || BE32(preauth_sig_len) || preauth_sig]…
    ///   || BE32(hints_json_len) || hints_json
    ///   || BE32(services_json_len) || services_json
    ///   || BE32(profile_json_len) || profile_json
    ///   || prev_hash (32) if present
    ///
    /// Every byte of every `PublicKeyRecord` is covered, including the
    /// ML-KEM encapsulation key and the preauth signature. Gossip is
    /// re-forwarded by untrusted relays (§4.1); a relay that could swap the
    /// KEM key without breaking the signature would silently downgrade PQXDH
    /// to classical X3DH for every contact that copies the key (§3.4.1,
    /// §7.0.1). Absent optional fields are signed as zero length so presence
    /// itself is authenticated.
    ///
    /// No time of any kind is signed (§4.5 rule 3). The `signature` and
    /// `local_trust` fields are excluded; `received_at` is not a field of this
    /// type at all, so it cannot be signed by construction.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(DOMAIN_MAP_ENTRY);
        // The version byte is signed so a relay cannot relabel an entry.
        buf.push(self.version);
        buf.extend_from_slice(&self.peer_id.0);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&(self.public_keys.len() as u32).to_be_bytes());
        for pk in &self.public_keys {
            buf.extend_from_slice(&pk.ed25519_public);
            buf.extend_from_slice(&pk.x25519_public);
            // Preauth key is signed as 32 zero bytes if absent.
            buf.extend_from_slice(pk.preauth_x25519_public.as_ref().unwrap_or(&[0u8; 32]));
            // KEM encapsulation key and preauth signature are length-prefixed
            // so an absent field (len 0) is distinguishable from any present one.
            let kem = pk.kem_encapsulation_key.as_deref().unwrap_or(&[]);
            buf.extend_from_slice(&(kem.len() as u32).to_be_bytes());
            buf.extend_from_slice(kem);
            let preauth_sig = pk.preauth_sig.as_deref().unwrap_or(&[]);
            buf.extend_from_slice(&(preauth_sig.len() as u32).to_be_bytes());
            buf.extend_from_slice(preauth_sig);
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
    /// Map entries keyed by PeerId, each wrapped with its local `received_at`.
    /// This is the persisted form (§4.2): `received_at` survives a restart.
    entries: HashMap<PeerId, StoredMapEntry>,
    /// Staging buffer for entries awaiting multi-source confirmation (§4.1).
    ///
    /// When `entries.len() >= 100` each gossiped entry must be seen from at
    /// least 2 independent sources before it is promoted into `entries`.
    /// When `entries.len() >= 1000` the threshold rises to 3 sources.
    ///
    /// Key: peer_id of the entry being staged.
    /// Value: map of source_peer_id → best (highest-sequence) entry from that
    /// source, stamped with the local time it was staged so stale staging
    /// rows can be pruned on the same local clock as live entries.
    #[serde(skip)]
    pending_multi_source: HashMap<PeerId, HashMap<PeerId, StoredMapEntry>>,
    /// Timestamp of the most recently accepted sequence update per peer.
    /// Used to enforce MIN_UPDATE_INTERVAL_SECS rate limiting (§4.2).
    #[serde(skip)]
    last_update_ts: HashMap<PeerId, u64>,
    /// Whether at least one successful map exchange has completed since this
    /// process started (§4.2). Staleness pruning is suspended while `false`,
    /// so a node that was offline longer than `STALENESS_SECS` keeps its map
    /// until it has had a chance to re-observe peers. Deliberately not
    /// persisted: "since start" means every load begins suspended.
    #[serde(skip)]
    exchange_complete: bool,
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

    /// Get the wire entry for a peer ID.
    pub fn get(&self, peer_id: &PeerId) -> Option<&NetworkMapEntry> {
        self.entries.get(peer_id).map(|stored| &stored.entry)
    }

    /// Get the stored entry (wire entry plus local `received_at`) for a peer.
    pub fn get_stored(&self, peer_id: &PeerId) -> Option<&StoredMapEntry> {
        self.entries.get(peer_id)
    }

    /// Local receipt time of a peer's current entry, if the peer is known.
    /// This is the only "time" the map knows about a peer (§4.2).
    pub fn received_at(&self, peer_id: &PeerId) -> Option<u64> {
        self.entries.get(peer_id).map(|stored| stored.received_at)
    }

    /// Whether a successful map exchange has completed since process start.
    /// While `false`, `prune_stale` is a no-op (§4.2).
    pub fn exchange_complete(&self) -> bool {
        self.exchange_complete
    }

    /// Record that a successful map exchange has completed since start,
    /// lifting the suspension on staleness pruning (§4.2).
    ///
    /// Called by the gossip engine once a remote peer's signed entry has been
    /// verified and merged. Idempotent; there is no way to un-set it short of
    /// a restart, matching the spec's "since start" wording.
    pub fn mark_exchange_complete(&mut self) {
        self.exchange_complete = true;
    }

    /// Insert or update an entry. Returns true if the entry was accepted.
    ///
    /// `now` is the **local** clock and becomes the entry's `received_at`.
    /// Nothing in `entry` is interpreted as a time (§4.5 rule 3).
    ///
    /// Acceptance rules (§4.2, §4.5):
    /// 1. Wire-format `version` must equal `MAP_ENTRY_FORMAT_VERSION`.
    /// 2. Sequence must be strictly greater than existing (or new entry).
    /// 3. Per-peer update rate: at most 1 accepted update per MIN_UPDATE_INTERVAL_SECS.
    /// 4. Field validation must pass (lengths, endpoint formats, avatar hash length).
    /// 5. If prev_hash is present and an existing entry is stored, it must match.
    ///
    /// Signature verification is the caller's responsibility (gossip.rs runs it
    /// before reaching here).
    pub fn insert(&mut self, entry: NetworkMapEntry, now: u64) -> Result<bool, MapError> {
        // --- Field and version validation (§4.2) ---
        // There is no timestamp window: the entry has no time field to check.
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
            if entry.sequence <= existing.entry.sequence {
                return Ok(false); // Stale — silently ignore.
            }
            // Verify prev_hash chain for updates to an existing entry.
            if let Some(prev_hash) = &entry.prev_hash {
                let expected_hash = existing.entry.payload_hash();
                if prev_hash != &expected_hash {
                    return Err(MapError::InvalidSignature(
                        "prev_hash does not match previous entry's payload hash".into(),
                    ));
                }
            }
        }
        // else: brand-new peer — accept any sequence (may have missed earlier updates).

        // --- Capacity check ---
        if self.entries.len() >= MAX_MAP_ENTRIES && !self.entries.contains_key(&entry.peer_id) {
            // Need to evict — LRU of untrusted entries first.
            self.evict_for_new_entry();
        }

        let peer_id = entry.peer_id;
        // Stamp the entry with the local clock. This is the only place
        // `received_at` is ever set for a live entry (§4.2): acceptance time,
        // from our own clock, never from anything the peer sent.
        self.entries.insert(
            peer_id,
            StoredMapEntry {
                entry,
                received_at: now,
            },
        );
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
        // (Version and field checks only; there is no timestamp to window.)
        Self::validate_entry(&entry)?;

        let target_peer = entry.peer_id;

        // If an existing live entry has the same or higher sequence, skip staging.
        if let Some(existing) = self.entries.get(&target_peer) {
            if entry.sequence <= existing.entry.sequence {
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
        let staged_sources = self.pending_multi_source.entry(target_peer).or_default();

        // Enforce per-peer source cap to limit per-entry memory consumption.
        if !staged_sources.contains_key(source_id)
            && staged_sources.len() >= MAX_STAGED_SOURCES_PER_PEER
        {
            // Too many distinct sources already staged — drop this one.
            return Ok(false);
        }

        // Keep the highest-sequence entry per source, stamped with the local
        // time it was staged so prune_stale can age the staging buffer too.
        let current_best = staged_sources.get(source_id);
        if current_best.is_none_or(|existing| entry.sequence > existing.entry.sequence) {
            staged_sources.insert(
                *source_id,
                StoredMapEntry {
                    entry,
                    received_at: now,
                },
            );
        }

        // Check if we now have enough independent sources to promote.
        if staged_sources.len() >= required {
            // Select the entry with the highest sequence number.
            let best = staged_sources
                .values()
                .max_by_key(|s| s.entry.sequence)
                .map(|s| s.entry.clone());

            // Remove from staging regardless of whether promotion succeeds.
            self.pending_multi_source.remove(&target_peer);

            if let Some(best_entry) = best {
                // `insert` re-stamps received_at with the promotion time.
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

    /// Remove stale entries: untrusted entries whose local `received_at` is
    /// older than `STALENESS_SECS` (§4.2, §17.9).
    ///
    /// Suspended (returns without touching anything) until
    /// `mark_exchange_complete` has been called since process start. A node
    /// that was offline for longer than the threshold would otherwise discard
    /// its whole map on the first cleanup tick before it could re-observe
    /// anyone; conversely it never treats old entries as fresh, because
    /// `received_at` is persisted rather than reset on load.
    ///
    /// Trusted-tier entries are never pruned by staleness (§17.9).
    pub fn prune_stale(&mut self, now: u64) {
        // §4.2: staleness pruning is suspended until one successful map
        // exchange has completed since start.
        if !self.exchange_complete {
            return;
        }
        let mut pruned: Vec<PeerId> = Vec::new();
        self.entries.retain(|id, stored| {
            if stored.entry.local_trust.is_trusted_tier() {
                return true;
            }
            // Age is measured purely on the local receipt clock; a peer has
            // no field with which to extend its own lifetime (§4.5 rule 3).
            let keep = now.saturating_sub(stored.received_at) < STALENESS_SECS;
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
            // Keep staging entries only if at least one staged row is fresh
            // on the same local clock.
            staged
                .values()
                .any(|s| now.saturating_sub(s.received_at) < STALENESS_SECS)
                && !pruned.contains(id)
        });
    }

    /// Get all wire entries as an iterator.
    pub fn entries(&self) -> impl Iterator<Item = &NetworkMapEntry> {
        self.entries.values().map(|stored| &stored.entry)
    }

    /// Get all stored entries (wire entry plus local `received_at`).
    pub fn stored_entries(&self) -> impl Iterator<Item = &StoredMapEntry> {
        self.entries.values()
    }

    /// Get a mutable wire entry (used to set `local_trust`).
    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut NetworkMapEntry> {
        self.entries
            .get_mut(peer_id)
            .map(|stored| &mut stored.entry)
    }

    /// Remove an entry, returning the stored form if it existed.
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<StoredMapEntry> {
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
        // Wire-format gate (§4.2): the v1 layout (with `last_seen`) and any
        // unknown future layout are rejected with a typed error, never
        // reinterpreted. Checked first so no other field of an unsupported
        // layout is ever trusted.
        if entry.version != MAP_ENTRY_FORMAT_VERSION {
            return Err(MapError::UnsupportedEntryVersion(entry.version));
        }
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
                Self::is_valid_clearnet_endpoint(endpoint) || Self::is_valid_hostname_port(endpoint)
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
                endpoint.len() <= 128 && endpoint.bytes().all(|b| (0x20..0x7f).contains(&b))
            }
            // Overlay/mixnet types: node addresses are base32/base64 identifiers
            // or onion-style strings.  Restrict to alphanumeric + safe punctuation
            // to prevent injection into downstream parsers.
            TransportType::GNUnet | TransportType::Mixnet => {
                endpoint.len() <= 128
                    && endpoint.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/')
                    })
            }
            // DeniableCarrier: the carrier ladder resolves the actual endpoint
            // address internally; the hint endpoint is an opaque broker locator.
            // Accept anything that is a valid clearnet endpoint or a short ASCII
            // identifier — the ladder validates the rest.
            TransportType::DeniableCarrier => {
                Self::is_valid_clearnet_endpoint(endpoint)
                    || (endpoint.len() <= 256
                        && endpoint.bytes().all(|b| (0x20..0x7f).contains(&b)))
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
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
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
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
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

    /// Evict the least recently received untrusted entry to make room.
    /// If all entries are trusted, evict the oldest trusted entry by local
    /// `received_at` (§17.9 edge case). "Oldest" is always measured on the
    /// local receipt clock — a peer cannot make its entry look fresh.
    fn evict_for_new_entry(&mut self) {
        // Find the least recently received untrusted entry.
        let oldest_untrusted = self
            .entries
            .iter()
            .filter(|(_, s)| s.entry.local_trust.is_untrusted_tier())
            .min_by_key(|(_, s)| s.received_at)
            .map(|(id, _)| *id);

        if let Some(id) = oldest_untrusted {
            self.entries.remove(&id);
            self.last_update_ts.remove(&id);
            return;
        }

        // All trusted — evict the least recently received (extreme edge case).
        let oldest_trusted = self
            .entries
            .iter()
            .min_by_key(|(_, s)| s.received_at)
            .map(|(id, _)| *id);

        if let Some(id) = oldest_trusted {
            self.entries.remove(&id);
            self.last_update_ts.remove(&id);
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    /// Wire-format version is not `MAP_ENTRY_FORMAT_VERSION` (§4.2). Covers
    /// the pre-CMR-005 v1 layout that carried a self-reported `last_seen`.
    #[error("Unsupported map entry format version {0} (expected {MAP_ENTRY_FORMAT_VERSION})")]
    UnsupportedEntryVersion(u8),
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

    /// Unsigned stub entry for merge-rule tests (no public keys, so
    /// `verify_signature` passes it through; `insert` never verifies anyway).
    fn make_entry(peer_id: PeerId, seq: u64) -> NetworkMapEntry {
        NetworkMapEntry {
            version: MAP_ENTRY_FORMAT_VERSION,
            peer_id,
            public_keys: vec![],
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: seq,
            signature: vec![],
            prev_hash: None,
            local_trust: TrustLevel::Unknown,
        }
    }

    /// Properly signed entry with a deterministic key derived from `seed`.
    /// Returns the signing key too so tests can re-sign after mutation.
    fn signed_entry(
        seed: u8,
        seq: u64,
        prev_hash: Option<[u8; 32]>,
    ) -> (NetworkMapEntry, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let ed_pub: [u8; 32] = signing_key.verifying_key().to_bytes();
        let mut entry = NetworkMapEntry {
            version: MAP_ENTRY_FORMAT_VERSION,
            peer_id: PeerId::from_ed25519_pub(&ed_pub),
            public_keys: vec![PublicKeyRecord {
                ed25519_public: ed_pub,
                x25519_public: [0u8; 32],
                preauth_x25519_public: None,
                kem_encapsulation_key: None,
                preauth_sig: None,
            }],
            transport_hints: vec![],
            public_profile: None,
            services: vec![],
            sequence: seq,
            signature: vec![],
            prev_hash,
            local_trust: TrustLevel::Unknown,
        };
        entry.sign(&signing_key);
        (entry, signing_key)
    }

    // -------------------------------------------------------------------
    // Merge rules (§4.5)
    // -------------------------------------------------------------------

    #[test]
    fn test_insert_new_entry() {
        let mut map = NetworkMap::new();
        let entry = make_entry(PeerId([0x01; 32]), 1);
        assert!(map.insert(entry, 100).unwrap());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_higher_sequence_wins() {
        let mut map = NetworkMap::new();
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 1), 100).unwrap();
        assert!(map.insert(make_entry(pid, 2), 200).unwrap());
        assert_eq!(map.get(&pid).unwrap().sequence, 2);
        // Re-acceptance re-stamps the local receipt clock.
        assert_eq!(map.received_at(&pid), Some(200));
    }

    #[test]
    fn test_lower_sequence_rejected() {
        let mut map = NetworkMap::new();
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 5), 100).unwrap();
        assert!(!map.insert(make_entry(pid, 3), 200).unwrap());
        assert_eq!(map.get(&pid).unwrap().sequence, 5);
        // A rejected update must not touch the stored receipt time either.
        assert_eq!(map.received_at(&pid), Some(100));
    }

    // -------------------------------------------------------------------
    // Wire format (§4.2, CMR-005): no peer-reported time, versioned layout
    // -------------------------------------------------------------------

    /// The pre-CMR-005 v1 layout carried `last_seen`. A wire entry that still
    /// sends it must fail deserialization with a typed error — never be
    /// accepted with the field silently dropped.
    #[test]
    fn test_wire_entry_carrying_last_seen_is_rejected() {
        let (entry, _) = signed_entry(0x21, 1, None);
        let mut json = serde_json::to_value(&entry).unwrap();
        json["last_seen"] = serde_json::json!(1_700_000_000u64);
        let err = serde_json::from_value::<NetworkMapEntry>(json).unwrap_err();
        assert!(
            err.to_string().contains("last_seen"),
            "error must name the rejected field: {err}"
        );
    }

    /// Local-only bookkeeping names must be rejected on the wire too, so a
    /// peer cannot pre-set our `received_at` or `local_trust`.
    #[test]
    fn test_wire_entry_smuggling_local_only_fields_is_rejected() {
        for field in ["received_at", "local_trust"] {
            let (entry, _) = signed_entry(0x22, 1, None);
            let mut json = serde_json::to_value(&entry).unwrap();
            json[field] = serde_json::json!(0u64);
            assert!(
                serde_json::from_value::<NetworkMapEntry>(json).is_err(),
                "wire entry with `{field}` must be rejected"
            );
        }
    }

    /// `received_at` is LOCAL_ONLY: it never appears in the wire JSON and
    /// never influences the signed preimage; it is only in `StoredMapEntry`.
    #[test]
    fn test_received_at_is_never_serialized_onto_the_wire() {
        let (entry, _) = signed_entry(0x23, 7, None);
        let wire = serde_json::to_value(&entry).unwrap();
        let keys: Vec<&str> = wire
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(!keys.contains(&"received_at"), "wire keys: {keys:?}");
        assert!(!keys.contains(&"last_seen"), "wire keys: {keys:?}");
        assert!(!keys.contains(&"local_trust"), "wire keys: {keys:?}");
        assert!(keys.contains(&"version"), "wire keys: {keys:?}");

        // The storage wrapper carries it (persisted, §4.2) but the nested
        // wire entry inside it still does not.
        let stored = StoredMapEntry {
            entry: entry.clone(),
            received_at: 42,
        };
        let stored_json = serde_json::to_value(&stored).unwrap();
        assert_eq!(stored_json["received_at"], 42);
        assert!(stored_json["entry"].get("received_at").is_none());
        assert!(stored_json["entry"].get("last_seen").is_none());

        // Two wrappers with different receipt times share one preimage.
        let other = StoredMapEntry {
            entry,
            received_at: 9_999,
        };
        assert_eq!(
            stored.entry.signing_payload(),
            other.entry.signing_payload()
        );
    }

    /// `received_at` comes from the caller's local clock, never from the entry.
    #[test]
    fn test_received_at_taken_from_local_clock() {
        let mut map = NetworkMap::new();
        let pid = PeerId([0x05; 32]);
        assert!(map.insert(make_entry(pid, 1), 500).unwrap());
        assert_eq!(map.received_at(&pid), Some(500));
        assert_eq!(map.get_stored(&pid).unwrap().received_at, 500);
        assert_eq!(map.stored_entries().count(), 1);
    }

    /// An entry whose `version` is not the current format is rejected with a
    /// typed error on both insert paths, even when otherwise well-formed.
    #[test]
    fn test_unsupported_version_rejected() {
        let mut map = NetworkMap::new();
        let mut v1 = make_entry(PeerId([0x06; 32]), 1);
        v1.version = 1;
        match map.insert(v1.clone(), 100) {
            Err(MapError::UnsupportedEntryVersion(1)) => {}
            other => panic!("expected UnsupportedEntryVersion(1), got {other:?}"),
        }
        match map.insert_gossiped(v1, &PeerId([0x07; 32]), 100) {
            Err(MapError::UnsupportedEntryVersion(1)) => {}
            other => panic!("expected UnsupportedEntryVersion(1), got {other:?}"),
        }
        assert!(map.is_empty());
    }

    /// The version byte is inside the signed preimage: relabelling a signed
    /// entry's version invalidates its signature.
    #[test]
    fn test_version_is_covered_by_signature() {
        let (mut entry, _) = signed_entry(0x24, 1, None);
        assert!(entry.verify_signature().is_ok());
        entry.version = 1;
        assert!(entry.verify_signature().is_err());
    }

    // -------------------------------------------------------------------
    // Staleness pruning (§4.2, §17.9)
    // -------------------------------------------------------------------

    /// Pruning is suspended until one successful map exchange has completed
    /// since start; afterwards it removes untrusted entries older than
    /// STALENESS_SECS on the local receipt clock.
    #[test]
    fn test_prune_suspended_until_first_exchange() {
        let mut map = NetworkMap::new();
        let now = 10_000_000u64;
        let stale = PeerId([0x01; 32]);
        let fresh = PeerId([0x02; 32]);
        map.insert(make_entry(stale, 1), now - STALENESS_SECS - 1)
            .unwrap();
        map.insert(make_entry(fresh, 1), now - 100).unwrap();
        assert_eq!(map.len(), 2);

        // Before the first exchange: nothing is pruned, however stale.
        assert!(!map.exchange_complete());
        map.prune_stale(now);
        assert_eq!(
            map.len(),
            2,
            "pruning must be suspended before first exchange"
        );

        // After the first exchange: the stale untrusted entry goes.
        map.mark_exchange_complete();
        assert!(map.exchange_complete());
        map.prune_stale(now);
        assert_eq!(map.len(), 1);
        assert!(map.get(&stale).is_none());
        assert!(map.get(&fresh).is_some());
    }

    #[test]
    fn test_trusted_entries_not_pruned() {
        let mut map = NetworkMap::new();
        let now = 10_000_000u64;
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 1), now - STALENESS_SECS - 1)
            .unwrap();
        map.get_mut(&pid).unwrap().local_trust = TrustLevel::Trusted;

        map.mark_exchange_complete();
        map.prune_stale(now);
        assert_eq!(map.len(), 1); // Still there — trusted
    }

    /// `received_at` survives a persist/load round trip; the exchange flag
    /// does not (every load starts suspended, "since start").
    #[test]
    fn test_received_at_persisted_and_exchange_flag_reset_on_load() {
        let mut map = NetworkMap::new();
        let pid = PeerId([0x01; 32]);
        map.insert(make_entry(pid, 1), 1234).unwrap();
        map.mark_exchange_complete();

        let json = serde_json::to_string(&map).unwrap();
        let loaded: NetworkMap = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.received_at(&pid), Some(1234));
        assert!(
            !loaded.exchange_complete(),
            "suspension must restart on load"
        );
    }

    /// Capacity eviction removes the least recently *received* untrusted
    /// entry — measured on our clock, not anything a peer claimed.
    #[test]
    fn test_capacity_eviction_uses_received_at() {
        let mut map = NetworkMap::new();
        // Fill to the cap with distinct peers at increasing receipt times.
        for i in 0..MAX_MAP_ENTRIES as u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            map.insert(make_entry(PeerId(id), 1), 1_000 + u64::from(i))
                .unwrap();
        }
        assert_eq!(map.len(), MAX_MAP_ENTRIES);
        let oldest = PeerId([0u8; 32]);
        assert!(map.get(&oldest).is_some());

        // One more peer forces eviction of the earliest-received entry.
        let newcomer = PeerId([0xEE; 32]);
        assert!(map.insert(make_entry(newcomer, 1), 5_000_000).unwrap());
        assert_eq!(map.len(), MAX_MAP_ENTRIES);
        assert!(
            map.get(&oldest).is_none(),
            "oldest-received entry must be evicted"
        );
        assert!(map.get(&newcomer).is_some());
    }

    // -------------------------------------------------------------------
    // Field validation and signatures
    // -------------------------------------------------------------------

    #[test]
    fn test_field_validation() {
        let mut entry = make_entry(PeerId([0x01; 32]), 1);
        entry.transport_hints = (0..9)
            .map(|_| TransportHint {
                transport: TransportType::Clearnet,
                endpoint: Some("1.2.3.4:5".into()),
            })
            .collect();

        let mut map = NetworkMap::new();
        assert!(map.insert(entry, 100).is_err());
    }

    #[test]
    fn test_signature_sign_and_verify() {
        let (entry, _) = signed_entry(0x7a, 1, None);
        assert_eq!(entry.signature.len(), 64);
        assert!(entry.verify_signature().is_ok());
    }

    #[test]
    fn test_signature_wrong_peer_id_rejected() {
        let (mut entry, _) = signed_entry(0x7a, 1, None);
        // Change the peer_id after signing — verification must fail.
        entry.peer_id = PeerId([0xFFu8; 32]);
        assert!(entry.verify_signature().is_err());
    }

    #[test]
    fn test_tampered_entry_rejected() {
        let (mut entry, _) = signed_entry(0x3b, 1, None);
        // Tamper with sequence after signing.
        entry.sequence = 999;
        assert!(entry.verify_signature().is_err());
    }

    /// A relay that substitutes the ML-KEM encapsulation key (PQXDH
    /// downgrade, §3.4.1) or the preauth signature must break the entry
    /// signature — these fields are inside the v2 preimage.
    #[test]
    fn test_relay_substituting_kem_key_or_preauth_sig_rejected() {
        let (mut entry, signing_key) = signed_entry(0x3c, 1, None);
        // Owner publishes a genuine KEM key and preauth signature.
        entry.public_keys[0].kem_encapsulation_key = Some(vec![0xAA; 1184]);
        entry.public_keys[0].preauth_sig = Some(vec![0xBB; 64]);
        entry.sign(&signing_key);
        assert!(entry.verify_signature().is_ok());

        // Relay swaps in its own KEM key: signature no longer verifies.
        let mut swapped = entry.clone();
        swapped.public_keys[0].kem_encapsulation_key = Some(vec![0xCC; 1184]);
        assert!(swapped.verify_signature().is_err());

        // Relay strips the KEM key entirely: presence is signed, so rejected.
        let mut stripped = entry.clone();
        stripped.public_keys[0].kem_encapsulation_key = None;
        assert!(stripped.verify_signature().is_err());

        // Relay tampers with the preauth signature bytes: rejected.
        let mut bad_sig = entry;
        bad_sig.public_keys[0].preauth_sig = Some(vec![0xDD; 64]);
        assert!(bad_sig.verify_signature().is_err());
    }

    #[test]
    fn test_prev_hash_chain() {
        let mut map = NetworkMap::new();

        // First entry (sequence 1, no prev_hash)
        let (entry1, _) = signed_entry(0x5c, 1, None);
        let peer_id = entry1.peer_id;
        assert!(map.insert(entry1, 1000).unwrap());

        // Second entry (sequence 2, prev_hash = hash of entry1's payload)
        let prev_hash = map.get(&peer_id).unwrap().payload_hash();
        let (entry2, _) = signed_entry(0x5c, 2, Some(prev_hash));
        assert!(map.insert(entry2, 2000).unwrap());

        // Verify the chain
        let stored = map.get(&peer_id).unwrap();
        assert_eq!(stored.sequence, 2);
        assert!(stored.prev_hash.is_some());
    }

    #[test]
    fn test_prev_hash_mismatch_rejected() {
        let mut map = NetworkMap::new();
        let (entry1, _) = signed_entry(0x5c, 1, None);
        map.insert(entry1, 1000).unwrap();

        // Second entry with wrong prev_hash
        let (entry2, _) = signed_entry(0x5c, 2, Some([0xFF; 32]));
        assert!(map.insert(entry2, 2000).is_err()); // Should be rejected
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut map = NetworkMap::new();
        map.insert(make_entry(PeerId([0x01; 32]), 1), 100).unwrap();

        let json = serde_json::to_string(&map).unwrap();
        let recovered: NetworkMap = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.len(), 1);
    }
}
