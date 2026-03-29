//! Contact Record (§8.3)
//!
//! # What is a Contact Record?
//!
//! A contact record is created after a successful pairing handshake.
//! It stores everything we know about a peer: their public keys,
//! how we paired with them, our trust level, and optional metadata
//! like display name and context annotation.
//!
//! # Relationship to Trust
//!
//! A contact record does NOT imply trust. A newly paired contact
//! starts at Level 0 (Unknown) or Level 5 (Acquaintance) depending
//! on the pairing method. Trust escalation is a separate, explicit
//! user action.
//!
//! # Safety Numbers
//!
//! After pairing, safety numbers (§3.7.7) are computed and stored
//! in the contact record. The user is encouraged to verify safety
//! numbers before assigning trust above Level 2.
//!
//! # Context Annotation
//!
//! Users can annotate contacts with context — why they paired,
//! where they met, etc. This is stored encrypted in the contact
//! record and helps the user remember the context of each
//! relationship when making trust decisions later.

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;
use crate::trust::levels::TrustLevel;
use super::methods::PairingMethod;

// ---------------------------------------------------------------------------
// Contact Record
// ---------------------------------------------------------------------------

/// A contact record (§8.3).
///
/// Created after a successful pairing handshake. Contains all
/// the information needed to communicate with and make trust
/// decisions about a peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactRecord {
    /// The peer's unique identifier (SHA-256 of Ed25519 public key).
    pub peer_id: PeerId,

    /// The peer's Ed25519 public key (signing and identity).
    pub ed25519_public: [u8; 32],

    /// The peer's X25519 public key (key agreement).
    pub x25519_public: [u8; 32],

    /// Display name (human-readable, optional).
    /// Set by the peer during pairing, verified by signature.
    pub display_name: Option<String>,

    /// Our local nickname for this contact (optional).
    /// Set by us, not shared with the peer.
    pub local_nickname: Option<String>,

    /// How we paired with this contact.
    pub pairing_method: PairingMethod,

    /// When the pairing occurred (Unix timestamp).
    pub paired_at: u64,

    /// Our trust level for this contact.
    /// Starts at the initial level from pairing (usually Level 0 or 5).
    pub trust_level: TrustLevel,

    /// User's context annotation (why/how we paired).
    /// Stored encrypted. Helps the user remember the relationship
    /// context when making trust decisions later.
    pub context_annotation: Option<String>,

    /// Safety number for this contact (§3.7.7).
    /// Computed from both parties' public keys.
    /// Stored as the 60-digit numeric format.
    pub safety_number: Option<String>,

    /// Whether the safety number has been verified by the user.
    /// The user confirms by comparing safety numbers out-of-band.
    pub safety_number_verified: bool,

    /// Verification passphrase (§8.3 cross-cutting requirement #4).
    /// A shared word/phrase agreed upon during in-person pairing.
    /// Used for future out-of-band key change verification.
    /// Stored encrypted in the contact record.
    pub verification_passphrase: Option<String>,

    /// The preauth key for this contact (X3DH preauth model).
    /// Refreshed periodically. Used to establish sessions without
    /// requiring the peer to be online.
    pub preauth_key: Option<[u8; 32]>,

    /// When the preauth key was last updated.
    pub preauth_key_updated: Option<u64>,

    /// Bob's Ed25519 signature over `PREAUTH_SIG_DOMAIN || preauth_x25519_pub_bytes`
    /// (§7.0.1 identity binding).
    ///
    /// Populated when the peer advertises a preauth key with a signature
    /// (i.e., at pairing or in a presence announcement).  Used by Alice in
    /// `x3dh_initiate()` to verify that the preauth key was signed by the
    /// peer's long-term Ed25519 identity key.
    ///
    /// `None` for legacy contacts that pre-date this field — verification
    /// is skipped for those (backward compat).
    #[serde(default)]
    pub preauth_key_sig: Option<Vec<u8>>,

    /// Whether this contact has been blocked.
    /// Blocked contacts can't send us messages or see our online status.
    pub blocked: bool,

    /// When this contact was last seen online (Unix timestamp).
    pub last_seen: Option<u64>,

    /// Clearnet TCP endpoint for direct connection ("ip:port" or "hostname:port").
    /// Extracted from the contact's PairingPayload transport hints at pairing time.
    /// None if the contact did not advertise a clearnet endpoint.
    pub clearnet_endpoint: Option<String>,

    /// Tor v3 `.onion` endpoint for Tor-transport connections ("addr.onion:port").
    /// Extracted from the contact's PairingPayload transport hints at pairing time.
    /// None if the contact did not advertise a Tor endpoint.
    #[serde(default)]
    pub tor_endpoint: Option<String>,

    /// ML-KEM-768 encapsulation key (1184 bytes, raw).
    /// Advertised in pairing payloads and presence announcements for PQXDH (§3.4.1).
    /// None if the peer does not support post-quantum key agreement.
    #[serde(default)]
    pub kem_encapsulation_key: Option<Vec<u8>>,

    /// Whether this peer advertises itself as an available exit node.
    #[serde(default)]
    pub can_be_exit_node: bool,

    /// Whether this peer advertises itself as a wrapper/relay node.
    #[serde(default)]
    pub can_be_wrapper_node: bool,

    /// Whether this peer advertises store-and-forward capability.
    #[serde(default)]
    pub can_be_store_forward: bool,

    /// Whether this peer can endorse other peers in the web of trust.
    #[serde(default)]
    pub can_endorse_peers: bool,

    /// Last measured round-trip latency to this peer in milliseconds.
    /// None if no ping has been performed.
    #[serde(default)]
    pub latency_ms: Option<u32>,
}

impl ContactRecord {
    /// Create a new contact record from a successful pairing.
    ///
    /// `peer_id`: the verified peer ID from the handshake.
    /// `ed25519_public`: the peer's Ed25519 public key.
    /// `x25519_public`: the peer's X25519 public key.
    /// `method`: which pairing method was used.
    /// `now`: current unix timestamp.
    pub fn new(
        peer_id: PeerId,
        ed25519_public: [u8; 32],
        x25519_public: [u8; 32],
        method: PairingMethod,
        now: u64,
    ) -> Self {
        Self {
            peer_id,
            ed25519_public,
            x25519_public,
            display_name: None,
            local_nickname: None,
            pairing_method: method,
            paired_at: now,
            trust_level: TrustLevel::Unknown, // Default: no trust.
            context_annotation: None,
            safety_number: None,
            safety_number_verified: false,
            verification_passphrase: None,
            preauth_key: None,
            preauth_key_updated: None,
            preauth_key_sig: None,
            blocked: false,
            last_seen: None,
            clearnet_endpoint: None,
            tor_endpoint: None,
            kem_encapsulation_key: None,
            can_be_exit_node: false,
            can_be_wrapper_node: false,
            can_be_store_forward: false,
            can_endorse_peers: false,
            latency_ms: None,
        }
    }

    /// Set the trust level for this contact.
    ///
    /// Trust escalation is always a deliberate user action.
    /// The contact record doesn't enforce trust rules — that's
    /// the trust module's job. This just records the current level.
    pub fn set_trust_level(&mut self, level: TrustLevel) {
        self.trust_level = level;
    }

    /// Set the context annotation.
    pub fn set_annotation(&mut self, annotation: String) {
        self.context_annotation = Some(annotation);
    }

    /// Set the safety number (computed after pairing).
    pub fn set_safety_number(&mut self, number: String) {
        self.safety_number = Some(number);
    }

    /// Mark the safety number as verified by the user.
    pub fn verify_safety_number(&mut self) {
        self.safety_number_verified = true;
    }

    /// Block this contact.
    pub fn block(&mut self) {
        self.blocked = true;
    }

    /// Unblock this contact.
    pub fn unblock(&mut self) {
        self.blocked = false;
    }

    /// Update the preauth key.
    pub fn update_preauth_key(&mut self, key: [u8; 32], now: u64) {
        self.preauth_key = Some(key);
        self.preauth_key_updated = Some(now);
        // Clear any stale sig — caller must call update_preauth_key_with_sig
        // if a new signature is available for this key.
        self.preauth_key_sig = None;
    }

    /// Update the preauth key together with its identity binding signature.
    ///
    /// Prefer this over `update_preauth_key` whenever the peer provides a
    /// `preauth_sig` (§7.0.1) so that `x3dh_initiate()` can verify the binding.
    pub fn update_preauth_key_with_sig(&mut self, key: [u8; 32], sig: Vec<u8>, now: u64) {
        self.preauth_key = Some(key);
        self.preauth_key_updated = Some(now);
        self.preauth_key_sig = Some(sig);
    }

    /// Record when this contact was last seen online.
    pub fn update_last_seen(&mut self, now: u64) {
        self.last_seen = Some(now);
    }

    /// Whether this contact is in the trusted tier (Level 6+).
    pub fn is_trusted(&self) -> bool {
        self.trust_level.is_trusted_tier()
    }
}

// ---------------------------------------------------------------------------
// Contact Store
// ---------------------------------------------------------------------------

/// A store of contact records.
///
/// In a full implementation, this would be backed by the vault
/// storage layer. For now, it's an in-memory HashMap.
pub struct ContactStore {
    /// Contacts indexed by peer ID.
    contacts: std::collections::HashMap<PeerId, ContactRecord>,
}

impl ContactStore {
    /// Create a new empty contact store.
    pub fn new() -> Self {
        Self {
            contacts: std::collections::HashMap::new(),
        }
    }

    /// Add or update a contact.
    pub fn upsert(&mut self, record: ContactRecord) {
        self.contacts.insert(record.peer_id, record);
    }

    /// Look up a contact by peer ID.
    pub fn get(&self, peer_id: &PeerId) -> Option<&ContactRecord> {
        self.contacts.get(peer_id)
    }

    /// Look up a contact mutably.
    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut ContactRecord> {
        self.contacts.get_mut(peer_id)
    }

    /// Remove a contact.
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<ContactRecord> {
        self.contacts.remove(peer_id)
    }

    /// Get all contacts.
    pub fn all(&self) -> Vec<&ContactRecord> {
        self.contacts.values().collect()
    }

    /// Get all contacts at or above a given trust level.
    pub fn at_trust_level(&self, min_level: TrustLevel) -> Vec<&ContactRecord> {
        self.contacts
            .values()
            .filter(|c| c.trust_level >= min_level)
            .collect()
    }

    /// Get all blocked contacts.
    pub fn blocked(&self) -> Vec<&ContactRecord> {
        self.contacts.values().filter(|c| c.blocked).collect()
    }

    /// Number of contacts.
    pub fn count(&self) -> usize {
        self.contacts.len()
    }

    /// Number of trusted-tier contacts (Level 6+).
    pub fn trusted_count(&self) -> usize {
        self.contacts
            .values()
            .filter(|c| c.is_trusted())
            .count()
    }

    /// Remove all contacts (used on identity reset / killswitch).
    pub fn clear(&mut self) {
        self.contacts.clear();
    }
}

impl Default for ContactStore {
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

    /// Helper: create a test contact.
    fn test_contact(id_byte: u8, method: PairingMethod) -> ContactRecord {
        let ed_pub = [id_byte; 32];
        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        ContactRecord::new(
            peer_id,
            ed_pub,
            [id_byte + 1; 32],
            method,
            1000,
        )
    }

    #[test]
    fn test_new_contact() {
        let contact = test_contact(0x01, PairingMethod::QrCode);

        assert_eq!(contact.trust_level, TrustLevel::Unknown);
        assert!(!contact.blocked);
        assert!(!contact.safety_number_verified);
        assert!(contact.context_annotation.is_none());
    }

    #[test]
    fn test_trust_escalation() {
        let mut contact = test_contact(0x01, PairingMethod::QrCode);

        contact.set_trust_level(TrustLevel::Acquaintance);
        assert!(!contact.is_trusted());

        contact.set_trust_level(TrustLevel::Trusted);
        assert!(contact.is_trusted());
    }

    #[test]
    fn test_block_unblock() {
        let mut contact = test_contact(0x01, PairingMethod::QrCode);

        contact.block();
        assert!(contact.blocked);

        contact.unblock();
        assert!(!contact.blocked);
    }

    #[test]
    fn test_safety_number_verification() {
        let mut contact = test_contact(0x01, PairingMethod::Nfc);

        contact.set_safety_number("123456789012345678901234567890123456789012345678901234567890".to_string());
        assert!(!contact.safety_number_verified);

        contact.verify_safety_number();
        assert!(contact.safety_number_verified);
    }

    #[test]
    fn test_contact_store() {
        let mut store = ContactStore::new();

        let c1 = test_contact(0x01, PairingMethod::QrCode);
        let c2 = test_contact(0x02, PairingMethod::Nfc);
        let peer_id_1 = c1.peer_id;
        let peer_id_2 = c2.peer_id;

        store.upsert(c1);
        store.upsert(c2);

        assert_eq!(store.count(), 2);
        assert!(store.get(&peer_id_1).is_some());
        assert!(store.get(&peer_id_2).is_some());
    }

    #[test]
    fn test_store_trust_filter() {
        let mut store = ContactStore::new();

        let mut c1 = test_contact(0x01, PairingMethod::QrCode);
        c1.set_trust_level(TrustLevel::Trusted);

        let c2 = test_contact(0x02, PairingMethod::Nfc);
        // c2 stays at Unknown.

        store.upsert(c1);
        store.upsert(c2);

        assert_eq!(store.trusted_count(), 1);
        assert_eq!(store.at_trust_level(TrustLevel::Trusted).len(), 1);
        assert_eq!(store.at_trust_level(TrustLevel::Unknown).len(), 2);
    }

    #[test]
    fn test_store_remove() {
        let mut store = ContactStore::new();

        let c = test_contact(0x01, PairingMethod::QrCode);
        let pid = c.peer_id;
        store.upsert(c);

        assert_eq!(store.count(), 1);
        store.remove(&pid);
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_preauth_key_update() {
        let mut contact = test_contact(0x01, PairingMethod::QrCode);

        assert!(contact.preauth_key.is_none());

        contact.update_preauth_key([0xAA; 32], 2000);
        assert_eq!(contact.preauth_key, Some([0xAA; 32]));
        assert_eq!(contact.preauth_key_updated, Some(2000));
    }

    #[test]
    fn test_serde_roundtrip() {
        let contact = test_contact(0x01, PairingMethod::QrCode);
        let json = serde_json::to_string(&contact).unwrap();
        let recovered: ContactRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(recovered.peer_id, contact.peer_id);
        assert_eq!(recovered.pairing_method, PairingMethod::QrCode);
    }
}
