//! Group Core (§8.7.1, §8.7.2)
//!
//! # Group Identity
//!
//! Every group has a first-class network identity:
//! - A 32-byte group ID (randomly generated)
//! - An Ed25519 keypair for signing (group-level)
//! - An X25519 keypair for key agreement
//! - A public profile (name, description, avatar, type)
//!
//! # Network Types (§8.7.1)
//!
//! Groups come in four visibility levels:
//!
//! - **Private:** No profile visible to non-members. Invitation only.
//!   Member count hidden. Uses ring signatures (§3.5.2) for
//!   membership deniability.
//!
//! - **Closed:** Name and type visible. Member count hidden.
//!   Invitation only. Uses ring signatures.
//!
//! - **Open:** Full profile visible. Anyone can join (with approval).
//!   No ring signatures needed.
//!
//! - **Public:** Full profile visible. Anyone can join without approval.
//!   No ring signatures needed.
//!
//! # Key Material
//!
//! - Group public key: shared with all members
//! - Group private key: held by admin members only
//! - Per-member Sender Keys: distributed to all members via
//!   encrypted direct messages
//! - Group symmetric key: derived from the group keypair for
//!   group-level encryption (Step 4 of group message encryption)

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Serde helper: serialize [u8; 64] as hex string
// ---------------------------------------------------------------------------

/// Custom serde module for `Option<[u8; 64]>` fields.
///
/// `[u8; 64]` is not supported by serde's blanket array impl in older
/// Rust toolchains. We encode as a hex string instead, which is also
/// more human-readable in vault debug output.
mod serde_hex64 {
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let bytes = hex::decode(&s).map_err(DeError::custom)?;
                if bytes.len() != 64 {
                    return Err(DeError::custom("expected 64-byte hex string"));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serde helper: serialize Option<[u8; 32]> as optional hex string
// ---------------------------------------------------------------------------

mod serde_opt_key32 {
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let bytes = hex::decode(&s).map_err(DeError::custom)?;
                if bytes.len() != 32 {
                    return Err(DeError::custom("expected 32-byte hex string"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Peer Sender Key State (persisted per member per group)
// ---------------------------------------------------------------------------

/// Persisted receiver-side state for a remote member's Sender Key.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PeerSenderKeyState {
    /// Our copy of the sender's chain key, advanced to next_iteration.
    pub chain_key: [u8; 32],
    /// The next iteration we expect from this sender.
    pub next_iteration: u32,
    /// The sender's Ed25519 verifying key bytes (for signature verification).
    pub verifying_key: [u8; 32],
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum group name length (bytes).
pub const MAX_GROUP_NAME_LEN: usize = 64;

/// Maximum group description length (bytes).
pub const MAX_GROUP_DESCRIPTION_LEN: usize = 256;

/// Default rekeying interval (seconds) = 7 days.
///
/// Bounds the forward secrecy window for Sender Keys.
/// Unlike Double Ratchet, Sender Keys provide no forward secrecy
/// within a sending chain, so periodic rekeying is essential.
pub const DEFAULT_REKEY_INTERVAL_SECS: u64 = 7 * 24 * 3600;

/// Maximum members per group.
///
/// Ring signature performance degrades with group size.
/// 1000 members is the practical ceiling for the AOS ring
/// signature scheme.
pub const MAX_GROUP_MEMBERS: usize = 1000;

// ---------------------------------------------------------------------------
// Network Type
// ---------------------------------------------------------------------------

/// Group visibility and join policy (§8.7.1).
///
/// Controls who can see the group's profile, who can join,
/// and whether ring signatures are used for membership privacy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    /// No profile visible to non-members. Invitation only.
    /// Ring signatures used for membership deniability.
    Private,

    /// Name and type visible. Member count hidden. Invitation only.
    /// Ring signatures used.
    Closed,

    /// Full profile visible. Join with approval.
    /// No ring signatures (membership not secret).
    Open,

    /// Full profile visible. Join without approval.
    /// No ring signatures.
    Public,
}

impl NetworkType {
    /// Whether this group type uses ring signatures for
    /// membership privacy (§8.7.7 Step 5).
    ///
    /// Private and Closed groups SHOULD use AOS Linkable Ring Signatures
    /// (§3.5.2) so routing nodes cannot determine group membership.
    /// Open and Public groups don't need this because membership is not secret.
    ///
    /// **Implementation status: NOT YET IMPLEMENTED.**  The LSAG ring signature
    /// scheme required by §3.5.2 has not been built yet.  This function returns
    /// `false` to accurately reflect the current security level rather than
    /// advertising a property we do not yet provide.  When LSAG is implemented,
    /// this will return `true` for Private/Closed and the callers should gate
    /// the ring-sign path on the result.
    pub fn uses_ring_signatures(&self) -> bool {
        // TODO(§3.5.2): implement LSAG ring signatures and change to:
        //   matches!(self, Self::Private | Self::Closed)
        false
    }

    /// Whether member count is visible to non-members.
    pub fn shows_member_count(&self) -> bool {
        matches!(self, Self::Open | Self::Public)
    }

    /// Whether this group requires invitation to join.
    pub fn requires_invitation(&self) -> bool {
        matches!(self, Self::Private | Self::Closed)
    }

    /// Whether joining requires admin approval.
    pub fn requires_approval(&self) -> bool {
        matches!(self, Self::Private | Self::Closed | Self::Open)
    }
}

// ---------------------------------------------------------------------------
// Group Public Profile
// ---------------------------------------------------------------------------

/// A group's public profile (§8.7.1).
///
/// What non-members can see depends on the NetworkType:
/// - Private: nothing visible
/// - Closed: name and type only
/// - Open/Public: everything visible
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GroupPublicProfile {
    /// The group's unique identifier.
    pub group_id: [u8; 32],

    /// Display name (max 64 bytes).
    pub display_name: String,

    /// Description (max 256 bytes).
    pub description: String,

    /// SHA-256 hash of the group avatar (if set).
    pub avatar_hash: Option<[u8; 32]>,

    /// Group visibility and join policy.
    pub network_type: NetworkType,

    /// Number of members (None for Private/Closed groups).
    pub member_count: Option<u32>,

    /// When the group was created (Unix timestamp).
    pub created_at: u64,

    /// Ed25519 public key of the signer (group admin).
    pub signed_by: [u8; 32],

    /// Signature over the profile fields.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Group
// ---------------------------------------------------------------------------

/// A group (§8.7).
///
/// The core group structure holding identity, keys, membership,
/// and configuration. This is the local node's view of a group
/// it belongs to.
///
/// The `ed25519_private` key is serialized as a sequence of bytes.
/// The field is `Option<Vec<u8>>` in the serialized form for
/// forward compatibility (Serde handles `[u8; 64]` correctly in
/// Rust/serde 1.0 with const-generic array support).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    /// The group's unique identifier.
    pub group_id: [u8; 32],

    /// The group's public profile.
    pub profile: GroupPublicProfile,

    /// The group's Ed25519 public key (for verification).
    pub ed25519_public: [u8; 32],

    /// The group's X25519 public key (for key agreement).
    pub x25519_public: [u8; 32],

    /// The group's symmetric key (derived, for Step 4 encryption).
    /// All members hold this key.
    pub symmetric_key: [u8; 32],

    /// Whether we are an admin of this group.
    /// Admins hold the group's private key and can manage members.
    pub is_admin: bool,

    /// The group's Ed25519 private key (admins only).
    /// None if we're not an admin.
    /// Serialized as hex string (64 bytes → 128 hex chars).
    #[serde(with = "serde_hex64")]
    pub ed25519_private: Option<[u8; 64]>,

    /// List of member peer IDs.
    pub members: Vec<PeerId>,

    /// List of admin peer IDs.
    pub admins: Vec<PeerId>,

    /// Our own peer ID (for identification within the group).
    pub our_peer_id: PeerId,

    /// When we joined this group (Unix timestamp).
    pub joined_at: u64,

    /// Rekeying interval (seconds).
    /// Default: 7 days. Configurable per group by admins.
    pub rekey_interval_secs: u64,

    /// When the last rekey occurred (Unix timestamp).
    pub last_rekey_at: u64,

    /// Current Sender Key epoch (incremented on each rekey).
    pub sender_key_epoch: u64,

    /// Message sequence number (for ordering within the group).
    pub sequence: u64,

    /// Group-as-LAN configuration (§8.7.9).
    pub lan_config: GroupLanConfig,

    // ---- Sender Key state (§7.0.4) ----------------------------------------

    /// Our own Sender Key chain key for this group.
    /// Generated on group creation or rekey; advanced with each sent message.
    /// Serialized as hex so the vault can store and restore it.
    #[serde(default, with = "serde_opt_key32")]
    pub my_sender_chain_key: Option<[u8; 32]>,

    /// How many messages we've sent with the current sender_key_epoch.
    #[serde(default)]
    pub my_sender_iteration: u32,

    /// Our Sender Key Ed25519 signing key (64 bytes = secret + public).
    /// Used to authenticate group messages we send.
    #[serde(default, with = "serde_hex64")]
    pub my_sender_signing_key: Option<[u8; 64]>,

    /// Received Sender Keys from other group members.
    /// Key: peer_id bytes; Value: (chain_key, next_iteration, verifying_key_bytes).
    /// Persisted so we can decrypt out-of-order / restored messages.
    #[serde(default)]
    pub peer_sender_keys: std::collections::HashMap<[u8; 32], PeerSenderKeyState>,
}

/// Key material bundle passed to `Group::new_as_creator` and `Group::new_as_member`.
///
/// Wraps the three per-group cryptographic keys so that both constructors
/// stay within the 7-argument limit.
pub struct GroupKeys {
    /// Group Ed25519 public key (used for signing group messages).
    pub ed25519_public: [u8; 32],
    /// Group Ed25519 private key (only the admin has this on creation).
    pub ed25519_private: Option<[u8; 64]>,
    /// Group X25519 public key (used for key-agreement in member invites).
    pub x25519_public: [u8; 32],
    /// Group symmetric key (used for bulk encryption of group messages).
    pub symmetric_key: [u8; 32],
}

impl Group {
    /// Create a new group (we are the creator and initial admin).
    ///
    /// `group_id`: randomly generated 32-byte ID.
    /// `profile`: the public profile for this group.
    /// `keys`: all four group-level cryptographic keys.
    /// `our_peer_id`: our own peer ID.
    /// `now`: current unix timestamp.
    pub fn new_as_creator(
        group_id: [u8; 32],
        profile: GroupPublicProfile,
        keys: GroupKeys,
        our_peer_id: PeerId,
        now: u64,
    ) -> Self {
        let GroupKeys { ed25519_public, ed25519_private, x25519_public, symmetric_key } = keys;
        Self {
            group_id,
            profile,
            ed25519_public,
            x25519_public,
            symmetric_key,
            is_admin: true,
            ed25519_private,
            members: vec![our_peer_id],
            admins: vec![our_peer_id],
            our_peer_id,
            joined_at: now,
            rekey_interval_secs: DEFAULT_REKEY_INTERVAL_SECS,
            last_rekey_at: now,
            sender_key_epoch: 1,
            sequence: 0,
            lan_config: GroupLanConfig::default(),
            my_sender_chain_key: None,
            my_sender_iteration: 0,
            my_sender_signing_key: None,
            peer_sender_keys: std::collections::HashMap::new(),
        }
    }

    /// Create a group as a regular member (invited by an admin).
    pub fn new_as_member(
        group_id: [u8; 32],
        profile: GroupPublicProfile,
        keys: GroupKeys,
        our_peer_id: PeerId,
        membership: (Vec<PeerId>, Vec<PeerId>),
        sender_key_epoch: u64,
        now: u64,
    ) -> Self {
        let GroupKeys { ed25519_public, x25519_public, symmetric_key, .. } = keys;
        let (members, admins) = membership;
        Self {
            group_id,
            profile,
            ed25519_public,
            x25519_public,
            symmetric_key,
            is_admin: false,
            ed25519_private: None,
            members,
            admins,
            our_peer_id,
            joined_at: now,
            rekey_interval_secs: DEFAULT_REKEY_INTERVAL_SECS,
            last_rekey_at: now,
            sender_key_epoch,
            sequence: 0,
            lan_config: GroupLanConfig::default(),
            my_sender_chain_key: None,
            my_sender_iteration: 0,
            my_sender_signing_key: None,
            peer_sender_keys: std::collections::HashMap::new(),
        }
    }

    /// Whether a rekeying is due.
    ///
    /// Rekeying is needed when the interval has elapsed since the
    /// last rekey. Only admins should initiate rekeying.
    pub fn needs_rekey(&self, now: u64) -> bool {
        now.saturating_sub(self.last_rekey_at) >= self.rekey_interval_secs
    }

    /// Get the next message sequence number and increment.
    pub fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence;
        self.sequence += 1;
        seq
    }

    /// Number of members.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Number of admins.
    pub fn admin_count(&self) -> usize {
        self.admins.len()
    }

    /// Whether a peer is a member.
    pub fn is_member(&self, peer_id: &PeerId) -> bool {
        self.members.contains(peer_id)
    }

    /// Whether a peer is an admin.
    pub fn is_admin_peer(&self, peer_id: &PeerId) -> bool {
        self.admins.contains(peer_id)
    }

    /// Whether the group is at member capacity.
    pub fn is_full(&self) -> bool {
        self.members.len() >= MAX_GROUP_MEMBERS
    }
}

// ---------------------------------------------------------------------------
// Group-as-LAN Configuration (§8.7.9)
// ---------------------------------------------------------------------------

/// Configuration for Group-as-LAN private network namespace (§8.7.9).
///
/// When enabled, the group becomes a private mesh namespace with
/// its own routing scope, name resolution, and proximity discovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Default)]
pub struct GroupLanConfig {
    /// Whether network sharing is enabled for this group.
    /// Enables subnet route advertisement and group-scoped map entries.
    pub network_sharing_enabled: bool,

    /// Whether proximity sharing is enabled.
    /// Enables BLE token chain distribution to members for
    /// stealthy BLE rendezvous (push-to-talk over BLE).
    pub proximity_share_enabled: bool,
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test group.
    fn test_group(now: u64) -> Group {
        let our_peer_id = PeerId([0x01; 32]);

        let profile = GroupPublicProfile {
            group_id: [0xAA; 32],
            display_name: "Test Group".to_string(),
            description: "A test group".to_string(),
            avatar_hash: None,
            network_type: NetworkType::Private,
            member_count: None,
            created_at: now,
            signed_by: [0xBB; 32],
            signature: vec![0xCC; 64],
        };

        Group::new_as_creator(
            [0xAA; 32],
            profile,
            GroupKeys {
                ed25519_public: [0xBB; 32],
                ed25519_private: Some([0xDD; 64]),
                x25519_public: [0xEE; 32],
                symmetric_key: [0xFF; 32],
            },
            our_peer_id,
            now,
        )
    }

    #[test]
    fn test_new_group() {
        let group = test_group(1000);

        assert!(group.is_admin);
        assert_eq!(group.member_count(), 1);
        assert_eq!(group.admin_count(), 1);
        assert!(group.is_member(&PeerId([0x01; 32])));
        assert!(group.is_admin_peer(&PeerId([0x01; 32])));
    }

    #[test]
    fn test_rekey_schedule() {
        let now = 1000;
        let group = test_group(now);

        // Not due yet.
        assert!(!group.needs_rekey(now + 1000));

        // Due after the interval.
        assert!(group.needs_rekey(now + DEFAULT_REKEY_INTERVAL_SECS));
    }

    #[test]
    fn test_sequence_numbers() {
        let mut group = test_group(1000);

        assert_eq!(group.next_sequence(), 0);
        assert_eq!(group.next_sequence(), 1);
        assert_eq!(group.next_sequence(), 2);
    }

    #[test]
    fn test_network_type_properties() {
        // Ring signatures are not yet implemented (§3.5.2 TODO).
        // All network types return false until LSAG is built.
        assert!(!NetworkType::Private.uses_ring_signatures());
        assert!(!NetworkType::Closed.uses_ring_signatures());
        assert!(!NetworkType::Open.uses_ring_signatures());
        assert!(!NetworkType::Public.uses_ring_signatures());

        assert!(!NetworkType::Private.shows_member_count());
        assert!(!NetworkType::Closed.shows_member_count());
        assert!(NetworkType::Open.shows_member_count());
        assert!(NetworkType::Public.shows_member_count());

        assert!(NetworkType::Private.requires_invitation());
        assert!(NetworkType::Closed.requires_invitation());
        assert!(!NetworkType::Open.requires_invitation());
        assert!(!NetworkType::Public.requires_invitation());
    }

    #[test]
    fn test_member_as_non_admin() {
        let now = 1000;
        let profile = GroupPublicProfile {
            group_id: [0xAA; 32],
            display_name: "Test".to_string(),
            description: "".to_string(),
            avatar_hash: None,
            network_type: NetworkType::Open,
            member_count: Some(5),
            created_at: now,
            signed_by: [0xBB; 32],
            signature: vec![0xCC; 64],
        };

        let group = Group::new_as_member(
            [0xAA; 32],
            profile,
            GroupKeys {
                ed25519_public: [0xBB; 32],
                ed25519_private: None,
                x25519_public: [0xEE; 32],
                symmetric_key: [0xFF; 32],
            },
            PeerId([0x02; 32]),
            (vec![PeerId([0x01; 32]), PeerId([0x02; 32])], vec![PeerId([0x01; 32])]),
            3,
            now,
        );

        assert!(!group.is_admin);
        assert!(group.ed25519_private.is_none());
        assert_eq!(group.member_count(), 2);
        assert_eq!(group.sender_key_epoch, 3);
    }

    #[test]
    fn test_group_lan_config_defaults() {
        let config = GroupLanConfig::default();
        assert!(!config.network_sharing_enabled);
        assert!(!config.proximity_share_enabled);
    }
}
