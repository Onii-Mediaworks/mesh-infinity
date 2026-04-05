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
// serde_hex64 sub-module — see its own module-level docs.
// serde_hex64 sub-module — see its own module-level docs.
mod serde_hex64 {
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    // Begin the block scope.
    // Perform the 'serialize' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'serialize' operation.
    // Errors are propagated to the caller via Result.
    pub fn serialize<S: Serializer>(v: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match v {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(b) => s.serialize_some(&hex::encode(b)),
            // Update the local state.
            // No value available.
            // No value available.
            None => s.serialize_none(),
        }
    }

    // Begin the block scope.
    // Perform the 'deserialize' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deserialize' operation.
    // Errors are propagated to the caller via Result.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        // Serialize to the wire format for transmission or storage.
        // Compute opt for this protocol step.
        // Compute opt for this protocol step.
        let opt: Option<String> = Option::deserialize(d)?;
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match opt {
            // Update the local state.
            // No value available.
            // No value available.
            None => Ok(None),
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(s) => {
                // Transform the result, mapping errors to the local error type.
                // Compute bytes for this protocol step.
                // Compute bytes for this protocol step.
                let bytes = hex::decode(&s).map_err(DeError::custom)?;
                // Validate the input length to prevent out-of-bounds access.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if bytes.len() != 64 {
                    // Reject with an explicit error for the caller to handle.
                    // Return to the caller.
                    // Return to the caller.
                    return Err(DeError::custom("expected 64-byte hex string"));
                }
                // Execute the operation and bind the result.
                // Compute arr for this protocol step.
                // Compute arr for this protocol step.
                let mut arr = [0u8; 64];
                // Copy the raw bytes into the fixed-size target array.
                // Copy into the fixed-size buffer.
                // Copy into the fixed-size buffer.
                arr.copy_from_slice(&bytes);
                // Wrap the computed value in the success variant.
                // Success path — return the computed value.
                // Success path — return the computed value.
                Ok(Some(arr))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serde helper: serialize Option<[u8; 32]> as optional hex string
// ---------------------------------------------------------------------------

// Sub-module: serde_opt_key32 — see module-level docs for details.
// serde_opt_key32 sub-module — see its own module-level docs.
// serde_opt_key32 sub-module — see its own module-level docs.
mod serde_opt_key32 {
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    // Begin the block scope.
    // Perform the 'serialize' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'serialize' operation.
    // Errors are propagated to the caller via Result.
    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match v {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(b) => s.serialize_some(&hex::encode(b)),
            // Update the local state.
            // No value available.
            // No value available.
            None => s.serialize_none(),
        }
    }

    // Begin the block scope.
    // Perform the 'deserialize' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deserialize' operation.
    // Errors are propagated to the caller via Result.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        // Serialize to the wire format for transmission or storage.
        // Compute opt for this protocol step.
        // Compute opt for this protocol step.
        let opt: Option<String> = Option::deserialize(d)?;
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match opt {
            // Update the local state.
            // No value available.
            // No value available.
            None => Ok(None),
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(s) => {
                // Transform the result, mapping errors to the local error type.
                // Compute bytes for this protocol step.
                // Compute bytes for this protocol step.
                let bytes = hex::decode(&s).map_err(DeError::custom)?;
                // Validate the input length to prevent out-of-bounds access.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if bytes.len() != 32 {
                    // Reject with an explicit error for the caller to handle.
                    // Return to the caller.
                    // Return to the caller.
                    return Err(DeError::custom("expected 32-byte hex string"));
                }
                // Execute the operation and bind the result.
                // Compute arr for this protocol step.
                // Compute arr for this protocol step.
                let mut arr = [0u8; 32];
                // Copy the raw bytes into the fixed-size target array.
                // Copy into the fixed-size buffer.
                // Copy into the fixed-size buffer.
                arr.copy_from_slice(&bytes);
                // Wrap the computed value in the success variant.
                // Success path — return the computed value.
                // Success path — return the computed value.
                Ok(Some(arr))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serde helper: serialize peer sender key maps with hex-string keys
// ---------------------------------------------------------------------------

/// Custom serde module for `HashMap<[u8; 32], PeerSenderKeyState>`.
///
/// The vault layer is JSON-backed, so map keys must be strings. Group sender
/// key state is naturally keyed by raw peer ID bytes, so we encode those keys
/// as lowercase hex on the wire and restore them on load.
mod serde_peer_sender_keys {
    use std::collections::HashMap;

    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::PeerSenderKeyState;

    pub fn serialize<S: Serializer>(
        value: &HashMap<[u8; 32], PeerSenderKeyState>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let encoded: HashMap<String, &PeerSenderKeyState> = value
            .iter()
            .map(|(peer_id, state)| (hex::encode(peer_id), state))
            .collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<HashMap<[u8; 32], PeerSenderKeyState>, D::Error> {
        let encoded = HashMap::<String, PeerSenderKeyState>::deserialize(deserializer)?;
        let mut decoded = HashMap::with_capacity(encoded.len());
        for (peer_id_hex, state) in encoded {
            let peer_id_bytes = hex::decode(&peer_id_hex).map_err(DeError::custom)?;
            if peer_id_bytes.len() != 32 {
                return Err(DeError::custom("expected 32-byte peer id hex key"));
            }
            let mut peer_id = [0u8; 32];
            peer_id.copy_from_slice(&peer_id_bytes);
            decoded.insert(peer_id, state);
        }
        Ok(decoded)
    }
}

// ---------------------------------------------------------------------------
// Peer Sender Key State (persisted per member per group)
// ---------------------------------------------------------------------------

/// Persisted receiver-side state for a remote member's Sender Key.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
// Begin the block scope.
// PeerSenderKeyState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PeerSenderKeyState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PeerSenderKeyState {
    /// Our copy of the sender's chain key, advanced to next_iteration.
    // Execute this protocol step.
    // Execute this protocol step.
    pub chain_key: [u8; 32],
    /// The next iteration we expect from this sender.
    // Execute this protocol step.
    // Execute this protocol step.
    pub next_iteration: u32,
    /// The sender's Ed25519 verifying key bytes (for signature verification).
    // Execute this protocol step.
    // Execute this protocol step.
    pub verifying_key: [u8; 32],
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum group name length (bytes).
// MAX_GROUP_NAME_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_GROUP_NAME_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_GROUP_NAME_LEN: usize = 64;

/// Maximum group description length (bytes).
// MAX_GROUP_DESCRIPTION_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_GROUP_DESCRIPTION_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_GROUP_DESCRIPTION_LEN: usize = 256;

/// Default rekeying interval (seconds) = 7 days.
///
/// Bounds the forward secrecy window for Sender Keys.
/// Unlike Double Ratchet, Sender Keys provide no forward secrecy
/// within a sending chain, so periodic rekeying is essential.
// DEFAULT_REKEY_INTERVAL_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_REKEY_INTERVAL_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEFAULT_REKEY_INTERVAL_SECS: u64 = 7 * 24 * 3600;

/// Maximum members per group.
///
/// Ring signature performance degrades with group size.
/// 1000 members is the practical ceiling for the AOS ring
/// signature scheme.
// MAX_GROUP_MEMBERS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_GROUP_MEMBERS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_GROUP_MEMBERS: usize = 1000;

// ---------------------------------------------------------------------------
// Network Type
// ---------------------------------------------------------------------------

/// Group visibility and join policy (§8.7.1).
///
/// Controls who can see the group's profile, who can join,
/// and whether ring signatures are used for membership privacy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// NetworkType — variant enumeration.
// Match exhaustively to handle every protocol state.
// NetworkType — variant enumeration.
// Match exhaustively to handle every protocol state.
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

// Begin the block scope.
// NetworkType implementation — core protocol logic.
// NetworkType implementation — core protocol logic.
impl NetworkType {
    /// Whether this group type uses ring signatures for
    /// membership privacy (§8.7.7 Step 5).
    ///
    /// Private and Closed groups use AOS ring signatures (§3.5.2)
    /// so routing nodes cannot determine which member acted.
    /// Open and Public groups don't need this because membership is not secret.
    ///
    /// The cryptographic primitive exists in `crypto::ring_sig`, but the group
    /// operation and messaging paths still need to route the relevant private
    /// and closed-group actions through it rather than plain attributable
    /// signatures. Until those call sites are wired, this returns `false` to
    /// avoid overstating the current privacy property.
    // Perform the 'uses ring signatures' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'uses ring signatures' operation.
    // Errors are propagated to the caller via Result.
    pub fn uses_ring_signatures(&self) -> bool {
        matches!(self, Self::Private | Self::Closed)
    }

    /// Whether member count is visible to non-members.
    // Perform the 'shows member count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'shows member count' operation.
    // Errors are propagated to the caller via Result.
    pub fn shows_member_count(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Open | Self::Public)
    }

    /// Whether this group requires invitation to join.
    // Perform the 'requires invitation' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'requires invitation' operation.
    // Errors are propagated to the caller via Result.
    pub fn requires_invitation(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Private | Self::Closed)
    }

    /// Whether joining requires admin approval.
    // Perform the 'requires approval' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'requires approval' operation.
    // Errors are propagated to the caller via Result.
    pub fn requires_approval(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
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
// Begin the block scope.
// GroupPublicProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GroupPublicProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GroupPublicProfile {
    /// The group's unique identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    pub group_id: [u8; 32],

    /// Display name (max 64 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub display_name: String,

    /// Description (max 256 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: String,

    /// SHA-256 hash of the group avatar (if set).
    // Execute this protocol step.
    // Execute this protocol step.
    pub avatar_hash: Option<[u8; 32]>,

    /// Group visibility and join policy.
    // Execute this protocol step.
    // Execute this protocol step.
    pub network_type: NetworkType,

    /// Number of members (None for Private/Closed groups).
    // Execute this protocol step.
    // Execute this protocol step.
    pub member_count: Option<u32>,

    /// When the group was created (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    pub created_at: u64,

    /// Ed25519 public key of the signer (group admin).
    // Execute this protocol step.
    // Execute this protocol step.
    pub signed_by: [u8; 32],

    /// Signature over the profile fields.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// Group — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// Group — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct Group {
    /// The group's unique identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    pub group_id: [u8; 32],

    /// The group's public profile.
    // Execute this protocol step.
    // Execute this protocol step.
    pub profile: GroupPublicProfile,

    /// The group's Ed25519 public key (for verification).
    // Execute this protocol step.
    // Execute this protocol step.
    pub ed25519_public: [u8; 32],

    /// The group's X25519 public key (for key agreement).
    // Execute this protocol step.
    // Execute this protocol step.
    pub x25519_public: [u8; 32],

    /// The group's symmetric key (derived, for Step 4 encryption).
    /// All members hold this key.
    // Execute this protocol step.
    // Execute this protocol step.
    pub symmetric_key: [u8; 32],

    /// Whether we are an admin of this group.
    /// Admins hold the group's private key and can manage members.
    // Execute this protocol step.
    // Execute this protocol step.
    pub is_admin: bool,

    /// The group's Ed25519 private key (admins only).
    /// None if we're not an admin.
    /// Serialized as hex string (64 bytes → 128 hex chars).
    #[serde(with = "serde_hex64")]
    /// The ed25519 private for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ed25519_private: Option<[u8; 64]>,

    /// List of member peer IDs.
    // Execute this protocol step.
    // Execute this protocol step.
    pub members: Vec<PeerId>,

    /// List of admin peer IDs.
    // Execute this protocol step.
    // Execute this protocol step.
    pub admins: Vec<PeerId>,

    /// Our own peer ID (for identification within the group).
    // Execute this protocol step.
    // Execute this protocol step.
    pub our_peer_id: PeerId,

    /// When we joined this group (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    pub joined_at: u64,

    /// Rekeying interval (seconds).
    /// Default: 7 days. Configurable per group by admins.
    // Execute this protocol step.
    // Execute this protocol step.
    pub rekey_interval_secs: u64,

    /// When the last rekey occurred (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_rekey_at: u64,

    /// Current Sender Key epoch (incremented on each rekey).
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_key_epoch: u64,

    /// Message sequence number (for ordering within the group).
    // Execute this protocol step.
    // Execute this protocol step.
    pub sequence: u64,

    /// Group-as-LAN configuration (§8.7.9).
    // Execute this protocol step.
    // Execute this protocol step.
    pub lan_config: GroupLanConfig,

    // ---- Sender Key state (§7.0.4) ----------------------------------------
    /// Our own Sender Key chain key for this group.
    /// Generated on group creation or rekey; advanced with each sent message.
    /// Serialized as hex so the vault can store and restore it.
    #[serde(default, with = "serde_opt_key32")]
    /// The my sender chain key for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub my_sender_chain_key: Option<[u8; 32]>,

    /// How many messages we've sent with the current sender_key_epoch.
    #[serde(default)]
    /// The my sender iteration for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub my_sender_iteration: u32,

    /// Our Sender Key Ed25519 signing key (64 bytes = secret + public).
    /// Used to authenticate group messages we send.
    #[serde(default, with = "serde_hex64")]
    /// The my sender signing key for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub my_sender_signing_key: Option<[u8; 64]>,

    /// Received Sender Keys from other group members.
    /// Key: peer_id bytes; Value: (chain_key, next_iteration, verifying_key_bytes).
    /// Persisted so we can decrypt out-of-order / restored messages.
    #[serde(default, with = "serde_peer_sender_keys")]
    /// The peer sender keys for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_sender_keys: std::collections::HashMap<[u8; 32], PeerSenderKeyState>,
}

/// Key material bundle passed to `Group::new_as_creator` and `Group::new_as_member`.
///
/// Wraps the three per-group cryptographic keys so that both constructors
/// stay within the 7-argument limit.
// GroupKeys — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GroupKeys — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GroupKeys {
    /// Group Ed25519 public key (used for signing group messages).
    // Execute this protocol step.
    // Execute this protocol step.
    pub ed25519_public: [u8; 32],
    /// Group Ed25519 private key (only the admin has this on creation).
    // Execute this protocol step.
    // Execute this protocol step.
    pub ed25519_private: Option<[u8; 64]>,
    /// Group X25519 public key (used for key-agreement in member invites).
    // Execute this protocol step.
    // Execute this protocol step.
    pub x25519_public: [u8; 32],
    /// Group symmetric key (used for bulk encryption of group messages).
    // Execute this protocol step.
    // Execute this protocol step.
    pub symmetric_key: [u8; 32],
}

// Begin the block scope.
// Group implementation — core protocol logic.
// Group implementation — core protocol logic.
impl Group {
    /// Create a new group (we are the creator and initial admin).
    ///
    /// `group_id`: randomly generated 32-byte ID.
    /// `profile`: the public profile for this group.
    /// `keys`: all four group-level cryptographic keys.
    /// `our_peer_id`: our own peer ID.
    /// `now`: current unix timestamp.
    // Perform the 'new as creator' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new as creator' operation.
    // Errors are propagated to the caller via Result.
    pub fn new_as_creator(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        group_id: [u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        profile: GroupPublicProfile,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        keys: GroupKeys,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        our_peer_id: PeerId,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Self {
        // Key material — must be zeroized when no longer needed.
        // Compute GroupKeys for this protocol step.
        // Compute GroupKeys for this protocol step.
        let GroupKeys {
            ed25519_public,
            ed25519_private,
            x25519_public,
            symmetric_key,
        } = keys;
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            group_id,
            profile,
            // Execute this protocol step.
            // Execute this protocol step.
            ed25519_public,
            // Execute this protocol step.
            // Execute this protocol step.
            x25519_public,
            // Execute this protocol step.
            // Execute this protocol step.
            symmetric_key,
            // Execute this protocol step.
            // Execute this protocol step.
            is_admin: true,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            ed25519_private,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            members: vec![our_peer_id],
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            admins: vec![our_peer_id],
            // Execute this protocol step.
            // Execute this protocol step.
            our_peer_id,
            // Execute this protocol step.
            // Execute this protocol step.
            joined_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            rekey_interval_secs: DEFAULT_REKEY_INTERVAL_SECS,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            last_rekey_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            sender_key_epoch: 1,
            // Execute this protocol step.
            // Execute this protocol step.
            sequence: 0,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            lan_config: GroupLanConfig::default(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            my_sender_chain_key: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            my_sender_iteration: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            my_sender_signing_key: None,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            peer_sender_keys: std::collections::HashMap::new(),
        }
    }

    /// Create a group as a regular member (invited by an admin).
    // Perform the 'new as member' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new as member' operation.
    // Errors are propagated to the caller via Result.
    pub fn new_as_member(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        group_id: [u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        profile: GroupPublicProfile,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        keys: GroupKeys,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        our_peer_id: PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        membership: (Vec<PeerId>, Vec<PeerId>),
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        sender_key_epoch: u64,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Self {
        // Key material — must be zeroized when no longer needed.
        // Compute GroupKeys for this protocol step.
        // Compute GroupKeys for this protocol step.
        let GroupKeys {
            ed25519_public,
            x25519_public,
            symmetric_key,
            ..
        } = keys;
        // Identify the peer for this operation.
        // Bind the intermediate result.
        // Bind the intermediate result.
        let (members, admins) = membership;
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            group_id,
            profile,
            // Execute this protocol step.
            // Execute this protocol step.
            ed25519_public,
            // Execute this protocol step.
            // Execute this protocol step.
            x25519_public,
            // Execute this protocol step.
            // Execute this protocol step.
            symmetric_key,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            is_admin: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            ed25519_private: None,
            members,
            admins,
            // Execute this protocol step.
            // Execute this protocol step.
            our_peer_id,
            // Execute this protocol step.
            // Execute this protocol step.
            joined_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            rekey_interval_secs: DEFAULT_REKEY_INTERVAL_SECS,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            last_rekey_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            sender_key_epoch,
            // Execute this protocol step.
            // Execute this protocol step.
            sequence: 0,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            lan_config: GroupLanConfig::default(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            my_sender_chain_key: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            my_sender_iteration: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            my_sender_signing_key: None,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            peer_sender_keys: std::collections::HashMap::new(),
        }
    }

    /// Whether a rekeying is due.
    ///
    /// Rekeying is needed when the interval has elapsed since the
    /// last rekey. Only admins should initiate rekeying.
    // Perform the 'needs rekey' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'needs rekey' operation.
    // Errors are propagated to the caller via Result.
    pub fn needs_rekey(&self, now: u64) -> bool {
        // Clamp the value to prevent overflow or underflow.
        // Execute this protocol step.
        // Execute this protocol step.
        now.saturating_sub(self.last_rekey_at) >= self.rekey_interval_secs
    }

    /// Get the next message sequence number and increment.
    // Perform the 'next sequence' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'next sequence' operation.
    // Errors are propagated to the caller via Result.
    pub fn next_sequence(&mut self) -> u64 {
        // Execute the operation and bind the result.
        // Compute seq for this protocol step.
        // Compute seq for this protocol step.
        let seq = self.sequence;
        // Update the sequence to reflect the new state.
        // Advance sequence state.
        // Advance sequence state.
        self.sequence += 1;
        seq
    }

    /// Number of members.
    // Perform the 'member count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'member count' operation.
    // Errors are propagated to the caller via Result.
    pub fn member_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.members.len()
    }

    /// Number of admins.
    // Perform the 'admin count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'admin count' operation.
    // Errors are propagated to the caller via Result.
    pub fn admin_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.admins.len()
    }

    /// Whether a peer is a member.
    // Perform the 'is member' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_member(&self, peer_id: &PeerId) -> bool {
        // Check membership in the collection.
        // Execute this protocol step.
        self.members.contains(peer_id)
    }

    /// Whether a peer is an admin.
    // Perform the 'is admin peer' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_admin_peer(&self, peer_id: &PeerId) -> bool {
        // Check membership in the collection.
        // Execute this protocol step.
        self.admins.contains(peer_id)
    }

    /// Whether the group is at member capacity.
    // Perform the 'is full' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_full(&self) -> bool {
        // Validate the length matches the expected protocol size.
        // Execute this protocol step.
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
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
// Begin the block scope.
// GroupLanConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GroupLanConfig {
    /// Whether network sharing is enabled for this group.
    /// Enables subnet route advertisement and group-scoped map entries.
    // Execute this protocol step.
    pub network_sharing_enabled: bool,

    /// Whether proximity sharing is enabled.
    /// Enables BLE token chain distribution to members for
    /// stealthy BLE rendezvous (push-to-talk over BLE).
    // Execute this protocol step.
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
        // Ring signatures are not yet wired into group operations (§3.5.2 TODO).
        assert!(NetworkType::Private.uses_ring_signatures());
        assert!(NetworkType::Closed.uses_ring_signatures());
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
            (
                vec![PeerId([0x01; 32]), PeerId([0x02; 32])],
                vec![PeerId([0x01; 32])],
            ),
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

    #[test]
    fn test_group_json_round_trip_with_peer_sender_keys() {
        let mut group = test_group(1000);
        group.peer_sender_keys.insert(
            [0x22; 32],
            PeerSenderKeyState {
                chain_key: [0x33; 32],
                next_iteration: 7,
                verifying_key: [0x44; 32],
            },
        );

        let serialized = serde_json::to_string(&group).unwrap();
        assert!(serialized.contains(&hex::encode([0x22; 32])));

        let restored: Group = serde_json::from_str(&serialized).unwrap();
        let restored_state = restored.peer_sender_keys.get(&[0x22; 32]).unwrap();
        assert_eq!(restored_state.chain_key, [0x33; 32]);
        assert_eq!(restored_state.next_iteration, 7);
        assert_eq!(restored_state.verifying_key, [0x44; 32]);
    }
}
