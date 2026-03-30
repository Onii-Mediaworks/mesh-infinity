//! Social Profiles (§9)
//!
//! # Profile Layers (§9.0)
//!
//! Mesh Infinity has multiple profile layers, each with different
//! visibility and sharing rules:
//!
//! 1. **Global Public Profile** (§9.1) — opt-in, visible to everyone.
//!    Minimal: display name, tagline, avatar.
//!
//! 2. **Public Paired Profile** (§9.2) — visible to anyone we've
//!    paired with (Level 1+). Contains display name, tagline, bio,
//!    avatar, contact hints.
//!
//! 3. **Global Private Profile** (§9.3) — visible only to trusted
//!    peers (Level 6+). Contains private display name, bio, avatar
//!    override, contact hints.
//!
//! 4. **Per-Garden Profile** (§9.4) — per-community profile with
//!    Garden-specific display name, bio, avatar, pronouns.
//!
//! 5. **Anonymous Profile** (§9.5) — a mask-level identity with
//!    no linkage to any other profile layer.
//!
//! # Profile Resolution Order (§9.4)
//!
//! When displaying a peer's name, the system resolves in order:
//! 1. GardenProfile.display_name (if in a Garden context)
//! 2. GlobalPrivateProfile.private_display_name (if Level 6+)
//! 3. PublicPairedProfile.display_name (if paired)
//! 4. GlobalPublicProfile.public_display_name (if published)
//! 5. Peer ID (truncated hex, last resort)
//!
//! # Update Padding (§9)
//!
//! - Initial private profile exchange: random size in upper half of 0–16 MB
//! - Routine private updates: 1 KB bucket padding
//! - Paired/Garden updates: 256-byte bucket padding
//!
//! # Cross-Profile Linkage (§9.6)
//!
//! By default, profiles are UNLINKABLE. Cross-profile linkage
//! (e.g., "this anonymous poster is the same person as this
//! trusted peer") is NEVER automatic. It requires explicit
//! user action and a signed linkage claim.

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum display name length (bytes).
// MAX_DISPLAY_NAME_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_DISPLAY_NAME_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_DISPLAY_NAME_LEN: usize = 64;

/// Maximum tagline length (bytes).
// MAX_TAGLINE_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_TAGLINE_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_TAGLINE_LEN: usize = 128;

/// Maximum bio length (bytes).
// MAX_BIO_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_BIO_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_BIO_LEN: usize = 512;

/// Maximum pronouns length (bytes).
// MAX_PRONOUNS_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PRONOUNS_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_PRONOUNS_LEN: usize = 32;

/// Routine private profile update padding bucket (bytes).
// PRIVATE_UPDATE_PADDING — protocol constant.
// Defined by the spec; must not change without a version bump.
// PRIVATE_UPDATE_PADDING — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PRIVATE_UPDATE_PADDING: usize = 1024;

/// Paired/Garden profile update padding bucket (bytes).
// PAIRED_UPDATE_PADDING — protocol constant.
// Defined by the spec; must not change without a version bump.
// PAIRED_UPDATE_PADDING — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PAIRED_UPDATE_PADDING: usize = 256;

/// Retirement record retention period (seconds). 30 days.
// RETIREMENT_RETENTION_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// RETIREMENT_RETENTION_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const RETIREMENT_RETENTION_SECS: u64 = 30 * 24 * 3600;

// ---------------------------------------------------------------------------
// Global Public Profile (§9.1)
// ---------------------------------------------------------------------------

/// A global public profile, visible to everyone.
///
/// Opt-in — not created by default. Minimal information only.
/// Published to the public network map / DHT.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// GlobalPublicProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GlobalPublicProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GlobalPublicProfile {
    /// The peer ID this profile belongs to.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_id: PeerId,

    /// Public display name (max 64 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub display_name: Option<String>,

    /// Short tagline (max 128 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub tagline: Option<String>,

    /// SHA-256 hash of the avatar image.
    // Execute this protocol step.
    // Execute this protocol step.
    pub avatar_hash: Option<[u8; 32]>,

    /// Monotonically increasing version number.
    // Execute this protocol step.
    // Execute this protocol step.
    pub version: u64,

    /// Ed25519 signature over all fields (by public mask key).
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Public Paired Profile (§9.2)
// ---------------------------------------------------------------------------

/// Profile visible to anyone we've paired with (Level 1+).
///
/// Richer than the global public profile. Shared automatically
/// after pairing, signed by the relationship-specific mask key.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PublicPairedProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PublicPairedProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PublicPairedProfile {
    /// Display name (max 64 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub display_name: String,

    /// Short tagline (max 128 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub tagline: Option<String>,

    /// Bio (max 512 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub bio: Option<String>,

    /// SHA-256 hash of the avatar image.
    // Execute this protocol step.
    // Execute this protocol step.
    pub avatar_hash: Option<[u8; 32]>,

    /// Contact hint (how to reach this person out-of-band).
    // Execute this protocol step.
    // Execute this protocol step.
    pub contact_hint: Option<String>,

    /// Version number for update tracking.
    // Execute this protocol step.
    // Execute this protocol step.
    pub version: u64,

    /// Ed25519 signature (by mask key).
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Global Private Profile (§9.3)
// ---------------------------------------------------------------------------

/// Profile visible only to trusted peers (Level 6+).
///
/// Shared via the trust promotion protocol (§8.4).
/// Contains more personal information than the public profiles.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// GlobalPrivateProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GlobalPrivateProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GlobalPrivateProfile {
    /// Private display name (may differ from public).
    // Execute this protocol step.
    // Execute this protocol step.
    pub private_display_name: Option<String>,

    /// Private bio.
    // Execute this protocol step.
    // Execute this protocol step.
    pub private_bio: Option<String>,

    /// Contact hints (phone, email, etc. — shared only with trusted).
    // Execute this protocol step.
    // Execute this protocol step.
    pub contact_hints: Vec<String>,

    /// Avatar override hash (if different from public avatar).
    // Execute this protocol step.
    // Execute this protocol step.
    pub avatar_override_hash: Option<[u8; 32]>,

    /// Version number.
    // Execute this protocol step.
    // Execute this protocol step.
    pub version: u64,
}

// ---------------------------------------------------------------------------
// Per-Garden Profile (§9.4)
// ---------------------------------------------------------------------------

/// A per-community/Garden profile.
///
/// Each Garden can have its own display name, bio, avatar, and
/// pronouns. This allows users to present differently in different
/// communities without linking their identities.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// GardenProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// GardenProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct GardenProfile {
    /// Which Garden this profile is for.
    // Execute this protocol step.
    // Execute this protocol step.
    pub garden_id: [u8; 32],

    /// Display name in this Garden (max 64 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub display_name: Option<String>,

    /// Bio for this Garden (max 512 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub bio: Option<String>,

    /// Avatar hash for this Garden.
    // Execute this protocol step.
    // Execute this protocol step.
    pub avatar_hash: Option<[u8; 32]>,

    /// Pronouns (max 32 bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub pronouns: Option<String>,

    /// Version number.
    // Execute this protocol step.
    // Execute this protocol step.
    pub version: u64,

    /// Ed25519 signature (by mask key used for this Garden).
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Profile Resolution (§9.4)
// ---------------------------------------------------------------------------

/// Resolve the display name for a peer in a given context.
///
/// Follows the resolution order from §9.4:
/// 1. Garden profile display name (if in Garden context)
/// 2. Private profile display name (if Level 6+)
/// 3. Paired profile display name
/// 4. Public profile display name
/// 5. Peer ID (truncated hex)
// Perform the 'resolve display name' operation.
// Errors are propagated to the caller via Result.
// Perform the 'resolve display name' operation.
// Errors are propagated to the caller via Result.
pub fn resolve_display_name(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    peer_id: &PeerId,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    garden_profile: Option<&GardenProfile>,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    private_profile: Option<&GlobalPrivateProfile>,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    paired_profile: Option<&PublicPairedProfile>,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    public_profile: Option<&GlobalPublicProfile>,
// Begin the block scope.
// Execute this protocol step.
// Execute this protocol step.
) -> String {
    // 1. Garden profile.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if let Some(gp) = garden_profile {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(ref name) = gp.display_name {
            // Validate the input length to prevent out-of-bounds access.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !name.is_empty() {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                return name.clone();
            }
        }
    }

    // 2. Private profile (trusted tier).
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if let Some(pp) = private_profile {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(ref name) = pp.private_display_name {
            // Validate the input length to prevent out-of-bounds access.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !name.is_empty() {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                return name.clone();
            }
        }
    }

    // 3. Paired profile.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if let Some(pp) = paired_profile {
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !pp.display_name.is_empty() {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            return pp.display_name.clone();
        }
    }

    // 4. Public profile.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if let Some(pp) = public_profile {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(ref name) = pp.display_name {
            // Validate the input length to prevent out-of-bounds access.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !name.is_empty() {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                return name.clone();
            }
        }
    }

    // 5. Fallback: peer ID hex.
    // Execute this protocol step.
    // Execute this protocol step.
    peer_id.short_hex()
}

// ---------------------------------------------------------------------------
// Profile Retirement (§9.1)
// ---------------------------------------------------------------------------

/// A public identity retirement record (§9.1).
///
/// Announces that a public profile has been retired.
/// Kept for 30 days, then LRU-evicted.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PublicIdentityRetirement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PublicIdentityRetirement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PublicIdentityRetirement {
    /// The retired peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    pub retired_peer_id: PeerId,

    /// Why the identity was retired.
    // Execute this protocol step.
    // Execute this protocol step.
    pub reason: RetirementReason,

    /// When the retirement was announced.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,

    /// Ed25519 signature (by the retiring identity's public mask key).
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

/// Why a public identity was retired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// RetirementReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// RetirementReason — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RetirementReason {
    /// User voluntarily retired the identity.
    // Execute this protocol step.
    // Execute this protocol step.
    Voluntary,
    /// Emergency retirement (killswitch, compromise).
    // Execute this protocol step.
    // Execute this protocol step.
    Emergency,
}

// ---------------------------------------------------------------------------
// Cross-Profile Linkage (§9.6)
// ---------------------------------------------------------------------------

/// An explicit cross-profile linkage claim (§9.6).
///
/// Links two profiles as belonging to the same person.
/// NEVER automatic — requires explicit user action.
/// Signed by both profiles' mask keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ProfileLinkage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ProfileLinkage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ProfileLinkage {
    /// The first profile's peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    pub profile_a: PeerId,
    /// The second profile's peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    pub profile_b: PeerId,
    /// Whether the linkage is bidirectional (both parties agreed).
    // Execute this protocol step.
    // Execute this protocol step.
    pub bidirectional: bool,
    /// When the linkage was created.
    // Execute this protocol step.
    // Execute this protocol step.
    pub created_at: u64,
    /// Signature from profile A's mask key.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature_a: Vec<u8>,
    /// Signature from profile B's mask key (if bidirectional).
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature_b: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Update Padding
// ---------------------------------------------------------------------------

/// Pad a profile update to the appropriate bucket size.
///
/// `data`: the serialized profile update.
/// `bucket_size`: the padding bucket (PRIVATE_UPDATE_PADDING or
///   PAIRED_UPDATE_PADDING).
///
/// Returns padded data. The padding is random bytes appended
/// after a length delimiter.
// Perform the 'pad profile update' operation.
// Errors are propagated to the caller via Result.
// Perform the 'pad profile update' operation.
// Errors are propagated to the caller via Result.
pub fn pad_profile_update(data: &[u8], bucket_size: usize) -> Vec<u8> {
    // Round up to the next multiple of bucket_size.
    // Compute padded len for this protocol step.
    // Compute padded len for this protocol step.
    let padded_len = ((data.len() + 4) / bucket_size + 1) * bucket_size;

    // Pre-allocate the buffer to avoid repeated reallocations.
    // Compute padded for this protocol step.
    // Compute padded for this protocol step.
    let mut padded = Vec::with_capacity(padded_len);
    // 4-byte length prefix (little-endian) so the receiver knows
    // where the real data ends and padding begins.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    padded.extend_from_slice(&(data.len() as u32).to_le_bytes());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    padded.extend_from_slice(data);
    // Fill remainder with zeros (in production: random bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    padded.resize(padded_len, 0);
    padded
}

/// Remove padding from a profile update.
///
/// Returns the original data, or None if the length prefix is invalid.
// Perform the 'unpad profile update' operation.
// Errors are propagated to the caller via Result.
// Perform the 'unpad profile update' operation.
// Errors are propagated to the caller via Result.
pub fn unpad_profile_update(padded: &[u8]) -> Option<Vec<u8>> {
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if padded.len() < 4 {
        // No result available — signal absence to the caller.
        // Return to the caller.
        // Return to the caller.
        return None;
    }
    // Track the count for threshold and bounds checking.
    // Compute len for this protocol step.
    // Compute len for this protocol step.
    let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if 4 + len > padded.len() {
        // No result available — signal absence to the caller.
        // Return to the caller.
        // Return to the caller.
        return None;
    }
    // Wrap the found value for the caller.
    // Wrap the found value.
    // Wrap the found value.
    Some(padded[4..4 + len].to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> PeerId {
        PeerId::from_ed25519_pub(&[0x42; 32])
    }

    #[test]
    fn test_resolve_garden_first() {
        let gp = GardenProfile {
            garden_id: [0; 32],
            display_name: Some("GardenAlice".to_string()),
            bio: None,
            avatar_hash: None,
            pronouns: None,
            version: 1,
            signature: vec![],
        };

        let name = resolve_display_name(
            &test_peer(),
            Some(&gp),
            None,
            None,
            None,
        );
        assert_eq!(name, "GardenAlice");
    }

    #[test]
    fn test_resolve_private_over_paired() {
        let private = GlobalPrivateProfile {
            private_display_name: Some("RealAlice".to_string()),
            private_bio: None,
            contact_hints: vec![],
            avatar_override_hash: None,
            version: 1,
        };

        let paired = PublicPairedProfile {
            display_name: "PairedAlice".to_string(),
            tagline: None,
            bio: None,
            avatar_hash: None,
            contact_hint: None,
            version: 1,
            signature: vec![],
        };

        let name = resolve_display_name(
            &test_peer(),
            None,
            Some(&private),
            Some(&paired),
            None,
        );
        assert_eq!(name, "RealAlice");
    }

    #[test]
    fn test_resolve_fallback_to_peer_id() {
        let name = resolve_display_name(
            &test_peer(),
            None,
            None,
            None,
            None,
        );
        // Should be the short hex of the peer ID.
        assert_eq!(name.len(), 8); // 4 bytes = 8 hex chars.
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let data = b"hello profile";
        let padded = pad_profile_update(data, PAIRED_UPDATE_PADDING);

        // Padded should be a multiple of the bucket size.
        assert_eq!(padded.len() % PAIRED_UPDATE_PADDING, 0);
        assert!(padded.len() >= data.len() + 4);

        // Unpad should recover original.
        let recovered = unpad_profile_update(&padded).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_pad_sizes() {
        // Small data: padded to 1 bucket.
        let small = pad_profile_update(b"hi", PRIVATE_UPDATE_PADDING);
        assert_eq!(small.len(), PRIVATE_UPDATE_PADDING);

        // Data exactly at bucket boundary (minus length prefix):
        // rounds up to next bucket.
        let exact = vec![0u8; PRIVATE_UPDATE_PADDING - 4];
        let padded = pad_profile_update(&exact, PRIVATE_UPDATE_PADDING);
        assert_eq!(padded.len() % PRIVATE_UPDATE_PADDING, 0);
        assert!(padded.len() >= exact.len() + 4);
    }

    #[test]
    fn test_unpad_invalid() {
        // Too short.
        assert!(unpad_profile_update(&[]).is_none());
        assert!(unpad_profile_update(&[0, 0, 0]).is_none());

        // Length prefix claims more data than available.
        assert!(unpad_profile_update(&[0xFF, 0xFF, 0, 0, 0]).is_none());
    }

    #[test]
    fn test_retirement_reason_serde() {
        let retirement = PublicIdentityRetirement {
            retired_peer_id: test_peer(),
            reason: RetirementReason::Emergency,
            timestamp: 1000,
            signature: vec![0x42; 64],
        };
        let json = serde_json::to_string(&retirement).unwrap();
        let recovered: PublicIdentityRetirement = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.reason, RetirementReason::Emergency);
    }
}
