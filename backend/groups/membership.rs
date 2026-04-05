//! Group Membership Management (§8.7.3)
//!
//! # Membership Operations
//!
//! Group membership is managed by admins through four operations:
//!
//! 1. **Add member** — admin adds a peer to the group. The group
//!    public key and current Sender Key state are shared with the
//!    new member via an encrypted direct message.
//!
//! 2. **Remove member** — admin removes a non-admin member.
//!    Triggers the superset ring model (§8.7.4) and Sender Key
//!    rekeying.
//!
//! 3. **Promote to admin** — admin promotes a member. Subject to
//!    quorum confirmation via vote-to-reject (§8.10). The promoted
//!    member receives the group private key.
//!
//! 4. **Leave group** — any member can leave voluntarily.
//!    Triggers the same removal flow as admin removal.
//!
//! # Membership Events
//!
//! All membership changes produce MembershipEvent records that
//! are stored in the group's history. Events are signed by the
//! admin who performed the action (or the leaving member).
//!
//! # Member Lists
//!
//! Member lists are shared only among members. Non-members cannot
//! enumerate the group. For Private/Closed groups, even the member
//! count is hidden.
//!
//! # Quorum Rules
//!
//! Admin promotion requires quorum confirmation: existing admins
//! have a window to vote-to-reject. If no rejection vote reaches
//! threshold, the promotion is confirmed automatically.

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default vote-to-reject window for admin promotions (seconds).
/// 24 hours gives admins time to review and potentially reject.
// VOTE_TO_REJECT_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// VOTE_TO_REJECT_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const VOTE_TO_REJECT_WINDOW_SECS: u64 = 24 * 3600;

/// Default rejection threshold (fraction of admins who must reject).
/// 50% + 1 of admins must reject to block a promotion.
/// For a group with 3 admins, 2 must reject.
// DEFAULT_REJECTION_THRESHOLD — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_REJECTION_THRESHOLD — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEFAULT_REJECTION_THRESHOLD: f32 = 0.51;

// ---------------------------------------------------------------------------
// Member Role
// ---------------------------------------------------------------------------

/// A member's role within a group.
///
/// Roles determine what operations a member can perform.
/// The role hierarchy is: Admin > Member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// MemberRole — variant enumeration.
// Match exhaustively to handle every protocol state.
// MemberRole — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MemberRole {
    /// Regular member. Can send/receive messages and view content.
    /// Cannot manage other members or change group settings.
    Member,

    /// Group administrator. Can add/remove members, promote members,
    /// change group settings, trigger rekeying, and sign group profiles.
    /// Holds the group's private key.
    Admin,
}

// Begin the block scope.
// MemberRole implementation — core protocol logic.
// MemberRole implementation — core protocol logic.
impl MemberRole {
    /// Whether this role can manage other members.
    // Perform the 'can manage members' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'can manage members' operation.
    // Errors are propagated to the caller via Result.
    pub fn can_manage_members(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Admin)
    }

    /// Whether this role can change group settings.
    // Perform the 'can change settings' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'can change settings' operation.
    // Errors are propagated to the caller via Result.
    pub fn can_change_settings(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Admin)
    }

    /// Whether this role can trigger rekeying.
    // Perform the 'can trigger rekey' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'can trigger rekey' operation.
    // Errors are propagated to the caller via Result.
    pub fn can_trigger_rekey(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Admin)
    }
}

// ---------------------------------------------------------------------------
// Member Info
// ---------------------------------------------------------------------------

/// Information about a group member.
///
/// Stored in the group's member list. Contains the member's
/// identity, role, and bookkeeping metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MemberInfo — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MemberInfo — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MemberInfo {
    /// The member's peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_id: PeerId,

    /// The member's role (Admin or Member).
    // Execute this protocol step.
    // Execute this protocol step.
    pub role: MemberRole,

    /// When the member joined (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    pub joined_at: u64,

    /// Who added this member (admin's peer ID).
    /// None for the group creator.
    // Execute this protocol step.
    // Execute this protocol step.
    pub added_by: Option<PeerId>,

    /// The Sender Key epoch the member joined at.
    /// Members who joined at an older epoch may need
    /// to re-sync their Sender Key state.
    // Execute this protocol step.
    // Execute this protocol step.
    pub joined_epoch: u64,

    /// Whether this member has acknowledged the current
    /// Sender Key epoch. Members who haven't acknowledged
    /// might have missed a rekeying event.
    // Execute this protocol step.
    // Execute this protocol step.
    pub current_epoch_ack: bool,
}

// ---------------------------------------------------------------------------
// Membership Event
// ---------------------------------------------------------------------------

/// A membership change event.
///
/// Recorded in the group's event log. Signed by the actor
/// (the admin who performed the action or the leaving member).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MembershipEvent — variant enumeration.
// Match exhaustively to handle every protocol state.
// MembershipEvent — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MembershipEvent {
    /// A new member was added.
    // Execute this protocol step.
    // Execute this protocol step.
    MemberAdded {
        /// The new member's peer ID.
        // Execute this protocol step.
        // Execute this protocol step.
        member: PeerId,
        /// The admin who added them.
        // Execute this protocol step.
        // Execute this protocol step.
        added_by: PeerId,
        /// When they were added.
        // Execute this protocol step.
        // Execute this protocol step.
        timestamp: u64,
    },

    /// A member was removed by an admin.
    // Execute this protocol step.
    // Execute this protocol step.
    MemberRemoved {
        /// The removed member's peer ID.
        // Execute this protocol step.
        // Execute this protocol step.
        member: PeerId,
        /// The admin who removed them.
        // Execute this protocol step.
        // Execute this protocol step.
        removed_by: PeerId,
        /// When they were removed.
        // Execute this protocol step.
        // Execute this protocol step.
        timestamp: u64,
    },

    /// A member left voluntarily.
    // Execute this protocol step.
    // Execute this protocol step.
    MemberLeft {
        /// The leaving member's peer ID.
        // Execute this protocol step.
        // Execute this protocol step.
        member: PeerId,
        /// When they left.
        // Execute this protocol step.
        // Execute this protocol step.
        timestamp: u64,
    },

    /// A member was promoted to admin.
    // Execute this protocol step.
    // Execute this protocol step.
    AdminPromoted {
        /// The promoted member's peer ID.
        // Execute this protocol step.
        // Execute this protocol step.
        member: PeerId,
        /// The admin who promoted them.
        // Execute this protocol step.
        // Execute this protocol step.
        promoted_by: PeerId,
        /// When the promotion was confirmed.
        // Execute this protocol step.
        // Execute this protocol step.
        timestamp: u64,
    },

    /// A rekeying event occurred.
    // Execute this protocol step.
    // Execute this protocol step.
    Rekeyed {
        /// The new Sender Key epoch.
        // Execute this protocol step.
        // Execute this protocol step.
        new_epoch: u64,
        /// The admin who triggered it.
        // Execute this protocol step.
        // Execute this protocol step.
        triggered_by: PeerId,
        /// When rekeying occurred.
        // Execute this protocol step.
        // Execute this protocol step.
        timestamp: u64,
        /// Reason for rekeying.
        // Execute this protocol step.
        // Execute this protocol step.
        reason: RekeyReason,
    },
}

/// Why a rekeying was triggered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// RekeyReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// RekeyReason — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RekeyReason {
    /// Scheduled interval expired.
    // Execute this protocol step.
    // Execute this protocol step.
    Scheduled,
    /// A member was removed.
    // Execute this protocol step.
    // Execute this protocol step.
    MemberRemoved,
    /// An admin manually triggered rekeying.
    // Execute this protocol step.
    // Execute this protocol step.
    ManualTrigger,
    /// The superset ring model forced a rekey
    /// (second removal before first rekey completed).
    // Execute this protocol step.
    // Execute this protocol step.
    ForcedBySuperset,
    /// Automatic timeout (24h after first removal without rekey).
    // Execute this protocol step.
    // Execute this protocol step.
    SupersetTimeout,
}

// ---------------------------------------------------------------------------
// Admin Promotion Vote
// ---------------------------------------------------------------------------

/// State for an admin promotion vote (§8.10 vote-to-reject).
///
/// When an admin promotes a member, other admins have a window
/// to reject. If the rejection threshold is met, the promotion
/// is cancelled.
#[derive(Clone, Debug)]
// Begin the block scope.
// PromotionVote — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PromotionVote — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PromotionVote {
    /// The member being promoted.
    // Execute this protocol step.
    // Execute this protocol step.
    pub candidate: PeerId,

    /// The admin who proposed the promotion.
    // Execute this protocol step.
    // Execute this protocol step.
    pub proposed_by: PeerId,

    /// When the proposal was made (Unix timestamp).
    // Execute this protocol step.
    // Execute this protocol step.
    pub proposed_at: u64,

    /// Rejection votes received (only from eligible admins).
    // Execute this protocol step.
    // Execute this protocol step.
    pub rejections: Vec<PeerId>,

    /// Total number of admins at the time of proposal.
    /// Used to compute threshold.
    // Execute this protocol step.
    // Execute this protocol step.
    pub total_admins: usize,

    /// The rejection threshold (fraction).
    // Execute this protocol step.
    // Execute this protocol step.
    pub threshold: f32,

    /// The set of admins eligible to cast rejection votes.
    ///
    /// Populated at proposal time from the current admin list.
    /// `reject()` will silently ignore any voter not in this set,
    /// preventing non-admin or fabricated PeerIds from counting.
    // Execute this protocol step.
    // Execute this protocol step.
    pub eligible_voters: Vec<PeerId>,
}

// Begin the block scope.
// PromotionVote implementation — core protocol logic.
// PromotionVote implementation — core protocol logic.
impl PromotionVote {
    /// Create a new promotion vote.
    ///
    /// `eligible_voters` is the current admin list at proposal time —
    /// only these PeerIds are allowed to cast rejection votes.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        candidate: PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        proposed_by: PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        total_admins: usize,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        eligible_voters: Vec<PeerId>,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            candidate,
            // Execute this protocol step.
            // Execute this protocol step.
            proposed_by,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            proposed_at: now,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            rejections: Vec::new(),
            // Execute this protocol step.
            // Execute this protocol step.
            total_admins,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            threshold: DEFAULT_REJECTION_THRESHOLD,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            eligible_voters,
        }
    }

    /// Record a rejection vote from `voter`.
    ///
    /// Returns true if the threshold has been met (promotion blocked).
    /// Silently ignores votes from peers not in `eligible_voters` —
    /// only admins present at proposal time may reject.
    // Perform the 'reject' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'reject' operation.
    // Errors are propagated to the caller via Result.
    pub fn reject(&mut self, voter: PeerId) -> bool {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.eligible_voters.contains(&voter) {
            // Voter is not an eligible admin — ignore.
            // Return to the caller.
            // Return to the caller.
            return self.is_rejected();
        }
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.rejections.contains(&voter) {
            // Execute the operation and bind the result.
            // Append to the collection.
            // Append to the collection.
            self.rejections.push(voter);
        }
        // Delegate to the instance method.
        // Execute this protocol step.
        // Execute this protocol step.
        self.is_rejected()
    }

    /// Whether the rejection threshold has been met.
    // Perform the 'is rejected' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is rejected' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_rejected(&self) -> bool {
        // Track the count for threshold and bounds checking.
        // Compute required for this protocol step.
        // Compute required for this protocol step.
        let required = (self.total_admins as f32 * self.threshold).ceil() as usize;
        // Validate the length matches the expected protocol size.
        // Execute this protocol step.
        // Execute this protocol step.
        self.rejections.len() >= required
    }

    /// Whether the voting window has expired.
    // Perform the 'is expired' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is expired' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_expired(&self, now: u64) -> bool {
        // Clamp the value to prevent overflow or underflow.
        // Execute this protocol step.
        // Execute this protocol step.
        now.saturating_sub(self.proposed_at) > VOTE_TO_REJECT_WINDOW_SECS
    }

    /// Whether the promotion should be confirmed.
    ///
    /// Confirmed if the voting window has expired AND the
    /// rejection threshold was NOT met.
    // Perform the 'is confirmed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is confirmed' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_confirmed(&self, now: u64) -> bool {
        // Delegate to the instance method.
        // Execute this protocol step.
        // Execute this protocol step.
        self.is_expired(now) && !self.is_rejected()
    }
}

// ---------------------------------------------------------------------------
// Membership Manager
// ---------------------------------------------------------------------------

/// Manages group membership operations.
///
/// Validates membership changes, maintains the member list,
/// and produces membership events for the group's event log.
// MembershipManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MembershipManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MembershipManager {
    /// Current member list.
    // Execute this protocol step.
    // Execute this protocol step.
    pub members: Vec<MemberInfo>,

    /// Event log of all membership changes.
    // Execute this protocol step.
    // Execute this protocol step.
    pub events: Vec<MembershipEvent>,

    /// Pending admin promotion votes.
    // Execute this protocol step.
    // Execute this protocol step.
    pub pending_promotions: Vec<PromotionVote>,
}

// Begin the block scope.
// MembershipManager implementation — core protocol logic.
// MembershipManager implementation — core protocol logic.
impl MembershipManager {
    /// Create a new membership manager for a group.
    ///
    /// `creator`: the group creator's peer ID.
    /// `epoch`: the initial Sender Key epoch.
    /// `now`: current unix timestamp.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(creator: PeerId, epoch: u64, now: u64) -> Self {
        // Identify the peer for this operation.
        // Compute creator info for this protocol step.
        // Compute creator info for this protocol step.
        let creator_info = MemberInfo {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            peer_id: creator,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            role: MemberRole::Admin,
            // Execute this protocol step.
            // Execute this protocol step.
            joined_at: now,
            // Execute this protocol step.
            // Execute this protocol step.
            added_by: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            joined_epoch: epoch,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            current_epoch_ack: true,
        };

        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            members: vec![creator_info],
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            events: Vec::new(),
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            pending_promotions: Vec::new(),
        }
    }

    /// Add a member to the group.
    ///
    /// Only admins can add members. Returns an error if:
    /// - The actor is not an admin
    /// - The member is already in the group
    /// - The group is full
    // Perform the 'add member' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add member' operation.
    // Errors are propagated to the caller via Result.
    pub fn add_member(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Execute this protocol step.
        // Execute this protocol step.
        member: PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        added_by: PeerId,
        // Execute this protocol step.
        // Execute this protocol step.
        epoch: u64,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Result<(), MembershipError> {
        // Check that the actor is an admin.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.is_admin(&added_by) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::NotAdmin);
        }

        // Check for duplicate.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.is_member(&member) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::AlreadyMember);
        }

        // Check capacity.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.members.len() >= super::group::MAX_GROUP_MEMBERS {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::GroupFull);
        }

        // Add the member.
        // Append to the collection.
        // Append to the collection.
        self.members.push(MemberInfo {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            peer_id: member,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            role: MemberRole::Member,
            // Execute this protocol step.
            // Execute this protocol step.
            joined_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            added_by: Some(added_by),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            joined_epoch: epoch,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            current_epoch_ack: true,
        });

        // Record the event.
        // Append to the collection.
        // Append to the collection.
        self.events.push(MembershipEvent::MemberAdded {
            member,
            // Execute this protocol step.
            // Execute this protocol step.
            added_by,
            // Execute this protocol step.
            // Execute this protocol step.
            timestamp: now,
        });

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }

    /// Remove a member from the group.
    ///
    /// Only admins can remove members, and they cannot remove
    /// other admins (admin removal requires a different process).
    ///
    /// Returns true if a rekey is needed (always true after removal).
    // Perform the 'remove member' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'remove member' operation.
    // Errors are propagated to the caller via Result.
    pub fn remove_member(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Execute this protocol step.
        // Execute this protocol step.
        member: PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        removed_by: PeerId,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Result<bool, MembershipError> {
        // Check that the actor is an admin.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.is_admin(&removed_by) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::NotAdmin);
        }

        // Check that the target is a member.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.is_member(&member) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::NotMember);
        }

        // Cannot remove admins this way.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.is_admin(&member) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::CannotRemoveAdmin);
        }

        // Remove the member.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.members.retain(|m| m.peer_id != member);

        // Record the event.
        // Append to the collection.
        // Append to the collection.
        self.events.push(MembershipEvent::MemberRemoved {
            member,
            // Execute this protocol step.
            // Execute this protocol step.
            removed_by,
            // Execute this protocol step.
            // Execute this protocol step.
            timestamp: now,
        });

        // Rekeying is always needed after removal.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(true)
    }

    /// A member leaves voluntarily.
    ///
    /// Returns true if a rekey is needed (always true after a leave).
    // Perform the 'member leave' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'member leave' operation.
    // Errors are propagated to the caller via Result.
    pub fn member_leave(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Execute this protocol step.
        // Execute this protocol step.
        member: PeerId,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Result<bool, MembershipError> {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.is_member(&member) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::NotMember);
        }

        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.members.retain(|m| m.peer_id != member);

        // Begin the block scope.
        // Append to the collection.
        // Append to the collection.
        self.events.push(MembershipEvent::MemberLeft {
            member,
            // Execute this protocol step.
            // Execute this protocol step.
            timestamp: now,
        });

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(true)
    }

    /// Propose an admin promotion.
    ///
    /// Starts the vote-to-reject process. Other admins have
    /// VOTE_TO_REJECT_WINDOW_SECS to reject. If no rejection
    /// threshold is met, the promotion is confirmed.
    // Perform the 'propose promotion' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'propose promotion' operation.
    // Errors are propagated to the caller via Result.
    pub fn propose_promotion(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        candidate: PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        proposed_by: PeerId,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Result<(), MembershipError> {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.is_admin(&proposed_by) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::NotAdmin);
        }

        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.is_member(&candidate) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::NotMember);
        }

        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.is_admin(&candidate) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::AlreadyAdmin);
        }

        // Track the count for threshold and bounds checking.
        // Compute admin count for this protocol step.
        // Compute admin count for this protocol step.
        let admin_count = self.admin_count();
        // Identify the peer for this operation.
        // Compute eligible for this protocol step.
        // Compute eligible for this protocol step.
        let eligible: Vec<PeerId> = self
            .members
            .iter()
            // Select only elements matching the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            .filter(|m| m.role == MemberRole::Admin)
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            // Transform each element.
            .map(|m| m.peer_id)
            // Materialize the iterator into a concrete collection.
            // Collect into a concrete collection.
            // Collect into a concrete collection.
            .collect();
        // Capture the current timestamp for temporal ordering.
        // Compute vote for this protocol step.
        // Compute vote for this protocol step.
        let vote = PromotionVote::new(candidate, proposed_by, admin_count, eligible, now);
        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        self.pending_promotions.push(vote);

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }

    /// Confirm a pending promotion (after vote window expires).
    // Perform the 'confirm promotion' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'confirm promotion' operation.
    // Errors are propagated to the caller via Result.
    pub fn confirm_promotion(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        candidate: &PeerId,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Result<(), MembershipError> {
        // Find the pending promotion.
        // Compute vote idx for this protocol step.
        // Compute vote idx for this protocol step.
        let vote_idx = self
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            .pending_promotions
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            .iter()
            // Apply the closure to each element.
            // Execute this protocol step.
            // Execute this protocol step.
            .position(|v| v.candidate == *candidate);

        // Unique identifier for lookup and deduplication.
        // Compute idx for this protocol step.
        // Compute idx for this protocol step.
        let idx = match vote_idx {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(i) => i,
            // Update the local state.
            // No value available.
            // No value available.
            None => return Err(MembershipError::NoPendingPromotion),
        };

        // Execute the operation and bind the result.
        // Compute vote for this protocol step.
        // Compute vote for this protocol step.
        let vote = &self.pending_promotions[idx];

        // Check if confirmed (window expired and not rejected).
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !vote.is_confirmed(now) {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if vote.is_rejected() {
                // Remove from the collection and return the evicted value.
                // Remove from the collection.
                // Remove from the collection.
                self.pending_promotions.remove(idx);
                // Reject with an explicit error for the caller to handle.
                // Return to the caller.
                // Return to the caller.
                return Err(MembershipError::PromotionRejected);
            }
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            return Err(MembershipError::VoteWindowOpen);
        }

        // Calculate the position within the data structure.
        // Compute proposed by for this protocol step.
        // Compute proposed by for this protocol step.
        let proposed_by = vote.proposed_by;
        // Remove from the collection and return the evicted value.
        // Remove from the collection.
        // Remove from the collection.
        self.pending_promotions.remove(idx);

        // Promote the member.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(member) = self.members.iter_mut().find(|m| m.peer_id == *candidate) {
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            member.role = MemberRole::Admin;
        }

        // Begin the block scope.
        // Append to the collection.
        // Append to the collection.
        self.events.push(MembershipEvent::AdminPromoted {
            // Process the current step in the protocol.
            // Execute this protocol step.
            member: *candidate,
            // Process the current step in the protocol.
            // Execute this protocol step.
            promoted_by: proposed_by,
            // Execute this protocol step.
            timestamp: now,
        });

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Whether a peer is a member.
    // Perform the 'is member' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_member(&self, peer_id: &PeerId) -> bool {
        // Create an iterator over the collection elements.
        // Create an iterator over the elements.
        self.members.iter().any(|m| m.peer_id == *peer_id)
    }

    /// Whether a peer is an admin.
    // Perform the 'is admin' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_admin(&self, peer_id: &PeerId) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        self.members
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            .iter()
            // Apply the closure to each element.
            // Execute this protocol step.
            .any(|m| m.peer_id == *peer_id && m.role == MemberRole::Admin)
    }

    /// Number of members.
    // Perform the 'member count' operation.
    // Errors are propagated to the caller via Result.
    pub fn member_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        self.members.len()
    }

    /// Number of admins.
    // Perform the 'admin count' operation.
    // Errors are propagated to the caller via Result.
    pub fn admin_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        self.members
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            .iter()
            // Select only elements matching the predicate.
            // Filter by the predicate.
            .filter(|m| m.role == MemberRole::Admin)
            // Chain the operation on the intermediate result.
            .count()
    }

    /// Get all member peer IDs.
    // Perform the 'member ids' operation.
    // Errors are propagated to the caller via Result.
    pub fn member_ids(&self) -> Vec<PeerId> {
        // Transform the result, mapping errors to the local error type.
        // Create an iterator over the elements.
        self.members.iter().map(|m| m.peer_id).collect()
    }

    /// Get all admin peer IDs.
    // Perform the 'admin ids' operation.
    // Errors are propagated to the caller via Result.
    pub fn admin_ids(&self) -> Vec<PeerId> {
        // Mutate the internal state.
        // Execute this protocol step.
        self.members
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            .iter()
            // Select only elements matching the predicate.
            // Filter by the predicate.
            .filter(|m| m.role == MemberRole::Admin)
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            .map(|m| m.peer_id)
            // Materialize the iterator into a concrete collection.
            // Collect into a concrete collection.
            .collect()
    }
}

/// Errors from membership operations.
#[derive(Clone, Debug, PartialEq, Eq)]
// Begin the block scope.
// MembershipError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MembershipError {
    /// The actor is not an admin.
    // Execute this protocol step.
    NotAdmin,
    /// The target is already a member.
    // Execute this protocol step.
    AlreadyMember,
    /// The target is not a member.
    // Execute this protocol step.
    NotMember,
    /// The group is at capacity.
    // Execute this protocol step.
    GroupFull,
    /// Cannot remove an admin this way.
    // Execute this protocol step.
    CannotRemoveAdmin,
    /// The target is already an admin.
    // Execute this protocol step.
    AlreadyAdmin,
    /// No pending promotion for this candidate.
    // Execute this protocol step.
    NoPendingPromotion,
    /// The promotion was rejected by admin vote.
    // Execute this protocol step.
    PromotionRejected,
    /// The vote window is still open.
    // Execute this protocol step.
    VoteWindowOpen,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a PeerId from a byte.
    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn test_new_manager() {
        let mgr = MembershipManager::new(pid(0x01), 1, 1000);
        assert_eq!(mgr.member_count(), 1);
        assert_eq!(mgr.admin_count(), 1);
        assert!(mgr.is_admin(&pid(0x01)));
    }

    #[test]
    fn test_add_member() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);

        let result = mgr.add_member(pid(0x02), pid(0x01), 1, 1001);
        assert!(result.is_ok());
        assert_eq!(mgr.member_count(), 2);
        assert!(mgr.is_member(&pid(0x02)));
        assert!(!mgr.is_admin(&pid(0x02)));
    }

    #[test]
    fn test_add_member_not_admin() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);
        mgr.add_member(pid(0x02), pid(0x01), 1, 1001).unwrap();

        // Non-admin tries to add a member.
        let result = mgr.add_member(pid(0x03), pid(0x02), 1, 1002);
        assert_eq!(result, Err(MembershipError::NotAdmin));
    }

    #[test]
    fn test_add_duplicate() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);
        mgr.add_member(pid(0x02), pid(0x01), 1, 1001).unwrap();

        let result = mgr.add_member(pid(0x02), pid(0x01), 1, 1002);
        assert_eq!(result, Err(MembershipError::AlreadyMember));
    }

    #[test]
    fn test_remove_member() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);
        mgr.add_member(pid(0x02), pid(0x01), 1, 1001).unwrap();

        let result = mgr.remove_member(pid(0x02), pid(0x01), 1002);
        assert!(result.is_ok());
        assert!(result.unwrap()); // Rekey needed.
        assert_eq!(mgr.member_count(), 1);
        assert!(!mgr.is_member(&pid(0x02)));
    }

    #[test]
    fn test_cannot_remove_admin() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);

        // Try to remove ourselves (we're admin).
        let result = mgr.remove_member(pid(0x01), pid(0x01), 1001);
        assert_eq!(result, Err(MembershipError::CannotRemoveAdmin));
    }

    #[test]
    fn test_member_leave() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);
        mgr.add_member(pid(0x02), pid(0x01), 1, 1001).unwrap();

        let result = mgr.member_leave(pid(0x02), 1002);
        assert!(result.is_ok());
        assert_eq!(mgr.member_count(), 1);
    }

    #[test]
    fn test_promotion_vote_confirmed() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);
        mgr.add_member(pid(0x02), pid(0x01), 1, 1001).unwrap();

        // Propose promotion.
        mgr.propose_promotion(pid(0x02), pid(0x01), 1002).unwrap();

        // Try to confirm before window expires.
        let result = mgr.confirm_promotion(&pid(0x02), 1003);
        assert_eq!(result, Err(MembershipError::VoteWindowOpen));

        // Confirm after window expires.
        let after_window = 1002 + VOTE_TO_REJECT_WINDOW_SECS + 1;
        let result = mgr.confirm_promotion(&pid(0x02), after_window);
        assert!(result.is_ok());
        assert!(mgr.is_admin(&pid(0x02)));
    }

    #[test]
    fn test_promotion_rejected() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);
        // Add a second admin for voting.
        mgr.add_member(pid(0x02), pid(0x01), 1, 1001).unwrap();
        // Manually make them admin.
        mgr.members
            .iter_mut()
            .find(|m| m.peer_id == pid(0x02))
            .unwrap()
            .role = MemberRole::Admin;
        // Add the candidate.
        mgr.add_member(pid(0x03), pid(0x01), 1, 1002).unwrap();

        // Propose promotion.
        mgr.propose_promotion(pid(0x03), pid(0x01), 1003).unwrap();

        // Both admins reject (threshold = 51%, 2 admins → need 2 rejections).
        mgr.pending_promotions[0].reject(pid(0x01));
        mgr.pending_promotions[0].reject(pid(0x02));

        // Try to confirm.
        let after_window = 1003 + VOTE_TO_REJECT_WINDOW_SECS + 1;
        let result = mgr.confirm_promotion(&pid(0x03), after_window);
        assert_eq!(result, Err(MembershipError::PromotionRejected));

        // Candidate should NOT be admin.
        assert!(!mgr.is_admin(&pid(0x03)));
    }

    /// A non-admin peer who injects a rejection vote must be silently ignored.
    /// The promotion should still succeed after the window expires.
    #[test]
    fn test_promotion_ineligible_rejector_ignored() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);
        mgr.add_member(pid(0x03), pid(0x01), 1, 1002).unwrap();

        mgr.propose_promotion(pid(0x03), pid(0x01), 1003).unwrap();

        // pid(0xFF) is not an admin — its rejection must not count.
        mgr.pending_promotions[0].reject(pid(0xFF));

        assert_eq!(
            mgr.pending_promotions[0].rejections.len(),
            0,
            "ineligible rejector must not count"
        );

        // Promotion should still confirm after the window.
        let after_window = 1003 + VOTE_TO_REJECT_WINDOW_SECS + 1;
        let result = mgr.confirm_promotion(&pid(0x03), after_window);
        assert!(
            result.is_ok(),
            "ineligible rejections must not block promotion"
        );
        assert!(mgr.is_admin(&pid(0x03)));
    }

    #[test]
    fn test_event_log() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);

        mgr.add_member(pid(0x02), pid(0x01), 1, 1001).unwrap();
        mgr.remove_member(pid(0x02), pid(0x01), 1002).unwrap();

        assert_eq!(mgr.events.len(), 2);
        assert!(matches!(mgr.events[0], MembershipEvent::MemberAdded { .. }));
        assert!(matches!(
            mgr.events[1],
            MembershipEvent::MemberRemoved { .. }
        ));
    }
}
