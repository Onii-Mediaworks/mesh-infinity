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
pub const VOTE_TO_REJECT_WINDOW_SECS: u64 = 24 * 3600;

/// Default rejection threshold (fraction of admins who must reject).
/// 50% + 1 of admins must reject to block a promotion.
/// For a group with 3 admins, 2 must reject.
pub const DEFAULT_REJECTION_THRESHOLD: f32 = 0.51;

// ---------------------------------------------------------------------------
// Member Role
// ---------------------------------------------------------------------------

/// A member's role within a group.
///
/// Roles determine what operations a member can perform.
/// The role hierarchy is: Admin > Member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberRole {
    /// Regular member. Can send/receive messages and view content.
    /// Cannot manage other members or change group settings.
    Member,

    /// Group administrator. Can add/remove members, promote members,
    /// change group settings, trigger rekeying, and sign group profiles.
    /// Holds the group's private key.
    Admin,
}

impl MemberRole {
    /// Whether this role can manage other members.
    pub fn can_manage_members(&self) -> bool {
        matches!(self, Self::Admin)
    }

    /// Whether this role can change group settings.
    pub fn can_change_settings(&self) -> bool {
        matches!(self, Self::Admin)
    }

    /// Whether this role can trigger rekeying.
    pub fn can_trigger_rekey(&self) -> bool {
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
pub struct MemberInfo {
    /// The member's peer ID.
    pub peer_id: PeerId,

    /// The member's role (Admin or Member).
    pub role: MemberRole,

    /// When the member joined (Unix timestamp).
    pub joined_at: u64,

    /// Who added this member (admin's peer ID).
    /// None for the group creator.
    pub added_by: Option<PeerId>,

    /// The Sender Key epoch the member joined at.
    /// Members who joined at an older epoch may need
    /// to re-sync their Sender Key state.
    pub joined_epoch: u64,

    /// Whether this member has acknowledged the current
    /// Sender Key epoch. Members who haven't acknowledged
    /// might have missed a rekeying event.
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
pub enum MembershipEvent {
    /// A new member was added.
    MemberAdded {
        /// The new member's peer ID.
        member: PeerId,
        /// The admin who added them.
        added_by: PeerId,
        /// When they were added.
        timestamp: u64,
    },

    /// A member was removed by an admin.
    MemberRemoved {
        /// The removed member's peer ID.
        member: PeerId,
        /// The admin who removed them.
        removed_by: PeerId,
        /// When they were removed.
        timestamp: u64,
    },

    /// A member left voluntarily.
    MemberLeft {
        /// The leaving member's peer ID.
        member: PeerId,
        /// When they left.
        timestamp: u64,
    },

    /// A member was promoted to admin.
    AdminPromoted {
        /// The promoted member's peer ID.
        member: PeerId,
        /// The admin who promoted them.
        promoted_by: PeerId,
        /// When the promotion was confirmed.
        timestamp: u64,
    },

    /// A rekeying event occurred.
    Rekeyed {
        /// The new Sender Key epoch.
        new_epoch: u64,
        /// The admin who triggered it.
        triggered_by: PeerId,
        /// When rekeying occurred.
        timestamp: u64,
        /// Reason for rekeying.
        reason: RekeyReason,
    },
}

/// Why a rekeying was triggered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RekeyReason {
    /// Scheduled interval expired.
    Scheduled,
    /// A member was removed.
    MemberRemoved,
    /// An admin manually triggered rekeying.
    ManualTrigger,
    /// The superset ring model forced a rekey
    /// (second removal before first rekey completed).
    ForcedBySuperset,
    /// Automatic timeout (24h after first removal without rekey).
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
pub struct PromotionVote {
    /// The member being promoted.
    pub candidate: PeerId,

    /// The admin who proposed the promotion.
    pub proposed_by: PeerId,

    /// When the proposal was made (Unix timestamp).
    pub proposed_at: u64,

    /// Rejection votes received (only from eligible admins).
    pub rejections: Vec<PeerId>,

    /// Total number of admins at the time of proposal.
    /// Used to compute threshold.
    pub total_admins: usize,

    /// The rejection threshold (fraction).
    pub threshold: f32,

    /// The set of admins eligible to cast rejection votes.
    ///
    /// Populated at proposal time from the current admin list.
    /// `reject()` will silently ignore any voter not in this set,
    /// preventing non-admin or fabricated PeerIds from counting.
    pub eligible_voters: Vec<PeerId>,
}

impl PromotionVote {
    /// Create a new promotion vote.
    ///
    /// `eligible_voters` is the current admin list at proposal time —
    /// only these PeerIds are allowed to cast rejection votes.
    pub fn new(
        candidate: PeerId,
        proposed_by: PeerId,
        total_admins: usize,
        eligible_voters: Vec<PeerId>,
        now: u64,
    ) -> Self {
        Self {
            candidate,
            proposed_by,
            proposed_at: now,
            rejections: Vec::new(),
            total_admins,
            threshold: DEFAULT_REJECTION_THRESHOLD,
            eligible_voters,
        }
    }

    /// Record a rejection vote from `voter`.
    ///
    /// Returns true if the threshold has been met (promotion blocked).
    /// Silently ignores votes from peers not in `eligible_voters` —
    /// only admins present at proposal time may reject.
    pub fn reject(&mut self, voter: PeerId) -> bool {
        if !self.eligible_voters.contains(&voter) {
            // Voter is not an eligible admin — ignore.
            return self.is_rejected();
        }
        if !self.rejections.contains(&voter) {
            self.rejections.push(voter);
        }
        self.is_rejected()
    }

    /// Whether the rejection threshold has been met.
    pub fn is_rejected(&self) -> bool {
        let required = (self.total_admins as f32 * self.threshold).ceil() as usize;
        self.rejections.len() >= required
    }

    /// Whether the voting window has expired.
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.proposed_at) > VOTE_TO_REJECT_WINDOW_SECS
    }

    /// Whether the promotion should be confirmed.
    ///
    /// Confirmed if the voting window has expired AND the
    /// rejection threshold was NOT met.
    pub fn is_confirmed(&self, now: u64) -> bool {
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
pub struct MembershipManager {
    /// Current member list.
    pub members: Vec<MemberInfo>,

    /// Event log of all membership changes.
    pub events: Vec<MembershipEvent>,

    /// Pending admin promotion votes.
    pub pending_promotions: Vec<PromotionVote>,
}

impl MembershipManager {
    /// Create a new membership manager for a group.
    ///
    /// `creator`: the group creator's peer ID.
    /// `epoch`: the initial Sender Key epoch.
    /// `now`: current unix timestamp.
    pub fn new(creator: PeerId, epoch: u64, now: u64) -> Self {
        let creator_info = MemberInfo {
            peer_id: creator,
            role: MemberRole::Admin,
            joined_at: now,
            added_by: None,
            joined_epoch: epoch,
            current_epoch_ack: true,
        };

        Self {
            members: vec![creator_info],
            events: Vec::new(),
            pending_promotions: Vec::new(),
        }
    }

    /// Add a member to the group.
    ///
    /// Only admins can add members. Returns an error if:
    /// - The actor is not an admin
    /// - The member is already in the group
    /// - The group is full
    pub fn add_member(
        &mut self,
        member: PeerId,
        added_by: PeerId,
        epoch: u64,
        now: u64,
    ) -> Result<(), MembershipError> {
        // Check that the actor is an admin.
        if !self.is_admin(&added_by) {
            return Err(MembershipError::NotAdmin);
        }

        // Check for duplicate.
        if self.is_member(&member) {
            return Err(MembershipError::AlreadyMember);
        }

        // Check capacity.
        if self.members.len() >= super::group::MAX_GROUP_MEMBERS {
            return Err(MembershipError::GroupFull);
        }

        // Add the member.
        self.members.push(MemberInfo {
            peer_id: member,
            role: MemberRole::Member,
            joined_at: now,
            added_by: Some(added_by),
            joined_epoch: epoch,
            current_epoch_ack: true,
        });

        // Record the event.
        self.events.push(MembershipEvent::MemberAdded {
            member,
            added_by,
            timestamp: now,
        });

        Ok(())
    }

    /// Remove a member from the group.
    ///
    /// Only admins can remove members, and they cannot remove
    /// other admins (admin removal requires a different process).
    ///
    /// Returns true if a rekey is needed (always true after removal).
    pub fn remove_member(
        &mut self,
        member: PeerId,
        removed_by: PeerId,
        now: u64,
    ) -> Result<bool, MembershipError> {
        // Check that the actor is an admin.
        if !self.is_admin(&removed_by) {
            return Err(MembershipError::NotAdmin);
        }

        // Check that the target is a member.
        if !self.is_member(&member) {
            return Err(MembershipError::NotMember);
        }

        // Cannot remove admins this way.
        if self.is_admin(&member) {
            return Err(MembershipError::CannotRemoveAdmin);
        }

        // Remove the member.
        self.members.retain(|m| m.peer_id != member);

        // Record the event.
        self.events.push(MembershipEvent::MemberRemoved {
            member,
            removed_by,
            timestamp: now,
        });

        // Rekeying is always needed after removal.
        Ok(true)
    }

    /// A member leaves voluntarily.
    ///
    /// Returns true if a rekey is needed (always true after a leave).
    pub fn member_leave(
        &mut self,
        member: PeerId,
        now: u64,
    ) -> Result<bool, MembershipError> {
        if !self.is_member(&member) {
            return Err(MembershipError::NotMember);
        }

        self.members.retain(|m| m.peer_id != member);

        self.events.push(MembershipEvent::MemberLeft {
            member,
            timestamp: now,
        });

        Ok(true)
    }

    /// Propose an admin promotion.
    ///
    /// Starts the vote-to-reject process. Other admins have
    /// VOTE_TO_REJECT_WINDOW_SECS to reject. If no rejection
    /// threshold is met, the promotion is confirmed.
    pub fn propose_promotion(
        &mut self,
        candidate: PeerId,
        proposed_by: PeerId,
        now: u64,
    ) -> Result<(), MembershipError> {
        if !self.is_admin(&proposed_by) {
            return Err(MembershipError::NotAdmin);
        }

        if !self.is_member(&candidate) {
            return Err(MembershipError::NotMember);
        }

        if self.is_admin(&candidate) {
            return Err(MembershipError::AlreadyAdmin);
        }

        let admin_count = self.admin_count();
        let eligible: Vec<PeerId> = self.members.iter()
            .filter(|m| m.role == MemberRole::Admin)
            .map(|m| m.peer_id)
            .collect();
        let vote = PromotionVote::new(candidate, proposed_by, admin_count, eligible, now);
        self.pending_promotions.push(vote);

        Ok(())
    }

    /// Confirm a pending promotion (after vote window expires).
    pub fn confirm_promotion(
        &mut self,
        candidate: &PeerId,
        now: u64,
    ) -> Result<(), MembershipError> {
        // Find the pending promotion.
        let vote_idx = self
            .pending_promotions
            .iter()
            .position(|v| v.candidate == *candidate);

        let idx = match vote_idx {
            Some(i) => i,
            None => return Err(MembershipError::NoPendingPromotion),
        };

        let vote = &self.pending_promotions[idx];

        // Check if confirmed (window expired and not rejected).
        if !vote.is_confirmed(now) {
            if vote.is_rejected() {
                self.pending_promotions.remove(idx);
                return Err(MembershipError::PromotionRejected);
            }
            return Err(MembershipError::VoteWindowOpen);
        }

        let proposed_by = vote.proposed_by;
        self.pending_promotions.remove(idx);

        // Promote the member.
        if let Some(member) = self.members.iter_mut().find(|m| m.peer_id == *candidate) {
            member.role = MemberRole::Admin;
        }

        self.events.push(MembershipEvent::AdminPromoted {
            member: *candidate,
            promoted_by: proposed_by,
            timestamp: now,
        });

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Whether a peer is a member.
    pub fn is_member(&self, peer_id: &PeerId) -> bool {
        self.members.iter().any(|m| m.peer_id == *peer_id)
    }

    /// Whether a peer is an admin.
    pub fn is_admin(&self, peer_id: &PeerId) -> bool {
        self.members
            .iter()
            .any(|m| m.peer_id == *peer_id && m.role == MemberRole::Admin)
    }

    /// Number of members.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Number of admins.
    pub fn admin_count(&self) -> usize {
        self.members
            .iter()
            .filter(|m| m.role == MemberRole::Admin)
            .count()
    }

    /// Get all member peer IDs.
    pub fn member_ids(&self) -> Vec<PeerId> {
        self.members.iter().map(|m| m.peer_id).collect()
    }

    /// Get all admin peer IDs.
    pub fn admin_ids(&self) -> Vec<PeerId> {
        self.members
            .iter()
            .filter(|m| m.role == MemberRole::Admin)
            .map(|m| m.peer_id)
            .collect()
    }
}

/// Errors from membership operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipError {
    /// The actor is not an admin.
    NotAdmin,
    /// The target is already a member.
    AlreadyMember,
    /// The target is not a member.
    NotMember,
    /// The group is at capacity.
    GroupFull,
    /// Cannot remove an admin this way.
    CannotRemoveAdmin,
    /// The target is already an admin.
    AlreadyAdmin,
    /// No pending promotion for this candidate.
    NoPendingPromotion,
    /// The promotion was rejected by admin vote.
    PromotionRejected,
    /// The vote window is still open.
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
        mgr.members.iter_mut().find(|m| m.peer_id == pid(0x02)).unwrap().role = MemberRole::Admin;
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
            mgr.pending_promotions[0].rejections.len(), 0,
            "ineligible rejector must not count"
        );

        // Promotion should still confirm after the window.
        let after_window = 1003 + VOTE_TO_REJECT_WINDOW_SECS + 1;
        let result = mgr.confirm_promotion(&pid(0x03), after_window);
        assert!(result.is_ok(), "ineligible rejections must not block promotion");
        assert!(mgr.is_admin(&pid(0x03)));
    }

    #[test]
    fn test_event_log() {
        let mut mgr = MembershipManager::new(pid(0x01), 1, 1000);

        mgr.add_member(pid(0x02), pid(0x01), 1, 1001).unwrap();
        mgr.remove_member(pid(0x02), pid(0x01), 1002).unwrap();

        assert_eq!(mgr.events.len(), 2);
        assert!(matches!(mgr.events[0], MembershipEvent::MemberAdded { .. }));
        assert!(matches!(mgr.events[1], MembershipEvent::MemberRemoved { .. }));
    }
}
