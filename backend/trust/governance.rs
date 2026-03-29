//! Group Governance (§8.10)
//!
//! # Governance Model
//!
//! Default-allow: abstain = approval. Actions proceed unless
//! the rejection threshold is met. This prevents a minority
//! from blocking legitimate operations.
//!
//! # Quorum Thresholds (§8.10)
//!
//! - **Standard quorum (51%)**: admin promotion, all degraded-mode
//!   actions. Calculated over non-admin members.
//! - **Supermajority (67%)**: removing an admin. No exceptions.
//!   Calculated over non-admin members.
//! - **All-admin groups**: admin quorum = 51% of admins.
//!
//! # Admin-Heavy Threshold
//!
//! When admins exceed 50% of total membership, high-risk admin
//! actions additionally require admin quorum (51% of admins).
//! This is configurable per group.

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard quorum threshold (51% of non-admin members).
pub const STANDARD_QUORUM: f32 = 0.51;

/// Supermajority threshold (67% of non-admin members).
/// Required for removing an admin. No exceptions.
pub const SUPERMAJORITY_QUORUM: f32 = 0.67;

/// Admin-heavy threshold. When admins exceed this fraction of
/// total membership, admin quorum is additionally required.
pub const ADMIN_HEAVY_THRESHOLD: f32 = 0.50;

/// Admin quorum (51% of admins) for admin-heavy groups.
pub const ADMIN_QUORUM: f32 = 0.51;

// ---------------------------------------------------------------------------
// Governance Action
// ---------------------------------------------------------------------------

/// Actions that require governance approval (§8.10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceAction {
    /// Promote a member to admin. Standard quorum.
    PromoteAdmin { candidate: PeerId },

    /// Remove an admin. Supermajority required.
    RemoveAdmin { target: PeerId },

    /// Change the group's network type (e.g., Private → Open).
    /// Security increase: admin or standard quorum.
    /// Security decrease: admin AND standard quorum.
    ChangeNetworkType {
        from: super::super::groups::group::NetworkType,
        to: super::super::groups::group::NetworkType,
    },

    /// Change group settings (name, description, etc.).
    /// Standard quorum.
    ChangeSettings,

    /// Force a rekeying event. Admin only.
    ForceRekey,
}

impl GovernanceAction {
    /// What quorum threshold this action requires.
    pub fn required_quorum(&self) -> f32 {
        match self {
            Self::RemoveAdmin { .. } => SUPERMAJORITY_QUORUM,
            _ => STANDARD_QUORUM,
        }
    }

    /// Whether this action requires admin initiation.
    pub fn requires_admin(&self) -> bool {
        matches!(
            self,
            Self::PromoteAdmin { .. }
                | Self::RemoveAdmin { .. }
                | Self::ChangeNetworkType { .. }
                | Self::ChangeSettings
                | Self::ForceRekey
        )
    }
}

// ---------------------------------------------------------------------------
// Governance Vote
// ---------------------------------------------------------------------------

/// A vote on a governance action (§8.10).
///
/// The model is vote-to-reject (default allow). Members who don't
/// vote are counted as approving. Only explicit rejection votes
/// are collected.
#[derive(Clone, Debug)]
pub struct GovernanceVote {
    /// The action being voted on.
    pub action: GovernanceAction,

    /// Who proposed the action.
    pub proposed_by: PeerId,

    /// When the vote was proposed.
    pub proposed_at: u64,

    /// Rejection votes received (only from eligible voters).
    pub rejections: Vec<PeerId>,

    /// Number of eligible voters (non-admin members for standard,
    /// all admins for admin-only groups).
    pub eligible_voters: usize,

    /// The authoritative set of eligible voter PeerIds.
    ///
    /// Populated at vote-creation time from the current member/admin list.
    /// `reject()` silently ignores any PeerId not in this set, preventing
    /// non-members and fabricated identities from blocking governance actions.
    pub eligible_voter_ids: Vec<PeerId>,

    /// The required rejection threshold.
    pub threshold: f32,

    /// Whether the voting window has been manually closed.
    pub closed: bool,
}

impl GovernanceVote {
    /// Create a new governance vote.
    ///
    /// `eligible_voter_ids` must contain the complete list of PeerIds
    /// allowed to cast rejection votes.  `eligible_voters` is kept for
    /// the threshold denominator (may be larger than `eligible_voter_ids`
    /// if some members are unreachable and excluded from the id list).
    pub fn new(
        action: GovernanceAction,
        proposed_by: PeerId,
        eligible_voters: usize,
        eligible_voter_ids: Vec<PeerId>,
        now: u64,
    ) -> Self {
        let threshold = action.required_quorum();
        Self {
            action,
            proposed_by,
            proposed_at: now,
            rejections: Vec::new(),
            eligible_voters,
            eligible_voter_ids,
            threshold,
            closed: false,
        }
    }

    /// Cast a rejection vote from `voter`.
    ///
    /// Returns true if the rejection threshold has been met
    /// (the action is blocked).
    /// Silently ignores votes from peers not in `eligible_voter_ids` —
    /// non-members and fabricated identities cannot block governance actions.
    pub fn reject(&mut self, voter: PeerId) -> bool {
        if !self.eligible_voter_ids.contains(&voter) {
            // Not an eligible voter — discard.
            return self.is_rejected();
        }
        if !self.rejections.contains(&voter) {
            self.rejections.push(voter);
        }
        self.is_rejected()
    }

    /// Whether the rejection threshold has been met.
    pub fn is_rejected(&self) -> bool {
        if self.eligible_voters == 0 {
            return false;
        }
        let required = (self.eligible_voters as f32 * self.threshold).ceil() as usize;
        self.rejections.len() >= required
    }

    /// Whether the action should proceed (not rejected).
    pub fn is_approved(&self) -> bool {
        !self.is_rejected()
    }

    /// Check if the admin-heavy rule applies.
    ///
    /// `admin_count`: number of admins in the group.
    /// `total_members`: total membership count.
    ///
    /// Returns true if admins exceed ADMIN_HEAVY_THRESHOLD of
    /// total membership, meaning admin quorum is also required.
    pub fn admin_heavy_check(admin_count: usize, total_members: usize) -> bool {
        if total_members == 0 {
            return false;
        }
        (admin_count as f32 / total_members as f32) > ADMIN_HEAVY_THRESHOLD
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn test_standard_quorum() {
        // Eligible voters: pid(10)..pid(15) and pid(16) — 7 voters covering the
        // 6 needed for a 51% quorum of 10.
        let eligible: Vec<PeerId> = (10u8..=16).map(pid).collect();
        let mut vote = GovernanceVote::new(
            GovernanceAction::PromoteAdmin { candidate: pid(0x05) },
            pid(0x01),
            10, // 10 eligible voters
            eligible,
            1000,
        );

        // Standard quorum = 51% of 10 = ceil(5.1) = 6 rejections needed.
        for i in 0..5 {
            assert!(!vote.reject(pid(i + 10)));
        }
        // 5 rejections: not yet.
        assert!(vote.is_approved());

        // 6th rejection: blocked.
        assert!(vote.reject(pid(16)));
        assert!(vote.is_rejected());
        assert!(!vote.is_approved());
    }

    #[test]
    fn test_supermajority_for_admin_removal() {
        let action = GovernanceAction::RemoveAdmin { target: pid(0x02) };
        assert_eq!(action.required_quorum(), SUPERMAJORITY_QUORUM);

        // Eligible voters: pid(10)..pid(17) (8 voters, threshold ceil(10*0.67)=7).
        let eligible: Vec<PeerId> = (10u8..=17).map(pid).collect();
        let mut vote = GovernanceVote::new(action, pid(0x01), 10, eligible, 1000);

        // Supermajority = 67% of 10 = ceil(6.7) = 7 rejections needed.
        for i in 0..6 {
            assert!(!vote.reject(pid(i + 10)));
        }
        assert!(vote.is_approved());

        // 7th rejection: blocked.
        assert!(vote.reject(pid(17)));
        assert!(vote.is_rejected());
    }

    #[test]
    fn test_admin_heavy_detection() {
        // 3 admins out of 5 members = 60% > 50% threshold.
        assert!(GovernanceVote::admin_heavy_check(3, 5));

        // 2 admins out of 5 = 40% ≤ 50%.
        assert!(!GovernanceVote::admin_heavy_check(2, 5));

        // Edge: exactly 50%.
        assert!(!GovernanceVote::admin_heavy_check(5, 10));
    }

    #[test]
    fn test_duplicate_rejection_idempotent() {
        let mut vote = GovernanceVote::new(
            GovernanceAction::ChangeSettings,
            pid(0x01),
            3,
            vec![pid(0x10), pid(0x11), pid(0x12)],
            1000,
        );

        // Same voter twice — should only count once.
        vote.reject(pid(0x10));
        vote.reject(pid(0x10));

        assert_eq!(vote.rejections.len(), 1);
    }

    #[test]
    fn test_ineligible_voter_rejected() {
        // Only pid(0x10) and pid(0x11) are eligible.
        let mut vote = GovernanceVote::new(
            GovernanceAction::ChangeSettings,
            pid(0x01),
            2,
            vec![pid(0x10), pid(0x11)],
            1000,
        );

        // pid(0xFF) is NOT in the eligible list — must not count.
        vote.reject(pid(0xFF));
        assert_eq!(vote.rejections.len(), 0, "ineligible voter must not count");
        assert!(vote.is_approved(), "ineligible rejections must not block the action");

        // Eligible voter still works.
        vote.reject(pid(0x10));
        assert_eq!(vote.rejections.len(), 1);
    }

    #[test]
    fn test_actions_require_admin() {
        assert!(GovernanceAction::ForceRekey.requires_admin());
        assert!(GovernanceAction::ChangeSettings.requires_admin());
        assert!(
            GovernanceAction::PromoteAdmin { candidate: pid(0x01) }.requires_admin()
        );
    }
}
