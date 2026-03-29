//! Sender Key Rekeying (§8.7.4, §8.7.5)
//!
//! # What is Rekeying?
//!
//! Rekeying replaces the Sender Key material for a group. After a rekey,
//! old Sender Key state becomes undecryptable — providing forward secrecy
//! at the group level.
//!
//! # Why is Rekeying Needed?
//!
//! Unlike the Double Ratchet (which ratchets forward with every message),
//! Sender Keys do NOT provide forward secrecy within a sending chain.
//! If a member's Sender Key is compromised, all past messages in that
//! chain are readable. Periodic rekeying bounds this window.
//!
//! # Rekeying Triggers (§8.7.5)
//!
//! 1. **Member removal** — immediate rekey per the superset ring model
//! 2. **Scheduled interval** — default 7 days, configurable per group
//! 3. **On-demand** — any admin can trigger at any time
//!
//! # Superset Ring Model (§8.7.4)
//!
//! When a member is removed, there's a window between removal and
//! rekeying completion. During this window:
//!
//! - Content is encrypted for the REDUCED ring (excluding the removed member)
//! - The OUTER envelope still uses the FULL ring (superset) so external
//!   observers see no membership change
//! - The removed member cannot read new content
//!
//! Key rules:
//! - Tolerates exactly ONE pending removal between rekeyings
//! - A SECOND removal before the first rekey completes forces immediate rekeying
//! - Superset ring timeout: 24 hours max — auto-rekey if not completed
//! - Members who missed a rekeying must follow the re-inclusion flow
//!
//! # Re-Inclusion (§8.7.6)
//!
//! When a member has been offline during a rekeying:
//! 1. Member reconnects and detects they can't decrypt current messages
//! 2. Member sends a signed re-inclusion request
//! 3. A trusted member re-shares the current Sender Key state
//! 4. Re-inclusion is NOT automatic — requires active trust decision
//! 5. Grants access to NEW messages only, not messages during absence

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;
use super::membership::RekeyReason;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum time the superset ring can persist (seconds).
/// After 24 hours, automatic forced rekeying is triggered.
pub const SUPERSET_RING_TIMEOUT_SECS: u64 = 24 * 3600;

/// Quorum fraction for non-admin triggered rekeying.
/// If no admin is online after the superset timeout, 51% of
/// non-admin members can trigger a rekey.
pub const REKEY_QUORUM_FRACTION: f32 = 0.51;

// ---------------------------------------------------------------------------
// Rekey State
// ---------------------------------------------------------------------------

/// The rekeying state machine for a group.
///
/// Tracks whether the group is mid-rekey, whether a superset ring
/// is active, and when the next scheduled rekey is due.
#[derive(Clone, Debug)]
pub enum RekeyState {
    /// Normal operation. No pending rekey.
    /// The group is using the current Sender Key epoch.
    Normal {
        /// Current Sender Key epoch.
        epoch: u64,
        /// When the last rekey completed.
        last_rekey_at: u64,
    },

    /// One member has been removed. The superset ring is active.
    /// Content is encrypted for the reduced ring; outer envelope
    /// uses the superset ring.
    ///
    /// A second removal will force immediate rekeying.
    PendingRekey {
        /// Current Sender Key epoch (will increment after rekey).
        epoch: u64,
        /// The removed member's peer ID.
        removed_member: PeerId,
        /// When the removal happened.
        removed_at: u64,
        /// The superset ring (full member set including removed member).
        superset_ring: Vec<PeerId>,
        /// The reduced ring (current member set without removed member).
        reduced_ring: Vec<PeerId>,
    },

    /// Rekeying is in progress. New Sender Key material is being
    /// distributed to all members.
    Rekeying {
        /// The new epoch being established.
        new_epoch: u64,
        /// Members who have acknowledged the new epoch.
        acknowledged: Vec<PeerId>,
        /// Total members who need to acknowledge.
        total_members: usize,
        /// When rekeying started.
        started_at: u64,
        /// Why rekeying was triggered.
        reason: RekeyReason,
    },
}

impl RekeyState {
    /// Create the initial state for a new group.
    pub fn new(now: u64) -> Self {
        Self::Normal {
            epoch: 1,
            last_rekey_at: now,
        }
    }

    /// Get the current epoch.
    pub fn current_epoch(&self) -> u64 {
        match self {
            Self::Normal { epoch, .. } => *epoch,
            Self::PendingRekey { epoch, .. } => *epoch,
            Self::Rekeying { new_epoch, .. } => new_epoch - 1,
        }
    }

    /// Whether a superset ring is currently active.
    pub fn has_superset_ring(&self) -> bool {
        matches!(self, Self::PendingRekey { .. })
    }

    /// Whether rekeying is in progress.
    pub fn is_rekeying(&self) -> bool {
        matches!(self, Self::Rekeying { .. })
    }
}

// ---------------------------------------------------------------------------
// Rekey Manager
// ---------------------------------------------------------------------------

/// Manages the rekeying lifecycle for a group.
///
/// Handles the superset ring model, tracks acknowledgements,
/// and determines when rekeying is complete.
pub struct RekeyManager {
    /// Current rekey state.
    pub state: RekeyState,

    /// Scheduled rekey interval (seconds).
    pub rekey_interval: u64,
}

impl RekeyManager {
    /// Create a new rekey manager.
    pub fn new(rekey_interval: u64, now: u64) -> Self {
        Self {
            state: RekeyState::new(now),
            rekey_interval,
        }
    }

    /// Handle a member removal.
    ///
    /// If this is the first removal since the last rekey, enters
    /// the PendingRekey state (superset ring active).
    ///
    /// If a superset ring is already active (second removal),
    /// forces immediate rekeying.
    ///
    /// Returns the rekey action the caller should take.
    pub fn on_member_removed(
        &mut self,
        removed: PeerId,
        all_members: Vec<PeerId>,
        now: u64,
    ) -> RekeyAction {
        match &self.state {
            RekeyState::Normal { epoch, .. } => {
                // First removal — enter superset ring mode.
                let superset = {
                    let mut ring = all_members.clone();
                    if !ring.contains(&removed) {
                        ring.push(removed);
                    }
                    ring
                };
                let reduced = all_members;

                self.state = RekeyState::PendingRekey {
                    epoch: *epoch,
                    removed_member: removed,
                    removed_at: now,
                    superset_ring: superset,
                    reduced_ring: reduced,
                };

                RekeyAction::SupersetRingActive
            }

            RekeyState::PendingRekey { epoch, .. } => {
                // Second removal before first rekey completed.
                // Force immediate rekeying (§8.7.4).
                let new_epoch = epoch + 1;

                self.state = RekeyState::Rekeying {
                    new_epoch,
                    acknowledged: Vec::new(),
                    total_members: all_members.len(),
                    started_at: now,
                    reason: RekeyReason::ForcedBySuperset,
                };

                RekeyAction::ForceRekey { new_epoch }
            }

            RekeyState::Rekeying { .. } => {
                // Already rekeying — the removal will be handled
                // after the current rekey completes.
                RekeyAction::AlreadyRekeying
            }
        }
    }

    /// Start a scheduled or manual rekey.
    ///
    /// `reason`: why the rekey is being triggered.
    /// `member_count`: total members who need new Sender Key material.
    /// `now`: current unix timestamp.
    pub fn start_rekey(
        &mut self,
        reason: RekeyReason,
        member_count: usize,
        now: u64,
    ) -> u64 {
        let new_epoch = self.state.current_epoch() + 1;

        self.state = RekeyState::Rekeying {
            new_epoch,
            acknowledged: Vec::new(),
            total_members: member_count,
            started_at: now,
            reason,
        };

        new_epoch
    }

    /// Record that a member has acknowledged the new epoch.
    ///
    /// Returns true if all members have acknowledged (rekey complete).
    pub fn acknowledge(&mut self, member: PeerId) -> bool {
        if let RekeyState::Rekeying {
            acknowledged,
            total_members,
            ..
        } = &mut self.state
        {
            if !acknowledged.contains(&member) {
                acknowledged.push(member);
            }
            acknowledged.len() >= *total_members
        } else {
            false
        }
    }

    /// Complete the rekey (all members acknowledged or admin forced).
    ///
    /// Transitions back to Normal state with the new epoch.
    pub fn complete_rekey(&mut self, now: u64) {
        let new_epoch = match &self.state {
            RekeyState::Rekeying { new_epoch, .. } => *new_epoch,
            _ => self.state.current_epoch() + 1,
        };

        self.state = RekeyState::Normal {
            epoch: new_epoch,
            last_rekey_at: now,
        };
    }

    /// Check if a scheduled rekey is due.
    pub fn is_scheduled_rekey_due(&self, now: u64) -> bool {
        if let RekeyState::Normal { last_rekey_at, .. } = &self.state {
            now.saturating_sub(*last_rekey_at) >= self.rekey_interval
        } else {
            false
        }
    }

    /// Check if the superset ring has timed out.
    ///
    /// Returns true if a superset ring has been active for more than
    /// SUPERSET_RING_TIMEOUT_SECS (24 hours). The caller should
    /// trigger automatic forced rekeying.
    pub fn is_superset_timed_out(&self, now: u64) -> bool {
        if let RekeyState::PendingRekey { removed_at, .. } = &self.state {
            now.saturating_sub(*removed_at) >= SUPERSET_RING_TIMEOUT_SECS
        } else {
            false
        }
    }

    /// Get acknowledgement progress.
    ///
    /// Returns (acknowledged, total) or None if not rekeying.
    pub fn progress(&self) -> Option<(usize, usize)> {
        if let RekeyState::Rekeying {
            acknowledged,
            total_members,
            ..
        } = &self.state
        {
            Some((acknowledged.len(), *total_members))
        } else {
            None
        }
    }
}

/// What the caller should do after a rekey-related event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RekeyAction {
    /// Superset ring is now active. Encrypt content for the
    /// reduced ring but use the superset ring for the outer envelope.
    SupersetRingActive,

    /// Immediate forced rekeying required. Distribute new Sender
    /// Key material to all members at the given epoch.
    ForceRekey { new_epoch: u64 },

    /// Already in the middle of a rekey. The removal will be
    /// handled after the current rekey completes.
    AlreadyRekeying,
}

// ---------------------------------------------------------------------------
// Re-Inclusion Request (§8.7.6)
// ---------------------------------------------------------------------------

/// A request from a member who missed one or more rekeying events.
///
/// The member has reconnected and detected they can't decrypt
/// current messages (their Sender Key epoch is behind).
/// A trusted member must manually re-share the current Sender Key
/// state after verifying the requester's identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReInclusionRequest {
    /// The requesting member's peer ID.
    pub peer_id: PeerId,

    /// The epoch the member last had (so we know how far behind they are).
    pub last_known_epoch: u64,

    /// Ed25519 signature proving identity.
    pub signature: Vec<u8>,

    /// Unix timestamp.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::group::DEFAULT_REKEY_INTERVAL_SECS;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn test_initial_state() {
        let mgr = RekeyManager::new(DEFAULT_REKEY_INTERVAL_SECS, 1000);
        assert_eq!(mgr.state.current_epoch(), 1);
        assert!(!mgr.state.has_superset_ring());
        assert!(!mgr.state.is_rekeying());
    }

    #[test]
    fn test_first_removal_superset_ring() {
        let mut mgr = RekeyManager::new(DEFAULT_REKEY_INTERVAL_SECS, 1000);

        let action = mgr.on_member_removed(
            pid(0x03),
            vec![pid(0x01), pid(0x02)], // Remaining members.
            2000,
        );

        assert_eq!(action, RekeyAction::SupersetRingActive);
        assert!(mgr.state.has_superset_ring());
    }

    #[test]
    fn test_second_removal_forces_rekey() {
        let mut mgr = RekeyManager::new(DEFAULT_REKEY_INTERVAL_SECS, 1000);

        // First removal.
        mgr.on_member_removed(
            pid(0x03),
            vec![pid(0x01), pid(0x02)],
            2000,
        );

        // Second removal before rekey — forces immediate rekey.
        let action = mgr.on_member_removed(
            pid(0x02),
            vec![pid(0x01)],
            2001,
        );

        match action {
            RekeyAction::ForceRekey { new_epoch } => {
                assert_eq!(new_epoch, 2);
            }
            _ => panic!("Expected ForceRekey"),
        }
        assert!(mgr.state.is_rekeying());
    }

    #[test]
    fn test_scheduled_rekey() {
        let mut mgr = RekeyManager::new(DEFAULT_REKEY_INTERVAL_SECS, 1000);

        // Not due yet.
        assert!(!mgr.is_scheduled_rekey_due(1000 + 1000));

        // Due after interval.
        assert!(mgr.is_scheduled_rekey_due(1000 + DEFAULT_REKEY_INTERVAL_SECS));

        // Start the rekey.
        let new_epoch = mgr.start_rekey(RekeyReason::Scheduled, 3, 1000 + DEFAULT_REKEY_INTERVAL_SECS);
        assert_eq!(new_epoch, 2);
        assert!(mgr.state.is_rekeying());
    }

    #[test]
    fn test_rekey_acknowledgement() {
        let mut mgr = RekeyManager::new(DEFAULT_REKEY_INTERVAL_SECS, 1000);
        mgr.start_rekey(RekeyReason::ManualTrigger, 3, 2000);

        // Progress: 0/3.
        assert_eq!(mgr.progress(), Some((0, 3)));

        // Acknowledge from two members — not complete.
        assert!(!mgr.acknowledge(pid(0x01)));
        assert!(!mgr.acknowledge(pid(0x02)));
        assert_eq!(mgr.progress(), Some((2, 3)));

        // Third member — complete.
        assert!(mgr.acknowledge(pid(0x03)));
    }

    #[test]
    fn test_complete_rekey() {
        let mut mgr = RekeyManager::new(DEFAULT_REKEY_INTERVAL_SECS, 1000);
        mgr.start_rekey(RekeyReason::ManualTrigger, 2, 2000);

        mgr.acknowledge(pid(0x01));
        mgr.acknowledge(pid(0x02));

        mgr.complete_rekey(2001);

        assert!(!mgr.state.is_rekeying());
        assert_eq!(mgr.state.current_epoch(), 2);
    }

    #[test]
    fn test_superset_timeout() {
        let mut mgr = RekeyManager::new(DEFAULT_REKEY_INTERVAL_SECS, 1000);

        mgr.on_member_removed(
            pid(0x03),
            vec![pid(0x01), pid(0x02)],
            2000,
        );

        // Not timed out yet.
        assert!(!mgr.is_superset_timed_out(2000 + 1000));

        // Timed out after 24 hours.
        assert!(mgr.is_superset_timed_out(2000 + SUPERSET_RING_TIMEOUT_SECS));
    }

    #[test]
    fn test_duplicate_acknowledge() {
        let mut mgr = RekeyManager::new(DEFAULT_REKEY_INTERVAL_SECS, 1000);
        mgr.start_rekey(RekeyReason::ManualTrigger, 2, 2000);

        // Same member acknowledges twice — should be idempotent.
        assert!(!mgr.acknowledge(pid(0x01)));
        assert!(!mgr.acknowledge(pid(0x01)));
        assert_eq!(mgr.progress(), Some((1, 2)));
    }
}
