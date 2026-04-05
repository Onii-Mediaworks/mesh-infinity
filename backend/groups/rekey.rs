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

use super::membership::RekeyReason;
use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum time the superset ring can persist (seconds).
/// After 24 hours, automatic forced rekeying is triggered.
// SUPERSET_RING_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// SUPERSET_RING_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SUPERSET_RING_TIMEOUT_SECS: u64 = 24 * 3600;

/// Quorum fraction for non-admin triggered rekeying.
/// If no admin is online after the superset timeout, 51% of
/// non-admin members can trigger a rekey.
// REKEY_QUORUM_FRACTION — protocol constant.
// Defined by the spec; must not change without a version bump.
// REKEY_QUORUM_FRACTION — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const REKEY_QUORUM_FRACTION: f32 = 0.51;

// ---------------------------------------------------------------------------
// Rekey State
// ---------------------------------------------------------------------------

/// The rekeying state machine for a group.
///
/// Tracks whether the group is mid-rekey, whether a superset ring
/// is active, and when the next scheduled rekey is due.
#[derive(Clone, Debug)]
// Begin the block scope.
// RekeyState — variant enumeration.
// Match exhaustively to handle every protocol state.
// RekeyState — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RekeyState {
    /// Normal operation. No pending rekey.
    /// The group is using the current Sender Key epoch.
    Normal {
        /// Current Sender Key epoch.
        // Execute this protocol step.
        // Execute this protocol step.
        epoch: u64,
        /// When the last rekey completed.
        // Execute this protocol step.
        // Execute this protocol step.
        last_rekey_at: u64,
    },

    /// One member has been removed. The superset ring is active.
    /// Content is encrypted for the reduced ring; outer envelope
    /// uses the superset ring.
    ///
    /// A second removal will force immediate rekeying.
    // Execute this protocol step.
    // Execute this protocol step.
    PendingRekey {
        /// Current Sender Key epoch (will increment after rekey).
        // Execute this protocol step.
        // Execute this protocol step.
        epoch: u64,
        /// The removed member's peer ID.
        // Execute this protocol step.
        // Execute this protocol step.
        removed_member: PeerId,
        /// When the removal happened.
        // Execute this protocol step.
        // Execute this protocol step.
        removed_at: u64,
        /// The superset ring (full member set including removed member).
        // Execute this protocol step.
        // Execute this protocol step.
        superset_ring: Vec<PeerId>,
        /// The reduced ring (current member set without removed member).
        // Execute this protocol step.
        // Execute this protocol step.
        reduced_ring: Vec<PeerId>,
    },

    /// Rekeying is in progress. New Sender Key material is being
    /// distributed to all members.
    // Execute this protocol step.
    // Execute this protocol step.
    Rekeying {
        /// The new epoch being established.
        // Execute this protocol step.
        // Execute this protocol step.
        new_epoch: u64,
        /// Members who have acknowledged the new epoch.
        // Execute this protocol step.
        // Execute this protocol step.
        acknowledged: Vec<PeerId>,
        /// Total members who need to acknowledge.
        // Execute this protocol step.
        // Execute this protocol step.
        total_members: usize,
        /// When rekeying started.
        // Execute this protocol step.
        // Execute this protocol step.
        started_at: u64,
        /// Why rekeying was triggered.
        // Execute this protocol step.
        // Execute this protocol step.
        reason: RekeyReason,
    },
}

// Begin the block scope.
// RekeyState implementation — core protocol logic.
// RekeyState implementation — core protocol logic.
impl RekeyState {
    /// Create the initial state for a new group.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(now: u64) -> Self {
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::Normal {
            // Execute this protocol step.
            // Execute this protocol step.
            epoch: 1,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            last_rekey_at: now,
        }
    }

    /// Get the current epoch.
    // Perform the 'current epoch' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'current epoch' operation.
    // Errors are propagated to the caller via Result.
    pub fn current_epoch(&self) -> u64 {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Handle this match arm.
            // Handle Self::Normal { epoch, .. }.
            // Handle Self::Normal { epoch, .. }.
            Self::Normal { epoch, .. } => *epoch,
            // Handle this match arm.
            // Handle Self::PendingRekey { epoch, .. }.
            // Handle Self::PendingRekey { epoch, .. }.
            Self::PendingRekey { epoch, .. } => *epoch,
            // Handle this match arm.
            // Handle Self::Rekeying { new_epoch, .. }.
            // Handle Self::Rekeying { new_epoch, .. }.
            Self::Rekeying { new_epoch, .. } => new_epoch - 1,
        }
    }

    /// Whether a superset ring is currently active.
    // Perform the 'has superset ring' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'has superset ring' operation.
    // Errors are propagated to the caller via Result.
    pub fn has_superset_ring(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::PendingRekey { .. })
    }

    /// Whether rekeying is in progress.
    // Perform the 'is rekeying' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is rekeying' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_rekeying(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
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
// RekeyManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RekeyManager — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct RekeyManager {
    /// Current rekey state.
    // Execute this protocol step.
    // Execute this protocol step.
    pub state: RekeyState,

    /// Scheduled rekey interval (seconds).
    // Execute this protocol step.
    // Execute this protocol step.
    pub rekey_interval: u64,
}

// Begin the block scope.
// RekeyManager implementation — core protocol logic.
// RekeyManager implementation — core protocol logic.
impl RekeyManager {
    /// Create a new rekey manager.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(rekey_interval: u64, now: u64) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            state: RekeyState::new(now),
            // Execute this protocol step.
            // Execute this protocol step.
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
    // Perform the 'on member removed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'on member removed' operation.
    // Errors are propagated to the caller via Result.
    pub fn on_member_removed(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        removed: PeerId,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        all_members: Vec<PeerId>,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> RekeyAction {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match &self.state {
            // Begin the block scope.
            // Handle RekeyState::Normal { epoch, .. }.
            // Handle RekeyState::Normal { epoch, .. }.
            RekeyState::Normal { epoch, .. } => {
                // First removal — enter superset ring mode.
                // Compute superset for this protocol step.
                // Compute superset for this protocol step.
                let superset = {
                    // Identify the peer for this operation.
                    // Compute ring for this protocol step.
                    // Compute ring for this protocol step.
                    let mut ring = all_members.clone();
                    // Conditional branch based on the current state.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    if !ring.contains(&removed) {
                        // Add the element to the collection.
                        // Append to the collection.
                        // Append to the collection.
                        ring.push(removed);
                    }
                    ring
                };
                // Identify the peer for this operation.
                // Compute reduced for this protocol step.
                // Compute reduced for this protocol step.
                let reduced = all_members;

                // Update the state to reflect the new state.
                // Advance state state.
                // Advance state state.
                self.state = RekeyState::PendingRekey {
                    // Execute this protocol step.
                    // Execute this protocol step.
                    epoch: *epoch,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    removed_member: removed,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    removed_at: now,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    superset_ring: superset,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    reduced_ring: reduced,
                };

                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                RekeyAction::SupersetRingActive
            }

            // Begin the block scope.
            // Handle RekeyState::PendingRekey { epoch, .. }.
            // Handle RekeyState::PendingRekey { epoch, .. }.
            RekeyState::PendingRekey { epoch, .. } => {
                // Second removal before first rekey completed.
                // Force immediate rekeying (§8.7.4).
                // Compute new epoch for this protocol step.
                // Compute new epoch for this protocol step.
                let new_epoch = epoch + 1;

                // Update the state to reflect the new state.
                // Advance state state.
                // Advance state state.
                self.state = RekeyState::Rekeying {
                    // Execute this protocol step.
                    // Execute this protocol step.
                    new_epoch,
                    // Create a new instance with the specified parameters.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    acknowledged: Vec::new(),
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    total_members: all_members.len(),
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    started_at: now,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    reason: RekeyReason::ForcedBySuperset,
                };

                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                RekeyAction::ForceRekey { new_epoch }
            }

            // Begin the block scope.
            // Handle RekeyState::Rekeying { .. }.
            // Handle RekeyState::Rekeying { .. }.
            RekeyState::Rekeying { .. } => {
                // Already rekeying — the removal will be handled
                // after the current rekey completes.
                // Execute this protocol step.
                // Execute this protocol step.
                RekeyAction::AlreadyRekeying
            }
        }
    }

    /// Start a scheduled or manual rekey.
    ///
    /// `reason`: why the rekey is being triggered.
    /// `member_count`: total members who need new Sender Key material.
    /// `now`: current unix timestamp.
    // Perform the 'start rekey' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'start rekey' operation.
    // Errors are propagated to the caller via Result.
    pub fn start_rekey(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        reason: RekeyReason,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        member_count: usize,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> u64 {
        // Execute the operation and bind the result.
        // Compute new epoch for this protocol step.
        // Compute new epoch for this protocol step.
        let new_epoch = self.state.current_epoch() + 1;

        // Update the state to reflect the new state.
        // Advance state state.
        // Advance state state.
        self.state = RekeyState::Rekeying {
            // Execute this protocol step.
            // Execute this protocol step.
            new_epoch,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            acknowledged: Vec::new(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            total_members: member_count,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            started_at: now,
            reason,
        };

        // Execute this protocol step.
        // Execute this protocol step.
        new_epoch
    }

    /// Record that a member has acknowledged the new epoch.
    ///
    /// Returns true if all members have acknowledged (rekey complete).
    // Perform the 'acknowledge' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'acknowledge' operation.
    // Errors are propagated to the caller via Result.
    pub fn acknowledge(&mut self, member: PeerId) -> bool {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let RekeyState::Rekeying {
            // Execute this protocol step.
            // Execute this protocol step.
            acknowledged,
            // Execute this protocol step.
            // Execute this protocol step.
            total_members,
            // Chain the operation on the intermediate result.
            ..
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        } = &mut self.state
        {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !acknowledged.contains(&member) {
                // Execute the operation and bind the result.
                // Append to the collection.
                // Append to the collection.
                acknowledged.push(member);
            }
            // Validate the length matches the expected protocol size.
            // Execute this protocol step.
            // Execute this protocol step.
            acknowledged.len() >= *total_members
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            false
        }
    }

    /// Complete the rekey (all members acknowledged or admin forced).
    ///
    /// Transitions back to Normal state with the new epoch.
    // Perform the 'complete rekey' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'complete rekey' operation.
    // Errors are propagated to the caller via Result.
    pub fn complete_rekey(&mut self, now: u64) {
        // Dispatch based on the variant to apply type-specific logic.
        // Compute new epoch for this protocol step.
        // Compute new epoch for this protocol step.
        let new_epoch = match &self.state {
            // Handle this match arm.
            // Handle RekeyState::Rekeying { new_epoch, .. }.
            // Handle RekeyState::Rekeying { new_epoch, .. }.
            RekeyState::Rekeying { new_epoch, .. } => *new_epoch,
            // Update the local state.
            _ => self.state.current_epoch() + 1,
        };

        // Update the state to reflect the new state.
        // Advance state state.
        // Advance state state.
        self.state = RekeyState::Normal {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            epoch: new_epoch,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            last_rekey_at: now,
        };
    }

    /// Check if a scheduled rekey is due.
    // Perform the 'is scheduled rekey due' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is scheduled rekey due' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_scheduled_rekey_due(&self, now: u64) -> bool {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let RekeyState::Normal { last_rekey_at, .. } = &self.state {
            // Clamp the value to prevent overflow or underflow.
            // Execute this protocol step.
            // Execute this protocol step.
            now.saturating_sub(*last_rekey_at) >= self.rekey_interval
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            false
        }
    }

    /// Check if the superset ring has timed out.
    ///
    /// Returns true if a superset ring has been active for more than
    /// SUPERSET_RING_TIMEOUT_SECS (24 hours). The caller should
    /// trigger automatic forced rekeying.
    // Perform the 'is superset timed out' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is superset timed out' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_superset_timed_out(&self, now: u64) -> bool {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let RekeyState::PendingRekey { removed_at, .. } = &self.state {
            // Clamp the value to prevent overflow or underflow.
            // Execute this protocol step.
            // Execute this protocol step.
            now.saturating_sub(*removed_at) >= SUPERSET_RING_TIMEOUT_SECS
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            false
        }
    }

    /// Get acknowledgement progress.
    ///
    /// Returns (acknowledged, total) or None if not rekeying.
    // Perform the 'progress' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'progress' operation.
    // Errors are propagated to the caller via Result.
    pub fn progress(&self) -> Option<(usize, usize)> {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let RekeyState::Rekeying {
            // Execute this protocol step.
            // Execute this protocol step.
            acknowledged,
            // Execute this protocol step.
            // Execute this protocol step.
            total_members,
            // Chain the operation on the intermediate result.
            ..
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        } = &self.state
        {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some((acknowledged.len(), *total_members))
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // No value available.
            // No value available.
            None
        }
    }
}

/// What the caller should do after a rekey-related event.
#[derive(Clone, Debug, PartialEq, Eq)]
// Begin the block scope.
// RekeyAction — variant enumeration.
// Match exhaustively to handle every protocol state.
// RekeyAction — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RekeyAction {
    /// Superset ring is now active. Encrypt content for the
    /// reduced ring but use the superset ring for the outer envelope.
    // Execute this protocol step.
    // Execute this protocol step.
    SupersetRingActive,

    /// Immediate forced rekeying required. Distribute new Sender
    /// Key material to all members at the given epoch.
    // Execute this protocol step.
    // Execute this protocol step.
    ForceRekey { new_epoch: u64 },

    /// Already in the middle of a rekey. The removal will be
    /// handled after the current rekey completes.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// ReInclusionRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ReInclusionRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ReInclusionRequest {
    /// The requesting member's peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_id: PeerId,

    /// The epoch the member last had (so we know how far behind they are).
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_known_epoch: u64,

    /// Ed25519 signature proving identity.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,

    /// Unix timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::group::DEFAULT_REKEY_INTERVAL_SECS;
    use super::*;

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
        mgr.on_member_removed(pid(0x03), vec![pid(0x01), pid(0x02)], 2000);

        // Second removal before rekey — forces immediate rekey.
        let action = mgr.on_member_removed(pid(0x02), vec![pid(0x01)], 2001);

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
        let new_epoch = mgr.start_rekey(
            RekeyReason::Scheduled,
            3,
            1000 + DEFAULT_REKEY_INTERVAL_SECS,
        );
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

        mgr.on_member_removed(pid(0x03), vec![pid(0x01), pid(0x02)], 2000);

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
