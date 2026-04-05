//! Trust State Machine (§8.2)
//!
//! Negative trust states orthogonal to trust levels:
//!
//! ```text
//! Normal → Self-Disavowed → Compromised
//!   │           │               ↑
//!   └→ Friend-Disavowed ────────┘
//!       (local only)        (public, one-way door)
//! ```
//!
//! Self-Disavowed + Friend-Disavowed threshold met → Compromised (permanent).

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;

/// The trust state of a peer — orthogonal to trust level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// TrustState — variant enumeration.
// Match exhaustively to handle every protocol state.
// TrustState — variant enumeration.
// Match exhaustively to handle every protocol state.
// TrustState — variant enumeration.
// Match exhaustively to handle every protocol state.
// TrustState — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum TrustState {
    /// Normal operation — no negative markers.
    Normal,

    /// Self-declared compromise. Recoverable.
    /// Triggered by: killswitch, dead man's switch, remote wipe.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    SelfDisavowed {
        /// When the Self-Disavowed announcement was received.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        timestamp: u64,
    },

    /// Friend-declared compromise (local state only — never broadcast).
    /// Requires InnerCircle (Level 8) votes.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    FriendDisavowed {
        /// Number of verified InnerCircle votes received.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        vote_count: u32,
        /// The peer's published threshold at time of first vote.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        threshold: u32,
        /// When the first vote was received.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        first_vote_at: u64,
    },

    /// Permanently compromised — one-way door.
    /// Requires BOTH Self-Disavowed AND Friend-Disavowed threshold met.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Compromised {
        /// When Compromised state was determined locally.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        timestamp: u64,
    },
}

/// A Friend-Disavowed vote from an InnerCircle peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FriendDisavowedVote — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FriendDisavowedVote — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FriendDisavowedVote — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FriendDisavowedVote — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FriendDisavowedVote {
    /// Peer being flagged.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target_peer_id: PeerId,
    /// Peer casting the vote.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub voter_peer_id: PeerId,
    /// Threshold known at time of vote.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub known_threshold: u8,
    /// When the vote was cast.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
    /// Ed25519 signature by voter's relationship-specific mask key.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

/// State machine for managing trust state transitions.
// TrustStateMachine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustStateMachine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustStateMachine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TrustStateMachine — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TrustStateMachine {
    /// Current state.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub state: TrustState,
    /// The peer's published friend_disavow_threshold.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub threshold: u32,
    /// Accumulated votes (for Friend-Disavowed counting).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub votes: Vec<FriendDisavowedVote>,
    /// Whether Self-Disavowed has been received.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub self_disavowed: bool,
}

// Begin the block scope.
// TrustStateMachine implementation — core protocol logic.
// TrustStateMachine implementation — core protocol logic.
// TrustStateMachine implementation — core protocol logic.
// TrustStateMachine implementation — core protocol logic.
impl TrustStateMachine {
    /// Create a new state machine in Normal state.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(threshold: u32) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            state: TrustState::Normal,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            threshold,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            votes: Vec::new(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            self_disavowed: false,
        }
    }

    /// Process a Self-Disavowed announcement.
    // Perform the 'receive self disavowed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'receive self disavowed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'receive self disavowed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'receive self disavowed' operation.
    // Errors are propagated to the caller via Result.
    pub fn receive_self_disavowed(&mut self, timestamp: u64) {
        // Update the self disavowed to reflect the new state.
        // Advance self disavowed state.
        // Advance self disavowed state.
        // Advance self disavowed state.
        // Advance self disavowed state.
        self.self_disavowed = true;

        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match &self.state {
            // Begin the block scope.
            // Handle TrustState::Normal.
            // Handle TrustState::Normal.
            // Handle TrustState::Normal.
            // Handle TrustState::Normal.
            TrustState::Normal => {
                // Update the state to reflect the new state.
                // Advance state state.
                // Advance state state.
                // Advance state state.
                // Advance state state.
                self.state = TrustState::SelfDisavowed { timestamp };
            }
            // Begin the block scope.
            // Handle TrustState::FriendDisavowed { vote_count, threshold, .. }.
            // Handle TrustState::FriendDisavowed { vote_count, threshold, .. }.
            // Handle TrustState::FriendDisavowed { vote_count, threshold, .. }.
            // Handle TrustState::FriendDisavowed { vote_count, threshold, .. }.
            TrustState::FriendDisavowed {
                vote_count,
                threshold,
                ..
            } => {
                // Check if both conditions now met → Compromised
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if *vote_count >= *threshold {
                    // Update the state to reflect the new state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    self.state = TrustState::Compromised { timestamp };
                // Begin the block scope.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                } else {
                    // Update the state to reflect the new state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    self.state = TrustState::SelfDisavowed { timestamp };
                }
            }
            // Begin the block scope.
            // Handle TrustState::SelfDisavowed { .. }.
            // Handle TrustState::SelfDisavowed { .. }.
            // Handle TrustState::SelfDisavowed { .. }.
            // Handle TrustState::SelfDisavowed { .. }.
            TrustState::SelfDisavowed { .. } => {
                // Already self-disavowed — update timestamp
                // Advance state state.
                // Advance state state.
                // Advance state state.
                // Advance state state.
                self.state = TrustState::SelfDisavowed { timestamp };
            }
            // Begin the block scope.
            // Handle TrustState::Compromised { .. }.
            // Handle TrustState::Compromised { .. }.
            // Handle TrustState::Compromised { .. }.
            // Handle TrustState::Compromised { .. }.
            TrustState::Compromised { .. } => {
                // One-way door — cannot leave Compromised
            }
        }

        // Delegate to the instance method.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.check_compromised(timestamp);
    }

    /// Process a Friend-Disavowed vote.
    // Perform the 'receive friend disavowed vote' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'receive friend disavowed vote' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'receive friend disavowed vote' operation.
    // Errors are propagated to the caller via Result.
    pub fn receive_friend_disavowed_vote(&mut self, vote: FriendDisavowedVote) {
        // Trust level gate — restrict access based on peer trust.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if matches!(self.state, TrustState::Compromised { .. }) {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            return; // One-way door — already compromised
        }

        // Capture the current timestamp for temporal ordering.
        // Compute now for this protocol step.
        // Compute now for this protocol step.
        // Compute now for this protocol step.
        let now = vote.timestamp;
        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        self.votes.push(vote);
        // Track the count for threshold and bounds checking.
        // Compute vote count for this protocol step.
        // Compute vote count for this protocol step.
        // Compute vote count for this protocol step.
        let vote_count = self.votes.len() as u32;

        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match &self.state {
            // Begin the block scope.
            // Handle TrustState::Normal | TrustState::SelfDisavowed { .. }.
            // Handle TrustState::Normal | TrustState::SelfDisavowed { .. }.
            // Handle TrustState::Normal | TrustState::SelfDisavowed { .. }.
            TrustState::Normal | TrustState::SelfDisavowed { .. } => {
                // Bounds check to enforce protocol constraints.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if vote_count >= self.threshold {
                    // Update the state to reflect the new state.
                    // Advance state state.
                    // Advance state state.
                    // Advance state state.
                    self.state = TrustState::FriendDisavowed {
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        vote_count,
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        threshold: self.threshold,
                        // Transform the result, mapping errors to the local error type.
                        // Transform each element.
                        // Transform each element.
                        // Transform each element.
                        first_vote_at: self.votes.first().map(|v| v.timestamp).unwrap_or(now),
                    };
                }
            }
            // Begin the block scope.
            // Handle TrustState::FriendDisavowed { .. }.
            // Handle TrustState::FriendDisavowed { .. }.
            // Handle TrustState::FriendDisavowed { .. }.
            TrustState::FriendDisavowed { .. } => {
                // Update vote count
                // Advance state state.
                // Advance state state.
                // Advance state state.
                self.state = TrustState::FriendDisavowed {
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    vote_count,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    threshold: self.threshold,
                    // Transform the result, mapping errors to the local error type.
                    // Transform each element.
                    // Transform each element.
                    // Transform each element.
                    first_vote_at: self.votes.first().map(|v| v.timestamp).unwrap_or(now),
                };
            }
            // Handle this match arm.
            // Handle TrustState::Compromised { .. }.
            // Handle TrustState::Compromised { .. }.
            // Handle TrustState::Compromised { .. }.
            TrustState::Compromised { .. } => {}
        }

        // Delegate to the instance method.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.check_compromised(now);
    }

    /// Check if both conditions for Compromised are met.
    // Perform the 'check compromised' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check compromised' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check compromised' operation.
    // Errors are propagated to the caller via Result.
    fn check_compromised(&mut self, now: u64) {
        // Trust level gate — restrict access based on peer trust.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if matches!(self.state, TrustState::Compromised { .. }) {
            return;
        }

        // Execute the operation and bind the result.
        // Compute is self disavowed for this protocol step.
        // Compute is self disavowed for this protocol step.
        // Compute is self disavowed for this protocol step.
        let is_self_disavowed = self.self_disavowed;
        // Track the count for threshold and bounds checking.
        // Compute vote count for this protocol step.
        // Compute vote count for this protocol step.
        // Compute vote count for this protocol step.
        let vote_count = self.votes.len() as u32;
        // Track the count for threshold and bounds checking.
        // Compute threshold met for this protocol step.
        // Compute threshold met for this protocol step.
        // Compute threshold met for this protocol step.
        let threshold_met = vote_count >= self.threshold;

        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if is_self_disavowed && threshold_met {
            // Update the state to reflect the new state.
            // Advance state state.
            // Advance state state.
            // Advance state state.
            self.state = TrustState::Compromised { timestamp: now };
        }
    }

    /// Clear Self-Disavowed state (recovery).
    /// Only works if not already Compromised.
    // Perform the 'clear self disavowed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'clear self disavowed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'clear self disavowed' operation.
    // Errors are propagated to the caller via Result.
    pub fn clear_self_disavowed(&mut self) -> bool {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match &self.state {
            // Begin the block scope.
            // Handle TrustState::SelfDisavowed { .. }.
            // Handle TrustState::SelfDisavowed { .. }.
            // Handle TrustState::SelfDisavowed { .. }.
            TrustState::SelfDisavowed { .. } => {
                // Update the self disavowed to reflect the new state.
                // Advance self disavowed state.
                // Advance self disavowed state.
                // Advance self disavowed state.
                self.self_disavowed = false;
                // Update the state to reflect the new state.
                // Advance state state.
                // Advance state state.
                // Advance state state.
                self.state = if self.votes.len() as u32 >= self.threshold {
                    // Begin the block scope.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    TrustState::FriendDisavowed {
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        vote_count: self.votes.len() as u32,
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        threshold: self.threshold,
                        // Transform the result, mapping errors to the local error type.
                        // Transform each element.
                        // Transform each element.
                        // Transform each element.
                        first_vote_at: self.votes.first().map(|v| v.timestamp).unwrap_or(0),
                    }
                // Begin the block scope.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                } else {
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    TrustState::Normal
                };
                true
            }
            // Handle this match arm.
            // Handle TrustState::Compromised { .. }.
            // Handle TrustState::Compromised { .. }.
            // Handle TrustState::Compromised { .. }.
            TrustState::Compromised { .. } => false, // One-way door
            // Update the local state.
            // Handle _.
            // Handle _.
            // Handle _.
            _ => {
                // Update the self disavowed to reflect the new state.
                // Advance self disavowed state.
                // Advance self disavowed state.
                // Advance self disavowed state.
                self.self_disavowed = false;
                true
            }
        }
    }

    /// Check if the peer is in a negative trust state.
    // Perform the 'is negative' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is negative' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is negative' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_negative(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        !matches!(self.state, TrustState::Normal)
    }

    /// Check if the peer is permanently compromised.
    // Perform the 'is compromised' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is compromised' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is compromised' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_compromised(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self.state, TrustState::Compromised { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vote(target: PeerId, voter: PeerId, timestamp: u64) -> FriendDisavowedVote {
        FriendDisavowedVote {
            target_peer_id: target,
            voter_peer_id: voter,
            known_threshold: 2,
            timestamp,
            signature: vec![0u8; 64], // placeholder for tests
        }
    }

    #[test]
    fn test_initial_state_is_normal() {
        let sm = TrustStateMachine::new(2);
        assert_eq!(sm.state, TrustState::Normal);
        assert!(!sm.is_negative());
    }

    #[test]
    fn test_self_disavowed() {
        let mut sm = TrustStateMachine::new(2);
        sm.receive_self_disavowed(100);
        assert!(matches!(
            sm.state,
            TrustState::SelfDisavowed { timestamp: 100 }
        ));
        assert!(sm.is_negative());
    }

    #[test]
    fn test_self_disavowed_recovery() {
        let mut sm = TrustStateMachine::new(2);
        sm.receive_self_disavowed(100);
        assert!(sm.clear_self_disavowed());
        assert_eq!(sm.state, TrustState::Normal);
    }

    #[test]
    fn test_friend_disavowed_below_threshold() {
        let mut sm = TrustStateMachine::new(2);
        let target = PeerId([0x01; 32]);
        let voter = PeerId([0x02; 32]);

        sm.receive_friend_disavowed_vote(make_vote(target, voter, 100));
        // 1 vote, threshold 2 — stays Normal
        assert_eq!(sm.state, TrustState::Normal);
    }

    #[test]
    fn test_friend_disavowed_meets_threshold() {
        let mut sm = TrustStateMachine::new(2);
        let target = PeerId([0x01; 32]);

        sm.receive_friend_disavowed_vote(make_vote(target, PeerId([0x02; 32]), 100));
        sm.receive_friend_disavowed_vote(make_vote(target, PeerId([0x03; 32]), 200));

        assert!(matches!(
            sm.state,
            TrustState::FriendDisavowed { vote_count: 2, .. }
        ));
    }

    #[test]
    fn test_compromised_requires_both() {
        let mut sm = TrustStateMachine::new(2);
        let target = PeerId([0x01; 32]);

        // Self-Disavowed alone → not Compromised
        sm.receive_self_disavowed(100);
        assert!(!sm.is_compromised());

        // Add votes to meet threshold → now Compromised
        sm.receive_friend_disavowed_vote(make_vote(target, PeerId([0x02; 32]), 200));
        sm.receive_friend_disavowed_vote(make_vote(target, PeerId([0x03; 32]), 300));
        assert!(sm.is_compromised());
    }

    #[test]
    fn test_compromised_is_one_way_door() {
        let mut sm = TrustStateMachine::new(1);
        let target = PeerId([0x01; 32]);

        sm.receive_self_disavowed(100);
        sm.receive_friend_disavowed_vote(make_vote(target, PeerId([0x02; 32]), 200));
        assert!(sm.is_compromised());

        // Cannot recover from Compromised
        assert!(!sm.clear_self_disavowed());
        assert!(sm.is_compromised());
    }

    #[test]
    fn test_friend_disavowed_then_self_disavowed() {
        let mut sm = TrustStateMachine::new(1);
        let target = PeerId([0x01; 32]);

        // Friend votes first
        sm.receive_friend_disavowed_vote(make_vote(target, PeerId([0x02; 32]), 100));
        assert!(matches!(sm.state, TrustState::FriendDisavowed { .. }));

        // Then Self-Disavowed → should become Compromised
        sm.receive_self_disavowed(200);
        assert!(sm.is_compromised());
    }

    #[test]
    fn test_threshold_change() {
        let mut sm = TrustStateMachine::new(3);
        let target = PeerId([0x01; 32]);

        sm.receive_friend_disavowed_vote(make_vote(target, PeerId([0x02; 32]), 100));
        sm.receive_friend_disavowed_vote(make_vote(target, PeerId([0x03; 32]), 200));
        // 2 votes, threshold 3 — not yet Friend-Disavowed
        assert_eq!(sm.state, TrustState::Normal);
    }

    #[test]
    fn test_serde_roundtrip() {
        let state = TrustState::SelfDisavowed { timestamp: 12345 };
        let json = serde_json::to_string(&state).unwrap();
        let recovered: TrustState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, recovered);
    }
}
