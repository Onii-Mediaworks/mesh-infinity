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
pub enum TrustState {
    /// Normal operation — no negative markers.
    Normal,

    /// Self-declared compromise. Recoverable.
    /// Triggered by: killswitch, dead man's switch, remote wipe.
    SelfDisavowed {
        /// When the Self-Disavowed announcement was received.
        timestamp: u64,
    },

    /// Friend-declared compromise (local state only — never broadcast).
    /// Requires InnerCircle (Level 8) votes.
    FriendDisavowed {
        /// Number of verified InnerCircle votes received.
        vote_count: u32,
        /// The peer's published threshold at time of first vote.
        threshold: u32,
        /// When the first vote was received.
        first_vote_at: u64,
    },

    /// Permanently compromised — one-way door.
    /// Requires BOTH Self-Disavowed AND Friend-Disavowed threshold met.
    Compromised {
        /// When Compromised state was determined locally.
        timestamp: u64,
    },
}

/// A Friend-Disavowed vote from an InnerCircle peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriendDisavowedVote {
    /// Peer being flagged.
    pub target_peer_id: PeerId,
    /// Peer casting the vote.
    pub voter_peer_id: PeerId,
    /// Threshold known at time of vote.
    pub known_threshold: u8,
    /// When the vote was cast.
    pub timestamp: u64,
    /// Ed25519 signature by voter's relationship-specific mask key.
    pub signature: Vec<u8>,
}

/// State machine for managing trust state transitions.
pub struct TrustStateMachine {
    /// Current state.
    pub state: TrustState,
    /// The peer's published friend_disavow_threshold.
    pub threshold: u32,
    /// Accumulated votes (for Friend-Disavowed counting).
    pub votes: Vec<FriendDisavowedVote>,
    /// Whether Self-Disavowed has been received.
    pub self_disavowed: bool,
}

impl TrustStateMachine {
    /// Create a new state machine in Normal state.
    pub fn new(threshold: u32) -> Self {
        Self {
            state: TrustState::Normal,
            threshold,
            votes: Vec::new(),
            self_disavowed: false,
        }
    }

    /// Process a Self-Disavowed announcement.
    pub fn receive_self_disavowed(&mut self, timestamp: u64) {
        self.self_disavowed = true;

        match &self.state {
            TrustState::Normal => {
                self.state = TrustState::SelfDisavowed { timestamp };
            }
            TrustState::FriendDisavowed { vote_count, threshold, .. } => {
                // Check if both conditions now met → Compromised
                if *vote_count >= *threshold {
                    self.state = TrustState::Compromised { timestamp };
                } else {
                    self.state = TrustState::SelfDisavowed { timestamp };
                }
            }
            TrustState::SelfDisavowed { .. } => {
                // Already self-disavowed — update timestamp
                self.state = TrustState::SelfDisavowed { timestamp };
            }
            TrustState::Compromised { .. } => {
                // One-way door — cannot leave Compromised
            }
        }

        self.check_compromised(timestamp);
    }

    /// Process a Friend-Disavowed vote.
    pub fn receive_friend_disavowed_vote(&mut self, vote: FriendDisavowedVote) {
        if matches!(self.state, TrustState::Compromised { .. }) {
            return; // One-way door — already compromised
        }

        let now = vote.timestamp;
        self.votes.push(vote);
        let vote_count = self.votes.len() as u32;

        match &self.state {
            TrustState::Normal | TrustState::SelfDisavowed { .. } => {
                if vote_count >= self.threshold {
                    self.state = TrustState::FriendDisavowed {
                        vote_count,
                        threshold: self.threshold,
                        first_vote_at: self.votes.first().map(|v| v.timestamp).unwrap_or(now),
                    };
                }
            }
            TrustState::FriendDisavowed { .. } => {
                // Update vote count
                self.state = TrustState::FriendDisavowed {
                    vote_count,
                    threshold: self.threshold,
                    first_vote_at: self.votes.first().map(|v| v.timestamp).unwrap_or(now),
                };
            }
            TrustState::Compromised { .. } => {}
        }

        self.check_compromised(now);
    }

    /// Check if both conditions for Compromised are met.
    fn check_compromised(&mut self, now: u64) {
        if matches!(self.state, TrustState::Compromised { .. }) {
            return;
        }

        let is_self_disavowed = self.self_disavowed;
        let vote_count = self.votes.len() as u32;
        let threshold_met = vote_count >= self.threshold;

        if is_self_disavowed && threshold_met {
            self.state = TrustState::Compromised { timestamp: now };
        }
    }

    /// Clear Self-Disavowed state (recovery).
    /// Only works if not already Compromised.
    pub fn clear_self_disavowed(&mut self) -> bool {
        match &self.state {
            TrustState::SelfDisavowed { .. } => {
                self.self_disavowed = false;
                self.state = if self.votes.len() as u32 >= self.threshold {
                    TrustState::FriendDisavowed {
                        vote_count: self.votes.len() as u32,
                        threshold: self.threshold,
                        first_vote_at: self.votes.first().map(|v| v.timestamp).unwrap_or(0),
                    }
                } else {
                    TrustState::Normal
                };
                true
            }
            TrustState::Compromised { .. } => false, // One-way door
            _ => {
                self.self_disavowed = false;
                true
            }
        }
    }

    /// Check if the peer is in a negative trust state.
    pub fn is_negative(&self) -> bool {
        !matches!(self.state, TrustState::Normal)
    }

    /// Check if the peer is permanently compromised.
    pub fn is_compromised(&self) -> bool {
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
        assert!(matches!(sm.state, TrustState::SelfDisavowed { timestamp: 100 }));
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

        assert!(matches!(sm.state, TrustState::FriendDisavowed { vote_count: 2, .. }));
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
