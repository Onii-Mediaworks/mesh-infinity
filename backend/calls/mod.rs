//! Voice and Video Calls (§10.1.6)
//!
//! # Call Architecture
//!
//! Calls use the existing mesh messaging channel for signalling
//! (offer/answer/ICE/hangup) and establish a dedicated WireGuard
//! session for media transport.
//!
//! # Group Call Scaling
//!
//! | Participants | Mode |
//! |-------------|------|
//! | ≤ 4 | Full mesh (every peer connects to every other) |
//! | 5-50 video / 5-100 audio | sqrt(n) relay peers |
//! | Above cap | Degraded mode with quality warning |
//!
//! # Codec Support
//!
//! - Audio: Opus
//! - Video: VP8, VP9, AV1

use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum participants for full-mesh mode.
// FULL_MESH_MAX — protocol constant.
// Defined by the spec; must not change without a version bump.
// FULL_MESH_MAX — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const FULL_MESH_MAX: usize = 4;

/// Maximum video call participants before degraded mode.
// VIDEO_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
// VIDEO_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const VIDEO_CAP: usize = 50;

/// Maximum audio call participants before degraded mode.
// AUDIO_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
// AUDIO_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const AUDIO_CAP: usize = 100;

// ---------------------------------------------------------------------------
// Call Signal
// ---------------------------------------------------------------------------

/// Call signalling message sent over the mesh messaging channel.
///
/// These control call lifecycle. Media flows separately over
/// a dedicated WireGuard session.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// CallSignal — variant enumeration.
// Match exhaustively to handle every protocol state.
// CallSignal — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum CallSignal {
    /// Offer to start a call.
    Offer {
        /// Unique call identifier.
        // Execute this protocol step.
        // Execute this protocol step.
        call_id: [u8; 32],
        /// Offered codecs (audio).
        // Execute this protocol step.
        // Execute this protocol step.
        audio_codecs: Vec<AudioCodec>,
        /// Offered codecs (video). Empty for audio-only.
        // Execute this protocol step.
        // Execute this protocol step.
        video_codecs: Vec<VideoCodec>,
        /// Whether LoSec path is requested.
        // Execute this protocol step.
        // Execute this protocol step.
        losec_requested: bool,
        /// SDP-like session description.
        // Execute this protocol step.
        // Execute this protocol step.
        session_desc: String,
    },

    /// Accept a call offer.
    Answer {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        call_id: [u8; 32],
        /// Selected audio codec.
        // Execute this protocol step.
        // Execute this protocol step.
        audio_codec: AudioCodec,
        /// Selected video codec (None for audio-only).
        // Execute this protocol step.
        // Execute this protocol step.
        video_codec: Option<VideoCodec>,
        /// Whether LoSec was accepted.
        // Execute this protocol step.
        // Execute this protocol step.
        losec_accepted: bool,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        session_desc: String,
    },

    /// ICE candidate for NAT traversal.
    /// Mesh relay (§6.11) is preferred over ICE, but this
    /// is needed for WebRTC interop.
    // Execute this protocol step.
    // Execute this protocol step.
    IceCandidate {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        call_id: [u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        candidate: String,
    },

    /// End the call.
    Hangup {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        call_id: [u8; 32],
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        reason: HangupReason,
    },
}

/// Audio codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// AudioCodec — variant enumeration.
// Match exhaustively to handle every protocol state.
// AudioCodec — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum AudioCodec {
    Opus,
}

/// Video codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// VideoCodec — variant enumeration.
// Match exhaustively to handle every protocol state.
// VideoCodec — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum VideoCodec {
    VP8,
    VP9,
    AV1,
}

/// Why a call ended.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// HangupReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// HangupReason — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum HangupReason {
    /// User hung up normally.
    Normal,
    /// Call was declined.
    // Execute this protocol step.
    // Execute this protocol step.
    Declined,
    /// No answer within timeout.
    Timeout,
    /// Network error.
    // Execute this protocol step.
    // Execute this protocol step.
    NetworkError,
    /// Insufficient bandwidth.
    // Execute this protocol step.
    // Execute this protocol step.
    InsufficientBandwidth,
}

// ---------------------------------------------------------------------------
// Call State
// ---------------------------------------------------------------------------

/// State of an active call.
#[derive(Clone, Debug)]
// Begin the block scope.
// CallState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// CallState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct CallState {
    /// Unique call identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    pub call_id: [u8; 32],

    /// Whether this is a video call.
    // Execute this protocol step.
    // Execute this protocol step.
    pub is_video: bool,

    /// List of participants.
    // Execute this protocol step.
    // Execute this protocol step.
    pub participants: Vec<PeerId>,

    /// Current call mode.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mode: CallMode,

    /// Whether LoSec is active for this call.
    // Execute this protocol step.
    // Execute this protocol step.
    pub losec_active: bool,

    /// Whether push-to-talk is enabled.
    // Execute this protocol step.
    // Execute this protocol step.
    pub push_to_talk: bool,

    /// When the call started.
    // Execute this protocol step.
    // Execute this protocol step.
    pub started_at: u64,

    /// Audio codec in use.
    // Execute this protocol step.
    // Execute this protocol step.
    pub audio_codec: AudioCodec,

    /// Video codec in use (None for audio-only).
    // Execute this protocol step.
    // Execute this protocol step.
    pub video_codec: Option<VideoCodec>,
}

// Begin the block scope.
// CallState implementation — core protocol logic.
// CallState implementation — core protocol logic.
impl CallState {
    /// Create a new outgoing call.
    ///
    /// `call_id`: unique identifier for this call.
    /// `is_video`: whether video is enabled.
    /// `our_peer_id`: our own peer ID.
    /// `now`: current unix timestamp.
    // Perform the 'new outgoing' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new outgoing' operation.
    // Errors are propagated to the caller via Result.
    pub fn new_outgoing(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        call_id: [u8; 32],
        // Execute this protocol step.
        // Execute this protocol step.
        is_video: bool,
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
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            call_id,
            // Execute this protocol step.
            // Execute this protocol step.
            is_video,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            participants: vec![our_peer_id],
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            mode: CallMode::FullMesh,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            losec_active: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            push_to_talk: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            started_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            audio_codec: AudioCodec::Opus,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            video_codec: if is_video {
                Some(VideoCodec::VP9)
            } else {
                None
            },
        }
    }

    /// Add a participant and recalculate the call mode.
    ///
    /// Returns the new call mode. If the mode changed to Degraded,
    /// the UI should show a quality warning.
    // Perform the 'add participant' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add participant' operation.
    // Errors are propagated to the caller via Result.
    pub fn add_participant(&mut self, peer_id: PeerId) -> CallMode {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.participants.contains(&peer_id) {
            // Execute the operation and bind the result.
            // Append to the collection.
            // Append to the collection.
            self.participants.push(peer_id);
        }
        // Update the mode to reflect the new state.
        // Advance mode state.
        // Advance mode state.
        self.mode = select_call_mode(self.participants.len(), self.is_video);
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.mode
    }

    /// Remove a participant and recalculate the call mode.
    // Perform the 'remove participant' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'remove participant' operation.
    // Errors are propagated to the caller via Result.
    pub fn remove_participant(&mut self, peer_id: &PeerId) -> CallMode {
        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.participants.retain(|p| p != peer_id);
        // Update the mode to reflect the new state.
        // Advance mode state.
        // Advance mode state.
        self.mode = select_call_mode(self.participants.len(), self.is_video);
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.mode
    }

    /// Number of participants.
    // Perform the 'participant count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'participant count' operation.
    // Errors are propagated to the caller via Result.
    pub fn participant_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.participants.len()
    }

    /// Number of relay peers needed (for RelayMesh mode).
    // Perform the 'relay count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'relay count' operation.
    // Errors are propagated to the caller via Result.
    pub fn relay_count(&self) -> usize {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.mode == CallMode::RelayMesh {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            relay_peer_count(self.participants.len())
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            0
        }
    }

    /// Whether the call is audio-only.
    // Perform the 'is audio only' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is audio only' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_audio_only(&self) -> bool {
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        !self.is_video
    }

    /// Call duration in seconds.
    // Perform the 'duration secs' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'duration secs' operation.
    // Errors are propagated to the caller via Result.
    pub fn duration_secs(&self, now: u64) -> u64 {
        // Clamp the value to prevent overflow or underflow.
        // Execute this protocol step.
        // Execute this protocol step.
        now.saturating_sub(self.started_at)
    }

    /// Enable or disable video mid-call.
    ///
    /// Recalculates the call mode since video has lower
    /// participant caps.
    // Perform the 'set video' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'set video' operation.
    // Errors are propagated to the caller via Result.
    pub fn set_video(&mut self, enabled: bool) {
        // Update the is video to reflect the new state.
        // Advance is video state.
        // Advance is video state.
        self.is_video = enabled;
        // Update the video codec to reflect the new state.
        // Advance video codec state.
        // Advance video codec state.
        self.video_codec = if enabled { Some(VideoCodec::VP9) } else { None };
        // Update the mode to reflect the new state.
        // Advance mode state.
        // Advance mode state.
        self.mode = select_call_mode(self.participants.len(), self.is_video);
    }
}

/// Call topology mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// CallMode — variant enumeration.
// Match exhaustively to handle every protocol state.
// CallMode — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum CallMode {
    /// Every participant directly connected. ≤ 4 participants.
    // Execute this protocol step.
    FullMesh,
    /// Each node connects to sqrt(n) relay peers. 5-50/100 participants.
    // Execute this protocol step.
    RelayMesh,
    /// Over capacity. Quality warning displayed.
    // Execute this protocol step.
    Degraded,
}

/// Determine the appropriate call mode for a participant count.
// Perform the 'select call mode' operation.
// Errors are propagated to the caller via Result.
pub fn select_call_mode(participants: usize, is_video: bool) -> CallMode {
    // Bounds check to enforce protocol constraints.
    // Guard: validate the condition before proceeding.
    if participants <= FULL_MESH_MAX {
        // Process the current step in the protocol.
        // Execute this protocol step.
        CallMode::FullMesh
    // Begin the block scope.
    // Fallback when the guard was not satisfied.
    } else {
        // Execute the operation and bind the result.
        // Compute cap for this protocol step.
        let cap = if is_video { VIDEO_CAP } else { AUDIO_CAP };
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        if participants <= cap {
            // Process the current step in the protocol.
            // Execute this protocol step.
            CallMode::RelayMesh
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        } else {
            // Process the current step in the protocol.
            // Execute this protocol step.
            CallMode::Degraded
        }
    }
}

/// Number of relay peers each node should connect to in RelayMesh mode.
// Perform the 'relay peer count' operation.
// Errors are propagated to the caller via Result.
pub fn relay_peer_count(participants: usize) -> usize {
    // Process the current step in the protocol.
    // Execute this protocol step.
    (participants as f64).sqrt().ceil() as usize
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_mode_selection() {
        assert_eq!(select_call_mode(2, true), CallMode::FullMesh);
        assert_eq!(select_call_mode(4, true), CallMode::FullMesh);
        assert_eq!(select_call_mode(10, true), CallMode::RelayMesh);
        assert_eq!(select_call_mode(50, true), CallMode::RelayMesh);
        assert_eq!(select_call_mode(51, true), CallMode::Degraded);
        assert_eq!(select_call_mode(100, false), CallMode::RelayMesh);
        assert_eq!(select_call_mode(101, false), CallMode::Degraded);
    }

    #[test]
    fn test_relay_peer_count() {
        assert_eq!(relay_peer_count(9), 3);
        assert_eq!(relay_peer_count(16), 4);
        assert_eq!(relay_peer_count(25), 5);
        // ceil ensures we never undercount.
        assert_eq!(relay_peer_count(10), 4); // sqrt(10) ≈ 3.16 → 4
    }

    #[test]
    fn test_call_signal_serde() {
        let signal = CallSignal::Offer {
            call_id: [0xAA; 32],
            audio_codecs: vec![AudioCodec::Opus],
            video_codecs: vec![VideoCodec::VP9],
            losec_requested: false,
            session_desc: "test".to_string(),
        };

        let json = serde_json::to_string(&signal).unwrap();
        let recovered: CallSignal = serde_json::from_str(&json).unwrap();
        match recovered {
            CallSignal::Offer { call_id, .. } => {
                assert_eq!(call_id, [0xAA; 32]);
            }
            _ => panic!("Expected Offer"),
        }
    }
}
