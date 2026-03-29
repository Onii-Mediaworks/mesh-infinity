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
pub const FULL_MESH_MAX: usize = 4;

/// Maximum video call participants before degraded mode.
pub const VIDEO_CAP: usize = 50;

/// Maximum audio call participants before degraded mode.
pub const AUDIO_CAP: usize = 100;

// ---------------------------------------------------------------------------
// Call Signal
// ---------------------------------------------------------------------------

/// Call signalling message sent over the mesh messaging channel.
///
/// These control call lifecycle. Media flows separately over
/// a dedicated WireGuard session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CallSignal {
    /// Offer to start a call.
    Offer {
        /// Unique call identifier.
        call_id: [u8; 32],
        /// Offered codecs (audio).
        audio_codecs: Vec<AudioCodec>,
        /// Offered codecs (video). Empty for audio-only.
        video_codecs: Vec<VideoCodec>,
        /// Whether LoSec path is requested.
        losec_requested: bool,
        /// SDP-like session description.
        session_desc: String,
    },

    /// Accept a call offer.
    Answer {
        call_id: [u8; 32],
        /// Selected audio codec.
        audio_codec: AudioCodec,
        /// Selected video codec (None for audio-only).
        video_codec: Option<VideoCodec>,
        /// Whether LoSec was accepted.
        losec_accepted: bool,
        session_desc: String,
    },

    /// ICE candidate for NAT traversal.
    /// Mesh relay (§6.11) is preferred over ICE, but this
    /// is needed for WebRTC interop.
    IceCandidate {
        call_id: [u8; 32],
        candidate: String,
    },

    /// End the call.
    Hangup {
        call_id: [u8; 32],
        reason: HangupReason,
    },
}

/// Audio codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AudioCodec {
    Opus,
}

/// Video codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoCodec {
    VP8,
    VP9,
    AV1,
}

/// Why a call ended.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HangupReason {
    /// User hung up normally.
    Normal,
    /// Call was declined.
    Declined,
    /// No answer within timeout.
    Timeout,
    /// Network error.
    NetworkError,
    /// Insufficient bandwidth.
    InsufficientBandwidth,
}

// ---------------------------------------------------------------------------
// Call State
// ---------------------------------------------------------------------------

/// State of an active call.
#[derive(Clone, Debug)]
pub struct CallState {
    /// Unique call identifier.
    pub call_id: [u8; 32],

    /// Whether this is a video call.
    pub is_video: bool,

    /// List of participants.
    pub participants: Vec<PeerId>,

    /// Current call mode.
    pub mode: CallMode,

    /// Whether LoSec is active for this call.
    pub losec_active: bool,

    /// Whether push-to-talk is enabled.
    pub push_to_talk: bool,

    /// When the call started.
    pub started_at: u64,

    /// Audio codec in use.
    pub audio_codec: AudioCodec,

    /// Video codec in use (None for audio-only).
    pub video_codec: Option<VideoCodec>,
}

impl CallState {
    /// Create a new outgoing call.
    ///
    /// `call_id`: unique identifier for this call.
    /// `is_video`: whether video is enabled.
    /// `our_peer_id`: our own peer ID.
    /// `now`: current unix timestamp.
    pub fn new_outgoing(
        call_id: [u8; 32],
        is_video: bool,
        our_peer_id: PeerId,
        now: u64,
    ) -> Self {
        Self {
            call_id,
            is_video,
            participants: vec![our_peer_id],
            mode: CallMode::FullMesh,
            losec_active: false,
            push_to_talk: false,
            started_at: now,
            audio_codec: AudioCodec::Opus,
            video_codec: if is_video { Some(VideoCodec::VP9) } else { None },
        }
    }

    /// Add a participant and recalculate the call mode.
    ///
    /// Returns the new call mode. If the mode changed to Degraded,
    /// the UI should show a quality warning.
    pub fn add_participant(&mut self, peer_id: PeerId) -> CallMode {
        if !self.participants.contains(&peer_id) {
            self.participants.push(peer_id);
        }
        self.mode = select_call_mode(self.participants.len(), self.is_video);
        self.mode
    }

    /// Remove a participant and recalculate the call mode.
    pub fn remove_participant(&mut self, peer_id: &PeerId) -> CallMode {
        self.participants.retain(|p| p != peer_id);
        self.mode = select_call_mode(self.participants.len(), self.is_video);
        self.mode
    }

    /// Number of participants.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Number of relay peers needed (for RelayMesh mode).
    pub fn relay_count(&self) -> usize {
        if self.mode == CallMode::RelayMesh {
            relay_peer_count(self.participants.len())
        } else {
            0
        }
    }

    /// Whether the call is audio-only.
    pub fn is_audio_only(&self) -> bool {
        !self.is_video
    }

    /// Call duration in seconds.
    pub fn duration_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.started_at)
    }

    /// Enable or disable video mid-call.
    ///
    /// Recalculates the call mode since video has lower
    /// participant caps.
    pub fn set_video(&mut self, enabled: bool) {
        self.is_video = enabled;
        self.video_codec = if enabled { Some(VideoCodec::VP9) } else { None };
        self.mode = select_call_mode(self.participants.len(), self.is_video);
    }
}

/// Call topology mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallMode {
    /// Every participant directly connected. ≤ 4 participants.
    FullMesh,
    /// Each node connects to sqrt(n) relay peers. 5-50/100 participants.
    RelayMesh,
    /// Over capacity. Quality warning displayed.
    Degraded,
}

/// Determine the appropriate call mode for a participant count.
pub fn select_call_mode(participants: usize, is_video: bool) -> CallMode {
    if participants <= FULL_MESH_MAX {
        CallMode::FullMesh
    } else {
        let cap = if is_video { VIDEO_CAP } else { AUDIO_CAP };
        if participants <= cap {
            CallMode::RelayMesh
        } else {
            CallMode::Degraded
        }
    }
}

/// Number of relay peers each node should connect to in RelayMesh mode.
pub fn relay_peer_count(participants: usize) -> usize {
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
