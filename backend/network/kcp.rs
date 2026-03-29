//! KCP Reliability Sublayer (§5.30)
//!
//! # What is KCP?
//!
//! KCP is a reliable transport protocol that sits between WireGuard
//! and application data. It provides ARQ (Automatic Repeat reQuest)
//! with configurable reliability modes.
//!
//! # Configuration (§5.30)
//!
//! ```text
//! nodelay:   1       (no-delay mode; initial RTO 30ms)
//! interval:  20      (internal tick: 20ms)
//! resend:    2       (fast retransmit after 2 OOO ACKs)
//! nc:        1       (congestion control disabled)
//! snd_wnd:   128
//! rcv_wnd:   128
//! dead_link: 20      (declare dead after 20 unacked retransmits)
//! ```
//!
//! # Reliability Modes (§16.10.3)
//!
//! - **Full**: all frames retransmitted (default)
//! - **Selective**: only keyframes/headers retransmitted;
//!   delta/audio frames accept loss
//! - **None**: no retransmission (voice-only; Opus PLC handles loss)
//!
//! # Conv Derivation
//!
//! The KCP `conv` field (conversation ID) is derived from the first
//! 4 bytes of the WireGuard session key. Both sides compute it
//! independently — no round trip needed.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// KCP Configuration Constants (§5.30)
// ---------------------------------------------------------------------------

/// No-delay mode. 1 = enabled (initial RTO 30ms instead of 100ms).
pub const KCP_NODELAY: i32 = 1;

/// Internal tick interval (milliseconds).
pub const KCP_INTERVAL_MS: i32 = 20;

/// Fast retransmit threshold (out-of-order ACK count).
pub const KCP_RESEND: i32 = 2;

/// Congestion control. 1 = disabled (mesh manages its own congestion).
pub const KCP_NC: i32 = 1;

/// Default MTU (bytes). Adjusted per-tunnel based on TunnelAccept.mtu.
pub const KCP_DEFAULT_MTU: u16 = 1400;

/// Send window size (packets).
pub const KCP_SND_WND: u32 = 128;

/// Receive window size (packets).
pub const KCP_RCV_WND: u32 = 128;

/// Dead link threshold. After this many consecutive unacked
/// retransmits, the link is declared dead.
pub const KCP_DEAD_LINK: u32 = 20;

/// Initial RTO in no-delay mode (milliseconds).
pub const KCP_INITIAL_RTO_MS: u32 = 30;

/// RTO backoff multiplier (1.5× instead of 2× in no-delay mode).
pub const KCP_RTO_MULTIPLIER: f32 = 1.5;

/// Maximum RTO (milliseconds).
pub const KCP_MAX_RTO_MS: u32 = 5000;

// ---------------------------------------------------------------------------
// Reliability Mode (§16.10.3)
// ---------------------------------------------------------------------------

/// KCP reliability mode for different stream types.
///
/// Controls which frames are retransmitted when lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KcpReliabilityMode {
    /// All frames retransmitted. Default for messaging and files.
    Full,
    /// Only keyframes and headers retransmitted.
    /// Delta frames and audio frames accept loss.
    /// Used for video streaming (VP9, AV1).
    Selective,
    /// No retransmission at all.
    /// Used for voice-only calls where Opus PLC handles loss.
    None,
}

// ---------------------------------------------------------------------------
// KCP Session Config
// ---------------------------------------------------------------------------

/// Configuration for a KCP session.
///
/// Created from the KCP constants and per-tunnel parameters
/// (like MTU from TunnelAccept).
#[derive(Clone, Debug)]
pub struct KcpConfig {
    /// Conversation ID (first 4 bytes of WireGuard session key).
    pub conv: u32,
    /// Path MTU from tunnel negotiation.
    pub mtu: u16,
    /// Reliability mode.
    pub mode: KcpReliabilityMode,
    /// Send window size.
    pub snd_wnd: u32,
    /// Receive window size.
    pub rcv_wnd: u32,
}

impl KcpConfig {
    /// Derive the conv from a WireGuard session key.
    ///
    /// Both sides compute this independently — no round trip.
    /// Takes the first 4 bytes of the session key as a u32 (LE).
    pub fn conv_from_session_key(session_key: &[u8; 32]) -> u32 {
        u32::from_le_bytes([
            session_key[0],
            session_key[1],
            session_key[2],
            session_key[3],
        ])
    }

    /// Create a default config from a session key and MTU.
    pub fn new(session_key: &[u8; 32], mtu: u16, mode: KcpReliabilityMode) -> Self {
        Self {
            conv: Self::conv_from_session_key(session_key),
            mtu,
            mode,
            snd_wnd: KCP_SND_WND,
            rcv_wnd: KCP_RCV_WND,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conv_derivation() {
        let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                   0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let conv = KcpConfig::conv_from_session_key(&key);
        assert_eq!(conv, u32::from_le_bytes([0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn test_conv_deterministic() {
        // Both sides should compute the same conv.
        let key = [0xAA; 32];
        let conv1 = KcpConfig::conv_from_session_key(&key);
        let conv2 = KcpConfig::conv_from_session_key(&key);
        assert_eq!(conv1, conv2);
    }

    #[test]
    fn test_kcp_config_new() {
        let key = [0xBB; 32];
        let config = KcpConfig::new(&key, 1400, KcpReliabilityMode::Full);
        assert_eq!(config.mtu, 1400);
        assert_eq!(config.snd_wnd, KCP_SND_WND);
        assert_eq!(config.mode, KcpReliabilityMode::Full);
    }
}
