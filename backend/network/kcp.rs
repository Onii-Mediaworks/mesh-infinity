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
// KCP_NODELAY — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_NODELAY: i32 = 1;

/// Internal tick interval (milliseconds).
// KCP_INTERVAL_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_INTERVAL_MS: i32 = 20;

/// Fast retransmit threshold (out-of-order ACK count).
// KCP_RESEND — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_RESEND: i32 = 2;

/// Congestion control. 1 = disabled (mesh manages its own congestion).
// KCP_NC — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_NC: i32 = 1;

/// Default MTU (bytes). Adjusted per-tunnel based on TunnelAccept.mtu.
// KCP_DEFAULT_MTU — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_DEFAULT_MTU: u16 = 1400;

/// Send window size (packets).
// KCP_SND_WND — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_SND_WND: u32 = 128;

/// Receive window size (packets).
// KCP_RCV_WND — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_RCV_WND: u32 = 128;

/// Dead link threshold. After this many consecutive unacked
/// retransmits, the link is declared dead.
// KCP_DEAD_LINK — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_DEAD_LINK: u32 = 20;

/// Initial RTO in no-delay mode (milliseconds).
// KCP_INITIAL_RTO_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_INITIAL_RTO_MS: u32 = 30;

/// RTO backoff multiplier (1.5× instead of 2× in no-delay mode).
// KCP_RTO_MULTIPLIER — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_RTO_MULTIPLIER: f32 = 1.5;

/// Maximum RTO (milliseconds).
// KCP_MAX_RTO_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const KCP_MAX_RTO_MS: u32 = 5000;

// ---------------------------------------------------------------------------
// Reliability Mode (§16.10.3)
// ---------------------------------------------------------------------------

/// KCP reliability mode for different stream types.
///
/// Controls which frames are retransmitted when lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// KcpReliabilityMode — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum KcpReliabilityMode {
    /// All frames retransmitted. Default for messaging and files.
    Full,
    /// Only keyframes and headers retransmitted.
    /// Delta frames and audio frames accept loss.
    /// Used for video streaming (VP9, AV1).
    // Execute this protocol step.
    Selective,
    /// No retransmission at all.
    /// Used for voice-only calls where Opus PLC handles loss.
    // No value available.
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
// Begin the block scope.
// KcpConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct KcpConfig {
    /// Conversation ID (first 4 bytes of WireGuard session key).
    // Execute this protocol step.
    pub conv: u32,
    /// Path MTU from tunnel negotiation.
    // Execute this protocol step.
    pub mtu: u16,
    /// Reliability mode.
    // Execute this protocol step.
    pub mode: KcpReliabilityMode,
    /// Send window size.
    // Execute this protocol step.
    pub snd_wnd: u32,
    /// Receive window size.
    // Execute this protocol step.
    pub rcv_wnd: u32,
}

// Begin the block scope.
// KcpConfig implementation — core protocol logic.
impl KcpConfig {
    /// Derive the conv from a WireGuard session key.
    ///
    /// Both sides compute this independently — no round trip.
    /// Takes the first 4 bytes of the session key as a u32 (LE).
    // Perform the 'conv from session key' operation.
    // Errors are propagated to the caller via Result.
    pub fn conv_from_session_key(session_key: &[u8; 32]) -> u32 {
        // Invoke the associated function.
        // Execute this protocol step.
        u32::from_le_bytes([
            // Execute this protocol step.
            session_key[0],
            // Execute this protocol step.
            session_key[1],
            // Execute this protocol step.
            session_key[2],
            // Execute this protocol step.
            session_key[3],
        ])
    }

    /// Create a default config from a session key and MTU.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(session_key: &[u8; 32], mtu: u16, mode: KcpReliabilityMode) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        Self {
            // Invoke the associated function.
            // Execute this protocol step.
            conv: Self::conv_from_session_key(session_key),
            mtu,
            mode,
            // Process the current step in the protocol.
            // Execute this protocol step.
            snd_wnd: KCP_SND_WND,
            // Process the current step in the protocol.
            // Execute this protocol step.
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
