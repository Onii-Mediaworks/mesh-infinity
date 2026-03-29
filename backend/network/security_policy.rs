//! Security Policies and Hardening (§15)
//!
//! # Traffic Shaping (§15.4)
//!
//! All traffic is shaped to prevent timing analysis:
//! - Messages are delayed by priority-dependent jitter
//! - Multiple messages within a jitter window are coalesced
//! - Padding is applied to fixed size buckets
//!
//! # Security Floor (§16.5)
//!
//! Seven non-negotiable invariants:
//! 1. Cover traffic is never zero (while connected)
//! 2. Padding cannot be disabled
//! 3. Jitter cannot be disabled
//! 4. Inner tunnel cannot be bypassed
//! 5. Minimum 2 tunnels always maintained
//! 6. State transitions are gradual (no instant drop to zero)
//! 7. Zero state only on explicit user disconnect
//!
//! # Dead Man's Switch (§15)
//!
//! Messages with CancellationBased release conditions use
//! periodic cancellation signals. If the signal stops arriving,
//! the message is released. Grace period: 10% of window.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Jitter Constants (§15.4)
// ---------------------------------------------------------------------------

/// Jitter for Urgent priority messages (milliseconds).
pub const JITTER_URGENT_MS: u64 = 0;

/// Maximum jitter for High priority messages (milliseconds).
pub const JITTER_HIGH_MAX_MS: u64 = 50;

/// Maximum jitter for Normal priority messages (milliseconds).
pub const JITTER_NORMAL_MAX_MS: u64 = 250;

/// Maximum jitter for Low priority messages (milliseconds).
pub const JITTER_LOW_MAX_MS: u64 = 250;

// ---------------------------------------------------------------------------
// Cover Traffic Model (§16.2)
// ---------------------------------------------------------------------------

/// Cover traffic parameters per device activity state (§16.2).
///
/// Cover traffic ensures that an observer can't distinguish
/// between idle periods and active communication.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CoverTrafficParams {
    /// Target number of tunnels for this state.
    pub target_tunnels_min: u8,
    pub target_tunnels_max: u8,
    /// Cover traffic rate per tunnel (bytes/sec).
    pub cover_rate_bytes_per_sec: u32,
}

/// Cover traffic parameters for each device state.
pub fn cover_traffic_for_state(state: DeviceActivityState) -> CoverTrafficParams {
    match state {
        DeviceActivityState::ActiveConversation => CoverTrafficParams {
            target_tunnels_min: 3,
            target_tunnels_max: 4,
            cover_rate_bytes_per_sec: 7_168, // ~7 KB/s
        },
        DeviceActivityState::ForegroundIdle => CoverTrafficParams {
            target_tunnels_min: 2,
            target_tunnels_max: 4,
            cover_rate_bytes_per_sec: 3_072, // ~3 KB/s
        },
        DeviceActivityState::Backgrounded => CoverTrafficParams {
            target_tunnels_min: 2,
            target_tunnels_max: 3,
            cover_rate_bytes_per_sec: 1_024, // ~1 KB/s
        },
        DeviceActivityState::ScreenOff => CoverTrafficParams {
            target_tunnels_min: 2,
            target_tunnels_max: 2,
            cover_rate_bytes_per_sec: 205, // ~0.2 KB/s
        },
        DeviceActivityState::LowBattery => CoverTrafficParams {
            target_tunnels_min: 2,
            target_tunnels_max: 2,
            cover_rate_bytes_per_sec: 205, // ~0.2 KB/s
        },
        DeviceActivityState::ExplicitDisconnect => CoverTrafficParams {
            target_tunnels_min: 0,
            target_tunnels_max: 0,
            cover_rate_bytes_per_sec: 0,
        },
    }
}

/// Device activity state for cover traffic computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceActivityState {
    /// User is actively messaging / in a call.
    ActiveConversation,
    /// App is in foreground but no active conversation.
    ForegroundIdle,
    /// App is backgrounded.
    Backgrounded,
    /// Phone screen is off / device idle.
    ScreenOff,
    /// Battery is low.
    LowBattery,
    /// User explicitly disconnected (zero state).
    ExplicitDisconnect,
}

// ---------------------------------------------------------------------------
// Latency Budget (§16.9)
// ---------------------------------------------------------------------------

/// Message delivery latency budget (milliseconds) by component.
///
/// Total budget (excluding network): <72ms.
#[derive(Clone, Debug)]
pub struct LatencyBudget {
    /// UI processing (compose → FFI): <5ms.
    pub ui_processing_ms: u32,
    /// Encryption (Double Ratchet + 4-layer): <3ms.
    pub encryption_ms: u32,
    /// Traffic shaper jitter (High priority): 0–50ms.
    pub shaper_jitter_ms: u32,
    /// KCP framing + WireGuard: <2ms.
    pub kcp_wireguard_ms: u32,
    /// Recipient decrypt + KCP: <2ms.
    pub recipient_decrypt_ms: u32,
    /// Recipient Double Ratchet: <2ms.
    pub recipient_ratchet_ms: u32,
    /// Recipient UI render: <8ms.
    pub recipient_render_ms: u32,
}

impl Default for LatencyBudget {
    fn default() -> Self {
        Self {
            ui_processing_ms: 5,
            encryption_ms: 3,
            shaper_jitter_ms: 50,
            kcp_wireguard_ms: 2,
            recipient_decrypt_ms: 2,
            recipient_ratchet_ms: 2,
            recipient_render_ms: 8,
        }
    }
}

impl LatencyBudget {
    /// Total latency budget excluding network (milliseconds).
    pub fn total_ms(&self) -> u32 {
        self.ui_processing_ms
            + self.encryption_ms
            + self.shaper_jitter_ms
            + self.kcp_wireguard_ms
            + self.recipient_decrypt_ms
            + self.recipient_ratchet_ms
            + self.recipient_render_ms
    }
}

// ---------------------------------------------------------------------------
// Stream Latency Ceilings (§16.10)
// ---------------------------------------------------------------------------

/// Stream type for latency ceiling selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamType {
    Voice,
    Video,
    RemoteDesktop,
    ScreenShare,
    PushToTalk,
}

/// Maximum acceptable latency for a stream type (milliseconds).
pub fn stream_latency_ceiling(stream_type: StreamType) -> u32 {
    match stream_type {
        StreamType::Voice => 150,
        StreamType::Video => 200,
        StreamType::RemoteDesktop => 100,
        StreamType::ScreenShare => 100,
        StreamType::PushToTalk => 200,
    }
}

/// Stream profile for the transport solver (§16.10).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamProfile {
    pub stream_type: StreamType,
    pub target_bitrate: u32,
    pub max_latency_ms: u32,
    pub loss_tolerance: f32,
    pub jitter_tolerance: u32,
}

impl StreamProfile {
    /// Create a default profile for a stream type.
    pub fn default_for(stream_type: StreamType) -> Self {
        let ceiling = stream_latency_ceiling(stream_type);
        match stream_type {
            StreamType::Voice => Self {
                stream_type,
                target_bitrate: 32_000, // 32 kbps Opus.
                max_latency_ms: ceiling,
                loss_tolerance: 0.05,
                jitter_tolerance: 30,
            },
            StreamType::Video => Self {
                stream_type,
                target_bitrate: 2_000_000, // 2 Mbps.
                max_latency_ms: ceiling,
                loss_tolerance: 0.02,
                jitter_tolerance: 50,
            },
            StreamType::RemoteDesktop => Self {
                stream_type,
                target_bitrate: 5_000_000,
                max_latency_ms: ceiling,
                loss_tolerance: 0.0,
                jitter_tolerance: 20,
            },
            StreamType::ScreenShare => Self {
                stream_type,
                target_bitrate: 3_000_000,
                max_latency_ms: ceiling,
                loss_tolerance: 0.01,
                jitter_tolerance: 30,
            },
            StreamType::PushToTalk => Self {
                stream_type,
                target_bitrate: 16_000, // 16 kbps.
                max_latency_ms: ceiling,
                loss_tolerance: 0.10,
                jitter_tolerance: 50,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Dead Man's Switch Cancellation (§15)
// ---------------------------------------------------------------------------

/// Cancellation signal for dead man's switch messages.
///
/// Sent periodically to prevent release of a CancellationBased
/// store-and-forward message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancellationSignal {
    /// Which message to cancel.
    pub message_id: [u8; 16],
    /// When this cancellation was issued.
    pub issued_at: u64,
    /// When the next cancellation is expected.
    /// If not received by this time + 10% grace, the message releases.
    pub next_expected: u64,
    /// Ed25519 signature over (message_id || issued_at || next_expected).
    pub sig: Vec<u8>,
}

/// Grace period as a fraction of the cancellation window.
/// 10% of the window is the grace before release.
pub const DMS_GRACE_FRACTION: f32 = 0.10;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_traffic_states() {
        let active = cover_traffic_for_state(DeviceActivityState::ActiveConversation);
        assert_eq!(active.target_tunnels_min, 3);
        assert!(active.cover_rate_bytes_per_sec > 0);

        let disconnected = cover_traffic_for_state(DeviceActivityState::ExplicitDisconnect);
        assert_eq!(disconnected.target_tunnels_min, 0);
        assert_eq!(disconnected.cover_rate_bytes_per_sec, 0);
    }

    #[test]
    fn test_latency_budget() {
        let budget = LatencyBudget::default();
        assert!(budget.total_ms() <= 72);
    }

    #[test]
    fn test_stream_ceilings() {
        assert_eq!(stream_latency_ceiling(StreamType::Voice), 150);
        assert_eq!(stream_latency_ceiling(StreamType::RemoteDesktop), 100);
    }

    #[test]
    fn test_stream_profiles() {
        let voice = StreamProfile::default_for(StreamType::Voice);
        assert_eq!(voice.max_latency_ms, 150);
        assert!(voice.loss_tolerance > 0.0);

        let rdp = StreamProfile::default_for(StreamType::RemoteDesktop);
        assert_eq!(rdp.loss_tolerance, 0.0); // No loss acceptable.
    }
}
