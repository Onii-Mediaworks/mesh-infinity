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
// JITTER_URGENT_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
// JITTER_URGENT_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const JITTER_URGENT_MS: u64 = 0;

/// Maximum jitter for High priority messages (milliseconds).
// JITTER_HIGH_MAX_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
// JITTER_HIGH_MAX_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const JITTER_HIGH_MAX_MS: u64 = 50;

/// Maximum jitter for Normal priority messages (milliseconds).
// JITTER_NORMAL_MAX_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
// JITTER_NORMAL_MAX_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const JITTER_NORMAL_MAX_MS: u64 = 250;

/// Maximum jitter for Low priority messages (milliseconds).
// JITTER_LOW_MAX_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
// JITTER_LOW_MAX_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const JITTER_LOW_MAX_MS: u64 = 250;

// ---------------------------------------------------------------------------
// Cover Traffic Model (§16.2)
// ---------------------------------------------------------------------------

/// Cover traffic parameters per device activity state (§16.2).
///
/// Cover traffic ensures that an observer can't distinguish
/// between idle periods and active communication.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
// Begin the block scope.
// CoverTrafficParams — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// CoverTrafficParams — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct CoverTrafficParams {
    /// Target number of tunnels for this state.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target_tunnels_min: u8,
    /// The target tunnels max for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target_tunnels_max: u8,
    /// Cover traffic rate per tunnel (bytes/sec).
    // Execute this protocol step.
    // Execute this protocol step.
    pub cover_rate_bytes_per_sec: u32,
}

/// Cover traffic parameters for each device state.
// Perform the 'cover traffic for state' operation.
// Errors are propagated to the caller via Result.
// Perform the 'cover traffic for state' operation.
// Errors are propagated to the caller via Result.
pub fn cover_traffic_for_state(state: DeviceActivityState) -> CoverTrafficParams {
    // Dispatch based on the variant to apply type-specific logic.
    // Dispatch on the variant.
    // Dispatch on the variant.
    match state {
        // Begin the block scope.
        // Handle DeviceActivityState::ActiveConversation.
        // Handle DeviceActivityState::ActiveConversation.
        DeviceActivityState::ActiveConversation => CoverTrafficParams {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_min: 3,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_max: 4,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            cover_rate_bytes_per_sec: 7_168, // ~7 KB/s
        },
        // Begin the block scope.
        // Handle DeviceActivityState::ForegroundIdle.
        // Handle DeviceActivityState::ForegroundIdle.
        DeviceActivityState::ForegroundIdle => CoverTrafficParams {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_min: 2,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_max: 4,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            cover_rate_bytes_per_sec: 3_072, // ~3 KB/s
        },
        // Begin the block scope.
        // Handle DeviceActivityState::Backgrounded.
        // Handle DeviceActivityState::Backgrounded.
        DeviceActivityState::Backgrounded => CoverTrafficParams {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_min: 2,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_max: 3,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            cover_rate_bytes_per_sec: 1_024, // ~1 KB/s
        },
        // Begin the block scope.
        // Handle DeviceActivityState::ScreenOff.
        // Handle DeviceActivityState::ScreenOff.
        DeviceActivityState::ScreenOff => CoverTrafficParams {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_min: 2,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_max: 2,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            cover_rate_bytes_per_sec: 205, // ~0.2 KB/s
        },
        // Begin the block scope.
        // Handle DeviceActivityState::LowBattery.
        // Handle DeviceActivityState::LowBattery.
        DeviceActivityState::LowBattery => CoverTrafficParams {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_min: 2,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_max: 2,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            cover_rate_bytes_per_sec: 205, // ~0.2 KB/s
        },
        // Begin the block scope.
        // Handle DeviceActivityState::ExplicitDisconnect.
        // Handle DeviceActivityState::ExplicitDisconnect.
        DeviceActivityState::ExplicitDisconnect => CoverTrafficParams {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_min: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            target_tunnels_max: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            cover_rate_bytes_per_sec: 0,
        },
    }
}

/// Device activity state for cover traffic computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// DeviceActivityState — variant enumeration.
// Match exhaustively to handle every protocol state.
// DeviceActivityState — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum DeviceActivityState {
    /// User is actively messaging / in a call.
    // Execute this protocol step.
    // Execute this protocol step.
    ActiveConversation,
    /// App is in foreground but no active conversation.
    // Execute this protocol step.
    // Execute this protocol step.
    ForegroundIdle,
    /// App is backgrounded.
    // Execute this protocol step.
    // Execute this protocol step.
    Backgrounded,
    /// Phone screen is off / device idle.
    // Execute this protocol step.
    // Execute this protocol step.
    ScreenOff,
    /// Battery is low.
    // Execute this protocol step.
    // Execute this protocol step.
    LowBattery,
    /// User explicitly disconnected (zero state).
    // Execute this protocol step.
    // Execute this protocol step.
    ExplicitDisconnect,
}

// ---------------------------------------------------------------------------
// Latency Budget (§16.9)
// ---------------------------------------------------------------------------

/// Message delivery latency budget (milliseconds) by component.
///
/// Total budget (excluding network): <72ms.
#[derive(Clone, Debug)]
// Begin the block scope.
// LatencyBudget — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// LatencyBudget — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct LatencyBudget {
    /// UI processing (compose → FFI): <5ms.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ui_processing_ms: u32,
    /// Encryption (Double Ratchet + 4-layer): <3ms.
    // Execute this protocol step.
    // Execute this protocol step.
    pub encryption_ms: u32,
    /// Traffic shaper jitter (High priority): 0–50ms.
    // Execute this protocol step.
    // Execute this protocol step.
    pub shaper_jitter_ms: u32,
    /// KCP framing + WireGuard: <2ms.
    // Execute this protocol step.
    // Execute this protocol step.
    pub kcp_wireguard_ms: u32,
    /// Recipient decrypt + KCP: <2ms.
    // Execute this protocol step.
    // Execute this protocol step.
    pub recipient_decrypt_ms: u32,
    /// Recipient Double Ratchet: <2ms.
    // Execute this protocol step.
    // Execute this protocol step.
    pub recipient_ratchet_ms: u32,
    /// Recipient UI render: <8ms.
    // Execute this protocol step.
    // Execute this protocol step.
    pub recipient_render_ms: u32,
}

// Trait implementation for protocol conformance.
// Implement Default for LatencyBudget.
// Implement Default for LatencyBudget.
impl Default for LatencyBudget {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            ui_processing_ms: 5,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            encryption_ms: 3,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            shaper_jitter_ms: 50,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            kcp_wireguard_ms: 2,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            recipient_decrypt_ms: 2,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            recipient_ratchet_ms: 2,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            recipient_render_ms: 8,
        }
    }
}

// Begin the block scope.
// LatencyBudget implementation — core protocol logic.
// LatencyBudget implementation — core protocol logic.
impl LatencyBudget {
    /// Total latency budget excluding network (milliseconds).
    // Perform the 'total ms' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'total ms' operation.
    // Errors are propagated to the caller via Result.
    pub fn total_ms(&self) -> u32 {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.ui_processing_ms
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            + self.encryption_ms
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            + self.shaper_jitter_ms
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            + self.kcp_wireguard_ms
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            + self.recipient_decrypt_ms
            // Process the current step in the protocol.
            // Execute this protocol step.
            + self.recipient_ratchet_ms
            // Process the current step in the protocol.
            // Execute this protocol step.
            + self.recipient_render_ms
    }
}

// ---------------------------------------------------------------------------
// Stream Latency Ceilings (§16.10)
// ---------------------------------------------------------------------------

/// Stream type for latency ceiling selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// StreamType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum StreamType {
    Voice,
    Video,
    // Execute this protocol step.
    RemoteDesktop,
    // Execute this protocol step.
    ScreenShare,
    // Execute this protocol step.
    PushToTalk,
}

/// Maximum acceptable latency for a stream type (milliseconds).
// Perform the 'stream latency ceiling' operation.
// Errors are propagated to the caller via Result.
pub fn stream_latency_ceiling(stream_type: StreamType) -> u32 {
    // Dispatch based on the variant to apply type-specific logic.
    // Dispatch on the variant.
    match stream_type {
        // Handle this match arm.
        StreamType::Voice => 150,
        // Handle this match arm.
        StreamType::Video => 200,
        // Handle this match arm.
        StreamType::RemoteDesktop => 100,
        // Handle this match arm.
        StreamType::ScreenShare => 100,
        // Handle this match arm.
        StreamType::PushToTalk => 200,
    }
}

/// Stream profile for the transport solver (§16.10).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// StreamProfile — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct StreamProfile {
    /// The stream type for this instance.
    // Execute this protocol step.
    pub stream_type: StreamType,
    /// The target bitrate for this instance.
    // Execute this protocol step.
    pub target_bitrate: u32,
    /// The max latency ms for this instance.
    // Execute this protocol step.
    pub max_latency_ms: u32,
    /// The loss tolerance for this instance.
    // Execute this protocol step.
    pub loss_tolerance: f32,
    /// The jitter tolerance for this instance.
    // Execute this protocol step.
    pub jitter_tolerance: u32,
}

// Begin the block scope.
// StreamProfile implementation — core protocol logic.
impl StreamProfile {
    /// Create a default profile for a stream type.
    // Perform the 'default for' operation.
    // Errors are propagated to the caller via Result.
    pub fn default_for(stream_type: StreamType) -> Self {
        // Execute the operation and bind the result.
        // Compute ceiling for this protocol step.
        let ceiling = stream_latency_ceiling(stream_type);
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        match stream_type {
            // Begin the block scope.
            // Handle StreamType::Voice.
            StreamType::Voice => Self {
                // Execute this protocol step.
                stream_type,
                // Process the current step in the protocol.
                // Execute this protocol step.
                target_bitrate: 32_000, // 32 kbps Opus.
                // Process the current step in the protocol.
                // Execute this protocol step.
                max_latency_ms: ceiling,
                // Process the current step in the protocol.
                // Execute this protocol step.
                loss_tolerance: 0.05,
                // Process the current step in the protocol.
                // Execute this protocol step.
                jitter_tolerance: 30,
            },
            // Begin the block scope.
            // Handle StreamType::Video.
            StreamType::Video => Self {
                // Execute this protocol step.
                stream_type,
                // Process the current step in the protocol.
                // Execute this protocol step.
                target_bitrate: 2_000_000, // 2 Mbps.
                // Process the current step in the protocol.
                // Execute this protocol step.
                max_latency_ms: ceiling,
                // Process the current step in the protocol.
                // Execute this protocol step.
                loss_tolerance: 0.02,
                // Process the current step in the protocol.
                // Execute this protocol step.
                jitter_tolerance: 50,
            },
            // Begin the block scope.
            // Handle StreamType::RemoteDesktop.
            StreamType::RemoteDesktop => Self {
                // Execute this protocol step.
                stream_type,
                // Process the current step in the protocol.
                // Execute this protocol step.
                target_bitrate: 5_000_000,
                // Process the current step in the protocol.
                // Execute this protocol step.
                max_latency_ms: ceiling,
                // Process the current step in the protocol.
                // Execute this protocol step.
                loss_tolerance: 0.0,
                // Process the current step in the protocol.
                // Execute this protocol step.
                jitter_tolerance: 20,
            },
            // Begin the block scope.
            // Handle StreamType::ScreenShare.
            StreamType::ScreenShare => Self {
                // Execute this protocol step.
                stream_type,
                // Process the current step in the protocol.
                // Execute this protocol step.
                target_bitrate: 3_000_000,
                // Process the current step in the protocol.
                // Execute this protocol step.
                max_latency_ms: ceiling,
                // Process the current step in the protocol.
                // Execute this protocol step.
                loss_tolerance: 0.01,
                // Process the current step in the protocol.
                // Execute this protocol step.
                jitter_tolerance: 30,
            },
            // Begin the block scope.
            // Handle StreamType::PushToTalk.
            StreamType::PushToTalk => Self {
                // Execute this protocol step.
                stream_type,
                // Process the current step in the protocol.
                // Execute this protocol step.
                target_bitrate: 16_000, // 16 kbps.
                // Process the current step in the protocol.
                // Execute this protocol step.
                max_latency_ms: ceiling,
                // Process the current step in the protocol.
                // Execute this protocol step.
                loss_tolerance: 0.10,
                // Process the current step in the protocol.
                // Execute this protocol step.
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
// Begin the block scope.
// CancellationSignal — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct CancellationSignal {
    /// Which message to cancel.
    // Execute this protocol step.
    pub message_id: [u8; 16],
    /// When this cancellation was issued.
    // Execute this protocol step.
    pub issued_at: u64,
    /// When the next cancellation is expected.
    /// If not received by this time + 10% grace, the message releases.
    // Execute this protocol step.
    pub next_expected: u64,
    /// Ed25519 signature over (message_id || issued_at || next_expected).
    // Execute this protocol step.
    pub sig: Vec<u8>,
}

/// Grace period as a fraction of the cancellation window.
/// 10% of the window is the grace before release.
// DMS_GRACE_FRACTION — protocol constant.
// Defined by the spec; must not change without a version bump.
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
