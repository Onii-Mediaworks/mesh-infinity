//! Transport Health Monitoring (§5.11)
//!
//! # What is Transport Health?
//!
//! Each active transport connection has a "health" — a measure of how
//! reliable and fast it is right now. The transport solver uses this
//! to make routing decisions: prefer healthy transports, avoid degraded
//! ones, and mark dead ones for teardown.
//!
//! # Health States
//!
//! - **Live:** transport is working normally. Packets are getting through,
//!   latency is reasonable, no errors.
//!
//! - **Degraded:** transport is working but poorly. High latency, packet
//!   loss, or intermittent failures. The solver applies a scoring penalty
//!   to degraded transports.
//!
//! - **Dead:** transport has stopped responding entirely. Keepalive probes
//!   have failed. The solver removes this transport from the candidate set.
//!
//! # Latency Tracking
//!
//! Latency is tracked using an Exponential Moving Average (EMA) with
//! alpha ≈ 0.05. This means:
//! - Recent measurements have more influence than old ones
//! - A single spike doesn't dramatically change the average
//! - The baseline updates slowly, reflecting long-term trends
//!
//! # Keepalive Probes
//!
//! Every 25 seconds (matching WireGuard's recommendation), a keepalive
//! probe is sent on idle connections. If no response comes within the
//! timeout, the transport is marked Dead and the peer is attempted
//! via the next available transport.

use crate::network::transport_hint::{BandwidthClass, TransportType};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Keepalive probe interval in seconds (§5.11).
/// Matches WireGuard's persistent keepalive recommendation.
pub const KEEPALIVE_INTERVAL_SECS: u64 = 25;

/// EMA smoothing factor (alpha ≈ 0.05 means the average adjusts slowly,
/// giving more weight to historical measurements over single data points).
pub const LATENCY_EMA_ALPHA: f32 = 0.05;

// ---------------------------------------------------------------------------
// Health state
// ---------------------------------------------------------------------------

/// The health state of a transport connection.
///
/// Used by the transport solver (§5.10) in Layer 1 constraint elimination:
/// - Live: normal scoring
/// - Degraded: 0.5× reliability score penalty
/// - Dead: eliminated from candidate set entirely
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState {
    /// Transport is working normally.
    Live,
    /// Transport is working but poorly (high latency, packet loss).
    Degraded,
    /// Transport has stopped responding. Teardown pending.
    Dead,
}

// ---------------------------------------------------------------------------
// Transport status
// ---------------------------------------------------------------------------

/// Complete status of a single transport connection.
///
/// This is what the solver sees when deciding which transport to use.
/// It combines the transport type, its health, measured performance,
/// and hardware availability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportStatus {
    /// Which transport this is (Tor, BLE, Clearnet, etc.).
    pub transport: TransportType,

    /// Current health state.
    pub health: HealthState,

    /// Measured latency (exponential moving average, in milliseconds).
    /// None if the transport is new and hasn't been measured yet.
    /// In that case, the solver assumes average latency (0.5 score).
    pub latency_ema: Option<f32>,

    /// Observed bandwidth class.
    /// Starts at the transport's default (§5.11) and is refined by
    /// observing actual transfer speeds.
    pub bandwidth: BandwidthClass,

    /// Whether the hardware for this transport is available.
    /// For example, BLE is only available if the device has a Bluetooth
    /// radio. Tor is only available if the Tor client is running.
    pub hardware_available: bool,
}

impl TransportStatus {
    /// Create a new transport status with default values.
    ///
    /// Hardware availability must be provided — the transport manager
    /// detects this at startup by checking for the relevant hardware/daemon.
    pub fn new(transport: TransportType, hardware_available: bool) -> Self {
        let bandwidth = transport.default_bandwidth();
        Self {
            transport,
            health: if hardware_available {
                HealthState::Live
            } else {
                HealthState::Dead
            },
            latency_ema: None,
            bandwidth,
            hardware_available,
        }
    }

    /// Update the latency EMA with a new measurement.
    ///
    /// Uses exponential moving average: new_ema = alpha * measurement + (1 - alpha) * old_ema.
    /// If this is the first measurement, it becomes the initial value.
    pub fn update_latency(&mut self, measured_ms: f32) {
        self.latency_ema = Some(match self.latency_ema {
            Some(old) => LATENCY_EMA_ALPHA * measured_ms + (1.0 - LATENCY_EMA_ALPHA) * old,
            None => measured_ms, // First measurement becomes the baseline
        });
    }

    /// Compute the reliability score for the solver (0.0 to 1.0).
    ///
    /// Live transports get their EMA-based score.
    /// Degraded transports get half their normal score.
    /// Dead transports get 0 (they're eliminated in Layer 1 anyway).
    pub fn reliability_score(&self) -> f32 {
        match self.health {
            HealthState::Live => self.latency_ema.map(|_| 0.8).unwrap_or(0.5),
            HealthState::Degraded => self.latency_ema.map(|_| 0.4).unwrap_or(0.25),
            HealthState::Dead => 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Health Event (internal monitoring)
// ---------------------------------------------------------------------------

/// An event from the transport health monitor.
///
/// The transport manager emits these as conditions change.
/// The solver subscribes to them to update its scoring.
#[derive(Clone, Debug)]
pub struct TransportHealthEvent {
    /// Which transport this event is about.
    pub transport: TransportType,
    /// What happened.
    pub event: HealthEvent,
    /// When it happened (Unix timestamp).
    pub timestamp: u64,
}

/// Types of health events.
#[derive(Clone, Debug)]
pub enum HealthEvent {
    /// Keepalive probe succeeded. Includes measured round-trip time in ms.
    KeepaliveOk { rtt_ms: f32 },
    /// Keepalive probe timed out.
    KeepaliveTimeout,
    /// Transport-level error (e.g., Tor circuit failed).
    Error(String),
    /// Transport recovered from degraded/dead state.
    Recovered,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_transport_status() {
        let status = TransportStatus::new(TransportType::Tor, true);
        assert_eq!(status.health, HealthState::Live);
        assert!(status.hardware_available);
        assert_eq!(status.latency_ema, None);
    }

    #[test]
    fn test_unavailable_hardware() {
        let status = TransportStatus::new(TransportType::BLE, false);
        assert_eq!(status.health, HealthState::Dead);
        assert!(!status.hardware_available);
    }

    #[test]
    fn test_latency_ema_first_measurement() {
        let mut status = TransportStatus::new(TransportType::Clearnet, true);
        status.update_latency(100.0);
        // First measurement becomes the baseline
        assert_eq!(status.latency_ema, Some(100.0));
    }

    #[test]
    fn test_latency_ema_smoothing() {
        let mut status = TransportStatus::new(TransportType::Clearnet, true);
        status.update_latency(100.0); // Baseline: 100

        // A spike to 200 should only move the EMA slightly
        // (alpha = 0.05, so new = 0.05 * 200 + 0.95 * 100 = 105)
        status.update_latency(200.0);
        let ema = status.latency_ema.unwrap();
        assert!((ema - 105.0).abs() < 0.1, "EMA should be ~105, got {ema}");
    }

    #[test]
    fn test_reliability_scores() {
        let mut live = TransportStatus::new(TransportType::Tor, true);
        live.update_latency(50.0);
        assert!(live.reliability_score() > 0.5);

        let degraded = TransportStatus {
            health: HealthState::Degraded,
            ..TransportStatus::new(TransportType::Tor, true)
        };
        assert!(degraded.reliability_score() < live.reliability_score());

        let dead = TransportStatus {
            health: HealthState::Dead,
            ..TransportStatus::new(TransportType::Tor, true)
        };
        assert_eq!(dead.reliability_score(), 0.0);
    }

    #[test]
    fn test_serde_roundtrip() {
        let status = TransportStatus::new(TransportType::BLE, true);
        let json = serde_json::to_string(&status).unwrap();
        let recovered: TransportStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.transport, TransportType::BLE);
    }
}
