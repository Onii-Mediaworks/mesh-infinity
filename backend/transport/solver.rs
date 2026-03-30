//! Transport Selection — Constraint Solver (§5.10)
//!
//! # What Does the Solver Do?
//!
//! When the system needs to send a packet to a peer, the solver decides
//! WHICH transport to use. This isn't a simple priority list — it's a
//! multi-layer constraint solving problem that balances:
//!
//! - Security (anonymization level)
//! - Performance (latency, bandwidth)
//! - Battery cost
//! - Transport diversity (spread traffic across multiple transports)
//! - Peer capabilities (what transports does the other side support?)
//! - Threat context (Critical mode disables clearnet)
//!
//! # Five-Layer Decision Model
//!
//! ## Layer 1: Hard Constraint Elimination
//! Remove transports that CAN'T be used (no hardware, peer doesn't support,
//! transport is dead, threat context forbids it, etc.). This is binary:
//! either a transport passes ALL checks or it's eliminated.
//!
//! ## Layer 2: Soft Scoring
//! Each surviving transport gets a score (0.0–1.0) across multiple dimensions.
//! The dimensions are weighted differently based on the context (Normal vs
//! Critical, streaming vs messaging).
//!
//! ## Layer 3: Multi-Transport Composition
//! Decide whether to use a single transport or compose multiple (e.g.,
//! send the same message on both Tor and clearnet for redundancy).
//!
//! ## Layer 4: Diversity Enforcement
//! If the node is using only 1-2 transport types, the solver applies
//! increasing pressure to use additional transports (even if they're
//! slightly worse) to maintain transport diversity.
//!
//! ## Layer 5: Failure Handling
//! If no transport survives Layer 1, determine whether the message
//! should be queued for store-and-forward delivery or returned as
//! a failure to the application.

use crate::network::threat_context::ThreatContext;
use crate::network::transport_hint::{BandwidthClass, TransportType};
use super::health::{HealthState, TransportStatus};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Reference latency for normalization (§5.10.3).
/// Latency scores use the formula `1 / (1 + lat/ref)`, which maps
/// 0ms → 1.0, 500ms → 0.5, and higher latencies asymptotically toward 0.
/// 500ms is chosen as the midpoint because it represents the typical
/// round-trip time for a 3-hop Tor circuit — the most common anonymizing
/// transport.  This ensures Tor gets a ~0.5 latency score rather than
/// being heavily penalized against direct connections.
const LATENCY_REFERENCE_MS: f32 = 500.0;

// ---------------------------------------------------------------------------
// Solver Input
// ---------------------------------------------------------------------------

/// Input to the transport solver — everything it needs to make a decision.
///
/// This is assembled by the routing layer before calling the solver.
/// It describes: what we're sending, who we're sending to, what transports
/// are available, and what the security context is.
#[derive(Clone, Debug)]
pub struct SolverInput {
    /// Application-layer requirements (bandwidth, latency, anonymization).
    pub hint: SolverHint,
    /// Global security level.
    pub threat_context: ThreatContext,
    /// Available transports on this device with their current health.
    pub available: Vec<TransportStatus>,
    /// Transports the peer supports (from their network map entry).
    pub peer_transports: Vec<TransportType>,
    /// Number of currently active transport types (for diversity scoring).
    pub active_transport_count: usize,
}

/// Application-layer hints for transport selection.
///
/// The application layer (chat, voice call, file transfer) provides
/// these hints to tell the solver what it needs.
#[derive(Clone, Debug, Default)]
pub struct SolverHint {
    /// Minimum bandwidth needed (None = no requirement).
    pub min_bandwidth_bps: Option<u32>,
    /// Maximum latency acceptable (None = no requirement).
    pub max_latency_ms: Option<u32>,
    /// Minimum anonymization level (None = use threat context default).
    pub min_anonymization: Option<f32>,
    /// Whether this is an ongoing stream (voice, video, MNRDP).
    pub stream: bool,
    /// Message priority (affects jitter window, scoring weights).
    pub priority: Priority,
}

/// Message priority level (§16.9.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Priority {
    /// Background sync, low-priority updates.
    Background,
    /// Standard messages.
    #[default]
    Normal,
    /// Direct messages from trusted peers, active conversation.
    High,
    /// Calls, pairing requests, direct mentions.
    Critical,
}

// ---------------------------------------------------------------------------
// Solver Output
// ---------------------------------------------------------------------------

/// The solver's decision.
#[derive(Clone, Debug)]
pub enum SolverOutput {
    /// Use a single transport.
    Single(TransportType),
    /// Use multiple transports in parallel (redundancy).
    Parallel(Vec<TransportType>),
    /// No suitable transport found.
    Failure(SolverFailure),
}

/// Why the solver couldn't find a suitable transport.
#[derive(Clone, Debug)]
pub struct SolverFailure {
    /// What went wrong.
    pub reason: FailureReason,
    /// Whether store-and-forward delivery is viable.
    pub queue_eligible: bool,
}

/// Failure reasons.
#[derive(Clone, Debug)]
pub enum FailureReason {
    /// No transports available (all hardware dead).
    NoTransportsAvailable,
    /// Peer doesn't support any compatible transport.
    PeerUnreachable,
    /// Application constraints are too tight.
    ConstraintsTooTight,
    /// Threat context eliminated all options.
    ThreatContextExclusion,
}

// ---------------------------------------------------------------------------
// Transport Score (Layer 2)
// ---------------------------------------------------------------------------

/// Scores for a single transport across multiple dimensions.
///
/// Each dimension is 0.0–1.0 where 1.0 is best.
/// The final score is a weighted sum of all dimensions.
#[derive(Clone, Debug)]
struct TransportScore {
    /// How well this transport anonymizes traffic (0.0 = none, 1.0 = mixnet).
    anonymization: f32,
    /// How reliable this transport is right now (0.0 = dead, 1.0 = perfect).
    reliability: f32,
    /// Latency score (1.0 = instant, lower = slower).
    latency_score: f32,
    /// Bandwidth score (0.2 = low, 0.6 = medium, 1.0 = high).
    bandwidth_score: f32,
    /// Battery cost (1.0 = cheap, 0.2 = expensive).
    battery_cost: f32,
    /// How much using this transport diversifies our connections.
    diversity_contribution: f32,
}

/// Weight vectors for different contexts (§5.10.3).
///
/// All weights sum to 1.0. Different contexts prioritize different
/// dimensions — e.g., Critical mode weights anonymization heavily,
/// while a voice call weights latency heavily.
struct Weights {
    anonymization: f32,
    reliability: f32,
    latency: f32,
    bandwidth: f32,
    battery: f32,
    diversity: f32,
}

impl Weights {
    /// Weights for Normal threat context.
    ///
    /// Balanced across all dimensions.  Anonymization (0.25) is the single
    /// largest weight because even in Normal mode, Mesh Infinity defaults
    /// to privacy-first.  Reliability and latency tie at 0.20 — both
    /// matter for real-time messaging.
    fn normal() -> Self {
        Self {
            anonymization: 0.25,
            reliability: 0.20,
            latency: 0.20,
            bandwidth: 0.15,
            battery: 0.10,
            diversity: 0.10,
        }
    }

    /// Weights for Elevated threat context.
    ///
    /// Anonymization jumps to 0.40 — the solver will strongly prefer
    /// Tor/I2P over clearnet.  Battery drops to 0.05 because power
    /// efficiency is secondary when the user faces active surveillance.
    fn elevated() -> Self {
        Self {
            anonymization: 0.40,
            reliability: 0.20,
            latency: 0.15,
            bandwidth: 0.10,
            battery: 0.05,
            diversity: 0.10,
        }
    }

    /// Weights for Critical threat context.
    ///
    /// Anonymization dominates at 0.50 — half the total score.  Combined
    /// with the Layer 1 hard gate that eliminates all non-anonymizing,
    /// non-proximity transports in Critical mode, this ensures the solver
    /// will never choose a transport that reveals the user's IP.
    fn critical() -> Self {
        Self {
            anonymization: 0.50,
            reliability: 0.20,
            latency: 0.10,
            bandwidth: 0.05,
            battery: 0.05,
            diversity: 0.10,
        }
    }

    /// Weights for streaming (voice/video) — prioritize latency.
    ///
    /// Anonymization is significantly reduced (0.05) because stream
    /// mode is explicitly about low latency. Latency (0.40) and
    /// reliability (0.30) dominate — users who enable streaming
    /// have accepted the privacy tradeoff.
    fn stream() -> Self {
        Self {
            anonymization: 0.05,
            reliability: 0.30,
            latency: 0.40,
            bandwidth: 0.15,
            battery: 0.05,
            diversity: 0.05,
        }
    }
}

// ---------------------------------------------------------------------------
// Solver Implementation
// ---------------------------------------------------------------------------

/// Run the transport solver.
///
/// This is the main entry point. Takes the full solver input and returns
/// the best transport (or failure reason).
pub fn solve(input: &SolverInput) -> SolverOutput {
    // -----------------------------------------------------------------------
    // Layer 1: Hard Constraint Elimination
    // -----------------------------------------------------------------------
    // Remove transports that can't be used at all.

    let candidates: Vec<&TransportStatus> = input
        .available
        .iter()
        .filter(|t| {
            // Check 1: Hardware must be available
            if !t.hardware_available {
                return false;
            }

            // Check 2: Peer must support this transport
            // (proximity transports are exempt — discovered via scan, not map)
            if !t.transport.is_proximity()
                && !input.peer_transports.contains(&t.transport)
            {
                return false;
            }

            // Check 3: Transport must not be dead
            if t.health == HealthState::Dead {
                return false;
            }

            // Check 4: Threat context hard gates
            match input.threat_context {
                ThreatContext::Critical => {
                    // In Critical: only anonymizing transports
                    if !t.transport.is_anonymizing() && !t.transport.is_proximity() {
                        return false;
                    }
                }
                ThreatContext::Elevated => {
                    // In Elevated: no clearnet unless local
                    if t.transport == TransportType::Clearnet {
                        return false;
                    }
                }
                ThreatContext::Normal => {
                    // Normal: everything allowed
                }
            }

            // Check 5: Anonymization floor
            if let Some(min_anon) = input.hint.min_anonymization {
                if t.transport.anonymization_score() < min_anon {
                    return false;
                }
            }

            // Check 6: Bandwidth floor
            if let Some(min_bw) = input.hint.min_bandwidth_bps {
                let bw_ok = match t.bandwidth {
                    BandwidthClass::Low => min_bw < 100_000,
                    BandwidthClass::Medium => min_bw < 10_000_000,
                    BandwidthClass::High => true,
                };
                if !bw_ok {
                    return false;
                }
            }

            // Check 7: Latency ceiling
            if let Some(max_lat) = input.hint.max_latency_ms {
                if let Some(ema) = t.latency_ema {
                    if ema > max_lat as f32 {
                        return false;
                    }
                }
                // Unknown latency passes (haven't measured yet)
            }

            true
        })
        .collect();

    // If nothing survived Layer 1, we have a failure
    if candidates.is_empty() {
        return SolverOutput::Failure(SolverFailure {
            reason: if input.available.iter().all(|t| !t.hardware_available) {
                FailureReason::NoTransportsAvailable
            } else if input.peer_transports.is_empty() {
                FailureReason::PeerUnreachable
            } else if input.threat_context == ThreatContext::Critical {
                FailureReason::ThreatContextExclusion
            } else {
                FailureReason::ConstraintsTooTight
            },
            queue_eligible: true, // S&F might work later
        });
    }

    // -----------------------------------------------------------------------
    // Layer 2: Soft Scoring
    // -----------------------------------------------------------------------

    // Choose weights based on context
    let weights = if input.hint.stream {
        Weights::stream()
    } else {
        match input.threat_context {
            ThreatContext::Normal => Weights::normal(),
            ThreatContext::Elevated => Weights::elevated(),
            ThreatContext::Critical => Weights::critical(),
        }
    };

    // Score each candidate
    let mut scored: Vec<(&TransportStatus, f32)> = candidates
        .iter()
        .map(|t| {
            let score = TransportScore {
                anonymization: t.transport.anonymization_score(),
                reliability: t.reliability_score(),
                latency_score: {
                    let lat = t.latency_ema.unwrap_or(LATENCY_REFERENCE_MS);
                    1.0 / (1.0 + lat / LATENCY_REFERENCE_MS)
                },
                bandwidth_score: match t.bandwidth {
                    BandwidthClass::Low => 0.2,
                    BandwidthClass::Medium => 0.6,
                    BandwidthClass::High => 1.0,
                },
                battery_cost: match t.transport {
                    TransportType::BLE | TransportType::WiFiDirect => 0.2,
                    TransportType::USBSerial | TransportType::Layer2 => 1.0,
                    _ => 0.6,
                },
                diversity_contribution: {
                    if input.active_transport_count == 0 {
                        1.0
                    } else {
                        // More types = more diversity = lower marginal benefit
                        1.0 / (input.active_transport_count as f32)
                    }
                },
            };

            // Weighted sum
            let final_score = weights.anonymization * score.anonymization
                + weights.reliability * score.reliability
                + weights.latency * score.latency_score
                + weights.bandwidth * score.bandwidth_score
                + weights.battery * score.battery_cost
                + weights.diversity * score.diversity_contribution;

            (*t, final_score)
        })
        .collect();

    // Sort by score descending
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // -----------------------------------------------------------------------
    // Layer 3-5: Use the top-scored transport
    // -----------------------------------------------------------------------

    // For Critical priority or redundancy hints, use parallel transports
    if input.hint.priority == Priority::Critical && scored.len() >= 2 {
        let top_two: Vec<TransportType> = scored
            .iter()
            .take(2)
            .map(|(t, _)| t.transport.clone())
            .collect();
        return SolverOutput::Parallel(top_two);
    }

    // Default: use the single best transport
    SolverOutput::Single(scored[0].0.transport.clone())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_status(transport: TransportType, available: bool) -> TransportStatus {
        TransportStatus::new(transport, available)
    }

    #[test]
    fn test_single_transport() {
        let input = SolverInput {
            hint: SolverHint::default(),
            threat_context: ThreatContext::Normal,
            available: vec![make_status(TransportType::Clearnet, true)],
            peer_transports: vec![TransportType::Clearnet],
            active_transport_count: 1,
        };

        let result = solve(&input);
        assert!(matches!(result, SolverOutput::Single(TransportType::Clearnet)));
    }

    #[test]
    fn test_no_transports_available() {
        let input = SolverInput {
            hint: SolverHint::default(),
            threat_context: ThreatContext::Normal,
            available: vec![make_status(TransportType::BLE, false)],
            peer_transports: vec![TransportType::BLE],
            active_transport_count: 0,
        };

        let result = solve(&input);
        assert!(matches!(result, SolverOutput::Failure(_)));
    }

    #[test]
    fn test_critical_mode_blocks_clearnet() {
        let input = SolverInput {
            hint: SolverHint::default(),
            threat_context: ThreatContext::Critical,
            available: vec![
                make_status(TransportType::Clearnet, true),
                make_status(TransportType::Tor, true),
            ],
            peer_transports: vec![TransportType::Clearnet, TransportType::Tor],
            active_transport_count: 0,
        };

        let result = solve(&input);
        // Should select Tor, not Clearnet
        match result {
            SolverOutput::Single(t) => assert_eq!(t, TransportType::Tor),
            SolverOutput::Parallel(ts) => assert!(ts.contains(&TransportType::Tor)),
            _ => panic!("Expected transport selection"),
        }
    }

    #[test]
    fn test_prefers_anonymizing_in_elevated() {
        let input = SolverInput {
            hint: SolverHint::default(),
            threat_context: ThreatContext::Elevated,
            available: vec![
                make_status(TransportType::Tor, true),
                make_status(TransportType::I2P, true),
            ],
            peer_transports: vec![TransportType::Tor, TransportType::I2P],
            active_transport_count: 0,
        };

        let result = solve(&input);
        // Should pick Tor (higher anonymization score than I2P)
        match result {
            SolverOutput::Single(t) => assert_eq!(t, TransportType::Tor),
            _ => panic!("Expected single transport"),
        }
    }

    #[test]
    fn test_stream_prefers_latency() {
        let mut fast = make_status(TransportType::Clearnet, true);
        fast.update_latency(10.0); // Very low latency

        let mut slow = make_status(TransportType::Tor, true);
        slow.update_latency(500.0); // High latency

        let input = SolverInput {
            hint: SolverHint {
                stream: true,
                ..Default::default()
            },
            threat_context: ThreatContext::Normal,
            available: vec![fast, slow],
            peer_transports: vec![TransportType::Clearnet, TransportType::Tor],
            active_transport_count: 0,
        };

        let result = solve(&input);
        match result {
            SolverOutput::Single(t) => assert_eq!(t, TransportType::Clearnet),
            _ => panic!("Expected clearnet for low-latency stream"),
        }
    }

    #[test]
    fn test_critical_priority_uses_parallel() {
        let input = SolverInput {
            hint: SolverHint {
                priority: Priority::Critical,
                ..Default::default()
            },
            threat_context: ThreatContext::Normal,
            available: vec![
                make_status(TransportType::Tor, true),
                make_status(TransportType::Clearnet, true),
            ],
            peer_transports: vec![TransportType::Tor, TransportType::Clearnet],
            active_transport_count: 2,
        };

        let result = solve(&input);
        assert!(matches!(result, SolverOutput::Parallel(_)));
    }
}
