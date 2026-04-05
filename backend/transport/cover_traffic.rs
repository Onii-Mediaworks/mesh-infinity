//! Cover Traffic Injection (§6.5, §15.4)
//!
//! # What is Cover Traffic?
//!
//! Cover traffic is synthetic noise injected into transport links to prevent
//! traffic analysis. Without it, a network observer (ISP, hostile relay, or
//! local network attacker) can determine:
//! - **When** a user is communicating (silence = no traffic)
//! - **How much** data is being exchanged (traffic volume correlates with
//!   message count and size)
//! - **With whom** the user is communicating (traffic timing correlation
//!   across multiple observation points)
//!
//! # How it Works
//!
//! The generator uses a **leaky-bucket** algorithm:
//! 1. Time is divided into intervals (derived from the target packet rate).
//! 2. Real packets sent during each interval are counted against the budget.
//! 3. When polled, if fewer real packets have been sent than the target rate
//!    demands, a cover packet is generated to fill the gap.
//! 4. The result: from an observer's perspective, traffic flows at a constant
//!    rate regardless of whether the user is active or idle.
//!
//! # Cover Packet Format
//!
//! Cover packets are filled with cryptographically random bytes (not zeros —
//! all-zeros payloads are trivially distinguishable from encrypted data).
//! They are the same size as real WireGuard-encrypted packets, making them
//! indistinguishable at the network layer. The receiving end discards them
//! after WireGuard decryption reveals they are not valid inner packets.
//!
//! # Jitter
//!
//! A ±10% random variation is applied to the interval duration to prevent
//! timing fingerprinting. Without jitter, the perfectly regular cadence of
//! cover packets would itself be a fingerprint distinguishing cover-only
//! periods from mixed real+cover periods (where real traffic introduces
//! natural variation).
//!
//! # Threat Context Integration
//!
//! Cover traffic is disabled in `ThreatContext::Normal` to save bandwidth
//! and battery. It is enabled automatically in `Elevated` and `Critical`
//! threat contexts, where the privacy benefit outweighs the cost.
//!
//! # Spec References
//!
//! - §6.5: Persistent tunnels carry "real traffic, cover traffic, and
//!   topology gossip — indistinguishably mixed."
//! - §15.4.1: "When no real traffic exists, synthetic WireGuard packets
//!   of exactly MTU bytes are generated at the target rate."
//! - §15.4.4 step 7: "If no real frames pending: generate cover traffic
//!   frame (random bytes, path MTU size) and transmit."

use std::time::{Duration, Instant};

use rand::RngExt;

// ---------------------------------------------------------------------------
// Constants — defaults for cover traffic generation
// ---------------------------------------------------------------------------

/// Default target rate: 2 packets per second.
/// This balances bandwidth cost against traffic analysis resistance.
/// At 1024-byte packets, this consumes ~2 KiB/s (~16 kbit/s) — negligible
/// on modern connections but sufficient to mask idle/active transitions.
pub const DEFAULT_RATE_PPS: f64 = 2.0;

/// Default cover packet size in bytes.
/// Matches typical WireGuard-encrypted packet size. In production, this
/// should be set to the negotiated path MTU (§15.4.2) for the specific
/// transport link so that cover packets are indistinguishable from real ones.
pub const DEFAULT_PACKET_SIZE: usize = 1024;

/// Jitter magnitude: ±10% random variation on interval timing.
/// This prevents timing fingerprinting of the cover traffic cadence.
/// The value 0.10 means the interval can vary from 90% to 110% of nominal.
const JITTER_FRACTION: f64 = 0.10;

// ---------------------------------------------------------------------------
// CoverTrafficConfig — user-facing configuration knobs
// ---------------------------------------------------------------------------

/// Configuration for cover traffic generation on a single transport link.
///
/// Each active WireGuard tunnel maintains its own `CoverTrafficConfig`,
/// because different links may have different path MTUs and different
/// bandwidth budgets. A high-bandwidth Ethernet link might tolerate a
/// higher rate; a metered cellular link might use a lower rate.
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    /// Target packet rate in packets per second.
    /// Real packets count against this budget — cover packets fill the gap.
    /// For example, at 2.0 pps: if 1 real packet was sent this interval,
    /// only 1 cover packet is needed to meet the target.
    pub target_rate_pps: f64,

    /// Size of each cover packet in bytes.
    /// Should match the negotiated path MTU so that cover packets are
    /// indistinguishable from real packets by size alone (§15.4.2).
    pub packet_size: usize,

    /// Whether cover traffic is currently enabled.
    /// Disabled in `ThreatContext::Normal`, enabled in `Elevated`/`Critical`.
    pub enabled: bool,
}

impl Default for CoverTrafficConfig {
    /// Sensible defaults: 2 pps, 1024-byte packets, disabled by default.
    /// The caller enables cover traffic when threat context rises above Normal.
    fn default() -> Self {
        Self {
            target_rate_pps: DEFAULT_RATE_PPS,
            packet_size: DEFAULT_PACKET_SIZE,
            enabled: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CoverTrafficGenerator — per-link stateful cover traffic engine
// ---------------------------------------------------------------------------

/// Per-link cover traffic state machine.
///
/// One instance exists for each active transport link (WireGuard tunnel).
/// The poll loop calls `poll_cover_packet()` on every cycle; the generator
/// tracks real packet counts and fills the gap with cover packets to
/// maintain a constant observable rate.
///
/// # Lifecycle
///
/// 1. Created when a transport link is established (`new(config)`).
/// 2. Every time a real packet is sent on this link, call `record_real_packet()`.
/// 3. On every poll cycle, call `poll_cover_packet()`:
///    - Returns `Some(bytes)` if a cover packet is due.
///    - Returns `None` if the real traffic rate already meets the target.
/// 4. When the link is torn down, the generator is dropped.
pub struct CoverTrafficGenerator {
    /// Current configuration (rate, size, enabled/disabled).
    config: CoverTrafficConfig,

    /// How many real packets were sent during the current interval.
    /// Reset to zero when the interval rolls over.
    real_packets_this_interval: u32,

    /// How many cover packets were already sent during the current interval.
    /// Reset to zero when the interval rolls over.
    cover_packets_this_interval: u32,

    /// Timestamp when the current interval started.
    /// Used to determine when the interval has elapsed.
    interval_start: Instant,

    /// Duration of the current interval (includes jitter).
    /// Recomputed with fresh jitter each time the interval rolls over.
    interval_duration: Duration,
}

impl CoverTrafficGenerator {
    /// Create a new generator with the given configuration.
    ///
    /// The generator starts in whatever enabled/disabled state the config
    /// specifies. The first interval begins immediately.
    pub fn new(config: CoverTrafficConfig) -> Self {
        // Compute the initial interval duration from the config's target rate.
        // Includes jitter so even the first interval is not a precise multiple.
        let interval_duration = compute_jittered_interval(config.target_rate_pps);

        Self {
            config,
            real_packets_this_interval: 0,
            cover_packets_this_interval: 0,
            interval_start: Instant::now(),
            interval_duration,
        }
    }

    /// Notify the generator that a real packet was sent on this link.
    ///
    /// This counts against the cover traffic budget: if the real traffic
    /// rate already meets or exceeds the target, no cover packets are needed.
    /// Called by the transport layer each time it transmits a real payload.
    pub fn record_real_packet(&mut self) {
        // Saturating add prevents overflow if somehow billions of packets
        // are sent in a single interval (shouldn't happen, but defensive).
        self.real_packets_this_interval = self.real_packets_this_interval.saturating_add(1);
    }

    /// Check whether a cover packet should be sent right now.
    ///
    /// Returns `Some(Vec<u8>)` containing a cover packet if one is due,
    /// or `None` if no cover packet is needed at this moment.
    ///
    /// # Algorithm
    ///
    /// 1. If disabled, return None immediately.
    /// 2. If the current interval has elapsed, roll over to a new interval.
    /// 3. Compute how many total packets (real + cover) should have been sent
    ///    by now, proportional to how far through the interval we are.
    /// 4. If real + already-sent-cover packets are below that target, generate
    ///    and return a cover packet.
    /// 5. Otherwise, return None.
    pub fn poll_cover_packet(&mut self) -> Option<Vec<u8>> {
        // Disabled generators never produce cover packets.
        if !self.config.enabled {
            return None;
        }

        // Zero or negative rate means no cover traffic desired.
        if self.config.target_rate_pps <= 0.0 {
            return None;
        }

        let now = Instant::now();

        // Check whether the current interval has elapsed.
        // If so, roll over: reset counters and start a new interval
        // with fresh jitter applied to the duration.
        if now.duration_since(self.interval_start) >= self.interval_duration {
            self.roll_over_interval(now);
        }

        // Calculate how far through the current interval we are (0.0 to 1.0).
        // This determines how many packets should have been sent by now.
        let elapsed = now.duration_since(self.interval_start);
        let progress = elapsed.as_secs_f64() / self.interval_duration.as_secs_f64();

        // Target packets so far = total interval budget × progress fraction.
        // The budget for one interval is target_rate_pps × interval_duration_secs.
        // We use max(1, ...) to ensure at least one packet is expected at any
        // non-zero point in the interval — without this, ceil(budget * 0.0) = 0
        // right after rollover, causing the generator to miss the first packet.
        let interval_secs = self.interval_duration.as_secs_f64();
        let total_budget = self.config.target_rate_pps * interval_secs;
        let computed = (total_budget * progress).ceil() as u32;
        let target_so_far = if total_budget >= 1.0 {
            computed.max(1)
        } else {
            computed
        };

        // How many packets (real + cover) have actually been sent so far.
        let sent_so_far = self
            .real_packets_this_interval
            .saturating_add(self.cover_packets_this_interval);

        // If we've already met the target, no cover packet needed.
        if sent_so_far >= target_so_far {
            return None;
        }

        // Generate a cover packet: random bytes at the configured size.
        // Track it so we don't overshoot the target on subsequent polls.
        self.cover_packets_this_interval = self.cover_packets_this_interval.saturating_add(1);
        Some(generate_random_payload(self.config.packet_size))
    }

    /// Enable or disable cover traffic generation.
    ///
    /// When transitioning from disabled to enabled, the interval is reset
    /// so that cover traffic starts fresh rather than trying to "catch up"
    /// for the time it was disabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        // Detect disabled → enabled transition for interval reset.
        let was_disabled = !self.config.enabled;
        self.config.enabled = enabled;

        // On enable, reset the interval so cover traffic starts cleanly.
        // Without this, the generator might try to "catch up" for time
        // spent disabled, sending a burst of cover packets.
        if was_disabled && enabled {
            self.roll_over_interval(Instant::now());
        }
    }

    /// Update the target packet rate.
    ///
    /// Takes effect on the next interval rollover. The current interval
    /// continues with its existing budget to avoid mid-interval rate jumps
    /// that could create observable discontinuities.
    pub fn set_rate(&mut self, pps: f64) {
        self.config.target_rate_pps = pps;
    }

    /// Returns a read-only reference to the current configuration.
    /// Useful for logging, diagnostics, and UI display.
    pub fn config(&self) -> &CoverTrafficConfig {
        &self.config
    }

    /// Returns whether the generator is currently enabled.
    /// Convenience accessor that avoids exposing the full config.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Roll over to a new interval: reset packet counters and recompute
    /// the interval duration with fresh jitter.
    ///
    /// `now` is passed in to avoid a redundant `Instant::now()` call
    /// (the caller already has the current time).
    fn roll_over_interval(&mut self, now: Instant) {
        self.real_packets_this_interval = 0;
        self.cover_packets_this_interval = 0;
        self.interval_start = now;
        // Recompute interval with fresh jitter for this new period.
        self.interval_duration = compute_jittered_interval(self.config.target_rate_pps);
    }
}

// ---------------------------------------------------------------------------
// Free functions — interval computation and payload generation
// ---------------------------------------------------------------------------

/// Compute a jittered interval duration from the target packets-per-second rate.
///
/// The base interval is `1.0 / rate` seconds (time between packets at
/// constant rate). Jitter of ±`JITTER_FRACTION` (±10%) is applied using
/// a thread-local CSPRNG to prevent timing fingerprinting.
///
/// # Returns
///
/// A `Duration` representing the jittered interval. If `rate` is zero or
/// negative, returns a very large duration (effectively disabling output).
fn compute_jittered_interval(rate: f64) -> Duration {
    // Guard against zero/negative rate: return a long interval that
    // effectively produces no packets (polled but never triggers).
    if rate <= 0.0 {
        return Duration::from_secs(3600);
    }

    // Base interval: time between packets at the target constant rate.
    let base_secs = 1.0 / rate;

    // Generate jitter: uniform random in [-JITTER_FRACTION, +JITTER_FRACTION].
    // Using thread_rng() which is a CSPRNG on all supported platforms.
    let mut rng = rand::rng();
    let jitter_factor: f64 = rng.random_range((1.0 - JITTER_FRACTION)..=(1.0 + JITTER_FRACTION));

    // Apply jitter to the base interval.
    let jittered_secs = base_secs * jitter_factor;

    // Clamp to a minimum of 1 microsecond to prevent zero-duration intervals
    // that would spin the poll loop at 100% CPU.
    Duration::from_secs_f64(jittered_secs.max(0.000_001))
}

/// Generate a cover packet payload of `size` bytes filled with
/// cryptographically random data.
///
/// # Why Random Bytes?
///
/// All-zeros payloads are trivially distinguishable from ChaCha20-encrypted
/// data (which appears uniformly random). Using CSPRNG output ensures cover
/// packets are statistically indistinguishable from real encrypted payloads
/// at the byte level.
fn generate_random_payload(size: usize) -> Vec<u8> {
    // Allocate the buffer and fill with random bytes in one pass.
    let mut payload = vec![0u8; size];
    rand::fill(&mut payload[..]);
    payload
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// Helper: create a generator with cover traffic enabled at the given rate.
    fn enabled_generator(rate: f64, packet_size: usize) -> CoverTrafficGenerator {
        CoverTrafficGenerator::new(CoverTrafficConfig {
            target_rate_pps: rate,
            packet_size,
            enabled: true,
        })
    }

    /// Helper: create a generator with cover traffic disabled.
    fn disabled_generator() -> CoverTrafficGenerator {
        CoverTrafficGenerator::new(CoverTrafficConfig {
            target_rate_pps: DEFAULT_RATE_PPS,
            packet_size: DEFAULT_PACKET_SIZE,
            enabled: false,
        })
    }

    // -----------------------------------------------------------------------
    // Test 1: Cover packets generated when no real traffic
    // -----------------------------------------------------------------------

    /// When no real packets are sent, the generator must produce cover
    /// packets to fill the entire budget. After one full interval elapses,
    /// polling should yield at least one cover packet.
    #[test]
    fn cover_packets_generated_when_idle() {
        // Use a high rate (100 pps) so the interval is short (~10ms)
        // and we don't need to sleep long to trigger packet generation.
        // Poll in a loop to account for timing variance on loaded CI systems.
        let mut gen = enabled_generator(100.0, 512);

        let mut got_packet = false;
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(10));
            if gen.poll_cover_packet().is_some() {
                got_packet = true;
                break;
            }
        }
        assert!(
            got_packet,
            "Expected a cover packet when no real traffic was sent"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2: Cover packets suppressed when real traffic meets target rate
    // -----------------------------------------------------------------------

    /// When enough real packets are recorded to meet the target rate,
    /// the generator should NOT produce any cover packets — real traffic
    /// already provides sufficient cover.
    #[test]
    fn cover_suppressed_when_real_traffic_sufficient() {
        // Rate = 2 pps, so 1 interval ≈ 500ms.
        // If we record enough real packets to fill the budget, no covers needed.
        let mut gen = enabled_generator(2.0, 256);

        // Record more real packets than the interval budget demands.
        // At 2 pps with a ~500ms interval, the budget is ~1 packet.
        // Recording 5 real packets far exceeds any reasonable budget.
        for _ in 0..5 {
            gen.record_real_packet();
        }

        // Poll immediately (within the same interval) — should get None
        // because real traffic already exceeds the target.
        let packet = gen.poll_cover_packet();
        assert!(
            packet.is_none(),
            "Expected no cover packet when real traffic exceeds target"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: Cover packets have the correct size
    // -----------------------------------------------------------------------

    /// Cover packets must be exactly `packet_size` bytes — no more, no less.
    /// Size mismatches would allow an observer to distinguish cover from real.
    #[test]
    fn cover_packet_has_correct_size() {
        // Use multiple sizes to verify the size is configurable.
        for &size in &[64, 256, 1024, 1400, 4096] {
            let mut gen = enabled_generator(100.0, size);

            // Sleep to ensure the interval demands a packet.
            thread::sleep(Duration::from_millis(15));

            if let Some(packet) = gen.poll_cover_packet() {
                assert_eq!(
                    packet.len(),
                    size,
                    "Cover packet size mismatch: expected {}, got {}",
                    size,
                    packet.len()
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: Jitter is within ±10% bounds
    // -----------------------------------------------------------------------

    /// The jittered interval must stay within [base * 0.90, base * 1.10].
    /// We test this by generating many intervals and checking bounds.
    #[test]
    fn jitter_within_bounds() {
        let rate = 10.0; // base interval = 100ms
        let base_secs = 1.0 / rate;
        let min_secs = base_secs * (1.0 - JITTER_FRACTION); // 90ms
        let max_secs = base_secs * (1.0 + JITTER_FRACTION); // 110ms

        // Generate 1000 intervals and verify every one is in bounds.
        for _ in 0..1000 {
            let interval = compute_jittered_interval(rate);
            let secs = interval.as_secs_f64();

            assert!(
                secs >= min_secs - 1e-9 && secs <= max_secs + 1e-9,
                "Jittered interval {:.6}s out of bounds [{:.6}, {:.6}]",
                secs,
                min_secs,
                max_secs
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: Disabled generator produces no packets
    // -----------------------------------------------------------------------

    /// A disabled generator must never produce cover packets, regardless
    /// of how much time passes or how many times it is polled.
    #[test]
    fn disabled_generator_produces_no_packets() {
        let mut gen = disabled_generator();

        // Sleep to let time pass, then poll multiple times.
        thread::sleep(Duration::from_millis(50));

        // Poll 100 times — should always get None.
        for i in 0..100 {
            let packet = gen.poll_cover_packet();
            assert!(
                packet.is_none(),
                "Disabled generator produced a packet on poll {}",
                i
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: Rate changes take effect
    // -----------------------------------------------------------------------

    /// After calling `set_rate()`, the generator should use the new rate
    /// on the next interval. We verify by changing to zero rate (which
    /// should stop cover traffic) and to a high rate (which should produce it).
    #[test]
    fn rate_changes_take_effect() {
        // Start with high rate to confirm packets are generated.
        // Poll in a loop to account for timing variance on loaded systems.
        let mut gen = enabled_generator(100.0, 128);
        let mut got_packet = false;
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(10));
            if gen.poll_cover_packet().is_some() {
                got_packet = true;
                break;
            }
        }
        assert!(
            got_packet,
            "Expected cover packet at high rate before rate change"
        );

        // Change to zero rate — should stop generating.
        gen.set_rate(0.0);

        // Force a rollover by waiting and polling so the new rate takes effect.
        thread::sleep(Duration::from_millis(50));

        // With zero rate, polling should return None.
        // Poll multiple times to ensure no packets leak through.
        for _ in 0..10 {
            let packet = gen.poll_cover_packet();
            assert!(
                packet.is_none(),
                "Expected no cover packet after setting rate to zero"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: Default config has expected values
    // -----------------------------------------------------------------------

    /// Verify the Default implementation produces the documented defaults:
    /// 2 pps, 1024 bytes, disabled.
    #[test]
    fn default_config_values() {
        let config = CoverTrafficConfig::default();
        assert_eq!(config.target_rate_pps, DEFAULT_RATE_PPS);
        assert_eq!(config.packet_size, DEFAULT_PACKET_SIZE);
        assert!(!config.enabled, "Default config should be disabled");
    }

    // -----------------------------------------------------------------------
    // Test 8: Cover packets contain random data (not all zeros)
    // -----------------------------------------------------------------------

    /// Cover packets must contain random bytes, not a fixed pattern.
    /// All-zeros would be trivially distinguishable from encrypted data.
    /// We check that at least some bytes are non-zero (a 1024-byte
    /// all-zeros payload from a CSPRNG has probability 2^-8192, so
    /// this test is deterministic in practice).
    #[test]
    fn cover_packets_contain_random_data() {
        let payload = generate_random_payload(1024);

        // Verify the payload is not all zeros.
        let non_zero_count = payload.iter().filter(|&&b| b != 0).count();
        assert!(
            non_zero_count > 0,
            "Cover packet payload should not be all zeros"
        );

        // Verify there's actual randomness: at least 10% of bytes
        // should be non-zero (expected ~99.6% for uniform random).
        assert!(
            non_zero_count > payload.len() / 10,
            "Cover packet should have substantial randomness, got {} non-zero out of {}",
            non_zero_count,
            payload.len()
        );
    }

    // -----------------------------------------------------------------------
    // Test 9: Enable/disable transitions reset interval state
    // -----------------------------------------------------------------------

    /// When re-enabling cover traffic after it was disabled, the generator
    /// should start a fresh interval rather than trying to catch up for
    /// the disabled period (which would cause a burst of cover packets).
    #[test]
    fn enable_resets_interval() {
        // Create enabled, then disable.
        let mut gen = enabled_generator(2.0, 256);
        gen.set_enabled(false);

        // Wait a long time (relative to the interval).
        thread::sleep(Duration::from_millis(600));

        // Re-enable. If the interval wasn't reset, the generator would
        // think it needs to catch up for 600ms of missed cover traffic.
        gen.set_enabled(true);

        // The first poll after re-enable should behave normally: at most
        // one packet, not a burst. At 2 pps with a fresh ~500ms interval,
        // immediate poll after enable should produce 0 or 1 packets.
        let mut count = 0;
        for _ in 0..10 {
            if gen.poll_cover_packet().is_some() {
                count += 1;
            }
        }

        // Should not have produced more than 2 packets (budget for one interval).
        assert!(
            count <= 2,
            "Expected at most 2 packets after re-enable, got {} (burst detected)",
            count
        );
    }

    // -----------------------------------------------------------------------
    // Test 10: Zero-rate edge case
    // -----------------------------------------------------------------------

    /// A generator with zero rate should never produce packets, even when
    /// enabled. Zero rate means "no cover traffic desired."
    #[test]
    fn zero_rate_produces_no_packets() {
        let mut gen = enabled_generator(0.0, 256);

        // Sleep and poll.
        thread::sleep(Duration::from_millis(50));
        for _ in 0..10 {
            assert!(
                gen.poll_cover_packet().is_none(),
                "Zero-rate generator should not produce packets"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: Accessor methods return correct state
    // -----------------------------------------------------------------------

    /// Verify that `config()` and `is_enabled()` reflect mutations.
    #[test]
    fn accessor_methods() {
        let mut gen = disabled_generator();

        // Initially disabled.
        assert!(!gen.is_enabled());
        assert_eq!(gen.config().target_rate_pps, DEFAULT_RATE_PPS);

        // Enable and change rate.
        gen.set_enabled(true);
        gen.set_rate(5.0);
        assert!(gen.is_enabled());
        assert_eq!(gen.config().target_rate_pps, 5.0);
    }
}
