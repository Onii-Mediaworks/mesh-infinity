//! Software-Defined Radio (SDR) Transport Stack
//!
//! # Architecture
//!
//! The RF/SDR transport layer treats ALL radio communication as software-defined.
//! Dedicated hardware (LoRa chips, HF radios, Meshtastic nodes) are hardware
//! profiles that implement the [`SdrDriver`] trait with limited configurability.
//! Full SDR devices (HackRF, LimeSDR, PlutoSDR, ADALM-PLUTO, RTL-SDR) implement
//! the full trait and can be dynamically reconfigured across the entire spectrum.
//!
//! ```text
//! Application layer (encrypted mesh packet)
//!     ↓
//! SDR framing (preamble, sync word, CRC, FEC)
//!     ↓
//! Modulation (LoRa / FSK / GMSK / BPSK / QPSK / OFDM / etc.)
//!     ↓
//! Channel / frequency selection (static, ALE, or FHSS hop)
//!     ↓
//! Hardware driver (SoapySDR / LimeSuite / RTL-SDR / LoRa chip / etc.)
//!     ↓
//! Antenna
//! ```
//!
//! # Radio Profiles
//!
//! Three named profiles cover the primary use cases:
//!
//! - **Secure** — FHSS with short burst windows, AES-SIV framing, 100ms hop dwell.
//!   Maximally resistant to interception and direction-finding.
//!   Bandwidth: ~1–5 kbps. Range: depends on band.
//!
//! - **LongRange** — LoRa SF12 or HF SSB, narrow bandwidth, maximum link budget.
//!   Best for reaching very distant peers (10–2000km depending on band).
//!   Bandwidth: ~250bps–1kbps. Range: regional to global (HF).
//!
//! - **Evasive** — ALE-style automatic link establishment with rapid band-hopping.
//!   Dwell time randomized (50–500ms). Frequency selected by spectrum sensing.
//!   No fixed channel, no predictable pattern.
//!
//! - **Balanced** — Moderate FHSS, medium bandwidth, best for normal operation.
//!   Good range, reasonable throughput, moderate evasion.
//!
//! # Frequency Hopping Spread Spectrum (FHSS)
//!
//! FHSS synchronization uses a shared hop key (derived from the X3DH session
//! key via HKDF) to generate a pseudo-random hop sequence. Both sides maintain
//! a synchronized epoch counter. The hop table is:
//!
//! ```text
//! epoch_freq[i] = HopTable[HMAC-SHA256(hop_key, epoch || i) mod table_len]
//! ```
//!
//! The epoch advances every `dwell_ms` milliseconds. A ±2 epoch guard window
//! tolerates clock drift of up to 2× dwell_ms.
//!
//! # Automatic Link Establishment (ALE)
//!
//! ALE (MIL-STD-188-141B / FED-STD-1045A compatible) is used on HF bands to
//! automatically negotiate a working frequency. The ALE controller:
//! 1. Scans the pre-programmed channel list for the peer's ALE address
//! 2. Calls the peer on the best-scored channel
//! 3. Links — both sides lock to that channel for the session
//! 4. On link failure, automatically re-links on the next best channel
//!
//! # Spectrum Sensing
//!
//! Before transmitting, the SDR performs a Clear Channel Assessment (CCA):
//! - Measure received signal strength (RSSI) on the target channel
//! - If RSSI > `cca_threshold_dbm`, wait up to `cca_backoff_ms`
//! - If channel remains busy, move to next channel in hop table
//!   This avoids co-channel interference and aids in evasion.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Frequency Bands
// ---------------------------------------------------------------------------

/// ITU frequency band designations covering the full usable SDR spectrum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrequencyBand {
    /// Medium Frequency (300 kHz – 3 MHz). AM broadcast band, some amateur.
    Mf,
    /// High Frequency (3 – 30 MHz). Ionospheric skip, global range.
    Hf,
    /// Very High Frequency (30 – 300 MHz). Line-of-sight, 20–150km.
    Vhf,
    /// Ultra High Frequency (300 MHz – 3 GHz). Urban/suburban, ISM bands.
    Uhf,
    /// Super High Frequency (3 – 30 GHz). Short range, high bandwidth.
    Shf,
    /// Extremely High Frequency (30 – 300 GHz). Millimeter wave, experimental.
    Ehf,
}

impl FrequencyBand {
    /// Minimum frequency in Hz.
    pub fn min_hz(&self) -> u64 {
        match self {
            Self::Mf => 300_000,
            Self::Hf => 3_000_000,
            Self::Vhf => 30_000_000,
            Self::Uhf => 300_000_000,
            Self::Shf => 3_000_000_000,
            Self::Ehf => 30_000_000_000,
        }
    }

    /// Maximum frequency in Hz.
    pub fn max_hz(&self) -> u64 {
        match self {
            Self::Mf => 3_000_000,
            Self::Hf => 30_000_000,
            Self::Vhf => 300_000_000,
            Self::Uhf => 3_000_000_000,
            Self::Shf => 30_000_000_000,
            Self::Ehf => 300_000_000_000,
        }
    }

    /// Determine the band for a given frequency.
    pub fn classify(freq_hz: u64) -> Option<Self> {
        match freq_hz {
            300_000..=2_999_999 => Some(Self::Mf),
            3_000_000..=29_999_999 => Some(Self::Hf),
            30_000_000..=299_999_999 => Some(Self::Vhf),
            300_000_000..=2_999_999_999 => Some(Self::Uhf),
            3_000_000_000..=29_999_999_999 => Some(Self::Shf),
            30_000_000_000..=300_000_000_000 => Some(Self::Ehf),
            _ => None,
        }
    }

    /// Whether this band supports long-range ionospheric propagation.
    pub fn supports_skywave(&self) -> bool {
        matches!(self, Self::Hf | Self::Mf)
    }

    /// Whether this band is ISM (license-free in most jurisdictions).
    pub fn has_ism_channels(&self) -> bool {
        // ISM bands exist across VHF/UHF/SHF (433MHz, 868MHz, 915MHz, 2.4GHz, 5.8GHz)
        matches!(self, Self::Vhf | Self::Uhf | Self::Shf)
    }
}

// ---------------------------------------------------------------------------
// Modulation Types
// ---------------------------------------------------------------------------

/// Radio modulation scheme.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Modulation {
    // Analog-heritage digital modes
    /// Frequency Shift Keying (FSK). Simple, low SNR requirement.
    /// Used in: narrowband digital radio, POCSAG, APRS.
    Fsk { deviation_hz: u32 },
    /// Gaussian FSK (GFSK). Filtered FSK for reduced spectral splatter.
    /// Used in: Bluetooth, DECT.
    Gfsk { deviation_hz: u32, bt: f32 },
    /// Gaussian Minimum Shift Keying (GMSK). Constant-envelope, spectral efficient.
    /// Used in: GSM, TETRA, DMR.
    Gmsk { bandwidth_hz: u32 },
    /// Single-Sideband (SSB/USB/LSB). HF standard for voice and digital modes.
    Ssb { upper_sideband: bool },
    /// Amplitude Modulation (AM). Legacy, for interop.
    Am,

    // Phase / quadrature
    /// Binary Phase Shift Keying (BPSK). 1 bit/symbol, robust at low SNR.
    Bpsk,
    /// Quadrature Phase Shift Keying (QPSK). 2 bits/symbol, balanced.
    Qpsk,
    /// 8PSK. 3 bits/symbol. Used in satellite modems.
    Psk8,
    /// 16QAM. 4 bits/symbol. Requires higher SNR.
    Qam16,
    /// 64QAM. 6 bits/symbol. High bandwidth, needs strong signal.
    Qam64,
    /// 256QAM. 8 bits/symbol. Used in cable/broadband, very high SNR required.
    Qam256,

    // Spread spectrum
    /// LoRa chirp spread spectrum (CSS). Up to +20dB over noise floor.
    /// Spreading factor 6–12 (SF12 = longest range, lowest rate).
    LoRaCss {
        spreading_factor: u8,
        coding_rate: LoRaCodingRate,
    },
    /// Direct Sequence Spread Spectrum (DSSS). 802.11b, GPS-like.
    Dsss { chip_rate_mcps: f32 },

    // Multicarrier
    /// Orthogonal Frequency Division Multiplexing (OFDM). WiFi, LTE.
    Ofdm { subcarriers: u32, cp_ratio: f32 },

    // Custom / raw
    /// Raw IQ samples passed directly to driver. For experimentation.
    RawIq {
        sample_rate_hz: u32,
        bits_per_sample: u8,
    },
}

/// LoRa forward error correction coding rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoRaCodingRate {
    /// 4/5 — lowest overhead, highest throughput.
    Cr45,
    /// 4/6.
    Cr46,
    /// 4/7.
    Cr47,
    /// 4/8 — maximum redundancy, most robust.
    Cr48,
}

impl LoRaCodingRate {
    /// Overhead fraction (e.g. 0.2 for 4/5).
    pub fn overhead(&self) -> f32 {
        match self {
            Self::Cr45 => 0.20,
            Self::Cr46 => 0.33,
            Self::Cr47 => 0.43,
            Self::Cr48 => 0.50,
        }
    }
}

// ---------------------------------------------------------------------------
// Channel Configuration
// ---------------------------------------------------------------------------

/// A single radio channel definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadioChannel {
    /// Center frequency in Hz.
    pub freq_hz: u64,
    /// Channel bandwidth in Hz.
    pub bandwidth_hz: u32,
    /// Modulation scheme.
    pub modulation: Modulation,
    /// Transmit power in dBm (None = use device default).
    pub tx_power_dbm: Option<i8>,
    /// Human-readable label for this channel (e.g. "433MHz ISM", "7.074MHz FT8").
    pub label: String,
}

impl RadioChannel {
    /// Approximate maximum raw data rate in bits per second (before FEC/framing overhead).
    pub fn approx_data_rate_bps(&self) -> u32 {
        match &self.modulation {
            Modulation::Fsk { deviation_hz } => {
                // Rough: baud rate ≈ bandwidth / 2
                (self.bandwidth_hz / 2).min(*deviation_hz * 4)
            }
            Modulation::Gfsk { deviation_hz, .. } => (self.bandwidth_hz / 2).min(*deviation_hz * 4),
            Modulation::Gmsk { .. } => self.bandwidth_hz / 2,
            Modulation::Ssb { .. } => 3_000, // ~3kHz voice bandwidth → ~3kbps digital
            Modulation::Am => 1_000,
            Modulation::Bpsk => self.bandwidth_hz,
            Modulation::Qpsk => self.bandwidth_hz * 2,
            Modulation::Psk8 => self.bandwidth_hz * 3,
            Modulation::Qam16 => self.bandwidth_hz * 4,
            Modulation::Qam64 => self.bandwidth_hz * 6,
            Modulation::Qam256 => self.bandwidth_hz * 8,
            Modulation::LoRaCss {
                spreading_factor,
                coding_rate,
            } => {
                // LoRa data rate = SF * (BW / 2^SF) * (4 / (4 + cr_num))
                let sf = *spreading_factor as f64;
                let bw = self.bandwidth_hz as f64;
                let cr = 4.0 / (4.0 + coding_rate.overhead() as f64 * 4.0);
                let rate = sf * (bw / (1u64 << spreading_factor) as f64) * cr;
                rate.max(100.0) as u32
            }
            Modulation::Dsss { chip_rate_mcps } => (*chip_rate_mcps * 1_000_000.0) as u32 / 11,
            Modulation::Ofdm { subcarriers, .. } => self.bandwidth_hz * subcarriers / 1024,
            Modulation::RawIq {
                sample_rate_hz,
                bits_per_sample,
            } => {
                *sample_rate_hz * *bits_per_sample as u32 * 2 // IQ = 2 components
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FHSS Configuration
// ---------------------------------------------------------------------------

/// Frequency Hopping Spread Spectrum (FHSS) configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FhssConfig {
    /// The set of channels to hop across.
    /// Must be agreed between both parties before session establishment.
    pub hop_table: Vec<RadioChannel>,
    /// How long to dwell on each channel (milliseconds).
    /// Shorter = harder to track; longer = better throughput.
    pub dwell_ms: u32,
    /// Clock tolerance guard window in epochs.
    /// Both sides accept messages from current_epoch ± guard_epochs.
    pub guard_epochs: u8,
    /// Hop key (32 bytes, derived from X3DH session key via HKDF).
    /// Used to generate the pseudo-random hop sequence.
    #[serde(with = "hex_bytes")]
    pub hop_key: [u8; 32],
}

impl FhssConfig {
    /// Compute the channel index for a given epoch.
    ///
    /// Uses HMAC-SHA256(hop_key, epoch_be_bytes) mod table_len.
    pub fn channel_for_epoch(&self, epoch: u64) -> usize {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(&self.hop_key).expect("HMAC can accept any key size");
        mac.update(&epoch.to_be_bytes());
        let result = mac.finalize().into_bytes();

        // Use first 4 bytes as u32 for the table index
        let idx = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
        (idx as usize) % self.hop_table.len()
    }

    /// Current epoch based on system time and dwell_ms.
    pub fn current_epoch(&self) -> u64 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now_ms / self.dwell_ms as u64
    }

    /// Current channel (for the current epoch).
    pub fn current_channel(&self) -> Option<&RadioChannel> {
        if self.hop_table.is_empty() {
            return None;
        }
        let epoch = self.current_epoch();
        let idx = self.channel_for_epoch(epoch);
        self.hop_table.get(idx)
    }

    /// Channels valid for reception in the guard window
    /// (current epoch ± guard_epochs).
    pub fn receive_channels(&self) -> Vec<(u64, &RadioChannel)> {
        if self.hop_table.is_empty() {
            return vec![];
        }
        let epoch = self.current_epoch();
        let guard = self.guard_epochs as u64;
        let start = epoch.saturating_sub(guard);
        let end = epoch.saturating_add(guard);
        (start..=end)
            .map(|e| {
                let idx = self.channel_for_epoch(e);
                (e, &self.hop_table[idx])
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ALE (Automatic Link Establishment)
// ---------------------------------------------------------------------------

/// ALE channel scoring for automatic frequency selection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AleChannelScore {
    /// Center frequency in Hz.
    pub freq_hz: u64,
    /// Last measured RSSI when listening on this channel (dBm).
    pub rssi_dbm: f32,
    /// Link quality assessment (0.0 = unusable, 1.0 = excellent).
    pub lqa: f32,
    /// Time of last successful contact on this channel (Unix seconds).
    pub last_contact: Option<u64>,
    /// Number of failed call attempts on this channel.
    pub failure_count: u32,
}

/// ALE controller state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AleController {
    /// Scored channel list (HF frequencies typically).
    pub channels: Vec<AleChannelScore>,
    /// Our ALE address (typically a 3-character callsign identifier).
    pub local_address: String,
    /// Currently linked channel (if in LINKED state).
    pub linked_freq_hz: Option<u64>,
    /// ALE state machine state.
    pub state: AleState,
}

/// ALE link state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AleState {
    /// Sounding / listening for calls.
    #[default]
    Scanning,
    /// Calling a peer on a specific channel.
    Calling,
    /// Link established — communicating.
    Linked,
    /// Link failed — attempting re-establishment.
    RelinkPending,
}

impl AleController {
    /// Select the best channel for establishing a new link.
    ///
    /// Scoring factors:
    /// 1. LQA (link quality, 0.0–1.0) — primary factor
    /// 2. Recency of last successful contact (newer = better)
    /// 3. RSSI (higher = better, but not dominant — LQA matters more)
    /// 4. Failure count penalty (exponential backoff per failed call)
    pub fn select_best_channel(&self) -> Option<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.channels
            .iter()
            .max_by(|a, b| {
                let score_a = ale_score(a, now);
                let score_b = ale_score(b, now);
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|ch| ch.freq_hz)
    }

    /// Record the result of a call attempt on a channel.
    pub fn record_call_result(&mut self, freq_hz: u64, success: bool) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some(ch) = self.channels.iter_mut().find(|c| c.freq_hz == freq_hz) {
            if success {
                ch.last_contact = Some(now);
                ch.lqa = (ch.lqa * 0.8 + 1.0 * 0.2).min(1.0); // EMA toward 1.0
                ch.failure_count = 0;
                self.linked_freq_hz = Some(freq_hz);
                self.state = AleState::Linked;
            } else {
                ch.failure_count += 1;
                ch.lqa = (ch.lqa * 0.8).max(0.0); // EMA toward 0.0
                self.state = AleState::RelinkPending;
            }
        }
    }

    /// Update RSSI measurement for a channel.
    pub fn update_rssi(&mut self, freq_hz: u64, rssi_dbm: f32) {
        if let Some(ch) = self.channels.iter_mut().find(|c| c.freq_hz == freq_hz) {
            ch.rssi_dbm = rssi_dbm;
        } else {
            self.channels.push(AleChannelScore {
                freq_hz,
                rssi_dbm,
                lqa: 0.5, // Unknown — start neutral
                last_contact: None,
                failure_count: 0,
            });
        }
    }
}

/// Compute a composite ALE channel score.
fn ale_score(ch: &AleChannelScore, now_secs: u64) -> f32 {
    // LQA is the primary factor (0.0–1.0)
    let mut score = ch.lqa * 0.6;

    // Recency bonus: decays over 24 hours
    if let Some(last) = ch.last_contact {
        let age_hours = (now_secs.saturating_sub(last)) as f32 / 3600.0;
        let recency = (1.0 - age_hours / 24.0).max(0.0);
        score += recency * 0.2;
    }

    // RSSI: normalize from -130dBm (noise floor) to -40dBm (excellent)
    let rssi_norm = ((ch.rssi_dbm + 130.0) / 90.0).clamp(0.0, 1.0);
    score += rssi_norm * 0.1;

    // Failure penalty: exponential backoff
    let penalty = 1.0 / (1.0 + ch.failure_count as f32);
    score *= penalty;

    score
}

// ---------------------------------------------------------------------------
// Spectrum Sensing / Clear Channel Assessment
// ---------------------------------------------------------------------------

/// Spectrum sensing result for a channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelSense {
    /// Measured RSSI (dBm).
    pub rssi_dbm: f32,
    /// Whether the channel appears clear (below CCA threshold).
    pub clear: bool,
    /// Estimated noise floor (dBm), averaged over multiple measurements.
    pub noise_floor_dbm: f32,
    /// Signal-to-noise ratio (dB).
    pub snr_db: f32,
}

impl ChannelSense {
    /// Synthesize a ChannelSense from a single RSSI measurement.
    ///
    /// `noise_floor_dbm` should come from an averaged background measurement.
    pub fn from_rssi(rssi_dbm: f32, noise_floor_dbm: f32, cca_threshold_dbm: f32) -> Self {
        Self {
            rssi_dbm,
            clear: rssi_dbm < cca_threshold_dbm,
            noise_floor_dbm,
            snr_db: rssi_dbm - noise_floor_dbm,
        }
    }
}

// ---------------------------------------------------------------------------
// Packet Framing
// ---------------------------------------------------------------------------

/// SDR mesh packet frame structure.
///
/// The frame wraps an encrypted mesh packet for over-the-air transmission.
/// All fields after the sync word are protected by the application-layer
/// encryption — the radio layer sees only the frame header.
///
/// ```text
/// [4 bytes] Sync word (band-specific, agreed pre-session)
/// [1 byte]  Frame version (0x01)
/// [1 byte]  Flags (FHSS=0x01, ALE=0x02, priority bits[3:2])
/// [2 bytes] Payload length (LE)
/// [N bytes] Encrypted payload (4-layer mesh packet)
/// [2 bytes] CRC-16/CCITT of header+payload
/// ```
///
/// The sync word is not secret — it identifies the mesh protocol.
/// The payload is encrypted at the application layer before being
/// handed to the SDR transport.
#[derive(Clone, Debug)]
pub struct SdrFrame {
    /// Frame version.
    pub version: u8,
    /// Frame flags.
    pub flags: SdrFrameFlags,
    /// Encrypted payload.
    pub payload: Vec<u8>,
}

bitflags::bitflags! {
    /// Flags in the SDR frame header.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct SdrFrameFlags: u8 {
        /// Frame was sent on an FHSS channel.
        const FHSS = 0x01;
        /// Frame is part of an ALE call sequence.
        const ALE = 0x02;
        /// Frame is high priority.
        const HIGH_PRIORITY = 0x04;
        /// Frame contains a hop table update.
        const HOP_UPDATE = 0x08;
    }
}

// ---------------------------------------------------------------------------
// Sync Words (per-band, pre-agreed)
// ---------------------------------------------------------------------------

/// Sync word for each band.
///
/// Sync words are chosen to be distinct from common noise patterns
/// and from each other. They are not secret.
pub const SYNC_HF: [u8; 4] = [0xD9, 0x1E, 0x8C, 0x2A];
pub const SYNC_VHF: [u8; 4] = [0xF3, 0x7B, 0x44, 0x11];
pub const SYNC_UHF: [u8; 4] = [0xA5, 0xC2, 0x6D, 0xE0];
pub const SYNC_SHF: [u8; 4] = [0x1B, 0x9F, 0x3C, 0x57];
pub const SYNC_LORA: [u8; 4] = [0x34, 0x12, 0xCD, 0xAB]; // LoRa sync 0x12/0x34 extended
pub const SYNC_FHSS: [u8; 4] = [0x72, 0xE4, 0x0B, 0x96];

// ---------------------------------------------------------------------------
// Radio Profile
// ---------------------------------------------------------------------------

/// Named radio profile for quick configuration.
///
/// Each profile is a pre-configured set of channels, modulation, and FHSS
/// settings optimized for a specific operational mode. Profiles can be
/// further tuned via [`SdrConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadioProfile {
    /// Secure: FHSS with 100ms dwell, short bursts, maximum evasion.
    /// Bandwidth: 1–5 kbps. Best against active adversaries.
    Secure,
    /// Long Range: LoRa SF12 or HF SSB, maximum link budget.
    /// Bandwidth: 250bps–1kbps. Best for reaching distant peers.
    LongRange,
    /// Evasive: ALE-style band-hopping, randomized dwell (50–500ms).
    /// Unpredictable frequency selection via spectrum sensing.
    /// Best when transmission patterns must be obscured.
    Evasive,
    /// Balanced: moderate FHSS, medium bandwidth, good range.
    /// Default for normal mesh operation over radio.
    Balanced,
    /// Custom: user-defined configuration.
    Custom,
}

// ---------------------------------------------------------------------------
// SDR Hardware Capabilities
// ---------------------------------------------------------------------------

/// What a hardware driver can do.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    /// Minimum tunable frequency (Hz).
    pub min_freq_hz: u64,
    /// Maximum tunable frequency (Hz).
    pub max_freq_hz: u64,
    /// Maximum transmit power (dBm).
    pub max_tx_power_dbm: i8,
    /// Minimum transmit power (dBm).
    pub min_tx_power_dbm: i8,
    /// Maximum sample rate / bandwidth (Hz).
    pub max_bandwidth_hz: u32,
    /// Whether full-duplex (TX+RX simultaneously) is supported.
    pub full_duplex: bool,
    /// Whether the driver supports raw IQ streaming.
    pub raw_iq: bool,
    /// Whether the device has a built-in LoRa modem.
    pub has_lora_modem: bool,
    /// Whether the device can do spectrum sensing (RSSI across a band).
    pub can_sense_spectrum: bool,
    /// Number of independent receive channels.
    pub rx_channels: u8,
    /// Number of independent transmit channels.
    pub tx_channels: u8,
}

impl HardwareCapabilities {
    /// LoRa dedicated chip (SX1276/SX1278/SX1262, etc.).
    /// Fixed frequency range (433/868/915MHz), no raw IQ, no full-duplex.
    pub fn lora_chip() -> Self {
        Self {
            min_freq_hz: 137_000_000,
            max_freq_hz: 1_020_000_000,
            max_tx_power_dbm: 20,
            min_tx_power_dbm: -4,
            max_bandwidth_hz: 500_000,
            full_duplex: false,
            raw_iq: false,
            has_lora_modem: true,
            can_sense_spectrum: true,
            rx_channels: 1,
            tx_channels: 1,
        }
    }

    /// HackRF One — wideband SDR, TX+RX, 1MHz–6GHz, half-duplex.
    pub fn hackrf() -> Self {
        Self {
            min_freq_hz: 1_000_000,
            max_freq_hz: 6_000_000_000,
            max_tx_power_dbm: 10,
            min_tx_power_dbm: -40,
            max_bandwidth_hz: 20_000_000,
            full_duplex: false,
            raw_iq: true,
            has_lora_modem: false,
            can_sense_spectrum: true,
            rx_channels: 1,
            tx_channels: 1,
        }
    }

    /// LimeSDR — full-duplex, 100kHz–3.8GHz, high performance.
    pub fn limesdr() -> Self {
        Self {
            min_freq_hz: 100_000,
            max_freq_hz: 3_800_000_000,
            max_tx_power_dbm: 20,
            min_tx_power_dbm: -60,
            max_bandwidth_hz: 61_440_000,
            full_duplex: true,
            raw_iq: true,
            has_lora_modem: false,
            can_sense_spectrum: true,
            rx_channels: 2,
            tx_channels: 2,
        }
    }

    /// ADALM-PLUTO (PlutoSDR) — 325MHz–3.8GHz, full-duplex.
    pub fn pluto_sdr() -> Self {
        Self {
            min_freq_hz: 325_000_000,
            max_freq_hz: 3_800_000_000,
            max_tx_power_dbm: 0,
            min_tx_power_dbm: -90,
            max_bandwidth_hz: 56_000_000,
            full_duplex: true,
            raw_iq: true,
            has_lora_modem: false,
            can_sense_spectrum: true,
            rx_channels: 1,
            tx_channels: 1,
        }
    }

    /// RTL-SDR — receive-only, 500kHz–1766MHz (varies by chip).
    /// Cannot transmit — RX only for monitoring/sniffing.
    pub fn rtl_sdr() -> Self {
        Self {
            min_freq_hz: 500_000,
            max_freq_hz: 1_766_000_000,
            max_tx_power_dbm: -120, // RX only
            min_tx_power_dbm: -120,
            max_bandwidth_hz: 3_200_000,
            full_duplex: false,
            raw_iq: true,
            has_lora_modem: false,
            can_sense_spectrum: true,
            rx_channels: 1,
            tx_channels: 0, // No TX
        }
    }

    /// Generic HF transceiver (e.g. Icom IC-7300, Elecraft K3, SDRPlay).
    /// HF-only (3–30MHz), SSB/CW/digital modes.
    pub fn hf_transceiver() -> Self {
        Self {
            min_freq_hz: 1_800_000,
            max_freq_hz: 30_000_000,
            max_tx_power_dbm: 50, // 100W typical
            min_tx_power_dbm: 0,
            max_bandwidth_hz: 3_000,
            full_duplex: false,
            raw_iq: true, // IF output available on most modern HF rigs
            has_lora_modem: false,
            can_sense_spectrum: true,
            rx_channels: 1,
            tx_channels: 1,
        }
    }

    /// Meshtastic-compatible node (e.g. TTGO T-Beam, Heltec LoRa32).
    /// LoRa chip + GPS + BLE. ISM bands only.
    pub fn meshtastic() -> Self {
        let mut caps = Self::lora_chip();
        caps.has_lora_modem = true;
        caps
    }

    /// Whether a given channel configuration is achievable with this hardware.
    pub fn supports_channel(&self, ch: &RadioChannel) -> bool {
        ch.freq_hz >= self.min_freq_hz
            && ch.freq_hz <= self.max_freq_hz
            && ch.bandwidth_hz <= self.max_bandwidth_hz
    }

    /// Whether a given modulation is achievable with this hardware.
    pub fn supports_modulation(&self, modulation: &Modulation) -> bool {
        match modulation {
            Modulation::LoRaCss { .. } => self.has_lora_modem,
            Modulation::RawIq { .. } => self.raw_iq,
            _ => true, // Software-defined modulations require raw IQ or DSP
        }
    }

    /// Whether this hardware can transmit (has a TX path).
    pub fn can_transmit(&self) -> bool {
        self.tx_channels > 0 && self.max_tx_power_dbm > self.min_tx_power_dbm
    }
}

// ---------------------------------------------------------------------------
// SDR Driver Type (hardware backend)
// ---------------------------------------------------------------------------

/// SDR hardware driver type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SdrDriverType {
    /// Generic LoRa chip (SX1276/SX1278/SX1262/SX1268).
    LoRaChip { model: LoRaChipModel },
    /// HackRF One (via SoapySDR or direct libhackrf).
    HackRf,
    /// LimeSDR (via SoapySDR or direct LimeSuite).
    LimeSdr,
    /// ADALM-PLUTO / PlutoSDR (via libiio / SoapySDR).
    PlutoSdr,
    /// RTL-SDR (receive-only, via librtlsdr / SoapySDR).
    RtlSdr,
    /// Generic HF transceiver with CAT/CI-V control and audio IF.
    HfTransceiver { model: String },
    /// Meshtastic-compatible node.
    Meshtastic,
    /// SoapySDR generic (any SoapySDR-compatible device).
    SoapySdr {
        driver: String,
        serial: Option<String>,
    },
    /// Simulated/test driver (no hardware required).
    Simulated,
}

/// LoRa chip model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoRaChipModel {
    /// Semtech SX1276 (widely used, 433/868/915MHz).
    Sx1276,
    /// Semtech SX1278 (433MHz optimized).
    Sx1278,
    /// Semtech SX1262 (latest generation, improved link budget).
    Sx1262,
    /// Semtech SX1268 (SX1262 variant with higher power).
    Sx1268,
    /// Generic/unknown LoRa chip.
    Generic,
}

impl SdrDriverType {
    /// Hardware capabilities for this driver.
    pub fn capabilities(&self) -> HardwareCapabilities {
        match self {
            Self::LoRaChip { .. } => HardwareCapabilities::lora_chip(),
            Self::HackRf => HardwareCapabilities::hackrf(),
            Self::LimeSdr => HardwareCapabilities::limesdr(),
            Self::PlutoSdr => HardwareCapabilities::pluto_sdr(),
            Self::RtlSdr => HardwareCapabilities::rtl_sdr(),
            Self::HfTransceiver { .. } => HardwareCapabilities::hf_transceiver(),
            Self::Meshtastic => HardwareCapabilities::meshtastic(),
            Self::SoapySdr { .. } => {
                // Conservative defaults — actual caps queried from device at runtime
                HardwareCapabilities::hackrf() // Treat like HackRF by default
            }
            Self::Simulated => HardwareCapabilities {
                min_freq_hz: 1_000,
                max_freq_hz: 300_000_000_000,
                max_tx_power_dbm: 30,
                min_tx_power_dbm: -60,
                max_bandwidth_hz: 100_000_000,
                full_duplex: true,
                raw_iq: true,
                has_lora_modem: true,
                can_sense_spectrum: true,
                rx_channels: 4,
                tx_channels: 4,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Full SDR Configuration
// ---------------------------------------------------------------------------

/// Complete SDR transport configuration.
///
/// This is the top-level configuration object for an SDR transport session.
/// It specifies the hardware, channel, FHSS/ALE settings, and operational profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdrConfig {
    /// Hardware driver to use.
    pub driver: SdrDriverType,
    /// Active operational profile.
    pub profile: RadioProfile,
    /// Primary channel (used when not in FHSS mode).
    pub primary_channel: RadioChannel,
    /// FHSS configuration (active when profile is Secure or Evasive,
    /// or when explicitly enabled).
    pub fhss: Option<FhssConfig>,
    /// ALE controller (active on HF bands when profile is Evasive or LongRange).
    pub ale: Option<AleController>,
    /// Clear channel assessment threshold (dBm).
    /// Channels with RSSI above this are considered busy.
    pub cca_threshold_dbm: f32,
    /// Maximum CCA backoff time (ms) before giving up on a channel.
    pub cca_backoff_ms: u32,
    /// Whether to enable automatic gain control (AGC) on receive.
    pub agc: bool,
    /// Manual receive gain (dB), used when AGC is disabled.
    pub rx_gain_db: f32,
    /// Maximum transmit power (dBm). Clamped to hardware limits.
    pub tx_power_dbm: i8,
    /// Whether the transport is currently enabled.
    pub enabled: bool,
}

impl SdrConfig {
    /// Create a Balanced profile configuration for the given driver and primary frequency.
    pub fn balanced(driver: SdrDriverType, primary_freq_hz: u64) -> Self {
        Self {
            driver,
            profile: RadioProfile::Balanced,
            primary_channel: RadioChannel {
                freq_hz: primary_freq_hz,
                bandwidth_hz: 125_000, // 125kHz — standard LoRa bandwidth
                modulation: Modulation::LoRaCss {
                    spreading_factor: 9, // SF9 — balance of range and speed
                    coding_rate: LoRaCodingRate::Cr46,
                },
                tx_power_dbm: Some(14),
                label: format!("Balanced {}MHz", primary_freq_hz / 1_000_000),
            },
            fhss: None,
            ale: None,
            cca_threshold_dbm: -90.0,
            cca_backoff_ms: 200,
            agc: true,
            rx_gain_db: 20.0,
            tx_power_dbm: 14,
            enabled: true,
        }
    }

    /// Create a Secure profile: FHSS across ISM UHF channels, 100ms dwell.
    pub fn secure(driver: SdrDriverType, hop_key: [u8; 32]) -> Self {
        // Pre-computed ISM 433MHz sub-band hop table (ETSI EN 300 220)
        let hop_table = ism_433_channels();
        Self {
            driver,
            profile: RadioProfile::Secure,
            primary_channel: hop_table[0].clone(),
            fhss: Some(FhssConfig {
                hop_table,
                dwell_ms: 100,
                guard_epochs: 2,
                hop_key,
            }),
            ale: None,
            cca_threshold_dbm: -85.0,
            cca_backoff_ms: 50, // Short backoff — hop away if busy
            agc: true,
            rx_gain_db: 20.0,
            tx_power_dbm: 10,
            enabled: true,
        }
    }

    /// Create a LongRange profile: LoRa SF12, maximum link budget.
    pub fn long_range(driver: SdrDriverType, primary_freq_hz: u64) -> Self {
        Self {
            driver,
            profile: RadioProfile::LongRange,
            primary_channel: RadioChannel {
                freq_hz: primary_freq_hz,
                bandwidth_hz: 125_000,
                modulation: Modulation::LoRaCss {
                    spreading_factor: 12,              // SF12 = max range, min rate (~250bps)
                    coding_rate: LoRaCodingRate::Cr48, // Max FEC for reliability
                },
                tx_power_dbm: Some(20), // Maximum power
                label: format!("LongRange SF12 {}MHz", primary_freq_hz / 1_000_000),
            },
            fhss: None,
            ale: None,
            cca_threshold_dbm: -100.0, // Very sensitive — avoid interference
            cca_backoff_ms: 500,
            agc: true,
            rx_gain_db: 30.0, // High gain for weak signals
            tx_power_dbm: 20,
            enabled: true,
        }
    }

    /// Create a LongRange HF profile: SSB on 40m/20m amateur band.
    pub fn long_range_hf(driver: SdrDriverType) -> Self {
        // 40m band (7.000–7.300 MHz) — excellent regional/continental coverage
        let ale_channels = hf_40m_ale_channels();
        Self {
            driver,
            profile: RadioProfile::LongRange,
            primary_channel: RadioChannel {
                freq_hz: 7_074_000,  // 7.074 MHz — FT8 frequency, known good
                bandwidth_hz: 3_000, // 3kHz SSB bandwidth
                modulation: Modulation::Ssb {
                    upper_sideband: true,
                },
                tx_power_dbm: Some(37), // 5W — QRP, long range on HF
                label: "HF 40m SSB 7.074MHz".into(),
            },
            fhss: None,
            ale: Some(AleController {
                channels: ale_channels,
                local_address: String::new(), // Set at session time
                linked_freq_hz: None,
                state: AleState::Scanning,
            }),
            cca_threshold_dbm: -80.0,
            cca_backoff_ms: 1000, // Longer backoff for HF propagation delays
            agc: true,
            rx_gain_db: 10.0,
            tx_power_dbm: 37,
            enabled: true,
        }
    }

    /// Create an Evasive profile: randomized dwell, spectrum sensing, ALE.
    pub fn evasive(driver: SdrDriverType, hop_key: [u8; 32]) -> Self {
        // Wide UHF hop table spanning multiple ISM sub-bands
        let hop_table = uhf_evasive_channels();
        Self {
            driver,
            profile: RadioProfile::Evasive,
            primary_channel: hop_table[0].clone(),
            fhss: Some(FhssConfig {
                hop_table,
                dwell_ms: 75, // 50–100ms randomized at runtime
                guard_epochs: 3,
                hop_key,
            }),
            ale: None,
            cca_threshold_dbm: -80.0,
            cca_backoff_ms: 30, // Very short — immediately hop on busy channel
            agc: true,
            rx_gain_db: 20.0,
            tx_power_dbm: 8, // Low power — avoid long-range detection
            enabled: true,
        }
    }

    /// Whether this config uses FHSS.
    pub fn is_fhss(&self) -> bool {
        self.fhss.is_some()
    }

    /// Whether this config uses ALE.
    pub fn is_ale(&self) -> bool {
        self.ale.is_some()
    }
}

// ---------------------------------------------------------------------------
// Pre-built Channel Tables
// ---------------------------------------------------------------------------

/// ISM 433MHz sub-band channels (ETSI EN 300 220 §4.2, 869.4–869.65MHz also included).
/// 20 channels spread across 433.05–434.79 MHz at 87.5kHz spacing.
pub fn ism_433_channels() -> Vec<RadioChannel> {
    (0..20u64)
        .map(|i| RadioChannel {
            freq_hz: 433_050_000 + i * 87_500,
            bandwidth_hz: 125_000,
            modulation: Modulation::LoRaCss {
                spreading_factor: 8,
                coding_rate: LoRaCodingRate::Cr46,
            },
            tx_power_dbm: Some(10),
            label: format!("ISM433-{}", i),
        })
        .collect()
}

/// ISM 868MHz EU channels (ETSI EN 300 220, 868.0–868.6 MHz).
/// 8 channels at 200kHz spacing (LoRaWAN EU868 band).
pub fn ism_868_channels() -> Vec<RadioChannel> {
    [
        868_100_000u64,
        868_300_000,
        868_500_000,
        867_100_000,
        867_300_000,
        867_500_000,
        867_700_000,
        867_900_000,
    ]
    .iter()
    .enumerate()
    .map(|(i, &freq)| RadioChannel {
        freq_hz: freq,
        bandwidth_hz: 125_000,
        modulation: Modulation::LoRaCss {
            spreading_factor: 9,
            coding_rate: LoRaCodingRate::Cr45,
        },
        tx_power_dbm: Some(14),
        label: format!("EU868-{}", i),
    })
    .collect()
}

/// ISM 915MHz US/AU channels (FCC Part 15, 902–928 MHz).
/// 64 channels at 200kHz spacing.
pub fn ism_915_channels() -> Vec<RadioChannel> {
    (0..64u64)
        .map(|i| RadioChannel {
            freq_hz: 902_300_000 + i * 200_000,
            bandwidth_hz: 125_000,
            modulation: Modulation::LoRaCss {
                spreading_factor: 9,
                coding_rate: LoRaCodingRate::Cr45,
            },
            tx_power_dbm: Some(20),
            label: format!("US915-{}", i),
        })
        .collect()
}

/// HF 40m band ALE channel list (7.0–7.3 MHz, 3kHz spacing).
/// Standard amateur/emergency frequencies for ALE operation.
pub fn hf_40m_ale_channels() -> Vec<AleChannelScore> {
    [
        7_000_000u64,
        7_030_000,
        7_045_000,
        7_074_000,
        7_100_000,
        7_150_000,
        7_200_000,
        7_255_000,
        7_300_000,
    ]
    .iter()
    .map(|&freq| AleChannelScore {
        freq_hz: freq,
        rssi_dbm: -100.0, // Unknown — will be measured
        lqa: 0.5,
        last_contact: None,
        failure_count: 0,
    })
    .collect()
}

/// HF 20m band ALE channel list (14.0–14.35 MHz).
/// Excellent daytime DX (long-distance) propagation.
pub fn hf_20m_ale_channels() -> Vec<AleChannelScore> {
    [
        14_000_000u64,
        14_030_000,
        14_074_000,
        14_100_000,
        14_200_000,
        14_230_000,
        14_280_000,
        14_300_000,
        14_350_000,
    ]
    .iter()
    .map(|&freq| AleChannelScore {
        freq_hz: freq,
        rssi_dbm: -100.0,
        lqa: 0.5,
        last_contact: None,
        failure_count: 0,
    })
    .collect()
}

/// Wide UHF evasive hop table spanning 433, 868, and 915MHz ISM bands.
/// 50 channels spread across three bands — highly resistant to selective jamming.
pub fn uhf_evasive_channels() -> Vec<RadioChannel> {
    let mut channels = Vec::new();
    // 10 channels from 433MHz band
    for i in 0..10u64 {
        channels.push(RadioChannel {
            freq_hz: 433_050_000 + i * 175_000,
            bandwidth_hz: 125_000,
            modulation: Modulation::Gfsk {
                deviation_hz: 62_500,
                bt: 0.5,
            },
            tx_power_dbm: Some(8),
            label: format!("Ev433-{}", i),
        });
    }
    // 10 channels from 868MHz band
    for i in 0..10u64 {
        channels.push(RadioChannel {
            freq_hz: 868_000_000 + i * 600_000 / 10,
            bandwidth_hz: 200_000,
            modulation: Modulation::Gfsk {
                deviation_hz: 100_000,
                bt: 0.5,
            },
            tx_power_dbm: Some(8),
            label: format!("Ev868-{}", i),
        });
    }
    // 15 channels from 915MHz band
    for i in 0..15u64 {
        channels.push(RadioChannel {
            freq_hz: 902_300_000 + i * 1_720_000,
            bandwidth_hz: 200_000,
            modulation: Modulation::Gfsk {
                deviation_hz: 100_000,
                bt: 0.5,
            },
            tx_power_dbm: Some(8),
            label: format!("Ev915-{}", i),
        });
    }
    // 15 channels from 2.4GHz band (2400–2483.5 MHz, ISM)
    for i in 0..15u64 {
        channels.push(RadioChannel {
            freq_hz: 2_400_000_000 + i * 5_500_000,
            bandwidth_hz: 1_000_000,
            modulation: Modulation::Qpsk,
            tx_power_dbm: Some(8),
            label: format!("Ev2400-{}", i),
        });
    }
    channels
}

// ---------------------------------------------------------------------------
// Session State
// ---------------------------------------------------------------------------

/// Active SDR session with a specific peer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SdrSession {
    /// Peer's identifier (hex-encoded public key prefix for RF addressing).
    pub peer_addr: String,
    /// Current configuration.
    pub config: Option<SdrConfig>,
    /// Whether the session is currently active (radio link established).
    pub active: bool,
    /// Session statistics.
    pub stats: SdrStats,
}

/// SDR session statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SdrStats {
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Total frames transmitted.
    pub tx_frames: u64,
    /// Total frames received.
    pub rx_frames: u64,
    /// Frames lost (transmitted but no ACK received).
    pub lost_frames: u64,
    /// Total FHSS hops performed.
    pub fhss_hops: u64,
    /// ALE re-link events.
    pub ale_relinks: u32,
    /// Last measured RSSI (dBm).
    pub last_rssi_dbm: f32,
    /// Last measured SNR (dB).
    pub last_snr_db: f32,
}

impl SdrStats {
    /// Packet loss ratio (0.0–1.0).
    pub fn loss_ratio(&self) -> f32 {
        if self.tx_frames == 0 {
            0.0
        } else {
            self.lost_frames as f32 / self.tx_frames as f32
        }
    }
}

// ---------------------------------------------------------------------------
// SDR Manager
// ---------------------------------------------------------------------------

/// Manages all active SDR sessions and the global radio configuration.
#[derive(Debug, Default)]
pub struct SdrManager {
    /// Active sessions keyed by peer ID (hex).
    pub sessions: HashMap<String, SdrSession>,
    /// Global RF config (applies to all sessions that don't override).
    pub global_config: Option<SdrConfig>,
    /// Whether SDR transport is globally enabled.
    pub enabled: bool,
}

impl SdrManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a new global configuration and restart affected sessions.
    pub fn apply_config(&mut self, config: SdrConfig) {
        self.enabled = config.enabled;
        self.global_config = Some(config);
    }

    /// Get the configuration for a specific peer session.
    /// Falls back to the global config if no per-peer override exists.
    pub fn session_config(&self, peer_id: &str) -> Option<&SdrConfig> {
        self.sessions
            .get(peer_id)
            .and_then(|s| s.config.as_ref())
            .or(self.global_config.as_ref())
    }

    /// Record a frame received from a peer.
    pub fn record_rx(&mut self, peer_id: &str, bytes: usize, rssi_dbm: f32, snr_db: f32) {
        let session = self.sessions.entry(peer_id.to_string()).or_default();
        session.stats.rx_bytes += bytes as u64;
        session.stats.rx_frames += 1;
        session.stats.last_rssi_dbm = rssi_dbm;
        session.stats.last_snr_db = snr_db;
        session.active = true;
    }

    /// Record a frame transmitted to a peer.
    pub fn record_tx(&mut self, peer_id: &str, bytes: usize) {
        let session = self.sessions.entry(peer_id.to_string()).or_default();
        session.stats.tx_bytes += bytes as u64;
        session.stats.tx_frames += 1;
    }

    /// Record a lost frame (transmitted but no ACK).
    pub fn record_loss(&mut self, peer_id: &str) {
        let session = self.sessions.entry(peer_id.to_string()).or_default();
        session.stats.lost_frames += 1;
    }

    /// Record an FHSS hop.
    pub fn record_fhss_hop(&mut self, peer_id: &str) {
        let session = self.sessions.entry(peer_id.to_string()).or_default();
        session.stats.fhss_hops += 1;
    }

    /// Summary stats for all active SDR sessions.
    pub fn aggregate_stats(&self) -> SdrStats {
        let mut agg = SdrStats::default();
        for session in self.sessions.values() {
            agg.tx_bytes += session.stats.tx_bytes;
            agg.rx_bytes += session.stats.rx_bytes;
            agg.tx_frames += session.stats.tx_frames;
            agg.rx_frames += session.stats.rx_frames;
            agg.lost_frames += session.stats.lost_frames;
            agg.fhss_hops += session.stats.fhss_hops;
            agg.ale_relinks += session.stats.ale_relinks;
        }
        agg
    }
}

// ---------------------------------------------------------------------------
// Hex bytes serialization helper (for hop_key)
// ---------------------------------------------------------------------------

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_band_classify() {
        assert_eq!(FrequencyBand::classify(7_074_000), Some(FrequencyBand::Hf));
        assert_eq!(
            FrequencyBand::classify(433_920_000),
            Some(FrequencyBand::Uhf)
        );
        assert_eq!(
            FrequencyBand::classify(868_100_000),
            Some(FrequencyBand::Uhf)
        );
        assert_eq!(
            FrequencyBand::classify(2_400_000_000),
            Some(FrequencyBand::Uhf)
        );
        assert_eq!(
            FrequencyBand::classify(5_800_000_000),
            Some(FrequencyBand::Shf)
        );
        assert_eq!(
            FrequencyBand::classify(144_000_000),
            Some(FrequencyBand::Vhf)
        );
        assert_eq!(FrequencyBand::classify(1), None);
    }

    #[test]
    fn test_lora_data_rate() {
        // SF12 125kHz should be ~250bps (very low — expected for max range)
        let ch = RadioChannel {
            freq_hz: 868_100_000,
            bandwidth_hz: 125_000,
            modulation: Modulation::LoRaCss {
                spreading_factor: 12,
                coding_rate: LoRaCodingRate::Cr48,
            },
            tx_power_dbm: Some(14),
            label: "Test".into(),
        };
        let rate = ch.approx_data_rate_bps();
        assert!(
            rate > 100,
            "SF12 data rate should be > 100bps, got {}",
            rate
        );
        assert!(
            rate < 1000,
            "SF12 data rate should be < 1000bps, got {}",
            rate
        );

        // SF7 125kHz should be much higher (~5kbps)
        let ch7 = RadioChannel {
            modulation: Modulation::LoRaCss {
                spreading_factor: 7,
                coding_rate: LoRaCodingRate::Cr45,
            },
            ..ch.clone()
        };
        let rate7 = ch7.approx_data_rate_bps();
        assert!(rate7 > rate, "SF7 should be faster than SF12");
    }

    #[test]
    fn test_fhss_channel_deterministic() {
        let key = [0xABu8; 32];
        let config = FhssConfig {
            hop_table: ism_433_channels(),
            dwell_ms: 100,
            guard_epochs: 2,
            hop_key: key,
        };
        // Same epoch → same channel
        let ch1 = config.channel_for_epoch(42);
        let ch2 = config.channel_for_epoch(42);
        assert_eq!(ch1, ch2);

        // Different epoch → likely different channel (not guaranteed but statistically true)
        let ch3 = config.channel_for_epoch(43);
        // Can't assert they're different (might collide), but they should be valid indices
        assert!(ch3 < config.hop_table.len());
    }

    #[test]
    fn test_fhss_channel_within_bounds() {
        let config = FhssConfig {
            hop_table: ism_433_channels(),
            dwell_ms: 100,
            guard_epochs: 2,
            hop_key: [0x01u8; 32],
        };
        for epoch in 0..1000u64 {
            let idx = config.channel_for_epoch(epoch);
            assert!(
                idx < config.hop_table.len(),
                "Channel index out of bounds at epoch {}",
                epoch
            );
        }
    }

    #[test]
    fn test_fhss_hop_distribution() {
        // Verify FHSS is roughly uniform — no channel should appear > 20% of the time
        let table_len = 20usize;
        let config = FhssConfig {
            hop_table: ism_433_channels(),
            dwell_ms: 100,
            guard_epochs: 2,
            hop_key: [0xCAu8; 32],
        };
        let mut counts = vec![0usize; table_len];
        for epoch in 0..1000u64 {
            counts[config.channel_for_epoch(epoch)] += 1;
        }
        let max_count = *counts.iter().max().unwrap();
        // With 1000 epochs and 20 channels, expect ~50 per channel; allow 3x tolerance
        assert!(
            max_count < 150,
            "FHSS distribution is too skewed: max={}",
            max_count
        );
    }

    #[test]
    fn test_ale_channel_scoring() {
        let mut ale = AleController {
            channels: hf_40m_ale_channels(),
            ..Default::default()
        };
        // Record a successful call on 7.074MHz
        ale.record_call_result(7_074_000, true);
        // Should now prefer 7.074MHz
        let best = ale.select_best_channel().unwrap();
        assert_eq!(best, 7_074_000);
    }

    #[test]
    fn test_ale_failure_penalty() {
        let mut ale = AleController {
            channels: hf_40m_ale_channels(),
            ..Default::default()
        };
        // Record many failures on the first channel
        for _ in 0..5 {
            ale.record_call_result(7_000_000, false);
        }
        // Record one success on a different channel
        ale.record_call_result(7_074_000, true);
        // 7.074MHz should score higher than the failed channel
        let best = ale.select_best_channel().unwrap();
        assert_ne!(
            best, 7_000_000,
            "Heavily failed channel should not be selected"
        );
    }

    #[test]
    fn test_hardware_capabilities() {
        let hackrf = HardwareCapabilities::hackrf();
        assert!(hackrf.can_transmit());
        assert!(!hackrf.full_duplex);
        assert!(hackrf.raw_iq);

        let rtlsdr = HardwareCapabilities::rtl_sdr();
        assert!(!rtlsdr.can_transmit()); // RX only
        assert!(rtlsdr.raw_iq);

        let limesdr = HardwareCapabilities::limesdr();
        assert!(limesdr.full_duplex);
        assert_eq!(limesdr.rx_channels, 2);
    }

    #[test]
    fn test_hardware_supports_channel() {
        let lora = HardwareCapabilities::lora_chip();
        let good = RadioChannel {
            freq_hz: 433_175_000,
            bandwidth_hz: 125_000,
            modulation: Modulation::LoRaCss {
                spreading_factor: 9,
                coding_rate: LoRaCodingRate::Cr45,
            },
            tx_power_dbm: Some(14),
            label: "Test".into(),
        };
        assert!(lora.supports_channel(&good));

        let bad = RadioChannel {
            freq_hz: 100_000, // Below LoRa chip minimum
            ..good.clone()
        };
        assert!(!lora.supports_channel(&bad));
    }

    #[test]
    fn test_secure_config() {
        let config = SdrConfig::secure(SdrDriverType::Simulated, [0xABu8; 32]);
        assert!(config.is_fhss());
        assert!(!config.is_ale());
        assert_eq!(config.profile, RadioProfile::Secure);
        let fhss = config.fhss.as_ref().unwrap();
        assert_eq!(fhss.dwell_ms, 100);
        assert!(!fhss.hop_table.is_empty());
    }

    #[test]
    fn test_long_range_hf_config() {
        let config = SdrConfig::long_range_hf(SdrDriverType::Simulated);
        assert!(!config.is_fhss());
        assert!(config.is_ale());
        assert_eq!(config.profile, RadioProfile::LongRange);
        assert_eq!(
            FrequencyBand::classify(config.primary_channel.freq_hz),
            Some(FrequencyBand::Hf)
        );
    }

    #[test]
    fn test_evasive_config() {
        let config = SdrConfig::evasive(SdrDriverType::Simulated, [0x00u8; 32]);
        assert!(config.is_fhss());
        let fhss = config.fhss.as_ref().unwrap();
        // Evasive table spans multiple bands
        assert!(
            fhss.hop_table.len() >= 40,
            "Evasive table should have many channels"
        );
    }

    #[test]
    fn test_sdr_manager() {
        let mut mgr = SdrManager::new();
        mgr.apply_config(SdrConfig::balanced(SdrDriverType::Simulated, 433_175_000));
        assert!(mgr.enabled);

        mgr.record_rx("peer_abc", 128, -85.0, 12.0);
        mgr.record_tx("peer_abc", 64);
        mgr.record_fhss_hop("peer_abc");

        let agg = mgr.aggregate_stats();
        assert_eq!(agg.rx_bytes, 128);
        assert_eq!(agg.tx_bytes, 64);
        assert_eq!(agg.fhss_hops, 1);
    }

    #[test]
    fn test_channel_sense() {
        // RSSI of -85 dBm (above -90 dBm threshold) → channel is BUSY (not clear)
        let sense = ChannelSense::from_rssi(-85.0, -110.0, -90.0);
        assert!(!sense.clear); // -85 is not < -90 → busy
        assert_eq!(sense.snr_db, 25.0); // -85 - (-110) = 25 dB SNR

        // RSSI of -100 dBm (below -90 dBm threshold) → channel is CLEAR (quiet)
        let sense2 = ChannelSense::from_rssi(-100.0, -110.0, -90.0);
        assert!(sense2.clear); // -100 < -90 → clear
        assert_eq!(sense2.snr_db, 10.0); // -100 - (-110) = 10 dB SNR
    }

    #[test]
    fn test_ism_channel_tables() {
        let ch433 = ism_433_channels();
        assert_eq!(ch433.len(), 20);
        assert!(ch433
            .iter()
            .all(|c| FrequencyBand::classify(c.freq_hz) == Some(FrequencyBand::Uhf)));

        let ch868 = ism_868_channels();
        assert_eq!(ch868.len(), 8);

        let ch915 = ism_915_channels();
        assert_eq!(ch915.len(), 64);

        let evasive = uhf_evasive_channels();
        assert_eq!(evasive.len(), 50);
    }

    #[test]
    fn test_sdr_driver_capabilities() {
        assert_eq!(
            SdrDriverType::LoRaChip {
                model: LoRaChipModel::Sx1276
            }
            .capabilities()
            .has_lora_modem,
            true
        );
        assert_eq!(SdrDriverType::RtlSdr.capabilities().tx_channels, 0);
        assert_eq!(SdrDriverType::LimeSdr.capabilities().rx_channels, 2);
        assert!(SdrDriverType::Simulated.capabilities().max_freq_hz > 30_000_000_000);
    }
}
