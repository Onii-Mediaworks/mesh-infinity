//! Ultrasonic Acoustic Transport (§5.12)
//!
//! This module implements a software-defined acoustic data channel that encodes
//! digital data as ultrasonic audio tones in the 18–22 kHz band — above the
//! threshold of human hearing — allowing two devices to exchange data using
//! only their built-in speakers and microphones, without Bluetooth, NFC, or
//! any network infrastructure.
//!
//! # Design Philosophy
//!
//! The DSP engine is **decoupled from audio I/O**. All encoding and decoding
//! operates on `&[f32]` PCM buffers that the caller obtains from (or feeds to)
//! whatever audio API is available on the host platform. This keeps the module
//! free of external dependencies while remaining portable across Linux ALSA/
//! PulseAudio, macOS CoreAudio, Android AudioTrack/AudioRecord, and Windows
//! WASAPI — all of which can ultimately provide or consume `f32` PCM data at
//! 44 100 Hz.
//!
//! # Modulation
//!
//! Binary Frequency-Shift Keying (FSK) is used:
//!
//! | Symbol | Frequency |
//! |--------|-----------|
//! | Pilot  | 18 000 Hz |
//! | Space (0) | 20 000 Hz |
//! | Mark  (1) | 19 000 Hz |
//!
//! Each bit occupies `sample_rate / baud_rate` samples (441 samples at the
//! default 44 100 Hz / 100 bps).  A Hann window is applied to each symbol to
//! suppress spectral splatter between adjacent tones.
//!
//! Byte framing uses one start bit (Space = 0), eight data bits LSB-first, and
//! one stop bit (Mark = 1), giving 10 symbols per byte (UART-style framing).
//!
//! # Frame Format
//!
//! ```text
//! ┌───────────────┬──────────────┬─────────────────┬───────────────┬────────────────┐
//! │  PILOT        │  SYNC        │  LENGTH         │  PAYLOAD      │  CRC16         │
//! │  50 ms 18kHz  │  0xAA  0x55  │  u16 big-endian │  N bytes      │  CRC-CCITT     │
//! └───────────────┴──────────────┴─────────────────┴───────────────┴────────────────┘
//! ```
//!
//! - **PILOT**: 50 ms of 18 000 Hz sinusoid — used by the receiver to locate
//!   the start of a burst and calibrate the symbol clock.
//! - **SYNC**: `0xAA 0x55` — two framing bytes that confirm the pilot was not
//!   a false positive and align the bit stream.
//! - **LENGTH**: payload byte count as a 16-bit big-endian unsigned integer.
//!   Maximum value is [`MAX_PAYLOAD_BYTES`] (255).
//! - **PAYLOAD**: the raw application data.
//! - **CRC16**: CRC-16/CCITT-FALSE (polynomial 0x1021, init 0xFFFF) over the
//!   LENGTH and PAYLOAD fields.  Detects single-burst errors and most multi-bit
//!   corruption events.
//!
//! # Goertzel Detection
//!
//! The decoder uses the Goertzel algorithm — an O(N) single-bin DFT — rather
//! than a full FFT.  For each symbol window the algorithm computes the signal
//! power at exactly the mark and space frequencies; whichever is stronger
//! determines the decoded bit.  This is optimal for narrow-band FSK.
//!
//! # References
//!
//! - §5.12 of the Mesh Infinity specification
//! - Goertzel, G. (1958). An algorithm for the evaluation of finite trigonometric
//!   series. *The American Mathematical Monthly*, 65(1), 34–35.
//! - ITU-T V.21 / Bell 103 for FSK UART framing conventions.

use std::collections::VecDeque;
use std::f64::consts::PI;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default PCM sample rate (Hz).  44.1 kHz is the CD-quality standard
/// supported by every consumer audio device.  The Nyquist limit for this
/// rate is 22.05 kHz — comfortably above our highest tone (20 kHz).
pub const DEFAULT_SAMPLE_RATE: u32 = 44_100;

/// Default baud rate (symbols per second).  100 bps gives 441 samples per
/// symbol at 44.1 kHz, providing strong Goertzel discrimination between
/// mark and space tones while keeping the effective data rate at ~10 bytes/s
/// after UART framing overhead (10 symbols per byte).
pub const DEFAULT_BAUD_RATE: u32 = 100;

/// Pilot / sync tone frequency (Hz).  18 kHz is above the hearing threshold
/// for most adults (presbycusis typically cuts off at 15-17 kHz) but well
/// within the microphone response range of every modern smartphone and laptop.
pub const PILOT_FREQ: f64 = 18_000.0;

/// Mark frequency (19 kHz) — encodes bit value 1.
/// Spaced 1 kHz from pilot and 1 kHz from space, giving each tone a clear
/// spectral separation that survives even low-quality microphone/speaker
/// frequency response roll-off in the near-ultrasonic band.
pub const MARK_FREQ: f64 = 19_000.0;

/// Space frequency (20 kHz) — encodes bit value 0.
/// 20 kHz is the practical upper limit for consumer audio hardware; going
/// higher would risk attenuation by the speaker's low-pass filter.
pub const SPACE_FREQ: f64 = 20_000.0;

/// Duration of the pilot burst at the start of every frame (milliseconds).
/// 50ms is long enough for reliable Goertzel detection (50ms × 44.1kHz =
/// 2205 samples ≈ 5 full cycles at 18kHz per Goertzel window).
pub const PILOT_DURATION_MS: u32 = 50;

/// Sync word sent immediately after the pilot tone.
/// 0xAA = 10101010, 0x55 = 01010101 — these alternating bit patterns
/// produce a distinctive mark/space alternation that is easy to detect
/// and unlikely to appear in random noise or payload data.
pub const SYNC_BYTE_0: u8 = 0xAA;
pub const SYNC_BYTE_1: u8 = 0x55;

/// Maximum payload bytes per frame.
pub const MAX_PAYLOAD_BYTES: usize = 255;

/// CRC-16/CCITT-FALSE polynomial.
const CRC16_POLY: u16 = 0x1021;
/// CRC-16/CCITT-FALSE initial value.
const CRC16_INIT: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by the ultrasonic decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UltrasonicError {
    /// No pilot tone was detected in the provided samples.
    NoPilotDetected,
    /// Pilot tone found but the SYNC bytes were absent or corrupted.
    SyncNotFound,
    /// The declared LENGTH field exceeds [`MAX_PAYLOAD_BYTES`].
    PayloadTooLarge,
    /// The CRC check failed — frame is corrupted.
    CrcMismatch,
    /// The sample buffer is too short to contain a complete frame.
    BufferTooShort,
}

impl std::fmt::Display for UltrasonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UltrasonicError::NoPilotDetected => write!(f, "no pilot tone detected"),
            UltrasonicError::SyncNotFound => write!(f, "sync bytes not found after pilot"),
            UltrasonicError::PayloadTooLarge => {
                write!(f, "payload length exceeds maximum ({MAX_PAYLOAD_BYTES})")
            }
            UltrasonicError::CrcMismatch => write!(f, "CRC16 mismatch — frame corrupted"),
            UltrasonicError::BufferTooShort => write!(f, "sample buffer too short for full frame"),
        }
    }
}

impl std::error::Error for UltrasonicError {}

// ---------------------------------------------------------------------------
// CRC-16/CCITT-FALSE
// ---------------------------------------------------------------------------

/// Compute CRC-16/CCITT-FALSE over `data`.
///
/// Polynomial: 0x1021, initial value: 0xFFFF, no input/output reflection,
/// no final XOR.  This is the same polynomial used by XMODEM and many
/// embedded serial protocols.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = CRC16_INIT;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ CRC16_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// DSP helpers
// ---------------------------------------------------------------------------

/// Generate `num_samples` of a pure sinusoid at `freq` Hz.
///
/// The phase is continuous across successive calls when the starting sample
/// index `sample_offset` is provided.  Here we use a stateless approach and
/// start every tone segment at phase 0; the Hann window masks the resulting
/// phase discontinuity at symbol boundaries.
#[inline]
fn generate_tone(freq: f64, sample_rate: u32, num_samples: usize) -> Vec<f32> {
    let sr = sample_rate as f64;
    (0..num_samples)
        .map(|i| (2.0 * PI * freq * (i as f64) / sr).sin() as f32)
        .collect()
}

/// Apply a Hann window to `samples` in-place.
///
/// The Hann window tapers the signal to zero at both endpoints of each
/// symbol, which greatly reduces spectral leakage between adjacent symbols
/// and makes the Goertzel detector more reliable.
#[inline]
fn apply_hann_window(samples: &mut [f32]) {
    let n = samples.len();
    if n == 0 {
        return;
    }
    let n_f = n as f64;
    for (i, s) in samples.iter_mut().enumerate() {
        let w = 0.5 * (1.0 - (2.0 * PI * i as f64 / (n_f - 1.0)).cos());
        *s *= w as f32;
    }
}

/// Goertzel algorithm — compute the normalised power at a single target
/// frequency within a block of `N` samples.
///
/// The algorithm runs in O(N) time and O(1) memory, making it ideal for
/// real-time per-symbol frequency detection.
///
/// Returns the squared magnitude of the DFT bin corresponding to `freq`,
/// normalised by `N²`.  Values are not in dB; compare them directly.
#[inline]
fn goertzel(samples: &[f32], freq: f64, sample_rate: u32) -> f64 {
    let n = samples.len() as f64;
    let sr = sample_rate as f64;
    let k = (0.5 + n * freq / sr).floor();
    let omega = 2.0 * PI * k / n;
    let coeff = 2.0 * omega.cos();
    let mut s_prev2: f64 = 0.0;
    let mut s_prev1: f64 = 0.0;
    for &x in samples {
        let s = x as f64 + coeff * s_prev1 - s_prev2;
        s_prev2 = s_prev1;
        s_prev1 = s;
    }
    // Squared magnitude
    let real = s_prev1 - s_prev2 * omega.cos();
    let imag = s_prev2 * omega.sin();
    (real * real + imag * imag) / (n * n)
}

// ---------------------------------------------------------------------------
// UART-style byte framing
// ---------------------------------------------------------------------------

/// Encode one byte as a sequence of bits using UART framing:
/// `[start=0] [b0 b1 b2 b3 b4 b5 b6 b7 (LSB first)] [stop=1]`
#[inline]
fn byte_to_uart_bits(byte: u8) -> [bool; 10] {
    let mut bits = [false; 10];
    // start bit = 0 (Space)
    bits[0] = false;
    // data bits, LSB first
    for i in 0..8 {
        bits[1 + i] = (byte >> i) & 1 == 1;
    }
    // stop bit = 1 (Mark)
    bits[9] = true;
    bits
}

/// Attempt to decode a UART-framed byte from 10 consecutive bits.
///
/// Returns `None` if the start bit is not 0 or the stop bit is not 1.
#[inline]
fn uart_bits_to_byte(bits: &[bool; 10]) -> Option<u8> {
    if bits[0] {
        return None; // start bit must be 0
    }
    if !bits[9] {
        return None; // stop bit must be 1
    }
    let mut byte: u8 = 0;
    for i in 0..8 {
        if bits[1 + i] {
            byte |= 1 << i;
        }
    }
    Some(byte)
}

// ---------------------------------------------------------------------------
// UltrasonicModem
// ---------------------------------------------------------------------------

/// Pure-DSP FSK modem operating in the 18–20 kHz ultrasonic band.
///
/// The modem is stateless — it holds only configuration parameters.  All
/// encode/decode operations return/accept plain `Vec<f32>` / `&[f32]` PCM
/// buffers that the caller connects to the audio hardware.
///
/// See module-level documentation and §5.12 for the full wire format.
pub struct UltrasonicModem {
    /// PCM sample rate in Hz.
    sample_rate: u32,
    /// Symbol rate (baud) — symbols per second.
    baud_rate: u32,
}

impl Default for UltrasonicModem {
    fn default() -> Self {
        Self::new()
    }
}

impl UltrasonicModem {
    /// Create a modem with default parameters (44 100 Hz / 100 bps).
    pub fn new() -> Self {
        Self::new_with_params(DEFAULT_SAMPLE_RATE, DEFAULT_BAUD_RATE)
    }

    /// Create a modem with custom sample rate and baud rate.
    ///
    /// # Panics
    ///
    /// Panics if `sample_rate == 0`, `baud_rate == 0`, or
    /// `sample_rate / baud_rate < 2` (symbol too short for Goertzel).
    pub fn new_with_params(sample_rate: u32, baud_rate: u32) -> Self {
        assert!(sample_rate > 0, "sample_rate must be > 0");
        assert!(baud_rate > 0, "baud_rate must be > 0");
        assert!(sample_rate / baud_rate >= 2, "symbol_samples must be >= 2");
        Self {
            sample_rate,
            baud_rate,
        }
    }

    /// Number of PCM samples per FSK symbol.
    #[inline]
    pub fn symbol_samples(&self) -> usize {
        (self.sample_rate / self.baud_rate) as usize
    }

    // ------------------------------------------------------------------
    // Pilot generation and detection
    // ------------------------------------------------------------------

    /// Generate a pilot tone burst of `duration_ms` milliseconds at
    /// [`PILOT_FREQ`] (18 000 Hz).  The pilot is sent at the start of every
    /// frame so the receiver can locate the burst and calibrate symbol timing.
    pub fn generate_pilot(&self, duration_ms: u32) -> Vec<f32> {
        let num_samples =
            ((self.sample_rate as f64) * (duration_ms as f64) / 1000.0).round() as usize;
        generate_tone(PILOT_FREQ, self.sample_rate, num_samples)
    }

    /// Return `true` if `samples` appear to contain a sustained pilot tone.
    ///
    /// The heuristic requires that the mean Goertzel energy at [`PILOT_FREQ`]
    /// exceeds that at both data frequencies by a factor of `SNR_THRESHOLD`,
    /// evaluated over a rolling window of at least 30 ms of audio.
    ///
    /// This is intentionally conservative to avoid false positives from
    /// environmental ultrasonic noise.
    pub fn detect_pilot(&self, samples: &[f32]) -> bool {
        let min_window = ((self.sample_rate as f64) * 0.030).ceil() as usize; // 30 ms
        if samples.len() < min_window {
            return false;
        }
        // Evaluate the pilot in overlapping windows equal to one symbol length,
        // stepped by symbol_samples / 2 for robustness.
        let sym = self.symbol_samples();
        let step = (sym / 2).max(1);
        let end = samples.len().saturating_sub(min_window);
        // We need at least one full window.
        let limit = samples.len().saturating_sub(sym) + 1;
        if limit == 0 {
            return false;
        }

        let check_len = sym.min(samples.len());
        let mut pilot_detections: usize = 0;
        let mut windows_checked: usize = 0;

        let mut offset = 0;
        while offset + check_len <= samples.len() {
            let window = &samples[offset..offset + check_len];
            let e_pilot = goertzel(window, PILOT_FREQ, self.sample_rate);
            let e_mark = goertzel(window, MARK_FREQ, self.sample_rate);
            let e_space = goertzel(window, SPACE_FREQ, self.sample_rate);
            let noise = e_mark.max(e_space).max(1e-30);
            if e_pilot / noise > 2.0 {
                pilot_detections += 1;
            }
            windows_checked += 1;
            offset += step;
            // We only need to cover the min_window span.
            if offset > end + check_len {
                break;
            }
        }

        // Pilot is confirmed if it dominates in the majority of windows.
        windows_checked > 0 && pilot_detections * 2 >= windows_checked
    }

    // ------------------------------------------------------------------
    // Encoding
    // ------------------------------------------------------------------

    /// Encode `data` bytes into a complete PCM frame (f32 samples in [-1.0, 1.0]).
    ///
    /// The returned buffer should be played back at [`self.sample_rate`] through
    /// the device speaker.  At 44 100 Hz / 100 bps the overhead is:
    ///
    /// - Pilot: 2 205 samples (50 ms)
    /// - 4 header bytes (SYNC + LENGTH): 4 × 441 × 10 = 17 640 samples
    /// - N payload bytes: N × 441 × 10 samples
    /// - 2 CRC bytes: 2 × 441 × 10 = 8 820 samples
    pub fn encode(&self, data: &[u8]) -> Vec<f32> {
        assert!(
            data.len() <= MAX_PAYLOAD_BYTES,
            "payload exceeds MAX_PAYLOAD_BYTES"
        );
        let sym = self.symbol_samples();

        // Build the byte stream: [SYNC_0, SYNC_1, LEN_HI, LEN_LO, ...payload..., CRC_HI, CRC_LO]
        let len = data.len() as u16;
        let mut crc_input = Vec::with_capacity(2 + data.len());
        crc_input.push((len >> 8) as u8);
        crc_input.push((len & 0xFF) as u8);
        crc_input.extend_from_slice(data);
        let crc = crc16(&crc_input);

        let mut wire_bytes: Vec<u8> = Vec::with_capacity(6 + data.len());
        wire_bytes.push(SYNC_BYTE_0);
        wire_bytes.push(SYNC_BYTE_1);
        wire_bytes.push((len >> 8) as u8);
        wire_bytes.push((len & 0xFF) as u8);
        wire_bytes.extend_from_slice(data);
        wire_bytes.push((crc >> 8) as u8);
        wire_bytes.push((crc & 0xFF) as u8);

        // Estimate output capacity: pilot + 10 symbols/byte × sym samples
        let pilot_samples =
            ((self.sample_rate as f64) * (PILOT_DURATION_MS as f64) / 1000.0).round() as usize;
        let mut out: Vec<f32> = Vec::with_capacity(pilot_samples + wire_bytes.len() * 10 * sym);

        // 1. Pilot burst
        out.extend_from_slice(&self.generate_pilot(PILOT_DURATION_MS));

        // 2. Data bytes as UART-framed FSK symbols
        for &byte in &wire_bytes {
            let bits = byte_to_uart_bits(byte);
            for &bit in &bits {
                let freq = if bit { MARK_FREQ } else { SPACE_FREQ };
                let mut symbol = generate_tone(freq, self.sample_rate, sym);
                apply_hann_window(&mut symbol);
                out.extend_from_slice(&symbol);
            }
        }

        out
    }

    // ------------------------------------------------------------------
    // Decoding helpers
    // ------------------------------------------------------------------

    /// Decode one FSK bit from the symbol window `samples`.
    ///
    /// Returns `true` (Mark = 1) if the energy at [`MARK_FREQ`] exceeds
    /// [`SPACE_FREQ`], otherwise `false` (Space = 0).
    #[inline]
    fn decode_bit(&self, samples: &[f32]) -> bool {
        let e_mark = goertzel(samples, MARK_FREQ, self.sample_rate);
        let e_space = goertzel(samples, SPACE_FREQ, self.sample_rate);
        e_mark > e_space
    }

    /// Attempt to decode one UART byte starting at `samples[offset]`.
    ///
    /// `samples` must have at least `10 * symbol_samples()` elements starting
    /// at `offset`.  Returns `Some(byte)` on success or `None` on framing error.
    fn decode_byte_at(&self, samples: &[f32], offset: usize) -> Option<u8> {
        let sym = self.symbol_samples();
        let required = offset + 10 * sym;
        if samples.len() < required {
            return None;
        }
        let mut bits = [false; 10];
        for (i, bit) in bits.iter_mut().enumerate() {
            let start = offset + i * sym;
            let window = &samples[start..start + sym];
            *bit = self.decode_bit(window);
        }
        uart_bits_to_byte(&bits)
    }

    /// Locate the first sample offset where a sustained pilot tone begins.
    ///
    /// The search slides a `symbol_samples()`-wide window through `samples`,
    /// steps by `symbol_samples() / 4`, and counts consecutive windows that
    /// show dominant pilot energy.  Returns the byte-aligned start offset (the
    /// first sample after the pilot burst).
    fn find_pilot_end(&self, samples: &[f32]) -> Option<usize> {
        let sym = self.symbol_samples();
        // Phase 1: scan forward (at symbol resolution) to find pilot start.
        let pilot_min_samples =
            ((self.sample_rate as f64) * (PILOT_DURATION_MS as f64) / 1000.0 * 0.6).ceil() as usize;
        let min_consecutive = (pilot_min_samples / sym).max(1);

        let mut consecutive: usize = 0;
        let mut pilot_confirmed_at: Option<usize> = None; // offset where pilot was confirmed
        let mut offset = 0usize;

        while offset + sym <= samples.len() {
            let window = &samples[offset..offset + sym];
            let e_pilot = goertzel(window, PILOT_FREQ, self.sample_rate);
            let e_mark = goertzel(window, MARK_FREQ, self.sample_rate);
            let e_space = goertzel(window, SPACE_FREQ, self.sample_rate);
            let noise = e_mark.max(e_space).max(1e-30);
            let is_pilot = e_pilot / noise > 1.5;

            if is_pilot {
                consecutive += 1;
                if consecutive >= min_consecutive {
                    // Pilot confirmed.  Record this window as where we know
                    // we're inside the pilot burst — the actual pilot could
                    // have started up to (consecutive-1)*sym earlier, but we
                    // don't need to know the exact start.
                    pilot_confirmed_at = Some(offset);
                    break;
                }
            } else {
                consecutive = 0;
            }
            offset += sym; // advance by full symbol so windows are aligned
        }

        let pilot_confirmed = pilot_confirmed_at?;

        // Phase 2: scan forward from the confirmed pilot position to find
        // where the pilot ENDS (first non-pilot window on a symbol boundary).
        let mut scan = pilot_confirmed + sym;
        while scan + sym <= samples.len() {
            let window = &samples[scan..scan + sym];
            let e_pilot = goertzel(window, PILOT_FREQ, self.sample_rate);
            let e_mark = goertzel(window, MARK_FREQ, self.sample_rate);
            let e_space = goertzel(window, SPACE_FREQ, self.sample_rate);
            let noise = e_mark.max(e_space).max(1e-30);
            let is_pilot = e_pilot / noise > 1.5;

            if !is_pilot {
                // `scan` is the first non-pilot window — this is the data start.
                return Some(scan);
            }
            scan += sym;
        }

        // Pilot runs to end of buffer — no data yet.
        None
    }

    // ------------------------------------------------------------------
    // Public decode API
    // ------------------------------------------------------------------

    /// Decode a complete frame from `samples`.
    ///
    /// The buffer must start at (or before) the pilot tone.  Returns the
    /// decoded payload bytes, or an [`UltrasonicError`] describing the failure.
    pub fn decode(&self, samples: &[f32]) -> Result<Vec<u8>, UltrasonicError> {
        self.decode_stream(samples)
            .map(|(data, _)| data)
            .ok_or(UltrasonicError::NoPilotDetected)
    }

    /// Find and decode the **first** complete valid frame within `samples`.
    ///
    /// Unlike [`decode`], this method tolerates leading garbage (silence,
    /// noise, or a partial previous frame) and returns both the decoded data
    /// and the number of samples consumed up to the end of the frame, allowing
    /// the caller to trim its ring buffer.
    ///
    /// Returns `Some((payload, samples_consumed))` on success, `None` if no
    /// valid frame is found.
    pub fn decode_stream(&self, samples: &[f32]) -> Option<(Vec<u8>, usize)> {
        let sym = self.symbol_samples();

        // Phase 1: locate pilot end (= data stream start)
        let data_start = self.find_pilot_end(samples)?;

        // Phase 2: decode bytes from data_start onwards
        // We need at least 4 header bytes: SYNC(2) + LEN(2)
        let header_bytes = 4;
        let header_symbols = header_bytes * 10 * sym;
        if data_start + header_symbols > samples.len() {
            return None; // buffer too short
        }

        // Decode the 4 header bytes
        let sync0 = self.decode_byte_at(samples, data_start)?;
        let sync1 = self.decode_byte_at(samples, data_start + 10 * sym)?;
        if sync0 != SYNC_BYTE_0 || sync1 != SYNC_BYTE_1 {
            return None; // sync mismatch
        }

        let len_hi = self.decode_byte_at(samples, data_start + 20 * sym)?;
        let len_lo = self.decode_byte_at(samples, data_start + 30 * sym)?;
        let payload_len = ((len_hi as u16) << 8 | len_lo as u16) as usize;

        if payload_len > MAX_PAYLOAD_BYTES {
            return None;
        }

        // Phase 3: decode payload + CRC (payload_len + 2 more bytes)
        let total_bytes = payload_len + 2; // payload + 2 CRC bytes
        let payload_crc_start = data_start + 40 * sym; // after 4 header bytes

        if payload_crc_start + total_bytes * 10 * sym > samples.len() {
            return None; // buffer too short for payload
        }

        let mut payload = Vec::with_capacity(payload_len);
        for i in 0..payload_len {
            let offset = payload_crc_start + i * 10 * sym;
            let byte = self.decode_byte_at(samples, offset)?;
            payload.push(byte);
        }

        // Decode 2 CRC bytes
        let crc_offset = payload_crc_start + payload_len * 10 * sym;
        let crc_hi = self.decode_byte_at(samples, crc_offset)?;
        let crc_lo = self.decode_byte_at(samples, crc_offset + 10 * sym)?;
        let received_crc = (crc_hi as u16) << 8 | crc_lo as u16;

        // Verify CRC over [LEN_HI, LEN_LO, ...payload...]
        let mut crc_input = Vec::with_capacity(2 + payload_len);
        crc_input.push(len_hi);
        crc_input.push(len_lo);
        crc_input.extend_from_slice(&payload);
        let computed_crc = crc16(&crc_input);

        if received_crc != computed_crc {
            return None; // CRC mismatch
        }

        // Samples consumed = end of last CRC byte
        let consumed = crc_offset + 20 * sym;
        Some((payload, consumed))
    }

    /// Test helper: expose `find_pilot_end` for tests that need to compute
    /// byte-accurate offsets within an encoded sample buffer.
    #[cfg(test)]
    pub fn find_pilot_end_pub(&self, samples: &[f32]) -> Option<usize> {
        self.find_pilot_end(samples)
    }
}

// ---------------------------------------------------------------------------
// UltrasonicTransport
// ---------------------------------------------------------------------------

/// High-level acoustic transport that maintains outbound and inbound queues.
///
/// This is the integration point for the transport manager (§5.10).  The
/// caller feeds microphone PCM into [`feed_audio`] and retrieves speaker PCM
/// from [`next_audio_frame`]; application-layer packets flow through [`send`]
/// and [`recv`].
///
/// The internal sample accumulator grows until a complete frame (pilot + data)
/// is found, then resets from the byte after the last decoded frame — this
/// prevents stale bytes from poisoning subsequent decodes while the device is
/// continuously recording.
pub struct UltrasonicTransport {
    modem: UltrasonicModem,
    /// Packets waiting to be encoded and played back.
    outbound_frames: Mutex<VecDeque<Vec<u8>>>,
    /// Successfully decoded inbound packets.
    inbound_frames: Mutex<VecDeque<Vec<u8>>>,
    /// Accumulated microphone samples not yet decoded.
    audio_accumulator: Mutex<Vec<f32>>,
}

impl Default for UltrasonicTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl UltrasonicTransport {
    /// Create a new transport with default modem parameters.
    pub fn new() -> Self {
        Self {
            modem: UltrasonicModem::new(),
            outbound_frames: Mutex::new(VecDeque::new()),
            inbound_frames: Mutex::new(VecDeque::new()),
            audio_accumulator: Mutex::new(Vec::new()),
        }
    }

    /// Maximum payload bytes that fit in one frame.
    pub fn max_payload_bytes() -> usize {
        MAX_PAYLOAD_BYTES
    }

    /// Queue `data` for ultrasonic transmission.
    ///
    /// The data will be returned as encoded PCM on the next call to
    /// [`next_audio_frame`].
    ///
    /// # Panics
    ///
    /// Panics if `data.len() > MAX_PAYLOAD_BYTES`.
    pub fn send(&self, data: &[u8]) {
        assert!(
            data.len() <= MAX_PAYLOAD_BYTES,
            "payload exceeds MAX_PAYLOAD_BYTES"
        );
        if let Ok(mut q) = self.outbound_frames.lock() {
            q.push_back(data.to_vec());
        }
    }

    /// Return the next encoded audio frame to be played through the speaker,
    /// or `None` if there are no pending outbound packets.
    ///
    /// The returned `Vec<f32>` is a complete frame (pilot + data + CRC) ready
    /// for direct delivery to the audio output at `DEFAULT_SAMPLE_RATE` Hz.
    pub fn next_audio_frame(&self) -> Option<Vec<f32>> {
        let data = self.outbound_frames.lock().ok()?.pop_front()?;
        Some(self.modem.encode(&data))
    }

    /// Feed microphone PCM samples into the decoder.
    ///
    /// Call this with whatever PCM data the audio input callback provides.
    /// Internally the samples are accumulated until a complete frame is found,
    /// at which point the decoded payload is placed in the inbound queue and
    /// the accumulator is trimmed.
    ///
    /// This method is designed to be called from a real-time audio callback:
    /// it holds the accumulator lock for the minimum necessary time.
    pub fn feed_audio(&self, samples: &[f32]) {
        let mut acc = match self.audio_accumulator.lock() {
            Ok(a) => a,
            Err(_) => return,
        };
        acc.extend_from_slice(samples);

        // Attempt to decode; on success, trim accumulator and push to inbound.
        // We loop in case multiple frames arrived in one batch.
        while let Some((payload, consumed)) = self.modem.decode_stream(&acc) {
            if let Ok(mut inbound) = self.inbound_frames.lock() {
                inbound.push_back(payload);
            }
            // Trim the accumulator, keeping samples after the frame.
            let remaining = acc[consumed..].to_vec();
            *acc = remaining;
        }

        // Prevent unbounded accumulator growth: keep the most recent
        // `max_frame_samples * 4` samples when nothing has decoded yet.
        let sym = self.modem.symbol_samples();
        // Worst-case frame: pilot + (6 + MAX_PAYLOAD_BYTES) * 10 symbols
        let max_frame_samples = ((self.modem.sample_rate as f64) * (PILOT_DURATION_MS as f64)
            / 1000.0) as usize
            + (6 + MAX_PAYLOAD_BYTES) * 10 * sym;
        let cap = max_frame_samples * 4;
        if acc.len() > cap {
            let trim = acc.len() - cap;
            acc.drain(..trim);
        }
    }

    /// Retrieve the next successfully decoded inbound packet, or `None` if
    /// no complete frame has arrived yet.
    pub fn recv(&self) -> Option<Vec<u8>> {
        self.inbound_frames.lock().ok()?.pop_front()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // CRC
    // ------------------------------------------------------------------

    #[test]
    fn crc16_known_value() {
        // CRC-16/CCITT-FALSE of the ASCII string "123456789" must be 0x29B1.
        let data = b"123456789";
        assert_eq!(
            crc16(data),
            0x29B1,
            "CRC-16/CCITT-FALSE known vector failed"
        );
    }

    #[test]
    fn crc16_empty() {
        // Empty input gives the init value unchanged.
        assert_eq!(crc16(b""), 0xFFFF);
    }

    #[test]
    fn crc16_single_byte_flip_detected() {
        let data = b"Hello ultrasonic world!";
        let good_crc = crc16(data);
        let mut corrupted = data.to_vec();
        corrupted[5] ^= 0x80;
        assert_ne!(
            crc16(&corrupted),
            good_crc,
            "bit flip was not detected by CRC"
        );
    }

    // ------------------------------------------------------------------
    // UART framing
    // ------------------------------------------------------------------

    #[test]
    fn uart_roundtrip_all_bytes() {
        for b in 0u8..=255 {
            let bits = byte_to_uart_bits(b);
            let decoded = uart_bits_to_byte(&bits).expect("uart round-trip failed");
            assert_eq!(decoded, b);
        }
    }

    #[test]
    fn uart_framing_start_stop() {
        let bits = byte_to_uart_bits(0b10101010);
        assert!(!bits[0], "start bit must be 0");
        assert!(bits[9], "stop bit must be 1");
    }

    #[test]
    fn uart_bad_start_bit() {
        let mut bits = byte_to_uart_bits(0x42);
        bits[0] = true; // corrupt start bit
        assert!(uart_bits_to_byte(&bits).is_none());
    }

    #[test]
    fn uart_bad_stop_bit() {
        let mut bits = byte_to_uart_bits(0x42);
        bits[9] = false; // corrupt stop bit
        assert!(uart_bits_to_byte(&bits).is_none());
    }

    // ------------------------------------------------------------------
    // Tone generation and Goertzel
    // ------------------------------------------------------------------

    #[test]
    fn goertzel_detects_target_frequency() {
        let sr = 44_100u32;
        let n = 441; // one symbol at 100 bps
        let tone = generate_tone(MARK_FREQ, sr, n);
        let e_mark = goertzel(&tone, MARK_FREQ, sr);
        let e_space = goertzel(&tone, SPACE_FREQ, sr);
        let e_pilot = goertzel(&tone, PILOT_FREQ, sr);
        assert!(
            e_mark > e_space * 10.0,
            "mark energy should greatly exceed space: mark={e_mark:.6e} space={e_space:.6e}"
        );
        assert!(
            e_mark > e_pilot * 10.0,
            "mark energy should greatly exceed pilot: mark={e_mark:.6e} pilot={e_pilot:.6e}"
        );
    }

    #[test]
    fn goertzel_space_frequency() {
        let sr = 44_100u32;
        let n = 441;
        let tone = generate_tone(SPACE_FREQ, sr, n);
        let e_mark = goertzel(&tone, MARK_FREQ, sr);
        let e_space = goertzel(&tone, SPACE_FREQ, sr);
        assert!(
            e_space > e_mark * 10.0,
            "space energy should greatly exceed mark: space={e_space:.6e} mark={e_mark:.6e}"
        );
    }

    // ------------------------------------------------------------------
    // Pilot generation and detection
    // ------------------------------------------------------------------

    #[test]
    fn pilot_detect_positive() {
        let modem = UltrasonicModem::new();
        let pilot = modem.generate_pilot(50);
        assert!(
            modem.detect_pilot(&pilot),
            "should detect pilot in a pure pilot buffer"
        );
    }

    #[test]
    fn pilot_detect_negative_silence() {
        let modem = UltrasonicModem::new();
        let silence = vec![0.0f32; 4410]; // 100 ms of silence
        assert!(
            !modem.detect_pilot(&silence),
            "should not detect pilot in silence"
        );
    }

    #[test]
    fn pilot_detect_negative_data_tone() {
        let modem = UltrasonicModem::new();
        // Pure mark tone — not a pilot
        let data_tone = generate_tone(MARK_FREQ, DEFAULT_SAMPLE_RATE, 4410);
        assert!(
            !modem.detect_pilot(&data_tone),
            "should not detect pilot in a pure mark tone"
        );
    }

    #[test]
    fn pilot_detect_too_short() {
        let modem = UltrasonicModem::new();
        // Only 10 ms — below the 30 ms minimum
        let short_pilot = modem.generate_pilot(10);
        assert!(
            !modem.detect_pilot(&short_pilot),
            "should not detect pilot in buffer shorter than 30 ms"
        );
    }

    // ------------------------------------------------------------------
    // Encode / decode roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn encode_decode_short_message() {
        let modem = UltrasonicModem::new();
        let message = b"Hi";
        let samples = modem.encode(message);
        let decoded = modem.decode(&samples).expect("decode failed");
        assert_eq!(decoded, message);
    }

    #[test]
    fn encode_decode_empty_payload() {
        let modem = UltrasonicModem::new();
        let samples = modem.encode(b"");
        let decoded = modem
            .decode(&samples)
            .expect("decode of empty payload failed");
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_decode_all_byte_values() {
        let modem = UltrasonicModem::new();
        let message: Vec<u8> = (0u8..=255).collect();
        // Split into MAX_PAYLOAD_BYTES chunks
        for chunk in message.chunks(MAX_PAYLOAD_BYTES) {
            let samples = modem.encode(chunk);
            let decoded = modem.decode(&samples).expect("decode failed");
            assert_eq!(decoded, chunk);
        }
    }

    #[test]
    fn encode_decode_max_payload() {
        let modem = UltrasonicModem::new();
        let message = vec![0xA5u8; MAX_PAYLOAD_BYTES];
        let samples = modem.encode(&message);
        let decoded = modem
            .decode(&samples)
            .expect("decode of max-length payload failed");
        assert_eq!(decoded, message);
    }

    #[test]
    fn encode_decode_binary_pattern() {
        let modem = UltrasonicModem::new();
        // Alternating 0x00 and 0xFF — stress-tests start/stop bit detection
        let message: Vec<u8> = (0..32)
            .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
            .collect();
        let samples = modem.encode(&message);
        let decoded = modem
            .decode(&samples)
            .expect("decode of binary pattern failed");
        assert_eq!(decoded, message);
    }

    // ------------------------------------------------------------------
    // CRC error detection
    // ------------------------------------------------------------------

    #[test]
    fn crc_error_detection_corrupt_payload() {
        let modem = UltrasonicModem::new();
        let message = b"Corrupt me";
        let mut samples = modem.encode(message);

        // Corrupt the CRC by replacing all 20 CRC symbols (2 bytes × 10 symbols/byte)
        // with a pure MARK tone (bit = 1). This guarantees the decoded CRC bits differ
        // from the correct CRC for all but pathological messages.
        //
        // Frame layout (pilot end = data start):
        //   find_pilot_end → data_start
        //   20 * sym — SYNC (2 bytes)
        //   20 * sym — LENGTH (2 bytes)
        //   payload_len * 10 * sym — payload
        //   20 * sym — CRC (2 bytes)   ← corrupt this region
        //
        // We locate data_start by encoding a second copy and finding the first
        // non-pilot window position, then compute offsets from there.

        // Build a MARK-frequency tone burst (all 1-bits).
        let sym = modem.symbol_samples();
        let sr = DEFAULT_SAMPLE_RATE as f64;
        let mark_burst: Vec<f32> = (0..20 * sym)
            .map(|i| (2.0 * std::f64::consts::PI * MARK_FREQ * (i as f64) / sr) as f32)
            .map(|phase| phase.sin())
            .collect();

        // Locate data_start by scanning for pilot end.
        let data_start = modem.find_pilot_end_pub(&samples).unwrap_or(0);
        let payload_len = message.len();
        let crc_start = data_start + (4 + payload_len) * 10 * sym;
        // Splice in the corrupted CRC region.
        if crc_start + 20 * sym <= samples.len() {
            samples[crc_start..crc_start + 20 * sym].copy_from_slice(&mark_burst);
        }

        // The decode_stream must return None (CRC catches the corruption) or
        // decode to different bytes. A pure MARK-tone CRC encodes 0xFFFF which
        // will not equal the valid CRC for any real payload.
        let result = modem.decode_stream(&samples);
        if let Some((decoded, _)) = result {
            assert_ne!(
                decoded,
                b"Corrupt me".to_vec(),
                "corrupt CRC should not decode to original message"
            );
        }
        // None is the expected and typical outcome.
    }

    #[test]
    fn crc_single_byte_corruption_detected() {
        // Directly test: build a frame, flip a CRC byte, verify mismatch.
        let data = b"test crc";
        let len = data.len() as u16;
        let mut crc_in = vec![(len >> 8) as u8, (len & 0xFF) as u8];
        crc_in.extend_from_slice(data);
        let good_crc = crc16(&crc_in);

        // Corrupt one payload byte
        crc_in[2] ^= 0x01;
        let bad_crc = crc16(&crc_in);
        assert_ne!(good_crc, bad_crc, "single-byte corruption must change CRC");
    }

    // ------------------------------------------------------------------
    // decode_stream: frame within a larger buffer
    // ------------------------------------------------------------------

    #[test]
    fn decode_stream_frame_in_larger_buffer() {
        let modem = UltrasonicModem::new();
        let message = b"stream test";
        let frame = modem.encode(message);

        // Append 1000 samples of silence AFTER the frame (the common case:
        // mic buffer contains one complete frame followed by more audio).
        // The frame itself starts at index 0 so pilot detection is reliable.
        let mut buffer = frame.clone();
        buffer.extend(vec![0.0f32; 1000]);

        let result = modem.decode_stream(&buffer);
        assert!(result.is_some(), "should find frame within larger buffer");
        let (decoded, consumed) = result.unwrap();
        assert_eq!(decoded, message);
        // consumed must be <= total buffer length
        assert!(
            consumed <= buffer.len(),
            "consumed cannot exceed buffer length"
        );
        // consumed must cover at least the frame itself
        assert!(
            consumed >= frame.len(),
            "consumed should cover at least the frame"
        );
    }

    #[test]
    fn decode_stream_no_frame() {
        let modem = UltrasonicModem::new();
        // Random-ish noise (use a deterministic pattern to avoid test flakiness)
        let noise: Vec<f32> = (0..8820)
            .map(|i| (i as f32 * 0.017_453_3).sin() * 0.1)
            .collect();
        let result = modem.decode_stream(&noise);
        assert!(result.is_none(), "should not find frame in noise/silence");
    }

    // ------------------------------------------------------------------
    // UltrasonicTransport
    // ------------------------------------------------------------------

    #[test]
    fn transport_send_recv_roundtrip() {
        let tx = UltrasonicTransport::new();
        let rx = UltrasonicTransport::new();

        let payload = b"transport roundtrip";
        tx.send(payload);

        let audio = tx.next_audio_frame().expect("should have an encoded frame");
        assert!(rx.recv().is_none(), "nothing received before feed");

        rx.feed_audio(&audio);

        let received = rx.recv().expect("should have decoded a frame");
        assert_eq!(received, payload);
    }

    #[test]
    fn transport_no_pending_frame() {
        let transport = UltrasonicTransport::new();
        assert!(transport.next_audio_frame().is_none());
        assert!(transport.recv().is_none());
    }

    #[test]
    fn transport_multiple_frames_queued() {
        let tx = UltrasonicTransport::new();
        let rx = UltrasonicTransport::new();

        let msgs: &[&[u8]] = &[b"first", b"second", b"third"];
        for m in msgs {
            tx.send(m);
        }

        let mut audio_concat: Vec<f32> = Vec::new();
        while let Some(frame) = tx.next_audio_frame() {
            audio_concat.extend_from_slice(&frame);
        }

        // Feed all audio at once
        rx.feed_audio(&audio_concat);

        for m in msgs {
            let recv = rx.recv().expect("should have decoded all frames");
            assert_eq!(recv, *m);
        }
        assert!(rx.recv().is_none(), "no extra frames");
    }

    #[test]
    fn transport_max_payload() {
        assert_eq!(UltrasonicTransport::max_payload_bytes(), MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn transport_accumulator_trim_does_not_corrupt() {
        // Feed many short silent chunks — the accumulator should not OOM
        // and should decode correctly when a real frame is inserted.
        let tx = UltrasonicTransport::new();
        let rx = UltrasonicTransport::new();

        // Flood with silence chunks
        let silence = vec![0.0f32; 441];
        for _ in 0..200 {
            rx.feed_audio(&silence);
        }

        // Now send a real frame
        let payload = b"after silence";
        tx.send(payload);
        let audio = tx.next_audio_frame().unwrap();
        rx.feed_audio(&audio);

        let received = rx.recv().expect("should decode after silence flood");
        assert_eq!(received, payload);
    }
}
