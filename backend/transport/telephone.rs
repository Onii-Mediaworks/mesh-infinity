//! Telephone Network Transport (§5.16)
//!
//! ## §5.16.1 — PSTN Dial-Up Bridge
//!
//! A PSTN dial-up bridge uses the standard serial modem transport (§5.13 USB
//! Serial, or an AT-command modem connected to a serial port).  When the call
//! connects the result is a raw byte pipe identical to a direct serial link.
//! No special encoding is needed; [`crate::transport::usb_serial`] handles
//! the physical framing.
//!
//! ## §5.16.2 — Cellular Voice Subchannel
//!
//! When two Mesh Infinity users are on an active phone call their clients
//! exchange data inaudibly using a **codec-surviving FSK modem** embedded in
//! the call audio.
//!
//! ### Encoding parameters
//!
//! | Parameter | Value | Reason |
//! |-----------|-------|--------|
//! | Mark (bit 1) | 1200 Hz | Survives AMR-WB, EVS, G.711 codecs |
//! | Space (bit 0) | 2200 Hz | Same |
//! | Pilot carrier | 600 Hz | Presence detection, starts first |
//! | Baud rate | 50 bps | Conservative: 8000 / 160 samples/symbol |
//! | Sample rate | 8000 Hz | Narrowband voice codec sample rate |
//! | Framing | UART-style (1 start + 8 data + 1 stop) | 10 symbols/byte |
//! | Error correction | Reed-Solomon RS(255,223) | 16 parity bytes |
//!
//! The pilot carrier is transmitted for 1 second before data to let the
//! receiver synchronize.  The receiver runs a Goertzel filter on all three
//! frequencies (600, 1200, 2200 Hz) and picks the dominant tone per symbol.
//!
//! ### Integration with Sigma protocol (§3.5.4)
//!
//! The subchannel carries the Sigma handshake over the 50 bps channel.
//! After Reed-Solomon encoding the wire bandwidth is ≈ 50 × 223/255 ≈ 44 bps
//! effective.  The Sigma handshake is ≈ 200 bytes per side → ~36 seconds.
//! This is within the §5.16.3 flow's patience threshold.
//!
//! ### Platform implementation
//!
//! Platform audio (microphone / speaker) is abstracted via the
//! [`AudioPlatform`] trait.  Platform-specific implementations inject
//! 8000 Hz PCM samples.  This module handles all encoding/decoding.

use std::f64::consts::PI;

// ────────────────────────────────────────────────────────────────────────────
// Modem parameters
// ────────────────────────────────────────────────────────────────────────────

/// Narrowband voice codec sample rate (Hz).  All cellular voice codecs
/// (AMR-NB, G.711, GSM-FR) operate at 8 kHz.  AMR-WB uses 16 kHz but
/// downsamples for narrowband compatibility, so 8 kHz is the safe baseline
/// that survives transcoding across any cellular network.
pub const SAMPLE_RATE: u32 = 8000;

/// Baud rate (symbols per second).  50 bps is extremely conservative —
/// it gives each symbol 160 audio samples, which provides enough redundancy
/// for the Goertzel detector to discriminate tones even after lossy codec
/// processing (AMR at 4.75 kbps introduces severe quantization).
pub const BAUD_RATE: u32 = 50;

/// Samples per symbol — 160 samples at 8 kHz = 20ms per symbol.
/// This matches the AMR codec frame length (20ms), ensuring each symbol
/// falls entirely within a single codec frame and is not split across
/// two frames with potentially different quantization.
pub const SAMPLES_PER_SYMBOL: usize = (SAMPLE_RATE / BAUD_RATE) as usize;

/// Mark frequency (1200 Hz) — represents bit value 1.
/// Chosen in the 300–3400 Hz voice passband because cellular codecs
/// aggressively filter everything outside this range.  1200 Hz and
/// 2200 Hz are spaced far enough apart (~1 kHz) that even aggressive
/// codec quantization cannot confuse them.
pub const MARK_FREQ: f64 = 1200.0;

/// Space frequency (2200 Hz) — represents bit value 0.
/// Bell 202 uses the same mark/space frequencies; this is intentional
/// for compatibility with APRS and legacy amateur radio modems.
pub const SPACE_FREQ: f64 = 2200.0;

/// Pilot carrier frequency (600 Hz) — used for presence detection.
/// Deliberately below the mark/space band so the Goertzel detector can
/// unambiguously distinguish pilot from data.  600 Hz is above the
/// voice codec high-pass filter cutoff (~300 Hz) but below the lowest
/// data tone, creating a clean energy-ratio signature.
pub const PILOT_FREQ: f64 = 600.0;

/// Pilot duration: 1 second (8000 samples).  Long enough for the
/// receiver to reliably detect the tone and synchronize, even through
/// cellular codec processing which introduces ~50ms startup artifacts.
pub const PILOT_DURATION_SAMPLES: usize = SAMPLE_RATE as usize;

/// Goertzel detector threshold: pilot energy must exceed mark+space
/// energy by this factor to declare "pilot present".  A threshold of 2.0
/// provides ~6 dB of discrimination margin, which is sufficient because
/// the pilot frequency (600 Hz) is well-separated from mark (1200) and
/// space (2200), so codec artifacts produce minimal cross-frequency leakage.
pub const PILOT_DETECT_THRESHOLD: f64 = 2.0;

/// Reed-Solomon code parameters: RS(255, 223) over GF(2^8).
/// This gives t=16 symbol error correction per block.  At 50 baud with
/// typical cellular bit error rates (~1%), a 255-byte block accumulates
/// ~2-3 errors — well within the correction capacity.  RS(255,223) is the
/// same code used in CCSDS deep-space communications, chosen for its
/// proven performance in noisy channels.
pub const RS_N: usize = 255;
pub const RS_K: usize = 223;
/// 32 parity bytes provide correction of up to 16 symbol errors
/// and detection of up to 32 symbol errors per block.
pub const RS_PARITY: usize = RS_N - RS_K;

// ────────────────────────────────────────────────────────────────────────────
// FSK encoder
// ────────────────────────────────────────────────────────────────────────────

/// Encode `data` bytes as FSK audio samples (i16 PCM, 8000 Hz).
///
/// The output starts with a pilot tone (`PILOT_DURATION_SAMPLES` samples)
/// followed by the UART-framed data (RS-encoded).
///
/// Audio levels are normalised to ±16384 (half of i16 range) to leave
/// headroom for codec processing.
pub fn encode(data: &[u8]) -> Vec<i16> {
    let rs_encoded = rs_encode(data);
    let mut samples = Vec::new();

    // Pilot tone burst.
    samples.extend(generate_tone(PILOT_FREQ, PILOT_DURATION_SAMPLES));

    // UART framing: start bit (0) + 8 data bits LSB-first + stop bit (1).
    for &byte in &rs_encoded {
        // Start bit = 0 (space).
        samples.extend(generate_tone(SPACE_FREQ, SAMPLES_PER_SYMBOL));
        for bit in 0..8u8 {
            let b = (byte >> bit) & 1;
            let freq = if b == 1 { MARK_FREQ } else { SPACE_FREQ };
            samples.extend(generate_tone(freq, SAMPLES_PER_SYMBOL));
        }
        // Stop bit = 1 (mark).
        samples.extend(generate_tone(MARK_FREQ, SAMPLES_PER_SYMBOL));
    }

    samples
}

/// Generate `n` samples of a pure sinusoidal tone at `freq` Hz.
fn generate_tone(freq: f64, n: usize) -> Vec<i16> {
    let mut out = Vec::with_capacity(n);
    let omega = 2.0 * PI * freq / SAMPLE_RATE as f64;
    for i in 0..n {
        let amplitude = 16384.0 * (omega * i as f64).sin();
        out.push(amplitude as i16);
    }
    out
}

// ────────────────────────────────────────────────────────────────────────────
// FSK decoder
// ────────────────────────────────────────────────────────────────────────────

/// Goertzel single-bin DFT for one frequency over a window of samples.
///
/// The Goertzel algorithm is computationally cheaper than a full FFT when
/// you only need the energy at a few specific frequencies (3 in our case:
/// pilot, mark, space).  It runs in O(N) per frequency with only 3
/// multiplies per sample, versus O(N log N) for an FFT.
///
/// The final energy calculation uses the recurrence relation's last two
/// values to compute |X[k]|^2 without complex arithmetic.
fn goertzel(samples: &[i16], freq: f64) -> f64 {
    let n = samples.len() as f64;
    let k = (n * freq / SAMPLE_RATE as f64).round();
    let omega = 2.0 * PI * k / n;
    let coeff = 2.0 * omega.cos();
    let (mut s_prev, mut s_prev2) = (0.0f64, 0.0f64);
    for &s in samples {
        let s_cur = s as f64 + coeff * s_prev - s_prev2;
        s_prev2 = s_prev;
        s_prev = s_cur;
    }
    s_prev2 * s_prev2 + s_prev * s_prev - coeff * s_prev * s_prev2
}

/// Decode UART-framed FSK audio samples.
///
/// Returns the decoded bytes on success, or `Err` if pilot is not detected
/// or if Reed-Solomon decoding fails.
pub fn decode(samples: &[i16]) -> Result<Vec<u8>, &'static str> {
    // Find pilot start.
    let data_start = find_pilot_end(samples).ok_or("pilot not detected")?;

    // Decode UART-framed bytes from data_start.
    let mut decoded_bytes = Vec::new();
    let mut pos = data_start;

    while pos + 10 * SAMPLES_PER_SYMBOL <= samples.len() {
        // Start bit should be SPACE (0); verify.
        let start_window = &samples[pos..pos + SAMPLES_PER_SYMBOL];
        let mark_e = goertzel(start_window, MARK_FREQ);
        let space_e = goertzel(start_window, SPACE_FREQ);
        if mark_e > space_e {
            // Not a valid start bit — skip one symbol and try again.
            pos += SAMPLES_PER_SYMBOL;
            continue;
        }
        pos += SAMPLES_PER_SYMBOL; // consume start bit

        let mut byte_val: u8 = 0;
        for bit in 0..8usize {
            if pos + SAMPLES_PER_SYMBOL > samples.len() {
                break;
            }
            let window = &samples[pos..pos + SAMPLES_PER_SYMBOL];
            let mark_e = goertzel(window, MARK_FREQ);
            let space_e = goertzel(window, SPACE_FREQ);
            if mark_e > space_e {
                byte_val |= 1 << bit;
            }
            pos += SAMPLES_PER_SYMBOL;
        }
        // Consume stop bit (ignored for value).
        pos += SAMPLES_PER_SYMBOL;
        decoded_bytes.push(byte_val);
    }

    if decoded_bytes.is_empty() {
        return Err("no data decoded after pilot");
    }

    rs_decode(&decoded_bytes)
}

/// Find where the pilot tone ends and data begins.
///
/// Scans forward through the sample buffer looking for the transition from
/// pilot energy dominant → mark/space energy dominant.
/// Returns the sample index of the first data symbol, or `None`.
pub fn find_pilot_end(samples: &[i16]) -> Option<usize> {
    let step = SAMPLES_PER_SYMBOL;
    if samples.len() < step {
        return None;
    }

    // Phase 1: scan forward to find the end of the pilot burst.
    let mut in_pilot = false;
    let mut i = 0;
    while i + step <= samples.len() {
        let window = &samples[i..i + step];
        let pilot_e = goertzel(window, PILOT_FREQ);
        let mark_e = goertzel(window, MARK_FREQ);
        let space_e = goertzel(window, SPACE_FREQ);
        let data_e = mark_e + space_e;

        if data_e < 1.0 {
            i += step;
            continue;
        }
        let pilot_ratio = pilot_e / data_e;

        if pilot_ratio > PILOT_DETECT_THRESHOLD {
            in_pilot = true;
        } else if in_pilot {
            // Pilot ended — this window is where data begins.
            return Some(i);
        }
        i += step;
    }
    None
}

// ────────────────────────────────────────────────────────────────────────────
// Reed-Solomon codec (GF(2^8), primitive polynomial 0x11D = x^8+x^4+x^3+x^2+1)
// ────────────────────────────────────────────────────────────────────────────

/// Galois Field GF(2^8) primitive polynomial.
/// 0x187 = x^8 + x^7 + x^2 + x + 1, the CCSDS polynomial used in
/// DVB-S, CD-ROM, and deep-space communications standards.  This is
/// an irreducible polynomial over GF(2) that generates all 255 nonzero
/// elements of GF(256) via repeated multiplication by the primitive
/// element alpha = 2.
const GF_POLY: u16 = 0x187;

/// GF(2^8) logarithm and antilogarithm (exponentiation) tables.
/// These precomputed tables convert multiplication to addition in
/// log-space: mul(a,b) = exp[log[a] + log[b]], which is O(1) per
/// multiply instead of the O(8) bit-by-bit polynomial multiplication.
/// The exp table is doubled to 512 entries to avoid modular reduction
/// on the sum — a classic space-time trade-off.
struct Gf {
    log: [u8; 256],
    exp: [u8; 512],
}

impl Gf {
    fn build() -> Self {
        let mut log = [0u8; 256];
        let mut exp = [0u8; 512];
        let mut x = 1u16;
        for (i, entry) in exp[..255].iter_mut().enumerate() {
            *entry = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= GF_POLY;
            }
        }
        for i in 255..512usize {
            exp[i] = exp[i - 255];
        }
        log[0] = 0; // undefined but we guard against using it
        Gf { log, exp }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let la = self.log[a as usize] as usize;
        let lb = self.log[b as usize] as usize;
        self.exp[la + lb]
    }

    fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    fn pow(&self, base: u8, n: usize) -> u8 {
        if n == 0 {
            return 1;
        }
        if base == 0 {
            return 0;
        }
        let l = self.log[base as usize] as usize;
        self.exp[(l * n) % 255]
    }

    fn inv(&self, a: u8) -> Option<u8> {
        // GF(256) does not define the inverse of 0; return None so callers
        // can propagate the error rather than unwinding the process.
        if a == 0 {
            return None;
        }
        let l = self.log[a as usize] as usize;
        Some(self.exp[255 - l])
    }
}

/// Compute RS(255,K) generator polynomial coefficients.
///
/// The generator is `g(x) = ∏(x - α^i)` for i in [1..=RS_PARITY].
fn rs_generator(gf: &Gf) -> Vec<u8> {
    let t = RS_PARITY;
    let mut g = vec![1u8];
    for i in 1..=(t as u8) {
        let root = gf.pow(2, i as usize); // α^i, α = 2
                                          // Multiply g by (x + root) in GF(2^8).
                                          // new_g[j]   += g[j] * root   (multiply by constant 'root')
                                          // new_g[j+1] += g[j]          (multiply by x)
        let mut new_g = vec![0u8; g.len() + 1];
        for (j, &gj) in g.iter().enumerate() {
            new_g[j] ^= gf.mul(gj, root);
            new_g[j + 1] ^= gj;
        }
        g = new_g;
    }
    g
}

/// RS-encode `data`.
///
/// Prepends a 2-byte little-endian length prefix so `rs_decode` can recover
/// the exact original byte count without relying on zero-stripping.
///
/// If `data.len() + 2 > RS_K`, data is split into RS_K-byte chunks (with
/// the length prefix in the first chunk only).
pub fn rs_encode(data: &[u8]) -> Vec<u8> {
    let gf = Gf::build();
    let gen = rs_generator(&gf);
    let mut out = Vec::new();

    // Prepend 2-byte length so the decoder can recover the exact payload size.
    let mut with_len = Vec::with_capacity(data.len() + 2);
    with_len.extend_from_slice(&(data.len() as u16).to_le_bytes());
    with_len.extend_from_slice(data);

    for chunk in with_len.chunks(RS_K) {
        // Pad to RS_K if last chunk is short.
        let mut padded = chunk.to_vec();
        padded.resize(RS_K, 0);

        // Polynomial division to get parity.
        let mut remainder = [0u8; RS_PARITY];
        for &b in &padded {
            // feedback = current byte XOR highest-degree remainder coefficient
            let feedback = b ^ remainder[RS_PARITY - 1];
            // Shift register: reg[i] = reg[i-1] XOR gen[i]*feedback
            for i in (1..RS_PARITY).rev() {
                remainder[i] = remainder[i - 1] ^ gf.mul(gen[i], feedback);
            }
            remainder[0] = gf.mul(gen[0], feedback);
        }

        out.extend_from_slice(&padded);
        // Parity bytes: syndrome evaluation treats chunk[K+j] as the coefficient of
        // x^(PARITY-1-j), so highest-degree parity first = remainder[PARITY-1..0].
        out.extend(remainder.iter().rev().copied());
    }
    out
}

/// RS-decode `codeword`.
///
/// Attempts to correct up to `RS_PARITY / 2 = 16` symbol errors.
/// Returns the decoded data bytes (without parity), or `Err` on
/// uncorrectable errors.
pub fn rs_decode(codeword: &[u8]) -> Result<Vec<u8>, &'static str> {
    let gf = Gf::build();
    let block_len = RS_N; // 255 symbols per block
    let mut out = Vec::new();

    for chunk in codeword.chunks(block_len) {
        if chunk.len() < RS_PARITY {
            return Err("codeword too short");
        }

        // Compute syndromes S_i = c(α^i) for i in [1..=RS_PARITY].
        let mut syndromes = vec![0u8; RS_PARITY];
        let mut all_zero = true;
        for (i, s) in syndromes.iter_mut().enumerate() {
            let alpha_i = gf.pow(2, i + 1);
            let mut eval = 0u8;
            for &c in chunk {
                eval = gf.add(gf.mul(eval, alpha_i), c);
            }
            *s = eval;
            if eval != 0 {
                all_zero = false;
            }
        }

        if all_zero {
            // No errors — extract data portion.
            let data_len = chunk.len() - RS_PARITY;
            out.extend_from_slice(&chunk[..data_len]);
            continue;
        }

        // Berlekamp-Massey to find error locator polynomial.
        let sigma = berlekamp_massey(&gf, &syndromes)?;
        let num_errors = sigma.len() - 1;
        if num_errors > RS_PARITY / 2 {
            return Err("too many errors to correct");
        }

        // Chien search: find error locations.
        //
        // Our generator has roots at α^1..α^t, so for an error at codeword
        // array position pos, the error locator polynomial Λ has a root at
        // X_pos^{-1} = α^{pos+1}.  We test Λ(α^{pos+1}) == 0 for each pos.
        let n = chunk.len();
        let mut error_pos = Vec::new();
        for i in 0..n {
            // Root of Λ for array position i is α^{i+1}.
            let root = gf.pow(2, i + 1);
            let mut eval = 0u8;
            let mut alpha_pow = 1u8;
            for &s in &sigma {
                eval ^= gf.mul(s, alpha_pow);
                alpha_pow = gf.mul(alpha_pow, root);
            }
            if eval == 0 {
                error_pos.push(i);
            }
        }

        if error_pos.len() != num_errors {
            return Err("Chien search found unexpected number of roots");
        }

        // Forney algorithm: compute error magnitudes.
        //
        // With generator roots at α^1..α^t (b=1), the Forney formula simplifies to:
        //   e_pos = Ω(X_pos^{-1}) / Λ'(X_pos^{-1})
        // where X_pos^{-1} = α^{pos+1}.  (The X_pos^{1-b} = X_pos^0 = 1 factor
        // drops out since b=1.)
        let mut corrected = chunk.to_vec();
        // Compute omega(x) = S(x) * sigma(x) mod x^t.
        let mut omega = vec![0u8; RS_PARITY];
        for i in 0..RS_PARITY {
            for j in 0..sigma.len() {
                if i + j < RS_PARITY {
                    omega[i + j] ^= gf.mul(syndromes[i], sigma[j]);
                }
            }
        }
        // Formal derivative of sigma: σ'(x) = σ_1 + 3*σ_3*x^2 + ...
        // In GF(2^8), 2*σ_2 = 0, so only odd-indexed terms survive:
        // σ'[k] = σ[k+1] if k is even (i.e., sigma coefficient at odd index k+1).
        let mut sigma_prime = vec![0u8; sigma.len().saturating_sub(1)];
        for (i, s) in sigma.iter().enumerate().skip(1).step_by(2) {
            if i - 1 < sigma_prime.len() {
                sigma_prime[i - 1] = *s;
            }
        }

        for &pos in &error_pos {
            // Evaluate at X_pos^{-1} = α^{pos+1}.
            let eval_point = gf.pow(2, pos + 1);
            let mut omega_val = 0u8;
            let mut alpha_pow = 1u8;
            for &o in &omega {
                omega_val ^= gf.mul(o, alpha_pow);
                alpha_pow = gf.mul(alpha_pow, eval_point);
            }
            let mut sigma_prime_val = 0u8;
            alpha_pow = 1u8;
            for &sp in &sigma_prime {
                sigma_prime_val ^= gf.mul(sp, alpha_pow);
                alpha_pow = gf.mul(alpha_pow, eval_point);
            }
            // Forney: e_pos = Ω(eval_point) / Λ'(eval_point).
            // sigma_prime_val == 0 means the formal derivative vanished at this
            // root — this can happen with repeated roots in malformed codewords.
            let inv_spv = match gf.inv(sigma_prime_val) {
                Some(v) => v,
                None => return Err("division by zero in Forney algorithm"),
            };
            let magnitude = gf.mul(omega_val, inv_spv);
            corrected[pos] ^= magnitude;
        }

        let data_len = corrected.len() - RS_PARITY;
        out.extend_from_slice(&corrected[..data_len]);
    }

    // Recover exact payload from the 2-byte length prefix written by rs_encode.
    if out.len() < 2 {
        return Err("decoded output too short — missing length prefix");
    }
    let payload_len = u16::from_le_bytes([out[0], out[1]]) as usize;
    if 2 + payload_len > out.len() {
        return Err("length prefix exceeds decoded output");
    }
    Ok(out[2..2 + payload_len].to_vec())
}

/// Berlekamp-Massey algorithm: find the shortest LFSR (error locator
/// polynomial σ(x)) for the given syndrome sequence.
fn berlekamp_massey(gf: &Gf, syndromes: &[u8]) -> Result<Vec<u8>, &'static str> {
    let n = syndromes.len();
    let mut c = vec![0u8; n + 1];
    let mut b = vec![0u8; n + 1];
    c[0] = 1;
    b[0] = 1;
    let mut l = 0usize;
    let mut x = 1usize;
    let mut b_scalar: u8 = 1;

    for i in 0..n {
        // Compute discrepancy d.
        let mut d = syndromes[i];
        for j in 1..=l {
            d ^= gf.mul(c[j], syndromes[i.wrapping_sub(j)]);
        }
        if d == 0 {
            x += 1;
            continue;
        }
        let t = c.clone();
        // b_scalar is initialised to 1 and only updated to d when d != 0
        // (see assignment below), so it is always nonzero here.  The
        // Option unwrap is the safety net if that invariant ever breaks.
        let coeff = gf.mul(
            d,
            gf.inv(b_scalar).ok_or("b_scalar is zero in BM algorithm")?,
        );
        for j in x..=n {
            c[j] ^= gf.mul(coeff, b[j - x]);
        }
        if 2 * l <= i {
            l = i + 1 - l;
            b = t;
            b_scalar = d;
            x = 1;
        } else {
            x += 1;
        }
    }

    if l > n / 2 {
        return Err("too many errors: LFSR length exceeds t");
    }

    Ok(c[..=l].to_vec())
}

// ────────────────────────────────────────────────────────────────────────────
// Platform audio abstraction
// ────────────────────────────────────────────────────────────────────────────

/// Platform-specific audio I/O.
///
/// Platform implementations inject 8000 Hz i16 PCM mono samples via
/// `push_audio_input` and consume encoded output via `pull_audio_output`.
pub trait AudioPlatform: Send + Sync {
    /// Push incoming audio samples from the microphone.
    fn push_audio_input(&self, samples: &[i16]);
    /// Pull outgoing audio samples to feed to the speaker.
    fn pull_audio_output(&self) -> Vec<i16>;
    /// Whether the audio channel is currently active (call in progress).
    fn is_active(&self) -> bool;
}

// ────────────────────────────────────────────────────────────────────────────
// TelephoneSubchannel — main entry point
// ────────────────────────────────────────────────────────────────────────────

/// Subchannel state machine.
///
/// Created when a phone call begins.  The caller feeds audio samples in and
/// out; the subchannel handles all modem encoding/decoding and detection.
pub struct TelephoneSubchannel {
    // Held for its Drop side-effects (e.g. closing the audio device);
    // never read directly — the `_` prefix is intentional.
    _platform: Box<dyn AudioPlatform>,
    /// Accumulated incoming samples waiting for pilot detection.
    recv_buf: std::sync::Mutex<Vec<i16>>,
    /// Outgoing PCM samples queued for transmission.
    send_buf: std::sync::Mutex<Vec<i16>>,
}

impl TelephoneSubchannel {
    /// Create a subchannel backed by `platform`.
    pub fn new(platform: Box<dyn AudioPlatform>) -> Self {
        TelephoneSubchannel {
            _platform: platform,
            recv_buf: std::sync::Mutex::new(Vec::new()),
            send_buf: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Queue `data` for FSK transmission on the next audio callback.
    pub fn send(&self, data: &[u8]) {
        let samples = encode(data);
        self.send_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(samples);
    }

    /// Pull the next batch of outgoing audio samples (called by platform
    /// audio output callback).
    pub fn pull_output(&self, n: usize) -> Vec<i16> {
        let mut buf = self.send_buf.lock().unwrap_or_else(|e| e.into_inner());
        let take = buf.len().min(n);
        buf.drain(..take).collect()
    }

    /// Feed incoming audio samples (called by platform audio input callback).
    /// Returns a decoded payload if a complete frame was received.
    pub fn push_input(&self, samples: &[i16]) -> Option<Vec<u8>> {
        let mut buf = self.recv_buf.lock().unwrap_or_else(|e| e.into_inner());
        buf.extend_from_slice(samples);
        // Attempt decode when enough samples have accumulated.
        let min_samples = PILOT_DURATION_SAMPLES + 100 * 10 * SAMPLES_PER_SYMBOL;
        if buf.len() < min_samples {
            return None;
        }
        match decode(&buf) {
            Ok(data) => {
                buf.clear();
                Some(data)
            }
            Err(_) => {
                // Keep buffering — pilot might not have ended yet.
                // Discard samples older than 30 seconds to prevent unbounded growth.
                let max_samples = SAMPLE_RATE as usize * 30;
                if buf.len() > max_samples {
                    let trim = buf.len() - max_samples;
                    buf.drain(..trim);
                }
                None
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_tone_length() {
        let samples = generate_tone(MARK_FREQ, SAMPLES_PER_SYMBOL);
        assert_eq!(samples.len(), SAMPLES_PER_SYMBOL);
    }

    #[test]
    fn goertzel_marks_and_spaces() {
        // Generate pure MARK tone and check Goertzel picks up more energy there.
        let mark_samples = generate_tone(MARK_FREQ, SAMPLES_PER_SYMBOL);
        let mark_energy = goertzel(&mark_samples, MARK_FREQ);
        let space_energy = goertzel(&mark_samples, SPACE_FREQ);
        assert!(
            mark_energy > space_energy * 2.0,
            "MARK tone should have much more energy at MARK frequency"
        );

        let space_samples = generate_tone(SPACE_FREQ, SAMPLES_PER_SYMBOL);
        let space_e = goertzel(&space_samples, SPACE_FREQ);
        let mark_e = goertzel(&space_samples, MARK_FREQ);
        assert!(
            space_e > mark_e * 2.0,
            "SPACE tone should have much more energy at SPACE frequency"
        );
    }

    #[test]
    fn encode_produces_audio() {
        let data = b"SOS";
        let audio = encode(data);
        // Pilot (8000 samples) + bytes: rs_encode(3 bytes) = up to 35 bytes
        // 35 × 10 symbols × 160 samples = 56000 + 8000 = 64000 samples
        assert!(audio.len() > PILOT_DURATION_SAMPLES);
    }

    #[test]
    fn rs_encode_decode_clean() {
        let data = b"Hello telephone subchannel";
        let codeword = rs_encode(data);
        let decoded = rs_decode(&codeword).expect("clean codeword should decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn rs_encode_decode_with_errors() {
        let data = b"Error correction test";
        let mut codeword = rs_encode(data);
        // Introduce 10 random errors (well within t=16 correction capacity).
        for i in (0..codeword.len()).step_by(25).take(10) {
            codeword[i] ^= 0xFF;
        }
        let decoded = rs_decode(&codeword).expect("should correct ≤16 errors");
        assert_eq!(decoded, data);
    }

    #[test]
    fn pilot_detection() {
        let data = b"mesh";
        let audio = encode(data);
        let pilot_end = find_pilot_end(&audio).expect("pilot should be detected");
        // Pilot is 8000 samples; data_start should be close to that.
        assert!(
            pilot_end >= PILOT_DURATION_SAMPLES.saturating_sub(SAMPLES_PER_SYMBOL),
            "pilot end should be near 8000 samples, got {pilot_end}"
        );
    }

    #[test]
    fn encode_decode_roundtrip_short() {
        let data = b"Hi";
        let audio = encode(data);
        let decoded = decode(&audio).expect("roundtrip should succeed");
        assert_eq!(decoded, data);
    }

    #[test]
    fn gf_mul_commutativity() {
        let gf = Gf::build();
        let a = 0x53u8;
        let b = 0xCAu8;
        assert_eq!(gf.mul(a, b), gf.mul(b, a));
    }

    #[test]
    fn gf_inv() {
        let gf = Gf::build();
        for a in 1u8..=255 {
            let inv = gf.inv(a).expect("inv of nonzero should be Some");
            assert_eq!(gf.mul(a, inv), 1, "a * inv(a) should be 1");
        }
    }
}
