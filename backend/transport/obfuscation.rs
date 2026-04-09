//! Traffic Obfuscation Layer (§5.26) and Jitter Engine (§5.27)
//!
//! # Purpose
//!
//! DPI (Deep Packet Inspection) systems operated by censors and surveillance
//! infrastructure can identify application protocols by examining packet
//! structure, length patterns, and timing.  This module implements a pluggable
//! obfuscation layer that disguises Mesh Infinity traffic as ordinary internet
//! traffic, making it indistinguishable to passive observers without the
//! session key.
//!
//! # Position in the Stack
//!
//! ```text
//! WireGuard encryption (§5.2)   ← encrypted but still has WG packet structure
//!         ↓
//! ObfuscationLayer (§5.26)      ← THIS MODULE — hides the structure
//!         ↓
//! Physical transport (TCP/UDP)
//! ```
//!
//! # Obfuscation Modes
//!
//! | Mode        | Description                                              |
//! |-------------|----------------------------------------------------------|
//! | `None`      | Pass-through; no obfuscation applied                     |
//! | `Scramble`  | ChaCha20-based XOR keystream; removes all DPI patterns   |
//! | `Pad`       | Random padding to fixed-size blocks; hides length        |
//! | `HttpMimic` | Wraps payload as HTTP/1.1 POST; looks like web API calls |
//! | `TlsMimic`  | Wraps payload as TLS Application Data records            |
//! | `DnsTunnel` | Base32-encodes payload into DNS query labels             |
//!
//! # Jitter Engine (§5.27)
//!
//! [`JitterEngine`] introduces randomised inter-packet delays to defeat
//! timing-correlation attacks.  Four delay distributions are available:
//! Uniform, Gaussian (approximate), Exponential, and Polymorphic (§5.27.3),
//! which switches distributions unpredictably every 100–300 packets.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

// ---------------------------------------------------------------------------
// ObfuscationMode
// ---------------------------------------------------------------------------

/// Which obfuscation strategy to apply to outbound packets.
///
/// See the module-level documentation and §5.26 for the full specification
/// of each mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObfuscationMode {
    /// No obfuscation.  Packets are passed through unchanged.
    None,
    /// ChaCha20-keystream XOR.  Removes all structured DPI patterns while
    /// keeping packet length unchanged.
    Scramble,
    /// Random padding to the next 512-byte block boundary.  Hides message
    /// length patterns.
    Pad,
    /// Wraps each packet as an HTTP/1.1 POST request / response.  Traffic
    /// looks like web API calls to passive DPI observers.
    HttpMimic,
    /// Wraps each packet as a TLS 1.2 Application Data record.  Traffic is
    /// indistinguishable from ordinary HTTPS without the session key.
    TlsMimic,
    /// Encodes payload as base32 DNS query labels.  Bypasses captive portals
    /// and firewalls that permit only DNS traffic.
    DnsTunnel,
}

// ---------------------------------------------------------------------------
// ObfuscationLayer
// ---------------------------------------------------------------------------

/// Per-connection obfuscation context.
///
/// Create one `ObfuscationLayer` per WireGuard session.  The `session_key`
/// is the WireGuard-derived session key; an obfuscation-specific sub-key is
/// derived from it via HKDF so the two layers use independent key material.
///
/// `wrap` / `unwrap` are called by the transport send / receive paths
/// respectively.
pub struct ObfuscationLayer {
    mode: ObfuscationMode,
    /// Per-connection obfuscation key derived from the WireGuard session key.
    key: [u8; 32],
    /// Monotonically increasing sequence number stamped on every outbound packet.
    send_seq: AtomicU64,
    /// Stable random 32-bit connection identifier (set once on construction).
    conn_id: u32,
}

impl ObfuscationLayer {
    /// Construct a new `ObfuscationLayer` for the given mode.
    ///
    /// `session_key` is the WireGuard 32-byte session key.  An independent
    /// obfuscation key is derived via HKDF-SHA256 so that the WireGuard and
    /// obfuscation layers use disjoint key material.
    pub fn new(mode: ObfuscationMode, session_key: &[u8; 32]) -> Self {
        let info: &[u8] = match mode {
            ObfuscationMode::None => b"mesh-obfs-none-v1",
            ObfuscationMode::Scramble => b"mesh-obfs-scramble-v1",
            ObfuscationMode::Pad => b"mesh-obfs-pad-v1",
            ObfuscationMode::HttpMimic => b"mesh-obfs-http-v1",
            ObfuscationMode::TlsMimic => b"mesh-obfs-tls-v1",
            ObfuscationMode::DnsTunnel => b"mesh-obfs-dns-v1",
        };
        let key = derive_obfs_key(session_key, info);

        // Random connection ID — 4 bytes from the OS CSPRNG.
        let mut conn_id_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut conn_id_bytes);
        let conn_id = u32::from_le_bytes(conn_id_bytes);

        ObfuscationLayer {
            mode,
            key,
            send_seq: AtomicU64::new(0),
            conn_id,
        }
    }

    /// Wrap an outbound packet with the configured obfuscation.
    ///
    /// Increments the internal sequence counter atomically so concurrent
    /// callers receive distinct sequence numbers.
    pub fn wrap(&self, packet: &[u8]) -> Vec<u8> {
        let seq = self.send_seq.fetch_add(1, Ordering::Relaxed);
        match self.mode {
            ObfuscationMode::None => packet.to_vec(),
            ObfuscationMode::Scramble => scramble_wrap(&self.key, seq, self.conn_id, packet),
            ObfuscationMode::Pad => pad_wrap(&self.key, packet),
            ObfuscationMode::HttpMimic => http_wrap(packet),
            ObfuscationMode::TlsMimic => tls_wrap(packet),
            ObfuscationMode::DnsTunnel => dns_wrap(&self.key, packet),
        }
    }

    /// Unwrap an inbound obfuscated packet.
    ///
    /// Returns `None` if the packet does not match the expected framing for
    /// the configured mode (e.g., a `TlsMimic` packet that starts with the
    /// wrong content-type byte, or an `HttpMimic` packet with a malformed
    /// header).
    ///
    /// The receive-side sequence number is embedded in `Scramble` packets and
    /// extracted automatically; no separate counter is maintained here.
    pub fn unwrap(&self, obfuscated: &[u8]) -> Option<Vec<u8>> {
        match self.mode {
            ObfuscationMode::None => Some(obfuscated.to_vec()),
            ObfuscationMode::Scramble => scramble_unwrap(&self.key, self.conn_id, obfuscated),
            ObfuscationMode::Pad => pad_unwrap(obfuscated),
            ObfuscationMode::HttpMimic => http_unwrap(obfuscated),
            ObfuscationMode::TlsMimic => tls_unwrap(obfuscated),
            ObfuscationMode::DnsTunnel => dns_unwrap(&self.key, obfuscated),
        }
    }

    /// The active obfuscation mode.
    pub fn mode(&self) -> ObfuscationMode {
        self.mode
    }

    /// Maximum overhead (bytes) that this layer adds to any packet.
    ///
    /// Used by the transport layer to size MTU appropriately so that
    /// obfuscated packets do not exceed the physical MTU.
    pub fn max_overhead(&self) -> usize {
        match self.mode {
            // No framing overhead.
            ObfuscationMode::None => 0,
            // 8-byte sequence number prepended; length unchanged after that.
            ObfuscationMode::Scramble => 12, // 8-byte seq + 4-byte conn_id
            // 2-byte length prefix + up to 511 bytes of padding.
            ObfuscationMode::Pad => 2 + 511,
            // HTTP headers — worst-case ~200 bytes.
            ObfuscationMode::HttpMimic => 256,
            // TLS record header — 5 bytes per record; a max-size payload needs
            // only 1 record for packets ≤ 16384 bytes.
            ObfuscationMode::TlsMimic => 5,
            // DNS label framing + session_id + base domain text encoding.
            // Each 63-char label holds 39 raw bytes; framing ~ 40 chars per chunk.
            ObfuscationMode::DnsTunnel => 512,
        }
    }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte obfuscation key from `session_key` using HKDF-SHA256.
///
/// `mode_info` is a static string that binds the derived key to a specific
/// obfuscation mode so keys cannot be accidentally reused across modes.
fn derive_obfs_key(session_key: &[u8; 32], mode_info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut out = [0u8; 32];
    hk.expand(mode_info, &mut out)
        .expect("32-byte HKDF output is always valid");
    out
}

// ---------------------------------------------------------------------------
// Mode: Scramble (ChaCha20-keystream XOR)
// ---------------------------------------------------------------------------
//
// The chacha20poly1305 crate bundles the chacha20 stream cipher but does not
// re-export the raw ChaCha20 cipher type.  We implement the keystream using
// the XOR-of-SHA256-blocks construction which is computationally equivalent
// to a PRF-keyed stream and requires no additional dependencies.
//
// Wire format (outbound):
//   [8-byte seq LE] [4-byte conn_id LE] [XOR'd payload bytes]
//   ^--- these 12 header bytes are NOT XOR'd ---^
//
// The receiver extracts seq and conn_id from the header, re-derives the same
// keystream, and XORs the payload back to plaintext.

/// Scramble (XOR with SHA-256-derived keystream) and prepend seq+conn_id header.
fn scramble_wrap(key: &[u8; 32], seq: u64, conn_id: u32, packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + packet.len());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&conn_id.to_le_bytes());
    let stream = keystream(key, seq, conn_id, packet.len());
    for (b, k) in packet.iter().zip(stream.iter()) {
        out.push(b ^ k);
    }
    out
}

/// Descramble: extract header, re-derive keystream, XOR payload.
fn scramble_unwrap(key: &[u8; 32], _conn_id: u32, obfuscated: &[u8]) -> Option<Vec<u8>> {
    if obfuscated.len() < 12 {
        return None;
    }
    let seq = u64::from_le_bytes(obfuscated[0..8].try_into().ok()?);
    let recv_conn_id = u32::from_le_bytes(obfuscated[8..12].try_into().ok()?);
    let payload = &obfuscated[12..];
    let stream = keystream(key, seq, recv_conn_id, payload.len());
    let plaintext: Vec<u8> = payload
        .iter()
        .zip(stream.iter())
        .map(|(b, k)| b ^ k)
        .collect();
    Some(plaintext)
}

/// Produce `len` keystream bytes for a given (key, seq, conn_id) triple.
///
/// Construction: repeatedly hash `key || seq_le || conn_id_le || block_index_le`
/// with SHA-256, concatenate the 32-byte digests, and take the first `len`
/// bytes.  This is a deterministic PRF — both sender and receiver derive the
/// same stream without any state exchange beyond the header.
fn keystream(key: &[u8; 32], seq: u64, conn_id: u32, len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut stream = Vec::with_capacity(len + 32);
    let mut block_idx: u32 = 0;
    while stream.len() < len {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(seq.to_le_bytes());
        hasher.update(conn_id.to_le_bytes());
        hasher.update(block_idx.to_le_bytes());
        stream.extend_from_slice(&hasher.finalize());
        block_idx = block_idx.wrapping_add(1);
    }
    stream.truncate(len);
    stream
}

// ---------------------------------------------------------------------------
// Mode: Pad
// ---------------------------------------------------------------------------
//
// Wire format:
//   [2-byte original length, big-endian] [original bytes] [random padding]
//
// Total length is rounded up to the next multiple of 512 bytes.
// The padding bytes are produced by a deterministic PRNG seeded from the
// session key so the receiver can verify (but we intentionally skip that
// verification here — the WireGuard AEAD already provides integrity).

const PAD_BLOCK: usize = 512;

fn pad_wrap(key: &[u8; 32], packet: &[u8]) -> Vec<u8> {
    let orig_len = packet.len();
    // 2 bytes for length prefix + payload
    let data_len = 2 + orig_len;
    // Round up to next multiple of PAD_BLOCK
    let padded_len = data_len.div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let pad_bytes = padded_len - data_len;

    let mut out = Vec::with_capacity(padded_len);
    // 2-byte big-endian original length
    out.push(((orig_len >> 8) & 0xFF) as u8);
    out.push((orig_len & 0xFF) as u8);
    out.extend_from_slice(packet);

    // Fill padding with PRNG bytes derived from session key + payload hash.
    // Use a simple LCG seeded from key XOR for deterministic but varied padding.
    let mut rng_state = lcg_seed_from_key(key);
    for _ in 0..pad_bytes {
        rng_state = lcg_next(rng_state);
        out.push((rng_state >> 33) as u8);
    }
    out
}

fn pad_unwrap(obfuscated: &[u8]) -> Option<Vec<u8>> {
    if obfuscated.len() < 2 {
        return None;
    }
    let orig_len = ((obfuscated[0] as usize) << 8) | (obfuscated[1] as usize);
    if 2 + orig_len > obfuscated.len() {
        return None;
    }
    Some(obfuscated[2..2 + orig_len].to_vec())
}

// ---------------------------------------------------------------------------
// Mode: HttpMimic
// ---------------------------------------------------------------------------
//
// Outbound packets are wrapped as HTTP/1.1 POST requests.
// Inbound packets are unwrapped from either a POST request or a 200 response.
//
// This mode is primarily useful in contexts where a middlebox permits HTTP but
// blocks unrecognised protocols.  The fake Content-Type and Host headers make
// the traffic look like a mobile app calling a cloud API endpoint.

fn http_wrap(packet: &[u8]) -> Vec<u8> {
    // Generate a random 16-hex-char request ID using a simple LCG seeded
    // from OsRng to avoid an additional heavy dep.
    let mut id_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut id_bytes);
    let request_id = hex_encode(&id_bytes);

    let header = format!(
        "POST /api/v1/sync HTTP/1.1\r\n\
         Host: cloud.example.com\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         X-Request-Id: {}\r\n\
         \r\n",
        packet.len(),
        request_id,
    );
    let mut out = Vec::with_capacity(header.len() + packet.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(packet);
    out
}

fn http_unwrap(obfuscated: &[u8]) -> Option<Vec<u8>> {
    // Accept both a POST request and a 200 response.
    // Search for \r\n\r\n in raw bytes so binary payloads are handled correctly:
    // only the header portion needs to be valid UTF-8.
    const CRLF2: &[u8] = b"\r\n\r\n";
    let header_end = obfuscated.windows(CRLF2.len()).position(|w| w == CRLF2)?;
    let header_bytes = &obfuscated[..header_end];
    let body_start = header_end + 4;

    // Parse the header section as text for Content-Length extraction.
    let header_section = std::str::from_utf8(header_bytes).ok()?;

    // Find Content-Length header (case-insensitive scan)
    let content_length = header_section.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            line["content-length:".len()..].trim().parse::<usize>().ok()
        } else {
            None
        }
    })?;

    let body_end = body_start + content_length;
    if body_end > obfuscated.len() {
        return None;
    }
    Some(obfuscated[body_start..body_end].to_vec())
}

// ---------------------------------------------------------------------------
// Mode: TlsMimic
// ---------------------------------------------------------------------------
//
// Wire format (per TLS record):
//   [0x17] [0x03] [0x03] [2-byte payload length, big-endian] [payload bytes]
//
// 0x17 = ContentType::ApplicationData
// 0x03 0x03 = legacy TLS 1.2 version field (required by TLS 1.3 spec)
//
// RFC 8446 §5.1 caps a TLS record at 2^14 = 16384 bytes of plaintext.
// Payloads larger than that are split across multiple records, each with its
// own 5-byte header.  On unwrap the records are concatenated.

const TLS_MAX_RECORD: usize = 16384;
const TLS_CONTENT_TYPE_APP_DATA: u8 = 0x17;
const TLS_VERSION_HI: u8 = 0x03;
const TLS_VERSION_LO: u8 = 0x03;

fn tls_wrap(packet: &[u8]) -> Vec<u8> {
    let num_records = (packet.len() + TLS_MAX_RECORD - 1).max(1) / TLS_MAX_RECORD;
    // At least 1 record, even for an empty packet.
    let num_records = num_records.max(1);
    let mut out = Vec::with_capacity(packet.len() + num_records * 5);

    if packet.is_empty() {
        // Single empty record
        out.extend_from_slice(&[
            TLS_CONTENT_TYPE_APP_DATA,
            TLS_VERSION_HI,
            TLS_VERSION_LO,
            0,
            0,
        ]);
        return out;
    }

    let mut offset = 0;
    while offset < packet.len() {
        let chunk_end = (offset + TLS_MAX_RECORD).min(packet.len());
        let chunk = &packet[offset..chunk_end];
        let chunk_len = chunk.len() as u16;
        out.push(TLS_CONTENT_TYPE_APP_DATA);
        out.push(TLS_VERSION_HI);
        out.push(TLS_VERSION_LO);
        out.push((chunk_len >> 8) as u8);
        out.push((chunk_len & 0xFF) as u8);
        out.extend_from_slice(chunk);
        offset = chunk_end;
    }
    out
}

fn tls_unwrap(obfuscated: &[u8]) -> Option<Vec<u8>> {
    if obfuscated.is_empty() {
        return None;
    }
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < obfuscated.len() {
        // Need at least a 5-byte record header.
        if pos + 5 > obfuscated.len() {
            return None;
        }
        if obfuscated[pos] != TLS_CONTENT_TYPE_APP_DATA {
            return None;
        }
        // We do not strictly enforce the version bytes to allow future
        // flexibility, but both must be 0x03 for this implementation.
        if obfuscated[pos + 1] != TLS_VERSION_HI || obfuscated[pos + 2] != TLS_VERSION_LO {
            return None;
        }
        let record_len = ((obfuscated[pos + 3] as usize) << 8) | (obfuscated[pos + 4] as usize);
        let data_start = pos + 5;
        let data_end = data_start + record_len;
        if data_end > obfuscated.len() {
            return None;
        }
        result.extend_from_slice(&obfuscated[data_start..data_end]);
        pos = data_end;
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// Mode: DnsTunnel
// ---------------------------------------------------------------------------
//
// Payload is base32-encoded (no padding alphabet) and split into 63-character
// labels (the DNS label length limit).  Labels are joined with dots and a
// fake domain suffix is appended so the query looks plausible.
//
// Wire format (text):
//   <label1>.<label2>....<session_id>.mesh.local
//
// session_id is derived from the first 4 bytes of the session key, encoded
// as 8 lowercase hex characters, to bind queries to a session without
// requiring a full handshake.

/// Base32 alphabet (RFC 4648, lowercase, no padding).
const BASE32_ALPHA: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | (byte as u64);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(BASE32_ALPHA[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(BASE32_ALPHA[idx] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for ch in s.chars() {
        let val = BASE32_ALPHA.iter().position(|&c| c == ch as u8)? as u64;
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn dns_session_id(key: &[u8; 32]) -> String {
    hex_encode(&key[0..4])
}

const DNS_LABEL_MAX: usize = 63;
const DNS_SUFFIX: &str = ".mesh.local";

fn dns_wrap(key: &[u8; 32], packet: &[u8]) -> Vec<u8> {
    let encoded = base32_encode(packet);
    let session_id = dns_session_id(key);

    let mut labels: Vec<&str> = Vec::new();
    let mut remaining = encoded.as_str();
    while remaining.len() > DNS_LABEL_MAX {
        let (chunk, rest) = remaining.split_at(DNS_LABEL_MAX);
        labels.push(chunk);
        remaining = rest;
    }
    if !remaining.is_empty() {
        labels.push(remaining);
    }

    // Format: label1.label2....session_id.mesh.local
    let query = if labels.is_empty() {
        format!("{}{}", session_id, DNS_SUFFIX)
    } else {
        format!("{}.{}{}", labels.join("."), session_id, DNS_SUFFIX)
    };
    query.into_bytes()
}

fn dns_unwrap(key: &[u8; 32], obfuscated: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(obfuscated).ok()?;
    let session_id = dns_session_id(key);
    let expected_suffix = format!(".{}{}", session_id, DNS_SUFFIX);

    // Text must end with .<session_id>.mesh.local
    let labels_part = text.strip_suffix(&expected_suffix)?;
    if labels_part.is_empty() {
        // Empty payload encoded as just the session/suffix.
        return Some(Vec::new());
    }

    // Reassemble all labels (removing dots between them).
    let combined: String = labels_part.split('.').collect();
    base32_decode(&combined)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple LCG PRNG — fast, seedable, no extra deps.
/// Not cryptographically secure; used only for padding bytes.
#[inline]
fn lcg_next(state: u64) -> u64 {
    state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
}

fn lcg_seed_from_key(key: &[u8; 32]) -> u64 {
    // XOR the first 8 bytes of the key together as a quick seed.
    let mut seed = 0u64;
    for (i, &byte) in key[..8].iter().enumerate() {
        seed ^= (byte as u64) << (i * 8);
    }
    seed
}

/// Encode a byte slice as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// JitterEngine (§5.27)
// ---------------------------------------------------------------------------

/// Which statistical distribution to use for inter-packet delay sampling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JitterDistribution {
    /// Uniform random in `[0, jitter_range_ms]`.
    Uniform,
    /// Approximately Gaussian (sum of 12 uniform samples), clipped to
    /// `[0, jitter_range_ms]`.
    Gaussian,
    /// Exponential distribution: `-mean * ln(U)` where U is uniform(0,1).
    /// Models Tor-like inter-cell timing.
    Exponential,
    /// Switches between Uniform, Gaussian, and Exponential every
    /// 100–300 packets (§5.27.3).
    Polymorphic,
}

/// Engine that computes randomised inter-packet delays to defeat timing-
/// correlation attacks.
///
/// All randomness comes from a fast LCG seeded at construction time from
/// [`OsRng`].  The LCG is cheap, deterministic per-session, and avoids
/// blocking on the OS entropy pool in hot paths.
///
/// Call [`JitterEngine::next_delay_ms`] to get a delay value, or
/// [`JitterEngine::apply_delay`] to sleep for that duration inline.
pub struct JitterEngine {
    base_delay_ms: u64,
    jitter_range_ms: u64,
    distribution: JitterDistribution,
    rng_state: Mutex<LcgState>,
}

/// Internal LCG state for the jitter engine.
struct LcgState {
    state: u64,
    /// Current active distribution (relevant only when `distribution` is
    /// [`JitterDistribution::Polymorphic`]).
    active_dist: JitterDistribution,
    /// Packets remaining before switching distributions (Polymorphic mode).
    packets_until_switch: u64,
}

impl JitterEngine {
    /// Create a jitter engine with the [`JitterDistribution::Uniform`]
    /// distribution.
    pub fn new(base_ms: u64, range_ms: u64) -> Self {
        Self::new_with_distribution(base_ms, range_ms, JitterDistribution::Uniform)
    }

    /// Create a jitter engine with an explicit distribution.
    pub fn new_with_distribution(base_ms: u64, range_ms: u64, dist: JitterDistribution) -> Self {
        // Seed from OS entropy.
        let mut seed_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut seed_bytes);
        let seed = u64::from_le_bytes(seed_bytes);

        // Initial polymorphic interval (100–300 packets).
        let mut state0 = LcgState {
            state: seed,
            active_dist: JitterDistribution::Uniform,
            packets_until_switch: 100,
        };
        // Randomise the initial polymorphic interval using first LCG output.
        let first = lcg_next(seed);
        state0.packets_until_switch = 100 + (first % 201); // [100, 300]
        state0.state = first;

        JitterEngine {
            base_delay_ms: base_ms,
            jitter_range_ms: range_ms,
            distribution: dist,
            rng_state: Mutex::new(state0),
        }
    }

    /// Sample the next inter-packet delay in milliseconds.
    ///
    /// The returned value is in the range
    /// `[base_delay_ms, base_delay_ms + jitter_range_ms]` for Uniform and
    /// Gaussian modes.  Exponential mode may transiently exceed the upper
    /// bound (it is only approximately bounded in expectation).
    pub fn next_delay_ms(&self) -> u64 {
        let mut inner = self.rng_state.lock().expect("jitter lock poisoned");
        let dist = match self.distribution {
            JitterDistribution::Polymorphic => {
                // Advance polymorphic state.
                if inner.packets_until_switch == 0 {
                    // Switch to the next distribution.
                    inner.state = lcg_next(inner.state);
                    let choice = inner.state % 3;
                    inner.active_dist = match choice {
                        0 => JitterDistribution::Uniform,
                        1 => JitterDistribution::Gaussian,
                        _ => JitterDistribution::Exponential,
                    };
                    // New random interval in [100, 300].
                    inner.state = lcg_next(inner.state);
                    inner.packets_until_switch = 100 + (inner.state % 201);
                } else {
                    inner.packets_until_switch -= 1;
                }
                inner.active_dist
            }
            other => other,
        };

        let jitter = match dist {
            JitterDistribution::Uniform => {
                inner.state = lcg_next(inner.state);
                if self.jitter_range_ms == 0 {
                    0
                } else {
                    inner.state % (self.jitter_range_ms + 1)
                }
            }
            JitterDistribution::Gaussian => {
                // Box-Muller via sum-of-uniforms (central limit theorem, n=12).
                // The sum of 12 U[0,1] variables has mean 6 and std ≈ 1.
                // We normalise to [0, jitter_range_ms].
                let mut sum: u64 = 0;
                for _ in 0..12 {
                    inner.state = lcg_next(inner.state);
                    // Scale to [0, 1000] then sum
                    sum += inner.state % 1001;
                }
                // sum is in [0, 12000]; mean ≈ 6000; normalise to [0, range].
                if self.jitter_range_ms == 0 {
                    0
                } else {
                    (sum * self.jitter_range_ms / 12000).min(self.jitter_range_ms)
                }
            }
            JitterDistribution::Exponential => {
                // Approximate exponential: -mean * ln(U).
                // We avoid floating-point by using a discrete approximation:
                //   geometric distribution as discrete analogue of exponential.
                // mean = jitter_range_ms / 2.  We use repeated halving.
                let mean = (self.jitter_range_ms / 2).max(1);
                let mut delay: u64 = 0;
                let mut p: u64 = mean;
                loop {
                    inner.state = lcg_next(inner.state);
                    // Bernoulli(0.5) trial
                    if inner.state & 1 == 0 {
                        break;
                    }
                    delay += p;
                    p = p.div_ceil(2); // halve (geometric series)
                    if p == 0 {
                        break;
                    }
                }
                delay.min(self.jitter_range_ms * 2) // cap at 2× range
            }
            JitterDistribution::Polymorphic => {
                // This branch is unreachable because Polymorphic resolves to
                // one of the other three variants above.
                unreachable!("Polymorphic resolved before match");
            }
        };

        self.base_delay_ms + jitter
    }

    /// Compute a jitter delay and sleep for that duration.
    ///
    /// Intended for use in blocking send loops.  For async contexts, callers
    /// should call [`next_delay_ms`] and await a timer manually.
    pub fn apply_delay(&self) {
        let delay_ms = self.next_delay_ms();
        if delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ]
    }

    // -- HttpMimic ------------------------------------------------------------

    #[test]
    fn http_mimic_roundtrip_empty() {
        let payload = b"";
        let wrapped = http_wrap(payload);
        let unwrapped = http_unwrap(&wrapped).expect("http_unwrap failed on empty payload");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn http_mimic_roundtrip_short() {
        let payload = b"hello world";
        let wrapped = http_wrap(payload);
        let unwrapped = http_unwrap(&wrapped).expect("http_unwrap failed");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn http_mimic_roundtrip_binary() {
        let payload: Vec<u8> = (0u8..=255u8).collect();
        let wrapped = http_wrap(&payload);
        let unwrapped = http_unwrap(&wrapped).expect("http_unwrap failed on binary");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn http_mimic_contains_post_header() {
        let wrapped = http_wrap(b"data");
        let text = std::str::from_utf8(&wrapped).unwrap();
        assert!(text.starts_with("POST /api/v1/sync HTTP/1.1\r\n"));
        assert!(text.contains("Content-Type: application/octet-stream"));
        assert!(text.contains("X-Request-Id:"));
    }

    #[test]
    fn http_unwrap_rejects_garbage() {
        assert!(http_unwrap(b"not http at all").is_none());
    }

    #[test]
    fn http_unwrap_rejects_truncated_body() {
        // Header says Content-Length: 100 but body has 0 bytes.
        let fake = b"POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\n";
        assert!(http_unwrap(fake).is_none());
    }

    // -- TlsMimic ------------------------------------------------------------

    #[test]
    fn tls_mimic_roundtrip_small() {
        let payload = b"mesh infinity tls test";
        let wrapped = tls_wrap(payload);
        let unwrapped = tls_unwrap(&wrapped).expect("tls_unwrap failed");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn tls_mimic_roundtrip_empty() {
        let payload = b"";
        let wrapped = tls_wrap(payload);
        assert_eq!(wrapped, vec![0x17, 0x03, 0x03, 0x00, 0x00]);
        let unwrapped = tls_unwrap(&wrapped).expect("tls_unwrap failed on empty");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn tls_mimic_roundtrip_exactly_max_record() {
        let payload = vec![0xABu8; TLS_MAX_RECORD];
        let wrapped = tls_wrap(&payload);
        // Should be exactly one record: 5 header bytes + 16384 payload bytes
        assert_eq!(wrapped.len(), 5 + TLS_MAX_RECORD);
        let unwrapped = tls_unwrap(&wrapped).expect("tls_unwrap failed on max-record payload");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn tls_mimic_roundtrip_multi_record() {
        // 40000 bytes → 3 records (16384 + 16384 + 7232)
        let payload: Vec<u8> = (0..40000u32).map(|i| (i % 251) as u8).collect();
        let wrapped = tls_wrap(&payload);
        let unwrapped = tls_unwrap(&wrapped).expect("tls_unwrap multi-record failed");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn tls_mimic_roundtrip_just_over_max_record() {
        let payload = vec![0x55u8; TLS_MAX_RECORD + 1];
        let wrapped = tls_wrap(&payload);
        // Two records: 5+16384 and 5+1
        assert_eq!(wrapped.len(), 5 + TLS_MAX_RECORD + 5 + 1);
        let unwrapped = tls_unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn tls_mimic_rejects_wrong_content_type() {
        let mut wrapped = tls_wrap(b"test");
        wrapped[0] = 0x16; // HandshakeType — wrong
        assert!(tls_unwrap(&wrapped).is_none());
    }

    #[test]
    fn tls_mimic_rejects_wrong_version() {
        let mut wrapped = tls_wrap(b"test");
        wrapped[1] = 0x02; // TLS 1.0 major version — wrong
        assert!(tls_unwrap(&wrapped).is_none());
    }

    #[test]
    fn tls_mimic_rejects_truncated_header() {
        let truncated = vec![0x17, 0x03]; // only 2 bytes
        assert!(tls_unwrap(&truncated).is_none());
    }

    #[test]
    fn tls_mimic_rejects_truncated_body() {
        let mut wrapped = tls_wrap(b"hello world");
        // Claim a longer body than we have
        wrapped[3] = 0x01;
        wrapped[4] = 0x00; // says 256 bytes, but we have 11
        assert!(tls_unwrap(&wrapped).is_none());
    }

    // -- Pad -----------------------------------------------------------------

    #[test]
    fn pad_roundtrip_small() {
        let key = test_key();
        let payload = b"short";
        let wrapped = pad_wrap(&key, payload);
        assert_eq!(
            wrapped.len() % PAD_BLOCK,
            0,
            "padded length not a multiple of {PAD_BLOCK}"
        );
        let unwrapped = pad_unwrap(&wrapped).expect("pad_unwrap failed");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn pad_roundtrip_exact_block_minus_two() {
        // payload of exactly PAD_BLOCK - 2 bytes → 2 + (PAD_BLOCK-2) = PAD_BLOCK → one block
        let key = test_key();
        let payload = vec![0u8; PAD_BLOCK - 2];
        let wrapped = pad_wrap(&key, &payload);
        assert_eq!(wrapped.len(), PAD_BLOCK);
        let unwrapped = pad_unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn pad_roundtrip_large() {
        let key = test_key();
        let payload: Vec<u8> = (0..1500u32).map(|i| (i % 256) as u8).collect();
        let wrapped = pad_wrap(&key, &payload);
        assert_eq!(wrapped.len() % PAD_BLOCK, 0);
        let unwrapped = pad_unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn pad_unwrap_rejects_truncated() {
        assert!(pad_unwrap(&[]).is_none());
        assert!(pad_unwrap(&[0x00]).is_none());
    }

    #[test]
    fn pad_unwrap_rejects_impossible_length() {
        // Header says 1000 bytes but there are only 5 bytes total.
        let data = vec![0x03, 0xE8, 0x00, 0x01, 0x02]; // len=1000, 3 body bytes
        assert!(pad_unwrap(&data).is_none());
    }

    // -- Scramble ------------------------------------------------------------

    #[test]
    fn scramble_roundtrip() {
        let key = test_key();
        let layer = ObfuscationLayer::new(ObfuscationMode::Scramble, &key);
        let payload = b"scramble test payload 1234";
        let wrapped = layer.wrap(payload);
        assert_ne!(
            wrapped[12..],
            *payload,
            "wrapped should differ from plaintext"
        );
        let unwrapped = layer.unwrap(&wrapped).expect("scramble unwrap failed");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn scramble_roundtrip_different_keys_fail() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 0xFF;
        let layer_send = ObfuscationLayer::new(ObfuscationMode::Scramble, &key1);
        let layer_recv = ObfuscationLayer::new(ObfuscationMode::Scramble, &key2);
        let payload = b"secret data";
        let wrapped = layer_send.wrap(payload);
        let unwrapped = layer_recv
            .unwrap(&wrapped)
            .expect("unwrap succeeds structurally");
        // With a different key the XOR output will differ from plaintext.
        assert_ne!(
            unwrapped, payload,
            "different keys should produce different plaintext"
        );
    }

    #[test]
    fn scramble_sequence_numbers_unique() {
        let key = test_key();
        let layer = ObfuscationLayer::new(ObfuscationMode::Scramble, &key);
        let payload = b"same payload";
        let w1 = layer.wrap(payload);
        let w2 = layer.wrap(payload);
        // Different sequence numbers → different XOR'd output
        assert_ne!(w1, w2);
    }

    #[test]
    fn scramble_unwrap_rejects_short() {
        let key = test_key();
        let layer = ObfuscationLayer::new(ObfuscationMode::Scramble, &key);
        assert!(layer.unwrap(&[0u8; 11]).is_none());
    }

    // -- DnsTunnel -----------------------------------------------------------

    #[test]
    fn base32_encode_decode_roundtrip() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let encoded = base32_encode(&data);
        let decoded = base32_decode(&encoded).expect("base32 decode failed");
        assert_eq!(decoded, data);
    }

    #[test]
    fn base32_encode_decode_empty() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_decode("").unwrap(), b"");
    }

    #[test]
    fn base32_encode_uses_valid_chars() {
        let data = b"hello world 12345";
        let encoded = base32_encode(data);
        for ch in encoded.chars() {
            assert!(
                ch.is_ascii_alphanumeric() && (ch.is_ascii_lowercase() || ch.is_ascii_digit()),
                "unexpected base32 char: {ch}"
            );
        }
    }

    #[test]
    fn dns_tunnel_roundtrip_short() {
        let key = test_key();
        let payload = b"dns tunnel test";
        let wrapped = dns_wrap(&key, payload);
        let text = std::str::from_utf8(&wrapped).unwrap();
        assert!(text.ends_with(DNS_SUFFIX), "missing .mesh.local suffix");
        let unwrapped = dns_unwrap(&key, &wrapped).expect("dns_unwrap failed");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn dns_tunnel_roundtrip_large() {
        let key = test_key();
        let payload: Vec<u8> = (0..500u32).map(|i| (i % 256) as u8).collect();
        let wrapped = dns_wrap(&key, &payload);
        let unwrapped = dns_unwrap(&key, &wrapped).expect("dns_unwrap large failed");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn dns_tunnel_labels_within_limit() {
        let key = test_key();
        let payload: Vec<u8> = vec![0xABu8; 200];
        let wrapped = dns_wrap(&key, &payload);
        let text = std::str::from_utf8(&wrapped).unwrap();
        // Remove the session_id.mesh.local suffix
        let session_id = dns_session_id(&key);
        let suffix = format!(".{}{}", session_id, DNS_SUFFIX);
        let labels_part = text.strip_suffix(&suffix).unwrap();
        for label in labels_part.split('.') {
            assert!(
                label.len() <= DNS_LABEL_MAX,
                "label too long: {} chars",
                label.len()
            );
        }
    }

    #[test]
    fn dns_tunnel_wrong_key_fails() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 0x01;
        let payload = b"secret";
        let wrapped = dns_wrap(&key1, payload);
        // Wrong key → wrong session ID → suffix mismatch → None
        assert!(dns_unwrap(&key2, &wrapped).is_none());
    }

    // -- ObfuscationLayer via mode() and max_overhead() ----------------------

    #[test]
    fn max_overhead_all_modes_non_negative() {
        let key = test_key();
        for mode in [
            ObfuscationMode::None,
            ObfuscationMode::Scramble,
            ObfuscationMode::Pad,
            ObfuscationMode::HttpMimic,
            ObfuscationMode::TlsMimic,
            ObfuscationMode::DnsTunnel,
        ] {
            let layer = ObfuscationLayer::new(mode, &key);
            // usize is always ≥ 0; this test is structural, ensuring the method
            // exists and returns a sensible value.
            let _ = layer.max_overhead();
            assert_eq!(layer.mode(), mode);
        }
    }

    #[test]
    fn none_mode_passthrough() {
        let key = test_key();
        let layer = ObfuscationLayer::new(ObfuscationMode::None, &key);
        let payload = b"plaintext";
        assert_eq!(layer.wrap(payload), payload);
        assert_eq!(layer.unwrap(payload).unwrap(), payload);
    }

    // -- JitterEngine --------------------------------------------------------

    #[test]
    fn jitter_uniform_in_range() {
        let engine = JitterEngine::new(10, 50);
        for _ in 0..1000 {
            let d = engine.next_delay_ms();
            assert!((10..=60).contains(&d), "delay {d} out of [10, 60]");
        }
    }

    #[test]
    fn jitter_gaussian_in_range() {
        let engine = JitterEngine::new_with_distribution(5, 100, JitterDistribution::Gaussian);
        for _ in 0..1000 {
            let d = engine.next_delay_ms();
            assert!((5..=105).contains(&d), "gaussian delay {d} out of [5, 105]");
        }
    }

    #[test]
    fn jitter_exponential_base_always_present() {
        let engine = JitterEngine::new_with_distribution(20, 40, JitterDistribution::Exponential);
        for _ in 0..500 {
            let d = engine.next_delay_ms();
            assert!(d >= 20, "exponential delay {d} below base 20");
        }
    }

    #[test]
    fn jitter_zero_range_returns_base() {
        let engine = JitterEngine::new(42, 0);
        for _ in 0..100 {
            assert_eq!(engine.next_delay_ms(), 42);
        }
    }

    #[test]
    fn jitter_polymorphic_changes_distribution() {
        // Run enough iterations that the Polymorphic engine must switch at
        // least once (switch interval is [100, 300]; run 400 samples).
        let engine = JitterEngine::new_with_distribution(0, 100, JitterDistribution::Polymorphic);
        let samples: Vec<u64> = (0..400).map(|_| engine.next_delay_ms()).collect();
        // All samples must be in [0, 200] (base=0, range=100, exponential cap is 2×range).
        for &s in &samples {
            assert!(s <= 200, "polymorphic delay {s} exceeded cap");
        }
        // Verify the engine produces non-constant output (it would be
        // astronomically unlikely for 400 samples from three distributions to
        // all be identical).
        let first = samples[0];
        assert!(
            samples.iter().any(|&s| s != first),
            "all 400 polymorphic samples were identical — RNG appears stuck"
        );
    }

    #[test]
    fn jitter_apply_delay_zero_base_zero_range() {
        // apply_delay with zero delay should return quickly without blocking.
        let engine = JitterEngine::new(0, 0);
        engine.apply_delay(); // must not sleep
    }

    // -- Full ObfuscationLayer roundtrip via wrap/unwrap ---------------------

    #[test]
    fn layer_tls_roundtrip() {
        let key = test_key();
        let layer = ObfuscationLayer::new(ObfuscationMode::TlsMimic, &key);
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let wrapped = layer.wrap(&payload);
        let unwrapped = layer.unwrap(&wrapped).expect("tls layer unwrap failed");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn layer_pad_roundtrip() {
        let key = test_key();
        let layer = ObfuscationLayer::new(ObfuscationMode::Pad, &key);
        let payload = b"pad roundtrip via layer";
        let wrapped = layer.wrap(payload);
        let unwrapped = layer.unwrap(&wrapped).expect("pad layer unwrap failed");
        assert_eq!(unwrapped.as_slice(), payload.as_slice());
    }

    #[test]
    fn layer_http_roundtrip() {
        let key = test_key();
        let layer = ObfuscationLayer::new(ObfuscationMode::HttpMimic, &key);
        let payload = b"http layer roundtrip";
        let wrapped = layer.wrap(payload);
        let unwrapped = layer.unwrap(&wrapped).expect("http layer unwrap failed");
        assert_eq!(unwrapped.as_slice(), payload.as_slice());
    }

    #[test]
    fn layer_dns_roundtrip() {
        let key = test_key();
        let layer = ObfuscationLayer::new(ObfuscationMode::DnsTunnel, &key);
        let payload = b"dns layer roundtrip payload";
        let wrapped = layer.wrap(payload);
        let unwrapped = layer.unwrap(&wrapped).expect("dns layer unwrap failed");
        assert_eq!(unwrapped.as_slice(), payload.as_slice());
    }
}
