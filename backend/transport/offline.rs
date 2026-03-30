//! Offline Transport / Sneakernet (§5.28)
//!
//! Offline transport treats physical media, external storage services, and
//! any non-networked carrier as first-class transport mechanisms.  The mesh
//! packet format is identical to any other transport; the "medium" is physical
//! rather than radio or wire.
//!
//! ## Design principle
//!
//! The network layer doesn't care how bits get from A to B.  A USB drive
//! physically carried between two nodes, a shared S3 bucket, an air-gapped
//! machine reading a QR code — all are valid transports with defined wire formats.
//!
//! ## Wire format (.mib files)
//!
//! ```text
//! [ PhysicalTransferHeader (fixed-width, big-endian) ]
//! [ mesh packet 0 (length-prefixed) ]
//! [ mesh packet 1 ]
//! ...
//! ```
//!
//! Files are named `meshinfinity_bundle_{bundle_id_hex}.mib`.
//!
//! ## Security model
//!
//! Physical media is untrusted.  Mesh packet encryption is end-to-end and
//! independent of the transport.  A malicious courier can delay, replay
//! (blocked by `bundle_id` deduplication), or drop bundles — but cannot
//! decrypt or forge them.
//!
//! ## Air-gap bridge (§5.28.4)
//!
//! An air-gapped node has no network connectivity.  Offline transport is its
//! only path.  The `created_at` / `expires_at` fields accommodate the latency
//! of physical transport (default `expires_at` is 30 days; configurable).

use std::collections::HashSet;
use std::io;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// `.mib` file magic bytes: ASCII "MIOT" (Mesh Infinity Offline Transport).
/// Chosen to be unlikely to appear at the start of arbitrary files, allowing
/// quick rejection of non-bundle data when scanning removable media.
pub const BUNDLE_MAGIC: [u8; 4] = [0x4D, 0x49, 0x4F, 0x54];

/// Current format version.  Bumped on incompatible header changes.
/// The parser rejects any version != 1 to prevent silent misparse
/// of future formats (§5.28.1 forward-compatibility rule).
pub const BUNDLE_VERSION: u8 = 1;

/// Default bundle TTL: 30 days.  Physical transport latency (mail, USB
/// drive, courier) can be days or weeks — this generous TTL ensures
/// bundles remain valid for typical sneakernet round-trips while still
/// expiring eventually to bound storage growth on the receiver.
pub const DEFAULT_TTL_SECS: u64 = 30 * 24 * 3600;

/// Serialised `PhysicalTransferHeader` size in bytes (fixed-width encoding).
///
/// Layout:
///   4   magic
///   1   version
///   1   routing_mode
///  32   source_id
///   1   dest_id_present (bool byte)
///  32   dest_id (zeroed if absent)
///  16   bundle_id
///   8   created_at
///   8   expires_at
///   4   packet_count
///   8   total_size
///  32   checksum
/// ─────────────────
/// 147 bytes total
pub const HEADER_SIZE: usize = 147;

// ─────────────────────────────────────────────────────────────────────────────
// RoutingMode
// ─────────────────────────────────────────────────────────────────────────────

/// Routing behaviour when a bundle is imported.
///
/// This field is critical for air-gapped networks (§5.28.4) where the
/// receiving node must decide what to do with the bundle without any
/// online coordination.  `PointToPoint` means "I am the final destination",
/// `NeedsRouting` means "inject into the mesh for further forwarding",
/// and `Broadcast` means "process on all receiving nodes".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RoutingMode {
    /// `dest_id` is the final recipient; receiver delivers directly or holds
    /// for pickup.
    PointToPoint = 0,
    /// `dest_id` is the next intended hop or `None` for best-effort; receiver
    /// injects into mesh routing.
    NeedsRouting = 1,
    /// No specific destination; all receiving nodes process as applicable.
    Broadcast = 2,
}

impl RoutingMode {
    fn from_u8(v: u8) -> Result<Self, OfflineError> {
        match v {
            0 => Ok(RoutingMode::PointToPoint),
            1 => Ok(RoutingMode::NeedsRouting),
            2 => Ok(RoutingMode::Broadcast),
            _ => Err(OfflineError::MalformedHeader("unknown routing mode")),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PhysicalTransferHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Header prepended to all offline transport bundles.
///
/// Determines routing behaviour on arrival and provides integrity + replay
/// protection.
#[derive(Debug, Clone)]
pub struct PhysicalTransferHeader {
    /// Must be `BUNDLE_MAGIC`.
    pub magic: [u8; 4],
    /// Format version; currently 1.
    pub version: u8,
    /// How the receiver should route this bundle.
    pub routing_mode: RoutingMode,
    /// Sender's mesh peer ID (or `[0u8; 32]` for anonymous).
    pub source_id: [u8; 32],
    /// Destination peer ID if `PointToPoint`; `None` otherwise.
    pub dest_id: Option<[u8; 32]>,
    /// Random 128-bit bundle ID for deduplication.
    pub bundle_id: [u8; 16],
    /// Unix timestamp (seconds) when the bundle was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) after which the bundle should be discarded.
    pub expires_at: u64,
    /// Number of mesh packets in this bundle.
    pub packet_count: u32,
    /// Total bytes of all packets (excluding this header).
    pub total_size: u64,
    /// SHA-256 of all packet bytes; integrity check on arrival.
    pub checksum: [u8; 32],
}

impl PhysicalTransferHeader {
    /// Serialise to `HEADER_SIZE` bytes (big-endian).
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        let mut pos = 0;

        buf[pos..pos + 4].copy_from_slice(&self.magic);
        pos += 4;
        buf[pos] = self.version;
        pos += 1;
        buf[pos] = self.routing_mode as u8;
        pos += 1;
        buf[pos..pos + 32].copy_from_slice(&self.source_id);
        pos += 32;
        match &self.dest_id {
            Some(id) => {
                buf[pos] = 1;
                pos += 1;
                buf[pos..pos + 32].copy_from_slice(id);
                pos += 32;
            }
            None => {
                buf[pos] = 0;
                pos += 1;
                pos += 32; // leave zeroed
            }
        }
        buf[pos..pos + 16].copy_from_slice(&self.bundle_id);
        pos += 16;
        buf[pos..pos + 8].copy_from_slice(&self.created_at.to_be_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.expires_at.to_be_bytes());
        pos += 8;
        buf[pos..pos + 4].copy_from_slice(&self.packet_count.to_be_bytes());
        pos += 4;
        buf[pos..pos + 8].copy_from_slice(&self.total_size.to_be_bytes());
        pos += 8;
        buf[pos..pos + 32].copy_from_slice(&self.checksum);

        buf
    }

    /// Deserialise from `HEADER_SIZE` bytes.
    pub fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Result<Self, OfflineError> {
        let mut pos = 0;

        let magic: [u8; 4] = buf[pos..pos + 4].try_into().unwrap();
        if magic != BUNDLE_MAGIC {
            return Err(OfflineError::InvalidMagic(magic));
        }
        pos += 4;

        let version = buf[pos];
        if version != BUNDLE_VERSION {
            return Err(OfflineError::UnsupportedVersion(version));
        }
        pos += 1;

        let routing_mode = RoutingMode::from_u8(buf[pos])?;
        pos += 1;

        let source_id: [u8; 32] = buf[pos..pos + 32].try_into().unwrap();
        pos += 32;

        let dest_id_present = buf[pos] != 0;
        pos += 1;
        let dest_id_raw: [u8; 32] = buf[pos..pos + 32].try_into().unwrap();
        let dest_id = if dest_id_present { Some(dest_id_raw) } else { None };
        pos += 32;

        let bundle_id: [u8; 16] = buf[pos..pos + 16].try_into().unwrap();
        pos += 16;

        let created_at = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let expires_at = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let packet_count = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let total_size = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let checksum: [u8; 32] = buf[pos..pos + 32].try_into().unwrap();

        Ok(PhysicalTransferHeader {
            magic,
            version,
            routing_mode,
            source_id,
            dest_id,
            bundle_id,
            created_at,
            expires_at,
            packet_count,
            total_size,
            checksum,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bundle builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build a `.mib` bundle from a list of mesh packets.
///
/// Each packet is length-prefixed (4-byte big-endian u32) in the stream.
/// The `checksum` field is computed over all packet bytes before
/// length-prefixing (i.e. the raw packet contents concatenated).
pub fn build_bundle(
    packets: &[Vec<u8>],
    routing_mode: RoutingMode,
    source_id: [u8; 32],
    dest_id: Option<[u8; 32]>,
    bundle_id: [u8; 16],
) -> Result<Vec<u8>, OfflineError> {
    let now_secs = unix_now();
    let expires_at = now_secs + DEFAULT_TTL_SECS;
    let packet_count = packets.len() as u32;

    // Compute checksum and total_size over raw packet bytes.
    let mut hasher = Sha256::new();
    let mut total_size: u64 = 0;
    for pkt in packets {
        hasher.update(pkt.as_slice());
        total_size += pkt.len() as u64;
    }
    let checksum: [u8; 32] = hasher.finalize().into();

    let header = PhysicalTransferHeader {
        magic: BUNDLE_MAGIC,
        version: BUNDLE_VERSION,
        routing_mode,
        source_id,
        dest_id,
        bundle_id,
        created_at: now_secs,
        expires_at,
        packet_count,
        total_size,
        checksum,
    };

    // Serialise: header + length-prefixed packets.
    let mut out = Vec::with_capacity(HEADER_SIZE + total_size as usize + packets.len() * 4);
    out.extend_from_slice(&header.to_bytes());
    for pkt in packets {
        let len = pkt.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(pkt.as_slice());
    }

    Ok(out)
}

/// Filename for a bundle given its ID.
pub fn bundle_filename(bundle_id: &[u8; 16]) -> String {
    format!("meshinfinity_bundle_{}.mib", hex::encode(bundle_id))
}

/// External storage path for a bundle.
/// Layout: `{prefix}/{dest_peer_id_hex}/{bundle_id_hex}.mib`
pub fn storage_path(prefix: &str, dest_id: &[u8; 32], bundle_id: &[u8; 16]) -> String {
    format!("{}/{}/{}.mib", prefix, hex::encode(dest_id), hex::encode(bundle_id))
}

// ─────────────────────────────────────────────────────────────────────────────
// Bundle parser / importer
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed, validated bundle ready for routing.
#[derive(Debug)]
pub struct ParsedBundle {
    pub header: PhysicalTransferHeader,
    /// Decoded mesh packets.
    pub packets: Vec<Vec<u8>>,
}

/// Parse and validate a `.mib` bundle from raw bytes.
///
/// Validation sequence per §5.28.1:
/// 1. Verify magic and version.
/// 2. Check `expires_at` — if past, return `Expired`.
/// 3. Verify `checksum` — on mismatch, return `ChecksumMismatch`.
/// 4. Caller should dedup on `bundle_id` before acting on packets.
pub fn parse_bundle(data: &[u8]) -> Result<ParsedBundle, OfflineError> {
    if data.len() < HEADER_SIZE {
        return Err(OfflineError::TruncatedHeader);
    }

    let header_bytes: [u8; HEADER_SIZE] = data[..HEADER_SIZE].try_into().unwrap();
    let header = PhysicalTransferHeader::from_bytes(&header_bytes)?;

    // Check expiry.
    let now = unix_now();
    if now > header.expires_at {
        return Err(OfflineError::Expired {
            expired_at: header.expires_at,
            now,
        });
    }

    // Parse packet stream.
    let mut packets: Vec<Vec<u8>> = Vec::with_capacity(header.packet_count as usize);
    let mut pos = HEADER_SIZE;
    while pos < data.len() {
        if pos + 4 > data.len() {
            return Err(OfflineError::TruncatedPacket);
        }
        let pkt_len =
            u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + pkt_len > data.len() {
            return Err(OfflineError::TruncatedPacket);
        }
        packets.push(data[pos..pos + pkt_len].to_vec());
        pos += pkt_len;
    }

    if packets.len() != header.packet_count as usize {
        return Err(OfflineError::PacketCountMismatch {
            expected: header.packet_count,
            got: packets.len() as u32,
        });
    }

    // Verify checksum.
    let mut hasher = Sha256::new();
    for pkt in &packets {
        hasher.update(pkt.as_slice());
    }
    let computed: [u8; 32] = hasher.finalize().into();
    if computed != header.checksum {
        return Err(OfflineError::ChecksumMismatch);
    }

    Ok(ParsedBundle { header, packets })
}

// ─────────────────────────────────────────────────────────────────────────────
// External storage relay config (§5.28.3)
// ─────────────────────────────────────────────────────────────────────────────

/// Storage backend for external relay.
#[derive(Debug, Clone)]
pub enum StorageBackend {
    S3Compatible {
        endpoint: String,
        bucket: String,
        /// Credential reference (key into the node's secret store).
        credentials: String,
    },
    WebDAV {
        url: String,
        credentials: String,
    },
    LocalPath {
        path: String,
    },
}

/// Direction of relay traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDirection {
    InboundOnly,
    OutboundOnly,
    Bidirectional,
}

/// External storage relay configuration.
#[derive(Debug, Clone)]
pub struct ExternalStorageRelay {
    /// Local name for this relay config.
    pub relay_id: String,
    pub backend: StorageBackend,
    /// How often to check for incoming bundles.
    pub poll_interval: std::time::Duration,
    /// Path prefix for outbound bundles (node writes here).
    pub outbox_prefix: String,
    /// Path prefix for inbound bundles (node reads from here).
    pub inbox_prefix: String,
    pub direction: RelayDirection,
}

impl ExternalStorageRelay {
    /// Construct the inbound path for a bundle addressed to `own_id`.
    pub fn inbound_path(&self, own_id: &[u8; 32], bundle_id: &[u8; 16]) -> String {
        storage_path(&self.inbox_prefix, own_id, bundle_id)
    }

    /// Construct the outbound path for a bundle addressed to `dest_id`.
    pub fn outbound_path(&self, dest_id: &[u8; 32], bundle_id: &[u8; 16]) -> String {
        storage_path(&self.outbox_prefix, dest_id, bundle_id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bundle deduplication store
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory deduplication store for bundle IDs.
///
/// A persistent implementation would back this with SQLite.
/// This in-memory version is used for testing and short-lived sessions.
pub struct BundleDeduplicator {
    seen: Mutex<HashSet<[u8; 16]>>,
}

impl BundleDeduplicator {
    pub fn new() -> Self {
        BundleDeduplicator {
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Returns `true` if this bundle ID has already been processed.
    pub fn is_duplicate(&self, bundle_id: &[u8; 16]) -> bool {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).contains(bundle_id)
    }

    /// Mark a bundle ID as processed.
    pub fn mark_seen(&self, bundle_id: [u8; 16]) {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).insert(bundle_id);
    }
}

impl Default for BundleDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QR / Base45 helpers (§5.28.2)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum bundle size suitable for a single QR code (Base45-encoded).
pub const QR_MAX_BYTES: usize = 2048;

/// Base45 alphabet (RFC 9285).  This specific character set was designed
/// for QR code alphanumeric mode, which encodes pairs of these characters
/// in 11 bits — roughly 45% more efficient than binary-mode QR for the
/// same error correction level.  This makes it possible to fit a small
/// mesh bundle (≤2 KB) into a single scannable QR code.
const BASE45_ALPHABET: &[u8; 45] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/// Encode `data` as a Base45 string suitable for QR codes (RFC 9285).
///
/// Two input bytes are encoded as three Base45 characters (expansion ~1.33×).
/// A trailing odd byte is encoded as two characters.  This is the same
/// encoding used by EU Digital COVID Certificates, chosen here for its
/// optimal QR code density.
pub fn base45_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut i = 0;
    while i < data.len() {
        if i + 1 < data.len() {
            let n = (data[i] as u32) * 256 + data[i + 1] as u32;
            let c = n % 45;
            let d = (n / 45) % 45;
            let e = n / (45 * 45);
            out.push(BASE45_ALPHABET[c as usize]);
            out.push(BASE45_ALPHABET[d as usize]);
            out.push(BASE45_ALPHABET[e as usize]);
            i += 2;
        } else {
            let n = data[i] as u32;
            let c = n % 45;
            let d = n / 45;
            out.push(BASE45_ALPHABET[c as usize]);
            out.push(BASE45_ALPHABET[d as usize]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// Decode a Base45 string back to bytes.
pub fn base45_decode(s: &str) -> Result<Vec<u8>, OfflineError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 / 3);
    let mut i = 0;
    while i < bytes.len() {
        let c = char_to_base45(bytes[i])?;
        if i + 2 < bytes.len() {
            let d = char_to_base45(bytes[i + 1])?;
            let e = char_to_base45(bytes[i + 2])?;
            let n = c as u32 + d as u32 * 45 + e as u32 * 45 * 45;
            if n > 0xFFFF {
                return Err(OfflineError::Base45Invalid);
            }
            out.push((n >> 8) as u8);
            out.push((n & 0xFF) as u8);
            i += 3;
        } else if i + 1 < bytes.len() {
            let d = char_to_base45(bytes[i + 1])?;
            let n = c as u32 + d as u32 * 45;
            if n > 0xFF {
                return Err(OfflineError::Base45Invalid);
            }
            out.push(n as u8);
            i += 2;
        } else {
            return Err(OfflineError::Base45Invalid);
        }
    }
    Ok(out)
}

fn char_to_base45(b: u8) -> Result<u8, OfflineError> {
    BASE45_ALPHABET
        .iter()
        .position(|&c| c == b)
        .map(|p| p as u8)
        .ok_or(OfflineError::Base45Invalid)
}

// ─────────────────────────────────────────────────────────────────────────────
// Transport Workflow
// ─────────────────────────────────────────────────────────────────────────────

// ── Physical media export (§5.28.2) ──────────────────────────────────────────

/// Export a set of packets as a `.mib` bundle file to `dir`.
///
/// Builds the bundle with `build_bundle()`, writes it to
/// `dir/meshinfinity_bundle_{bundle_id_hex}.mib`, and returns the full path.
pub fn export_to_dir(
    dir: &std::path::Path,
    packets: &[Vec<u8>],
    routing_mode: RoutingMode,
    source_id: [u8; 32],
    dest_id: Option<[u8; 32]>,
    bundle_id: [u8; 16],
) -> Result<std::path::PathBuf, OfflineError> {
    let data = build_bundle(packets, routing_mode, source_id, dest_id, bundle_id)?;
    let path = dir.join(bundle_filename(&bundle_id));
    std::fs::write(&path, &data)?;
    Ok(path)
}

// ── Physical media import (§5.28.2) ──────────────────────────────────────────

/// Scan `dir` for `.mib` files and return their paths (no auto-processing).
///
/// The caller decides which bundles to import; this only enumerates candidates.
pub fn scan_dir_for_bundles(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "mib"))
        .collect()
}

/// Read, validate, deduplicate, and return a `.mib` bundle from `path`.
///
/// Returns `Err(OfflineError::Duplicate)` if the bundle was already processed.
pub fn import_from_file(
    path: &std::path::Path,
    dedup: &BundleDeduplicator,
) -> Result<ParsedBundle, OfflineError> {
    let data = std::fs::read(path)?;
    let bundle = parse_bundle(&data)?;
    if dedup.is_duplicate(&bundle.header.bundle_id) {
        return Err(OfflineError::Duplicate);
    }
    dedup.mark_seen(bundle.header.bundle_id);
    Ok(bundle)
}

// ── QR segmentation and reassembly (§5.28.2) ─────────────────────────────────

/// Encode a bundle as one or more Base45 QR strings (§5.28.2).
///
/// Each segment is formatted as `"{seq}/{total}:{base45_data}"` (1-indexed).
/// For a bundle that fits in a single QR, `total=1` and one element is returned.
/// The `N/T:` prefix allows unambiguous reassembly regardless of Base45 content
/// (Base45 includes `/` in its alphabet, so content-based detection is unreliable).
pub fn segment_for_qr(data: &[u8]) -> Vec<String> {
    // Base45 expands ~1.33×, so each raw chunk must be ≤ QR_MAX_BYTES * 3/4.
    let raw_chunk_max = (QR_MAX_BYTES * 3) / 4;
    let chunks: Vec<&[u8]> = data.chunks(raw_chunk_max).collect();
    let total = chunks.len();
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| format!("{}/{}:{}", i + 1, total, base45_encode(chunk)))
        .collect()
}

/// Reassemble segments produced by `segment_for_qr` into the original bytes.
///
/// Each segment must be in `"{seq}/{total}:{base45_data}"` format.
/// Segments may be provided in any order.
pub fn reassemble_from_qr(segments: &[&str]) -> Result<Vec<u8>, OfflineError> {
    if segments.is_empty() {
        return Err(OfflineError::Base45Invalid);
    }
    let mut indexed: Vec<(usize, &str)> = Vec::with_capacity(segments.len());
    for seg in segments {
        let slash = seg.find('/').ok_or(OfflineError::Base45Invalid)?;
        let colon = seg[slash..].find(':').ok_or(OfflineError::Base45Invalid)? + slash;
        let seq: usize = seg[..slash]
            .parse()
            .map_err(|_| OfflineError::Base45Invalid)?;
        indexed.push((seq, &seg[colon + 1..]));
    }
    indexed.sort_by_key(|(seq, _)| *seq);
    let mut out = Vec::new();
    for (_, b45) in &indexed {
        out.extend_from_slice(&base45_decode(b45)?);
    }
    Ok(out)
}

// ── External storage relay — LocalPath backend (§5.28.3) ─────────────────────

/// Ingest all available bundles from the `LocalPath` inbox for `own_id`.
///
/// Reads `.mib` files from `{base}/{relay.inbox_prefix}/{own_id_hex}/`,
/// validates, and deduplicates.  Expired, corrupt, or duplicate bundles are
/// silently skipped per §5.28.1 security model.
///
/// S3-compatible and WebDAV backends require caller-side download; this
/// function handles only the `LocalPath` case.
pub fn relay_ingest_local(
    relay: &ExternalStorageRelay,
    own_id: &[u8; 32],
    dedup: &BundleDeduplicator,
) -> Vec<ParsedBundle> {
    let base = match &relay.backend {
        StorageBackend::LocalPath { path } => path.clone(),
        _ => return Vec::new(),
    };
    let inbox_dir = std::path::PathBuf::from(base)
        .join(&relay.inbox_prefix)
        .join(hex::encode(own_id));
    scan_dir_for_bundles(&inbox_dir)
        .into_iter()
        .filter_map(|p| import_from_file(&p, dedup).ok())
        .collect()
}

/// Write an outbound bundle to the `LocalPath` outbox directory for `dest_id`.
///
/// Creates the destination directory if needed.  For S3-compatible and WebDAV
/// backends, build the bundle with `build_bundle()` and upload the bytes.
pub fn relay_export_local(
    relay: &ExternalStorageRelay,
    packets: &[Vec<u8>],
    routing_mode: RoutingMode,
    source_id: [u8; 32],
    dest_id: [u8; 32],
    bundle_id: [u8; 16],
) -> Result<(), OfflineError> {
    let base = match &relay.backend {
        StorageBackend::LocalPath { path } => path.clone(),
        _ => {
            return Err(OfflineError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "relay_export_local only supports LocalPath backend",
            )))
        }
    };
    let outbox_dir = std::path::PathBuf::from(base)
        .join(&relay.outbox_prefix)
        .join(hex::encode(dest_id));
    std::fs::create_dir_all(&outbox_dir)?;
    export_to_dir(
        &outbox_dir,
        packets,
        routing_mode,
        source_id,
        Some(dest_id),
        bundle_id,
    )?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OfflineError {
    #[error("invalid magic bytes: {0:?}")]
    InvalidMagic([u8; 4]),
    #[error("unsupported bundle version: {0}")]
    UnsupportedVersion(u8),
    #[error("malformed header: {0}")]
    MalformedHeader(&'static str),
    #[error("header truncated")]
    TruncatedHeader,
    #[error("packet data truncated")]
    TruncatedPacket,
    #[error("packet count mismatch: expected {expected}, got {got}")]
    PacketCountMismatch { expected: u32, got: u32 },
    #[error("checksum mismatch — bundle may be corrupted or tampered")]
    ChecksumMismatch,
    #[error("bundle expired at {expired_at}; current time {now}")]
    Expired { expired_at: u64, now: u64 },
    #[error("bundle_id already seen — duplicate delivery prevented")]
    Duplicate,
    #[error("base45 encoding error")]
    Base45Invalid,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bundle_id() -> [u8; 16] {
        [0x42u8; 16]
    }

    fn make_source_id() -> [u8; 32] {
        [0xABu8; 32]
    }

    fn sample_packets() -> Vec<Vec<u8>> {
        vec![
            b"hello world".to_vec(),
            b"second packet with more data".to_vec(),
        ]
    }

    // ── Header serialisation ─────────────────────────────────────────────────

    #[test]
    fn header_roundtrip_with_dest() {
        let bundle_id = make_bundle_id();
        let source_id = make_source_id();
        let dest_id = [0xCDu8; 32];

        let h = PhysicalTransferHeader {
            magic: BUNDLE_MAGIC,
            version: BUNDLE_VERSION,
            routing_mode: RoutingMode::PointToPoint,
            source_id,
            dest_id: Some(dest_id),
            bundle_id,
            created_at: 1_000_000,
            expires_at: 1_000_000 + DEFAULT_TTL_SECS,
            packet_count: 2,
            total_size: 500,
            checksum: [0x99u8; 32],
        };

        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let h2 = PhysicalTransferHeader::from_bytes(&bytes).unwrap();

        assert_eq!(h2.magic, BUNDLE_MAGIC);
        assert_eq!(h2.routing_mode, RoutingMode::PointToPoint);
        assert_eq!(h2.source_id, source_id);
        assert_eq!(h2.dest_id, Some(dest_id));
        assert_eq!(h2.bundle_id, bundle_id);
        assert_eq!(h2.created_at, 1_000_000);
        assert_eq!(h2.packet_count, 2);
        assert_eq!(h2.checksum, [0x99u8; 32]);
    }

    #[test]
    fn header_roundtrip_no_dest() {
        let h = PhysicalTransferHeader {
            magic: BUNDLE_MAGIC,
            version: BUNDLE_VERSION,
            routing_mode: RoutingMode::Broadcast,
            source_id: [0u8; 32],
            dest_id: None,
            bundle_id: [1u8; 16],
            created_at: 0,
            expires_at: DEFAULT_TTL_SECS,
            packet_count: 0,
            total_size: 0,
            checksum: [0u8; 32],
        };
        let bytes = h.to_bytes();
        let h2 = PhysicalTransferHeader::from_bytes(&bytes).unwrap();
        assert!(h2.dest_id.is_none());
        assert_eq!(h2.routing_mode, RoutingMode::Broadcast);
    }

    #[test]
    fn header_rejects_wrong_magic() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = b'X';
        let result = PhysicalTransferHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(OfflineError::InvalidMagic(_))));
    }

    #[test]
    fn header_rejects_wrong_version() {
        let h = PhysicalTransferHeader {
            magic: BUNDLE_MAGIC,
            version: BUNDLE_VERSION,
            routing_mode: RoutingMode::NeedsRouting,
            source_id: [0u8; 32],
            dest_id: None,
            bundle_id: [0u8; 16],
            created_at: 0,
            expires_at: 9_999_999_999,
            packet_count: 0,
            total_size: 0,
            checksum: [0u8; 32],
        };
        let mut bytes = h.to_bytes();
        bytes[4] = 99; // corrupt version
        let result = PhysicalTransferHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(OfflineError::UnsupportedVersion(99))));
    }

    // ── Bundle build + parse ─────────────────────────────────────────────────

    #[test]
    fn bundle_roundtrip() {
        let packets = sample_packets();
        let bundle = build_bundle(
            &packets,
            RoutingMode::PointToPoint,
            make_source_id(),
            Some([0xFFu8; 32]),
            make_bundle_id(),
        )
        .unwrap();

        let parsed = parse_bundle(&bundle).unwrap();
        assert_eq!(parsed.packets.len(), 2);
        assert_eq!(parsed.packets[0], b"hello world");
        assert_eq!(parsed.packets[1], b"second packet with more data");
        assert_eq!(parsed.header.routing_mode, RoutingMode::PointToPoint);
    }

    #[test]
    fn bundle_checksum_tamper_detected() {
        let packets = sample_packets();
        let mut bundle = build_bundle(
            &packets,
            RoutingMode::Broadcast,
            [0u8; 32],
            None,
            [0u8; 16],
        )
        .unwrap();

        // Flip a bit in the packet data (after header).
        let flip_pos = HEADER_SIZE + 10;
        bundle[flip_pos] ^= 0xFF;

        let result = parse_bundle(&bundle);
        assert!(matches!(result, Err(OfflineError::ChecksumMismatch)));
    }

    #[test]
    fn bundle_rejects_expired() {
        let packets = sample_packets();
        let mut bundle = build_bundle(
            &packets,
            RoutingMode::NeedsRouting,
            [0u8; 32],
            None,
            [1u8; 16],
        )
        .unwrap();

        // Set expires_at to 1 (in the past) in the header.
        // expires_at is at offset 4+1+1+32+1+32+16+8 = 95 from header start.
        let expires_offset = 4 + 1 + 1 + 32 + 1 + 32 + 16 + 8;
        bundle[expires_offset..expires_offset + 8].copy_from_slice(&1u64.to_be_bytes());
        // Also need to recompute checksum — but the checksum covers packet
        // bytes, not the header, so it remains valid.  The expiry check runs
        // before checksum.

        let result = parse_bundle(&bundle);
        assert!(matches!(result, Err(OfflineError::Expired { .. })));
    }

    // ── Deduplication ────────────────────────────────────────────────────────

    #[test]
    fn dedup_rejects_second_delivery() {
        let dedup = BundleDeduplicator::new();
        let id = [0xABu8; 16];
        assert!(!dedup.is_duplicate(&id));
        dedup.mark_seen(id);
        assert!(dedup.is_duplicate(&id));
    }

    // ── Filename helpers ─────────────────────────────────────────────────────

    #[test]
    fn bundle_filename_format() {
        let id = [0u8; 16];
        let name = bundle_filename(&id);
        assert!(name.starts_with("meshinfinity_bundle_"));
        assert!(name.ends_with(".mib"));
    }

    #[test]
    fn storage_path_format() {
        let dest_id = [0xAAu8; 32];
        let bundle_id = [0xBBu8; 16];
        let path = storage_path("inbox", &dest_id, &bundle_id);
        assert!(path.contains("inbox/"));
        assert!(path.ends_with(".mib"));
    }

    // ── Base45 ───────────────────────────────────────────────────────────────

    #[test]
    fn base45_roundtrip_even() {
        let data = b"hello";
        let encoded = base45_encode(data);
        let decoded = base45_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base45_roundtrip_odd() {
        let data = b"hi";
        let encoded = base45_encode(data);
        let decoded = base45_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base45_roundtrip_empty() {
        let data: &[u8] = b"";
        let encoded = base45_encode(data);
        assert!(encoded.is_empty());
        let decoded = base45_decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base45_invalid_char_rejected() {
        let result = base45_decode("!invalid");
        assert!(matches!(result, Err(OfflineError::Base45Invalid)));
    }

    // ── Transport workflow: export/import ─────────────────────────────────────

    #[test]
    fn export_to_dir_creates_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle_id = [0x01u8; 16];
        let path = export_to_dir(
            dir.path(),
            &[b"hello".to_vec()],
            RoutingMode::PointToPoint,
            [0x11u8; 32],
            Some([0x22u8; 32]),
            bundle_id,
        )
        .unwrap();
        assert!(path.exists());
        assert!(path.extension().map_or(false, |e| e == "mib"));
        // File must be parseable.
        let data = std::fs::read(&path).unwrap();
        parse_bundle(&data).expect("exported bundle must be valid");
    }

    #[test]
    fn scan_dir_finds_mib_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle_id = [0x02u8; 16];
        export_to_dir(
            dir.path(),
            &[b"data".to_vec()],
            RoutingMode::Broadcast,
            [0x33u8; 32],
            None,
            bundle_id,
        )
        .unwrap();
        // Also create a non-mib file — should be ignored.
        std::fs::write(dir.path().join("other.txt"), b"ignore me").unwrap();

        let found = scan_dir_for_bundles(dir.path());
        assert_eq!(found.len(), 1);
        assert!(found[0].extension().map_or(false, |e| e == "mib"));
    }

    #[test]
    fn import_from_file_succeeds_and_deduplicates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle_id = [0x03u8; 16];
        let path = export_to_dir(
            dir.path(),
            &[b"payload".to_vec()],
            RoutingMode::PointToPoint,
            [0x44u8; 32],
            Some([0x55u8; 32]),
            bundle_id,
        )
        .unwrap();

        let dedup = BundleDeduplicator::new();

        // First import succeeds.
        let bundle = import_from_file(&path, &dedup).expect("first import must succeed");
        assert_eq!(bundle.packets.len(), 1);
        assert_eq!(bundle.packets[0], b"payload");

        // Second import is rejected as duplicate.
        let result = import_from_file(&path, &dedup);
        assert!(matches!(result, Err(OfflineError::Duplicate)));
    }

    // ── QR segmentation / reassembly ─────────────────────────────────────────

    #[test]
    fn qr_single_segment_roundtrip() {
        let data = b"small bundle fits in one QR";
        let segs = segment_for_qr(data);
        assert_eq!(segs.len(), 1);
        // Single segment is prefixed "1/1:..." (always use N/T: format).
        assert!(segs[0].starts_with("1/1:"), "got: {}", segs[0]);
        let recovered = reassemble_from_qr(&[segs[0].as_str()]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn qr_multi_segment_roundtrip() {
        // Build data that exceeds QR_MAX_BYTES after Base45 encoding.
        // Base45 expands ~1.33×, so ~1600 raw bytes → ~2133 encoded > 2048.
        let data = vec![0xA5u8; 1600];
        let segs = segment_for_qr(&data);
        assert!(segs.len() > 1, "must produce multiple segments for large data");
        // All segments have seq/total prefix.
        for seg in &segs {
            assert!(seg.contains('/') && seg.contains(':'));
        }
        // Reassemble out of order (reverse).
        let seg_refs: Vec<&str> = segs.iter().rev().map(|s| s.as_str()).collect();
        let recovered = reassemble_from_qr(&seg_refs).unwrap();
        assert_eq!(recovered, data);
    }

    // ── Relay workflow: LocalPath ─────────────────────────────────────────────

    #[test]
    fn relay_export_and_ingest_localpath() {
        let base_dir = tempfile::tempdir().expect("tempdir");
        let relay = ExternalStorageRelay {
            relay_id: "test".to_string(),
            backend: StorageBackend::LocalPath {
                path: base_dir.path().to_str().unwrap().to_string(),
            },
            poll_interval: std::time::Duration::from_secs(300),
            outbox_prefix: "outbox".to_string(),
            inbox_prefix: "inbox".to_string(),
            direction: RelayDirection::Bidirectional,
        };

        let source_id = [0x10u8; 32];
        let dest_id = [0x20u8; 32];
        let bundle_id = [0x30u8; 16];

        // Export from source to dest outbox.
        relay_export_local(
            &relay,
            &[b"relay-packet".to_vec()],
            RoutingMode::PointToPoint,
            source_id,
            dest_id,
            bundle_id,
        )
        .expect("relay export must succeed");

        // The exported file lives in {base}/outbox/{dest_id_hex}/.
        let outbox_dir = base_dir
            .path()
            .join("outbox")
            .join(hex::encode(dest_id));
        let found = scan_dir_for_bundles(&outbox_dir);
        assert_eq!(found.len(), 1);

        // Simulate dest node ingesting from its inbox.
        // Copy the outbox file to the inbox location for the test.
        let inbox_dir = base_dir
            .path()
            .join("inbox")
            .join(hex::encode(dest_id));
        std::fs::create_dir_all(&inbox_dir).unwrap();
        let src_path = &found[0];
        let dst_path = inbox_dir.join(src_path.file_name().unwrap());
        std::fs::copy(src_path, &dst_path).unwrap();

        let dedup = BundleDeduplicator::new();
        let ingested = relay_ingest_local(&relay, &dest_id, &dedup);
        assert_eq!(ingested.len(), 1);
        assert_eq!(ingested[0].packets[0], b"relay-packet");
    }

    // ── Constants ────────────────────────────────────────────────────────────

    #[test]
    fn header_size_constant_matches_serialised() {
        let h = PhysicalTransferHeader {
            magic: BUNDLE_MAGIC,
            version: BUNDLE_VERSION,
            routing_mode: RoutingMode::Broadcast,
            source_id: [0u8; 32],
            dest_id: None,
            bundle_id: [0u8; 16],
            created_at: 0,
            expires_at: 0,
            packet_count: 0,
            total_size: 0,
            checksum: [0u8; 32],
        };
        assert_eq!(h.to_bytes().len(), HEADER_SIZE);
    }
}
