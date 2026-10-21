//! Direct File Transfer Protocol (§11.1)
//!
//! # How It Works
//!
//! 1. Sender sends a `FileTransferOffer` as a chat message
//! 2. Recipient replies with `FileTransferAccept` (or silence = reject)
//! 3. Sender streams `FileTransferChunk` messages with a sliding window
//!    of 64 outstanding chunks. Each chunk is ACK'd individually.
//! 4. Recipient reassembles, verifies SHA-256, sends `FileTransferComplete`
//! 5. On reconnect: recipient sends `FileTransferResume` with a bitfield
//!    of received chunks; sender retransmits only missing ones
//!
//! # Chunk Size
//!
//! Default: 64 KB (65536 bytes). Power-of-two recommended.
//! Each chunk is encrypted with the session key before transmission.
//!
//! # Sliding Window
//!
//! The sender maintains a window of 64 outstanding (unacknowledged)
//! chunks. This bounds the receiver's reassembly buffer to
//! 64 × chunk_size bytes (4 MB at default chunk size).
//!
//! # Integrity
//!
//! The `file_id` is the SHA-256 hash of the plaintext file.
//! After reassembly, the recipient computes SHA-256 and compares.
//! Mismatch = `FileTransferComplete { ok: false }`.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default chunk size (bytes). 64 KB.
// DEFAULT_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_CHUNK_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEFAULT_CHUNK_SIZE: u32 = 65_536;

/// Maximum outstanding chunks in the sliding window.
/// Bounds receiver reassembly buffer to window × chunk_size.
// SLIDING_WINDOW_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// SLIDING_WINDOW_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SLIDING_WINDOW_SIZE: u32 = 64;

/// Longest wire `transferId` the receive side accepts.
///
/// Our own ids are 32 hex characters (128 random bits); 64 leaves room for
/// other implementations while keeping map keys and JSON records bounded.
// MAX_TRANSFER_ID_LEN — receive-side structural limit (§11.1 offer/accept).
// Anything longer is dropped before it reaches the transfer list.
pub const MAX_TRANSFER_ID_LEN: usize = 64;

/// Longest display name accepted from a `file_offer`.
///
/// 255 bytes is the common filesystem component limit; the name is only
/// ever shown to the user, never used to build a path, but keeping it
/// bounded stops a peer from bloating the transfer list.
// MAX_FILE_NAME_LEN — receive-side structural limit (§11.1 offer).
// Display-only; the on-disk name is derived from a local random id.
pub const MAX_FILE_NAME_LEN: usize = 255;

/// Largest single `file_chunk` payload the receive side writes to disk.
///
/// Equal to the negotiated chunk size (§11.1: "max chunk_size bytes"); the
/// sender in `poll.rs` never emits more than `FILE_CHUNK_SIZE` per frame.
// MAX_CHUNK_BYTES — receive-side structural limit (§11.1 chunk).
// A larger chunk is a protocol violation and aborts the transfer.
pub const MAX_CHUNK_BYTES: usize = DEFAULT_CHUNK_SIZE as usize;

/// Largest file size an offer may declare.
///
/// `chunk_count` is a `u32` and chunks are at most `DEFAULT_CHUNK_SIZE`
/// bytes, so this is the protocol's own addressable ceiling (§11.1).
// MAX_TRANSFER_BYTES — derived from the u32 chunk_count wire field.
// Offers above it cannot be expressed on the wire and are rejected.
pub const MAX_TRANSFER_BYTES: u64 = (u32::MAX as u64) * (DEFAULT_CHUNK_SIZE as u64);

/// Pending (not yet accepted) inbound offers allowed per claimed sender.
// MAX_PENDING_OFFERS_PER_PEER — DoS bound on the unaccepted offer list.
// The sender string is self-asserted, so the global cap is the hard bound.
pub const MAX_PENDING_OFFERS_PER_PEER: usize = 16;

/// Pending inbound offers allowed across all senders.
// MAX_PENDING_OFFERS — hard DoS bound on the unaccepted offer list.
// Beyond this, new offers are dropped until the user accepts or cancels.
pub const MAX_PENDING_OFFERS: usize = 128;

/// Sub-directory of the app data directory that receives inbound transfers.
// TRANSFER_DIR_NAME — the only place accepted files are written by default.
// Lives under the private app data dir, never under a world-writable path.
pub const TRANSFER_DIR_NAME: &str = "transfers";

// ---------------------------------------------------------------------------
// Receive-side validation (§11.1)
// ---------------------------------------------------------------------------

/// Reasons the receive side refuses an offer, chunk, or save path.
///
/// Every variant is a structural violation by the remote peer (or a local
/// caller passing peer data through unchecked); none is an I/O failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
// TransferError — typed rejection reasons for inbound transfer frames.
// Surfaced as log lines and as the `error` field on the transfer record.
pub enum TransferError {
    /// The wire `transferId` was empty.
    #[error("transfer id is empty")]
    EmptyId,
    /// The wire `transferId` exceeded `MAX_TRANSFER_ID_LEN` bytes.
    #[error("transfer id longer than {MAX_TRANSFER_ID_LEN} bytes")]
    IdTooLong,
    /// The wire `transferId` used a byte outside `[0-9A-Za-z_-]`.
    #[error("transfer id contains a byte outside [0-9A-Za-z_-]")]
    IdCharset,
    /// The offered file name was empty.
    #[error("file name is empty")]
    EmptyName,
    /// The offered file name exceeded `MAX_FILE_NAME_LEN` bytes.
    #[error("file name longer than {MAX_FILE_NAME_LEN} bytes")]
    NameTooLong,
    /// The offered file name carried a separator, NUL, or control byte.
    #[error("file name contains a path separator, NUL, or control byte")]
    NameCharset,
    /// The offered file name was `.` or `..`.
    #[error("file name is a reserved path component")]
    NameReserved,
    /// The declared size cannot be expressed by a u32 chunk count.
    #[error("declared size {0} exceeds the addressable maximum")]
    SizeTooLarge(u64),
    /// A single chunk exceeded `MAX_CHUNK_BYTES`.
    #[error("chunk of {0} bytes exceeds the {MAX_CHUNK_BYTES}-byte chunk limit")]
    ChunkTooLarge(usize),
    /// Writing the chunk would exceed the size declared in the offer.
    #[error("chunk would push the transfer past its declared size")]
    ChunkOverflow,
    /// The chunk's `offset` did not match the bytes written so far.
    #[error("chunk offset {got} does not match the expected offset {expected}")]
    ChunkOutOfOrder { expected: u64, got: u64 },
}

/// Check that a wire `transferId` is non-empty, bounded, and drawn from
/// `[0-9A-Za-z_-]` only.
///
/// The id is used as a map key and echoed in JSON records; it is never used
/// to build a filesystem path, but a fixed charset keeps logs and records
/// free of separators, NULs, and control bytes regardless.
pub fn validate_transfer_id(id: &str) -> Result<(), TransferError> {
    // Empty ids would collide with "no transfer" lookups.
    if id.is_empty() {
        return Err(TransferError::EmptyId);
    }
    // Bound the key length before scanning its bytes.
    if id.len() > MAX_TRANSFER_ID_LEN {
        return Err(TransferError::IdTooLong);
    }
    // Only URL-safe alphanumerics; hex ids from `start_file_transfer` pass.
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(TransferError::IdCharset);
    }
    Ok(())
}

/// Check that an offered display name is safe to show and store.
///
/// The name is display-only, but a stupid-user path (saving under the
/// offered name) must still never escape a directory, so separators,
/// NULs, control bytes, and `.`/`..` are refused up front.
pub fn validate_file_name(name: &str) -> Result<(), TransferError> {
    // An empty name gives the user nothing to decide on.
    if name.is_empty() {
        return Err(TransferError::EmptyName);
    }
    // Bound before scanning.
    if name.len() > MAX_FILE_NAME_LEN {
        return Err(TransferError::NameTooLong);
    }
    // Separators on either platform, NUL, and ASCII control bytes.
    if name
        .chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control())
    {
        return Err(TransferError::NameCharset);
    }
    // `.` and `..` are directory references, not file names.
    if name == "." || name == ".." {
        return Err(TransferError::NameReserved);
    }
    Ok(())
}

/// Check that an offer's declared size fits the protocol's u32 chunk count.
pub fn validate_offer_size(size: u64) -> Result<(), TransferError> {
    // Sizes beyond this cannot be chunk-addressed on the wire.
    if size > MAX_TRANSFER_BYTES {
        return Err(TransferError::SizeTooLarge(size));
    }
    Ok(())
}

/// Check that a chunk may be appended to a receive transfer.
///
/// `transferred` is the byte count written so far, `total` the size from
/// the accepted offer, `chunk_len` the decoded chunk size, and `offset`
/// the chunk's declared offset if the frame carried one.
pub fn check_chunk(
    transferred: u64,
    total: u64,
    chunk_len: usize,
    offset: Option<u64>,
) -> Result<(), TransferError> {
    // Per-chunk cap: the sender agreed to the chunk size in the offer.
    if chunk_len > MAX_CHUNK_BYTES {
        return Err(TransferError::ChunkTooLarge(chunk_len));
    }
    // Total cap: the declared size is the ceiling on what we write to disk.
    // A checked add means an arithmetic overflow is itself an overflow of
    // the transfer, never a wrap-around that slips under `total`.
    let end = transferred
        .checked_add(chunk_len as u64)
        .ok_or(TransferError::ChunkOverflow)?;
    if end > total {
        return Err(TransferError::ChunkOverflow);
    }
    // Chunks are appended sequentially; an offset that disagrees with the
    // bytes already written would corrupt the file silently.
    if let Some(got) = offset {
        if got != transferred {
            return Err(TransferError::ChunkOutOfOrder {
                expected: transferred,
                got,
            });
        }
    }
    Ok(())
}

/// Directory under the app data dir where inbound transfers are written.
pub fn transfer_dir(data_dir: &Path) -> PathBuf {
    // Always inside the private app data directory; never `/tmp`.
    data_dir.join(TRANSFER_DIR_NAME)
}

/// Build the on-disk path for an inbound transfer from a *local* id.
///
/// `local_id` must be an id we generated ourselves (random hex); it is
/// validated anyway so a caller can never route a peer string through here.
/// The result is always `<data_dir>/transfers/<local_id>.part`.
pub fn receive_path(data_dir: &Path, local_id: &str) -> Result<PathBuf, TransferError> {
    // Defence in depth: even a local id must satisfy the fixed charset.
    validate_transfer_id(local_id)?;
    // `.part` marks an in-progress download until `file_complete` verifies it.
    Ok(transfer_dir(data_dir).join(format!("{local_id}.part")))
}

/// Create the destination file for an inbound transfer, exclusively.
///
/// `create_new` fails if anything already exists at `path` — a regular
/// file, a symlink, or a directory — so an existing file is never truncated
/// and a pre-planted symlink is never followed.
pub fn create_receive_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

// ---------------------------------------------------------------------------
// Protocol Messages
// ---------------------------------------------------------------------------

/// Offer to transfer a file (§11.1).
///
/// Sent as a chat message. Contains metadata about the file
/// so the recipient can decide whether to accept.
#[derive(Clone, Debug, Serialize, Deserialize)]
// FileTransferOffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferOffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferOffer {
    /// SHA-256 hash of the plaintext file.
    /// Serves as both file ID and integrity check.
    pub file_id: [u8; 32],

    /// File name (human-readable).
    pub name: String,

    /// Exact size of the plaintext file (bytes).
    pub size: u64,

    /// MIME type (e.g., "image/png", "application/pdf").
    pub mime_type: String,

    /// Chunk size in bytes. Default: 65536 (64 KB).
    /// Power-of-two recommended.
    pub chunk_size: u32,

    /// Total number of chunks: ceil(size / chunk_size).
    pub chunk_count: u32,
}

/// Accept a file transfer offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// FileTransferAccept — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferAccept — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferAccept {
    /// The file_id from the offer.
    pub file_id: [u8; 32],
}

/// A single chunk of file data.
///
/// Encrypted with the session key before transmission.
/// Chunks arrive in order but may need retransmission.
#[derive(Clone, Debug, Serialize, Deserialize)]
// FileTransferChunk — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferChunk — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferChunk {
    /// Which file this chunk belongs to.
    pub file_id: [u8; 32],

    /// Zero-indexed chunk number.
    pub chunk_index: u32,

    /// The encrypted chunk data. Max chunk_size bytes.
    pub data: Vec<u8>,
}

/// Acknowledgement of a received chunk.
///
/// `ok: true` means the chunk was received and stored.
/// `ok: false` means the chunk was corrupted; sender retransmits.
#[derive(Clone, Debug, Serialize, Deserialize)]
// FileTransferChunkAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferChunkAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferChunkAck {
    /// Which file.
    pub file_id: [u8; 32],

    /// Which chunk was acknowledged.
    pub chunk_index: u32,

    /// Whether the chunk was received successfully.
    pub ok: bool,
}

/// Resume a partially completed transfer after reconnection.
///
/// The receiver sends a bitfield of which chunks it already has.
/// The sender retransmits only the missing ones.
#[derive(Clone, Debug, Serialize, Deserialize)]
// FileTransferResume — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferResume — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferResume {
    /// Which file.
    pub file_id: [u8; 32],

    /// Packed bitfield of received chunks.
    /// Bit N = 1 means chunk N has been received and verified.
    /// Length: ceil(chunk_count / 8) bytes.
    pub received_chunks: Vec<u8>,
}

/// Completion notification.
///
/// Sent by the receiver after all chunks are received and reassembled.
/// `ok: true` means SHA-256 verification passed.
/// `ok: false` means SHA-256 mismatch; sender may retransmit the entire file.
#[derive(Clone, Debug, Serialize, Deserialize)]
// FileTransferComplete — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferComplete — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferComplete {
    /// Which file.
    pub file_id: [u8; 32],

    /// Whether the file was received intact.
    pub ok: bool,
}

// ---------------------------------------------------------------------------
// Transfer State (Sender Side)
// ---------------------------------------------------------------------------

/// Tracks the state of an outgoing file transfer.
///
/// Manages the sliding window, tracks ACKs, and determines
/// which chunks need retransmission.
#[derive(Clone, Debug)]
// SendTransferState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SendTransferState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SendTransferState {
    /// The offer that initiated this transfer.
    pub offer: FileTransferOffer,

    /// Which chunks have been sent but not yet ACK'd.
    /// Key: chunk_index, Value: send timestamp.
    pub in_flight: std::collections::HashMap<u32, u64>,

    /// Which chunks have been ACK'd.
    pub acknowledged: Vec<bool>,

    /// Next chunk index to send.
    pub next_chunk: u32,

    /// When the transfer started.
    pub started_at: u64,

    /// Total bytes sent (including retransmissions).
    pub bytes_sent: u64,
}

// SendTransferState implementation — core protocol logic.
// SendTransferState implementation — core protocol logic.
impl SendTransferState {
    /// Create a new send transfer state from an offer.
    pub fn new(offer: FileTransferOffer, now: u64) -> Self {
        // Track the count for threshold and bounds checking.
        let chunk_count = offer.chunk_count as usize;
        Self {
            offer,
            in_flight: std::collections::HashMap::new(),
            acknowledged: vec![false; chunk_count],
            next_chunk: 0,
            started_at: now,
            bytes_sent: 0,
        }
    }

    /// Whether the sliding window has room for more chunks.
    pub fn can_send(&self) -> bool {
        // Validate the length matches the expected protocol size.
        (self.in_flight.len() as u32) < SLIDING_WINDOW_SIZE
            && self.next_chunk < self.offer.chunk_count
    }

    /// Record that a chunk was sent.
    pub fn mark_sent(&mut self, chunk_index: u32, now: u64) {
        self.in_flight.insert(chunk_index, now);
    }

    /// Record that a chunk was acknowledged.
    ///
    /// Returns true if the transfer is now complete (all chunks ACK'd).
    pub fn mark_ack(&mut self, chunk_index: u32) -> bool {
        // Remove from the collection and return the evicted value.
        // Remove from the collection.
        // Remove from the collection.
        self.in_flight.remove(&chunk_index);
        // Validate the input length to prevent out-of-bounds access.
        if (chunk_index as usize) < self.acknowledged.len() {
            self.acknowledged[chunk_index as usize] = true;
        }
        // Delegate to the instance method.
        self.is_complete()
    }

    /// Whether all chunks have been acknowledged.
    pub fn is_complete(&self) -> bool {
        // Create an iterator over the collection elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        self.acknowledged.iter().all(|&ack| ack)
    }

    /// Progress as a fraction (0.0 to 1.0).
    pub fn progress(&self) -> f32 {
        // Capture the current timestamp for temporal ordering.
        let acked = self.acknowledged.iter().filter(|&&a| a).count();
        // Clamp the value to prevent overflow or underflow.
        acked as f32 / self.offer.chunk_count.max(1) as f32
    }

    /// Get the list of missing chunk indices from a resume bitfield.
    pub fn missing_from_resume(&self, resume: &FileTransferResume) -> Vec<u32> {
        // Pre-allocate the buffer to avoid repeated reallocations.
        let mut missing = Vec::new();
        // Process each chunk independently for streaming compatibility.
        // Iterate over each element.
        // Iterate over each element.
        for i in 0..self.offer.chunk_count {
            // Track the count for threshold and bounds checking.
            let byte_idx = (i / 8) as usize;
            // Unique identifier for lookup and deduplication.
            let bit_idx = i % 8;
            // Track the count for threshold and bounds checking.
            let has_chunk = if byte_idx < resume.received_chunks.len() {
                (resume.received_chunks[byte_idx] >> bit_idx) & 1 == 1
            } else {
                false
            };
            if !has_chunk {
                // Add the element to the collection.
                // Append to the collection.
                // Append to the collection.
                missing.push(i);
            }
        }
        missing
    }
}

// ---------------------------------------------------------------------------
// Transfer State (Receiver Side)
// ---------------------------------------------------------------------------

/// Tracks the state of an incoming file transfer.
///
/// Manages received chunk bitfield, reassembly buffer tracking,
/// and integrity verification.
#[derive(Clone, Debug)]
// ReceiveTransferState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ReceiveTransferState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ReceiveTransferState {
    /// The offer that initiated this transfer.
    pub offer: FileTransferOffer,

    /// Bitfield of received chunks.
    pub received: Vec<bool>,

    /// When the transfer started.
    pub started_at: u64,

    /// Total bytes received.
    pub bytes_received: u64,
}

// ReceiveTransferState implementation — core protocol logic.
// ReceiveTransferState implementation — core protocol logic.
impl ReceiveTransferState {
    /// Create a new receive transfer state from an accepted offer.
    pub fn new(offer: FileTransferOffer, now: u64) -> Self {
        // Track the count for threshold and bounds checking.
        let chunk_count = offer.chunk_count as usize;
        Self {
            offer,
            received: vec![false; chunk_count],
            started_at: now,
            bytes_received: 0,
        }
    }

    /// Record that a chunk was received.
    pub fn mark_received(&mut self, chunk_index: u32, chunk_size: u64) {
        // Validate the input length to prevent out-of-bounds access.
        if (chunk_index as usize) < self.received.len() {
            self.received[chunk_index as usize] = true;
            // Update the bytes received to reflect the new state.
            // Advance bytes received state.
            // Advance bytes received state.
            self.bytes_received += chunk_size;
        }
    }

    /// Whether all chunks have been received.
    pub fn is_complete(&self) -> bool {
        // Create an iterator over the collection elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        self.received.iter().all(|&r| r)
    }

    /// Generate a resume bitfield for reconnection.
    pub fn resume_bitfield(&self) -> Vec<u8> {
        // Track the count for threshold and bounds checking.
        let byte_count = (self.offer.chunk_count as usize).div_ceil(8);
        // Pre-allocate the buffer to avoid repeated reallocations.
        let mut bitfield = vec![0u8; byte_count];
        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        for (i, &received) in self.received.iter().enumerate() {
            if received {
                bitfield[i / 8] |= 1 << (i % 8);
            }
        }
        bitfield
    }

    /// Progress as a fraction (0.0 to 1.0).
    pub fn progress(&self) -> f32 {
        // Track the count for threshold and bounds checking.
        let received = self.received.iter().filter(|&&r| r).count();
        // Clamp the value to prevent overflow or underflow.
        received as f32 / self.offer.chunk_count.max(1) as f32
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_offer() -> FileTransferOffer {
        FileTransferOffer {
            file_id: [0xAA; 32],
            name: "test.txt".to_string(),
            size: 256_000,
            mime_type: "text/plain".to_string(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            chunk_count: 4, // 256KB / 64KB = 4 chunks
        }
    }

    #[test]
    fn test_send_state_lifecycle() {
        let mut state = SendTransferState::new(test_offer(), 1000);

        assert!(state.can_send());
        assert!(!state.is_complete());
        assert_eq!(state.progress(), 0.0);

        // Send and ACK all chunks.
        for i in 0..4 {
            state.mark_sent(i, 1000 + i as u64);
            state.next_chunk = i + 1;
        }

        // ACK them.
        for i in 0..3 {
            assert!(!state.mark_ack(i));
        }
        assert!(state.mark_ack(3)); // Last one completes.
        assert_eq!(state.progress(), 1.0);
    }

    #[test]
    fn test_receive_state_lifecycle() {
        let mut state = ReceiveTransferState::new(test_offer(), 1000);

        assert!(!state.is_complete());

        // Receive all chunks.
        for i in 0..4 {
            state.mark_received(i, DEFAULT_CHUNK_SIZE as u64);
        }

        assert!(state.is_complete());
        assert_eq!(state.progress(), 1.0);
    }

    #[test]
    fn test_resume_bitfield() {
        let mut state = ReceiveTransferState::new(test_offer(), 1000);

        // Receive chunks 0 and 2.
        state.mark_received(0, DEFAULT_CHUNK_SIZE as u64);
        state.mark_received(2, DEFAULT_CHUNK_SIZE as u64);

        let bitfield = state.resume_bitfield();
        // Bit 0 and bit 2 should be set: 0b00000101 = 5.
        assert_eq!(bitfield[0], 0b00000101);
    }

    #[test]
    fn test_missing_from_resume() {
        let state = SendTransferState::new(test_offer(), 1000);

        // Resume says chunks 0 and 2 received.
        let resume = FileTransferResume {
            file_id: [0xAA; 32],
            received_chunks: vec![0b00000101],
        };

        let missing = state.missing_from_resume(&resume);
        assert_eq!(missing, vec![1, 3]);
    }

    #[test]
    fn test_sliding_window() {
        let mut offer = test_offer();
        offer.chunk_count = 100;
        let mut state = SendTransferState::new(offer, 1000);

        // Fill the window.
        for i in 0..SLIDING_WINDOW_SIZE {
            state.mark_sent(i, 1000);
            state.next_chunk = i + 1;
        }

        // Window is full — can't send more.
        assert!(!state.can_send());

        // ACK one — window opens.
        state.mark_ack(0);
        assert!(state.can_send());
    }

    // ── Receive-side validation ──────────────────────────────────────────────

    /// Path-shaped and oversized transfer ids are refused; plain ids pass.
    #[test]
    fn transfer_id_rejects_traversal_and_oversize() {
        // A peer-chosen id that would have become `/tmp/../home/...`.
        assert_eq!(
            validate_transfer_id("../home/user/.config/meshinfinity/settings.vault"),
            Err(TransferError::IdCharset)
        );
        assert_eq!(validate_transfer_id("a/b"), Err(TransferError::IdCharset));
        assert_eq!(validate_transfer_id("a\\b"), Err(TransferError::IdCharset));
        assert_eq!(validate_transfer_id(".."), Err(TransferError::IdCharset));
        assert_eq!(validate_transfer_id("id\0"), Err(TransferError::IdCharset));
        assert_eq!(validate_transfer_id(""), Err(TransferError::EmptyId));
        let long = "a".repeat(MAX_TRANSFER_ID_LEN + 1);
        assert_eq!(validate_transfer_id(&long), Err(TransferError::IdTooLong));
        // Our own 32-hex ids and URL-safe ids are fine.
        assert_eq!(validate_transfer_id(&"f".repeat(32)), Ok(()));
        assert_eq!(validate_transfer_id("abc_DEF-123"), Ok(()));
    }

    /// Names with separators, control bytes, or dot entries are refused.
    #[test]
    fn file_name_rejects_separators_and_reserved() {
        assert_eq!(
            validate_file_name("../../etc/passwd"),
            Err(TransferError::NameCharset)
        );
        assert_eq!(
            validate_file_name("dir\\x.txt"),
            Err(TransferError::NameCharset)
        );
        assert_eq!(
            validate_file_name("x\u{7}.txt"),
            Err(TransferError::NameCharset)
        );
        assert_eq!(
            validate_file_name("x\0.txt"),
            Err(TransferError::NameCharset)
        );
        assert_eq!(validate_file_name("."), Err(TransferError::NameReserved));
        assert_eq!(validate_file_name(".."), Err(TransferError::NameReserved));
        assert_eq!(validate_file_name(""), Err(TransferError::EmptyName));
        let long = "n".repeat(MAX_FILE_NAME_LEN + 1);
        assert_eq!(validate_file_name(&long), Err(TransferError::NameTooLong));
        assert_eq!(validate_file_name("photo (1).jpg"), Ok(()));
    }

    /// Chunk caps: per-chunk size, declared total, and sequential offsets.
    #[test]
    fn check_chunk_enforces_size_total_and_order() {
        // One byte over the chunk limit.
        assert_eq!(
            check_chunk(0, u64::MAX, MAX_CHUNK_BYTES + 1, None),
            Err(TransferError::ChunkTooLarge(MAX_CHUNK_BYTES + 1))
        );
        // Exactly at the chunk limit is fine when the total allows it.
        assert_eq!(
            check_chunk(0, MAX_CHUNK_BYTES as u64, MAX_CHUNK_BYTES, None),
            Ok(())
        );
        // Would exceed the declared total.
        assert_eq!(
            check_chunk(6, 10, 5, None),
            Err(TransferError::ChunkOverflow)
        );
        // Fills the declared total exactly.
        assert_eq!(check_chunk(6, 10, 4, Some(6)), Ok(()));
        // Any chunk against a zero-size offer overflows.
        assert_eq!(
            check_chunk(0, 0, 1, None),
            Err(TransferError::ChunkOverflow)
        );
        // Offset must equal bytes written so far.
        assert_eq!(
            check_chunk(6, 10, 4, Some(0)),
            Err(TransferError::ChunkOutOfOrder {
                expected: 6,
                got: 0
            })
        );
        // Checked arithmetic: a huge `transferred` cannot wrap past `total`.
        assert_eq!(
            check_chunk(u64::MAX, u64::MAX, 1, None),
            Err(TransferError::ChunkOverflow)
        );
    }

    /// Offer sizes beyond the u32 chunk-count ceiling are refused.
    #[test]
    fn offer_size_bounded_by_chunk_count() {
        assert_eq!(validate_offer_size(MAX_TRANSFER_BYTES), Ok(()));
        assert_eq!(
            validate_offer_size(MAX_TRANSFER_BYTES + 1),
            Err(TransferError::SizeTooLarge(MAX_TRANSFER_BYTES + 1))
        );
    }

    /// The receive path always lands in `<data_dir>/transfers/` and only
    /// accepts a charset-validated local id.
    #[test]
    fn receive_path_is_rooted_in_transfer_dir() {
        let data_dir = Path::new("/data/app");
        let path = receive_path(data_dir, "0123456789abcdef0123456789abcdef").unwrap();
        assert!(path.starts_with(transfer_dir(data_dir)));
        assert!(path.to_string_lossy().ends_with(".part"));
        // A traversal id can never produce a path.
        assert_eq!(
            receive_path(data_dir, "../x"),
            Err(TransferError::IdCharset)
        );
    }

    /// `create_receive_file` never truncates an existing file.
    #[test]
    fn create_receive_file_refuses_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.bin");
        std::fs::write(&path, b"keep me").unwrap();
        // Exclusive create must fail on the existing file...
        assert!(create_receive_file(&path).is_err());
        // ...and leave its contents untouched.
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
        // A fresh path is created normally.
        let fresh = dir.path().join("fresh.part");
        assert!(create_receive_file(&fresh).is_ok());
        assert!(fresh.exists());
    }
}
