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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default chunk size (bytes). 64 KB.
pub const DEFAULT_CHUNK_SIZE: u32 = 65_536;

/// Maximum outstanding chunks in the sliding window.
/// Bounds receiver reassembly buffer to window × chunk_size.
pub const SLIDING_WINDOW_SIZE: u32 = 64;

// ---------------------------------------------------------------------------
// Protocol Messages
// ---------------------------------------------------------------------------

/// Offer to transfer a file (§11.1).
///
/// Sent as a chat message. Contains metadata about the file
/// so the recipient can decide whether to accept.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
pub struct FileTransferAccept {
    /// The file_id from the offer.
    pub file_id: [u8; 32],
}

/// A single chunk of file data.
///
/// Encrypted with the session key before transmission.
/// Chunks arrive in order but may need retransmission.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

impl SendTransferState {
    /// Create a new send transfer state from an offer.
    pub fn new(offer: FileTransferOffer, now: u64) -> Self {
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
        self.in_flight.remove(&chunk_index);
        if (chunk_index as usize) < self.acknowledged.len() {
            self.acknowledged[chunk_index as usize] = true;
        }
        self.is_complete()
    }

    /// Whether all chunks have been acknowledged.
    pub fn is_complete(&self) -> bool {
        self.acknowledged.iter().all(|&ack| ack)
    }

    /// Progress as a fraction (0.0 to 1.0).
    pub fn progress(&self) -> f32 {
        let acked = self.acknowledged.iter().filter(|&&a| a).count();
        acked as f32 / self.offer.chunk_count.max(1) as f32
    }

    /// Get the list of missing chunk indices from a resume bitfield.
    pub fn missing_from_resume(&self, resume: &FileTransferResume) -> Vec<u32> {
        let mut missing = Vec::new();
        for i in 0..self.offer.chunk_count {
            let byte_idx = (i / 8) as usize;
            let bit_idx = i % 8;
            let has_chunk = if byte_idx < resume.received_chunks.len() {
                (resume.received_chunks[byte_idx] >> bit_idx) & 1 == 1
            } else {
                false
            };
            if !has_chunk {
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

impl ReceiveTransferState {
    /// Create a new receive transfer state from an accepted offer.
    pub fn new(offer: FileTransferOffer, now: u64) -> Self {
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
        if (chunk_index as usize) < self.received.len() {
            self.received[chunk_index as usize] = true;
            self.bytes_received += chunk_size;
        }
    }

    /// Whether all chunks have been received.
    pub fn is_complete(&self) -> bool {
        self.received.iter().all(|&r| r)
    }

    /// Generate a resume bitfield for reconnection.
    pub fn resume_bitfield(&self) -> Vec<u8> {
        let byte_count = (self.offer.chunk_count as usize).div_ceil(8);
        let mut bitfield = vec![0u8; byte_count];
        for (i, &received) in self.received.iter().enumerate() {
            if received {
                bitfield[i / 8] |= 1 << (i % 8);
            }
        }
        bitfield
    }

    /// Progress as a fraction (0.0 to 1.0).
    pub fn progress(&self) -> f32 {
        let received = self.received.iter().filter(|&&r| r).count();
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
}
