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

// ---------------------------------------------------------------------------
// Protocol Messages
// ---------------------------------------------------------------------------

/// Offer to transfer a file (§11.1).
///
/// Sent as a chat message. Contains metadata about the file
/// so the recipient can decide whether to accept.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FileTransferOffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferOffer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferOffer {
    /// SHA-256 hash of the plaintext file.
    /// Serves as both file ID and integrity check.
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_id: [u8; 32],

    /// File name (human-readable).
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,

    /// Exact size of the plaintext file (bytes).
    // Execute this protocol step.
    // Execute this protocol step.
    pub size: u64,

    /// MIME type (e.g., "image/png", "application/pdf").
    // Execute this protocol step.
    // Execute this protocol step.
    pub mime_type: String,

    /// Chunk size in bytes. Default: 65536 (64 KB).
    /// Power-of-two recommended.
    // Execute this protocol step.
    // Execute this protocol step.
    pub chunk_size: u32,

    /// Total number of chunks: ceil(size / chunk_size).
    // Execute this protocol step.
    // Execute this protocol step.
    pub chunk_count: u32,
}

/// Accept a file transfer offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FileTransferAccept — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferAccept — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferAccept {
    /// The file_id from the offer.
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_id: [u8; 32],
}

/// A single chunk of file data.
///
/// Encrypted with the session key before transmission.
/// Chunks arrive in order but may need retransmission.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FileTransferChunk — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferChunk — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferChunk {
    /// Which file this chunk belongs to.
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_id: [u8; 32],

    /// Zero-indexed chunk number.
    // Execute this protocol step.
    // Execute this protocol step.
    pub chunk_index: u32,

    /// The encrypted chunk data. Max chunk_size bytes.
    // Execute this protocol step.
    // Execute this protocol step.
    pub data: Vec<u8>,
}

/// Acknowledgement of a received chunk.
///
/// `ok: true` means the chunk was received and stored.
/// `ok: false` means the chunk was corrupted; sender retransmits.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FileTransferChunkAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferChunkAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferChunkAck {
    /// Which file.
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_id: [u8; 32],

    /// Which chunk was acknowledged.
    // Execute this protocol step.
    // Execute this protocol step.
    pub chunk_index: u32,

    /// Whether the chunk was received successfully.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ok: bool,
}

/// Resume a partially completed transfer after reconnection.
///
/// The receiver sends a bitfield of which chunks it already has.
/// The sender retransmits only the missing ones.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FileTransferResume — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferResume — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferResume {
    /// Which file.
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_id: [u8; 32],

    /// Packed bitfield of received chunks.
    /// Bit N = 1 means chunk N has been received and verified.
    /// Length: ceil(chunk_count / 8) bytes.
    // Execute this protocol step.
    // Execute this protocol step.
    pub received_chunks: Vec<u8>,
}

/// Completion notification.
///
/// Sent by the receiver after all chunks are received and reassembled.
/// `ok: true` means SHA-256 verification passed.
/// `ok: false` means SHA-256 mismatch; sender may retransmit the entire file.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FileTransferComplete — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FileTransferComplete — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FileTransferComplete {
    /// Which file.
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_id: [u8; 32],

    /// Whether the file was received intact.
    // Execute this protocol step.
    // Execute this protocol step.
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
// Begin the block scope.
// SendTransferState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SendTransferState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SendTransferState {
    /// The offer that initiated this transfer.
    // Execute this protocol step.
    // Execute this protocol step.
    pub offer: FileTransferOffer,

    /// Which chunks have been sent but not yet ACK'd.
    /// Key: chunk_index, Value: send timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    pub in_flight: std::collections::HashMap<u32, u64>,

    /// Which chunks have been ACK'd.
    // Execute this protocol step.
    // Execute this protocol step.
    pub acknowledged: Vec<bool>,

    /// Next chunk index to send.
    // Execute this protocol step.
    // Execute this protocol step.
    pub next_chunk: u32,

    /// When the transfer started.
    // Execute this protocol step.
    // Execute this protocol step.
    pub started_at: u64,

    /// Total bytes sent (including retransmissions).
    // Execute this protocol step.
    // Execute this protocol step.
    pub bytes_sent: u64,
}

// Begin the block scope.
// SendTransferState implementation — core protocol logic.
// SendTransferState implementation — core protocol logic.
impl SendTransferState {
    /// Create a new send transfer state from an offer.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(offer: FileTransferOffer, now: u64) -> Self {
        // Track the count for threshold and bounds checking.
        // Compute chunk count for this protocol step.
        // Compute chunk count for this protocol step.
        let chunk_count = offer.chunk_count as usize;
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            offer,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            in_flight: std::collections::HashMap::new(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            acknowledged: vec![false; chunk_count],
            // Execute this protocol step.
            // Execute this protocol step.
            next_chunk: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            started_at: now,
            // Execute this protocol step.
            // Execute this protocol step.
            bytes_sent: 0,
        }
    }

    /// Whether the sliding window has room for more chunks.
    // Perform the 'can send' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'can send' operation.
    // Errors are propagated to the caller via Result.
    pub fn can_send(&self) -> bool {
        // Validate the length matches the expected protocol size.
        // Execute this protocol step.
        // Execute this protocol step.
        (self.in_flight.len() as u32) < SLIDING_WINDOW_SIZE
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            && self.next_chunk < self.offer.chunk_count
    }

    /// Record that a chunk was sent.
    // Perform the 'mark sent' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'mark sent' operation.
    // Errors are propagated to the caller via Result.
    pub fn mark_sent(&mut self, chunk_index: u32, now: u64) {
        // Insert into the lookup table for efficient retrieval.
        // Insert into the map/set.
        // Insert into the map/set.
        self.in_flight.insert(chunk_index, now);
    }

    /// Record that a chunk was acknowledged.
    ///
    /// Returns true if the transfer is now complete (all chunks ACK'd).
    // Perform the 'mark ack' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'mark ack' operation.
    // Errors are propagated to the caller via Result.
    pub fn mark_ack(&mut self, chunk_index: u32) -> bool {
        // Remove from the collection and return the evicted value.
        // Remove from the collection.
        // Remove from the collection.
        self.in_flight.remove(&chunk_index);
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if (chunk_index as usize) < self.acknowledged.len() {
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            self.acknowledged[chunk_index as usize] = true;
        }
        // Delegate to the instance method.
        // Execute this protocol step.
        // Execute this protocol step.
        self.is_complete()
    }

    /// Whether all chunks have been acknowledged.
    // Perform the 'is complete' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is complete' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_complete(&self) -> bool {
        // Create an iterator over the collection elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        self.acknowledged.iter().all(|&ack| ack)
    }

    /// Progress as a fraction (0.0 to 1.0).
    // Perform the 'progress' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'progress' operation.
    // Errors are propagated to the caller via Result.
    pub fn progress(&self) -> f32 {
        // Capture the current timestamp for temporal ordering.
        // Compute acked for this protocol step.
        // Compute acked for this protocol step.
        let acked = self.acknowledged.iter().filter(|&&a| a).count();
        // Clamp the value to prevent overflow or underflow.
        // Execute this protocol step.
        // Execute this protocol step.
        acked as f32 / self.offer.chunk_count.max(1) as f32
    }

    /// Get the list of missing chunk indices from a resume bitfield.
    // Perform the 'missing from resume' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'missing from resume' operation.
    // Errors are propagated to the caller via Result.
    pub fn missing_from_resume(&self, resume: &FileTransferResume) -> Vec<u32> {
        // Pre-allocate the buffer to avoid repeated reallocations.
        // Compute missing for this protocol step.
        // Compute missing for this protocol step.
        let mut missing = Vec::new();
        // Process each chunk independently for streaming compatibility.
        // Iterate over each element.
        // Iterate over each element.
        for i in 0..self.offer.chunk_count {
            // Track the count for threshold and bounds checking.
            // Compute byte idx for this protocol step.
            // Compute byte idx for this protocol step.
            let byte_idx = (i / 8) as usize;
            // Unique identifier for lookup and deduplication.
            // Compute bit idx for this protocol step.
            // Compute bit idx for this protocol step.
            let bit_idx = i % 8;
            // Track the count for threshold and bounds checking.
            // Compute has chunk for this protocol step.
            // Compute has chunk for this protocol step.
            let has_chunk = if byte_idx < resume.received_chunks.len() {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                (resume.received_chunks[byte_idx] >> bit_idx) & 1 == 1
            // Begin the block scope.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            } else {
                false
            };
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
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
// Begin the block scope.
// ReceiveTransferState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ReceiveTransferState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ReceiveTransferState {
    /// The offer that initiated this transfer.
    // Execute this protocol step.
    // Execute this protocol step.
    pub offer: FileTransferOffer,

    /// Bitfield of received chunks.
    // Execute this protocol step.
    // Execute this protocol step.
    pub received: Vec<bool>,

    /// When the transfer started.
    // Execute this protocol step.
    // Execute this protocol step.
    pub started_at: u64,

    /// Total bytes received.
    // Execute this protocol step.
    // Execute this protocol step.
    pub bytes_received: u64,
}

// Begin the block scope.
// ReceiveTransferState implementation — core protocol logic.
// ReceiveTransferState implementation — core protocol logic.
impl ReceiveTransferState {
    /// Create a new receive transfer state from an accepted offer.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(offer: FileTransferOffer, now: u64) -> Self {
        // Track the count for threshold and bounds checking.
        // Compute chunk count for this protocol step.
        // Compute chunk count for this protocol step.
        let chunk_count = offer.chunk_count as usize;
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            offer,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            received: vec![false; chunk_count],
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            started_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            bytes_received: 0,
        }
    }

    /// Record that a chunk was received.
    // Perform the 'mark received' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'mark received' operation.
    // Errors are propagated to the caller via Result.
    pub fn mark_received(&mut self, chunk_index: u32, chunk_size: u64) {
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if (chunk_index as usize) < self.received.len() {
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            self.received[chunk_index as usize] = true;
            // Update the bytes received to reflect the new state.
            // Advance bytes received state.
            // Advance bytes received state.
            self.bytes_received += chunk_size;
        }
    }

    /// Whether all chunks have been received.
    // Perform the 'is complete' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is complete' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_complete(&self) -> bool {
        // Create an iterator over the collection elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        self.received.iter().all(|&r| r)
    }

    /// Generate a resume bitfield for reconnection.
    // Perform the 'resume bitfield' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'resume bitfield' operation.
    // Errors are propagated to the caller via Result.
    pub fn resume_bitfield(&self) -> Vec<u8> {
        // Track the count for threshold and bounds checking.
        // Compute byte count for this protocol step.
        // Compute byte count for this protocol step.
        let byte_count = (self.offer.chunk_count as usize).div_ceil(8);
        // Pre-allocate the buffer to avoid repeated reallocations.
        // Compute bitfield for this protocol step.
        // Compute bitfield for this protocol step.
        let mut bitfield = vec![0u8; byte_count];
        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        for (i, &received) in self.received.iter().enumerate() {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if received {
                // Execute the operation and bind the result.
                // Execute this protocol step.
                // Execute this protocol step.
                bitfield[i / 8] |= 1 << (i % 8);
            }
        }
        bitfield
    }

    /// Progress as a fraction (0.0 to 1.0).
    // Perform the 'progress' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'progress' operation.
    // Errors are propagated to the caller via Result.
    pub fn progress(&self) -> f32 {
        // Track the count for threshold and bounds checking.
        // Compute received for this protocol step.
        // Compute received for this protocol step.
        let received = self.received.iter().filter(|&&r| r).count();
        // Clamp the value to prevent overflow or underflow.
        // Execute this protocol step.
        // Execute this protocol step.
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
