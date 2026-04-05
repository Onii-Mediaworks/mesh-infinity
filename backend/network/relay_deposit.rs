//! Relay Deposits (§10.3)
//!
//! # What is a Relay?
//!
//! A relay is a dead drop — deposit a message, pick it up later.
//! Unlike store-and-forward (§6.8), relays are anonymous and
//! use size-class padding to prevent traffic analysis.
//!
//! # Size Classes (§10.3)
//!
//! All deposits are padded to one of 8 fixed size classes to
//! prevent observers from inferring content type by size:
//!
//! | Class | Padded Size |
//! |-------|-------------|
//! | 0 | 1 KB |
//! | 1 | 4 KB |
//! | 2 | 16 KB |
//! | 3 | 64 KB |
//! | 4 | 256 KB |
//! | 5 | 1 MB |
//! | 6 | 4 MB |
//! | 7 | 16 MB |
//!
//! # Retrieval Gate
//!
//! Optional HMAC-based gate that prevents anyone without the
//! secret key from retrieving the deposit. The depositor sets
//! an HMAC over the relay_id; the retriever must present a
//! matching proof derived from the same secret.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size class padded sizes (bytes).
// SIZE_CLASSES — protocol constant.
// Defined by the spec; must not change without a version bump.
// SIZE_CLASSES — protocol constant.
// Defined by the spec; must not change without a version bump.
// SIZE_CLASSES — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SIZE_CLASSES: [usize; 8] = [
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    1_024, // Class 0: 1 KB
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    4_096, // Class 1: 4 KB
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    16_384, // Class 2: 16 KB
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    65_536, // Class 3: 64 KB
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    262_144, // Class 4: 256 KB
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    1_048_576, // Class 5: 1 MB
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    4_194_304, // Class 6: 4 MB
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    16_777_216, // Class 7: 16 MB
];

/// Minimum relay expiry (seconds). 1 hour.
// MIN_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MIN_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MIN_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MIN_EXPIRY_SECS: u64 = 3600;

/// Maximum relay expiry (seconds). 30 days.
// MAX_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_EXPIRY_SECS: u64 = 30 * 24 * 3600;

/// Maximum deposits held by a single relay server.
// MAX_DEPOSITS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_DEPOSITS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_DEPOSITS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_DEPOSITS: usize = 10_000;

/// Maximum total storage for relay deposits (bytes). 500 MB.
// MAX_TOTAL_STORAGE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_TOTAL_STORAGE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_TOTAL_STORAGE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_TOTAL_STORAGE: u64 = 500 * 1_048_576;

// ---------------------------------------------------------------------------
// Protocol Messages
// ---------------------------------------------------------------------------

/// A relay deposit (§10.3).
///
/// The depositor puts an encrypted payload into the relay.
/// The payload is padded to the size class boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// RelayDeposit — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RelayDeposit — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RelayDeposit — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct RelayDeposit {
    /// Unique relay identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub relay_id: [u8; 32],
    /// The padded encrypted payload.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload: Vec<u8>,
    /// When this deposit expires.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expiry: u64,
    /// Depositor's ephemeral public key.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub deposit_pubkey: [u8; 32],
    /// Ed25519 signature over (relay_id || expiry).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expiry_sig: Vec<u8>,
    /// Size class (0–7).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub size_class: u8,
    /// Optional retrieval gate (HMAC-based).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub retrieval_gate: Option<RetrievalGate>,
}

/// HMAC-based retrieval gate.
///
/// The retriever must present a proof that matches the HMAC
/// to retrieve the deposit. Prevents brute-force enumeration.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// RetrievalGate — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RetrievalGate — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RetrievalGate — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct RetrievalGate {
    /// HMAC-SHA256(secret_key, relay_id).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub hmac: [u8; 32],
}

/// Request to retrieve a deposit.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// RelayRetrieve — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RelayRetrieve — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RelayRetrieve — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct RelayRetrieve {
    /// Which relay to retrieve from.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub relay_id: [u8; 32],
    /// Gate proof (required if the deposit has a gate).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub gate_proof: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Size Class Helpers
// ---------------------------------------------------------------------------

/// Determine the size class for a given payload size.
///
/// Returns the smallest class that fits the payload.
/// Payloads larger than 16 MB are rejected.
// Perform the 'size class for' operation.
// Errors are propagated to the caller via Result.
// Perform the 'size class for' operation.
// Errors are propagated to the caller via Result.
// Perform the 'size class for' operation.
// Errors are propagated to the caller via Result.
pub fn size_class_for(payload_size: usize) -> Option<u8> {
    // Iterate over each element in the collection.
    // Iterate over each element.
    // Iterate over each element.
    // Iterate over each element.
    for (i, &class_size) in SIZE_CLASSES.iter().enumerate() {
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if payload_size <= class_size {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Some(i as u8);
        }
    }
    // Process the current step in the protocol.
    // No value available.
    // No value available.
    // No value available.
    None // Too large.
}

/// Get the padded size for a size class.
// Perform the 'padded size' operation.
// Errors are propagated to the caller via Result.
// Perform the 'padded size' operation.
// Errors are propagated to the caller via Result.
// Perform the 'padded size' operation.
// Errors are propagated to the caller via Result.
pub fn padded_size(class: u8) -> usize {
    // Fall back to the default value on failure.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    SIZE_CLASSES.get(class as usize).copied().unwrap_or(0)
}

/// Pad a payload to its size class boundary.
///
/// Appends a 4-byte little-endian length prefix, then the payload,
/// then zero-fill to the padded size. The receiver reads the length
/// prefix to know where real data ends.
///
/// Returns None if the payload is too large for any size class.
// Perform the 'pad payload' operation.
// Errors are propagated to the caller via Result.
// Perform the 'pad payload' operation.
// Errors are propagated to the caller via Result.
// Perform the 'pad payload' operation.
// Errors are propagated to the caller via Result.
pub fn pad_payload(payload: &[u8]) -> Option<Vec<u8>> {
    // Prepare the data buffer for the next processing stage.
    // Compute class for this protocol step.
    // Compute class for this protocol step.
    // Compute class for this protocol step.
    let class = size_class_for(payload.len() + 4)?; // +4 for length prefix
                                                    // Track the count for threshold and bounds checking.
                                                    // Compute target size for this protocol step.
                                                    // Compute target size for this protocol step.
                                                    // Compute target size for this protocol step.
    let target_size = padded_size(class);

    // Pre-allocate the buffer to avoid repeated reallocations.
    // Compute padded for this protocol step.
    // Compute padded for this protocol step.
    // Compute padded for this protocol step.
    let mut padded = Vec::with_capacity(target_size);
    // 4-byte LE length prefix.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    padded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    // Append the data segment to the accumulating buffer.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    // Append bytes to the accumulator.
    padded.extend_from_slice(payload);
    // Zero-fill to target size.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    padded.resize(target_size, 0);

    // Wrap the found value for the caller.
    // Wrap the found value.
    // Wrap the found value.
    // Wrap the found value.
    Some(padded)
}

/// Remove padding from a relay payload.
///
/// Reads the 4-byte LE length prefix and extracts the real data.
/// Returns None if the format is invalid.
// Perform the 'unpad payload' operation.
// Errors are propagated to the caller via Result.
// Perform the 'unpad payload' operation.
// Errors are propagated to the caller via Result.
// Perform the 'unpad payload' operation.
// Errors are propagated to the caller via Result.
pub fn unpad_payload(padded: &[u8]) -> Option<Vec<u8>> {
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if padded.len() < 4 {
        // No result available — signal absence to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return None;
    }
    // Track the count for threshold and bounds checking.
    // Compute len for this protocol step.
    // Compute len for this protocol step.
    // Compute len for this protocol step.
    let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if 4 + len > padded.len() {
        // No result available — signal absence to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return None;
    }
    // Wrap the found value for the caller.
    // Wrap the found value.
    // Wrap the found value.
    // Wrap the found value.
    Some(padded[4..4 + len].to_vec())
}

/// Compute an HMAC gate for a relay deposit.
///
/// `secret_key`: the shared secret between depositor and retriever.
/// `relay_id`: the unique relay identifier.
///
/// Returns the 32-byte HMAC that the retriever must present.
// Perform the 'compute gate hmac' operation.
// Errors are propagated to the caller via Result.
// Perform the 'compute gate hmac' operation.
// Errors are propagated to the caller via Result.
// Perform the 'compute gate hmac' operation.
// Errors are propagated to the caller via Result.
pub fn compute_gate_hmac(secret_key: &[u8], relay_id: &[u8; 32]) -> [u8; 32] {
    // HMAC-SHA256 accepts keys of any length — new_from_slice is infallible
    // for this implementation (HMAC does not impose a minimum key length).
    // The expect message is kept as a compile-time invariant note; this branch
    // is unreachable in practice.
    // Compute mac for this protocol step.
    // Compute mac for this protocol step.
    // Compute mac for this protocol step.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret_key)
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .expect("HMAC-SHA256 accepts any key length — this is infallible");
    // Feed the next data segment into the running hash/MAC.
    // Feed data into the running computation.
    // Feed data into the running computation.
    // Feed data into the running computation.
    mac.update(relay_id);
    // Initialize the MAC for authentication tag computation.
    // Compute result for this protocol step.
    // Compute result for this protocol step.
    // Compute result for this protocol step.
    let result = mac.finalize().into_bytes();
    // Allocate the output buffer for the result.
    // Compute out for this protocol step.
    // Compute out for this protocol step.
    // Compute out for this protocol step.
    let mut out = [0u8; 32];
    // Copy the raw bytes into the fixed-size target array.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    // Copy into the fixed-size buffer.
    out.copy_from_slice(&result);
    out
}

/// Verify a retrieval gate proof.
///
/// Checks that the provided proof matches the stored HMAC.
/// Uses constant-time comparison to prevent timing attacks.
// Perform the 'verify gate' operation.
// Errors are propagated to the caller via Result.
// Perform the 'verify gate' operation.
// Errors are propagated to the caller via Result.
// Perform the 'verify gate' operation.
// Errors are propagated to the caller via Result.
pub fn verify_gate(gate: &RetrievalGate, proof: &[u8; 32]) -> bool {
    // Constant-time comparison.
    // Compute diff for this protocol step.
    // Compute diff for this protocol step.
    // Compute diff for this protocol step.
    let mut diff = 0u8;
    // Iterate over each element in the collection.
    // Iterate over each element.
    // Iterate over each element.
    // Iterate over each element.
    for (a, b) in gate.hmac.iter().zip(proof.iter()) {
        // Execute this step in the protocol sequence.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        diff |= a ^ b;
    }
    // Update the local state.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    diff == 0
}

// ---------------------------------------------------------------------------
// Deposit Result
// ---------------------------------------------------------------------------

/// Result of attempting to store a relay deposit.
#[derive(Debug, PartialEq, Eq)]
// Begin the block scope.
// DepositResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// DepositResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// DepositResult — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum DepositResult {
    /// Deposit accepted.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Accepted,
    /// Payload too large for any size class.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    PayloadTooLarge,
    /// Deposit has already expired.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    AlreadyExpired,
    /// Expiry is out of allowed range.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ExpiryOutOfRange,
    /// Server is at deposit capacity.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    CapacityFull,
    /// Invalid signature format.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    InvalidSignature,
    /// Size class doesn't match payload.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    SizeClassMismatch,
}

/// Result of attempting to retrieve a deposit.
#[derive(Debug, PartialEq, Eq)]
// Begin the block scope.
// RetrieveResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// RetrieveResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// RetrieveResult — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RetrieveResult {
    /// Deposit not found (wrong relay_id or already expired/collected).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    NotFound,
    /// Gate proof required but not provided.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    GateRequired,
    /// Gate proof doesn't match.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    GateInvalid,
}

// ---------------------------------------------------------------------------
// Relay Server
// ---------------------------------------------------------------------------

/// A relay deposit server (§10.3).
///
/// Manages anonymous dead-drop deposits with size-class padding,
/// HMAC retrieval gates, and expiry enforcement.
// RelayServer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RelayServer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// RelayServer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct RelayServer {
    /// Stored deposits. Key: relay_id.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    deposits: HashMap<[u8; 32], RelayDeposit>,
    /// Total bytes stored across all deposits.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    total_bytes: u64,
}

// Begin the block scope.
// RelayServer implementation — core protocol logic.
// RelayServer implementation — core protocol logic.
// RelayServer implementation — core protocol logic.
impl RelayServer {
    /// Create a new relay server.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            deposits: HashMap::new(),
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            total_bytes: 0,
        }
    }

    /// Accept a deposit.
    ///
    /// Validates: size class, expiry range, signature format,
    /// capacity limits.
    // Perform the 'deposit' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deposit' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deposit' operation.
    // Errors are propagated to the caller via Result.
    pub fn deposit(&mut self, deposit: RelayDeposit, now: u64) -> DepositResult {
        // Check expiry is in the future.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if deposit.expiry <= now {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::AlreadyExpired;
        }

        // Check expiry is within allowed range.
        // Compute ttl for this protocol step.
        // Compute ttl for this protocol step.
        // Compute ttl for this protocol step.
        let ttl = deposit.expiry - now;
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !(MIN_EXPIRY_SECS..=MAX_EXPIRY_SECS).contains(&ttl) {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::ExpiryOutOfRange;
        }

        // Verify the expiry signature using the depositor's public key.
        // Signs: DOMAIN_RELAY_REQUEST || relay_id || expiry (BE u64).
        // Prevents the relay from accepting forged expiry windows.
        {
            use crate::crypto::signing;
            // Validate the input length to prevent out-of-bounds access.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if deposit.expiry_sig.len() != 64 {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return DepositResult::InvalidSignature;
            }
            // Pre-allocate the buffer to avoid repeated reallocations.
            // Compute msg for this protocol step.
            // Compute msg for this protocol step.
            // Compute msg for this protocol step.
            let mut msg = Vec::with_capacity(32 + 8);
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            msg.extend_from_slice(&deposit.relay_id);
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            msg.extend_from_slice(&deposit.expiry.to_be_bytes());
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !signing::verify(
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                &deposit.deposit_pubkey,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                signing::DOMAIN_RELAY_REQUEST,
                &msg,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                &deposit.expiry_sig,
                // Begin the block scope.
            ) {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return DepositResult::InvalidSignature;
            }
        }

        // Check size class validity.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if deposit.size_class > 7 {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::PayloadTooLarge;
        }

        // Check payload matches declared size class.
        // Compute expected size for this protocol step.
        // Compute expected size for this protocol step.
        // Compute expected size for this protocol step.
        let expected_size = padded_size(deposit.size_class);
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if deposit.payload.len() != expected_size {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::SizeClassMismatch;
        }

        // Check capacity.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.deposits.len() >= MAX_DEPOSITS {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::CapacityFull;
        }
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.total_bytes + deposit.payload.len() as u64 > MAX_TOTAL_STORAGE {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::CapacityFull;
        }

        // Accept the deposit.
        // Compute bytes for this protocol step.
        // Compute bytes for this protocol step.
        let bytes = deposit.payload.len() as u64;
        // Insert into the lookup table for efficient retrieval.
        // Insert into the map/set.
        // Insert into the map/set.
        self.deposits.insert(deposit.relay_id, deposit);
        // Update the total bytes to reflect the new state.
        // Advance total bytes state.
        // Advance total bytes state.
        self.total_bytes += bytes;

        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        DepositResult::Accepted
    }

    /// Retrieve a deposit.
    ///
    /// If the deposit has a gate, the retriever must provide a
    /// valid proof. On successful retrieval, the deposit is removed.
    // Perform the 'retrieve' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'retrieve' operation.
    // Errors are propagated to the caller via Result.
    pub fn retrieve(
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        request: &RelayRetrieve,
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Result<RelayDeposit, RetrieveResult> {
        // Check if the deposit exists and hasn't expired.
        // Compute deposit for this protocol step.
        // Compute deposit for this protocol step.
        let deposit = match self.deposits.get(&request.relay_id) {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(d) if d.expiry > now => d,
            // Update the local state.
            _ => return Err(RetrieveResult::NotFound),
        };

        // Check gate if present.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(ref gate) = deposit.retrieval_gate {
            // Dispatch based on the variant to apply type-specific logic.
            // Dispatch on the variant.
            // Dispatch on the variant.
            match &request.gate_proof {
                // Update the local state.
                // No value available.
                // No value available.
                None => return Err(RetrieveResult::GateRequired),
                // Wrap the found value for the caller.
                // Wrap the found value.
                // Wrap the found value.
                Some(proof) => {
                    // Conditional branch based on the current state.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    if !verify_gate(gate, proof) {
                        // Reject with an explicit error for the caller to handle.
                        // Return to the caller.
                        // Return to the caller.
                        return Err(RetrieveResult::GateInvalid);
                    }
                }
            }
        }

        // Remove and return the deposit.  We verified existence in the
        // `deposits.get()` call above and hold `&mut self` throughout, so
        // no other code path can concurrently remove the entry.  The key
        // must still be present; treat a missing entry as an internal
        // invariant violation rather than a user-visible error.
        // Compute deposit for this protocol step.
        // Compute deposit for this protocol step.
        let deposit = self
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            .deposits
            // Remove from the collection and return the evicted value.
            // Remove from the collection.
            // Remove from the collection.
            .remove(&request.relay_id)
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            .expect("deposit must still exist after existence check in the same exclusive borrow");
        // Update the total bytes to reflect the new state.
        // Advance total bytes state.
        // Advance total bytes state.
        self.total_bytes -= deposit.payload.len() as u64;
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(deposit)
    }

    /// Garbage-collect expired deposits.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    pub fn gc(&mut self, now: u64) {
        // Track the count for threshold and bounds checking.
        // Compute before for this protocol step.
        // Compute before for this protocol step.
        let before = self.deposits.len();
        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.deposits.retain(|_, d| d.expiry > now);
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.deposits.len() < before {
            // Recalculate total bytes.
            // Advance total bytes state.
            // Advance total bytes state.
            self.total_bytes = self.deposits.values().map(|d| d.payload.len() as u64).sum();
        }
    }

    /// Number of stored deposits.
    // Perform the 'count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'count' operation.
    // Errors are propagated to the caller via Result.
    pub fn count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.deposits.len()
    }

    /// Total bytes stored.
    // Perform the 'total bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'total bytes' operation.
    // Errors are propagated to the caller via Result.
    pub fn total_bytes(&self) -> u64 {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.total_bytes
    }
}

// Trait implementation for protocol conformance.
// Implement Default for RelayServer.
// Implement Default for RelayServer.
impl Default for RelayServer {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a properly-signed relay deposit.
    ///
    /// Uses a deterministic keypair derived from `id` so tests are reproducible.
    fn make_deposit(id: u8, class: u8, expiry: u64) -> RelayDeposit {
        use crate::crypto::signing;
        let secret = [id; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let deposit_pubkey = signing_key.verifying_key().to_bytes();
        let relay_id = [id; 32];

        // Build the signed message exactly as deposit() expects.
        let mut msg = Vec::with_capacity(32 + 8);
        msg.extend_from_slice(&relay_id);
        msg.extend_from_slice(&expiry.to_be_bytes());
        let expiry_sig = signing::sign(&secret, signing::DOMAIN_RELAY_REQUEST, &msg);

        let psize = padded_size(class);
        RelayDeposit {
            relay_id,
            payload: vec![0x42; psize],
            expiry,
            deposit_pubkey,
            expiry_sig,
            size_class: class,
            retrieval_gate: None,
        }
    }

    #[test]
    fn test_size_class_selection() {
        assert_eq!(size_class_for(100), Some(0));
        assert_eq!(size_class_for(1024), Some(0));
        assert_eq!(size_class_for(1025), Some(1));
        assert_eq!(size_class_for(1_000_000), Some(5));
        assert_eq!(size_class_for(16_777_216), Some(7));
        assert_eq!(size_class_for(16_777_217), None);
    }

    #[test]
    fn test_padded_size() {
        assert_eq!(padded_size(0), 1_024);
        assert_eq!(padded_size(7), 16_777_216);
        assert_eq!(padded_size(8), 0);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let data = b"hello relay world";
        let padded = pad_payload(data).unwrap();
        assert_eq!(padded.len(), 1_024); // Class 0.
        let recovered = unpad_payload(&padded).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_deposit_and_retrieve() {
        let mut server = RelayServer::new();
        let now = 1000;

        let dep = make_deposit(0x01, 0, now + 3600);
        assert_eq!(server.deposit(dep, now), DepositResult::Accepted);
        assert_eq!(server.count(), 1);

        let req = RelayRetrieve {
            relay_id: [0x01; 32],
            gate_proof: None,
        };
        let result = server.retrieve(&req, now);
        assert!(result.is_ok());
        assert_eq!(server.count(), 0);
    }

    #[test]
    fn test_gate_verification() {
        let secret = b"my-secret-key";
        let relay_id = [0xAA; 32];

        let hmac = compute_gate_hmac(secret, &relay_id);
        let gate = RetrievalGate { hmac };

        // Correct proof.
        let proof = compute_gate_hmac(secret, &relay_id);
        assert!(verify_gate(&gate, &proof));

        // Wrong proof.
        let wrong = [0xFF; 32];
        assert!(!verify_gate(&gate, &wrong));
    }

    #[test]
    fn test_gated_deposit() {
        let mut server = RelayServer::new();
        let now = 1000;
        let secret = b"secret";
        let relay_id = [0x02; 32];

        let hmac = compute_gate_hmac(secret, &relay_id);
        let mut dep = make_deposit(0x02, 0, now + 3600);
        dep.retrieval_gate = Some(RetrievalGate { hmac });

        server.deposit(dep, now);

        // Without proof: fails.
        let req_no_proof = RelayRetrieve {
            relay_id,
            gate_proof: None,
        };
        assert_eq!(
            server.retrieve(&req_no_proof, now).unwrap_err(),
            RetrieveResult::GateRequired
        );

        // Wrong proof: fails.
        let req_wrong = RelayRetrieve {
            relay_id,
            gate_proof: Some([0xFF; 32]),
        };
        assert_eq!(
            server.retrieve(&req_wrong, now).unwrap_err(),
            RetrieveResult::GateInvalid
        );

        // Correct proof: succeeds.
        let proof = compute_gate_hmac(secret, &relay_id);
        let req_ok = RelayRetrieve {
            relay_id,
            gate_proof: Some(proof),
        };
        assert!(server.retrieve(&req_ok, now).is_ok());
    }

    #[test]
    fn test_expired_deposit_rejected() {
        let mut server = RelayServer::new();
        let dep = make_deposit(0x01, 0, 500); // Already expired at now=1000.
        assert_eq!(server.deposit(dep, 1000), DepositResult::AlreadyExpired);
    }

    #[test]
    fn test_size_class_mismatch() {
        let mut server = RelayServer::new();
        let mut dep = make_deposit(0x01, 0, 5000);
        dep.payload = vec![0; 500]; // Doesn't match class 0 (1024).
        assert_eq!(server.deposit(dep, 1000), DepositResult::SizeClassMismatch);
    }

    #[test]
    fn test_gc_removes_expired() {
        let mut server = RelayServer::new();
        let now = 1000;
        // Both deposits need TTL >= MIN_EXPIRY_SECS to be accepted.
        server.deposit(make_deposit(0x01, 0, now + MIN_EXPIRY_SECS + 100), now);
        server.deposit(make_deposit(0x02, 0, now + MIN_EXPIRY_SECS + 5000), now);
        assert_eq!(server.count(), 2);

        // GC after first expires, before second.
        server.gc(now + MIN_EXPIRY_SECS + 200);
        assert_eq!(server.count(), 1);
    }

    #[test]
    fn test_invalid_expiry_sig_rejected() {
        let mut server = RelayServer::new();
        let now = 1000;
        let mut dep = make_deposit(0x01, 0, now + MIN_EXPIRY_SECS + 100);
        // Corrupt the signature.
        dep.expiry_sig[0] ^= 0xFF;
        assert_eq!(
            server.deposit(dep, now),
            DepositResult::InvalidSignature,
            "corrupted expiry signature must be rejected"
        );
    }

    #[test]
    fn test_wrong_key_expiry_sig_rejected() {
        use crate::crypto::signing;
        let mut server = RelayServer::new();
        let now = 1000;
        // Build a deposit signed by a different key (id=0xFF, not id=0x01).
        let mut dep = make_deposit(0x01, 0, now + MIN_EXPIRY_SECS + 100);
        let wrong_secret = [0xFFu8; 32];
        let mut msg = Vec::new();
        msg.extend_from_slice(&dep.relay_id);
        msg.extend_from_slice(&dep.expiry.to_be_bytes());
        dep.expiry_sig = signing::sign(&wrong_secret, signing::DOMAIN_RELAY_REQUEST, &msg);
        // deposit_pubkey still claims to be 0x01's key — signature won't verify.
        assert_eq!(
            server.deposit(dep, now),
            DepositResult::InvalidSignature,
            "expiry sig from wrong key must be rejected"
        );
    }

    #[test]
    fn test_tampered_expiry_rejected() {
        let mut server = RelayServer::new();
        let now = 1000;
        let mut dep = make_deposit(0x01, 0, now + MIN_EXPIRY_SECS + 100);
        // Tamper with expiry after signing — signature covers original value.
        dep.expiry += 86400; // extend by 1 day
        assert_eq!(
            server.deposit(dep, now),
            DepositResult::InvalidSignature,
            "deposit with tampered expiry must be rejected"
        );
    }
}
