//! Store-and-Forward (§6.8)
//!
//! # What is Store-and-Forward?
//!
//! When the destination is unreachable (offline, out of range, etc.),
//! store-and-forward (S&F) provides deferred delivery. A trusted node
//! holds the message and delivers it when the recipient comes online.
//!
//! # How It Works
//!
//! 1. Sender tries to deliver a message but routing fails.
//! 2. Sender creates a StoreAndForwardRequest with:
//!    - The encrypted payload
//!    - A signed expiry timestamp (sender can't be tricked into infinite storage)
//!    - Priority and release conditions
//! 3. The request is deposited at a trusted S&F node.
//! 4. When the recipient comes online and is reachable, the S&F node
//!    delivers the queued messages.
//!
//! # Signed Expiry (§6.8)
//!
//! The expiry timestamp is signed by the sender's Ed25519 key.
//! This prevents the S&F node from extending the storage window —
//! it MUST honor the sender's original TTL. Default TTL: 7 days.
//!
//! # Metadata Honestly Documented
//!
//! A S&F node knows: destination address, payload size, send time,
//! expiry time, priority, and application ID. This is NOT a protocol-
//! level privacy guarantee — it's a social trust guarantee. Use only
//! trusted nodes for S&F. The spec prefers mixnet delivery (§5.25)
//! when available.
//!
//! # DoS Prevention Quotas
//!
//! Since sealed sender prevents per-sender quotas (the S&F node
//! doesn't know who sent the message), limits are per-destination
//! and aggregate:
//!
//! - Max 1 MB per individual message payload
//! - Max 500 pending messages per destination address
//! - Max 50 MB aggregate payload per destination per 24 hours
//! - Configurable total storage cap (default 2 GB client / 20 GB server)
//! - Max 60 deposits per minute per inbound tunnel

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::table::DeviceAddress;

// ---------------------------------------------------------------------------
// Constants — quotas and limits (§6.8)
// ---------------------------------------------------------------------------

/// Maximum payload size for a single S&F message (bytes).
/// 1 MB is generous for text/metadata but prevents abuse
/// with huge payloads.
// MAX_PAYLOAD_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PAYLOAD_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PAYLOAD_SIZE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_PAYLOAD_SIZE: usize = 1_048_576;

/// Maximum pending messages per destination address.
/// When this limit is reached, new deposits for that destination
/// are rejected with DestinationQueueFull.
// MAX_MESSAGES_PER_DEST — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_MESSAGES_PER_DEST — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_MESSAGES_PER_DEST — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_MESSAGES_PER_DEST: usize = 500;

/// Maximum aggregate payload per destination per 24 hours (bytes).
/// 50 MB per destination per day prevents a flood targeting one recipient.
// MAX_PAYLOAD_PER_DEST_24H — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PAYLOAD_PER_DEST_24H — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_PAYLOAD_PER_DEST_24H — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_PAYLOAD_PER_DEST_24H: u64 = 50 * 1_048_576;

/// Default total storage cap for client-mode nodes (bytes).
/// 2 GB is enough for moderate S&F relay use.
// DEFAULT_CLIENT_STORAGE_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_CLIENT_STORAGE_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_CLIENT_STORAGE_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEFAULT_CLIENT_STORAGE_CAP: u64 = 2 * 1_024 * 1_024 * 1_024;

/// Default total storage cap for server-mode nodes (bytes).
/// 20 GB for dedicated relay servers.
// DEFAULT_SERVER_STORAGE_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_SERVER_STORAGE_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_SERVER_STORAGE_CAP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEFAULT_SERVER_STORAGE_CAP: u64 = 20 * 1_024 * 1_024 * 1_024;

/// Maximum deposits per minute per inbound tunnel.
/// Rate limiting at the tunnel level prevents a single connection
/// from flooding the S&F queue.
// MAX_DEPOSITS_PER_MINUTE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_DEPOSITS_PER_MINUTE — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_DEPOSITS_PER_MINUTE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_DEPOSITS_PER_MINUTE: u32 = 60;

/// Default sender-side TTL (seconds) = 7 days.
/// The sender can set a shorter TTL, but this is the default
/// when no explicit TTL is specified.
// DEFAULT_TTL_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_TTL_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEFAULT_TTL_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;

/// Domain separator for dead man's switch cancellation signatures.
///
/// Cancellation signal signs: DOMAIN_DMS_CANCEL || message_id || issued_at || next_expected
// DOMAIN_DMS_CANCEL — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_DMS_CANCEL — protocol constant.
// Defined by the spec; must not change without a version bump.
// DOMAIN_DMS_CANCEL — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DOMAIN_DMS_CANCEL: &[u8] = b"meshinfinity-dms-cancel-v1";

/// Duration of the 24-hour rate limiting window (seconds).
// RATE_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// RATE_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// RATE_WINDOW_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
const RATE_WINDOW_SECS: u64 = 24 * 3600;

// ---------------------------------------------------------------------------
// Priority
// ---------------------------------------------------------------------------

/// Message priority for S&F ordering.
///
/// Higher priority messages are delivered first when the recipient
/// comes online. This ensures time-sensitive messages (like calls
/// or security alerts) aren't stuck behind large file transfers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
// Begin the block scope.
// Priority — variant enumeration.
// Match exhaustively to handle every protocol state.
// Priority — variant enumeration.
// Match exhaustively to handle every protocol state.
// Priority — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum Priority {
    /// Background transfers, bulk data. Delivered last.
    Low = 0,
    /// Normal messages. Default priority.
    #[default]
    // Update the local state.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Normal = 1,
    /// Time-sensitive messages (group invites, pairing requests).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    High = 2,
    /// Critical messages (security alerts, killswitch signals).
    /// Always delivered first.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Critical = 3,
}

// ---------------------------------------------------------------------------
// Release Condition
// ---------------------------------------------------------------------------

/// Conditions that control when a stored message is released.
///
/// Most messages use Immediate (deliver as soon as the recipient
/// appears). The other conditions support specialized use cases:
///
/// - `NotBefore`: scheduled delivery (e.g., birthday messages).
/// - `CancellationBased`: dead man's switch — the message is
///   delivered unless the sender cancels it within the window.
///   If the sender goes silent, the message is released automatically.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ReleaseCondition — variant enumeration.
// Match exhaustively to handle every protocol state.
// ReleaseCondition — variant enumeration.
// Match exhaustively to handle every protocol state.
// ReleaseCondition — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ReleaseCondition {
    /// Deliver as soon as the recipient is reachable.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Immediate,

    /// Don't deliver until after this Unix timestamp.
    /// Useful for scheduled/timed delivery.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    NotBefore(u64),

    /// Dead man's switch: deliver unless cancelled.
    ///
    /// The sender must periodically send cancellation signals.
    /// If `cancellation_window_secs` passes without a cancellation,
    /// the message is released. `max_lifetime` is the absolute
    /// maximum storage time regardless of cancellations.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    CancellationBased {
        /// How long to wait for a cancellation before releasing (seconds).
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        cancellation_window_secs: u32,
        /// Timestamp of the last cancellation signal received.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        last_cancellation: u64,
        /// Absolute maximum lifetime (seconds from creation).
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        max_lifetime: u64,
    },
}

// ---------------------------------------------------------------------------
// Store-and-Forward Request
// ---------------------------------------------------------------------------

/// A request to store a message for deferred delivery (§6.8).
///
/// This is the on-wire format sent to a S&F node when the recipient
/// is unreachable. The S&F node validates quotas, stores the payload,
/// and delivers when the recipient comes online.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// StoreAndForwardRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// StoreAndForwardRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// StoreAndForwardRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct StoreAndForwardRequest {
    /// Destination device address (who the message is for).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub destination: DeviceAddress,

    /// The encrypted payload (opaque to the S&F node).
    /// Maximum size: MAX_PAYLOAD_SIZE (1 MB).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload: Vec<u8>,

    /// Unix timestamp when this message expires.
    /// Computed as send_time + ttl. The S&F node MUST delete
    /// the message after this time.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expiry: u64,

    /// Ed25519 signature over the expiry timestamp.
    /// Prevents the S&F node from extending storage.
    /// Signs: "meshinfinity-sf-expiry-v1" || destination || expiry.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expiry_sig: Vec<u8>,

    /// Delivery priority.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub priority: Priority,

    /// Conditions for releasing the message.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub release_condition: ReleaseCondition,

    /// Optional application identifier.
    /// Allows the recipient to route stored messages to the
    /// correct application handler (e.g., chat vs file transfer).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub application_id: Option<[u8; 16]>,

    /// Ed25519 public key authorised to send cancellation signals for this
    /// message.  Required when `release_condition` is `CancellationBased`;
    /// ignored otherwise.  The S&F node verifies cancellation signals
    /// against this key in `apply_cancellation()`.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub cancellation_pubkey: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Deposit Result
// ---------------------------------------------------------------------------

/// Result of attempting to deposit a message at a S&F node.
#[derive(Debug, PartialEq, Eq)]
// Begin the block scope.
// DepositResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// DepositResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// DepositResult — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum DepositResult {
    /// Message accepted for storage.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Accepted,
    /// Rejected: payload exceeds MAX_PAYLOAD_SIZE.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    PayloadTooLarge,
    /// Rejected: destination queue is full (MAX_MESSAGES_PER_DEST).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    DestinationQueueFull,
    /// Rejected: destination's 24-hour aggregate limit exceeded.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    AggregateQuotaExceeded,
    /// Rejected: total storage cap reached.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    StorageCapReached,
    /// Rejected: deposit rate limit exceeded for this tunnel.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    RateLimited,
    /// Rejected: message has already expired.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    AlreadyExpired,
    /// Rejected: invalid expiry signature.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    InvalidExpirySig,
}

// ---------------------------------------------------------------------------
// Cancellation Result
// ---------------------------------------------------------------------------

/// Result of attempting to apply a dead man's switch cancellation signal.
#[derive(Debug, PartialEq, Eq)]
// Begin the block scope.
// CancellationResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// CancellationResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// CancellationResult — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum CancellationResult {
    /// Cancellation accepted — `last_cancellation` updated.
    Applied,
    /// No message with this ID exists (already delivered, expired, or unknown).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    MessageNotFound,
    /// The target message does not use `CancellationBased` release condition.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    NotCancellable,
    /// No `cancellation_pubkey` was set on the message at deposit time.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    NoCancellationKey,
    /// Signature verification failed — signal may be forged or replayed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    InvalidSignature,
    /// `issued_at` is in the future or predates the last accepted cancellation.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    StaleSignal,
}

// ---------------------------------------------------------------------------
// Stored Message
// ---------------------------------------------------------------------------

/// A message stored in the S&F queue.
///
/// This is the internal representation — it wraps the original request
/// with bookkeeping metadata (deposit time, delivery attempts, etc.).
#[derive(Clone, Debug)]
// Begin the block scope.
// StoredMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// StoredMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// StoredMessage — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
struct StoredMessage {
    /// Unique identifier for this stored message.
    /// Generated at deposit time; used by cancellation signals to
    /// locate the message without revealing destination metadata.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    message_id: [u8; 16],

    /// The original S&F request.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    request: StoreAndForwardRequest,

    /// When this message was deposited.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    deposited_at: u64,

    /// Number of delivery attempts made.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    delivery_attempts: u32,

    /// Whether this message has been delivered.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    delivered: bool,
}

// ---------------------------------------------------------------------------
// Per-Destination Queue
// ---------------------------------------------------------------------------

/// S&F queue for a single destination address.
///
/// Tracks messages, payload quotas, and rate limiting for one recipient.
#[derive(Debug)]
// Begin the block scope.
// DestinationQueue — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// DestinationQueue — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// DestinationQueue — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
struct DestinationQueue {
    /// Stored messages, ordered by priority (highest first) then deposit time.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    messages: Vec<StoredMessage>,

    /// Total payload bytes deposited in the current 24-hour window.
    /// Reset when the window expires.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    payload_24h: u64,

    /// Start of the current 24-hour rate window.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    window_start: u64,
}

// Begin the block scope.
// DestinationQueue implementation — core protocol logic.
// DestinationQueue implementation — core protocol logic.
// DestinationQueue implementation — core protocol logic.
impl DestinationQueue {
    /// Create a new empty queue for a destination.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    fn new(now: u64) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            messages: Vec::new(),
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            payload_24h: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            window_start: now,
        }
    }

    /// Number of pending (undelivered) messages.
    // Perform the 'pending count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pending count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pending count' operation.
    // Errors are propagated to the caller via Result.
    fn pending_count(&self) -> usize {
        // Create an iterator over the collection elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        // Create an iterator over the elements.
        self.messages.iter().filter(|m| !m.delivered).count()
    }

    /// Check and reset the 24-hour rate window if it has expired.
    // Perform the 'check window' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check window' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'check window' operation.
    // Errors are propagated to the caller via Result.
    fn check_window(&mut self, now: u64) {
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if now.saturating_sub(self.window_start) >= RATE_WINDOW_SECS {
            // Update the payload 24h to reflect the new state.
            // Advance payload 24h state.
            // Advance payload 24h state.
            // Advance payload 24h state.
            self.payload_24h = 0;
            // Update the window start to reflect the new state.
            // Advance window start state.
            // Advance window start state.
            // Advance window start state.
            self.window_start = now;
        }
    }
}

// ---------------------------------------------------------------------------
// Store-and-Forward Server
// ---------------------------------------------------------------------------

/// The store-and-forward server (§6.8).
///
/// Manages deferred message delivery for offline recipients. Each node
/// that participates in S&F runs one of these. It enforces all the
/// quota and rate-limiting rules from the spec.
///
/// # Storage Model
///
/// Messages are stored in memory (for the prototype). A production
/// implementation would back this with the vault storage layer.
/// The total storage cap is enforced across all destinations.
// StoreForwardServer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// StoreForwardServer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// StoreForwardServer — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct StoreForwardServer {
    /// Per-destination queues.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    queues: HashMap<DeviceAddress, DestinationQueue>,

    /// Total payload bytes stored across all destinations.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    total_stored_bytes: u64,

    /// Maximum total storage (bytes).
    /// Set from DEFAULT_CLIENT_STORAGE_CAP or DEFAULT_SERVER_STORAGE_CAP.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    storage_cap: u64,

    /// Per-tunnel deposit rate tracking.
    /// Key: tunnel identifier (simplified to a u64 for now).
    /// Value: (window_start, deposit_count).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    tunnel_rates: HashMap<u64, (u64, u32)>,
}

// Begin the block scope.
// StoreForwardServer implementation — core protocol logic.
// StoreForwardServer implementation — core protocol logic.
// StoreForwardServer implementation — core protocol logic.
impl StoreForwardServer {
    /// Create a new S&F server with the given storage cap.
    ///
    /// Use DEFAULT_CLIENT_STORAGE_CAP for client-mode nodes,
    /// DEFAULT_SERVER_STORAGE_CAP for dedicated relay servers.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(storage_cap: u64) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            queues: HashMap::new(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            total_stored_bytes: 0,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            storage_cap,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            tunnel_rates: HashMap::new(),
        }
    }

    /// Create a client-mode S&F server (2 GB cap).
    // Perform the 'new client' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new client' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new client' operation.
    // Errors are propagated to the caller via Result.
    pub fn new_client() -> Self {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::new(DEFAULT_CLIENT_STORAGE_CAP)
    }

    /// Create a server-mode S&F server (20 GB cap).
    // Perform the 'new server' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new server' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new server' operation.
    // Errors are propagated to the caller via Result.
    pub fn new_server() -> Self {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::new(DEFAULT_SERVER_STORAGE_CAP)
    }

    /// Update the total storage cap without discarding queued messages.
    ///
    /// Startup, node-mode changes, and restored settings all need to adjust the
    /// S&F relay posture while preserving any already-buffered deliveries.
    pub fn set_storage_cap(&mut self, storage_cap: u64) {
        self.storage_cap = storage_cap;
    }

    /// Deposit a message for deferred delivery.
    ///
    /// Validates all quota rules before accepting:
    /// 1. Payload size ≤ 1 MB
    /// 2. Destination queue not full (≤ 500 messages)
    /// 3. 24-hour aggregate payload ≤ 50 MB per destination
    /// 4. Total storage not at cap
    /// 5. Deposit rate ≤ 60/minute per tunnel
    /// 6. Message not already expired
    ///
    /// `tunnel_id`: identifier for the inbound tunnel (for rate limiting).
    /// `now`: current unix timestamp.
    // Perform the 'deposit' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deposit' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deposit' operation.
    // Errors are propagated to the caller via Result.
    pub fn deposit(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        request: StoreAndForwardRequest,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        tunnel_id: u64,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> DepositResult {
        // -------------------------------------------------------------------
        // Check 1: Payload size limit.
        // -------------------------------------------------------------------
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if request.payload.len() > MAX_PAYLOAD_SIZE {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::PayloadTooLarge;
        }

        // -------------------------------------------------------------------
        // Check 2: Message not already expired.
        // -------------------------------------------------------------------
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if request.expiry <= now {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::AlreadyExpired;
        }

        // -------------------------------------------------------------------
        // Check 3: Expiry signature validation.
        //
        // The expiry_sig MUST be a valid Ed25519 signature over:
        //   DOMAIN_SF_EXPIRY || destination || expiry (big-endian u64)
        //
        // This prevents the S&F node from extending the storage window.
        // The sender signs the expiry at creation; the S&F node cannot
        // forge a new expiry without the sender's private key.
        //
        // The expiry_sig is signed by the RECIPIENT's key over:
        //   DOMAIN_SF_EXPIRY || destination || expiry (BE u64)
        //
        // This allows the S&F node to verify using the destination's
        // public key (which equals destination.0 in our addressing model),
        // without needing to know the sender identity at all.
        //
        // Security property: only the intended recipient can authorize
        // the storage window for their own messages, preventing an
        // attacker from depositing messages with extended expiry windows.
        // -------------------------------------------------------------------
        {
            use crate::crypto::signing;
            // Validate the input length to prevent out-of-bounds access.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if request.expiry_sig.len() != 64 {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return DepositResult::InvalidExpirySig;
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
            msg.extend_from_slice(&request.destination.0);
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            msg.extend_from_slice(&request.expiry.to_be_bytes());
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !signing::verify(
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                &request.destination.0,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                signing::DOMAIN_SF_EXPIRY,
                &msg,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                &request.expiry_sig,
                // Begin the block scope.
            ) {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return DepositResult::InvalidExpirySig;
            }
        }

        // -------------------------------------------------------------------
        // Check 4: Per-tunnel rate limit.
        // Max 60 deposits per minute per inbound tunnel.
        // -------------------------------------------------------------------
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.is_rate_limited(tunnel_id, now) {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::RateLimited;
        }

        // -------------------------------------------------------------------
        // Check 5: Total storage cap.
        // -------------------------------------------------------------------
        // Compute payload size for this protocol step.
        // Compute payload size for this protocol step.
        // Compute payload size for this protocol step.
        let payload_size = request.payload.len() as u64;
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.total_stored_bytes + payload_size > self.storage_cap {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::StorageCapReached;
        }

        // -------------------------------------------------------------------
        // Check 6: Per-destination limits.
        // -------------------------------------------------------------------
        // Compute queue for this protocol step.
        // Compute queue for this protocol step.
        // Compute queue for this protocol step.
        let queue = self
            // Chain the operation on the intermediate result.
            .queues
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            .entry(request.destination)
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            .or_insert_with(|| DestinationQueue::new(now));

        // Reset 24h window if needed.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        queue.check_window(now);

        // Max 500 pending messages per destination.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if queue.pending_count() >= MAX_MESSAGES_PER_DEST {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::DestinationQueueFull;
        }

        // Max 50 MB aggregate per destination per 24 hours.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if queue.payload_24h + payload_size > MAX_PAYLOAD_PER_DEST_24H {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return DepositResult::AggregateQuotaExceeded;
        }

        // -------------------------------------------------------------------
        // All checks passed — store the message.
        // -------------------------------------------------------------------
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        queue.payload_24h += payload_size;
        // Update the total stored bytes to reflect the new state.
        // Advance total stored bytes state.
        // Advance total stored bytes state.
        // Advance total stored bytes state.
        self.total_stored_bytes += payload_size;

        // Assign a random message_id for use by cancellation signals.
        // Compute message id for this protocol step.
        // Compute message id for this protocol step.
        // Compute message id for this protocol step.
        let mut message_id = [0u8; 16];
        use rand_core::RngCore;
        // OS-provided cryptographic random number generator.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        rand_core::OsRng.fill_bytes(&mut message_id);

        // Begin the block scope.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        queue.messages.push(StoredMessage {
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            message_id,
            request,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            deposited_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            delivery_attempts: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            delivered: false,
        });

        // Record the deposit for rate limiting.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.record_deposit(tunnel_id, now);

        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        DepositResult::Accepted
    }

    /// Retrieve pending messages for a destination that has come online.
    ///
    /// Returns messages in priority order (highest first), then by
    /// deposit time (oldest first within same priority). Only returns
    /// messages whose release conditions are met.
    ///
    /// `now`: current unix timestamp.
    // Perform the 'retrieve' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'retrieve' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'retrieve' operation.
    // Errors are propagated to the caller via Result.
    pub fn retrieve(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        destination: &DeviceAddress,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Vec<StoreAndForwardRequest> {
        // Dispatch based on the variant to apply type-specific logic.
        // Compute queue for this protocol step.
        // Compute queue for this protocol step.
        // Compute queue for this protocol step.
        let queue = match self.queues.get_mut(destination) {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            // Wrap the found value.
            Some(q) => q,
            // Update the local state.
            // No value available.
            // No value available.
            // No value available.
            None => return Vec::new(),
        };

        // Pre-allocate the buffer to avoid repeated reallocations.
        // Compute deliverable for this protocol step.
        // Compute deliverable for this protocol step.
        // Compute deliverable for this protocol step.
        let mut deliverable = Vec::new();

        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for msg in queue.messages.iter_mut() {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if msg.delivered {
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                continue;
            }

            // Check expiry — don't deliver expired messages.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if msg.request.expiry <= now {
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                continue;
            }

            // Check release condition (pass deposited_at for max_lifetime enforcement).
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !Self::release_condition_met(&msg.request.release_condition, msg.deposited_at, now) {
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                continue;
            }

            // Mark as delivered and collect.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            msg.delivered = true;
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            msg.delivery_attempts += 1;
            // Execute the operation and bind the result.
            // Append to the collection.
            // Append to the collection.
            // Append to the collection.
            deliverable.push(msg.request.clone());
        }

        // Sort by priority (highest first), then deposit time (oldest first).
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        deliverable.sort_by(|a, b| {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            b.priority.cmp(&a.priority)
        });

        // Execute this step in the protocol sequence.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        deliverable
    }

    /// Garbage-collect expired and delivered messages.
    ///
    /// Should be called periodically (e.g., every 5 minutes).
    /// Removes:
    /// - Messages past their expiry timestamp
    /// - Messages that have been delivered
    /// - Empty destination queues
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    pub fn gc(&mut self, now: u64) {
        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for queue in self.queues.values_mut() {
            // Remove expired and delivered messages.
            // Compute before len for this protocol step.
            // Compute before len for this protocol step.
            // Compute before len for this protocol step.
            let before_len = queue.messages.len();
            // Filter the collection, keeping only elements that pass.
            // Filter elements that match the predicate.
            // Filter elements that match the predicate.
            // Filter elements that match the predicate.
            queue.messages.retain(|msg| {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                !msg.delivered && msg.request.expiry > now
            });

            // Recalculate total stored bytes after removal.
            // Compute removed bytes for this protocol step.
            // Compute removed bytes for this protocol step.
            // Compute removed bytes for this protocol step.
            let removed_bytes: u64 = (before_len - queue.messages.len()) as u64;
            // This is approximate — we'd need to track per-message size
            // for exact accounting. For now, recalculate from scratch.
            // Compute   for this protocol step.
            // Compute   for this protocol step.
            // Compute   for this protocol step.
            let _ = removed_bytes; // Silence warning.
        }

        // Recalculate total stored bytes from scratch.
        // Advance total stored bytes state.
        // Advance total stored bytes state.
        // Advance total stored bytes state.
        self.total_stored_bytes = self
            // Chain the operation on the intermediate result.
            .queues
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            .values()
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            .flat_map(|q| q.messages.iter())
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            // Transform each element.
            // Transform each element.
            .map(|m| m.request.payload.len() as u64)
            // Chain the operation on the intermediate result.
            .sum();

        // Remove empty queues.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.queues.retain(|_, q| !q.messages.is_empty());

        // Clean up old tunnel rate entries.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.tunnel_rates.retain(|_, (start, _)| {
            // Clamp the value to prevent overflow or underflow.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            now.saturating_sub(*start) < 120 // Keep for 2 minutes.
        });
    }

    /// Total number of pending messages across all destinations.
    // Perform the 'total pending' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'total pending' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'total pending' operation.
    // Errors are propagated to the caller via Result.
    pub fn total_pending(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.queues
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            .values()
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            .flat_map(|q| q.messages.iter())
            // Select only elements matching the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            .filter(|m| !m.delivered)
            // Chain the operation on the intermediate result.
            .count()
    }

    /// Total stored bytes.
    // Perform the 'total bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'total bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'total bytes' operation.
    // Errors are propagated to the caller via Result.
    pub fn total_bytes(&self) -> u64 {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.total_stored_bytes
    }

    /// Number of destinations with pending messages.
    // Perform the 'destination count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'destination count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'destination count' operation.
    // Errors are propagated to the caller via Result.
    pub fn destination_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.queues.len()
    }

    /// Process a dead man's switch cancellation signal.
    ///
    /// Finds the message identified by `signal.message_id`, verifies the
    /// Ed25519 signature against the `cancellation_pubkey` stored at deposit
    /// time, and — if valid — updates `last_cancellation` to prevent the
    /// message from being released during the next window.
    ///
    /// The signed message is:
    ///   `DOMAIN_DMS_CANCEL || message_id || issued_at (BE u64) || next_expected (BE u64)`
    ///
    /// `now`: current unix timestamp (used to reject stale signals).
    // Perform the 'apply cancellation' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'apply cancellation' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'apply cancellation' operation.
    // Errors are propagated to the caller via Result.
    pub fn apply_cancellation(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        signal: &crate::network::security_policy::CancellationSignal,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> CancellationResult {
        use crate::crypto::signing;

        // Find the message across all queues.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for queue in self.queues.values_mut() {
            // Iterate over each element in the collection.
            // Iterate over each element.
            // Iterate over each element.
            // Iterate over each element.
            for msg in queue.messages.iter_mut() {
                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if msg.message_id != signal.message_id {
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    continue;
                }
                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if msg.delivered {
                    // Return the result to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    return CancellationResult::MessageNotFound;
                }

                // Check that the message uses CancellationBased release.
                // Bind the intermediate result.
                // Bind the intermediate result.
                // Bind the intermediate result.
                let (cancellation_window_secs, last_cancellation) =
                    // Dispatch based on the variant to apply type-specific logic.
                    // Dispatch on the variant.
                    // Dispatch on the variant.
                    // Dispatch on the variant.
                    match &mut msg.request.release_condition {
                        // Begin the block scope.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        ReleaseCondition::CancellationBased {
                            // Process the current step in the protocol.
                            // Execute this protocol step.
                            // Execute this protocol step.
                            // Execute this protocol step.
                            cancellation_window_secs,
                            // Process the current step in the protocol.
                            // Execute this protocol step.
                            // Execute this protocol step.
                            // Execute this protocol step.
                            last_cancellation,
                            // Chain the operation on the intermediate result.
                            ..
                        // Handle this match arm.
                        } => (cancellation_window_secs, last_cancellation),
                        // Update the local state.
                        _ => return CancellationResult::NotCancellable,
                    };

                // Require a cancellation key to have been set at deposit time.
                // Compute pubkey for this protocol step.
                // Compute pubkey for this protocol step.
                // Compute pubkey for this protocol step.
                let pubkey = match msg.request.cancellation_pubkey {
                    // Wrap the found value for the caller.
                    // Wrap the found value.
                    // Wrap the found value.
                    // Wrap the found value.
                    Some(ref k) => *k,
                    // Update the local state.
                    // No value available.
                    // No value available.
                    // No value available.
                    None => return CancellationResult::NoCancellationKey,
                };

                // Reject stale signals (issued in the future or before last
                // accepted cancellation).
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if signal.issued_at > now {
                    // Return the result to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    return CancellationResult::StaleSignal;
                }
                // Bounds check to enforce protocol constraints.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if signal.issued_at <= *last_cancellation && *last_cancellation != msg.deposited_at
                {
                    // Return the result to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    return CancellationResult::StaleSignal;
                }

                // Verify the Ed25519 signature:
                //   DOMAIN_DMS_CANCEL || message_id || issued_at || next_expected
                // Compute signed msg for this protocol step.
                // Compute signed msg for this protocol step.
                // Compute signed msg for this protocol step.
                let mut signed_msg = Vec::with_capacity(16 + 8 + 8);
                // Append the data segment to the accumulating buffer.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                signed_msg.extend_from_slice(&signal.message_id);
                // Append the data segment to the accumulating buffer.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                signed_msg.extend_from_slice(&signal.issued_at.to_be_bytes());
                // Append the data segment to the accumulating buffer.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                // Append bytes to the accumulator.
                signed_msg.extend_from_slice(&signal.next_expected.to_be_bytes());

                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if !signing::verify(&pubkey, DOMAIN_DMS_CANCEL, &signed_msg, &signal.sig) {
                    // Return the result to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    return CancellationResult::InvalidSignature;
                }

                // All good — update last_cancellation to prevent release.
                *last_cancellation = now;
                // Bind the computed value for subsequent use.
                // Compute   for this protocol step.
                // Compute   for this protocol step.
                // Compute   for this protocol step.
                let _ = cancellation_window_secs; // used in release_condition_met

                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return CancellationResult::Applied;
            }
        }

        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        CancellationResult::MessageNotFound
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Check if a release condition is met.
    // Perform the 'release condition met' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'release condition met' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'release condition met' operation.
    // Errors are propagated to the caller via Result.
    fn release_condition_met(condition: &ReleaseCondition, deposited_at: u64, now: u64) -> bool {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match condition {
            // Immediate: always releasable.
            ReleaseCondition::Immediate => true,

            // NotBefore: only after the specified timestamp.
            ReleaseCondition::NotBefore(ts) => now >= *ts,

            // CancellationBased: release if:
            // - the absolute max_lifetime has elapsed since deposit (cannot be
            //   blocked indefinitely by repeated cancellations), OR
            // - the cancellation window has elapsed since the last signal.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            ReleaseCondition::CancellationBased {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                cancellation_window_secs,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                last_cancellation,
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                max_lifetime,
                // Begin the block scope.
                // Handle }.
                // Handle }.
                // Handle }.
            } => {
                // Enforce the absolute upper bound: once max_lifetime has
                // elapsed since the deposit, the message MUST be released even
                // if the owner keeps sending cancellation signals (§14.3).
                // Compute absolute deadline for this protocol step.
                // Compute absolute deadline for this protocol step.
                // Compute absolute deadline for this protocol step.
                let absolute_deadline = deposited_at.saturating_add(*max_lifetime);
                // Bounds check to enforce protocol constraints.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if now >= absolute_deadline {
                    // Return the result to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    return true;
                }
                // Normal path: release when the silence window elapses.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                now.saturating_sub(*last_cancellation)
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    >= *cancellation_window_secs as u64
            }
        }
    }

    /// Check if a tunnel is rate-limited.
    // Perform the 'is rate limited' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is rate limited' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is rate limited' operation.
    // Errors are propagated to the caller via Result.
    fn is_rate_limited(&self, tunnel_id: u64, now: u64) -> bool {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some((window_start, count)) = self.tunnel_rates.get(&tunnel_id) {
            // Check if we're in the current minute window.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if now.saturating_sub(*window_start) < 60 {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return *count >= MAX_DEPOSITS_PER_MINUTE;
            }
        }
        false
    }

    /// Record a deposit for rate limiting.
    // Perform the 'record deposit' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'record deposit' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'record deposit' operation.
    // Errors are propagated to the caller via Result.
    fn record_deposit(&mut self, tunnel_id: u64, now: u64) {
        // Capture the current timestamp for temporal ordering.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        let entry = self.tunnel_rates.entry(tunnel_id).or_insert((now, 0));

        // Reset if the window has expired.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if now.saturating_sub(entry.0) >= 60 {
            *entry = (now, 0);
        }

        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        entry.1 += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: return the DeviceAddress that make_request(b, ...) uses as
    /// the destination — i.e. the Ed25519 verifying key for secret seed b.
    fn dest_of(b: u8) -> DeviceAddress {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[b; 32]);
        DeviceAddress(signing_key.verifying_key().to_bytes())
    }

    /// Helper: create a properly-signed S&F request.
    ///
    /// The expiry_sig is signed by the destination's key (seed = `dest` byte),
    /// since our addressing model equates destination.0 with the Ed25519 pubkey.
    fn make_request(dest: u8, payload_size: usize, expiry: u64) -> StoreAndForwardRequest {
        use crate::crypto::signing;
        // In the test model, the destination address IS the Ed25519 public key.
        // We derive the secret from `dest` so dest[0..32] == verifying_key_bytes.
        let secret = [dest; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let destination = DeviceAddress(signing_key.verifying_key().to_bytes());

        // Match the signed message in deposit().
        let mut msg = Vec::with_capacity(32 + 8);
        msg.extend_from_slice(&destination.0);
        msg.extend_from_slice(&expiry.to_be_bytes());
        let expiry_sig = signing::sign(&secret, signing::DOMAIN_SF_EXPIRY, &msg);

        StoreAndForwardRequest {
            destination,
            payload: vec![0x42; payload_size],
            expiry,
            expiry_sig,
            priority: Priority::Normal,
            cancellation_pubkey: None,
            release_condition: ReleaseCondition::Immediate,
            application_id: None,
        }
    }

    #[test]
    fn test_deposit_and_retrieve() {
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;
        let expiry = now + DEFAULT_TTL_SECS;

        // Deposit a message.
        let result = server.deposit(make_request(0xAA, 100, expiry), 1, now);
        assert_eq!(result, DepositResult::Accepted);
        assert_eq!(server.total_pending(), 1);

        // Retrieve it.
        let messages = server.retrieve(&dest_of(0xAA), now + 1);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload.len(), 100);

        // After retrieval, it's marked delivered.
        let messages2 = server.retrieve(&dest_of(0xAA), now + 2);
        assert_eq!(messages2.len(), 0);
    }

    #[test]
    fn test_payload_too_large() {
        let mut server = StoreForwardServer::new(100_000_000);
        let now = 1000;

        let result = server.deposit(make_request(0xAA, MAX_PAYLOAD_SIZE + 1, now + 3600), 1, now);
        assert_eq!(result, DepositResult::PayloadTooLarge);
    }

    #[test]
    fn test_already_expired() {
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;

        // Expiry is in the past.
        let result = server.deposit(make_request(0xAA, 100, now - 1), 1, now);
        assert_eq!(result, DepositResult::AlreadyExpired);
    }

    #[test]
    fn test_destination_queue_full() {
        let mut server = StoreForwardServer::new(100_000_000);
        let now = 1000;
        let expiry = now + 3600;

        // Fill the queue to MAX_MESSAGES_PER_DEST.
        for i in 0..MAX_MESSAGES_PER_DEST {
            let result = server.deposit(
                make_request(0xAA, 10, expiry),
                (i as u64) % 50, // Spread across tunnels to avoid rate limit.
                now,
            );
            assert_eq!(
                result,
                DepositResult::Accepted,
                "Message {} should be accepted",
                i
            );
        }

        // One more should be rejected.
        let result = server.deposit(make_request(0xAA, 10, expiry), 99, now);
        assert_eq!(result, DepositResult::DestinationQueueFull);
    }

    #[test]
    fn test_storage_cap() {
        // 200 bytes cap.
        let mut server = StoreForwardServer::new(200);
        let now = 1000;
        let expiry = now + 3600;

        // Deposit 150 bytes: OK.
        let r1 = server.deposit(make_request(0xAA, 150, expiry), 1, now);
        assert_eq!(r1, DepositResult::Accepted);

        // Deposit 100 more bytes: exceeds 200 cap.
        let r2 = server.deposit(make_request(0xBB, 100, expiry), 2, now);
        assert_eq!(r2, DepositResult::StorageCapReached);
    }

    #[test]
    fn test_rate_limiting() {
        let mut server = StoreForwardServer::new(100_000_000);
        let now = 1000;
        let expiry = now + 3600;
        let tunnel_id = 42;

        // Deposit MAX_DEPOSITS_PER_MINUTE messages from the same tunnel.
        for _ in 0..MAX_DEPOSITS_PER_MINUTE {
            let r = server.deposit(make_request(0xAA, 10, expiry), tunnel_id, now);
            assert_eq!(r, DepositResult::Accepted);
        }

        // One more from the same tunnel: rate limited.
        let r = server.deposit(make_request(0xAA, 10, expiry), tunnel_id, now);
        assert_eq!(r, DepositResult::RateLimited);

        // Different tunnel: OK.
        let r2 = server.deposit(make_request(0xAA, 10, expiry), tunnel_id + 1, now);
        assert_eq!(r2, DepositResult::Accepted);
    }

    #[test]
    fn test_priority_ordering() {
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;
        let expiry = now + 3600;

        // Deposit messages with different priorities.
        let mut req_low = make_request(0xAA, 10, expiry);
        req_low.priority = Priority::Low;
        req_low.payload = vec![0x01; 10]; // Distinguish payloads.

        let mut req_critical = make_request(0xAA, 10, expiry);
        req_critical.priority = Priority::Critical;
        req_critical.payload = vec![0x03; 10];

        let mut req_normal = make_request(0xAA, 10, expiry);
        req_normal.priority = Priority::Normal;
        req_normal.payload = vec![0x02; 10];

        server.deposit(req_low, 1, now);
        server.deposit(req_critical, 2, now);
        server.deposit(req_normal, 3, now);

        // Retrieve: should be in priority order (Critical, Normal, Low).
        let messages = server.retrieve(&dest_of(0xAA), now + 1);
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].priority, Priority::Critical);
        assert_eq!(messages[1].priority, Priority::Normal);
        assert_eq!(messages[2].priority, Priority::Low);
    }

    #[test]
    fn test_not_before_release() {
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;
        let release_time = now + 3600;
        let expiry = now + 7200;

        let mut req = make_request(0xAA, 10, expiry);
        req.release_condition = ReleaseCondition::NotBefore(release_time);

        server.deposit(req, 1, now);

        // Before release time: nothing delivered.
        let m1 = server.retrieve(&dest_of(0xAA), now + 100);
        assert_eq!(m1.len(), 0);

        // After release time: delivered.
        let m2 = server.retrieve(&dest_of(0xAA), release_time + 1);
        assert_eq!(m2.len(), 1);
    }

    #[test]
    fn test_gc_removes_expired() {
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;
        let expiry = now + 100; // Short TTL.

        server.deposit(make_request(0xAA, 50, expiry), 1, now);
        assert_eq!(server.total_pending(), 1);
        assert_eq!(server.total_bytes(), 50);

        // GC after expiry.
        server.gc(expiry + 1);

        assert_eq!(server.total_pending(), 0);
        assert_eq!(server.total_bytes(), 0);
        assert_eq!(server.destination_count(), 0);
    }

    #[test]
    fn test_invalid_expiry_sig() {
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;

        let mut req = make_request(0xAA, 10, now + 3600);
        req.expiry_sig = Vec::new(); // Empty signature.

        let result = server.deposit(req, 1, now);
        assert_eq!(result, DepositResult::InvalidExpirySig);
    }

    #[test]
    fn test_corrupted_expiry_sig_rejected() {
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;
        let mut req = make_request(0xAA, 10, now + 3600);
        // Valid 64-byte length but corrupted content.
        req.expiry_sig[0] ^= 0xFF;
        assert_eq!(
            server.deposit(req, 1, now),
            DepositResult::InvalidExpirySig,
            "structurally valid but corrupted expiry signature must be rejected"
        );
    }

    #[test]
    fn test_wrong_key_expiry_sig_rejected() {
        use crate::crypto::signing;
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;
        let expiry = now + 3600;
        let mut req = make_request(0xAA, 10, expiry);
        // Re-sign with a different key (seed 0xBB ≠ 0xAA).
        let wrong_secret = [0xBBu8; 32];
        let mut msg = Vec::new();
        msg.extend_from_slice(&req.destination.0);
        msg.extend_from_slice(&expiry.to_be_bytes());
        req.expiry_sig = signing::sign(&wrong_secret, signing::DOMAIN_SF_EXPIRY, &msg);
        assert_eq!(
            server.deposit(req, 1, now),
            DepositResult::InvalidExpirySig,
            "expiry sig from wrong key must be rejected"
        );
    }

    #[test]
    fn test_tampered_expiry_rejected() {
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;
        let mut req = make_request(0xAA, 10, now + 3600);
        // Extend the expiry after signing.
        req.expiry += 86400;
        assert_eq!(
            server.deposit(req, 1, now),
            DepositResult::InvalidExpirySig,
            "tampered expiry must be rejected"
        );
    }

    // --- Dead Man's Switch cancellation tests (§15) ---

    /// Helper: deposit a DMS message and return the assigned message_id.
    fn deposit_dms(
        server: &mut StoreForwardServer,
        cancellation_secret: &[u8; 32],
        window_secs: u32,
        now: u64,
    ) -> [u8; 16] {
        use ed25519_dalek::SigningKey as Ed25519SK;
        let signing_key = Ed25519SK::from_bytes(cancellation_secret);
        let cancel_pub = signing_key.verifying_key().to_bytes();

        let mut req = make_request(0xAA, 10, now + 86400);
        req.release_condition = ReleaseCondition::CancellationBased {
            cancellation_window_secs: window_secs,
            last_cancellation: now,
            max_lifetime: 86400,
        };
        req.cancellation_pubkey = Some(cancel_pub);

        let result = server.deposit(req, 1, now);
        assert_eq!(result, DepositResult::Accepted);

        // Extract the message_id from the stored message.
        server
            .queues
            .values()
            .flat_map(|q| q.messages.iter())
            .next()
            .expect("message should be stored")
            .message_id
    }

    /// Helper: build a valid CancellationSignal signed by `secret`.
    fn make_cancellation(
        secret: &[u8; 32],
        message_id: [u8; 16],
        issued_at: u64,
        next_expected: u64,
    ) -> crate::network::security_policy::CancellationSignal {
        use crate::crypto::signing;
        let mut msg = Vec::with_capacity(16 + 8 + 8);
        msg.extend_from_slice(&message_id);
        msg.extend_from_slice(&issued_at.to_be_bytes());
        msg.extend_from_slice(&next_expected.to_be_bytes());
        let sig = signing::sign(secret, DOMAIN_DMS_CANCEL, &msg);
        crate::network::security_policy::CancellationSignal {
            message_id,
            issued_at,
            next_expected,
            sig,
        }
    }

    #[test]
    fn test_dms_message_not_released_while_cancelled() {
        let mut server = StoreForwardServer::new(1_000_000);
        let secret = [0xCCu8; 32];
        let now = 1000;
        let window = 60u32; // 60-second window.

        let mid = deposit_dms(&mut server, &secret, window, now);

        // Immediately after deposit: last_cancellation == now, so
        // the window has NOT elapsed — message must not release.
        let msgs = server.retrieve(&dest_of(0xAA), now + 10);
        assert_eq!(msgs.len(), 0, "DMS message must not release within window");

        // Apply a valid cancellation to reset the window.
        let sig = make_cancellation(&secret, mid, now + 10, now + 70);
        let result = server.apply_cancellation(&sig, now + 10);
        assert_eq!(result, CancellationResult::Applied);

        // Window resets to now+10, so we must wait another 60s.
        let msgs2 = server.retrieve(&dest_of(0xAA), now + 30);
        assert_eq!(
            msgs2.len(),
            0,
            "DMS message must not release while cancelled"
        );
    }

    #[test]
    fn test_dms_message_releases_when_window_elapses() {
        let mut server = StoreForwardServer::new(1_000_000);
        let secret = [0xDDu8; 32];
        let now = 1000;
        let window = 60u32;

        deposit_dms(&mut server, &secret, window, now);

        // 61 seconds later with no cancellation — must release.
        let msgs = server.retrieve(&dest_of(0xAA), now + 61);
        assert_eq!(
            msgs.len(),
            1,
            "DMS message must release after window elapses"
        );
    }

    #[test]
    fn test_dms_cancellation_wrong_key_rejected() {
        let mut server = StoreForwardServer::new(1_000_000);
        let secret = [0xEEu8; 32];
        let now = 1000;
        let window = 3600u32;

        let mid = deposit_dms(&mut server, &secret, window, now);

        // Sign with a different key.
        let wrong_secret = [0xFFu8; 32];
        let bad_sig = make_cancellation(&wrong_secret, mid, now + 1, now + 3601);
        let result = server.apply_cancellation(&bad_sig, now + 1);
        assert_eq!(result, CancellationResult::InvalidSignature);
    }

    #[test]
    fn test_dms_cancellation_tampered_message_id_rejected() {
        let mut server = StoreForwardServer::new(1_000_000);
        let secret = [0xCCu8; 32];
        let now = 1000;
        let window = 3600u32;

        let mid = deposit_dms(&mut server, &secret, window, now);

        // Tamper the message_id — signal should not find the message.
        let mut bad_mid = mid;
        bad_mid[0] ^= 0xFF;
        let bad_sig = make_cancellation(&secret, bad_mid, now + 1, now + 3601);
        let result = server.apply_cancellation(&bad_sig, now + 1);
        assert_eq!(result, CancellationResult::MessageNotFound);
    }

    /// max_lifetime must override repeated cancellations (§14.3).
    ///
    /// After `max_lifetime` seconds from deposit, the message releases even if
    /// the owner sends a valid cancellation signal within the normal window.
    /// This prevents the dead man's switch from being held open indefinitely.
    #[test]
    fn test_dms_max_lifetime_forces_release() {
        let mut server = StoreForwardServer::new(1_000_000);
        let secret = [0xBBu8; 32];
        let now = 1000;
        // Use a 24-hour cancellation window AND a short max_lifetime (30s).
        // Normally the 24-hour window means we'd wait a day; max_lifetime cuts it to 30s.
        use ed25519_dalek::SigningKey as Ed25519SK;
        let signing_key = Ed25519SK::from_bytes(&secret);
        let cancel_pub = signing_key.verifying_key().to_bytes();

        let mut req = make_request(0xAA, 10, now + 86400);
        req.release_condition = ReleaseCondition::CancellationBased {
            cancellation_window_secs: 86400, // 24-hour window — would normally block for a day
            last_cancellation: now,
            max_lifetime: 30, // but absolute cap is only 30 seconds
        };
        req.cancellation_pubkey = Some(cancel_pub);
        let result = server.deposit(req, 1, now);
        assert_eq!(result, DepositResult::Accepted);

        // 29 seconds in: still within max_lifetime — must not release.
        let msgs = server.retrieve(&dest_of(0xAA), now + 29);
        assert_eq!(msgs.len(), 0, "must not release before max_lifetime");

        // 31 seconds in: max_lifetime exceeded — must release regardless of window.
        let msgs2 = server.retrieve(&dest_of(0xAA), now + 31);
        assert_eq!(
            msgs2.len(),
            1,
            "must release after max_lifetime even with long cancellation window"
        );
    }

    /// Cancellation keeps the message held when still within max_lifetime.
    #[test]
    fn test_dms_cancellation_still_held_within_max_lifetime() {
        let mut server = StoreForwardServer::new(1_000_000);
        let secret = [0xAAu8; 32];
        let now = 1000;
        let window = 60u32;
        let mid = deposit_dms(&mut server, &secret, window, now);

        // Apply cancellation at now+10 (message was deposited at now, max_lifetime=86400).
        let sig = make_cancellation(&secret, mid, now + 10, now + 70);
        assert_eq!(
            server.apply_cancellation(&sig, now + 10),
            CancellationResult::Applied
        );

        // At now+50 (within the new cancellation window of [now+10, now+10+60]):
        // max_lifetime (86400s) is far away — must still be held.
        let msgs = server.retrieve(&dest_of(0xAA), now + 50);
        assert_eq!(
            msgs.len(),
            0,
            "must remain held within cancellation window and within max_lifetime"
        );
    }

    #[test]
    fn test_dms_non_cancellable_message_rejected() {
        let mut server = StoreForwardServer::new(1_000_000);
        let now = 1000;

        // Deposit a normal Immediate message.
        let result = server.deposit(make_request(0xAA, 10, now + 3600), 1, now);
        assert_eq!(result, DepositResult::Accepted);

        let mid = server
            .queues
            .values()
            .flat_map(|q| q.messages.iter())
            .next()
            .unwrap()
            .message_id;

        // Try to cancel it — should be rejected as NotCancellable.
        let secret = [0x01u8; 32];
        let sig = make_cancellation(&secret, mid, now + 1, now + 61);
        let result = server.apply_cancellation(&sig, now + 1);
        assert_eq!(result, CancellationResult::NotCancellable);
    }
}
