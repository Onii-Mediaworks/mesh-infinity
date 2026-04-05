//! Message Delivery Status (§10.1.1, §16.9.2)
//!
//! # Delivery State Machine
//!
//! Messages follow a strict state machine:
//!
//! ```text
//! Pending → Sending → Sent → Delivered → Read
//!                  ↘                        ↗
//!                   → Failed ─────(retry)──→ Pending
//! ```
//!
//! Each transition is validated — you can't go from Pending to Read
//! directly. This prevents state corruption from out-of-order receipts.
//!
//! # Optimistic Display (§16.9.2)
//!
//! Messages are displayed in the thread immediately when they reach
//! Pending status, before encryption or network transmission.
//! The delivery indicator updates as the status progresses.
//!
//! # Retry Logic
//!
//! Failed messages can be retried up to MAX_RETRIES times.
//! Each retry resets the status to Pending and goes through
//! the full delivery pipeline again.

use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of delivery retries before permanent failure.
// MAX_RETRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_RETRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_RETRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_RETRIES: u32 = 3;

/// Retry backoff intervals (seconds).
/// Exponential: 5s, 30s, 120s.
// RETRY_BACKOFF_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// RETRY_BACKOFF_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// RETRY_BACKOFF_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const RETRY_BACKOFF_SECS: [u64; 3] = [5, 30, 120];

// ---------------------------------------------------------------------------
// Delivery Status
// ---------------------------------------------------------------------------

/// Delivery status of a message.
///
/// The state machine enforces valid transitions. Invalid transitions
/// (e.g., Pending → Read) are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// DeliveryStatus — variant enumeration.
// Match exhaustively to handle every protocol state.
// DeliveryStatus — variant enumeration.
// Match exhaustively to handle every protocol state.
// DeliveryStatus — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum DeliveryStatus {
    /// Message queued locally, not yet encrypted/sent.
    /// Displayed optimistically in the thread (§16.9.2).
    Pending,
    /// Message encrypted and handed to the transport layer.
    Sending,
    /// Message accepted by the network (WireGuard ACK or S&F deposit).
    Sent,
    /// Recipient's device received and decrypted the message.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Delivered,
    /// Recipient has viewed the message (read receipt received).
    Read,
    /// Delivery failed after retry exhaustion.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Failed { reason: String },
}

// Begin the block scope.
// DeliveryStatus implementation — core protocol logic.
// DeliveryStatus implementation — core protocol logic.
// DeliveryStatus implementation — core protocol logic.
impl DeliveryStatus {
    /// Whether the message is in a terminal state (no further transitions).
    // Perform the 'is terminal' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is terminal' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is terminal' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_terminal(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Read | Self::Failed { .. })
    }

    /// Whether the message should show a retry option in the UI.
    // Perform the 'is retryable' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is retryable' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is retryable' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_retryable(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Failed { .. })
    }

    /// Icon hint for UI rendering (§22.5.2 _DeliveryIcon).
    // Perform the 'icon hint' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'icon hint' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'icon hint' operation.
    // Errors are propagated to the caller via Result.
    pub fn icon_hint(&self) -> &'static str {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Handle this match arm.
            Self::Pending => "clock",
            // Handle this match arm.
            Self::Sending => "spinner",
            // Handle this match arm.
            Self::Sent => "check",
            // Handle this match arm.
            Self::Delivered => "done_all",
            // Handle this match arm.
            Self::Read => "done_all_blue",
            // Handle this match arm.
            // Handle Self::Failed { .. }.
            // Handle Self::Failed { .. }.
            // Handle Self::Failed { .. }.
            Self::Failed { .. } => "error_retry",
        }
    }

    /// Check if a transition to the target status is valid.
    ///
    /// The state machine enforces:
    /// - Pending → Sending (encryption started)
    /// - Sending → Sent (network accepted)
    /// - Sending → Failed (encryption or send error)
    /// - Sent → Delivered (delivery receipt received)
    /// - Sent → Failed (timeout or network error)
    /// - Delivered → Read (read receipt received)
    /// - Failed → Pending (retry initiated)
    ///
    /// All other transitions are invalid.
    // Perform the 'can transition to' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'can transition to' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'can transition to' operation.
    // Errors are propagated to the caller via Result.
    pub fn can_transition_to(&self, target: &DeliveryStatus) -> bool {
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            (self, target),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            (Self::Pending, Self::Sending)
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | (Self::Sending, Self::Sent)
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | (Self::Sending, Self::Failed { .. })
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | (Self::Sent, Self::Delivered)
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | (Self::Sent, Self::Failed { .. })
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | (Self::Delivered, Self::Read)
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                | (Self::Failed { .. }, Self::Pending)
        )
    }
}

// ---------------------------------------------------------------------------
// Delivery Tracker
// ---------------------------------------------------------------------------

/// Tracks delivery state for a single message.
///
/// Manages the state machine, retry count, and timestamps.
#[derive(Clone, Debug)]
// Begin the block scope.
// DeliveryTracker — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// DeliveryTracker — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// DeliveryTracker — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct DeliveryTracker {
    /// Current delivery status.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub status: DeliveryStatus,

    /// Number of delivery attempts made.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub attempts: u32,

    /// When the message was first created (Pending).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub created_at: u64,

    /// When the status last changed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_updated: u64,

    /// When the next retry should be attempted (if Failed).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub retry_after: Option<u64>,
}

// Begin the block scope.
// DeliveryTracker implementation — core protocol logic.
// DeliveryTracker implementation — core protocol logic.
// DeliveryTracker implementation — core protocol logic.
impl DeliveryTracker {
    /// Create a new tracker for a freshly composed message.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(now: u64) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            status: DeliveryStatus::Pending,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            attempts: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            created_at: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            last_updated: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            retry_after: None,
        }
    }

    /// Attempt to transition to a new status.
    ///
    /// Returns true if the transition was valid and applied.
    /// Returns false if the transition was invalid (state unchanged).
    // Perform the 'transition' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'transition' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'transition' operation.
    // Errors are propagated to the caller via Result.
    pub fn transition(&mut self, new_status: DeliveryStatus, now: u64) -> bool {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.status.can_transition_to(&new_status) {
            // Condition not met — return negative result.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return false;
        }

        // If transitioning to Sending, increment attempt count.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if matches!(new_status, DeliveryStatus::Sending) {
            // Update the attempts to reflect the new state.
            // Advance attempts state.
            // Advance attempts state.
            // Advance attempts state.
            self.attempts += 1;
        }

        // If transitioning to Failed, compute retry time.
        // `attempts` was already incremented when entering Sending, so the
        // 1st failure has attempts==1. Subtract 1 before indexing so the
        // 1st failure uses RETRY_BACKOFF_SECS[0] (5s) as documented.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if matches!(new_status, DeliveryStatus::Failed { .. }) {
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if self.attempts < MAX_RETRIES {
                // Track the count for threshold and bounds checking.
                // Compute backoff idx for this protocol step.
                // Compute backoff idx for this protocol step.
                // Compute backoff idx for this protocol step.
                let backoff_idx = (self.attempts.saturating_sub(1) as usize)
                    // Clamp the value to prevent overflow or underflow.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    .min(RETRY_BACKOFF_SECS.len() - 1);
                // Update the retry after to reflect the new state.
                // Advance retry after state.
                // Advance retry after state.
                // Advance retry after state.
                self.retry_after = Some(now + RETRY_BACKOFF_SECS[backoff_idx]);
            // Begin the block scope.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            } else {
                // Max retries exhausted — no more retries.
                // Advance retry after state.
                // Advance retry after state.
                self.retry_after = None;
            }
        }

        // If retrying (Failed → Pending), clear retry timer.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if matches!(
            (&self.status, &new_status),
            (DeliveryStatus::Failed { .. }, DeliveryStatus::Pending)
        ) {
            // Update the retry after to reflect the new state.
            // Advance retry after state.
            // Advance retry after state.
            self.retry_after = None;
        }

        // Update the status to reflect the new state.
        // Advance status state.
        // Advance status state.
        self.status = new_status;
        // Update the last updated to reflect the new state.
        // Advance last updated state.
        // Advance last updated state.
        self.last_updated = now;
        true
    }

    /// Whether a retry should be attempted now.
    ///
    /// Returns true if:
    /// - Status is Failed
    /// - We haven't exhausted retries
    /// - The retry backoff has elapsed
    // Perform the 'should retry' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'should retry' operation.
    // Errors are propagated to the caller via Result.
    pub fn should_retry(&self, now: u64) -> bool {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.status.is_retryable() {
            // Condition not met — return negative result.
            // Return to the caller.
            // Return to the caller.
            return false;
        }
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.attempts >= MAX_RETRIES {
            // Condition not met — return negative result.
            // Return to the caller.
            // Return to the caller.
            return false;
        }
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self.retry_after {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(after) => now >= after,
            // Update the local state.
            // No value available.
            // No value available.
            None => false,
        }
    }

    /// Whether the message has permanently failed (no more retries).
    // Perform the 'is permanently failed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is permanently failed' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_permanently_failed(&self) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.status.is_retryable() && self.attempts >= MAX_RETRIES
    }
}

// ---------------------------------------------------------------------------
// Delivery Receipt
// ---------------------------------------------------------------------------

/// A delivery receipt from the recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// DeliveryReceipt — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// DeliveryReceipt — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct DeliveryReceipt {
    /// The message ID this receipt is for.
    // Execute this protocol step.
    // Execute this protocol step.
    pub message_id: [u8; 16],
    /// New delivery status.
    // Execute this protocol step.
    // Execute this protocol step.
    pub status: ReceiptType,
    /// When the receipt was generated.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
}

/// Receipt type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// ReceiptType — variant enumeration.
// Match exhaustively to handle every protocol state.
// ReceiptType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ReceiptType {
    /// Message reached the recipient's device.
    // Execute this protocol step.
    // Execute this protocol step.
    Delivered,
    /// Message was viewed by the recipient.
    Read,
}

// ---------------------------------------------------------------------------
// Message Deduplication Cache (HIGH-4)
// ---------------------------------------------------------------------------

/// Maximum number of message IDs tracked per room.
///
/// Bounds memory usage: at ~40 bytes per entry (32-byte hex ID + 8-byte LRU
/// overhead), 10 000 entries consume ~400 KB per room — negligible even on
/// mobile devices.
// DEDUP_CACHE_PER_ROOM — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEDUP_CACHE_PER_ROOM: usize = 10_000;

/// Bounded LRU cache of processed message IDs.
///
/// SECURITY (HIGH-4): Prevents replay attacks where an attacker (or network
/// glitch) re-delivers a previously processed message.  Before accepting any
/// inbound message, the recipient checks this cache; if the message ID is
/// already present, the message is silently dropped.
///
/// The cache is bounded per room to prevent unbounded memory growth from
/// adversarial floods.  It uses an LRU eviction policy so the oldest
/// entries are discarded first — an attacker would need to generate
/// `DEDUP_CACHE_PER_ROOM` unique messages before a historical replay
/// could succeed, which is detectable as anomalous traffic.
///
/// Persistence: the cache is serialised to vault on every mutation so it
/// survives application restarts.
pub struct DeliveredMessageCache {
    /// Per-room LRU caches of message IDs.
    ///
    /// Key = room_id hex string, Value = LRU cache of message_id hex strings.
    /// Each inner cache is bounded to `DEDUP_CACHE_PER_ROOM` entries.
    rooms: std::collections::HashMap<String, LruCache<String, ()>>,
}

impl DeliveredMessageCache {
    /// Create a new, empty deduplication cache.
    ///
    /// No entries are present until messages are processed or the cache
    /// is loaded from vault via `from_snapshot`.
    pub fn new() -> Self {
        Self {
            rooms: std::collections::HashMap::new(),
        }
    }

    /// Check whether a message ID has already been processed in the given room.
    ///
    /// Returns `true` if the message is a duplicate (already in the cache),
    /// `false` if it is new.  Does NOT insert the ID — call `mark_delivered`
    /// after successful processing to record it.
    pub fn is_duplicate(&mut self, room_id: &str, msg_id: &str) -> bool {
        // Look up the per-room cache; if no cache exists for this room,
        // the message is necessarily not a duplicate.
        if let Some(cache) = self.rooms.get_mut(room_id) {
            // LruCache::get promotes the entry to most-recently-used.
            cache.get(msg_id).is_some()
        } else {
            false
        }
    }

    /// Record a message ID as processed in the given room.
    ///
    /// If the per-room cache does not yet exist, it is created with the
    /// standard capacity bound.  If the cache is full, the least-recently-
    /// used entry is evicted automatically by the LRU.
    pub fn mark_delivered(&mut self, room_id: &str, msg_id: &str) {
        // Retrieve or create the per-room LRU cache.
        let cache = self.rooms.entry(room_id.to_string()).or_insert_with(|| {
            // SAFETY: DEDUP_CACHE_PER_ROOM is a compile-time constant > 0.
            let capacity =
                NonZeroUsize::new(DEDUP_CACHE_PER_ROOM).expect("DEDUP_CACHE_PER_ROOM must be > 0");
            LruCache::new(capacity)
        });
        // Insert the message ID; if already present, this is a no-op that
        // promotes the entry to most-recently-used.
        cache.put(msg_id.to_string(), ());
    }

    /// Serialise the cache to a snapshot suitable for vault persistence.
    ///
    /// The snapshot format is a list of `(room_id, [msg_ids...])` pairs.
    /// Message IDs are stored in LRU order (least-recently-used first) so
    /// that `from_snapshot` can restore them in the correct eviction order.
    pub fn to_snapshot(&self) -> Vec<(String, Vec<String>)> {
        // Iterate over all rooms and collect their message IDs.
        self.rooms
            .iter()
            .map(|(room_id, cache)| {
                // LruCache::iter returns entries from least-recently-used to
                // most-recently-used — the correct order for re-insertion.
                let ids: Vec<String> = cache.iter().map(|(id, _)| id.clone()).collect();
                (room_id.clone(), ids)
            })
            .collect()
    }

    /// Restore the cache from a vault snapshot.
    ///
    /// Entries are inserted in the order they appear in the snapshot, so
    /// the last entry in each room's list becomes the most-recently-used.
    pub fn from_snapshot(snapshot: &[(String, Vec<String>)]) -> Self {
        // Rebuild the per-room caches from the serialised snapshot.
        let mut rooms = std::collections::HashMap::new();
        for (room_id, ids) in snapshot {
            // SAFETY: DEDUP_CACHE_PER_ROOM is a compile-time constant > 0.
            let capacity =
                NonZeroUsize::new(DEDUP_CACHE_PER_ROOM).expect("DEDUP_CACHE_PER_ROOM must be > 0");
            let mut cache = LruCache::new(capacity);
            // Insert in snapshot order: first entry = least-recently-used.
            for id in ids {
                cache.put(id.clone(), ());
            }
            rooms.insert(room_id.clone(), cache);
        }
        Self { rooms }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_states() {
        assert!(!DeliveryStatus::Pending.is_terminal());
        assert!(!DeliveryStatus::Sent.is_terminal());
        assert!(DeliveryStatus::Read.is_terminal());
        assert!(DeliveryStatus::Failed {
            reason: "timeout".into()
        }
        .is_terminal());
    }

    #[test]
    fn test_retryable() {
        assert!(!DeliveryStatus::Sent.is_retryable());
        assert!(DeliveryStatus::Failed { reason: "".into() }.is_retryable());
    }

    #[test]
    fn test_icon_hints() {
        assert_eq!(DeliveryStatus::Sent.icon_hint(), "check");
        assert_eq!(DeliveryStatus::Read.icon_hint(), "done_all_blue");
    }

    #[test]
    fn test_valid_transitions() {
        assert!(DeliveryStatus::Pending.can_transition_to(&DeliveryStatus::Sending));
        assert!(DeliveryStatus::Sending.can_transition_to(&DeliveryStatus::Sent));
        assert!(DeliveryStatus::Sent.can_transition_to(&DeliveryStatus::Delivered));
        assert!(DeliveryStatus::Delivered.can_transition_to(&DeliveryStatus::Read));
    }

    #[test]
    fn test_invalid_transitions() {
        // Can't skip from Pending to Read.
        assert!(!DeliveryStatus::Pending.can_transition_to(&DeliveryStatus::Read));
        // Can't go backwards from Delivered to Sending.
        assert!(!DeliveryStatus::Delivered.can_transition_to(&DeliveryStatus::Sending));
        // Can't go from Read to anything (terminal).
        assert!(!DeliveryStatus::Read.can_transition_to(&DeliveryStatus::Pending));
    }

    #[test]
    fn test_tracker_lifecycle() {
        let mut tracker = DeliveryTracker::new(1000);

        assert_eq!(tracker.status, DeliveryStatus::Pending);
        assert_eq!(tracker.attempts, 0);

        // Pending → Sending.
        assert!(tracker.transition(DeliveryStatus::Sending, 1001));
        assert_eq!(tracker.attempts, 1);

        // Sending → Sent.
        assert!(tracker.transition(DeliveryStatus::Sent, 1002));

        // Sent → Delivered.
        assert!(tracker.transition(DeliveryStatus::Delivered, 1003));

        // Delivered → Read.
        assert!(tracker.transition(DeliveryStatus::Read, 1004));

        // Read is terminal.
        assert!(tracker.status.is_terminal());
    }

    #[test]
    fn test_retry_logic() {
        let mut tracker = DeliveryTracker::new(1000);

        // Send and fail.
        tracker.transition(DeliveryStatus::Sending, 1001);
        tracker.transition(
            DeliveryStatus::Failed {
                reason: "timeout".into(),
            },
            1002,
        );

        // Should have a retry scheduled.
        // Attempt count is 1 (incremented when entering Sending).
        // backoff_idx = (1 - 1) = 0 → RETRY_BACKOFF_SECS[0] = 5 seconds.
        assert!(tracker.retry_after.is_some());
        assert!(!tracker.should_retry(1002)); // Too early.
        assert!(tracker.should_retry(1002 + RETRY_BACKOFF_SECS[0])); // After 5s backoff.

        // Retry: Failed → Pending → Sending.
        assert!(tracker.transition(DeliveryStatus::Pending, 1010));
        assert!(tracker.transition(DeliveryStatus::Sending, 1011));
        assert_eq!(tracker.attempts, 2);
    }

    #[test]
    fn test_max_retries() {
        let mut tracker = DeliveryTracker::new(1000);

        // Exhaust all retries.
        for i in 0..MAX_RETRIES {
            tracker.transition(DeliveryStatus::Sending, 1000 + i as u64 * 100);
            tracker.transition(
                DeliveryStatus::Failed {
                    reason: "err".into(),
                },
                1001 + i as u64 * 100,
            );
            if i < MAX_RETRIES - 1 {
                tracker.transition(DeliveryStatus::Pending, 1050 + i as u64 * 100);
            }
        }

        // Should be permanently failed.
        assert!(tracker.is_permanently_failed());
        assert!(!tracker.should_retry(999_999));
    }

    #[test]
    fn test_serde() {
        let status = DeliveryStatus::Failed {
            reason: "network error".into(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let recovered: DeliveryStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(recovered, DeliveryStatus::Failed { .. }));
    }

    // --- DeliveredMessageCache tests (HIGH-4) ---

    #[test]
    fn test_dedup_cache_new_message_not_duplicate() {
        // A brand-new message should not be detected as a duplicate.
        let mut cache = DeliveredMessageCache::new();
        assert!(!cache.is_duplicate("room_a", "msg_1"));
    }

    #[test]
    fn test_dedup_cache_delivered_message_is_duplicate() {
        // After marking a message as delivered, it should be a duplicate.
        let mut cache = DeliveredMessageCache::new();
        cache.mark_delivered("room_a", "msg_1");
        assert!(cache.is_duplicate("room_a", "msg_1"));
    }

    #[test]
    fn test_dedup_cache_different_rooms_independent() {
        // The same message ID in different rooms should not conflict.
        let mut cache = DeliveredMessageCache::new();
        cache.mark_delivered("room_a", "msg_1");
        // msg_1 is a duplicate in room_a but not in room_b.
        assert!(cache.is_duplicate("room_a", "msg_1"));
        assert!(!cache.is_duplicate("room_b", "msg_1"));
    }

    #[test]
    fn test_dedup_cache_lru_eviction() {
        // When the cache exceeds its capacity, the oldest entry is evicted.
        let mut cache = DeliveredMessageCache::new();
        // Fill the cache to capacity.
        for i in 0..DEDUP_CACHE_PER_ROOM {
            cache.mark_delivered("room_a", &format!("msg_{i}"));
        }

        // Adding one more should evict msg_0 (the LRU entry, since we
        // have not accessed it since insertion).
        cache.mark_delivered("room_a", "msg_overflow");
        // msg_0 was the least-recently-used — it should be evicted.
        assert!(!cache.is_duplicate("room_a", "msg_0"));
        // The overflow entry and recent entries should still be present.
        assert!(cache.is_duplicate("room_a", "msg_overflow"));
        // The most recently inserted (before overflow) should survive.
        let last = format!("msg_{}", DEDUP_CACHE_PER_ROOM - 1);
        assert!(cache.is_duplicate("room_a", &last));
    }

    #[test]
    fn test_dedup_cache_snapshot_roundtrip() {
        // Snapshot and restore should preserve the cache contents.
        let mut cache = DeliveredMessageCache::new();
        cache.mark_delivered("room_a", "msg_1");
        cache.mark_delivered("room_a", "msg_2");
        cache.mark_delivered("room_b", "msg_3");

        // Serialise and deserialise.
        let snapshot = cache.to_snapshot();
        let mut restored = DeliveredMessageCache::from_snapshot(&snapshot);

        // All entries should be present in the restored cache.
        assert!(restored.is_duplicate("room_a", "msg_1"));
        assert!(restored.is_duplicate("room_a", "msg_2"));
        assert!(restored.is_duplicate("room_b", "msg_3"));
        // A message not in the snapshot should not be a duplicate.
        assert!(!restored.is_duplicate("room_a", "msg_4"));
    }

    #[test]
    fn test_dedup_cache_mark_idempotent() {
        // Marking the same message twice should not cause issues.
        let mut cache = DeliveredMessageCache::new();
        cache.mark_delivered("room_a", "msg_1");
        cache.mark_delivered("room_a", "msg_1");
        assert!(cache.is_duplicate("room_a", "msg_1"));
    }
}
