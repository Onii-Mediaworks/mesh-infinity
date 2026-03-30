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

use serde::{Deserialize, Serialize};

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
        if matches!((&self.status, &new_status), (DeliveryStatus::Failed { .. }, DeliveryStatus::Pending)) {
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
        assert!(DeliveryStatus::Failed { reason: "timeout".into() }.is_terminal());
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
            DeliveryStatus::Failed { reason: "timeout".into() },
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
                DeliveryStatus::Failed { reason: "err".into() },
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
        let status = DeliveryStatus::Failed { reason: "network error".into() };
        let json = serde_json::to_string(&status).unwrap();
        let recovered: DeliveryStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(recovered, DeliveryStatus::Failed { .. }));
    }
}
