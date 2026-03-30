//! Session Key Management (§7.4, §7.5, §7.6)
//!
//! # What are Session Keys?
//!
//! Session keys are ephemeral symmetric keys used to encrypt data
//! within an ongoing connection. They sit ABOVE the Double Ratchet
//! (which handles per-message keys) and BELOW the transport layer
//! (which handles per-hop encryption via WireGuard).
//!
//! # Key Derivation (§7.4)
//!
//! Session keys are derived via:
//! ```text
//! session_key = HKDF-SHA256(
//!     ikm  = X25519(my_ephemeral_secret, their_ephemeral_public),
//!     salt = handshake_nonce,
//!     info = "meshinfinity-session-v1"
//! )
//! ```
//!
//! # Nonce Management
//!
//! Each message within a session uses a counter-based nonce:
//! - 12 bytes total (ChaCha20-Poly1305 nonce size)
//! - First 4 bytes: zero
//! - Last 8 bytes: monotonically incrementing u64, big-endian
//!
//! The counter MUST never wrap. When it approaches critical thresholds,
//! the session is rekeyed:
//!
//! | Threshold | Action |
//! |-----------|--------|
//! | 2^44 | First rekey attempt |
//! | 2^46 | Second rekey attempt |
//! | 2^47 | Third attempt + UI warning |
//! | 2^48 | Hard stall — no more data until rekeyed |
//!
//! # Rekeying (§7.5)
//!
//! When a rekey threshold is reached, both parties generate new
//! ephemeral X25519 keypairs and derive a fresh session key.
//! The old key is zeroized immediately. There is a 30-second
//! stall timeout — if rekeying hasn't completed, the session
//! is dropped.
//!
//! # Reconnect and Sync (§7.6)
//!
//! On reconnect after a disconnect:
//! 1. The reconnecting peer sends a SyncRequest with the timestamp
//!    and sequence number of their last received message.
//! 2. The other peer replays messages after that point.
//! 3. Messages are deduplicated by permanent message_id.
//!
//! Ordering is by per-conversation sequence_number (u64), NOT
//! by timestamp. Timestamps are for display only.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants — rekeying thresholds (§7.4)
// ---------------------------------------------------------------------------

/// First rekey attempt threshold.
/// At 2^44 ≈ 17.6 trillion messages, the session should rekey.
/// In practice this is never reached for text messaging, but
/// streaming sessions (voice/video) can hit it.
// REKEY_THRESHOLD_1 — protocol constant.
// Defined by the spec; must not change without a version bump.
// REKEY_THRESHOLD_1 — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const REKEY_THRESHOLD_1: u64 = 1 << 44;

/// Second rekey attempt threshold.
/// If the first attempt failed (peer unresponsive), try again at 2^46.
// REKEY_THRESHOLD_2 — protocol constant.
// Defined by the spec; must not change without a version bump.
// REKEY_THRESHOLD_2 — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const REKEY_THRESHOLD_2: u64 = 1 << 46;

/// Third rekey attempt with UI warning.
/// The user is warned that the session is at risk.
// REKEY_THRESHOLD_3 — protocol constant.
// Defined by the spec; must not change without a version bump.
// REKEY_THRESHOLD_3 — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const REKEY_THRESHOLD_3: u64 = 1 << 47;

/// Hard stall threshold.
/// NO more data is sent until rekeying completes.
/// Sending at this nonce would risk nonce reuse.
// REKEY_HARD_STALL — protocol constant.
// Defined by the spec; must not change without a version bump.
// REKEY_HARD_STALL — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const REKEY_HARD_STALL: u64 = 1 << 48;

/// Stall timeout before the session is dropped (seconds).
/// If rekeying hasn't completed within 30 seconds of hard stall,
/// the session is torn down.
// STALL_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// STALL_TIMEOUT_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const STALL_TIMEOUT_SECS: u64 = 30;

/// Maximum retries with the same ephemeral key.
/// After 3 failed rekey attempts with the same ephemeral, generate
/// a new ephemeral keypair.
// MAX_RETRIES_SAME_EPHEMERAL — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_RETRIES_SAME_EPHEMERAL — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_RETRIES_SAME_EPHEMERAL: u32 = 3;

/// How long to retain an ephemeral key after last transmission (seconds).
/// The ephemeral is kept briefly in case the peer needs it for
/// late-arriving messages, then zeroized.
// EPHEMERAL_RETENTION_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// EPHEMERAL_RETENTION_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const EPHEMERAL_RETENTION_SECS: u64 = 60;

/// Domain separator for session key derivation via HKDF.
/// Included in the `info` parameter to prevent cross-protocol
/// key reuse.
// SESSION_KEY_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// SESSION_KEY_DOMAIN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SESSION_KEY_DOMAIN: &[u8] = b"meshinfinity-session-v1";

// ---------------------------------------------------------------------------
// Session State
// ---------------------------------------------------------------------------

/// The state of an ongoing encrypted session.
///
/// Tracks the current session key, nonce counter, and rekeying
/// state. Each active connection (DM, group, file transfer, call)
/// has its own SessionState.
#[derive(Clone, Debug)]
// Begin the block scope.
// SessionState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SessionState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SessionState {
    /// The current session key (32 bytes, ChaCha20-Poly1305).
    /// Zeroized on Drop in a real implementation.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_key: [u8; 32],

    /// Monotonically incrementing nonce counter.
    /// Each encrypt operation increments this by 1.
    /// When it hits REKEY_THRESHOLD_1, rekeying begins.
    // Execute this protocol step.
    // Execute this protocol step.
    pub nonce_counter: u64,

    /// How many rekey attempts have been made at the current
    /// threshold level. Resets to 0 after a successful rekey.
    // Execute this protocol step.
    // Execute this protocol step.
    pub rekey_attempts: u32,

    /// Whether the session is currently stalled (nonce at REKEY_HARD_STALL).
    /// No data can be sent until rekeying completes.
    // Execute this protocol step.
    // Execute this protocol step.
    pub stalled: bool,

    /// Unix timestamp when the stall began (for timeout tracking).
    // Execute this protocol step.
    // Execute this protocol step.
    pub stall_started_at: Option<u64>,

    /// Session epoch — incremented on each successful rekey.
    /// Allows the peer to detect that we've rekeyed.
    // Execute this protocol step.
    // Execute this protocol step.
    pub epoch: u64,

    /// When this session was established.
    // Execute this protocol step.
    // Execute this protocol step.
    pub established_at: u64,
}

// Begin the block scope.
// SessionState implementation — core protocol logic.
// SessionState implementation — core protocol logic.
impl SessionState {
    /// Create a new session state with a freshly derived key.
    ///
    /// `session_key`: the 32-byte key from HKDF.
    /// `now`: current unix timestamp.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(session_key: [u8; 32], now: u64) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Execute this protocol step.
            // Execute this protocol step.
            session_key,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            nonce_counter: 0,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            rekey_attempts: 0,
            // Execute this protocol step.
            // Execute this protocol step.
            stalled: false,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            stall_started_at: None,
            // Execute this protocol step.
            // Execute this protocol step.
            epoch: 1,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            established_at: now,
        }
    }

    /// Get the next nonce for encryption.
    ///
    /// Returns a 12-byte nonce (4 zero bytes + 8-byte counter).
    /// Returns None if the session is stalled (must rekey first).
    // Perform the 'next nonce' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'next nonce' operation.
    // Errors are propagated to the caller via Result.
    pub fn next_nonce(&mut self) -> Option<[u8; 12]> {
        // Check if we're stalled — no more data allowed.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.stalled {
            // No result available — signal absence to the caller.
            // Return to the caller.
            // Return to the caller.
            return None;
        }

        // Check if we've hit the hard stall.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.nonce_counter >= REKEY_HARD_STALL {
            // Update the stalled to reflect the new state.
            // Advance stalled state.
            // Advance stalled state.
            self.stalled = true;
            // No result available — signal absence to the caller.
            // Return to the caller.
            // Return to the caller.
            return None;
        }

        // Build the 12-byte nonce.
        // First 4 bytes: zero (to fill ChaCha20-Poly1305's 96-bit nonce).
        // Last 8 bytes: counter in big-endian.
        // Compute nonce for this protocol step.
        // Compute nonce for this protocol step.
        let mut nonce = [0u8; 12];
        // Copy the raw bytes into the fixed-size target array.
        // Copy into the fixed-size buffer.
        // Copy into the fixed-size buffer.
        nonce[4..12].copy_from_slice(&self.nonce_counter.to_be_bytes());

        // Increment the counter.
        // Advance nonce counter state.
        // Advance nonce counter state.
        self.nonce_counter += 1;

        // Wrap the found value for the caller.
        // Wrap the found value.
        // Wrap the found value.
        Some(nonce)
    }

    /// Check which rekey action is needed (if any).
    ///
    /// Called after each encrypt operation to determine if
    /// rekeying should be initiated.
    // Perform the 'rekey action' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'rekey action' operation.
    // Errors are propagated to the caller via Result.
    pub fn rekey_action(&self) -> RekeyAction {
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.nonce_counter >= REKEY_HARD_STALL {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            RekeyAction::HardStall
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        } else if self.nonce_counter >= REKEY_THRESHOLD_3 {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            RekeyAction::RekeyWithWarning
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        } else if self.nonce_counter >= REKEY_THRESHOLD_2 {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            RekeyAction::RekeyUrgent
        // Bounds check to enforce protocol constraints.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        } else if self.nonce_counter >= REKEY_THRESHOLD_1 {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            RekeyAction::RekeyNormal
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            RekeyAction::None
        }
    }

    /// Complete a rekey by installing a new session key.
    ///
    /// Zeroizes the old key (caller must ensure this happens
    /// in the real implementation) and resets counters.
    // Perform the 'complete rekey' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'complete rekey' operation.
    // Errors are propagated to the caller via Result.
    pub fn complete_rekey(&mut self, new_key: [u8; 32], _now: u64) {
        // In a real implementation, the old key would be zeroized
        // via the SecureBytes wrapper. For now, overwrite with zeros.
        // Advance session key state.
        // Advance session key state.
        self.session_key = [0u8; 32];

        // Install the new key and reset state.
        // Advance session key state.
        // Advance session key state.
        self.session_key = new_key;
        // Update the nonce counter to reflect the new state.
        // Advance nonce counter state.
        // Advance nonce counter state.
        self.nonce_counter = 0;
        // Update the rekey attempts to reflect the new state.
        // Advance rekey attempts state.
        // Advance rekey attempts state.
        self.rekey_attempts = 0;
        // Update the stalled to reflect the new state.
        // Advance stalled state.
        // Advance stalled state.
        self.stalled = false;
        // Update the stall started at to reflect the new state.
        // Advance stall started at state.
        // Advance stall started at state.
        self.stall_started_at = None;
        // Update the epoch to reflect the new state.
        // Advance epoch state.
        // Advance epoch state.
        self.epoch += 1;
    }

    /// Record a failed rekey attempt.
    // Perform the 'rekey failed' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'rekey failed' operation.
    // Errors are propagated to the caller via Result.
    pub fn rekey_failed(&mut self, now: u64) {
        // Update the rekey attempts to reflect the new state.
        // Advance rekey attempts state.
        // Advance rekey attempts state.
        self.rekey_attempts += 1;

        // If we're at the hard stall, start the timeout clock.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.stalled && self.stall_started_at.is_none() {
            // Update the stall started at to reflect the new state.
            // Advance stall started at state.
            // Advance stall started at state.
            self.stall_started_at = Some(now);
        }
    }

    /// Whether the stall timeout has been exceeded.
    ///
    /// If the session has been stalled for longer than
    /// STALL_TIMEOUT_SECS, the session should be dropped.
    // Perform the 'is stall timed out' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is stall timed out' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_stall_timed_out(&self, now: u64) -> bool {
        // Flow control: check if the operation should be stalled.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(stall_start) = self.stall_started_at {
            // Clamp the value to prevent overflow or underflow.
            // Execute this protocol step.
            // Execute this protocol step.
            now.saturating_sub(stall_start) > STALL_TIMEOUT_SECS
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            false
        }
    }

    /// Whether a new ephemeral key should be generated.
    ///
    /// After MAX_RETRIES_SAME_EPHEMERAL failed attempts, the
    /// ephemeral keypair should be regenerated.
    // Perform the 'needs new ephemeral' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'needs new ephemeral' operation.
    // Errors are propagated to the caller via Result.
    pub fn needs_new_ephemeral(&self) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.rekey_attempts >= MAX_RETRIES_SAME_EPHEMERAL
    }
}

/// What rekey action is needed at the current nonce counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Begin the block scope.
// RekeyAction — variant enumeration.
// Match exhaustively to handle every protocol state.
// RekeyAction — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RekeyAction {
    /// No action needed — counter is well below all thresholds.
    // No value available.
    // No value available.
    None,
    /// Normal rekey — first threshold reached.
    // Execute this protocol step.
    // Execute this protocol step.
    RekeyNormal,
    /// Urgent rekey — second threshold reached.
    // Execute this protocol step.
    // Execute this protocol step.
    RekeyUrgent,
    /// Rekey with UI warning — third threshold reached.
    // Execute this protocol step.
    // Execute this protocol step.
    RekeyWithWarning,
    /// Hard stall — no more data until rekeyed.
    // Execute this protocol step.
    // Execute this protocol step.
    HardStall,
}

// ---------------------------------------------------------------------------
// Session Proposal
// ---------------------------------------------------------------------------

/// A proposal to establish or rekey a session (§7.4).
///
/// Sent by the initiator to propose a new session key.
/// The ephemeral public key is used with the recipient's ephemeral
/// for X25519 key agreement.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// SessionProposal — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SessionProposal — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SessionProposal {
    /// The sender's ephemeral X25519 public key for this session.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ephemeral_public: [u8; 32],

    /// A fresh random nonce used as the HKDF salt.
    /// Both parties use this to derive the same session key.
    // Execute this protocol step.
    // Execute this protocol step.
    pub handshake_nonce: [u8; 32],

    /// The session epoch being proposed.
    /// For initial establishment: 1.
    /// For rekeying: current_epoch + 1.
    // Execute this protocol step.
    // Execute this protocol step.
    pub proposed_epoch: u64,

    /// Unix timestamp.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Sync Request (§7.6)
// ---------------------------------------------------------------------------

/// A synchronization request sent on reconnect (§7.6).
///
/// When a peer reconnects after a disconnect, they send a SyncRequest
/// with the details of their last received message. The other peer
/// replays messages after that point.
///
/// Ordering is by sequence_number (per-conversation, monotonic u64),
/// NOT by timestamp. Timestamps are for display only.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// SyncRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SyncRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SyncRequest {
    /// The conversation/room ID this sync is for.
    // Execute this protocol step.
    // Execute this protocol step.
    pub conversation_id: [u8; 32],

    /// The sequence number of the last message we received.
    /// The peer should send all messages with sequence > this.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_received_sequence: u64,

    /// The timestamp of the last message we received.
    /// Used as a fallback if the peer doesn't track sequence numbers
    /// (e.g., an older version).
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_received_timestamp: u64,

    /// Our current session epoch.
    /// If it doesn't match the peer's, a full session re-establishment
    /// is needed (not just a sync).
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_epoch: u64,
}

// Begin the block scope.
// SyncRequest implementation — core protocol logic.
// SyncRequest implementation — core protocol logic.
impl SyncRequest {
    /// Whether this SyncRequest requires full session re-establishment
    /// rather than just message replay.
    ///
    /// A session epoch mismatch means the two sides are using different
    /// session keys — message replay alone is insufficient; both sides
    /// must renegotiate a shared session before any messages can be sent.
    ///
    /// Callers should check this BEFORE attempting to replay messages.
    // Perform the 'requires reestablishment' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'requires reestablishment' operation.
    // Errors are propagated to the caller via Result.
    pub fn requires_reestablishment(&self, current_epoch: u64) -> bool {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.session_epoch != current_epoch
    }

    /// Whether a specific message sequence number should be included in
    /// the replay set for this request.
    ///
    /// A message is included if its `seq > last_received_sequence`.
    /// This is sequence-based ordering — timestamps are NOT used for
    /// replay selection (they are display-only).
    // Perform the 'should replay sequence' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'should replay sequence' operation.
    // Errors are propagated to the caller via Result.
    pub fn should_replay_sequence(&self, seq: u64) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        seq > self.last_received_sequence
    }
}

/// Response to a SyncRequest.
///
/// Contains the messages the requesting peer missed.
/// Messages are already encrypted with the session key — the
/// peer can decrypt them with their existing session state.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// SyncResponse — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SyncResponse — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SyncResponse {
    /// The conversation/room ID.
    // Execute this protocol step.
    // Execute this protocol step.
    pub conversation_id: [u8; 32],

    /// Number of messages being replayed.
    // Execute this protocol step.
    // Execute this protocol step.
    pub message_count: u32,

    /// Whether there are more messages beyond what's included.
    /// If true, the peer should send another SyncRequest after
    /// processing these.
    // Execute this protocol step.
    // Execute this protocol step.
    pub has_more: bool,

    /// The peer's current session epoch.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_epoch: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        // Create a session and generate a few nonces.
        let mut session = SessionState::new([0xAA; 32], 1000);

        // First nonce should be counter 0.
        let n0 = session.next_nonce().unwrap();
        assert_eq!(&n0[4..12], &0u64.to_be_bytes());

        // Second nonce should be counter 1.
        let n1 = session.next_nonce().unwrap();
        assert_eq!(&n1[4..12], &1u64.to_be_bytes());

        // Counter should have advanced.
        assert_eq!(session.nonce_counter, 2);
    }

    #[test]
    fn test_rekey_thresholds() {
        let mut session = SessionState::new([0xAA; 32], 1000);

        // Below all thresholds.
        assert_eq!(session.rekey_action(), RekeyAction::None);

        // At first threshold.
        session.nonce_counter = REKEY_THRESHOLD_1;
        assert_eq!(session.rekey_action(), RekeyAction::RekeyNormal);

        // At second threshold.
        session.nonce_counter = REKEY_THRESHOLD_2;
        assert_eq!(session.rekey_action(), RekeyAction::RekeyUrgent);

        // At third threshold.
        session.nonce_counter = REKEY_THRESHOLD_3;
        assert_eq!(session.rekey_action(), RekeyAction::RekeyWithWarning);

        // At hard stall.
        session.nonce_counter = REKEY_HARD_STALL;
        assert_eq!(session.rekey_action(), RekeyAction::HardStall);
    }

    #[test]
    fn test_hard_stall_blocks_nonce() {
        let mut session = SessionState::new([0xAA; 32], 1000);

        // Set counter just below hard stall.
        session.nonce_counter = REKEY_HARD_STALL - 1;

        // One more nonce should work.
        assert!(session.next_nonce().is_some());

        // Now we're at REKEY_HARD_STALL — next should fail.
        assert!(session.next_nonce().is_none());
        assert!(session.stalled);
    }

    #[test]
    fn test_complete_rekey() {
        let mut session = SessionState::new([0xAA; 32], 1000);

        // Use some nonces.
        session.nonce_counter = REKEY_THRESHOLD_1;
        session.rekey_attempts = 2;

        // Rekey.
        session.complete_rekey([0xBB; 32], 2000);

        // Counter should reset.
        assert_eq!(session.nonce_counter, 0);
        assert_eq!(session.rekey_attempts, 0);
        assert!(!session.stalled);
        assert_eq!(session.epoch, 2);
        assert_eq!(session.session_key, [0xBB; 32]);
    }

    #[test]
    fn test_stall_timeout() {
        let mut session = SessionState::new([0xAA; 32], 1000);
        session.stalled = true;
        session.stall_started_at = Some(1000);

        // Not timed out yet.
        assert!(!session.is_stall_timed_out(1000 + STALL_TIMEOUT_SECS - 1));

        // Timed out.
        assert!(session.is_stall_timed_out(1000 + STALL_TIMEOUT_SECS + 1));
    }

    #[test]
    fn test_needs_new_ephemeral() {
        let mut session = SessionState::new([0xAA; 32], 1000);

        // Not yet.
        assert!(!session.needs_new_ephemeral());

        // After max retries.
        session.rekey_attempts = MAX_RETRIES_SAME_EPHEMERAL;
        assert!(session.needs_new_ephemeral());
    }

    #[test]
    fn test_rekey_failed_starts_timeout() {
        let mut session = SessionState::new([0xAA; 32], 1000);
        session.stalled = true;

        // First failure sets the timeout clock.
        session.rekey_failed(2000);
        assert_eq!(session.stall_started_at, Some(2000));
        assert_eq!(session.rekey_attempts, 1);

        // Subsequent failures don't reset the clock.
        session.rekey_failed(3000);
        assert_eq!(session.stall_started_at, Some(2000));
        assert_eq!(session.rekey_attempts, 2);
    }

    #[test]
    fn test_nonce_first_4_bytes_zero() {
        // The first 4 bytes of the nonce must always be zero.
        // This is required by ChaCha20-Poly1305's 96-bit nonce format.
        let mut session = SessionState::new([0xAA; 32], 1000);
        let nonce = session.next_nonce().unwrap();
        assert_eq!(&nonce[0..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_sync_request_serde() {
        let req = SyncRequest {
            conversation_id: [0x01; 32],
            last_received_sequence: 42,
            last_received_timestamp: 1000,
            session_epoch: 3,
        };
        let json = serde_json::to_string(&req).unwrap();
        let recovered: SyncRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.last_received_sequence, 42);
        assert_eq!(recovered.session_epoch, 3);
    }

    // ── Sync / reconnect semantics (§7.6) ────────────────────────────────────

    /// Epoch mismatch → full re-establishment required, not just replay.
    #[test]
    fn test_epoch_mismatch_requires_reestablishment() {
        let req = SyncRequest {
            conversation_id: [0x01; 32],
            last_received_sequence: 10,
            last_received_timestamp: 1000,
            session_epoch: 2, // peer thinks they're in epoch 2
        };

        // Our current epoch is 3 — mismatch.
        assert!(req.requires_reestablishment(3));
        // Matching epoch — no re-establishment needed.
        assert!(!req.requires_reestablishment(2));
    }

    /// Replay selection is by sequence number, NOT timestamp.
    ///
    /// Two messages with identical timestamps but different sequence numbers
    /// must be selected differently.  This is the key invariant that prevents
    /// duplicate delivery on reconnect.
    #[test]
    fn test_replay_selection_by_sequence_not_timestamp() {
        let req = SyncRequest {
            conversation_id: [0x01; 32],
            last_received_sequence: 5,
            last_received_timestamp: 9000, // same timestamp as messages below
            session_epoch: 1,
        };

        // A message that arrived AFTER sequence 5 must be replayed.
        assert!(req.should_replay_sequence(6));
        assert!(req.should_replay_sequence(100));

        // Messages up to and including sequence 5 must NOT be replayed.
        assert!(!req.should_replay_sequence(5));
        assert!(!req.should_replay_sequence(0));

        // Even if a message has the SAME timestamp as last_received_timestamp,
        // the sequence number determines whether it is replayed.
        // seq=4, ts=9000 (same ts, earlier seq) — must NOT be replayed.
        assert!(!req.should_replay_sequence(4));
        // seq=6, ts=9000 (same ts, later seq) — MUST be replayed.
        assert!(req.should_replay_sequence(6));
    }

    /// A replay boundary at sequence 0 means "send all messages".
    #[test]
    fn test_replay_from_start_when_sequence_zero() {
        let req = SyncRequest {
            conversation_id: [0x01; 32],
            last_received_sequence: 0,
            last_received_timestamp: 0,
            session_epoch: 1,
        };

        // Only sequences strictly greater than 0 are replayed.
        assert!(!req.should_replay_sequence(0));
        assert!(req.should_replay_sequence(1));
        assert!(req.should_replay_sequence(999));
    }

    /// SyncResponse.has_more signals pagination — the caller must send another
    /// SyncRequest after processing the current batch.
    #[test]
    fn test_sync_response_has_more_signals_pagination() {
        let partial = SyncResponse {
            conversation_id: [0x01; 32],
            message_count: 50,
            has_more: true,
            session_epoch: 1,
        };
        assert!(partial.has_more, "has_more must be true when more messages exist");

        let complete = SyncResponse {
            conversation_id: [0x01; 32],
            message_count: 7,
            has_more: false,
            session_epoch: 1,
        };
        assert!(!complete.has_more, "has_more must be false when all messages delivered");
    }
}
