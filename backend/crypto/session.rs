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
pub const REKEY_THRESHOLD_1: u64 = 1 << 44;

/// Second rekey attempt threshold.
/// If the first attempt failed (peer unresponsive), try again at 2^46.
pub const REKEY_THRESHOLD_2: u64 = 1 << 46;

/// Third rekey attempt with UI warning.
/// The user is warned that the session is at risk.
pub const REKEY_THRESHOLD_3: u64 = 1 << 47;

/// Hard stall threshold.
/// NO more data is sent until rekeying completes.
/// Sending at this nonce would risk nonce reuse.
pub const REKEY_HARD_STALL: u64 = 1 << 48;

/// Stall timeout before the session is dropped (seconds).
/// If rekeying hasn't completed within 30 seconds of hard stall,
/// the session is torn down.
pub const STALL_TIMEOUT_SECS: u64 = 30;

/// Maximum retries with the same ephemeral key.
/// After 3 failed rekey attempts with the same ephemeral, generate
/// a new ephemeral keypair.
pub const MAX_RETRIES_SAME_EPHEMERAL: u32 = 3;

/// How long to retain an ephemeral key after last transmission (seconds).
/// The ephemeral is kept briefly in case the peer needs it for
/// late-arriving messages, then zeroized.
pub const EPHEMERAL_RETENTION_SECS: u64 = 60;

/// Domain separator for session key derivation via HKDF.
/// Included in the `info` parameter to prevent cross-protocol
/// key reuse.
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
pub struct SessionState {
    /// The current session key (32 bytes, ChaCha20-Poly1305).
    /// Zeroized on Drop in a real implementation.
    pub session_key: [u8; 32],

    /// Monotonically incrementing nonce counter.
    /// Each encrypt operation increments this by 1.
    /// When it hits REKEY_THRESHOLD_1, rekeying begins.
    pub nonce_counter: u64,

    /// How many rekey attempts have been made at the current
    /// threshold level. Resets to 0 after a successful rekey.
    pub rekey_attempts: u32,

    /// Whether the session is currently stalled (nonce at REKEY_HARD_STALL).
    /// No data can be sent until rekeying completes.
    pub stalled: bool,

    /// Unix timestamp when the stall began (for timeout tracking).
    pub stall_started_at: Option<u64>,

    /// Session epoch — incremented on each successful rekey.
    /// Allows the peer to detect that we've rekeyed.
    pub epoch: u64,

    /// When this session was established.
    pub established_at: u64,
}

impl SessionState {
    /// Create a new session state with a freshly derived key.
    ///
    /// `session_key`: the 32-byte key from HKDF.
    /// `now`: current unix timestamp.
    pub fn new(session_key: [u8; 32], now: u64) -> Self {
        Self {
            session_key,
            nonce_counter: 0,
            rekey_attempts: 0,
            stalled: false,
            stall_started_at: None,
            epoch: 1,
            established_at: now,
        }
    }

    /// Get the next nonce for encryption.
    ///
    /// Returns a 12-byte nonce (4 zero bytes + 8-byte counter).
    /// Returns None if the session is stalled (must rekey first).
    pub fn next_nonce(&mut self) -> Option<[u8; 12]> {
        // Check if we're stalled — no more data allowed.
        if self.stalled {
            return None;
        }

        // Check if we've hit the hard stall.
        if self.nonce_counter >= REKEY_HARD_STALL {
            self.stalled = true;
            return None;
        }

        // Build the 12-byte nonce.
        // First 4 bytes: zero (to fill ChaCha20-Poly1305's 96-bit nonce).
        // Last 8 bytes: counter in big-endian.
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.nonce_counter.to_be_bytes());

        // Increment the counter.
        self.nonce_counter += 1;

        Some(nonce)
    }

    /// Check which rekey action is needed (if any).
    ///
    /// Called after each encrypt operation to determine if
    /// rekeying should be initiated.
    pub fn rekey_action(&self) -> RekeyAction {
        if self.nonce_counter >= REKEY_HARD_STALL {
            RekeyAction::HardStall
        } else if self.nonce_counter >= REKEY_THRESHOLD_3 {
            RekeyAction::RekeyWithWarning
        } else if self.nonce_counter >= REKEY_THRESHOLD_2 {
            RekeyAction::RekeyUrgent
        } else if self.nonce_counter >= REKEY_THRESHOLD_1 {
            RekeyAction::RekeyNormal
        } else {
            RekeyAction::None
        }
    }

    /// Complete a rekey by installing a new session key.
    ///
    /// Zeroizes the old key (caller must ensure this happens
    /// in the real implementation) and resets counters.
    pub fn complete_rekey(&mut self, new_key: [u8; 32], _now: u64) {
        // In a real implementation, the old key would be zeroized
        // via the SecureBytes wrapper. For now, overwrite with zeros.
        self.session_key = [0u8; 32];

        // Install the new key and reset state.
        self.session_key = new_key;
        self.nonce_counter = 0;
        self.rekey_attempts = 0;
        self.stalled = false;
        self.stall_started_at = None;
        self.epoch += 1;
    }

    /// Record a failed rekey attempt.
    pub fn rekey_failed(&mut self, now: u64) {
        self.rekey_attempts += 1;

        // If we're at the hard stall, start the timeout clock.
        if self.stalled && self.stall_started_at.is_none() {
            self.stall_started_at = Some(now);
        }
    }

    /// Whether the stall timeout has been exceeded.
    ///
    /// If the session has been stalled for longer than
    /// STALL_TIMEOUT_SECS, the session should be dropped.
    pub fn is_stall_timed_out(&self, now: u64) -> bool {
        if let Some(stall_start) = self.stall_started_at {
            now.saturating_sub(stall_start) > STALL_TIMEOUT_SECS
        } else {
            false
        }
    }

    /// Whether a new ephemeral key should be generated.
    ///
    /// After MAX_RETRIES_SAME_EPHEMERAL failed attempts, the
    /// ephemeral keypair should be regenerated.
    pub fn needs_new_ephemeral(&self) -> bool {
        self.rekey_attempts >= MAX_RETRIES_SAME_EPHEMERAL
    }
}

/// What rekey action is needed at the current nonce counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RekeyAction {
    /// No action needed — counter is well below all thresholds.
    None,
    /// Normal rekey — first threshold reached.
    RekeyNormal,
    /// Urgent rekey — second threshold reached.
    RekeyUrgent,
    /// Rekey with UI warning — third threshold reached.
    RekeyWithWarning,
    /// Hard stall — no more data until rekeyed.
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
pub struct SessionProposal {
    /// The sender's ephemeral X25519 public key for this session.
    pub ephemeral_public: [u8; 32],

    /// A fresh random nonce used as the HKDF salt.
    /// Both parties use this to derive the same session key.
    pub handshake_nonce: [u8; 32],

    /// The session epoch being proposed.
    /// For initial establishment: 1.
    /// For rekeying: current_epoch + 1.
    pub proposed_epoch: u64,

    /// Unix timestamp.
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
pub struct SyncRequest {
    /// The conversation/room ID this sync is for.
    pub conversation_id: [u8; 32],

    /// The sequence number of the last message we received.
    /// The peer should send all messages with sequence > this.
    pub last_received_sequence: u64,

    /// The timestamp of the last message we received.
    /// Used as a fallback if the peer doesn't track sequence numbers
    /// (e.g., an older version).
    pub last_received_timestamp: u64,

    /// Our current session epoch.
    /// If it doesn't match the peer's, a full session re-establishment
    /// is needed (not just a sync).
    pub session_epoch: u64,
}

impl SyncRequest {
    /// Whether this SyncRequest requires full session re-establishment
    /// rather than just message replay.
    ///
    /// A session epoch mismatch means the two sides are using different
    /// session keys — message replay alone is insufficient; both sides
    /// must renegotiate a shared session before any messages can be sent.
    ///
    /// Callers should check this BEFORE attempting to replay messages.
    pub fn requires_reestablishment(&self, current_epoch: u64) -> bool {
        self.session_epoch != current_epoch
    }

    /// Whether a specific message sequence number should be included in
    /// the replay set for this request.
    ///
    /// A message is included if its `seq > last_received_sequence`.
    /// This is sequence-based ordering — timestamps are NOT used for
    /// replay selection (they are display-only).
    pub fn should_replay_sequence(&self, seq: u64) -> bool {
        seq > self.last_received_sequence
    }
}

/// Response to a SyncRequest.
///
/// Contains the messages the requesting peer missed.
/// Messages are already encrypted with the session key — the
/// peer can decrypt them with their existing session state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    /// The conversation/room ID.
    pub conversation_id: [u8; 32],

    /// Number of messages being replayed.
    pub message_count: u32,

    /// Whether there are more messages beyond what's included.
    /// If true, the peer should send another SyncRequest after
    /// processing these.
    pub has_more: bool,

    /// The peer's current session epoch.
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
