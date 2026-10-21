//! Shared deterministic arbitrary-data helpers for fuzzing and simulator tests.
//!
//! The purpose of this module is to decode fuzz bytes into bounded values and
//! action sequences without ad hoc parsing logic in every harness.

use crate::routing::store_forward::{Priority, ReleaseCondition, StoreAndForwardRequest};
use crate::routing::table::DeviceAddress;

/// A deterministic cursor over arbitrary bytes.
///
/// The cursor never panics on short input. Missing bytes degrade to zero-like
/// values so the caller can keep decoding bounded structures.
#[derive(Debug, Clone, Copy)]
pub struct ByteCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    /// Create a new cursor over arbitrary bytes.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Consume one byte, or zero if the input is exhausted.
    pub fn take_u8(&mut self) -> u8 {
        let value = self.data.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        value
    }

    /// Consume one boolean bit.
    pub fn take_bool(&mut self) -> bool {
        self.take_u8() & 1 == 1
    }

    /// Consume a bounded usize value.
    pub fn take_bounded_usize(&mut self, max_inclusive: usize) -> usize {
        if max_inclusive == 0 {
            return 0;
        }
        usize::from(self.take_u8()) % (max_inclusive + 1)
    }

    /// Consume up to `max_len` bytes.
    pub fn take_bytes(&mut self, max_len: usize) -> &'a [u8] {
        // Read `wanted` first (consumes one byte from the cursor).
        let wanted = self.take_bounded_usize(max_len);
        // Recompute remaining AFTER take_bounded_usize has advanced the offset.
        let remaining = self.data.len().saturating_sub(self.offset);
        let take = wanted.min(remaining);
        let start = self.offset;
        let end = start + take;
        self.offset = end;
        &self.data[start..end]
    }

    /// Consume eight bytes as a little-endian u64 (zero-padded when short).
    pub fn take_u64_le(&mut self) -> u64 {
        let mut raw = [0u8; 8];
        for b in raw.iter_mut() {
            *b = self.take_u8();
        }
        u64::from_le_bytes(raw)
    }
}

// ---------------------------------------------------------------------------
// Store-and-forward deposit case (§6.8)
// ---------------------------------------------------------------------------

/// One decoded store-and-forward deposit attempt.
///
/// Shared by `fuzz_store_forward` and the in-tree corpus replay test so the
/// committed seeds are decoded by exactly one layout.
#[derive(Debug)]
pub struct StoreForwardCase {
    /// The deposit request built from the fuzz bytes.
    pub request: StoreAndForwardRequest,
    /// Inbound tunnel id used for rate limiting.
    pub tunnel_id: u64,
    /// The relay's notion of "now" for expiry checks.
    pub now: u64,
}

/// Decode a `StoreForwardCase` from arbitrary bytes.
///
/// Layout (all fields degrade to zero when the input runs out):
///   32 bytes destination address,
///   1 byte payload length (bounded to 4096) + payload bytes,
///   8 bytes expiry (LE), 8 bytes now (LE),
///   1 byte signature length (bounded to 128) + signature bytes,
///   1 byte priority selector, 8 bytes tunnel id (LE).
pub fn store_forward_case(data: &[u8]) -> StoreForwardCase {
    let mut cur = ByteCursor::new(data);

    // Destination address from fuzz bytes.
    let mut dest_bytes = [0u8; 32];
    for b in dest_bytes.iter_mut() {
        *b = cur.take_u8();
    }
    let destination = DeviceAddress(dest_bytes);

    // Fuzz-controlled payload (may be empty — that is a tracked negative case).
    let payload_len = cur.take_bounded_usize(4096);
    let payload: Vec<u8> = (0..payload_len).map(|_| cur.take_u8()).collect();

    // Fuzz-controlled expiry and relay clock.
    let expiry = cur.take_u64_le();
    let now = cur.take_u64_le();

    // Fuzz-controlled expiry signature (arbitrary bytes — usually invalid).
    let sig_len = cur.take_bounded_usize(128);
    let expiry_sig: Vec<u8> = (0..sig_len).map(|_| cur.take_u8()).collect();

    // Priority from one selector byte.
    let priority = match cur.take_u8() % 3 {
        0 => Priority::Low,
        1 => Priority::Normal,
        _ => Priority::Critical,
    };

    // Tunnel id last so the earlier fields keep their offsets stable.
    let tunnel_id = cur.take_u64_le();

    StoreForwardCase {
        request: StoreAndForwardRequest {
            destination,
            payload,
            expiry,
            expiry_sig,
            priority,
            cancellation_pubkey: None,
            release_condition: ReleaseCondition::Immediate,
            application_id: None,
        },
        tunnel_id,
        now,
    }
}
