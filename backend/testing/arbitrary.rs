//! Shared deterministic arbitrary-data helpers for fuzzing and simulator tests.
//!
//! The purpose of this module is to decode fuzz bytes into bounded values and
//! action sequences without ad hoc parsing logic in every harness.

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
        let remaining = self.data.len().saturating_sub(self.offset);
        let wanted = self.take_bounded_usize(max_len);
        let take = wanted.min(remaining);
        let start = self.offset;
        let end = start + take;
        self.offset = end;
        &self.data[start..end]
    }
}
