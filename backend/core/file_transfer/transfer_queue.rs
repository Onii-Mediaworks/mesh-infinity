//! FIFO transfer queue primitive used by file-transfer orchestration.
//!
//! This type wraps a [`VecDeque`] and provides a narrow queue API used by the
//! transfer manager to stage send/receive work in arrival order.

use std::collections::VecDeque;

use crate::core::error::Result;

pub struct TransferQueue<T> {
    queue: VecDeque<T>,
}

impl<T> Default for TransferQueue<T> {
    /// Build an empty transfer queue.
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TransferQueue<T> {
    /// Create a new empty FIFO queue.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    /// Push an item to the back of the queue.
    pub fn enqueue(&mut self, item: T) {
        self.queue.push_back(item);
    }

    /// Pop the oldest queued item, returning `Ok(None)` when empty.
    pub fn dequeue(&mut self) -> Result<Option<T>> {
        Ok(self.queue.pop_front())
    }

    /// Return a snapshot copy of queued items in current dequeue order.
    pub fn items(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.queue.iter().cloned().collect()
    }

    /// Retain only items for which `keep` returns `true`.
    ///
    /// Used by compaction/cleanup paths to remove canceled or stale entries.
    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.queue.retain(|item| keep(item));
    }
}
