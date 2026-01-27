use std::collections::VecDeque;

use crate::error::Result;

pub struct TransferQueue<T> {
    queue: VecDeque<T>,
}

impl<T> TransferQueue<T> {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    pub fn enqueue(&mut self, item: T) {
        self.queue.push_back(item);
    }

    pub fn dequeue(&mut self) -> Result<Option<T>> {
        Ok(self.queue.pop_front())
    }
}
