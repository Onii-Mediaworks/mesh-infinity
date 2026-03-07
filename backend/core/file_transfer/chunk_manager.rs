//! Byte-slice chunking helper for file-transfer pipelines.
//!
//! Splits an input buffer into fixed-size chunk payloads while preserving order.

use crate::core::error::Result;

pub struct ChunkManager {
    chunk_size: usize,
}

impl ChunkManager {
    /// Create a chunk manager with the target chunk size in bytes.
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Split `data` into contiguous chunks of at most `self.chunk_size` bytes.
    ///
    /// Returned vectors keep original byte order and contain no overlap.
    pub fn chunk(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let end = usize::min(offset + self.chunk_size, data.len());
            chunks.push(data[offset..end].to_vec());
            offset = end;
        }
        Ok(chunks)
    }
}
