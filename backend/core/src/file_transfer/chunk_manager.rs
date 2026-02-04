use crate::core::error::Result;

pub struct ChunkManager {
    chunk_size: usize,
}

impl ChunkManager {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

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
