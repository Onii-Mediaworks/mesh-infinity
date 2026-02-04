use std::collections::HashMap;
use std::time::SystemTime;

use ring::rand::{SecureRandom, SystemRandom};

use crate::core::{FileId, PeerId};
use crate::core::error::{MeshInfinityError, Result};

use super::{ChunkManager, TransferQueue};

#[derive(Clone, Debug)]
pub struct FileMetadata {
    pub name: String,
    pub size_bytes: u64,
    pub mime: Option<String>,
    pub checksum_crc32: Option<u32>,
}

impl FileMetadata {
    pub fn new(name: &str, size_bytes: u64) -> Self {
        Self {
            name: name.to_string(),
            size_bytes,
            mime: None,
            checksum_crc32: None,
        }
    }

    pub fn with_checksum(mut self, data: &[u8]) -> Self {
        self.checksum_crc32 = Some(crc32fast::hash(data));
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferDirection {
    Send,
    Receive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferStatus {
    Queued,
    InProgress,
    Completed,
    Failed,
    Canceled,
}

#[derive(Clone, Debug)]
pub struct TransferProgress {
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub started_at: Option<SystemTime>,
    pub updated_at: SystemTime,
}

impl TransferProgress {
    fn new(total_bytes: u64) -> Self {
        let now = SystemTime::now();
        Self {
            total_bytes,
            transferred_bytes: 0,
            started_at: None,
            updated_at: now,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransferItem {
    pub id: FileId,
    pub peer_id: PeerId,
    pub metadata: FileMetadata,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub progress: TransferProgress,
    pub last_error: Option<String>,
}

pub struct FileTransferManager {
    chunk_manager: ChunkManager,
    queue: TransferQueue<FileId>,
    transfers: HashMap<FileId, TransferItem>,
    rng: SystemRandom,
}

impl FileTransferManager {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_manager: ChunkManager::new(chunk_size),
            queue: TransferQueue::new(),
            transfers: HashMap::new(),
            rng: SystemRandom::new(),
        }
    }

    pub fn enqueue_send(&mut self, peer_id: PeerId, metadata: FileMetadata) -> Result<FileId> {
        self.enqueue_transfer(peer_id, metadata, TransferDirection::Send)
    }

    pub fn enqueue_receive(&mut self, peer_id: PeerId, metadata: FileMetadata) -> Result<FileId> {
        self.enqueue_transfer(peer_id, metadata, TransferDirection::Receive)
    }

    pub fn next_queued(&mut self) -> Result<Option<TransferItem>> {
        if let Some(id) = self.queue.dequeue()? {
            let transfer = self
                .transfers
                .get_mut(&id)
                .ok_or_else(|| MeshInfinityError::FileTransferError("queue item missing".to_string()))?;
            transfer.status = TransferStatus::InProgress;
            if transfer.progress.started_at.is_none() {
                transfer.progress.started_at = Some(SystemTime::now());
            }
            transfer.progress.updated_at = SystemTime::now();
            return Ok(Some(transfer.clone()));
        }

        Ok(None)
    }

    pub fn update_progress(&mut self, id: &FileId, bytes: u64) -> Result<TransferProgress> {
        let transfer = self
            .transfers
            .get_mut(id)
            .ok_or_else(|| MeshInfinityError::FileTransferError("transfer not found".to_string()))?;

        let now = SystemTime::now();
        if transfer.progress.started_at.is_none() {
            transfer.progress.started_at = Some(now);
        }
        transfer.progress.transferred_bytes = transfer
            .progress
            .transferred_bytes
            .saturating_add(bytes)
            .min(transfer.progress.total_bytes);
        transfer.progress.updated_at = now;
        transfer.status = if transfer.progress.transferred_bytes >= transfer.progress.total_bytes {
            TransferStatus::Completed
        } else {
            TransferStatus::InProgress
        };

        Ok(transfer.progress.clone())
    }

    pub fn complete(&mut self, id: &FileId) -> Result<()> {
        let transfer = self
            .transfers
            .get_mut(id)
            .ok_or_else(|| MeshInfinityError::FileTransferError("transfer not found".to_string()))?;
        transfer.progress.transferred_bytes = transfer.progress.total_bytes;
        transfer.progress.updated_at = SystemTime::now();
        transfer.status = TransferStatus::Completed;
        Ok(())
    }

    pub fn fail(&mut self, id: &FileId, reason: &str) -> Result<()> {
        let transfer = self
            .transfers
            .get_mut(id)
            .ok_or_else(|| MeshInfinityError::FileTransferError("transfer not found".to_string()))?;
        transfer.status = TransferStatus::Failed;
        transfer.progress.updated_at = SystemTime::now();
        transfer.last_error = Some(reason.to_string());
        Ok(())
    }

    pub fn cancel(&mut self, id: &FileId) -> Result<()> {
        let transfer = self
            .transfers
            .get_mut(id)
            .ok_or_else(|| MeshInfinityError::FileTransferError("transfer not found".to_string()))?;
        transfer.status = TransferStatus::Canceled;
        transfer.progress.updated_at = SystemTime::now();
        Ok(())
    }

    pub fn transfer(&self, id: &FileId) -> Option<TransferItem> {
        self.transfers.get(id).cloned()
    }

    pub fn transfers(&self) -> Vec<TransferItem> {
        self.transfers.values().cloned().collect()
    }

    pub fn chunk_payload(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.chunk_manager.chunk(data)
    }

    fn enqueue_transfer(
        &mut self,
        peer_id: PeerId,
        metadata: FileMetadata,
        direction: TransferDirection,
    ) -> Result<FileId> {
        let id = random_file_id(&self.rng)?;
        let transfer = TransferItem {
            id,
            peer_id,
            direction,
            status: TransferStatus::Queued,
            progress: TransferProgress::new(metadata.size_bytes),
            metadata,
            last_error: None,
        };
        self.transfers.insert(id, transfer);
        self.queue.enqueue(id);
        Ok(id)
    }
}

fn random_file_id(rng: &SystemRandom) -> Result<FileId> {
    let mut id = [0u8; 32];
    rng.fill(&mut id)
        .map_err(|_| MeshInfinityError::FileTransferError("file id generation failed".to_string()))?;
    Ok(id)
}
