//! File-transfer state machine and queue orchestration.
//!
//! Tracks transfer lifecycle (queued → in-progress → terminal states), progress
//! updates, bounded completed-history retention, queue compaction, and payload
//! chunking support.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::SystemTime;

use ring::rand::{SecureRandom, SystemRandom};

use crate::core::error::{MeshInfinityError, Result};
use crate::core::{FileId, PeerId};

use super::{ChunkManager, TransferQueue};

#[derive(Clone, Debug)]
pub struct FileMetadata {
    pub name: String,
    pub size_bytes: u64,
    pub mime: Option<String>,
    pub checksum_crc32: Option<u32>,
}

impl FileMetadata {
    /// Build file metadata with required name and size fields.
    pub fn new(name: &str, size_bytes: u64) -> Self {
        Self {
            name: name.to_string(),
            size_bytes,
            mime: None,
            checksum_crc32: None,
        }
    }

    /// Compute and attach CRC32 checksum from full file payload bytes.
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
    /// Initialize progress counters for a new transfer.
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
    completed_history: VecDeque<FileId>,
    max_completed_history: usize,
    rng: SystemRandom,
}

impl FileTransferManager {
    /// Create transfer manager with configured chunk size.
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_manager: ChunkManager::new(chunk_size),
            queue: TransferQueue::new(),
            transfers: HashMap::new(),
            completed_history: VecDeque::new(),
            max_completed_history: 1024,
            rng: SystemRandom::new(),
        }
    }

    /// Set max number of completed transfer ids retained in history.
    pub fn set_max_completed_history(&mut self, max: usize) {
        self.max_completed_history = max.max(1);
        while self.completed_history.len() > self.max_completed_history {
            self.completed_history.pop_front();
        }
    }

    /// Return completed-transfer ids in completion order (oldest → newest).
    pub fn recent_completed_transfers(&self) -> Vec<FileId> {
        self.completed_history.iter().copied().collect()
    }

    /// Compact queue/history/transfer map by removing canceled/stale entries.
    ///
    /// Returns number of records removed across managed collections.
    pub fn compact(&mut self) -> usize {
        let mut removed = 0usize;

        let active_set: HashSet<FileId> = self.queue.items().into_iter().collect();
        self.queue.retain(|id| {
            self.transfers
                .get(id)
                .map(|item| item.status != TransferStatus::Canceled)
                .unwrap_or(false)
        });
        removed = removed.saturating_add(active_set.len().saturating_sub(self.queue.items().len()));

        let mut live_ids: Vec<FileId> = self.queue.items();
        live_ids.extend(
            self.transfers
                .iter()
                .filter(|(_, item)| matches!(item.status, TransferStatus::InProgress))
                .map(|(id, _)| *id),
        );
        let live_set: HashSet<FileId> = live_ids.into_iter().collect();

        let before_hist = self.completed_history.len();
        self.completed_history
            .retain(|id| self.transfers.contains_key(id));
        removed = removed.saturating_add(before_hist.saturating_sub(self.completed_history.len()));

        let keep_completed: HashSet<FileId> = self.completed_history.iter().copied().collect();
        let before_transfers = self.transfers.len();
        self.transfers.retain(|id, item| {
            if live_set.contains(id) {
                return true;
            }

            match item.status {
                TransferStatus::Queued | TransferStatus::InProgress | TransferStatus::Failed => {
                    true
                }
                TransferStatus::Completed => keep_completed.contains(id),
                TransferStatus::Canceled => false,
            }
        });
        removed = removed.saturating_add(before_transfers.saturating_sub(self.transfers.len()));

        removed
    }

    /// Queue an outbound transfer for sending to `peer_id`.
    pub fn enqueue_send(&mut self, peer_id: PeerId, metadata: FileMetadata) -> Result<FileId> {
        self.enqueue_transfer(peer_id, metadata, TransferDirection::Send)
    }

    /// Queue an inbound transfer expected from `peer_id`.
    pub fn enqueue_receive(&mut self, peer_id: PeerId, metadata: FileMetadata) -> Result<FileId> {
        self.enqueue_transfer(peer_id, metadata, TransferDirection::Receive)
    }

    /// Pop next queued transfer and transition it to `InProgress`.
    pub fn next_queued(&mut self) -> Result<Option<TransferItem>> {
        if let Some(id) = self.queue.dequeue()? {
            let transfer = self.transfers.get_mut(&id).ok_or_else(|| {
                MeshInfinityError::FileTransferError("queue item missing".to_string())
            })?;
            transfer.status = TransferStatus::InProgress;
            if transfer.progress.started_at.is_none() {
                transfer.progress.started_at = Some(SystemTime::now());
            }
            transfer.progress.updated_at = SystemTime::now();
            return Ok(Some(transfer.clone()));
        }

        Ok(None)
    }

    /// Advance transfer progress by `bytes`, clamping to total size.
    ///
    /// Automatically marks transfer completed once transferred bytes reach total.
    pub fn update_progress(&mut self, id: &FileId, bytes: u64) -> Result<TransferProgress> {
        let transfer = self.transfers.get_mut(id).ok_or_else(|| {
            MeshInfinityError::FileTransferError("transfer not found".to_string())
        })?;

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
        let just_completed = transfer.progress.transferred_bytes >= transfer.progress.total_bytes;
        transfer.status = if just_completed {
            TransferStatus::Completed
        } else {
            TransferStatus::InProgress
        };

        if just_completed {
            self.completed_history.push_back(*id);
            while self.completed_history.len() > self.max_completed_history {
                self.completed_history.pop_front();
            }
        }

        Ok(transfer.progress.clone())
    }

    /// Mark transfer as completed and record id in bounded history.
    pub fn complete(&mut self, id: &FileId) -> Result<()> {
        let transfer = self.transfers.get_mut(id).ok_or_else(|| {
            MeshInfinityError::FileTransferError("transfer not found".to_string())
        })?;
        transfer.progress.transferred_bytes = transfer.progress.total_bytes;
        transfer.progress.updated_at = SystemTime::now();
        transfer.status = TransferStatus::Completed;
        self.completed_history.push_back(*id);
        while self.completed_history.len() > self.max_completed_history {
            self.completed_history.pop_front();
        }
        Ok(())
    }

    /// Mark transfer as failed with an error reason.
    pub fn fail(&mut self, id: &FileId, reason: &str) -> Result<()> {
        let transfer = self.transfers.get_mut(id).ok_or_else(|| {
            MeshInfinityError::FileTransferError("transfer not found".to_string())
        })?;
        transfer.status = TransferStatus::Failed;
        transfer.progress.updated_at = SystemTime::now();
        transfer.last_error = Some(reason.to_string());
        Ok(())
    }

    /// Mark transfer as canceled.
    pub fn cancel(&mut self, id: &FileId) -> Result<()> {
        let transfer = self.transfers.get_mut(id).ok_or_else(|| {
            MeshInfinityError::FileTransferError("transfer not found".to_string())
        })?;
        transfer.status = TransferStatus::Canceled;
        transfer.progress.updated_at = SystemTime::now();
        Ok(())
    }

    /// Return transfer snapshot for id if present.
    pub fn transfer(&self, id: &FileId) -> Option<TransferItem> {
        self.transfers.get(id).cloned()
    }

    /// Return snapshot of all tracked transfers.
    pub fn transfers(&self) -> Vec<TransferItem> {
        self.transfers.values().cloned().collect()
    }

    /// Chunk a payload using manager-configured chunk size.
    pub fn chunk_payload(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.chunk_manager.chunk(data)
    }

    /// Internal helper shared by send/receive enqueue paths.
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

/// Generate random 32-byte transfer id.
fn random_file_id(rng: &SystemRandom) -> Result<FileId> {
    let mut id = [0u8; 32];
    rng.fill(&mut id).map_err(|_| {
        MeshInfinityError::FileTransferError("file id generation failed".to_string())
    })?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test peer-id helper.
    fn peer(seed: u8) -> PeerId {
        let mut out = [0u8; 32];
        out[0] = seed;
        out
    }

    /// Compaction should purge canceled transfers from manager state.
    #[test]
    fn compact_removes_canceled_transfers() {
        let mut manager = FileTransferManager::new(4096);
        let id = manager
            .enqueue_send(peer(1), FileMetadata::new("x.bin", 10))
            .expect("enqueue");
        manager.cancel(&id).expect("cancel");

        let removed = manager.compact();
        assert!(removed >= 1);
        assert!(manager.transfer(&id).is_none());
    }

    /// Completed-history list should remain bounded and keep newest entries.
    #[test]
    fn completed_history_is_bounded_and_retained() {
        let mut manager = FileTransferManager::new(4096);
        manager.set_max_completed_history(2);

        let id1 = manager
            .enqueue_send(peer(1), FileMetadata::new("a.bin", 1))
            .expect("enqueue1");
        let id2 = manager
            .enqueue_send(peer(1), FileMetadata::new("b.bin", 1))
            .expect("enqueue2");
        let id3 = manager
            .enqueue_send(peer(1), FileMetadata::new("c.bin", 1))
            .expect("enqueue3");

        manager.complete(&id1).expect("complete1");
        manager.complete(&id2).expect("complete2");
        manager.complete(&id3).expect("complete3");

        let recent = manager.recent_completed_transfers();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0], id2);
        assert_eq!(recent[1], id3);
    }
}
