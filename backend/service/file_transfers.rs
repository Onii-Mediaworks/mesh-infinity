//! File-transfer lifecycle and progress operations.
//!
//! This module owns queueing, progress updates, cancellation, and summary views
//! for transfer records managed by the backend transfer manager.

use crate::core::error::{MeshInfinityError, Result};
use crate::core::file_transfer::FileMetadata;

use super::{
    file_id_from_string, file_id_string, peer_id_from_pairing_code, transfer_summary,
    FileTransferSummary, MeshInfinityService,
};

impl MeshInfinityService {
    /// Return snapshot of all tracked file-transfer summaries.
    pub fn file_transfers(&self) -> Vec<FileTransferSummary> {
        let transfers = self.file_transfers.lock().unwrap().transfers();
        transfers
            .into_iter()
            .map(|item| transfer_summary(&item))
            .collect()
    }

    /// Look up one file transfer by id.
    pub fn file_transfer(&self, transfer_id: &str) -> Option<FileTransferSummary> {
        let file_id = file_id_from_string(transfer_id)?;
        self.file_transfers
            .lock()
            .unwrap()
            .transfer(&file_id)
            .map(|item| transfer_summary(&item))
    }

    /// Queue a new outbound file transfer toward `peer_id`.
    pub fn queue_file_send(&self, peer_id: &str, name: &str, size_bytes: u64) -> Result<String> {
        let peer_id = peer_id_from_pairing_code(peer_id).ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("invalid peer id".to_string())
        })?;
        let metadata = FileMetadata::new(name, size_bytes);
        let mut manager = self.file_transfers.lock().unwrap();
        let id = manager.enqueue_send(peer_id, metadata)?;
        Ok(file_id_string(&id))
    }

    /// Queue a new inbound file transfer expectation from `peer_id`.
    pub fn queue_file_receive(&self, peer_id: &str, name: &str, size_bytes: u64) -> Result<String> {
        let peer_id = peer_id_from_pairing_code(peer_id).ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("invalid peer id".to_string())
        })?;
        let metadata = FileMetadata::new(name, size_bytes);
        let mut manager = self.file_transfers.lock().unwrap();
        let id = manager.enqueue_receive(peer_id, metadata)?;
        Ok(file_id_string(&id))
    }

    /// Pop next queued transfer and move it into active progress state.
    pub fn next_file_transfer(&self) -> Result<Option<FileTransferSummary>> {
        let mut manager = self.file_transfers.lock().unwrap();
        manager
            .next_queued()
            .map(|item| item.map(|item| transfer_summary(&item)))
    }

    /// Compact internal transfer manager state and return removed entry count.
    pub fn compact_file_transfers(&self) -> usize {
        self.file_transfers.lock().unwrap().compact()
    }

    /// Cancel transfer by id and return updated transfer snapshot.
    pub fn cancel_file_transfer(&self, transfer_id: &str) -> Result<FileTransferSummary> {
        let file_id = file_id_from_string(transfer_id).ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("invalid file id".to_string())
        })?;

        let mut manager = self.file_transfers.lock().unwrap();
        manager.cancel(&file_id)?;
        let item = manager.transfer(&file_id).ok_or_else(|| {
            MeshInfinityError::FileTransferError("transfer not found".to_string())
        })?;
        let summary = transfer_summary(&item);

        self.notify_transfer_listeners(&summary);
        Ok(summary)
    }

    /// Increment transfer progress and return updated progress snapshot.
    pub fn update_file_transfer_progress(
        &self,
        transfer_id: &str,
        bytes: u64,
    ) -> Result<FileTransferSummary> {
        let file_id = file_id_from_string(transfer_id).ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("invalid file id".to_string())
        })?;
        let mut manager = self.file_transfers.lock().unwrap();
        manager.update_progress(&file_id, bytes)?;
        let item = manager.transfer(&file_id).ok_or_else(|| {
            MeshInfinityError::FileTransferError("transfer not found".to_string())
        })?;
        let summary = transfer_summary(&item);

        self.notify_transfer_listeners(&summary);

        Ok(summary)
    }
}
