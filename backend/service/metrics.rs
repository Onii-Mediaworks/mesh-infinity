//! Service metrics and transfer-sync summaries.
//!
//! This module owns summary/reporting methods that derive runtime state views.

use super::{
    transfer_summary, FileTransferSummary, MeshInfinityService, NetworkStatsSummary,
    ReconnectSyncSnapshot,
};
use crate::core::error::Result;
use crate::core::file_transfer::TransferStatus;

impl MeshInfinityService {
    /// Return file transfers that can still be resumed.
    pub fn resumable_file_transfers(&self) -> Vec<FileTransferSummary> {
        let transfers = self.file_transfers.lock().unwrap().transfers();
        transfers
            .into_iter()
            .filter(|item| {
                matches!(
                    item.status,
                    TransferStatus::Queued | TransferStatus::InProgress | TransferStatus::Failed
                )
            })
            .map(|item| transfer_summary(&item))
            .collect()
    }

    /// Build reconnect snapshot containing missed messages and resumable work.
    pub fn reconnect_sync_snapshot(
        &self,
        room_id: &str,
        after_message_id: Option<&str>,
    ) -> Result<ReconnectSyncSnapshot> {
        Ok(ReconnectSyncSnapshot {
            missed_messages: self.sync_room_messages_since(room_id, after_message_id)?,
            resumable_transfers: self.resumable_file_transfers(),
        })
    }

    /// Return aggregate runtime network statistics.
    pub fn network_stats(&self) -> NetworkStatsSummary {
        let state = self.state.read().unwrap();
        let router_metrics = self.message_router.metrics();
        let manager = self.transport_manager.get_manager();
        let active_connections = self
            .peers
            .get_all_peers()
            .iter()
            .map(|peer| manager.active_connection_count(&super::peer_id_string(&peer.peer_id)))
            .sum();

        NetworkStatsSummary {
            bytes_sent: state.bytes_sent,
            bytes_received: state.bytes_received,
            active_connections,
            pending_routes: router_metrics.pending,
            delivered_routes: router_metrics.delivered,
            failed_routes: router_metrics.failed,
        }
    }
}
