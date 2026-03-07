//! Discovery-facing service operations.
//!
//! This module encapsulates mDNS lifecycle control and conversion of discovered
//! peers into UI/service summary structures.

use crate::core::error::{MeshInfinityError, Result};

use super::{peer_id_string, trust_label, MeshInfinityService, PeerSummary};

impl MeshInfinityService {
    /// Start mDNS discovery on specified port.
    pub fn enable_mdns(&self, port: u16) -> Result<()> {
        let peer_id = self
            .identity_manager
            .get_primary_identity()
            .map(|id| id.peer_id)
            .ok_or_else(|| MeshInfinityError::AuthError("No identity available".to_string()))?;

        let mut discovery = self
            .discovery
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Discovery lock poisoned: {}", e)))?;

        discovery.enable_mdns(peer_id, port)?;

        // Keep user-facing settings in sync with active discovery state.
        self.set_mesh_discovery(true);

        Ok(())
    }

    /// Stop mDNS discovery service.
    pub fn disable_mdns(&self) -> Result<()> {
        let mut discovery = self
            .discovery
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Discovery lock poisoned: {}", e)))?;

        discovery.disable_mdns()?;
        self.set_mesh_discovery(false);

        Ok(())
    }

    /// Report whether mDNS discovery is currently running.
    pub fn is_mdns_running(&self) -> bool {
        self.discovery
            .lock()
            .map(|d| d.is_mdns_running())
            .unwrap_or(false)
    }

    /// Return discovered peers as UI-facing summaries.
    pub fn get_discovered_peers(&self) -> Result<Vec<PeerSummary>> {
        let mut discovery = self
            .discovery
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Discovery lock poisoned: {}", e)))?;

        let peers = discovery.refresh()?;
        let summaries: Vec<PeerSummary> = peers
            .iter()
            .map(|peer| {
                let short_code: String = peer_id_string(&peer.peer_id).chars().take(6).collect();
                PeerSummary {
                    id: peer_id_string(&peer.peer_id),
                    name: format!("Peer {}", short_code),
                    trust_level: peer.trust_level as i32,
                    status: trust_label(peer.trust_level),
                }
            })
            .collect();

        Ok(summaries)
    }

    /// Return DHT-nearest discovered peers relative to local identity.
    pub fn get_nearest_discovered_peers(&self, limit: usize) -> Result<Vec<PeerSummary>> {
        let local_peer_id = self
            .identity_manager
            .get_primary_identity()
            .map(|id| id.peer_id)
            .ok_or_else(|| MeshInfinityError::AuthError("No identity available".to_string()))?;

        let discovery = self
            .discovery
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Discovery lock poisoned: {}", e)))?;

        let peers = discovery.nearest_peers(&local_peer_id, limit);
        let summaries = peers
            .iter()
            .map(|peer| {
                let short_code: String = peer_id_string(&peer.peer_id).chars().take(6).collect();
                PeerSummary {
                    id: peer_id_string(&peer.peer_id),
                    name: format!("Peer {}", short_code),
                    trust_level: peer.trust_level as i32,
                    status: trust_label(peer.trust_level),
                }
            })
            .collect();

        Ok(summaries)
    }

    /// Export a jumpstart payload that can be shared out-of-band.
    pub fn export_discovery_jumpstart(&self, limit: usize) -> Result<String> {
        let discovery = self
            .discovery
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Discovery lock poisoned: {}", e)))?;
        discovery.export_jumpstart(limit)
    }

    /// Import peers from a jumpstart payload and return ingested count.
    pub fn import_discovery_jumpstart(&self, payload_json: &str) -> Result<usize> {
        let mut discovery = self
            .discovery
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Discovery lock poisoned: {}", e)))?;
        discovery.import_jumpstart(payload_json)
    }
}
