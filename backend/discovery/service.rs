//! Unified peer discovery coordinator.
//!
//! Merges peer candidates from bootstrap seeds, adaptive cache, and optional
//! mDNS discovery into a deduplicated refresh snapshot. Also maintains a
//! DHT-like nearest-peer index and jumpstart import/export path for map sharing.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::core::error::Result;
use crate::core::{PeerId, PeerInfo};

use super::{AdaptiveDiscovery, BootstrapService, DiscoveryDht, JumpstartPayload, MdnsDiscovery};

pub struct DiscoveryService {
    bootstrap: BootstrapService,
    adaptive: AdaptiveDiscovery,
    dht: DiscoveryDht,
    mdns: Option<MdnsDiscovery>,
    last_refresh: Option<SystemTime>,
}

impl Default for DiscoveryService {
    /// Create discovery service with default subcomponents.
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryService {
    /// Construct discovery service with bootstrap/adaptive modules enabled.
    pub fn new() -> Self {
        Self {
            bootstrap: BootstrapService::new(),
            adaptive: AdaptiveDiscovery::new(),
            dht: DiscoveryDht::new(),
            mdns: None,
            last_refresh: None,
        }
    }

    /// Enable mDNS discovery with local peer information
    pub fn enable_mdns(&mut self, local_peer_id: PeerId, local_port: u16) -> Result<()> {
        let mdns = MdnsDiscovery::new(local_peer_id, local_port)?;
        mdns.start()?;
        self.mdns = Some(mdns);
        Ok(())
    }

    /// Disable mDNS discovery
    pub fn disable_mdns(&mut self) -> Result<()> {
        if let Some(mdns) = &self.mdns {
            mdns.stop()?;
        }
        self.mdns = None;
        Ok(())
    }

    /// Check if mDNS is running
    pub fn is_mdns_running(&self) -> bool {
        self.mdns.as_ref().is_some_and(|m| m.is_running())
    }

    /// Add static seed peer used by bootstrap discovery path.
    pub fn add_seed(&mut self, peer: PeerInfo) {
        self.dht.upsert(peer.clone());
        self.bootstrap.add_seed(peer);
    }

    /// Ingest observed peers into adaptive discovery memory.
    pub fn ingest(&mut self, peers: Vec<PeerInfo>) {
        self.dht.upsert_many(peers.clone());
        self.adaptive.ingest(peers);
    }

    /// Return up to `limit` peers nearest to `target` by XOR distance.
    pub fn nearest_peers(&self, target: &PeerId, limit: usize) -> Vec<PeerInfo> {
        self.dht.nearest_peers(target, limit)
    }

    /// Export a compact jumpstart payload from currently known peers.
    pub fn export_jumpstart(&self, limit: usize) -> Result<String> {
        let mut peers = self.dht.all_peers();
        peers.sort_by_key(|peer| peer.peer_id);
        peers.truncate(limit);
        JumpstartPayload::new(peers).encode_json()
    }

    /// Import a jumpstart payload and merge contained peers.
    pub fn import_jumpstart(&mut self, payload_json: &str) -> Result<usize> {
        let payload = JumpstartPayload::decode_json(payload_json)?;
        let count = payload.peers.len();
        self.dht.upsert_many(payload.peers.clone());
        self.adaptive.ingest(payload.peers);
        Ok(count)
    }

    /// Refresh all enabled discovery channels and return merged peer list.
    pub fn refresh(&mut self) -> Result<Vec<PeerInfo>> {
        let mut merged: HashMap<PeerId, PeerInfo> = HashMap::new();

        // Collect peers from bootstrap
        for peer in self.bootstrap.refresh()? {
            merged.insert(peer.peer_id, peer);
        }

        // Collect peers from adaptive discovery
        for peer in self.adaptive.snapshot()? {
            merged.insert(peer.peer_id, peer);
        }

        // Collect peers from DHT-like index (includes jumpstart imports).
        for peer in self.dht.all_peers() {
            merged.insert(peer.peer_id, peer);
        }

        // Collect peers from mDNS if enabled
        if let Some(mdns) = &self.mdns {
            for peer in mdns.discovered_peers()? {
                merged.insert(peer.peer_id, peer);
            }
        }

        self.last_refresh = Some(SystemTime::now());
        Ok(merged.into_values().collect())
    }

    /// Return timestamp of last successful refresh call.
    pub fn last_refresh(&self) -> Option<SystemTime> {
        self.last_refresh
    }
}
