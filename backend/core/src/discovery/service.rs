use std::collections::HashMap;
use std::time::SystemTime;

use crate::core::{PeerId, PeerInfo};
use crate::core::error::Result;

use super::{AdaptiveDiscovery, BootstrapService};

pub struct DiscoveryService {
    bootstrap: BootstrapService,
    adaptive: AdaptiveDiscovery,
    last_refresh: Option<SystemTime>,
}

impl DiscoveryService {
    pub fn new() -> Self {
        Self {
            bootstrap: BootstrapService::new(),
            adaptive: AdaptiveDiscovery::new(),
            last_refresh: None,
        }
    }

    pub fn add_seed(&mut self, peer: PeerInfo) {
        self.bootstrap.add_seed(peer);
    }

    pub fn ingest(&mut self, peers: Vec<PeerInfo>) {
        self.adaptive.ingest(peers);
    }

    pub fn refresh(&mut self) -> Result<Vec<PeerInfo>> {
        let mut merged: HashMap<PeerId, PeerInfo> = HashMap::new();
        for peer in self.bootstrap.refresh()? {
            merged.insert(peer.peer_id, peer);
        }
        for peer in self.adaptive.snapshot()? {
            merged.insert(peer.peer_id, peer);
        }
        self.last_refresh = Some(SystemTime::now());
        Ok(merged.into_values().collect())
    }

    pub fn last_refresh(&self) -> Option<SystemTime> {
        self.last_refresh
    }
}
