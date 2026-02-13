use std::collections::HashMap;
use std::time::SystemTime;

use crate::core::{PeerId, PeerInfo};
use crate::core::error::Result;

use super::{AdaptiveDiscovery, BootstrapService, MdnsDiscovery};

pub struct DiscoveryService {
    bootstrap: BootstrapService,
    adaptive: AdaptiveDiscovery,
    mdns: Option<MdnsDiscovery>,
    last_refresh: Option<SystemTime>,
}

impl DiscoveryService {
    pub fn new() -> Self {
        Self {
            bootstrap: BootstrapService::new(),
            adaptive: AdaptiveDiscovery::new(),
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
        self.mdns.as_ref()
            .map(|m| m.is_running())
            .unwrap_or(false)
    }

    pub fn add_seed(&mut self, peer: PeerInfo) {
        self.bootstrap.add_seed(peer);
    }

    pub fn ingest(&mut self, peers: Vec<PeerInfo>) {
        self.adaptive.ingest(peers);
    }

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

        // Collect peers from mDNS if enabled
        if let Some(mdns) = &self.mdns {
            for peer in mdns.discovered_peers()? {
                merged.insert(peer.peer_id, peer);
            }
        }

        self.last_refresh = Some(SystemTime::now());
        Ok(merged.into_values().collect())
    }

    pub fn last_refresh(&self) -> Option<SystemTime> {
        self.last_refresh
    }
}
