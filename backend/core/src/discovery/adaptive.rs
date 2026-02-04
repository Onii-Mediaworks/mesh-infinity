use crate::core::PeerInfo;
use crate::core::error::Result;

pub struct AdaptiveDiscovery {
    known_peers: Vec<PeerInfo>,
}

impl AdaptiveDiscovery {
    pub fn new() -> Self {
        Self {
            known_peers: Vec::new(),
        }
    }

    pub fn ingest(&mut self, peers: Vec<PeerInfo>) {
        self.known_peers.extend(peers);
    }

    pub fn snapshot(&self) -> Result<Vec<PeerInfo>> {
        Ok(self.known_peers.clone())
    }
}
