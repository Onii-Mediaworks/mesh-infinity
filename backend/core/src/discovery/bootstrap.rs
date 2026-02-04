use crate::core::PeerInfo;
use crate::core::error::Result;

pub struct BootstrapService {
    seeds: Vec<PeerInfo>,
}

impl BootstrapService {
    pub fn new() -> Self {
        Self { seeds: Vec::new() }
    }

    pub fn add_seed(&mut self, peer: PeerInfo) {
        self.seeds.push(peer);
    }

    pub fn seeds(&self) -> &[PeerInfo] {
        &self.seeds
    }

    pub fn refresh(&self) -> Result<Vec<PeerInfo>> {
        Ok(self.seeds.clone())
    }
}
