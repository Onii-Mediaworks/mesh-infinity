//! Lightweight discovery sources used by [`DiscoveryService`].
//!
//! These source adapters are intentionally simple and colocated to reduce file
//! count and keep "seed list + adaptive snapshot" behavior in one place.

use crate::core::error::Result;
use crate::core::PeerInfo;

/// In-memory adaptive discovery feed populated from observed peers.
pub struct AdaptiveDiscovery {
    known_peers: Vec<PeerInfo>,
}

impl Default for AdaptiveDiscovery {
    /// Construct default value for this type.
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveDiscovery {
    /// Create an empty adaptive discovery cache.
    pub fn new() -> Self {
        Self {
            known_peers: Vec::new(),
        }
    }

    /// Merge observed peers into the adaptive cache.
    pub fn ingest(&mut self, peers: Vec<PeerInfo>) {
        self.known_peers.extend(peers);
    }

    /// Return a snapshot for routing/peer selection.
    pub fn snapshot(&self) -> Result<Vec<PeerInfo>> {
        Ok(self.known_peers.clone())
    }
}

/// Static bootstrap seed source.
pub struct BootstrapService {
    seeds: Vec<PeerInfo>,
}

impl Default for BootstrapService {
    /// Construct default value for this type.
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapService {
    /// Create an empty seed set.
    pub fn new() -> Self {
        Self { seeds: Vec::new() }
    }

    /// Add a seed peer to bootstrap from.
    pub fn add_seed(&mut self, peer: PeerInfo) {
        self.seeds.push(peer);
    }

    /// Return immutable seed view.
    pub fn seeds(&self) -> &[PeerInfo] {
        &self.seeds
    }

    /// Refresh currently known seed peers.
    pub fn refresh(&self) -> Result<Vec<PeerInfo>> {
        Ok(self.seeds.clone())
    }
}
