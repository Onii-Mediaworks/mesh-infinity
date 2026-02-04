use std::collections::HashMap;

use crate::core::{PeerId, PeerInfo, TrustLevel};
use crate::core::error::{MeshInfinityError, Result};

pub struct PeerManager {
    peers: HashMap<PeerId, PeerInfo>,
    trust: HashMap<PeerId, TrustLevel>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            trust: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, peer: PeerInfo) -> Result<()> {
        self.trust.insert(peer.peer_id, peer.trust_level);
        self.peers.insert(peer.peer_id, peer);
        Ok(())
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Result<()> {
        self.peers.remove(peer_id);
        self.trust.remove(peer_id);
        Ok(())
    }

    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    pub fn get_all_peers(&self) -> Vec<PeerInfo> {
        self.peers.values().cloned().collect()
    }

    pub fn set_trust_level(&mut self, peer_id: &PeerId, trust_level: TrustLevel) -> Result<()> {
        if self.peers.contains_key(peer_id) {
            self.trust.insert(*peer_id, trust_level);
            Ok(())
        } else {
            Err(MeshInfinityError::PeerNotFound(format!("{:?}", peer_id)))
        }
    }

    pub fn trust_level(&self, peer_id: &PeerId) -> Option<TrustLevel> {
        self.trust.get(peer_id).copied()
    }
}
