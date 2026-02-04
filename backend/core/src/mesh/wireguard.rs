use std::collections::HashMap;

use crate::core::PeerId;
use crate::core::error::Result;

pub struct WireGuardMesh {
    peers: HashMap<PeerId, WireGuardPeer>,
}

pub struct WireGuardPeer {
    pub peer_id: PeerId,
    pub public_key: [u8; 32],
}

impl WireGuardMesh {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, peer: WireGuardPeer) -> Result<()> {
        self.peers.insert(peer.peer_id, peer);
        Ok(())
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Result<()> {
        self.peers.remove(peer_id);
        Ok(())
    }

    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&WireGuardPeer> {
        self.peers.get(peer_id)
    }
}
