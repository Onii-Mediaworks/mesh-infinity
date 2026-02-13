// Peer management for mesh network
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::core::{PeerId, PeerInfo, TransportType, TrustLevel as CoreTrustLevel};
use crate::core::error::Result;
use std::time::SystemTime;

pub struct PeerManager {
    peers: Arc<Mutex<HashMap<PeerId, PeerInfo>>>,
    trust_levels: Arc<Mutex<HashMap<PeerId, PeerTrustInfo>>>,
}

pub struct PeerTrustInfo {
    pub level: CoreTrustLevel,
    pub last_updated: SystemTime,
    pub verification_method: VerificationMethod,
}

pub enum VerificationMethod {
    InPerson,
    SharedSecret,
    TrustedIntroduction,
    PKI,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            trust_levels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_peer(&self, peer_info: PeerInfo) -> Result<()> {
        let mut peers = self.peers.lock().unwrap();
        peers.insert(peer_info.peer_id, peer_info);
        Ok(())
    }

    pub fn remove_peer(&self, peer_id: &PeerId) -> Result<()> {
        let mut peers = self.peers.lock().unwrap();
        peers.remove(peer_id);

        let mut trust_levels = self.trust_levels.lock().unwrap();
        trust_levels.remove(peer_id);

        Ok(())
    }

    pub fn get_peer(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        let peers = self.peers.lock().unwrap();
        peers.get(peer_id).cloned()
    }

    pub fn get_all_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().unwrap();
        peers.values().cloned().collect()
    }

    pub fn update_trust_level(
        &self,
        peer_id: &PeerId,
        trust_level: CoreTrustLevel,
        method: VerificationMethod
    ) -> Result<()> {
        let mut trust_levels = self.trust_levels.lock().unwrap();
        trust_levels.insert(*peer_id, PeerTrustInfo {
            level: trust_level,
            last_updated: SystemTime::now(),
            verification_method: method,
        });
        Ok(())
    }

    pub fn get_trust_level(&self, peer_id: &PeerId) -> Option<CoreTrustLevel> {
        let trust_levels = self.trust_levels.lock().unwrap();
        trust_levels.get(peer_id).map(|t| t.level)
    }

    pub fn update_peer_transports(&self, peer_id: &PeerId, transports: &[TransportType]) -> Result<()> {
        let mut peers = self.peers.lock().unwrap();
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.available_transports = transports.to_vec();
            Ok(())
        } else {
            Err(crate::core::error::MeshInfinityError::PeerNotFound(
                format!("{:?}", peer_id)
            ))
        }
    }
}
