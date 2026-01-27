use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use crate::core::{PeerId, TrustLevel};
use crate::error::Result;

#[derive(Clone)]
pub struct TrustRelationship {
    pub peer_id: PeerId,
    pub trust_level: TrustLevel,
    pub verification_methods: Vec<VerificationMethod>,
    pub last_seen: SystemTime,
}

#[derive(Clone, Copy)]
pub enum VerificationMethod {
    InPerson,
    SharedSecret,
    TrustedIntroduction,
    PKI,
}

pub struct WebOfTrust {
    trust_graph: Arc<RwLock<HashMap<PeerId, TrustRelationship>>>,
}

impl WebOfTrust {
    pub fn new() -> Self {
        Self {
            trust_graph: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_peer(
        &self,
        peer_id: PeerId,
        trust_level: TrustLevel,
        method: VerificationMethod,
    ) -> Result<()> {
        let relationship = TrustRelationship {
            peer_id,
            trust_level,
            verification_methods: vec![method],
            last_seen: SystemTime::now(),
        };

        self.trust_graph
            .write()
            .unwrap()
            .insert(peer_id, relationship);
        Ok(())
    }

    pub fn set_trust_level(&self, peer_id: &PeerId, trust_level: TrustLevel) -> Result<()> {
        if let Some(entry) = self.trust_graph.write().unwrap().get_mut(peer_id) {
            entry.trust_level = trust_level;
            entry.last_seen = SystemTime::now();
        }
        Ok(())
    }

    pub fn get_trust_level(&self, peer_id: &PeerId) -> Option<TrustLevel> {
        self.trust_graph
            .read()
            .unwrap()
            .get(peer_id)
            .map(|entry| entry.trust_level)
    }
}
