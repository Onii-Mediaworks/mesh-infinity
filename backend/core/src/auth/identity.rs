use std::collections::HashMap;
use std::time::SystemTime;

use ring::rand::{SecureRandom, SystemRandom};

use crate::core::PeerId;
use crate::error::{NetInfinityError, Result};

pub struct Identity {
    pub peer_id: PeerId,
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
    pub name: Option<String>,
    pub created_at: SystemTime,
    pub last_used: SystemTime,
}

pub struct IdentityManager {
    identities: HashMap<PeerId, Identity>,
    primary_identity: Option<PeerId>,
    rng: SystemRandom,
}

impl IdentityManager {
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            primary_identity: None,
            rng: SystemRandom::new(),
        }
    }

    pub fn generate_identity(&mut self, name: Option<String>) -> Result<PeerId> {
        let mut public_key = [0u8; 32];
        let mut secret_key = [0u8; 32];

        self.rng
            .fill(&mut public_key)
            .map_err(|_| NetInfinityError::CryptoError("identity generation failed".to_string()))?;
        self.rng
            .fill(&mut secret_key)
            .map_err(|_| NetInfinityError::CryptoError("identity generation failed".to_string()))?;

        let peer_id = derive_peer_id(&public_key);
        let now = SystemTime::now();

        let identity = Identity {
            peer_id,
            public_key,
            secret_key,
            name,
            created_at: now,
            last_used: now,
        };

        self.identities.insert(peer_id, identity);
        if self.primary_identity.is_none() {
            self.primary_identity = Some(peer_id);
        }

        Ok(peer_id)
    }

    pub fn set_primary_identity(&mut self, peer_id: &PeerId) -> Result<()> {
        if self.identities.contains_key(peer_id) {
            self.primary_identity = Some(*peer_id);
            Ok(())
        } else {
            Err(NetInfinityError::AuthError("Identity not found".to_string()))
        }
    }

    pub fn primary_identity(&self) -> Option<&Identity> {
        self.primary_identity
            .and_then(|peer_id| self.identities.get(&peer_id))
    }

    pub fn get_identity(&self, peer_id: &PeerId) -> Option<&Identity> {
        self.identities.get(peer_id)
    }
}

fn derive_peer_id(public_key: &[u8; 32]) -> PeerId {
    *public_key
}
