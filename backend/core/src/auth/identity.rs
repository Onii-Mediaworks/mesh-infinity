use std::collections::HashMap;
use std::time::SystemTime;

use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::core::error::{MeshInfinityError, Result};
use crate::core::PeerId;

pub struct Identity {
    pub peer_id: PeerId,
    pub keypair: Keypair,
    pub dh_secret: StaticSecret,
    pub dh_public: [u8; 32],
    pub name: Option<String>,
    pub created_at: SystemTime,
    pub last_used: SystemTime,
}

pub struct IdentityManager {
    identities: HashMap<PeerId, Identity>,
    primary_identity: Option<PeerId>,
}

impl IdentityManager {
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            primary_identity: None,
        }
    }

    pub fn generate_identity(&mut self, name: Option<String>) -> Result<PeerId> {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let dh_secret = StaticSecret::new(&mut rng);
        let dh_public = X25519PublicKey::from(&dh_secret).to_bytes();

        let peer_id = derive_peer_id(&keypair.public);
        let now = SystemTime::now();

        let identity = Identity {
            peer_id,
            keypair,
            dh_secret,
            dh_public,
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
            Err(MeshInfinityError::AuthError("Identity not found".to_string()))
        }
    }

    pub fn primary_identity(&self) -> Option<&Identity> {
        self.primary_identity
            .and_then(|peer_id| self.identities.get(&peer_id))
    }

    pub fn get_identity(&self, peer_id: &PeerId) -> Option<&Identity> {
        self.identities.get(peer_id)
    }

    pub fn sign(&self, peer_id: &PeerId, message: &[u8]) -> Result<Vec<u8>> {
        if let Some(identity) = self.identities.get(peer_id) {
            Ok(identity.keypair.sign(message).to_bytes().to_vec())
        } else {
            Err(MeshInfinityError::AuthError("Identity not found".to_string()))
        }
    }

    pub fn verify(&self, peer_id: &PeerId, message: &[u8], signature: &[u8]) -> Result<bool> {
        if let Some(identity) = self.identities.get(peer_id) {
            let signature_bytes: [u8; 64] = signature.try_into().map_err(|_| {
                MeshInfinityError::AuthError("Invalid signature length".to_string())
            })?;
            let signature = Signature::new(signature_bytes);
            Ok(identity.keypair.public.verify(message, &signature).is_ok())
        } else {
            Err(MeshInfinityError::AuthError("Identity not found".to_string()))
        }
    }

    pub fn public_signing_key(&self, peer_id: &PeerId) -> Result<[u8; 32]> {
        self.identities
            .get(peer_id)
            .map(|identity| identity.keypair.public.to_bytes())
            .ok_or_else(|| MeshInfinityError::AuthError("Identity not found".to_string()))
    }

    pub fn public_dh_key(&self, peer_id: &PeerId) -> Result<[u8; 32]> {
        self.identities
            .get(peer_id)
            .map(|identity| identity.dh_public)
            .ok_or_else(|| MeshInfinityError::AuthError("Identity not found".to_string()))
    }
}

fn derive_peer_id(public_key: &PublicKey) -> PeerId {
    const DOMAIN: &str = "meshinfinity-peer-id-v1";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN.as_bytes());
    hasher.update(public_key.as_bytes());
    let digest = hasher.finalize();
    let mut peer_id = [0u8; 32];
    peer_id.copy_from_slice(&digest);
    peer_id
}
