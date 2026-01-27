// Identity management
use std::collections::HashMap;

use ed25519_dalek::{Keypair, PublicKey, Signer, Verifier};
use crate::core::core::PeerId;
use crate::core::error::{NetInfinityError, Result};
use rand_core::OsRng;

pub struct IdentityManager {
    identities: HashMap<PeerId, Identity>,
    primary_identity: Option<PeerId>,
}

pub struct Identity {
    pub peer_id: PeerId,
    pub keypair: Keypair,
    pub name: Option<String>,
    pub created_at: std::time::SystemTime,
    pub last_used: std::time::SystemTime,
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
        
        let peer_id = Self::derive_peer_id(&keypair.public);
        
        let identity = Identity {
            peer_id,
            keypair,
            name,
            created_at: std::time::SystemTime::now(),
            last_used: std::time::SystemTime::now(),
        };
        
        self.identities.insert(peer_id, identity);
        
        // If this is the first identity, make it primary
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
            Err(crate::core::error::NetInfinityError::AuthError(
                "Identity not found".to_string()
            ))
        }
    }
    
    pub fn get_primary_identity(&self) -> Option<&Identity> {
        self.primary_identity.and_then(|id| self.identities.get(&id))
    }
    
    pub fn get_identity(&self, peer_id: &PeerId) -> Option<&Identity> {
        self.identities.get(peer_id)
    }
    
    pub fn sign(&self, peer_id: &PeerId, message: &[u8]) -> Result<Vec<u8>> {
        if let Some(identity) = self.identities.get(peer_id) {
            Ok(identity.keypair.sign(message).to_bytes().to_vec())
        } else {
            Err(crate::core::error::NetInfinityError::AuthError(
                "Identity not found".to_string()
            ))
        }
    }
    
    pub fn verify(&self, peer_id: &PeerId, message: &[u8], signature: &[u8]) -> Result<bool> {
        if let Some(identity) = self.identities.get(peer_id) {
            let signature_bytes: [u8; 64] = signature.try_into().map_err(|_| {
                NetInfinityError::AuthError("Invalid signature length".to_string())
            })?;
            let signature = ed25519_dalek::Signature::new(signature_bytes);
            Ok(identity.keypair.public.verify(message, &signature).is_ok())
        } else {
            Err(crate::core::error::NetInfinityError::AuthError(
                "Identity not found".to_string()
            ))
        }
    }
    
    fn derive_peer_id(public_key: &PublicKey) -> PeerId {
        // Simple derivation - in real implementation would use proper KDF
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(public_key.as_bytes());
        peer_id
    }
}
