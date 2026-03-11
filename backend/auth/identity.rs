//! Local identity and key-material management.
//!
//! Handles creation, lookup, and signing/verification operations for local
//! peer identities, including both Ed25519 signing keys and X25519 DH keys.

use std::collections::HashMap;
use std::time::SystemTime;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::core::error::{MeshInfinityError, Result};
use crate::core::PeerId;

pub struct Identity {
    pub peer_id: PeerId,
    pub signing_key: SigningKey,
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

impl Default for IdentityManager {
    /// Create empty identity manager with no primary identity selected.
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityManager {
    /// Construct an empty identity manager.
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            primary_identity: None,
        }
    }

    /// Generate and register a new identity, optionally assigning a display name.
    ///
    /// The first generated identity is automatically marked as primary.
    pub fn generate_identity(&mut self, name: Option<String>) -> Result<PeerId> {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let dh_secret = StaticSecret::random_from_rng(&mut rng);
        let dh_public = X25519PublicKey::from(&dh_secret).to_bytes();

        let peer_id = derive_peer_id(&signing_key.verifying_key());
        let now = SystemTime::now();

        let identity = Identity {
            peer_id,
            signing_key,
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

    /// Set an existing identity as the primary one used by default.
    pub fn set_primary_identity(&mut self, peer_id: &PeerId) -> Result<()> {
        if self.identities.contains_key(peer_id) {
            self.primary_identity = Some(*peer_id);
            Ok(())
        } else {
            Err(MeshInfinityError::AuthError(
                "Identity not found".to_string(),
            ))
        }
    }

    /// Return current primary identity, if configured.
    pub fn primary_identity(&self) -> Option<&Identity> {
        self.primary_identity
            .and_then(|peer_id| self.identities.get(&peer_id))
    }

    /// Alias for [`IdentityManager::primary_identity`].
    pub fn get_primary_identity(&self) -> Option<&Identity> {
        self.primary_identity()
    }

    /// Look up one identity by peer id.
    pub fn get_identity(&self, peer_id: &PeerId) -> Option<&Identity> {
        self.identities.get(peer_id)
    }

    /// Sign arbitrary message bytes with the selected local identity.
    pub fn sign(&self, peer_id: &PeerId, message: &[u8]) -> Result<Vec<u8>> {
        if let Some(identity) = self.identities.get(peer_id) {
            Ok(identity.signing_key.sign(message).to_bytes().to_vec())
        } else {
            Err(MeshInfinityError::AuthError(
                "Identity not found".to_string(),
            ))
        }
    }

    /// Verify signature against message bytes using local stored public key.
    pub fn verify(&self, peer_id: &PeerId, message: &[u8], signature: &[u8]) -> Result<bool> {
        if let Some(identity) = self.identities.get(peer_id) {
            let signature_bytes: [u8; 64] = signature.try_into().map_err(|_| {
                MeshInfinityError::AuthError("Invalid signature length".to_string())
            })?;
            let signature = Signature::from_bytes(&signature_bytes);
            Ok(identity.signing_key.verifying_key().verify(message, &signature).is_ok())
        } else {
            Err(MeshInfinityError::AuthError(
                "Identity not found".to_string(),
            ))
        }
    }

    /// Return public Ed25519 signing key bytes for an identity.
    pub fn public_signing_key(&self, peer_id: &PeerId) -> Result<[u8; 32]> {
        self.identities
            .get(peer_id)
            .map(|identity| identity.signing_key.verifying_key().to_bytes())
            .ok_or_else(|| MeshInfinityError::AuthError("Identity not found".to_string()))
    }

    /// Return public X25519 Diffie-Hellman key bytes for an identity.
    pub fn public_dh_key(&self, peer_id: &PeerId) -> Result<[u8; 32]> {
        self.identities
            .get(peer_id)
            .map(|identity| identity.dh_public)
            .ok_or_else(|| MeshInfinityError::AuthError("Identity not found".to_string()))
    }

    /// Reconstruct and register an identity from stored secret key bytes.
    ///
    /// This is the inverse of [`primary_secret_key_bytes`]: it rebuilds the
    /// Ed25519 signing key and X25519 DH keypair from their serialised scalar
    /// representations.  The first loaded identity is automatically set as
    /// primary.
    pub fn load_identity(
        &mut self,
        ed25519_secret: &[u8],
        x25519_secret: &[u8],
        name: Option<String>,
    ) -> Result<PeerId> {
        let secret_bytes: &[u8; 32] = ed25519_secret.try_into().map_err(|_| {
            MeshInfinityError::AuthError("Ed25519 secret key must be 32 bytes".to_string())
        })?;
        let dh_bytes: [u8; 32] = x25519_secret.try_into().map_err(|_| {
            MeshInfinityError::AuthError("X25519 secret key must be 32 bytes".to_string())
        })?;

        let signing_key = SigningKey::from_bytes(secret_bytes);
        let dh_secret = StaticSecret::from(dh_bytes);
        let dh_public = X25519PublicKey::from(&dh_secret).to_bytes();
        let peer_id = derive_peer_id(&signing_key.verifying_key());
        let now = SystemTime::now();

        let identity = Identity {
            peer_id,
            signing_key,
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

    /// Update the display name on the primary identity.
    pub fn set_name(&mut self, name: Option<String>) -> Result<()> {
        let peer_id = self
            .primary_identity
            .ok_or_else(|| MeshInfinityError::AuthError("No primary identity".to_string()))?;
        let identity = self
            .identities
            .get_mut(&peer_id)
            .ok_or_else(|| MeshInfinityError::AuthError("Primary identity not found".to_string()))?;
        identity.name = name;
        Ok(())
    }

    /// Export the raw secret key bytes for the primary identity.
    ///
    /// Returns `(ed25519_secret_32, x25519_secret_32)`, suitable for passing
    /// to [`IdentityStore::save`] via a [`PersistedIdentity`].
    pub fn primary_secret_key_bytes(&self) -> Option<([u8; 32], [u8; 32])> {
        self.primary_identity.and_then(|peer_id| {
            self.identities.get(&peer_id).map(|identity| {
                (identity.signing_key.to_bytes(), identity.dh_secret.to_bytes())
            })
        })
    }
}

/// Derive stable peer id from public signing key with domain separation.
fn derive_peer_id(verifying_key: &VerifyingKey) -> PeerId {
    const DOMAIN: &str = "meshinfinity-peer-id-v1";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN.as_bytes());
    hasher.update(verifying_key.as_bytes());
    let digest = hasher.finalize();
    let mut peer_id = [0u8; 32];
    peer_id.copy_from_slice(&digest);
    peer_id
}
