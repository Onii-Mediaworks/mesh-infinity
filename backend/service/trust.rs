//! Trust and identity-facing service operations.
//!
//! This module encapsulates backend entrypoints that read identity material,
//! create attestations, and evaluate trust outcomes.

use std::time::SystemTime;

use ed25519_dalek::Signer;

use crate::auth::identity::IdentityManager;
use crate::auth::web_of_trust::{
    Identity as WotIdentity, TrustAttestation, VerificationMethod as WotVerificationMethod,
    WebOfTrust,
};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::{PeerId, TrustLevel as CoreTrustLevel};

use super::{
    pairing_code_from_peer_id, peer_id_string, IdentitySummary, LocalProfile, MeshInfinityService,
};

impl MeshInfinityService {
    /// Return optional local identity display name.
    pub fn local_identity_name(&self) -> Option<String> {
        self.identity_manager
            .get_primary_identity()
            .and_then(|identity| identity.name.clone())
    }

    /// Return summary of primary local identity material.
    pub fn local_identity_summary(&self) -> Option<IdentitySummary> {
        self.identity_manager
            .get_primary_identity()
            .map(|identity| IdentitySummary {
                peer_id: identity.peer_id,
                public_key: identity.signing_key.verifying_key().to_bytes(),
                dh_public: identity.dh_public,
                name: identity.name.clone(),
            })
    }

    /// Create and store a trust attestation for a peer.
    pub fn trust_attest(
        &self,
        endorser_peer_id: &PeerId,
        target_peer_id: &PeerId,
        trust_level: CoreTrustLevel,
        method: WotVerificationMethod,
    ) -> Result<()> {
        let identity = self
            .identity_manager
            .get_identity(endorser_peer_id)
            .ok_or_else(|| MeshInfinityError::AuthError("Identity not found".to_string()))?;

        let mut attestation = TrustAttestation::new(
            *endorser_peer_id,
            *target_peer_id,
            trust_level,
            method,
            identity.signing_key.verifying_key().to_bytes(),
        );

        let message = attestation.signable_message();
        let signature = identity.signing_key.sign(&message);
        attestation.signature = signature.to_bytes().to_vec();

        self.web_of_trust.add_attestation(attestation)
    }

    /// Verify whether a trust attestation is valid for a peer.
    pub fn trust_verify(
        &self,
        target_peer_id: &PeerId,
        trust_markers: Vec<(PeerId, PeerId, CoreTrustLevel, SystemTime)>,
    ) -> CoreTrustLevel {
        use crate::auth::web_of_trust::TrustMarker;

        let markers = trust_markers
            .into_iter()
            .map(|(endorser, target, trust_level, timestamp)| TrustMarker {
                endorser,
                target,
                trust_level,
                timestamp,
            })
            .collect::<Vec<_>>();

        self.web_of_trust.verify_peer(target_peer_id, &markers)
    }

    // -------------------------------------------------------------------------
    // Identity persistence helpers (called by FFI after disk I/O)
    // -------------------------------------------------------------------------

    /// Returns `true` if the current identity has been saved to disk.
    pub fn is_identity_persisted(&self) -> bool {
        self.identity_persisted
    }

    /// Mark the current identity as having been saved to disk.
    pub fn set_identity_persisted(&mut self, persisted: bool) {
        self.identity_persisted = persisted;
    }

    /// Update the display name on the primary identity (in-memory only).
    /// Callers are responsible for re-persisting afterwards.
    pub fn set_identity_name(&mut self, name: Option<String>) -> Result<()> {
        self.identity_manager.set_name(name)
    }

    /// Return the raw secret key bytes for the primary identity.
    /// Returns `(ed25519_secret_32, x25519_secret_32)`.
    pub fn primary_secret_key_bytes(&self) -> Option<([u8; 32], [u8; 32])> {
        self.identity_manager.primary_secret_key_bytes()
    }

    /// Read the local profile (visibility, private bio, etc.).
    pub fn local_profile(&self) -> &LocalProfile {
        &self.local_profile
    }

    /// Replace the local profile in memory.
    /// Callers are responsible for re-persisting afterwards.
    pub fn set_local_profile(&mut self, profile: LocalProfile) {
        self.local_profile = profile;
    }

    /// Replace the active identity entirely from raw key bytes.
    ///
    /// Used during backup restore: discards the current in-memory identity,
    /// loads the supplied key material, and updates the WoT and settings state
    /// to match.  Callers are responsible for persisting the new identity.
    pub fn load_identity_from_bytes(
        &mut self,
        ed25519_secret: [u8; 32],
        x25519_secret: [u8; 32],
        name: Option<String>,
        profile: LocalProfile,
    ) -> Result<()> {
        let mut new_manager = IdentityManager::new();
        let peer_id =
            new_manager.load_identity(&ed25519_secret, &x25519_secret, name.clone())?;

        let wot_identity = WotIdentity {
            peer_id,
            public_key: new_manager
                .public_signing_key(&peer_id)
                .unwrap_or([0u8; 32]),
            name: name.clone(),
        };

        self.identity_manager = new_manager;
        self.web_of_trust = WebOfTrust::with_identity(wot_identity);
        self.local_profile = profile;
        self.identity_persisted = true;

        let pairing_code = pairing_code_from_peer_id(&peer_id);
        let mut state = self.state.write().unwrap();
        state.settings.pairing_code = pairing_code;
        state.settings.local_peer_id = peer_id_string(&peer_id);

        Ok(())
    }
}
