//! Trust and identity-facing service operations.
//!
//! This module encapsulates backend entrypoints that read identity material,
//! create attestations, and evaluate trust outcomes.

use std::time::SystemTime;

use ed25519_dalek::Signer;

use crate::auth::web_of_trust::{TrustAttestation, VerificationMethod as WotVerificationMethod};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::{PeerId, TrustLevel as CoreTrustLevel};

use super::{IdentitySummary, MeshInfinityService};

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
                public_key: identity.keypair.public.to_bytes(),
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
            identity.keypair.public.to_bytes(),
        );

        let message = attestation.signable_message();
        let signature = identity.keypair.sign(&message);
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
}
