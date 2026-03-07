//! Web-of-trust graph and trust attestation processing.
//!
//! Maintains direct trust relationships, propagated trust calculations, signed
//! attestations, and persistence/import utilities for trust state.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::storage::{
    ExportedTrustGraph, RevocationCertificate, RevocationReason, SerializableTrustRelationship,
};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::{PeerId, TrustLevel};

#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    pub peer_id: PeerId,
    pub public_key: [u8; 32],
    pub name: Option<String>,
}

#[derive(Clone)]
pub struct TrustRelationship {
    pub peer_id: PeerId,
    pub trust_level: TrustLevel,
    pub verification_methods: Vec<VerificationMethod>,
    pub last_seen: SystemTime,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum VerificationMethod {
    InPerson = 1,
    SharedSecret = 2,
    TrustedIntroduction = 3,
    PKI = 4,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TrustMarker {
    pub endorser: PeerId,
    pub target: PeerId,
    pub trust_level: TrustLevel,
    pub timestamp: SystemTime,
}

/// Cryptographically signed trust attestation
/// Allows one peer to endorse another peer's trustworthiness
#[derive(Clone, Serialize, Deserialize)]
pub struct TrustAttestation {
    pub endorser_id: PeerId,
    pub target_id: PeerId,
    pub trust_level: TrustLevel,
    pub verification_method: VerificationMethod,
    pub timestamp: SystemTime,
    pub signature: Vec<u8>,
    pub endorser_public_key: Vec<u8>,
}

impl TrustAttestation {
    /// Create a new trust attestation (signature must be added separately)
    pub fn new(
        endorser_id: PeerId,
        target_id: PeerId,
        trust_level: TrustLevel,
        verification_method: VerificationMethod,
        endorser_public_key: [u8; 32],
    ) -> Self {
        Self {
            endorser_id,
            target_id,
            trust_level,
            verification_method,
            timestamp: SystemTime::now(),
            signature: Vec::new(),
            endorser_public_key: endorser_public_key.to_vec(),
        }
    }

    /// Get the message that should be signed
    pub fn signable_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.endorser_id);
        msg.extend_from_slice(&self.target_id);
        msg.push(self.trust_level as u8);
        msg.push(self.verification_method as u8);

        // Add timestamp as u64
        if let Ok(duration) = self.timestamp.duration_since(SystemTime::UNIX_EPOCH) {
            msg.extend_from_slice(&duration.as_secs().to_le_bytes());
        }

        msg
    }

    /// Verify the signature on this attestation
    pub fn verify_signature(&self) -> Result<bool> {
        if self.signature.is_empty() {
            return Ok(false);
        }

        if self.endorser_public_key.len() != 32 {
            return Err(MeshInfinityError::CryptoError(
                "Invalid public key length".to_string(),
            ));
        }

        let public_key = PublicKey::from_bytes(&self.endorser_public_key)
            .map_err(|e| MeshInfinityError::CryptoError(format!("Invalid public key: {}", e)))?;

        if self.signature.len() != 64 {
            return Ok(false);
        }

        let sig_bytes: [u8; 64] = self.signature[..64]
            .try_into()
            .map_err(|_| MeshInfinityError::CryptoError("Invalid signature bytes".to_string()))?;
        let signature = Signature::from_bytes(&sig_bytes)
            .map_err(|_| MeshInfinityError::CryptoError("Invalid signature bytes".to_string()))?;

        let message = self.signable_message();
        Ok(public_key.verify(&message, &signature).is_ok())
    }
}

pub struct WebOfTrust {
    my_identity: Option<Identity>,
    trust_graph: Arc<RwLock<HashMap<PeerId, TrustRelationship>>>,
    attestations: Arc<RwLock<HashMap<PeerId, Vec<TrustAttestation>>>>,
    revocations: Arc<RwLock<Vec<RevocationCertificate>>>,
    pending_revocation_broadcasts: Arc<RwLock<VecDeque<RevocationCertificate>>>,
}

impl Default for WebOfTrust {
    /// Create an empty web-of-trust instance.
    fn default() -> Self {
        Self::new()
    }
}

impl WebOfTrust {
    /// Construct a trust graph without a local identity binding.
    pub fn new() -> Self {
        Self {
            my_identity: None,
            trust_graph: Arc::new(RwLock::new(HashMap::new())),
            attestations: Arc::new(RwLock::new(HashMap::new())),
            revocations: Arc::new(RwLock::new(Vec::new())),
            pending_revocation_broadcasts: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Construct a trust graph bound to the provided local identity.
    pub fn with_identity(identity: Identity) -> Self {
        Self {
            my_identity: Some(identity),
            trust_graph: Arc::new(RwLock::new(HashMap::new())),
            attestations: Arc::new(RwLock::new(HashMap::new())),
            revocations: Arc::new(RwLock::new(Vec::new())),
            pending_revocation_broadcasts: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Return local identity metadata if configured.
    pub fn identity(&self) -> Option<&Identity> {
        self.my_identity.as_ref()
    }

    /// Insert or replace direct trust relationship for a peer.
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

    /// Update direct trust level for an already-known peer.
    pub fn set_trust_level(&self, peer_id: &PeerId, trust_level: TrustLevel) -> Result<()> {
        if let Some(entry) = self.trust_graph.write().unwrap().get_mut(peer_id) {
            entry.trust_level = trust_level;
            entry.last_seen = SystemTime::now();
        }
        Ok(())
    }

    /// Fetch direct trust level for a peer, if present in graph.
    pub fn get_trust_level(&self, peer_id: &PeerId) -> Option<TrustLevel> {
        self.trust_graph
            .read()
            .unwrap()
            .get(peer_id)
            .map(|entry| entry.trust_level)
    }

    /// Calculate transitive trust level for a peer through the web of trust
    /// Uses breadth-first search with trust decay over distance
    pub fn calculate_transitive_trust(
        &self,
        target_peer: &PeerId,
        own_peer_id: &PeerId,
    ) -> TrustLevel {
        // Direct trust check first
        if let Some(direct_trust) = self.get_trust_level(target_peer) {
            return direct_trust;
        }

        // BFS to find trust paths
        let graph = self.trust_graph.read().unwrap();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut max_trust = 0.0f32;

        // Start from our own trusted peers
        queue.push_back((*own_peer_id, 1.0f32, 0u32)); // (peer_id, trust_weight, distance)
        visited.insert(*own_peer_id);

        const MAX_HOPS: u32 = 4; // Limit propagation distance
        const DECAY_FACTOR: f32 = 0.6; // Trust decays by 40% per hop

        while let Some((_current_peer, current_trust, distance)) = queue.pop_front() {
            if distance >= MAX_HOPS {
                continue;
            }

            // Get peers trusted by current_peer
            for (peer_id, relationship) in graph.iter() {
                if visited.contains(peer_id) {
                    continue;
                }

                let trust_value = trust_level_to_f32(relationship.trust_level);
                let propagated_trust = current_trust * trust_value * DECAY_FACTOR;

                if *peer_id == *target_peer {
                    max_trust = max_trust.max(propagated_trust);
                } else if propagated_trust > 0.1 {
                    // Only continue propagating if trust is still significant
                    queue.push_back((*peer_id, propagated_trust, distance + 1));
                    visited.insert(*peer_id);
                }
            }
        }

        f32_to_trust_level(max_trust)
    }

    /// Get all peers with at least a certain trust level
    pub fn get_trusted_peers(&self, min_trust: TrustLevel) -> Vec<PeerId> {
        self.trust_graph
            .read()
            .unwrap()
            .iter()
            .filter(|(_, rel)| rel.trust_level >= min_trust)
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    /// Calculate trust score through multiple paths
    /// Returns a confidence score based on multiple independent trust paths
    pub fn calculate_trust_confidence(&self, target_peer: &PeerId, own_peer_id: &PeerId) -> f32 {
        let graph = self.trust_graph.read().unwrap();
        let mut paths_found = 0;
        let mut total_trust = 0.0f32;

        // Find independent paths to target
        let mut visited_global = HashSet::new();

        for _ in 0..3 {
            // Try to find up to 3 independent paths
            if let Some(path_trust) =
                self.find_trust_path(&graph, own_peer_id, target_peer, &visited_global)
            {
                paths_found += 1;
                total_trust += path_trust;

                // Mark this path as used
                visited_global.insert(*target_peer);
            } else {
                break;
            }
        }

        if paths_found == 0 {
            0.0
        } else {
            // Confidence increases with multiple paths
            (total_trust / paths_found as f32) * (1.0 + (paths_found as f32 * 0.2))
        }
    }

    /// Find one trust path score from `from` to `to`, avoiding `blocked` peers.
    fn find_trust_path(
        &self,
        graph: &HashMap<PeerId, TrustRelationship>,
        from: &PeerId,
        to: &PeerId,
        blocked: &HashSet<PeerId>,
    ) -> Option<f32> {
        let mut queue = VecDeque::new();
        let mut visited = blocked.clone();

        queue.push_back((*from, 1.0f32));
        visited.insert(*from);

        while let Some((current, trust)) = queue.pop_front() {
            if current == *to {
                return Some(trust);
            }

            for (peer_id, relationship) in graph.iter() {
                if visited.contains(peer_id) {
                    continue;
                }

                let peer_trust = trust_level_to_f32(relationship.trust_level);
                let propagated = trust * peer_trust * 0.6;

                if propagated > 0.05 {
                    queue.push_back((*peer_id, propagated));
                    visited.insert(*peer_id);
                }
            }
        }

        None
    }

    /// Add a trust endorsement from one peer about another
    /// This is used for trust attestations
    pub fn add_endorsement(
        &self,
        endorser: &PeerId,
        target: &PeerId,
        trust_level: TrustLevel,
    ) -> Result<()> {
        // Only add endorsement if endorser is trusted
        if let Some(endorser_trust) = self.get_trust_level(endorser) {
            if endorser_trust >= TrustLevel::Trusted {
                self.add_peer(
                    *target,
                    trust_level,
                    VerificationMethod::TrustedIntroduction,
                )?;
            }
        }
        Ok(())
    }

    /// Remove a peer from the trust graph
    pub fn remove_peer(&self, peer_id: &PeerId) -> Result<()> {
        self.trust_graph.write().unwrap().remove(peer_id);
        Ok(())
    }

    /// Get all peers in the trust graph
    pub fn get_all_peers(&self) -> Vec<PeerId> {
        self.trust_graph.read().unwrap().keys().copied().collect()
    }

    /// Get the full trust relationship for a peer
    pub fn get_relationship(&self, peer_id: &PeerId) -> Option<TrustRelationship> {
        self.trust_graph.read().unwrap().get(peer_id).cloned()
    }

    /// Add a cryptographically signed trust attestation
    /// Verifies the signature before accepting
    pub fn add_attestation(&self, attestation: TrustAttestation) -> Result<()> {
        let now = SystemTime::now();
        let max_future_skew = Duration::from_secs(5 * 60);
        let max_age = Duration::from_secs(90 * 24 * 3600);

        // Ensure the attestation key material binds to the declared endorser identity.
        if attestation.endorser_public_key.len() != 32 {
            return Err(MeshInfinityError::CryptoError(
                "Invalid endorser public key length".to_string(),
            ));
        }
        let mut endorser_pub = [0u8; 32];
        endorser_pub.copy_from_slice(&attestation.endorser_public_key[..32]);
        let derived_endorser_id = derive_peer_id_from_public_key(&endorser_pub);
        if derived_endorser_id != attestation.endorser_id {
            return Err(MeshInfinityError::AuthError(
                "Attestation endorser id does not match public key".to_string(),
            ));
        }

        // Enforce timestamp validity window.
        match attestation.timestamp.duration_since(now) {
            Ok(future_offset) if future_offset > max_future_skew => {
                return Err(MeshInfinityError::AuthError(
                    "Attestation timestamp too far in the future".to_string(),
                ));
            }
            _ => {}
        }
        if let Ok(age) = now.duration_since(attestation.timestamp) {
            if age > max_age {
                return Err(MeshInfinityError::AuthError(
                    "Attestation timestamp too old".to_string(),
                ));
            }
        }

        // Verify the signature
        if !attestation.verify_signature()? {
            return Err(MeshInfinityError::CryptoError(
                "Invalid attestation signature".to_string(),
            ));
        }

        // Verify the endorser is trusted
        if let Some(endorser_trust) = self.get_trust_level(&attestation.endorser_id) {
            if endorser_trust < TrustLevel::Trusted {
                return Err(MeshInfinityError::AuthError(
                    "Endorser not sufficiently trusted".to_string(),
                ));
            }
        } else {
            return Err(MeshInfinityError::AuthError(
                "Endorser not in trust graph".to_string(),
            ));
        }

        // Store only non-replayed attestations.
        let fingerprint = attestation_fingerprint(&attestation);
        let mut attestations = self.attestations.write().unwrap();
        let entries = attestations.entry(attestation.target_id).or_default();
        if entries
            .iter()
            .any(|existing| attestation_fingerprint(existing) == fingerprint)
        {
            return Err(MeshInfinityError::AuthError(
                "Duplicate attestation replay detected".to_string(),
            ));
        }
        entries.push(attestation.clone());

        // Update trust level based on attestation
        if let Some(existing) = self.get_trust_level(&attestation.target_id) {
            // Take the higher of existing trust or attested trust
            let new_trust = if attestation.trust_level > existing {
                attestation.trust_level
            } else {
                existing
            };
            self.set_trust_level(&attestation.target_id, new_trust)?;
        } else {
            // New peer, add with attested trust level
            self.add_peer(
                attestation.target_id,
                attestation.trust_level,
                attestation.verification_method,
            )?;
        }

        Ok(())
    }

    /// Get all attestations for a peer
    pub fn get_attestations(&self, peer_id: &PeerId) -> Vec<TrustAttestation> {
        self.attestations
            .read()
            .unwrap()
            .get(peer_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Calculate trust based on attestations from multiple trusted peers
    /// Returns higher trust if multiple independent trusted peers attest
    pub fn calculate_attested_trust(&self, peer_id: &PeerId) -> TrustLevel {
        let attestations = self.get_attestations(peer_id);

        if attestations.is_empty() {
            return TrustLevel::Untrusted;
        }

        // Count attestations by trust level from trusted endorsers
        let mut highly_trusted_count = 0;
        let mut trusted_count = 0;

        for attestation in attestations {
            if let Some(endorser_trust) = self.get_trust_level(&attestation.endorser_id) {
                match endorser_trust {
                    TrustLevel::HighlyTrusted => {
                        highly_trusted_count += 1;
                        if attestation.trust_level >= TrustLevel::Trusted {
                            trusted_count += 1;
                        }
                    }
                    TrustLevel::Trusted => {
                        if attestation.trust_level >= TrustLevel::Trusted {
                            trusted_count += 1;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Multiple attestations from highly trusted peers
        if highly_trusted_count >= 2 {
            TrustLevel::HighlyTrusted
        } else if highly_trusted_count >= 1 || trusted_count >= 2 {
            TrustLevel::Trusted
        } else if trusted_count >= 1 {
            TrustLevel::Caution
        } else {
            TrustLevel::Untrusted
        }
    }

    /// Compute effective trust for peer from direct, propagated, and attested signals.
    pub fn verify_peer(&self, peer_id: &PeerId, trust_markers: &[TrustMarker]) -> TrustLevel {
        if let Some(identity) = &self.my_identity {
            if peer_id == &identity.peer_id {
                return TrustLevel::HighlyTrusted;
            }
        }

        let direct = self
            .get_trust_level(peer_id)
            .unwrap_or(TrustLevel::Untrusted);
        let propagated = self.calculate_propagated_trust(peer_id, trust_markers);
        let attested = self.calculate_attested_trust(peer_id);

        direct.max(propagated).max(attested)
    }

    /// Compute trust propagated via trusted endorsers observing `target`.
    fn calculate_propagated_trust(
        &self,
        target: &PeerId,
        trust_markers: &[TrustMarker],
    ) -> TrustLevel {
        let graph = self.trust_graph.read().unwrap();

        let mut endorsing_peers = Vec::new();

        for (peer_id, rel) in graph.iter() {
            if rel.trust_level >= TrustLevel::Trusted
                && self.peer_knows_about(peer_id, target, trust_markers)
            {
                endorsing_peers.push((peer_id, rel.trust_level));
            }
        }

        if endorsing_peers.is_empty() {
            return TrustLevel::Untrusted;
        }

        endorsing_peers.sort_by_key(|(_, trust_level)| *trust_level as u8);
        endorsing_peers.reverse();

        let mut total_trust: u32 = 0;
        let mut weight_sum: u32 = 0;

        for (_peer_id, trust_level) in endorsing_peers.into_iter().take(3) {
            let weight = match trust_level {
                TrustLevel::Trusted => 1,
                TrustLevel::HighlyTrusted => 2,
                _ => 0,
            };

            total_trust += weight * u32::from(trust_level as u8);
            weight_sum += weight;
        }

        if weight_sum > 0 {
            let avg_trust = total_trust / weight_sum;
            match avg_trust {
                0..=1 => TrustLevel::Untrusted,
                2..=3 => TrustLevel::Caution,
                4..=5 => TrustLevel::Trusted,
                _ => TrustLevel::HighlyTrusted,
            }
        } else {
            TrustLevel::Untrusted
        }
    }

    /// Return whether `peer_id` has a trust marker referencing `target`.
    fn peer_knows_about(
        &self,
        peer_id: &PeerId,
        target: &PeerId,
        trust_markers: &[TrustMarker],
    ) -> bool {
        trust_markers
            .iter()
            .any(|marker| marker.endorser == *peer_id && marker.target == *target)
    }

    /// Export trust graph for persistence
    pub fn export(&self) -> ExportedTrustGraph {
        let graph = self.trust_graph.read().unwrap();
        let attestations = self.attestations.read().unwrap();

        let relationships = graph
            .iter()
            .map(|(peer_id, rel)| {
                let timestamp = rel
                    .last_seen
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                SerializableTrustRelationship {
                    peer_id: *peer_id,
                    trust_level: rel.trust_level,
                    verification_methods: rel.verification_methods.clone(),
                    last_seen_timestamp: timestamp,
                }
            })
            .collect();

        ExportedTrustGraph {
            relationships,
            attestations: attestations.clone(),
            revocations: self.revocations.read().unwrap().clone(),
            version: 1,
        }
    }

    /// Import trust graph from persisted data
    pub fn import(exported: ExportedTrustGraph) -> Self {
        let mut graph = HashMap::new();

        for rel in exported.relationships {
            let last_seen = SystemTime::UNIX_EPOCH + Duration::from_secs(rel.last_seen_timestamp);

            graph.insert(
                rel.peer_id,
                TrustRelationship {
                    peer_id: rel.peer_id,
                    trust_level: rel.trust_level,
                    verification_methods: rel.verification_methods,
                    last_seen,
                },
            );
        }

        Self {
            my_identity: None,
            trust_graph: Arc::new(RwLock::new(graph)),
            attestations: Arc::new(RwLock::new(exported.attestations)),
            revocations: Arc::new(RwLock::new(exported.revocations)),
            pending_revocation_broadcasts: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Revoke trust for a peer
    pub fn revoke_trust(
        &self,
        peer_id: &PeerId,
        reason: RevocationReason,
    ) -> Result<RevocationCertificate> {
        // Remove peer from trust graph
        self.trust_graph.write().unwrap().remove(peer_id);

        // Remove attestations for this peer
        self.attestations.write().unwrap().remove(peer_id);

        // Create revocation certificate
        let local_peer_id = self
            .my_identity
            .as_ref()
            .map(|id| id.peer_id)
            .unwrap_or([0u8; 32]);

        let cert = RevocationCertificate::new(*peer_id, local_peer_id, reason);
        self.revocations.write().unwrap().push(cert.clone());

        Ok(cert)
    }

    /// Apply a revocation certificate from a trusted revoker.
    pub fn apply_revocation_certificate(
        &self,
        cert: RevocationCertificate,
        revoker_public_key: [u8; 32],
    ) -> Result<()> {
        if !cert.verify_signature(&revoker_public_key)? {
            return Err(MeshInfinityError::CryptoError(
                "Invalid revocation certificate signature".to_string(),
            ));
        }

        if let Some(identity) = &self.my_identity {
            if cert.revoker != identity.peer_id {
                let level = self
                    .get_trust_level(&cert.revoker)
                    .unwrap_or(TrustLevel::Untrusted);
                if level < TrustLevel::Trusted {
                    return Err(MeshInfinityError::AuthError(
                        "Revoker not sufficiently trusted".to_string(),
                    ));
                }
            }
        }

        if self
            .revocations
            .read()
            .unwrap()
            .iter()
            .any(|existing| existing.target == cert.target && existing.timestamp == cert.timestamp)
        {
            return Ok(());
        }

        self.trust_graph.write().unwrap().remove(&cert.target);
        self.attestations.write().unwrap().remove(&cert.target);
        self.revocations.write().unwrap().push(cert);
        Ok(())
    }

    /// Apply temporal decay to trust relationships
    /// Reduces trust level for peers not seen recently
    pub fn apply_temporal_decay(&self) {
        let now = SystemTime::now();
        let mut graph = self.trust_graph.write().unwrap();

        for rel in graph.values_mut() {
            if let Ok(age) = now.duration_since(rel.last_seen) {
                // Decay after 30 days
                if age > Duration::from_secs(30 * 24 * 3600) {
                    rel.trust_level = match rel.trust_level {
                        TrustLevel::HighlyTrusted => TrustLevel::Trusted,
                        TrustLevel::Trusted => TrustLevel::Caution,
                        TrustLevel::Caution => TrustLevel::Untrusted,
                        TrustLevel::Untrusted => TrustLevel::Untrusted,
                    };
                }
            }
        }
    }

    /// Broadcast revocation to connected peers
    /// In a real implementation, this would send the revocation certificate
    /// to all trusted peers in the mesh
    pub fn broadcast_revocation(&self, cert: RevocationCertificate) -> Result<()> {
        // Queue for runtime delivery subsystem; this function no longer acts as a stub.
        if self
            .pending_revocation_broadcasts
            .read()
            .unwrap()
            .iter()
            .any(|queued| queued.target == cert.target && queued.timestamp == cert.timestamp)
        {
            return Ok(());
        }

        self.pending_revocation_broadcasts
            .write()
            .unwrap()
            .push_back(cert);
        Ok(())
    }

    /// Return and clear pending revocation broadcasts.
    pub fn drain_pending_revocation_broadcasts(&self) -> Vec<RevocationCertificate> {
        self.pending_revocation_broadcasts
            .write()
            .unwrap()
            .drain(..)
            .collect()
    }

    /// Return known revocation certificates.
    pub fn revocations(&self) -> Vec<RevocationCertificate> {
        self.revocations.read().unwrap().clone()
    }

    /// Update last_seen timestamp for a peer
    pub fn update_last_seen(&self, peer_id: &PeerId) -> Result<()> {
        if let Some(rel) = self.trust_graph.write().unwrap().get_mut(peer_id) {
            rel.last_seen = SystemTime::now();
        }
        Ok(())
    }
}

/// Convert TrustLevel enum to float for calculations
fn trust_level_to_f32(level: TrustLevel) -> f32 {
    match level {
        TrustLevel::Untrusted => 0.0,
        TrustLevel::Caution => 0.3,
        TrustLevel::Trusted => 0.7,
        TrustLevel::HighlyTrusted => 1.0,
    }
}

/// Convert float trust score back to TrustLevel
fn f32_to_trust_level(score: f32) -> TrustLevel {
    if score >= 0.85 {
        TrustLevel::HighlyTrusted
    } else if score >= 0.5 {
        TrustLevel::Trusted
    } else if score >= 0.2 {
        TrustLevel::Caution
    } else {
        TrustLevel::Untrusted
    }
}

fn derive_peer_id_from_public_key(public_key: &[u8; 32]) -> PeerId {
    const DOMAIN: &str = "meshinfinity-peer-id-v1";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN.as_bytes());
    hasher.update(public_key);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn attestation_fingerprint(attestation: &TrustAttestation) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(attestation.signable_message());
    hasher.update(&attestation.signature);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Keypair, Signer};
    use rand_core::OsRng;

    fn peer_id_from_key(pk: &[u8; 32]) -> PeerId {
        derive_peer_id_from_public_key(pk)
    }

    #[test]
    fn add_attestation_rejects_replay_duplicate() {
        let keypair = Keypair::generate(&mut OsRng);
        let endorser = peer_id_from_key(&keypair.public.to_bytes());
        let target = [9u8; 32];

        let wot = WebOfTrust::new();
        wot.add_peer(endorser, TrustLevel::Trusted, VerificationMethod::InPerson)
            .unwrap();

        let mut att = TrustAttestation::new(
            endorser,
            target,
            TrustLevel::Trusted,
            VerificationMethod::TrustedIntroduction,
            keypair.public.to_bytes(),
        );
        att.signature = keypair.sign(&att.signable_message()).to_bytes().to_vec();

        wot.add_attestation(att.clone()).unwrap();
        let second = wot.add_attestation(att);
        assert!(second.is_err());
    }

    #[test]
    fn add_attestation_rejects_public_key_identity_mismatch() {
        let signer = Keypair::generate(&mut OsRng);
        let wrong = Keypair::generate(&mut OsRng);
        let endorser = peer_id_from_key(&wrong.public.to_bytes());
        let target = [7u8; 32];

        let wot = WebOfTrust::new();
        wot.add_peer(endorser, TrustLevel::Trusted, VerificationMethod::InPerson)
            .unwrap();

        let mut att = TrustAttestation::new(
            endorser,
            target,
            TrustLevel::Trusted,
            VerificationMethod::TrustedIntroduction,
            signer.public.to_bytes(),
        );
        att.signature = signer.sign(&att.signable_message()).to_bytes().to_vec();

        assert!(wot.add_attestation(att).is_err());
    }
}
