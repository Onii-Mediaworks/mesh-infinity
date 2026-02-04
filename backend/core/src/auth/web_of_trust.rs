use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Deserialize, Serialize};

use crate::core::{PeerId, TrustLevel};
use crate::core::error::{MeshInfinityError, Result};

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
                "Invalid public key length".to_string()
            ));
        }

        let public_key = PublicKey::from_bytes(&self.endorser_public_key)
            .map_err(|e| MeshInfinityError::CryptoError(format!("Invalid public key: {}", e)))?;

        if self.signature.len() != 64 {
            return Ok(false);
        }

        let signature = Signature::new(
            self.signature[..64].try_into().unwrap()
        );

        let message = self.signable_message();
        Ok(public_key.verify(&message, &signature).is_ok())
    }
}

pub struct WebOfTrust {
    my_identity: Option<Identity>,
    trust_graph: Arc<RwLock<HashMap<PeerId, TrustRelationship>>>,
    attestations: Arc<RwLock<HashMap<PeerId, Vec<TrustAttestation>>>>,
}

impl WebOfTrust {
    pub fn new() -> Self {
        Self {
            my_identity: None,
            trust_graph: Arc::new(RwLock::new(HashMap::new())),
            attestations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_identity(identity: Identity) -> Self {
        Self {
            my_identity: Some(identity),
            trust_graph: Arc::new(RwLock::new(HashMap::new())),
            attestations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn identity(&self) -> Option<&Identity> {
        self.my_identity.as_ref()
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

    /// Calculate transitive trust level for a peer through the web of trust
    /// Uses breadth-first search with trust decay over distance
    pub fn calculate_transitive_trust(&self, target_peer: &PeerId, own_peer_id: &PeerId) -> TrustLevel {
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
            if let Some(path_trust) = self.find_trust_path(
                &graph,
                own_peer_id,
                target_peer,
                &visited_global,
            ) {
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
                self.add_peer(*target, trust_level, VerificationMethod::TrustedIntroduction)?;
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
        self.trust_graph
            .read()
            .unwrap()
            .keys()
            .copied()
            .collect()
    }

    /// Get the full trust relationship for a peer
    pub fn get_relationship(&self, peer_id: &PeerId) -> Option<TrustRelationship> {
        self.trust_graph
            .read()
            .unwrap()
            .get(peer_id)
            .cloned()
    }

    /// Add a cryptographically signed trust attestation
    /// Verifies the signature before accepting
    pub fn add_attestation(&self, attestation: TrustAttestation) -> Result<()> {
        // Verify the signature
        if !attestation.verify_signature()? {
            return Err(MeshInfinityError::CryptoError(
                "Invalid attestation signature".to_string()
            ));
        }

        // Verify the endorser is trusted
        if let Some(endorser_trust) = self.get_trust_level(&attestation.endorser_id) {
            if endorser_trust < TrustLevel::Trusted {
                return Err(MeshInfinityError::AuthError(
                    "Endorser not sufficiently trusted".to_string()
                ));
            }
        } else {
            return Err(MeshInfinityError::AuthError(
                "Endorser not in trust graph".to_string()
            ));
        }

        // Store the attestation
        self.attestations
            .write()
            .unwrap()
            .entry(attestation.target_id)
            .or_insert_with(Vec::new)
            .push(attestation.clone());

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

    pub fn verify_peer(&self, peer_id: &PeerId, trust_markers: &[TrustMarker]) -> TrustLevel {
        if let Some(identity) = &self.my_identity {
            if peer_id == &identity.peer_id {
                return TrustLevel::HighlyTrusted;
            }
        }

        let direct = self.get_trust_level(peer_id).unwrap_or(TrustLevel::Untrusted);
        let propagated = self.calculate_propagated_trust(peer_id, trust_markers);
        let attested = self.calculate_attested_trust(peer_id);

        direct.max(propagated).max(attested)
    }

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

            total_trust += u32::from(weight) * u32::from(trust_level as u8);
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
