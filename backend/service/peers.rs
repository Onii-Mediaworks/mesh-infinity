//! Peer pairing and peer-summary synchronization.
//!
//! This module owns pairing-code ingestion and backend peer summary updates.

use std::time::SystemTime;

use crate::core::core::{PeerInfo, TransportType};
use crate::core::error::Result;
use crate::core::mesh::VerificationMethod;
use crate::core::TrustLevel as CoreTrustLevel;

use super::{
    peer_id_from_pairing_code, peer_id_string, random_peer_id, trust_label, MeshInfinityService,
    PeerSummary,
};
use crate::auth::web_of_trust::VerificationMethod as WotVerificationMethod;

impl MeshInfinityService {
    /// Pair a peer using pairing code and create/update peer summary.
    pub fn pair_peer(&self, code: &str) -> Result<()> {
        let trimmed = code.trim();
        if trimmed.is_empty() {
            return Ok(());
        }

        let peer_id = peer_id_from_pairing_code(trimmed).unwrap_or_else(random_peer_id);
        let peer_info = PeerInfo {
            peer_id,
            public_key: [0u8; 32],
            trust_level: CoreTrustLevel::Caution,
            available_transports: vec![TransportType::Tor, TransportType::Clearnet],
            last_seen: Some(SystemTime::now()),
            endpoint: None,
            transport_endpoints: std::collections::HashMap::new(),
        };

        self.peers.add_peer(peer_info)?;
        self.peers.update_trust_level(
            &peer_id,
            CoreTrustLevel::Caution,
            VerificationMethod::SharedSecret,
        )?;
        let _ = self.web_of_trust.add_peer(
            peer_id,
            CoreTrustLevel::Caution,
            WotVerificationMethod::SharedSecret,
        );

        {
            let short_code: String = trimmed.chars().take(6).collect();
            let mut state = self.state.write().unwrap();
            let peer_id_text = peer_id_string(&peer_id);
            if let Some(existing) = state.peers.iter_mut().find(|peer| peer.id == peer_id_text) {
                existing.name = format!("Peer {}", short_code);
                existing.trust_level = CoreTrustLevel::Caution as i32;
                existing.status = trust_label(CoreTrustLevel::Caution);
            } else {
                state.peers.insert(
                    0,
                    PeerSummary {
                        id: peer_id_text,
                        name: format!("Peer {}", short_code),
                        trust_level: CoreTrustLevel::Caution as i32,
                        status: trust_label(CoreTrustLevel::Caution),
                    },
                );
            }
        }

        // Reconciliation attempt: flush passive fallback queue for this peer.
        let _ = self.drain_passive_for_peer(&peer_id);
        Ok(())
    }
}
