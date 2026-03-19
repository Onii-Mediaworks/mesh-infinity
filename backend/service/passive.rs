//! Passive fallback queue and reconciliation operations.
//!
//! This module owns encrypted passive envelope buffering, replay protection,
//! bounded retention, and reconciliation delivery logic.

use std::time::SystemTime;

use crate::core::error::Result;
use crate::core::PeerId;

use super::{derive_passive_session_key, parse_peer_id_hex, MeshInfinityService};

impl MeshInfinityService {
    /// Return the latest passive-ack dedupe checkpoint for a peer, if present.
    pub fn passive_ack_checkpoint(&self, peer_id: &PeerId) -> Option<String> {
        self.state
            .read()
            .unwrap()
            .passive_acked
            .get(peer_id)
            .and_then(|history| history.back().cloned())
    }

    /// Compact passive fallback buffers by pruning expired envelopes and stale
    /// ack history entries.
    pub fn compact_passive_state(&self) -> usize {
        let now = SystemTime::now();
        let mut removed = 0usize;
        let mut state = self.state.write().unwrap();

        for queue in state.passive_outbox.values_mut() {
            let before = queue.len();
            queue.retain(|item| now <= item._expires_at);
            if queue.len() > super::MAX_PASSIVE_ENVELOPES_PER_PEER {
                let overflow = queue.len() - super::MAX_PASSIVE_ENVELOPES_PER_PEER;
                queue.drain(0..overflow);
            }
            removed = removed.saturating_add(before.saturating_sub(queue.len()));
        }
        state.passive_outbox.retain(|_, queue| !queue.is_empty());

        for history in state.passive_acked.values_mut() {
            while history.len() > super::MAX_PASSIVE_ACK_HISTORY {
                history.pop_front();
                removed = removed.saturating_add(1);
            }
        }
        state.passive_acked.retain(|_, history| !history.is_empty());

        removed
    }

    /// Attempt to decrypt and deliver queued passive envelopes for `peer_id`.
    ///
    /// Successfully delivered items are acked; failed decrypt/delivery entries
    /// are kept for a future reconciliation attempt.
    pub(super) fn drain_passive_for_peer(&self, peer_id: &PeerId) -> Result<usize> {
        let pending = {
            let mut state = self.state.write().unwrap();
            state.passive_outbox.remove(peer_id).unwrap_or_default()
        };

        if pending.is_empty() {
            return Ok(0);
        }

        let key = {
            let local_peer = {
                let state = self.state.read().unwrap();
                match parse_peer_id_hex(&state.settings.local_peer_id) {
                    Some(id) => id,
                    None => return Err(crate::core::error::MeshInfinityError::InvalidInput(
                        "local peer ID is not set or invalid".into(),
                    )),
                }
            };
            derive_passive_session_key(&local_peer, peer_id)
        };

        let mut delivered = 0usize;
        let mut remaining = Vec::new();
        let mut acked = Vec::new();

        for envelope in pending {
            if SystemTime::now() > envelope._expires_at {
                continue;
            }

            let plaintext = {
                let crypto = self.message_crypto.lock().unwrap();
                crypto.session_decrypt(&key, &envelope._ciphertext)
            };

            match plaintext {
                Ok(data) => {
                    let msg = String::from_utf8_lossy(&data).to_string();
                    if self.receive_message(*peer_id, None, &msg).is_ok() {
                        delivered = delivered.saturating_add(1);
                        acked.push(envelope._dedupe_key.clone());
                    } else {
                        remaining.push(envelope);
                    }
                }
                Err(_) => remaining.push(envelope),
            }
        }

        if !remaining.is_empty() || !acked.is_empty() {
            let mut state = self.state.write().unwrap();
            if !remaining.is_empty() {
                state
                    .passive_outbox
                    .entry(*peer_id)
                    .or_default()
                    .extend(remaining);
            }
            for dedupe in acked {
                let history = state.passive_acked.entry(*peer_id).or_default();
                if !history.iter().any(|item| item == &dedupe) {
                    history.push_back(dedupe);
                    while history.len() > super::MAX_PASSIVE_ACK_HISTORY {
                        history.pop_front();
                    }
                }
            }
        }

        Ok(delivered)
    }
}
