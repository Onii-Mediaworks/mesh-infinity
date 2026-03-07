//! Forward-secrecy session key manager.
//!
//! Maintains per-peer active session keys, rotates/ratchets key material, and
//! keeps bounded key history for short-lived recovery windows.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

use crate::core::core::PeerId;
use crate::core::error::{MeshInfinityError, Result};
use rand_core::{OsRng, RngCore};

#[derive(Clone)]
pub struct SessionKeys {
    pub encryption_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

pub struct PFSManager {
    current_sessions: HashMap<PeerId, SessionKeys>,
    key_history: HashMap<PeerId, VecDeque<SessionKeys>>,
    rotation_interval: Duration,
    max_history: usize,
}

pub type PfsManager = PFSManager;

impl PFSManager {
    /// Create PFS manager with rotation cadence and history limit.
    pub fn new(rotation_interval: Duration, max_history: usize) -> Self {
        Self {
            current_sessions: HashMap::new(),
            key_history: HashMap::new(),
            rotation_interval,
            max_history,
        }
    }

    /// Create a fresh session for `peer_id`, pushing previous keys into history.
    pub fn new_session(&mut self, peer_id: &PeerId) -> Result<SessionKeys> {
        let now = SystemTime::now();
        let session = SessionKeys {
            encryption_key: random_key()?,
            mac_key: random_key()?,
            created_at: now,
            expires_at: now + self.rotation_interval,
        };

        if let Some(previous) = self.current_sessions.insert(*peer_id, session.clone()) {
            let history = self.key_history.entry(*peer_id).or_default();
            history.push_back(previous);
            while history.len() > self.max_history {
                history.pop_front();
            }
        }

        Ok(session)
    }

    /// Ratchet key material for an existing session in-place.
    pub fn ratchet_session(&mut self, peer_id: &PeerId) -> Result<SessionKeys> {
        let current = self
            .current_sessions
            .get_mut(peer_id)
            .ok_or(MeshInfinityError::NoActiveSession)?;

        current.encryption_key = random_key()?;
        current.mac_key = random_key()?;
        current.created_at = SystemTime::now();
        current.expires_at = current.created_at + self.rotation_interval;

        Ok(current.clone())
    }
}

/// Generate cryptographically random 256-bit key material.
fn random_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Ok(key)
}
