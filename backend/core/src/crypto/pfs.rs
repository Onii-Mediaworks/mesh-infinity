use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

use ring::rand::{SecureRandom, SystemRandom};

use crate::core::PeerId;
use crate::error::{NetInfinityError, Result};

#[derive(Clone)]
pub struct SessionKeys {
    pub encryption_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

pub struct PfsManager {
    current_sessions: HashMap<PeerId, SessionKeys>,
    key_history: HashMap<PeerId, VecDeque<SessionKeys>>,
    rotation_interval: Duration,
    max_history: usize,
    rng: SystemRandom,
}

impl PfsManager {
    pub fn new(rotation_interval: Duration, max_history: usize) -> Self {
        Self {
            current_sessions: HashMap::new(),
            key_history: HashMap::new(),
            rotation_interval,
            max_history,
            rng: SystemRandom::new(),
        }
    }

    pub fn new_session(&mut self, peer_id: &PeerId) -> Result<SessionKeys> {
        let now = SystemTime::now();
        let session = SessionKeys {
            encryption_key: random_key(&self.rng)?,
            mac_key: random_key(&self.rng)?,
            created_at: now,
            expires_at: now + self.rotation_interval,
        };

        if let Some(previous) = self.current_sessions.insert(*peer_id, session.clone()) {
            let history = self.key_history.entry(*peer_id).or_insert_with(VecDeque::new);
            history.push_back(previous);
            while history.len() > self.max_history {
                history.pop_front();
            }
        }

        Ok(session)
    }

    pub fn ratchet_session(&mut self, peer_id: &PeerId) -> Result<SessionKeys> {
        let current = self
            .current_sessions
            .get_mut(peer_id)
            .ok_or(NetInfinityError::NoActiveSession)?;

        let now = SystemTime::now();
        current.encryption_key = random_key(&self.rng)?;
        current.mac_key = random_key(&self.rng)?;
        current.created_at = now;
        current.expires_at = now + self.rotation_interval;

        Ok(current.clone())
    }
}

fn random_key(rng: &SystemRandom) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    rng.fill(&mut key)
        .map_err(|_| NetInfinityError::CryptoError("random key generation failed".to_string()))?;
    Ok(key)
}
