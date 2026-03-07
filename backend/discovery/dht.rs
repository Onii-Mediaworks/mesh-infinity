//! Lightweight DHT-like peer index for discovery sharing.
//!
//! This module provides a local Kademlia-style distance index over [`PeerId`]
//! values. It does not perform transport/network RPC by itself; instead it
//! supports "share what you know" workflows where callers ingest observed peers
//! and request nearest-neighbor sets for exchange with other nodes.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::core::{PeerId, PeerInfo};

/// Minimal DHT-like peer record store keyed by [`PeerId`].
pub struct DiscoveryDht {
    peers: HashMap<PeerId, PeerInfo>,
    last_updated: HashMap<PeerId, SystemTime>,
}

impl Default for DiscoveryDht {
    /// Construct default value for this type.
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryDht {
    /// Create an empty DHT-like peer index.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            last_updated: HashMap::new(),
        }
    }

    /// Insert or update a peer record in the index.
    pub fn upsert(&mut self, peer: PeerInfo) {
        let peer_id = peer.peer_id;
        self.peers.insert(peer_id, peer);
        self.last_updated.insert(peer_id, SystemTime::now());
    }

    /// Merge a batch of peers into the index.
    pub fn upsert_many(&mut self, peers: Vec<PeerInfo>) {
        for peer in peers {
            self.upsert(peer);
        }
    }

    /// Return all known peers currently in the index.
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers.values().cloned().collect()
    }

    /// Return up to `limit` peers nearest to `target` by XOR distance.
    pub fn nearest_peers(&self, target: &PeerId, limit: usize) -> Vec<PeerInfo> {
        let mut items: Vec<(PeerInfo, [u8; 32])> = self
            .peers
            .values()
            .cloned()
            .map(|peer| {
                let distance = xor_distance(&peer.peer_id, target);
                (peer, distance)
            })
            .collect();

        items.sort_by(|(_, a), (_, b)| a.cmp(b));
        items
            .into_iter()
            .take(limit)
            .map(|(peer, _)| peer)
            .collect()
    }
}

/// Compute XOR distance for two peer identifiers.
fn xor_distance(a: &PeerId, b: &PeerId) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = a[idx] ^ b[idx];
    }
    out
}
