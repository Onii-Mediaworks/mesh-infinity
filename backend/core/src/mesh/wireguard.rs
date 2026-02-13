use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use boringtun::crypto::x25519::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::{Tunn, TunnResult};

use crate::core::{PeerId, PeerInfo, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::transport::TransportManager;
use super::obfuscation::{TrafficObfuscator, ObfuscationMode};

#[derive(Clone)]
pub struct WGConfig {
    pub interface: String,
    pub private_key: [u8; 32],
    pub port: u16,
    pub mtu: u16,
}

pub struct WireGuardMesh {
    config: WGConfig,
    private_key: Arc<X25519SecretKey>,
    public_key: [u8; 32],
    peers: Arc<Mutex<HashMap<PeerId, WGPeer>>>,
    ip_to_peer: Arc<Mutex<HashMap<IpAddr, PeerId>>>,
    next_index: AtomicU32,
    transport_manager: Option<Arc<TransportManager>>,
    obfuscator: Arc<Mutex<TrafficObfuscator>>,
}

pub struct WGPeer {
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<IpAddr>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
    pub latest_handshake: Option<std::time::SystemTime>,
    tunnel: Box<Tunn>,
    last_outbound: Option<Vec<u8>>,
}

impl WireGuardMesh {
    pub fn new(config: WGConfig) -> Result<Self> {
        let secret = secret_from_bytes(config.private_key)?;
        let public_key = secret
            .public_key()
            .as_bytes()
            .try_into()
            .map_err(|_| MeshInfinityError::WireGuardError("Invalid public key length".to_string()))?;

        Ok(Self {
            config,
            private_key: Arc::new(secret),
            public_key,
            peers: Arc::new(Mutex::new(HashMap::new())),
            ip_to_peer: Arc::new(Mutex::new(HashMap::new())),
            next_index: AtomicU32::new(1),
            transport_manager: None,
            obfuscator: Arc::new(Mutex::new(TrafficObfuscator::new(ObfuscationMode::None))),
        })
    }

    pub fn config(&self) -> &WGConfig {
        &self.config
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub fn add_peer(
        &self,
        peer_id: PeerId,
        public_key: [u8; 32],
        allowed_ips: Vec<IpAddr>,
        endpoint: Option<SocketAddr>,
        persistent_keepalive: Option<u16>,
    ) -> Result<()> {
        let index = self.next_index.fetch_add(1, Ordering::Relaxed);
        let peer_key = Arc::new(X25519PublicKey::from(&public_key[..]));
        let tunnel = Tunn::new(
            Arc::clone(&self.private_key),
            Arc::clone(&peer_key),
            None,
            persistent_keepalive,
            index,
            None,
        )
        .map_err(|err| MeshInfinityError::WireGuardError(err.to_string()))?;

        let peer = WGPeer {
            public_key,
            allowed_ips: allowed_ips.clone(),
            endpoint,
            persistent_keepalive,
            latest_handshake: None,
            tunnel,
            last_outbound: None,
        };

        // Update IP to peer mapping
        let mut ip_map = self.ip_to_peer.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("IP map lock poisoned: {}", e)))?;
        for ip in &allowed_ips {
            ip_map.insert(*ip, peer_id);
        }
        drop(ip_map);

        self.peers.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Peers lock poisoned: {}", e)))?
            .insert(peer_id, peer);
        Ok(())
    }

    pub fn remove_peer(&self, peer_id: &PeerId) -> Result<()> {
        let mut peers = self.peers.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Peers lock poisoned: {}", e)))?;

        // Get IPs to remove from mapping
        if let Some(peer) = peers.get(peer_id) {
            let mut ip_map = self.ip_to_peer.lock()
                .map_err(|e| MeshInfinityError::LockError(format!("IP map lock poisoned: {}", e)))?;
            for ip in &peer.allowed_ips {
                ip_map.remove(ip);
            }
        }

        peers.remove(peer_id);
        Ok(())
    }

    pub fn get_peer_by_ip(&self, ip: &IpAddr) -> Option<PeerId> {
        let ip_map = self.ip_to_peer.lock().ok()?;
        ip_map.get(ip).copied()
    }

    pub fn set_transport_manager(&mut self, transport_manager: Arc<TransportManager>) {
        self.transport_manager = Some(transport_manager);
    }

    pub fn send_message(&self, target: &PeerId, payload: &[u8]) -> Result<()> {
        let mut peers = self.peers.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Peers lock poisoned: {}", e)))?;
        let peer = peers
            .get_mut(target)
            .ok_or_else(|| MeshInfinityError::PeerNotFound(format!("{:?}", target)))?;

        // Encapsulate with WireGuard
        let mut dst = vec![0u8; 65535];
        let encrypted_packet = match peer.tunnel.encapsulate(payload, &mut dst) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            TunnResult::Done => return Ok(()),
            TunnResult::Err(err) => return Err(MeshInfinityError::WireGuardError(format!("{err:?}"))),
            _ => return Ok(()),
        };

        // Apply obfuscation if enabled
        let obfuscated_packet = {
            let obfuscator = self.obfuscator.lock()
                .map_err(|e| MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e)))?;
            obfuscator.obfuscate(&encrypted_packet)?
        };

        peer.latest_handshake = Some(std::time::SystemTime::now());

        // If transport manager is available, send over network
        if let Some(ref transport_mgr) = self.transport_manager {
            // Create PeerInfo for connection
            let peer_info = PeerInfo {
                peer_id: *target,
                public_key: peer.public_key,
                trust_level: crate::core::TrustLevel::Trusted, // Default for now
                available_transports: vec![TransportType::Clearnet],
                last_seen: Some(std::time::SystemTime::now()),
                endpoint: peer.endpoint,
            };

            // Try to get connection and send
            // For now, we'll use a blocking approach - TODO: make this properly async
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let transport_mgr = Arc::clone(transport_mgr);
                let packet = obfuscated_packet.clone();

                match handle.block_on(async {
                    transport_mgr.get_best_connection(&peer_info, &[TransportType::Clearnet]).await
                }) {
                    Ok(mut connection) => {
                        connection.send(&packet)?;
                    }
                    Err(_) => {
                        // Fallback: store for manual consumption if no transport available
                        peer.last_outbound = Some(obfuscated_packet);
                    }
                }
            } else {
                // No tokio runtime: store for manual consumption
                peer.last_outbound = Some(obfuscated_packet);
            }
        } else {
            // No transport manager: store for manual consumption (backward compatibility)
            peer.last_outbound = Some(obfuscated_packet);
        }

        Ok(())
    }

    pub fn receive_message(&self, source: &PeerId, obfuscated: &[u8]) -> Result<Vec<u8>> {
        // Deobfuscate first
        let encrypted = {
            let obfuscator = self.obfuscator.lock()
                .map_err(|e| MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e)))?;
            obfuscator.deobfuscate(obfuscated)?
        };

        let mut peers = self.peers.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Peers lock poisoned: {}", e)))?;
        let peer = peers
            .get_mut(source)
            .ok_or_else(|| MeshInfinityError::PeerNotFound(format!("{:?}", source)))?;

        let mut dst = vec![0u8; 65535];
        match peer.tunnel.decapsulate(None, &encrypted, &mut dst) {
            TunnResult::WriteToTunnelV4(packet, _addr) => Ok(packet.to_vec()),
            TunnResult::WriteToTunnelV6(packet, _addr) => Ok(packet.to_vec()),
            TunnResult::Err(e) => Err(MeshInfinityError::WireGuardError(format!("{:?}", e))),
            _ => Ok(Vec::new()),
        }
    }

    pub fn consume_outbound_packet(&self, target: &PeerId) -> Option<Vec<u8>> {
        let mut peers = self.peers.lock().ok()?;
        peers.get_mut(target).and_then(|peer| peer.last_outbound.take())
    }

    /// Enable traffic obfuscation
    pub fn set_obfuscation(&self, mode: ObfuscationMode) -> Result<()> {
        let mut obfuscator = self.obfuscator.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e)))?;
        *obfuscator = TrafficObfuscator::new(mode);
        Ok(())
    }

    /// Enable traffic obfuscation with a specific XOR key
    pub fn set_obfuscation_with_key(&self, mode: ObfuscationMode, key: [u8; 32]) -> Result<()> {
        let mut obfuscator = self.obfuscator.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e)))?;
        *obfuscator = TrafficObfuscator::with_key(mode, key);
        Ok(())
    }

    /// Get the current obfuscation mode
    pub fn get_obfuscation_mode(&self) -> Result<ObfuscationMode> {
        let obfuscator = self.obfuscator.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e)))?;
        Ok(obfuscator.mode())
    }
}

fn secret_from_bytes(bytes: [u8; 32]) -> Result<X25519SecretKey> {
    let hex = hex_encode(&bytes);
    X25519SecretKey::from_str(&hex)
        .map_err(|_| MeshInfinityError::WireGuardError("Invalid private key".to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}
