use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use boringtun::crypto::x25519::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::{Tunn, TunnResult};

use crate::core::core::{PeerId, TransportType};
use crate::core::error::{MeshInfinityError, Result};

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
    routing_table: Arc<Mutex<RoutingTable>>,
    next_index: AtomicU32,
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

pub struct RoutingTable {
    routes: HashMap<PeerId, RouteInfo>,
}

#[derive(Clone)]
pub struct RouteInfo {
    pub primary_path: PathInfo,
    pub backup_paths: Vec<PathInfo>,
    pub last_updated: std::time::SystemTime,
    pub quality_score: f32,
}

#[derive(Clone)]
pub struct PathInfo {
    pub transport: TransportType,
    pub endpoint: Endpoint,
    pub latency: Option<std::time::Duration>,
    pub reliability: f32,
    pub bandwidth: Option<u64>,
    pub cost: f32,
}

#[derive(Clone)]
pub struct Endpoint {
    pub peer_id: PeerId,
    pub address: SocketAddr,
}

impl WireGuardMesh {
    pub fn new(config: WGConfig) -> Result<Self> {
        let secret = secret_from_bytes(config.private_key)?;
        let public_key = secret.public_key().as_bytes().try_into().unwrap_or([0u8; 32]);

        Ok(Self {
            config,
            private_key: Arc::new(secret),
            public_key,
            peers: Arc::new(Mutex::new(HashMap::new())),
            routing_table: Arc::new(Mutex::new(RoutingTable::new())),
            next_index: AtomicU32::new(1),
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

        let mut routing_table = self.routing_table.lock().unwrap();
        for ip in &allowed_ips {
            routing_table.add_route(*ip, public_key);
        }
        drop(routing_table);

        self.peers.lock().unwrap().insert(peer_id, peer);
        Ok(())
    }

    pub fn remove_peer(&self, peer_id: &PeerId) -> Result<()> {
        let mut routing_table = self.routing_table.lock().unwrap();
        routing_table.remove_peer(peer_id);
        drop(routing_table);

        self.peers.lock().unwrap().remove(peer_id);
        Ok(())
    }

    pub fn send_message(&self, target: &PeerId, payload: &[u8]) -> Result<()> {
        let mut peers = self.peers.lock().unwrap();
        let peer = peers
            .get_mut(target)
            .ok_or_else(|| MeshInfinityError::PeerNotFound(format!("{:?}", target)))?;

        let mut dst = vec![0u8; 65535];
        match peer.tunnel.encapsulate(payload, &mut dst) {
            TunnResult::WriteToNetwork(packet) => {
                peer.last_outbound = Some(packet.to_vec());
                peer.latest_handshake = Some(std::time::SystemTime::now());
                Ok(())
            }
            TunnResult::Done => Ok(()),
            TunnResult::Err(err) => Err(MeshInfinityError::WireGuardError(format!(
                "{err:?}"
            ))),
            _ => Ok(()),
        }
    }

    pub fn consume_outbound_packet(&self, target: &PeerId) -> Option<Vec<u8>> {
        let mut peers = self.peers.lock().unwrap();
        peers.get_mut(target).and_then(|peer| peer.last_outbound.take())
    }
}

impl RoutingTable {
    pub fn new() -> Self {
        Self { routes: HashMap::new() }
    }

    pub fn add_route(&mut self, ip: IpAddr, peer_id: [u8; 32]) {
        let peer_id_array: PeerId = peer_id;
        self.routes.insert(
            peer_id_array,
            RouteInfo {
                primary_path: PathInfo {
                    transport: TransportType::Tor,
                    endpoint: Endpoint {
                        peer_id: peer_id_array,
                        address: SocketAddr::new(ip, 51820),
                    },
                    latency: None,
                    reliability: 0.9,
                    bandwidth: None,
                    cost: 0.1,
                },
                backup_paths: Vec::new(),
                last_updated: std::time::SystemTime::now(),
                quality_score: 0.9,
            },
        );
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.routes.remove(peer_id);
    }

    pub fn get_best_route(&self, target: &PeerId) -> Option<&RouteInfo> {
        self.routes.get(target)
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
