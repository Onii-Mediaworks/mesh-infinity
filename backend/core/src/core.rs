// Core types and structures for SeasonCom
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;
use serde::{Serialize, Deserialize};

// Core types
pub type PeerId = [u8; 32];
pub type SessionId = [u8; 32];
pub type MessageId = [u8; 32];
pub type FileId = [u8; 32];

// Transport types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportType {
    Tor = 1,
    I2P = 2,
    Bluetooth = 5,
    Clearnet = 10,
}

// Message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPacket {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Protocol,
    pub payload: Vec<u8>,
    pub interface: String,
    pub timestamp: SystemTime,
    pub is_encrypted: bool,
    pub connection_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Custom(u8),
}

// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub public_key: [u8; 32],
    pub trust_level: TrustLevel,
    pub available_transports: Vec<TransportType>,
    pub last_seen: Option<SystemTime>,
    pub endpoint: Option<SocketAddr>,
}

// Trust levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    Untrusted = 0,
    Caution = 1,
    Trusted = 2,
    HighlyTrusted = 3,
}

// Transport quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportQuality {
    pub latency: std::time::Duration,
    pub bandwidth: u64,
    pub reliability: f32,
    pub cost: f32,
    pub congestion: f32,
}

// Configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub config_path: Option<String>,
    pub log_level: u8,
    pub enable_tor: bool,
    pub enable_clearnet: bool,
    pub mesh_discovery: bool,
    pub allow_relays: bool,
    pub enable_i2p: bool,
    pub enable_bluetooth: bool,
    pub wireguard_port: u16,
    pub max_peers: usize,
    pub max_connections: usize,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            config_path: None,
            log_level: 2, // Info level
            enable_tor: true,
            enable_clearnet: true,
            mesh_discovery: true,
            allow_relays: true,
            enable_i2p: false,
            enable_bluetooth: false,
            wireguard_port: 51820,
            max_peers: 100,
            max_connections: 50,
        }
    }
}
