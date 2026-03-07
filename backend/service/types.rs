//! Public service-facing data models.
//!
//! This file defines stable backend service types consumed by callers (FFI/UI)
//! and by service submodules. It intentionally excludes runtime state internals.

use crate::core::core::{MeshConfig, PeerId, TransportType, TrustLevel as CoreTrustLevel};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeMode {
    Client,
    Server,
    Dual,
}

#[derive(Clone, Debug)]
pub struct RoomSummary {
    pub id: String,
    pub name: String,
    pub last_message: String,
    pub unread_count: i32,
    pub timestamp: String,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub id: String,
    pub room_id: String,
    pub sender: String,
    pub text: String,
    pub timestamp: String,
    pub is_outgoing: bool,
}

#[derive(Clone, Debug)]
pub struct PeerSummary {
    pub id: String,
    pub name: String,
    pub trust_level: i32,
    pub status: String,
}

#[derive(Clone, Debug)]
pub struct FileTransferSummary {
    pub id: String,
    pub peer_id: String,
    pub name: String,
    pub size_bytes: u64,
    pub transferred_bytes: u64,
    pub status: String,
    pub direction: String,
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub node_mode: NodeMode,
    pub enable_tor: bool,
    pub enable_clearnet: bool,
    pub mesh_discovery: bool,
    pub allow_relays: bool,
    pub enable_i2p: bool,
    pub enable_bluetooth: bool,
    pub enable_rf: bool,
    pub pairing_code: String,
    pub local_peer_id: String,
}

#[derive(Clone, Debug)]
pub struct IdentitySummary {
    pub peer_id: PeerId,
    pub public_key: [u8; 32],
    pub dh_public: [u8; 32],
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub initial_mode: NodeMode,
    pub mesh_config: MeshConfig,
    pub identity_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HostedServiceSummary {
    pub id: String,
    pub name: String,
    pub path: String,
    pub address: String,
    pub enabled: bool,
    pub min_trust_level: i32,
    pub allowed_transports: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct HostedServicePolicy {
    pub min_trust_level: CoreTrustLevel,
    pub allowed_transports: Vec<TransportType>,
}

#[derive(Clone, Copy, Debug)]
pub struct NetworkStatsSummary {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_connections: usize,
    pub pending_routes: usize,
    pub delivered_routes: u64,
    pub failed_routes: u64,
}

#[derive(Clone, Debug)]
pub struct ReconnectSyncSnapshot {
    pub missed_messages: Vec<Message>,
    pub resumable_transfers: Vec<FileTransferSummary>,
}

impl Default for ServiceConfig {
    /// Provide a safe baseline service configuration for local startup.
    fn default() -> Self {
        Self {
            initial_mode: NodeMode::Client,
            mesh_config: MeshConfig::default(),
            identity_name: None,
        }
    }
}

impl Default for HostedServicePolicy {
    /// Provide secure default hosted-service access policy.
    fn default() -> Self {
        Self {
            min_trust_level: CoreTrustLevel::Trusted,
            allowed_transports: vec![
                TransportType::Tor,
                TransportType::I2P,
                TransportType::Bluetooth,
            ],
        }
    }
}
