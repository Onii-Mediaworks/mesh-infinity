use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use crossbeam_channel::{unbounded, Receiver, Sender};
use std::time::{Duration, SystemTime};

use getrandom::getrandom;
use ed25519_dalek::Signer;
use crate::auth::identity::IdentityManager;
use crate::auth::web_of_trust::{
    Identity as WotIdentity, TrustAttestation, VerificationMethod as WotVerificationMethod,
    WebOfTrust,
};
use crate::core::core::{
    MeshConfig, PeerId, PeerInfo, TransportType, TrustLevel as CoreTrustLevel,
};
use crate::core::file_transfer::{
    FileMetadata, FileTransferManager, TransferDirection, TransferItem, TransferStatus,
};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::crypto::PfsManager;
use crate::core::discovery::DiscoveryService;
use crate::core::mesh::{
    EncryptedPayload, Endpoint, MessagePriority, MessageRouter, OutboundMessage, PathInfo,
    PeerManager, VerificationMethod,
};
use crate::transport::TransportManagerImpl;
use time::format_description;

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

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            initial_mode: NodeMode::Client,
            mesh_config: MeshConfig::default(),
            identity_name: None,
        }
    }
}

struct ServiceState {
    rooms: Vec<RoomSummary>,
    messages: HashMap<String, Vec<Message>>,
    peers: Vec<PeerSummary>,
    active_room_id: Option<String>,
    settings: Settings,
    mesh_config: MeshConfig,
    message_listeners: Vec<Sender<Message>>,
    transfer_listeners: Vec<Sender<FileTransferSummary>>,
}

pub struct MeshInfinityService {
    state: Arc<RwLock<ServiceState>>,
    peers: PeerManager,
    identity_manager: IdentityManager,
    web_of_trust: WebOfTrust,
    file_transfers: Arc<Mutex<FileTransferManager>>,
    transport_manager: TransportManagerImpl,
    message_router: MessageRouter,
    pfs_manager: Arc<Mutex<PfsManager>>,
    #[allow(dead_code)]
    discovery: Arc<Mutex<DiscoveryService>>,
}

impl MeshInfinityService {
    pub fn new(config: ServiceConfig) -> Self {
        let mut identity_manager = IdentityManager::new();
        let identity_peer_id = identity_manager
            .generate_identity(config.identity_name.clone())
            .unwrap_or_else(|_| random_peer_id());
        let wot_identity = identity_manager
            .get_primary_identity()
            .map(|identity| WotIdentity {
                peer_id: identity.peer_id,
                public_key: identity.keypair.public.to_bytes(),
                name: identity.name.clone(),
            })
            .unwrap_or_else(|| WotIdentity {
                peer_id: identity_peer_id,
                public_key: [0u8; 32],
                name: config.identity_name.clone(),
            });
        let web_of_trust = WebOfTrust::new(wot_identity);
        let pairing_code = pairing_code_from_peer_id(&identity_peer_id);
        let mesh_config = config.mesh_config;
        let transport_manager = TransportManagerImpl::new();
        transport_manager.set_tor_enabled(mesh_config.enable_tor);
        transport_manager.set_clearnet_enabled(mesh_config.enable_clearnet);
        transport_manager.set_i2p_enabled(mesh_config.enable_i2p);
        transport_manager.set_bluetooth_enabled(mesh_config.enable_bluetooth);
        let pfs_manager = Arc::new(Mutex::new(PfsManager::new(
            Duration::from_secs(60 * 60),
            8,
        )));
        let message_router = MessageRouter::new(transport_manager.get_manager());

        let state = ServiceState {
            rooms: Vec::new(),
            messages: HashMap::new(),
            peers: Vec::new(),
            active_room_id: None,
            settings: Settings {
                node_mode: config.initial_mode,
                enable_tor: mesh_config.enable_tor,
                enable_clearnet: mesh_config.enable_clearnet,
                mesh_discovery: mesh_config.mesh_discovery,
                allow_relays: mesh_config.allow_relays,
                enable_i2p: mesh_config.enable_i2p,
                enable_bluetooth: mesh_config.enable_bluetooth,
                pairing_code,
                local_peer_id: peer_id_string(&identity_peer_id),
            },
            mesh_config,
            message_listeners: Vec::new(),
            transfer_listeners: Vec::new(),
        };

        Self {
            state: Arc::new(RwLock::new(state)),
            peers: PeerManager::new(),
            identity_manager,
            web_of_trust,
            file_transfers: Arc::new(Mutex::new(FileTransferManager::new(64 * 1024))),
            transport_manager,
            message_router,
            pfs_manager,
            discovery: Arc::new(Mutex::new(DiscoveryService::new())),
        }
    }

    pub fn rooms(&self) -> Vec<RoomSummary> {
        self.state.read().unwrap().rooms.clone()
    }

    pub fn peers(&self) -> Vec<PeerSummary> {
        self.state.read().unwrap().peers.clone()
    }

    pub fn file_transfers(&self) -> Vec<FileTransferSummary> {
        let transfers = self.file_transfers.lock().unwrap().transfers();
        transfers
            .into_iter()
            .map(|item| transfer_summary(&item))
            .collect()
    }

    pub fn queue_file_send(&self, peer_id: &str, name: &str, size_bytes: u64) -> Result<String> {
        let peer_id = peer_id_from_pairing_code(peer_id).ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("invalid peer id".to_string())
        })?;
        let metadata = FileMetadata::new(name, size_bytes);
        let mut manager = self.file_transfers.lock().unwrap();
        let id = manager.enqueue_send(peer_id, metadata)?;
        Ok(file_id_string(&id))
    }

    pub fn queue_file_receive(
        &self,
        peer_id: &str,
        name: &str,
        size_bytes: u64,
    ) -> Result<String> {
        let peer_id = peer_id_from_pairing_code(peer_id).ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("invalid peer id".to_string())
        })?;
        let metadata = FileMetadata::new(name, size_bytes);
        let mut manager = self.file_transfers.lock().unwrap();
        let id = manager.enqueue_receive(peer_id, metadata)?;
        Ok(file_id_string(&id))
    }

    pub fn next_file_transfer(&self) -> Result<Option<FileTransferSummary>> {
        let mut manager = self.file_transfers.lock().unwrap();
        manager
            .next_queued()
            .map(|item| item.map(|item| transfer_summary(&item)))
    }

    pub fn update_file_transfer_progress(
        &self,
        transfer_id: &str,
        bytes: u64,
    ) -> Result<FileTransferSummary> {
        let file_id = file_id_from_string(transfer_id)
            .ok_or_else(|| MeshInfinityError::InvalidConfiguration("invalid file id".to_string()))?;
        let mut manager = self.file_transfers.lock().unwrap();
        manager.update_progress(&file_id, bytes)?;
        let item = manager
            .transfer(&file_id)
            .ok_or_else(|| MeshInfinityError::FileTransferError("transfer not found".to_string()))?;
        let summary = transfer_summary(&item);
        
        // Notify transfer listeners
        self.notify_transfer_listeners(&summary);
        
        Ok(summary)
    }

    pub fn settings(&self) -> Settings {
        let state = self.state.read().unwrap();
        let mut settings = state.settings.clone();
        sync_settings_from_mesh(&mut settings, &state.mesh_config);
        settings
    }

    pub fn active_room_id(&self) -> Option<String> {
        self.state.read().unwrap().active_room_id.clone()
    }

    pub fn active_room_title(&self) -> String {
        let state = self.state.read().unwrap();
        let active_id = state.active_room_id.as_deref().unwrap_or_default();
        state
            .rooms
            .iter()
            .find(|room| room.id == active_id)
            .map(|room| room.name.clone())
            .unwrap_or_default()
    }

    pub fn messages_for_active_room(&self) -> Vec<Message> {
        let state = self.state.read().unwrap();
        let active_id = match &state.active_room_id {
            Some(id) => id.clone(),
            None => return Vec::new(),
        };
        state
            .messages
            .get(&active_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn messages_for_room(&self, room_id: &str) -> Vec<Message> {
        let state = self.state.read().unwrap();
        state
            .messages
            .get(room_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn create_room(&self, name: &str) -> Result<String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(MeshInfinityError::InvalidConfiguration(
                "room name required".to_string(),
            ));
        }

        let mut state = self.state.write().unwrap();
        if state.settings.node_mode == NodeMode::Server {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        let room_id = random_id("room");
        state.rooms.insert(
            0,
            RoomSummary {
                id: room_id.clone(),
                name: trimmed.to_string(),
                last_message: String::new(),
                unread_count: 0,
                timestamp: String::new(),
            },
        );
        state.messages.insert(room_id.clone(), Vec::new());
        state.active_room_id = Some(room_id.clone());
        Ok(room_id)
    }

    pub fn select_room(&self, room_id: &str) -> Result<()> {
        let mut state = self.state.write().unwrap();
        if state.settings.node_mode == NodeMode::Server {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        state.active_room_id = Some(room_id.to_string());
        if let Some(room) = state.rooms.iter_mut().find(|room| room.id == room_id) {
            room.unread_count = 0;
        }
        Ok(())
    }

    pub fn delete_room(&self, room_id: &str) -> Result<()> {
        let mut state = self.state.write().unwrap();
        if state.settings.node_mode == NodeMode::Server {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        let index = state
            .rooms
            .iter()
            .position(|room| room.id == room_id)
            .ok_or_else(|| {
                MeshInfinityError::InvalidConfiguration("room not found".to_string())
            })?;

        state.rooms.remove(index);
        state.messages.remove(room_id);

        if state.active_room_id.as_deref() == Some(room_id) {
            state.active_room_id = state.rooms.first().map(|room| room.id.clone());
        }

        Ok(())
    }

    pub fn clear_active_room(&self) {
        self.state.write().unwrap().active_room_id = None;
    }

    pub fn register_message_listener(&self) -> Receiver<Message> {
        let (sender, receiver) = unbounded();
        self.state.write().unwrap().message_listeners.push(sender);
        receiver
    }

    pub fn register_transfer_listener(&self) -> Receiver<FileTransferSummary> {
        let (sender, receiver) = unbounded();
        self.state.write().unwrap().transfer_listeners.push(sender);
        receiver
    }

    fn notify_message_listeners(&self, message: &Message) {
        let state = self.state.read().unwrap();
        for sender in &state.message_listeners {
            let _ = sender.send(message.clone());
        }
    }

    fn notify_transfer_listeners(&self, transfer: &FileTransferSummary) {
        let state = self.state.read().unwrap();
        for sender in &state.transfer_listeners {
            let _ = sender.send(transfer.clone());
        }
    }

    pub fn send_message(&self, text: &str) -> Result<()> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let room_id = match self.state.read().unwrap().active_room_id.clone() {
            Some(id) => id,
            None => return Ok(()),
        };

        self.send_message_to_room(&room_id, trimmed)
    }

    pub fn send_message_to_room(&self, room_id: &str, text: &str) -> Result<()> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(());
        }

        {
            let mut state = self.state.write().unwrap();
            if state.settings.node_mode == NodeMode::Server {
                return Err(MeshInfinityError::OperationNotSupported);
            }

            let message = Message {
                id: random_id("msg"),
                room_id: room_id.to_string(),
                sender: "You".to_string(),
                text: trimmed.to_string(),
                timestamp: now_label(),
                is_outgoing: true,
            };

            state
                .messages
                .entry(room_id.to_string())
                .or_default()
                .push(message.clone());

            if let Some(room) = state.rooms.iter_mut().find(|room| room.id == room_id) {
                room.last_message = message.text.clone();
                room.timestamp = message.timestamp.clone();
            }

            self.notify_message_listeners(&message);
        }

        for peer in self.peers.get_all_peers() {
            let _ = self.route_outbound_message(peer.peer_id, trimmed.as_bytes());
        }

        Ok(())
    }

    pub fn delete_message(&self, message_id: &str) -> Result<String> {
        let mut state = self.state.write().unwrap();
        if state.settings.node_mode == NodeMode::Server {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        let mut found_room_id: Option<String> = None;
        for (room_id, messages) in state.messages.iter_mut() {
            if let Some(index) = messages.iter().position(|message| message.id == message_id) {
                messages.remove(index);
                found_room_id = Some(room_id.clone());
                break;
            }
        }

        let room_id = found_room_id.ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("message not found".to_string())
        })?;

        // Get last message info first to avoid overlapping borrows
        let last_message_info = state
            .messages
            .get(&room_id)
            .and_then(|messages| messages.last())
            .map(|msg| (msg.text.clone(), msg.timestamp.clone()));

        if let Some(room) = state.rooms.iter_mut().find(|room| room.id == room_id) {
            if let Some((text, timestamp)) = last_message_info {
                room.last_message = text;
                room.timestamp = timestamp;
            } else {
                room.last_message.clear();
                room.timestamp.clear();
            }
        }

        Ok(room_id)
    }

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

        let short_code: String = trimmed.chars().take(6).collect();
        let mut state = self.state.write().unwrap();
        state.peers.insert(
            0,
            PeerSummary {
                id: peer_id_string(&peer_id),
                name: format!("Peer {}", short_code),
                trust_level: CoreTrustLevel::Caution as i32,
                status: trust_label(CoreTrustLevel::Caution),
            },
        );
        Ok(())
    }

    pub fn receive_message(
        &self,
        peer_id: PeerId,
        room_id: Option<&str>,
        text: &str,
    ) -> Result<()> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(());
        }

        let short_code: String = peer_id_string(&peer_id).chars().take(6).collect();
        let sender = format!("Peer {}", short_code);
        let resolved_room_id = room_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| format!("dm-{}", short_code));

        let mut state = self.state.write().unwrap();
        if state.rooms.iter().all(|room| room.id != resolved_room_id) {
            state.rooms.push(RoomSummary {
                id: resolved_room_id.clone(),
                name: sender.clone(),
                last_message: String::new(),
                unread_count: 0,
                timestamp: String::new(),
            });
        }

        let message = Message {
            id: random_id("msg"),
            room_id: resolved_room_id.clone(),
            sender: sender.clone(),
            text: trimmed.to_string(),
            timestamp: now_label(),
            is_outgoing: false,
        };

        state
            .messages
            .entry(resolved_room_id.clone())
            .or_default()
            .push(message.clone());

        // Notify message listeners
        self.notify_message_listeners(&message);

        let is_active = state.active_room_id.as_deref() == Some(&resolved_room_id);
        if let Some(room) = state
            .rooms
            .iter_mut()
            .find(|room| room.id == resolved_room_id)
        {
            room.last_message = message.text;
            room.timestamp = message.timestamp;
            if !is_active {
                room.unread_count = room.unread_count.saturating_add(1);
            }
        }

        if state
            .peers
            .iter()
            .all(|peer| peer.id != peer_id_string(&peer_id))
        {
            let trust_level = self
                .peers
                .get_trust_level(&peer_id)
                .unwrap_or(CoreTrustLevel::Caution);
            state.peers.push(PeerSummary {
                id: peer_id_string(&peer_id),
                name: sender,
                trust_level: trust_level as i32,
                status: trust_label(trust_level),
            });
        }

        Ok(())
    }

    pub fn set_node_mode(&self, mode: NodeMode) {
        self.state.write().unwrap().settings.node_mode = mode;
    }

    pub fn set_enable_tor(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.enable_tor = value;
        state.settings.enable_tor = value;
        self.transport_manager.set_tor_enabled(value);
    }

    pub fn set_enable_clearnet(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.enable_clearnet = value;
        state.settings.enable_clearnet = value;
        self.transport_manager.set_clearnet_enabled(value);
    }

    pub fn set_mesh_discovery(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.mesh_discovery = value;
        state.settings.mesh_discovery = value;
    }

    pub fn set_allow_relays(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.allow_relays = value;
        state.settings.allow_relays = value;
    }

    pub fn set_enable_i2p(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.enable_i2p = value;
        state.settings.enable_i2p = value;
        self.transport_manager.set_i2p_enabled(value);
    }

    pub fn set_enable_bluetooth(&self, value: bool) {
        let mut state = self.state.write().unwrap();
        state.mesh_config.enable_bluetooth = value;
        state.settings.enable_bluetooth = value;
        self.transport_manager.set_bluetooth_enabled(value);
    }

    pub fn mesh_config(&self) -> MeshConfig {
        self.state.read().unwrap().mesh_config.clone()
    }

    pub fn local_identity_name(&self) -> Option<String> {
        self.identity_manager
            .get_primary_identity()
            .and_then(|identity| identity.name.clone())
    }

    pub fn local_identity_summary(&self) -> Option<IdentitySummary> {
        self.identity_manager.get_primary_identity().map(|identity| {
            IdentitySummary {
                peer_id: identity.peer_id,
                public_key: identity.keypair.public.to_bytes(),
                dh_public: identity.dh_public,
                name: identity.name.clone(),
            }
        })
    }

    pub fn trust_attest(
        &self,
        endorser_peer_id: &PeerId,
        target_peer_id: &PeerId,
        trust_level: CoreTrustLevel,
        method: WotVerificationMethod,
    ) -> Result<()> {
        let identity = self
            .identity_manager
            .get_identity(endorser_peer_id)
            .ok_or_else(|| MeshInfinityError::AuthError("Identity not found".to_string()))?;

        let mut attestation = TrustAttestation::new(
            *endorser_peer_id,
            *target_peer_id,
            trust_level,
            method,
            identity.keypair.public.to_bytes(),
        );

        let message = attestation.signable_message();
        let signature = identity.keypair.sign(&message);
        attestation.signature = signature.to_bytes().to_vec();

        self.web_of_trust.add_attestation(attestation)
    }

    pub fn trust_verify(
        &self,
        target_peer_id: &PeerId,
        trust_markers: Vec<(PeerId, PeerId, CoreTrustLevel, SystemTime)>,
    ) -> CoreTrustLevel {
        use crate::auth::web_of_trust::TrustMarker;

        let markers = trust_markers
            .into_iter()
            .map(|(endorser, target, trust_level, timestamp)| TrustMarker {
                endorser,
                target,
                trust_level,
                timestamp,
            })
            .collect::<Vec<_>>();

        self.web_of_trust.verify_peer(target_peer_id, &markers)
    }

    /// Enable mDNS discovery on the local network
    pub fn enable_mdns(&self, port: u16) -> Result<()> {
        let peer_id = self.identity_manager
            .get_primary_identity()
            .map(|id| id.peer_id)
            .ok_or_else(|| MeshInfinityError::AuthError("No identity available".to_string()))?;

        let mut discovery = self.discovery.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Discovery lock poisoned: {}", e)))?;

        discovery.enable_mdns(peer_id, port)?;

        // Update mesh_discovery flag
        self.set_mesh_discovery(true);

        Ok(())
    }

    /// Disable mDNS discovery
    pub fn disable_mdns(&self) -> Result<()> {
        let mut discovery = self.discovery.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Discovery lock poisoned: {}", e)))?;

        discovery.disable_mdns()?;
        self.set_mesh_discovery(false);

        Ok(())
    }

    /// Check if mDNS discovery is running
    pub fn is_mdns_running(&self) -> bool {
        self.discovery.lock()
            .map(|d| d.is_mdns_running())
            .unwrap_or(false)
    }

    /// Get discovered peers from all discovery methods
    pub fn get_discovered_peers(&self) -> Result<Vec<PeerSummary>> {
        let mut discovery = self.discovery.lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Discovery lock poisoned: {}", e)))?;

        let peers = discovery.refresh()?;

        // Convert to PeerSummary format
        let summaries: Vec<PeerSummary> = peers.iter().map(|peer| {
            let short_code: String = peer_id_string(&peer.peer_id).chars().take(6).collect();
            PeerSummary {
                id: peer_id_string(&peer.peer_id),
                name: format!("Peer {}", short_code),
                trust_level: peer.trust_level as i32,
                status: trust_label(peer.trust_level),
            }
        }).collect();

        Ok(summaries)
    }
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    getrandom(&mut bytes).expect("system RNG unavailable");
    format!("{}-{}", prefix, hex_encode(&bytes))
}

fn random_peer_id() -> PeerId {
    let mut bytes = [0u8; 32];
    getrandom(&mut bytes).expect("system RNG unavailable");
    bytes
}

fn peer_id_string(peer_id: &PeerId) -> String {
    hex_encode(peer_id)
}

fn file_id_string(file_id: &[u8; 32]) -> String {
    hex_encode(file_id)
}

fn pairing_code_from_peer_id(peer_id: &PeerId) -> String {
    let hex = hex_encode(peer_id);
    let short = &hex[..16];
    format!(
        "{}-{}-{}-{}",
        &short[0..4],
        &short[4..8],
        &short[8..12],
        &short[12..16]
    )
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

fn peer_id_from_pairing_code(code: &str) -> Option<PeerId> {
    let mut hex = String::new();
    for ch in code.chars() {
        if ch.is_ascii_hexdigit() {
            hex.push(ch);
        }
    }

    if hex.len() < 16 {
        return None;
    }

    let mut bytes = [0u8; 32];
    let available = hex.len() / 2;
    let count = usize::min(bytes.len(), available);
    for i in 0..count {
        let idx = i * 2;
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).ok()?;
        bytes[i] = byte;
    }
    Some(bytes)
}

fn file_id_from_string(value: &str) -> Option<[u8; 32]> {
    let mut hex = String::new();
    for ch in value.chars() {
        if ch.is_ascii_hexdigit() {
            hex.push(ch);
        }
    }

    if hex.len() < 64 {
        return None;
    }

    let mut bytes = [0u8; 32];
    for i in 0..bytes.len() {
        let idx = i * 2;
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).ok()?;
        bytes[i] = byte;
    }
    Some(bytes)
}

fn sync_settings_from_mesh(settings: &mut Settings, mesh_config: &MeshConfig) {
    settings.enable_tor = mesh_config.enable_tor;
    settings.enable_clearnet = mesh_config.enable_clearnet;
    settings.mesh_discovery = mesh_config.mesh_discovery;
    settings.allow_relays = mesh_config.allow_relays;
    settings.enable_i2p = mesh_config.enable_i2p;
    settings.enable_bluetooth = mesh_config.enable_bluetooth;
}

fn trust_label(level: CoreTrustLevel) -> String {
    match level {
        CoreTrustLevel::Untrusted => "Untrusted",
        CoreTrustLevel::Caution => "Caution",
        CoreTrustLevel::Trusted => "Trusted",
        CoreTrustLevel::HighlyTrusted => "Highly trusted",
    }
    .to_string()
}

impl MeshInfinityService {
    fn route_outbound_message(&self, target: PeerId, payload: &[u8]) -> Result<()> {
        let session = {
            let mut manager = self.pfs_manager.lock().unwrap();
            manager.new_session(&target)?
        };

        let encrypted_payload = EncryptedPayload {
            data: payload.to_vec(),
            encryption_key_id: session.encryption_key,
            mac: session.mac_key,
        };

        let paths = self.preferred_paths_for_peer(target);
        let message = OutboundMessage {
            payload: encrypted_payload,
            target,
            priority: MessagePriority::Normal,
            preferred_paths: paths,
            ttl: 4,
            max_retries: 3,
            current_retry: 0,
        };

        self.message_router.route_message(message)?;
        self.message_router.process_queue()
    }

    fn preferred_paths_for_peer(&self, target: PeerId) -> Vec<PathInfo> {
        let mesh_config = self.state.read().unwrap().mesh_config.clone();
        let mut paths = Vec::new();

        if mesh_config.enable_tor {
            paths.push(default_path(target, TransportType::Tor));
        }
        if mesh_config.enable_i2p {
            paths.push(default_path(target, TransportType::I2P));
        }
        if mesh_config.enable_clearnet {
            paths.push(default_path(target, TransportType::Clearnet));
        }
        if mesh_config.enable_bluetooth {
            paths.push(default_path(target, TransportType::Bluetooth));
        }

        paths
    }
}

fn default_path(target: PeerId, transport: TransportType) -> PathInfo {
    PathInfo {
        transport,
        endpoint: Endpoint {
            peer_id: target,
            address: peer_id_string(&target),
        },
        latency: None,
        reliability: 0.8,
        bandwidth: None,
        cost: 0.1,
    }
}

fn transfer_summary(item: &TransferItem) -> FileTransferSummary {
    FileTransferSummary {
        id: file_id_string(&item.id),
        peer_id: peer_id_string(&item.peer_id),
        name: item.metadata.name.clone(),
        size_bytes: item.metadata.size_bytes,
        transferred_bytes: item.progress.transferred_bytes,
        status: transfer_status_label(item.status),
        direction: transfer_direction_label(item.direction),
    }
}

fn transfer_status_label(status: TransferStatus) -> String {
    match status {
        TransferStatus::Queued => "Queued",
        TransferStatus::InProgress => "In progress",
        TransferStatus::Completed => "Completed",
        TransferStatus::Failed => "Failed",
        TransferStatus::Canceled => "Canceled",
    }
    .to_string()
}

fn transfer_direction_label(direction: TransferDirection) -> String {
    match direction {
        TransferDirection::Send => "Send",
        TransferDirection::Receive => "Receive",
    }
    .to_string()
}

fn now_label() -> String {
    let format = format_description::parse("[hour]:[minute]").ok();
    let now = time::OffsetDateTime::now_utc();
    match format {
        Some(format) => now.format(&format).unwrap_or_default(),
        None => String::new(),
    }
}
