//! High-level backend service orchestration for Mesh Infinity.
//!
//! This module exposes the primary stateful service used by UI/FFI callers.
//! It coordinates peer management, messaging, file transfer queues, trust
//! relationships, transport preferences, passive fallback delivery, and runtime
//! mode transitions.

use crossbeam_channel::Sender;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crate::auth::identity::IdentityManager;
use crate::auth::web_of_trust::{Identity as WotIdentity, WebOfTrust};
use crate::core::core::{MeshConfig, PeerId, TransportType, TrustLevel as CoreTrustLevel};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::file_transfer::{
    FileTransferManager, TransferDirection, TransferItem, TransferStatus,
};
use crate::core::mesh::{
    EncryptedPayload, Endpoint, MessagePriority, MessageRouter, OutboundMessage, PathInfo,
    PeerManager,
};
use crate::crypto::{MessageCrypto, PfsManager};
use crate::discovery::DiscoveryService;
use crate::transport::TransportManagerImpl;
use getrandom::getrandom;
use ring::digest::{digest, SHA256};
use time::format_description;

mod discovery;
mod file_transfers;
mod hosted_services;
mod lifecycle;
mod messaging;
mod metrics;
mod passive;
mod peers;
mod settings;
mod trust;
mod types;

pub use types::{
    FileTransferSummary, HostedServicePolicy, HostedServiceSummary, IdentitySummary, LocalProfile,
    Message, NetworkStatsSummary, NodeMode, PeerSummary, PreloadedIdentity, ReconnectSyncSnapshot,
    RoomSummary, ServiceConfig, Settings,
};

struct ServiceState {
    rooms: Vec<RoomSummary>,
    messages: HashMap<String, Vec<Message>>,
    peers: Vec<PeerSummary>,
    active_room_id: Option<String>,
    settings: Settings,
    mesh_config: MeshConfig,
    hosted_services: HashMap<String, HostedServiceSummary>,
    vpn_route_config: Option<String>,
    clearnet_route_config: Option<String>,
    bytes_sent: u64,
    bytes_received: u64,
    passive_outbox: HashMap<PeerId, Vec<PassiveEnvelope>>,
    passive_acked: HashMap<PeerId, VecDeque<String>>,
    message_listeners: Vec<Sender<Message>>,
    transfer_listeners: Vec<Sender<FileTransferSummary>>,
}

#[derive(Clone, Debug)]
struct PassiveEnvelope {
    _id: String,
    _created_at: SystemTime,
    _expires_at: SystemTime,
    _dedupe_key: String,
    _ciphertext: Vec<u8>,
}

const PASSIVE_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_PASSIVE_ENVELOPES_PER_PEER: usize = 64;
const MAX_PASSIVE_ACK_HISTORY: usize = 256;

pub struct MeshInfinityService {
    state: Arc<RwLock<ServiceState>>,
    peers: PeerManager,
    pub(super) identity_manager: IdentityManager,
    pub(super) web_of_trust: WebOfTrust,
    file_transfers: Arc<Mutex<FileTransferManager>>,
    transport_manager: TransportManagerImpl,
    message_router: Arc<MessageRouter>,
    pfs_manager: Arc<Mutex<PfsManager>>,
    message_crypto: Arc<Mutex<MessageCrypto>>,
    running: Arc<AtomicBool>,
    routing_worker: Mutex<Option<JoinHandle<()>>>,
    discovery: Arc<Mutex<DiscoveryService>>,
    /// `true` once an identity has been explicitly saved to disk.
    pub(super) identity_persisted: bool,
    /// Local profile fields (visibility prefs, private bio, etc.).
    pub(super) local_profile: LocalProfile,
}

impl MeshInfinityService {
    /// Construct a fully wired service instance from caller configuration.
    ///
    /// If `config.preloaded_identity` is `Some`, the service restores the
    /// existing identity from its serialised key material and marks it as
    /// persisted.  Otherwise a fresh identity is generated in memory and
    /// `identity_persisted` is set to `false` (onboarding will be shown).
    pub fn new(config: ServiceConfig) -> Self {
        let mut identity_manager = IdentityManager::new();
        let (identity_peer_id, identity_persisted, local_profile) =
            if let Some(ref preloaded) = config.preloaded_identity {
                let peer_id = identity_manager
                    .load_identity(
                        &preloaded.ed25519_secret,
                        &preloaded.x25519_secret,
                        preloaded.name.clone(),
                    )
                    .unwrap_or_else(|_| random_peer_id());
                (peer_id, true, preloaded.profile.clone())
            } else {
                let peer_id = identity_manager
                    .generate_identity(config.identity_name.clone())
                    .unwrap_or_else(|_| random_peer_id());
                (peer_id, false, LocalProfile::default())
            };
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
        let web_of_trust = WebOfTrust::with_identity(wot_identity);
        let pairing_code = pairing_code_from_peer_id(&identity_peer_id);
        let mesh_config = config.mesh_config;
        let transport_manager = TransportManagerImpl::new();
        transport_manager.set_tor_enabled(mesh_config.enable_tor);
        transport_manager.set_clearnet_enabled(mesh_config.enable_clearnet);
        transport_manager.set_i2p_enabled(mesh_config.enable_i2p);
        transport_manager.set_bluetooth_enabled(mesh_config.enable_bluetooth);
        transport_manager.set_rf_enabled(mesh_config.enable_rf);
        let pfs_manager = Arc::new(Mutex::new(PfsManager::new(Duration::from_secs(60 * 60), 8)));
        let message_crypto = Arc::new(Mutex::new(MessageCrypto::generate().unwrap_or_else(|_| {
            // Deterministic fallback only for service bootstrap resilience.
            let mut seed = [0u8; 32];
            seed[..identity_peer_id.len()].copy_from_slice(&identity_peer_id);
            let keypair = ed25519_dalek::Keypair::generate(&mut rand_core::OsRng);
            MessageCrypto::new(keypair, seed)
        })));
        let message_router = Arc::new(MessageRouter::new(
            transport_manager.get_manager(),
            identity_peer_id,
        ));

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
                enable_rf: mesh_config.enable_rf,
                pairing_code,
                local_peer_id: peer_id_string(&identity_peer_id),
            },
            mesh_config,
            hosted_services: HashMap::new(),
            vpn_route_config: None,
            clearnet_route_config: None,
            bytes_sent: 0,
            bytes_received: 0,
            passive_outbox: HashMap::new(),
            passive_acked: HashMap::new(),
            message_listeners: Vec::new(),
            transfer_listeners: Vec::new(),
        };

        let service = Self {
            state: Arc::new(RwLock::new(state)),
            peers: PeerManager::new(),
            identity_manager,
            web_of_trust,
            file_transfers: Arc::new(Mutex::new(FileTransferManager::new(64 * 1024))),
            transport_manager,
            message_router,
            pfs_manager,
            message_crypto,
            running: Arc::new(AtomicBool::new(false)),
            routing_worker: Mutex::new(None),
            discovery: Arc::new(Mutex::new(DiscoveryService::new())),
            identity_persisted,
            local_profile,
        };

        if matches!(config.initial_mode, NodeMode::Server | NodeMode::Dual) {
            let _ = service.start();
        }

        service
    }

    /// Return snapshot of known room summaries.
    pub fn rooms(&self) -> Vec<RoomSummary> {
        self.state.read().unwrap().rooms.clone()
    }

    /// Return snapshot of known peer summaries.
    pub fn peers(&self) -> Vec<PeerSummary> {
        self.state.read().unwrap().peers.clone()
    }
}

/// Generate a random id with stable `<prefix>-<HEX>` formatting.
fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    getrandom(&mut bytes).expect("system RNG unavailable");
    format!("{}-{}", prefix, hex_encode(&bytes))
}

/// Generate a random 32-byte peer identifier.
fn random_peer_id() -> PeerId {
    let mut bytes = [0u8; 32];
    getrandom(&mut bytes).expect("system RNG unavailable");
    bytes
}

/// Encode peer id as uppercase hexadecimal string.
pub(super) fn peer_id_string(peer_id: &PeerId) -> String {
    hex_encode(peer_id)
}

/// Encode file id as uppercase hexadecimal string.
fn file_id_string(file_id: &[u8; 32]) -> String {
    hex_encode(file_id)
}

/// Derive short human-friendly pairing code from peer id prefix bytes.
pub(super) fn pairing_code_from_peer_id(peer_id: &PeerId) -> String {
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

/// Hex-encode arbitrary bytes using uppercase alphabet.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Parse peer id from pairing code / hex-like input.
///
/// Accepts separators and any non-hex characters are ignored.
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
    for (i, slot) in bytes.iter_mut().enumerate().take(count) {
        let idx = i * 2;
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).ok()?;
        *slot = byte;
    }
    Some(bytes)
}

/// Parse full 32-byte file id from hex-like string.
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
    for (i, slot) in bytes.iter_mut().enumerate() {
        let idx = i * 2;
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).ok()?;
        *slot = byte;
    }
    Some(bytes)
}

/// Convert trust level enum into UI label.
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
    /// Encrypt and route outbound payload to target peer.
    ///
    /// On route failure, message is queued into passive fallback storage.
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

        let route_result = self.message_router.route_message(message).and_then(|_| {
            if !self.running.load(Ordering::Relaxed) {
                self.message_router.process_queue()
            } else {
                Ok(())
            }
        });

        if route_result.is_err() {
            self.enqueue_passive_fallback(target, payload)?;
        }

        let mut state = self.state.write().unwrap();
        state.bytes_sent = state.bytes_sent.saturating_add(payload.len() as u64);
        Ok(())
    }

    /// Queue payload for passive delivery with dedupe and bounded retention.
    fn enqueue_passive_fallback(&self, target: PeerId, payload: &[u8]) -> Result<()> {
        let local_peer = {
            let state = self.state.read().unwrap();
            parse_peer_id_hex(&state.settings.local_peer_id).unwrap_or([0u8; 32])
        };

        let dedupe_key = passive_dedupe_key(&target, payload);

        let session_key = derive_passive_session_key(&local_peer, &target);
        let ciphertext = {
            let mut crypto = self.message_crypto.lock().unwrap();
            crypto.session_encrypt(&session_key, payload)?
        };

        let envelope = PassiveEnvelope {
            _id: random_id("passive"),
            _created_at: SystemTime::now(),
            _expires_at: SystemTime::now() + Duration::from_secs(PASSIVE_RETENTION_SECS),
            _dedupe_key: dedupe_key.clone(),
            _ciphertext: ciphertext,
        };

        let mut state = self.state.write().unwrap();
        let already_acked = state
            .passive_acked
            .get(&target)
            .map(|history| history.iter().any(|item| item == &dedupe_key))
            .unwrap_or(false);
        if already_acked {
            return Ok(());
        }

        let queue = state.passive_outbox.entry(target).or_default();

        queue.retain(|item| SystemTime::now() <= item._expires_at);
        if queue.iter().any(|item| item._dedupe_key == dedupe_key) {
            return Ok(());
        }

        queue.push(envelope);
        if queue.len() > MAX_PASSIVE_ENVELOPES_PER_PEER {
            let overflow = queue.len() - MAX_PASSIVE_ENVELOPES_PER_PEER;
            queue.drain(0..overflow);
        }

        Ok(())
    }

    /// Build preferred path list for target based on trust and enabled transports.
    fn preferred_paths_for_peer(&self, target: PeerId) -> Vec<PathInfo> {
        let available = self
            .peers
            .get_peer(&target)
            .map(|peer| peer.available_transports)
            .unwrap_or_else(|| {
                vec![
                    TransportType::Tor,
                    TransportType::I2P,
                    TransportType::Bluetooth,
                    TransportType::Rf,
                    TransportType::Clearnet,
                ]
            });

        let trust = self
            .peers
            .get_trust_level(&target)
            .unwrap_or(CoreTrustLevel::Untrusted);

        let trust_allowed = allowed_transports_for_trust(trust);

        self.transport_manager
            .enabled_transport_order_for_available(&available)
            .into_iter()
            .filter(|transport| trust_allowed.contains(transport))
            .map(|transport| default_path(target, transport))
            .collect()
    }
}

/// Return transport allow-list permitted at a given trust level.
fn allowed_transports_for_trust(level: CoreTrustLevel) -> &'static [TransportType] {
    match level {
        CoreTrustLevel::Untrusted => &[TransportType::Tor],
        CoreTrustLevel::Caution => &[TransportType::Tor, TransportType::I2P],
        CoreTrustLevel::Trusted | CoreTrustLevel::HighlyTrusted => &[
            TransportType::Tor,
            TransportType::I2P,
            TransportType::Bluetooth,
            TransportType::Rf,
            TransportType::Clearnet,
        ],
    }
}

/// Deterministically derive passive session key from local/target peer ids.
fn derive_passive_session_key(local_peer: &PeerId, target: &PeerId) -> [u8; 32] {
    let mut seed = Vec::with_capacity(local_peer.len() + target.len());
    seed.extend_from_slice(local_peer);
    seed.extend_from_slice(target);
    let hashed = digest(&SHA256, &seed);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hashed.as_ref()[..32]);
    key
}

/// Parse canonical 32-byte peer id from hex string.
fn parse_peer_id_hex(value: &str) -> Option<PeerId> {
    let normalized: String = value.chars().filter(|ch| ch.is_ascii_hexdigit()).collect();
    if normalized.len() < 64 {
        return None;
    }

    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&normalized[start..start + 2], 16).ok()?;
    }
    Some(out)
}

/// Build default path descriptor for router enqueueing.
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

/// Build deterministic direct-message room id for a peer.
fn dm_room_id(peer_id: &PeerId) -> String {
    // Use the full peer identity for deterministic, collision-resistant DM rooms.
    format!("dm-{}", peer_id_string(peer_id))
}

/// Ensure a room id exists in room collection.
fn ensure_room_exists(rooms: &[RoomSummary], room_id: &str) -> Result<()> {
    if rooms.iter().any(|room| room.id == room_id) {
        Ok(())
    } else {
        Err(MeshInfinityError::InvalidConfiguration(
            "room not found".to_string(),
        ))
    }
}

/// Build passive dedupe key from peer and payload content.
fn passive_dedupe_key(target: &PeerId, payload: &[u8]) -> String {
    let mut input = Vec::with_capacity(target.len() + payload.len());
    input.extend_from_slice(target);
    input.extend_from_slice(payload);
    let hash = digest(&SHA256, &input);
    hex_encode(hash.as_ref())
}

/// Convert transfer item into UI summary struct.
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

/// Convert transfer status enum into user-facing label.
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

/// Convert transfer direction enum into user-facing label.
fn transfer_direction_label(direction: TransferDirection) -> String {
    match direction {
        TransferDirection::Send => "Send",
        TransferDirection::Receive => "Receive",
    }
    .to_string()
}

/// Build short local timestamp label used by message summaries.
fn now_label() -> String {
    let format = format_description::parse("[hour]:[minute]").ok();
    let now = time::OffsetDateTime::now_utc();
    match format {
        Some(format) => now.format(&format).unwrap_or_default(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mesh::VerificationMethod;

    /// Passive fallback queues when no transport paths.
    #[test]
    fn passive_fallback_queues_when_no_transport_paths() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("A1B2-C3D4-E5F6-1122");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("fallback-room").expect("room create");
        service
            .send_message_to_room(&room_id, "hello fallback")
            .expect("send message");

        let state = service.state.read().unwrap();
        let pending = state
            .passive_outbox
            .get(&peer_id)
            .map(|v| v.len())
            .unwrap_or(0);
        assert!(pending >= 1);
    }

    /// Passive fallback drains on reconciliation.
    #[test]
    fn passive_fallback_drains_on_reconciliation() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("1122-3344-5566-7788");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("reconcile-room").expect("room create");
        service
            .send_message_to_room(&room_id, "reconcile me")
            .expect("send message");

        let delivered = service
            .drain_passive_for_peer(&peer_id)
            .expect("drain passive queue");
        assert!(delivered >= 1);

        let state = service.state.read().unwrap();
        let remaining = state
            .passive_outbox
            .get(&peer_id)
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(remaining, 0);
    }

    /// Passive fallback stores ciphertext not plaintext.
    #[test]
    fn passive_fallback_stores_ciphertext_not_plaintext() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("99AA-BBCC-DDEE-FF00");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("cipher-room").expect("room create");
        let plain = b"origin-hidden-payload";
        service
            .send_message_to_room(&room_id, std::str::from_utf8(plain).unwrap())
            .expect("send message");

        let state = service.state.read().unwrap();
        let queued = state
            .passive_outbox
            .get(&peer_id)
            .and_then(|v| v.first())
            .expect("queued envelope should exist");

        assert_ne!(queued._ciphertext, plain);
        assert!(!queued
            ._ciphertext
            .windows(plain.len())
            .any(|slice| slice == plain));
    }

    /// Passive fallback observer cannot link origin beyond previous hop.
    #[test]
    fn passive_fallback_observer_cannot_link_origin_beyond_previous_hop() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("AAAA-BBBB-CCCC-DDDD");
        let _ = service.pair_peer("1111-2222-3333-4444");

        let peers = service.peers.get_all_peers();
        assert!(peers.len() >= 2, "expected two paired peers");
        let peer_a = peers[0].peer_id;
        let peer_b = peers[1].peer_id;

        let room_id = service.create_room("observer-room").expect("room create");
        service
            .send_message_to_room(&room_id, "same payload")
            .expect("send message");

        let local_peer = {
            let state = service.state.read().unwrap();
            parse_peer_id_hex(&state.settings.local_peer_id).expect("local peer id parse")
        };

        let state = service.state.read().unwrap();
        let env_a = state
            .passive_outbox
            .get(&peer_a)
            .and_then(|items| items.first())
            .expect("peer A should have passive envelope");
        let env_b = state
            .passive_outbox
            .get(&peer_b)
            .and_then(|items| items.first())
            .expect("peer B should have passive envelope");

        // Same plaintext to different peers must not produce linkable ciphertexts.
        assert_ne!(env_a._ciphertext, env_b._ciphertext);

        // Observer-visible ciphertext should not directly expose peer identities.
        assert!(!env_a
            ._ciphertext
            .windows(peer_a.len())
            .any(|window| window == peer_a));
        assert!(!env_a
            ._ciphertext
            .windows(peer_b.len())
            .any(|window| window == peer_b));
        assert!(!env_a
            ._ciphertext
            .windows(local_peer.len())
            .any(|window| window == local_peer));
    }

    /// Preferred paths gate clearnet for low trust even if enabled.
    #[test]
    fn preferred_paths_gate_clearnet_for_low_trust_even_if_enabled() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(true);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("ABCD-1234-EEEE-9999");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        // pair_peer assigns Caution trust by default.
        let paths = service.preferred_paths_for_peer(peer_id);
        assert!(paths.is_empty(), "clearnet must be gated for caution peers");
    }

    /// Preferred paths allow clearnet for trusted when privacy transports disabled.
    #[test]
    fn preferred_paths_allow_clearnet_for_trusted_when_privacy_transports_disabled() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(true);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("CAFE-BEEF-0000-1111");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        service
            .peers
            .update_trust_level(
                &peer_id,
                CoreTrustLevel::Trusted,
                VerificationMethod::SharedSecret,
            )
            .expect("update trust");

        let paths = service.preferred_paths_for_peer(peer_id);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].transport, TransportType::Clearnet);
    }

    /// Node mode transitions toggle routing worker lifecycle.
    #[test]
    fn node_mode_transitions_toggle_routing_worker_lifecycle() {
        let service = MeshInfinityService::new(ServiceConfig {
            initial_mode: NodeMode::Client,
            ..ServiceConfig::default()
        });

        assert!(!service.is_running());

        service.set_node_mode(NodeMode::Dual);
        assert!(service.is_running());

        service.set_node_mode(NodeMode::Client);
        assert!(!service.is_running());

        service.set_node_mode(NodeMode::Server);
        assert!(service.is_running());
    }

    /// Start stop are idempotent across role transitions.
    #[test]
    fn start_stop_are_idempotent_across_role_transitions() {
        let service = MeshInfinityService::new(ServiceConfig {
            initial_mode: NodeMode::Server,
            ..ServiceConfig::default()
        });

        assert!(service.is_running());

        service.start().expect("start should be idempotent");
        assert!(service.is_running());

        service.stop().expect("stop should succeed");
        assert!(!service.is_running());

        service.stop().expect("stop should be idempotent");
        assert!(!service.is_running());

        service.start().expect("restart should succeed");
        assert!(service.is_running());
    }

    /// Receive message uses collision resistant dm room ids.
    #[test]
    fn receive_message_uses_collision_resistant_dm_room_ids() {
        let service = MeshInfinityService::new(ServiceConfig::default());

        let mut peer_a = [0u8; 32];
        let mut peer_b = [0u8; 32];
        // Same first 3 bytes (same 6-hex prefix), different full identities.
        peer_a[0] = 0xAA;
        peer_a[1] = 0xBB;
        peer_a[2] = 0xCC;
        peer_a[3] = 0x01;

        peer_b[0] = 0xAA;
        peer_b[1] = 0xBB;
        peer_b[2] = 0xCC;
        peer_b[3] = 0x02;

        service
            .receive_message(peer_a, None, "hello from a")
            .expect("receive A");
        service
            .receive_message(peer_b, None, "hello from b")
            .expect("receive B");

        let rooms = service.rooms();
        assert!(rooms.iter().any(|room| room.id == dm_room_id(&peer_a)));
        assert!(rooms.iter().any(|room| room.id == dm_room_id(&peer_b)));
        assert_ne!(dm_room_id(&peer_a), dm_room_id(&peer_b));
    }

    /// Select room requires existing room.
    #[test]
    fn select_room_requires_existing_room() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        let err = service
            .select_room("room-does-not-exist")
            .expect_err("select must fail for unknown room");
        assert!(matches!(err, MeshInfinityError::InvalidConfiguration(_)));
    }

    /// Send message requires existing room.
    #[test]
    fn send_message_requires_existing_room() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        let err = service
            .send_message_to_room("room-does-not-exist", "hello")
            .expect_err("send must fail for unknown room");
        assert!(matches!(err, MeshInfinityError::InvalidConfiguration(_)));
    }

    /// Pair peer is idempotent for same code summary.
    #[test]
    fn pair_peer_is_idempotent_for_same_code_summary() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        let code = "ABCD-1234-EEEE-9999";

        service.pair_peer(code).expect("first pair");
        service.pair_peer(code).expect("second pair");

        let peer_id = peer_id_string(&peer_id_from_pairing_code(code).expect("peer id from code"));
        let state = service.state.read().unwrap();
        let count = state.peers.iter().filter(|peer| peer.id == peer_id).count();
        assert_eq!(
            count, 1,
            "pairing same code should not duplicate peer summary"
        );
    }

    /// Passive fallback dedupes identical payloads.
    #[test]
    fn passive_fallback_dedupes_identical_payloads() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("D00D-BEEF-1111-2222");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("dedupe-room").expect("room create");
        service
            .send_message_to_room(&room_id, "same payload")
            .expect("first send");
        service
            .send_message_to_room(&room_id, "same payload")
            .expect("second send");

        let state = service.state.read().unwrap();
        let pending = state
            .passive_outbox
            .get(&peer_id)
            .map(|items| items.len())
            .unwrap_or(0);
        assert_eq!(pending, 1, "identical pending payload should be deduped");
    }

    /// Passive fallback queue is bounded.
    #[test]
    fn passive_fallback_queue_is_bounded() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("ABBA-ABBA-ABBA-ABBA");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("bound-room").expect("room create");
        for i in 0..(MAX_PASSIVE_ENVELOPES_PER_PEER + 12) {
            service
                .send_message_to_room(&room_id, &format!("payload-{}", i))
                .expect("send");
        }

        let state = service.state.read().unwrap();
        let pending = state
            .passive_outbox
            .get(&peer_id)
            .map(|items| items.len())
            .unwrap_or(0);
        assert_eq!(pending, MAX_PASSIVE_ENVELOPES_PER_PEER);
    }

    /// Passive fallback replay is rejected after ack.
    #[test]
    fn passive_fallback_replay_is_rejected_after_ack() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("FACE-B00C-1234-5678");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("replay-room").expect("room create");
        service
            .send_message_to_room(&room_id, "replay-safe-payload")
            .expect("first send");

        let delivered = service
            .drain_passive_for_peer(&peer_id)
            .expect("drain should succeed");
        assert!(delivered >= 1);

        service
            .send_message_to_room(&room_id, "replay-safe-payload")
            .expect("second send with same payload");

        let state = service.state.read().unwrap();
        let pending = state
            .passive_outbox
            .get(&peer_id)
            .map(|items| items.len())
            .unwrap_or(0);
        assert_eq!(pending, 0, "acked payload should not be re-enqueued");
    }

    /// Passive ack checkpoint advances after drain.
    #[test]
    fn passive_ack_checkpoint_advances_after_drain() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("ABCD-ABCD-ABCD-ABCD");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("checkpoint-room").expect("room create");
        service
            .send_message_to_room(&room_id, "checkpoint-payload")
            .expect("send");

        let expected = {
            let state = service.state.read().unwrap();
            state
                .passive_outbox
                .get(&peer_id)
                .and_then(|items| items.first())
                .map(|env| env._dedupe_key.clone())
                .expect("queued envelope")
        };

        let delivered = service
            .drain_passive_for_peer(&peer_id)
            .expect("drain should succeed");
        assert!(delivered >= 1);

        let checkpoint = service
            .passive_ack_checkpoint(&peer_id)
            .expect("checkpoint should exist");
        assert_eq!(checkpoint, expected);
    }

    /// Passive compaction removes expired envelopes.
    #[test]
    fn passive_compaction_removes_expired_envelopes() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("EEEE-FFFF-0000-1111");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("compact-room").expect("room create");
        service
            .send_message_to_room(&room_id, "expire-me")
            .expect("send");

        {
            let mut state = service.state.write().unwrap();
            if let Some(queue) = state.passive_outbox.get_mut(&peer_id) {
                for env in queue.iter_mut() {
                    env._expires_at = SystemTime::UNIX_EPOCH;
                }
            }
        }

        let removed = service.compact_passive_state();
        assert!(removed >= 1);

        let state = service.state.read().unwrap();
        let remaining = state
            .passive_outbox
            .get(&peer_id)
            .map(|items| items.len())
            .unwrap_or(0);
        assert_eq!(remaining, 0);
    }

    /// Reconnect sync room since returns only newer messages.
    #[test]
    fn reconnect_sync_room_since_returns_only_newer_messages() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        let room_id = service.create_room("sync-room").expect("room create");

        service
            .send_message_to_room(&room_id, "m1")
            .expect("send m1");
        service
            .send_message_to_room(&room_id, "m2")
            .expect("send m2");
        service
            .send_message_to_room(&room_id, "m3")
            .expect("send m3");

        let all = service.messages_for_room(&room_id);
        let cursor = all.first().expect("m1 exists").id.clone();

        let delta = service
            .sync_room_messages_since(&room_id, Some(&cursor))
            .expect("sync since cursor");
        assert_eq!(delta.len(), 2);
        assert_eq!(delta[0].text, "m2");
        assert_eq!(delta[1].text, "m3");
    }

    /// Reconnect sync room with unknown cursor returns full room.
    #[test]
    fn reconnect_sync_room_with_unknown_cursor_returns_full_room() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        let room_id = service.create_room("sync-room-full").expect("room create");
        service
            .send_message_to_room(&room_id, "x1")
            .expect("send x1");
        service
            .send_message_to_room(&room_id, "x2")
            .expect("send x2");

        let synced = service
            .sync_room_messages_since(&room_id, Some("cursor-that-does-not-exist"))
            .expect("sync full fallback");
        assert_eq!(synced.len(), 2);
    }

    /// Resumable file transfers excludes completed and canceled.
    #[test]
    fn resumable_file_transfers_excludes_completed_and_canceled() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        let peer = "1111-2222-3333-4444";

        let completed_id = service
            .queue_file_send(peer, "done.bin", 10)
            .expect("queue completed candidate");
        let canceled_id = service
            .queue_file_send(peer, "cancel.bin", 10)
            .expect("queue canceled candidate");
        let queued_id = service
            .queue_file_send(peer, "queued.bin", 10)
            .expect("queue resumable candidate");

        service
            .update_file_transfer_progress(&completed_id, 10)
            .expect("complete transfer");
        service
            .cancel_file_transfer(&canceled_id)
            .expect("cancel transfer");

        let resumable = service.resumable_file_transfers();
        assert!(resumable.iter().any(|t| t.id == queued_id));
        assert!(!resumable.iter().any(|t| t.id == completed_id));
        assert!(!resumable.iter().any(|t| t.id == canceled_id));
    }

    /// Reconnect sync snapshot includes message delta and transfer resume set.
    #[test]
    fn reconnect_sync_snapshot_includes_message_delta_and_transfer_resume_set() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        let room_id = service.create_room("sync-snap").expect("room create");

        service
            .send_message_to_room(&room_id, "s1")
            .expect("send s1");
        service
            .send_message_to_room(&room_id, "s2")
            .expect("send s2");

        let cursor = service
            .messages_for_room(&room_id)
            .first()
            .expect("message exists")
            .id
            .clone();

        let queued_id = service
            .queue_file_send("AAAA-BBBB-CCCC-DDDD", "resume.bin", 42)
            .expect("queue transfer");

        let snapshot = service
            .reconnect_sync_snapshot(&room_id, Some(&cursor))
            .expect("build snapshot");
        assert_eq!(snapshot.missed_messages.len(), 1);
        assert_eq!(snapshot.missed_messages[0].text, "s2");
        assert!(snapshot
            .resumable_transfers
            .iter()
            .any(|transfer| transfer.id == queued_id));
    }

    /// Hosted services should enforce trust and transport ingress policy.
    #[test]
    fn hosted_service_access_policy_enforces_trust_and_transport() {
        let service = MeshInfinityService::new(ServiceConfig::default());

        service
            .configure_hosted_service_with_policy(
                "svc-work",
                "Work API",
                "/work",
                "10.0.0.10:8443",
                true,
                HostedServicePolicy {
                    min_trust_level: CoreTrustLevel::Trusted,
                    allowed_transports: vec![TransportType::Tor],
                },
            )
            .expect("configure hosted service");

        let _ = service.pair_peer("ABCD-EF01-2345-6789");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        // Default pairing trust is Caution, below Trusted requirement.
        let denied_low_trust = service
            .hosted_service_access_allowed("svc-work", &peer_id, TransportType::Tor)
            .expect("policy check");
        assert!(!denied_low_trust);

        service
            .peers
            .update_trust_level(
                &peer_id,
                CoreTrustLevel::Trusted,
                VerificationMethod::SharedSecret,
            )
            .expect("raise trust");

        // Trusted peer + allowed transport should pass.
        let allowed = service
            .hosted_service_access_allowed("svc-work", &peer_id, TransportType::Tor)
            .expect("policy check trusted tor");
        assert!(allowed);

        // Trusted peer but disallowed transport should fail.
        let denied_transport = service
            .hosted_service_access_allowed("svc-work", &peer_id, TransportType::Clearnet)
            .expect("policy check trusted clearnet");
        assert!(!denied_transport);
    }
}
