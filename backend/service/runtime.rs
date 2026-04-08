//! `MeshRuntime` — the single long-lived backend state container.
//!
//! Renamed from `MeshContext` (the God-object in `ffi/lib.rs`).  All fields
//! are identical; only the name and module location change.  The FFI shim
//! wraps this in a `Box` and passes a raw pointer to Flutter.
//!
//! ## Thread-safety
//! Every mutable field is wrapped in `std::sync::Mutex`.  The struct itself
//! is `Send + Sync`, so the raw pointer can safely cross FFI threads.
//!
//! ## Key material policy (§15.1)
//! No key material ever leaves this struct via FFI.  All FFI responses contain
//! only pre-validated, display-safe JSON.

use std::ffi::CString;
use std::sync::Mutex;

use crate::crypto::double_ratchet::DoubleRatchetSession;
use crate::identity::mesh_identity::MeshIdentity;
use crate::identity::peer_id::PeerId;
use crate::identity::self_identity::SelfIdentity;
use crate::mesh::MeshCoordinator;
use crate::messaging::room::Room;
use crate::network::security_policy::{
    cover_traffic_for_state, CoverTrafficParams, DeviceActivityState,
};
use crate::network::threat_context::ThreatContext;
use crate::pairing::contact::ContactStore;
use crate::routing::announcement::AnnouncementProcessor;
use crate::routing::loop_prevention::DeduplicationCache;
use crate::routing::store_forward::StoreForwardServer;
use crate::routing::table::{DeviceAddress, RoutingTable};
use crate::services::registry::ServiceStore;
use crate::storage::VaultManager;
use crate::transport::manager::TransportManager;
use crate::vpn::app_connector::AppConnectorConfig;
use crate::vpn::routing_mode::VpnManager;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Chunk size for file transfers: 64 KiB.
///
/// Chosen to keep individual read/write syscalls fast while delivering
/// granular progress updates to the Flutter UI.
pub const FILE_CHUNK_SIZE: usize = 65_536;

/// TCP port advertised in the Tor hidden service descriptor (§5.3).
///
/// Also used as the default clearnet listener port when none is configured.
pub const DEFAULT_HS_PORT: u16 = 7_234;

/// Number of file chunks to send per poll tick.
///
/// Limits how long a single poll cycle can block on file I/O so the event
/// loop stays responsive to other operations (keepalives, inbound frames, etc.).
pub const CHUNKS_PER_TICK: usize = 4;

// ---------------------------------------------------------------------------
// Vault-serialisable settings (§17.9 settings.vault)
// ---------------------------------------------------------------------------

/// Settings persisted to `settings.vault` (§17.9).
///
/// Mirrors the transport flags and node mode stored in `MeshRuntime`.
/// Deserialised on identity unlock and re-serialised on every settings change.
#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct SettingsVault {
    /// Node operating mode: 0 = client, 1 = relay, 2 = server.
    pub node_mode: u8,
    /// Threat context level (0 = Normal … 4 = Critical).
    pub threat_context: u8,
    /// Whether the Tor transport is enabled.
    pub tor: bool,
    /// Whether the clearnet TCP transport is enabled.
    pub clearnet: bool,
    /// Whether to fall back to clearnet when other transports fail.
    pub clearnet_fallback: bool,
    /// Whether the I2P transport is enabled.
    pub i2p: bool,
    /// Whether Bluetooth transport is enabled.
    pub bluetooth: bool,
    /// Whether the SDR/RF transport is enabled.
    pub rf: bool,
    /// Whether LAN peer discovery is enabled.
    pub mesh_discovery: bool,
    /// Whether to allow store-and-forward relay nodes.
    pub allow_relays: bool,
    /// Clearnet TCP listen port. 0 = use default (7234).
    pub clearnet_port: u16,
    /// Notification tier (1-4). 0 = use default (1 = MeshTunnel).
    pub notification_tier: u8,
    /// Whether notifications are enabled at all.
    pub notification_enabled: bool,
    /// Self-hosted push relay URL (empty = platform default).
    pub notification_push_url: String,
    /// Whether to show message previews in notifications.
    pub notification_show_previews: bool,
    /// Module enable/disable configuration (§17.13).
    #[serde(default)]
    pub module_config: Option<serde_json::Value>,
    /// App Connector configuration stored in backend-owned form.
    #[serde(default)]
    pub app_connector_config: Option<AppConnectorConfig>,
    /// Whether the pre-committed distress message feature is enabled.
    #[serde(default)]
    pub distress_message_enabled: bool,
    /// Whether periodic liveness signals are enabled.
    #[serde(default)]
    pub liveness_signal_enabled: bool,
    /// Whether to erase after repeated wrong PIN attempts.
    #[serde(default)]
    pub wrong_pin_wipe_enabled: bool,
    /// Wrong-PIN wipe threshold.
    #[serde(default = "default_wrong_pin_wipe_threshold")]
    pub wrong_pin_wipe_threshold: u8,
    /// Whether remote erase is allowed for authorised peers.
    #[serde(default)]
    pub remote_wipe_enabled: bool,
    /// Highest unlocked feature tier (0 = social .. 4 = power).
    #[serde(default)]
    pub active_tier: u8,
    /// Mesh participation profile (0 = minimal, 1 = standard, 2 = generous).
    #[serde(default = "default_bandwidth_profile")]
    pub bandwidth_profile: u8,
}

/// Minimal plaintext startup posture for Layer 1 before full identity unlock.
///
/// This record exists specifically so the native Android startup path can
/// restore transport posture and node mode before the encrypted settings vault
/// is available. It contains only startup-relevant transport state.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Layer1StartupConfig {
    /// Node operating mode: 0 = client, 1 = relay, 2 = server.
    pub node_mode: u8,
    /// Threat context level (0 = Normal … 4 = Critical).
    pub threat_context: u8,
    /// Whether the Tor transport should be started when allowed.
    pub tor: bool,
    /// Whether the clearnet TCP transport should be started when allowed.
    pub clearnet: bool,
    /// Whether the I2P transport should be started when allowed.
    pub i2p: bool,
    /// Whether Bluetooth transport should be started when allowed.
    pub bluetooth: bool,
    /// Whether RF transport should be started when allowed.
    pub rf: bool,
    /// Whether LAN peer discovery should be started when allowed.
    pub mesh_discovery: bool,
    /// Whether Layer 1 should participate in relaying/store-and-forward.
    pub allow_relays: bool,
    /// Clearnet TCP listen port.
    pub clearnet_port: u16,
}

impl Default for Layer1StartupConfig {
    fn default() -> Self {
        Self {
            node_mode: 0,
            threat_context: crate::network::threat_context::ThreatContext::Normal as u8,
            tor: false,
            clearnet: false,
            i2p: false,
            bluetooth: false,
            rf: false,
            mesh_discovery: true,
            allow_relays: true,
            clearnet_port: DEFAULT_HS_PORT,
        }
    }
}

/// Backend-owned directory entry for a discoverable Garden.
#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct GardenDirectoryEntry {
    /// Stable Garden identifier.
    pub id: String,
    /// Human-facing Garden name.
    pub name: String,
    /// Short description for discovery surfaces.
    pub description: String,
    /// Visibility/network type label: public/open/closed/private.
    pub network_type: String,
    /// Last known member count, if available.
    pub member_count: u32,
}

/// Backend-owned snapshot of Android proximity capability and peer state.
#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AndroidProximityState {
    /// Whether the current runtime is Android-backed.
    pub is_android: bool,
    /// Whether NFC hardware exists.
    pub nfc_available: bool,
    /// Whether NFC is currently enabled.
    pub nfc_enabled: bool,
    /// Whether Wi-Fi Direct hardware exists.
    pub wifi_direct_available: bool,
    /// Whether Wi-Fi Direct is enabled.
    pub wifi_direct_enabled: bool,
    /// Whether the required Wi-Fi Direct runtime permission is granted.
    pub wifi_direct_permission_granted: bool,
    /// Whether peer discovery is active.
    pub wifi_direct_discovery_active: bool,
    /// Whether a Wi-Fi Direct link is connected.
    pub wifi_direct_connected: bool,
    /// Current connection role.
    pub wifi_direct_connection_role: Option<String>,
    /// Current group owner address.
    pub wifi_direct_group_owner_address: Option<String>,
    /// Current connected device address.
    pub wifi_direct_connected_device_address: Option<String>,
    /// Current discovered peers.
    #[serde(default)]
    pub peers: Vec<AndroidWifiDirectPeer>,
}

/// Backend-owned snapshot of Android startup and unlock milestones.
#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub struct AndroidStartupState {
    /// Whether the current runtime is Android-backed.
    pub is_android: bool,
    /// Whether the device has reported locked-boot completion.
    pub locked_boot_completed: bool,
    /// Whether the device has reported full boot completion.
    pub boot_completed: bool,
    /// Whether the user profile has been unlocked.
    pub user_unlocked: bool,
    /// Whether the native startup path believes background startup is allowed.
    pub direct_boot_aware: bool,
    /// Last observed startup event, if any.
    pub last_event: Option<String>,
    /// Last observed startup event timestamp (milliseconds since epoch).
    pub last_event_at_ms: Option<u64>,
    /// Whether the direct-boot-aware Android startup service has been started.
    pub startup_service_started: bool,
    /// Whether the startup service currently believes it is foreground-active.
    pub startup_service_foreground: bool,
    /// Last startup-service start timestamp (milliseconds since epoch).
    pub startup_service_last_start_at_ms: Option<u64>,
    /// Last startup-service stop timestamp (milliseconds since epoch).
    pub startup_service_last_stop_at_ms: Option<u64>,
}

/// One Wi-Fi Direct peer as surfaced by the Android platform layer.
#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AndroidWifiDirectPeer {
    /// Human-facing device name.
    pub device_name: String,
    /// Stable device MAC/address.
    pub device_address: String,
    /// Platform status string.
    pub status: String,
    /// Primary device type, if known.
    pub primary_device_type: Option<String>,
    /// Secondary device type, if known.
    pub secondary_device_type: Option<String>,
    /// Whether the peer is group owner.
    pub is_group_owner: bool,
}

/// Persisted metadata for one registered device in a shared identity.
#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct RegisteredDevice {
    /// Stable 16-byte device identifier rendered as hex.
    pub id: String,
    /// Human-facing device name.
    pub name: String,
    /// Platform label used by the UI.
    pub platform: String,
    /// Administrative primary-device flag.
    pub is_primary: bool,
    /// When the device was registered.
    pub added_at_ms: u64,
    /// Last time the device was seen active by this registry.
    pub last_seen_ms: u64,
    /// Device that authorized this registration, if known.
    pub authorized_by_device_id: Option<String>,
}

const fn default_wrong_pin_wipe_threshold() -> u8 {
    5
}

const fn default_bandwidth_profile() -> u8 {
    1
}

// ---------------------------------------------------------------------------
// Type aliases for complex field types
// ---------------------------------------------------------------------------

/// Pending X3DH header: (ephemeral_pub [32], encrypted_ik [48]).
///
/// Stored keyed by peer ID; cleared when the peer sends its first reply
/// (which confirms it has derived the matching session).
pub type X3dhPendingMap = Mutex<std::collections::HashMap<PeerId, ([u8; 32], [u8; 48])>>;

/// Pending PQXDH extension: (kem_ciphertext, kem_binding [32]).
///
/// Set alongside `X3dhPendingMap` when Alice's ratchet session was bootstrapped
/// with the post-quantum extension.  Cleared on first reply from Bob.
pub type PqxdhPendingMap = Mutex<std::collections::HashMap<PeerId, (Vec<u8>, [u8; 32])>>;

// ---------------------------------------------------------------------------
// File transfer I/O state
// ---------------------------------------------------------------------------

/// Per-transfer I/O state for an active file transfer.
///
/// Stored in `MeshRuntime::active_file_io` keyed by `transfer_id`.
/// Holds the open file handle and current byte offset so the poll loop can
/// resume chunked I/O across ticks without re-opening the file.
pub struct FileIoState {
    /// Transfer direction (Send = we are uploading, Receive = we are downloading).
    pub direction: FileDirection,
    /// Hex peer ID of the other party.
    pub peer_id: String,
    /// 32-byte file identifier (SHA-256 of plaintext) sent on the wire.
    pub file_id: [u8; 32],
    /// Total file size in bytes (exact for send; from offer for receive).
    pub total_bytes: u64,
    /// Bytes successfully transferred so far.
    pub transferred_bytes: u64,
    /// Open file handle used for reading (send) or writing (receive).
    pub file: std::fs::File,
}

/// Whether a transfer is outbound (we send) or inbound (we receive).
#[derive(PartialEq, Eq)]
pub enum FileDirection {
    /// We are sending the file to a remote peer.
    Send,
    /// We are receiving the file from a remote peer.
    Receive,
}

// ---------------------------------------------------------------------------
// Per-transport enable/disable flags (§5.10)
// ---------------------------------------------------------------------------

/// Per-transport enable/disable flags.
///
/// Stored inside `MeshRuntime` and persisted to `SettingsVault` so they
/// survive restarts.
#[derive(Clone)]
pub struct TransportFlags {
    /// Whether the Tor hidden-service transport is active.
    pub tor: bool,
    /// Whether the clearnet TCP transport is active.
    pub clearnet: bool,
    /// Whether to fall back to clearnet when mesh/Tor paths are unavailable.
    pub clearnet_fallback: bool,
    /// Whether the I2P transport is active.
    pub i2p: bool,
    /// Whether Bluetooth LE transport is active.
    pub bluetooth: bool,
    /// Whether the SDR/RF transport is active.
    pub rf: bool,
    /// Whether LAN UDP broadcast discovery is active.
    pub mesh_discovery: bool,
    /// Whether to use store-and-forward relay nodes.
    pub allow_relays: bool,
}

impl Default for TransportFlags {
    /// Default flags match the spec bootstrap state: clearnet on, all others off
    /// except mesh_discovery and allow_relays which are on for usability.
    fn default() -> Self {
        Self {
            tor: false,
            clearnet: true,
            clearnet_fallback: true,
            i2p: false,
            bluetooth: false,
            rf: false,
            mesh_discovery: true,
            allow_relays: true,
        }
    }
}

// ---------------------------------------------------------------------------
// MeshRuntime
// ---------------------------------------------------------------------------

/// Opaque context handle passed to all FFI functions.
///
/// Owns **all** backend state — a single long-lived instance per app process.
/// The FFI shim allocates it with `Box::new`, converts to a raw pointer via
/// `Box::into_raw`, and hands that pointer to Flutter.  On shutdown,
/// `Box::from_raw` reconstructs the box and drops it.
///
/// ## Thread safety
/// Every mutable field is wrapped in `std::sync::Mutex`.  `identity_unlocked`
/// and `threat_context` are plain values, only mutated on the Flutter thread
/// which serialises access through the poll-events loop.
pub struct MeshRuntime {
    /// Data directory used for all vault storage files.
    pub data_dir: String,
    /// Vault manager — `Some` after identity unlock, `None` before.
    pub vault: Option<VaultManager>,
    /// Last JSON response string; kept alive so the returned pointer is stable
    /// until the next FFI call on this thread.
    pub last_response: Mutex<Option<CString>>,
    /// Last error string; same lifetime contract as `last_response`.
    pub last_error: Mutex<Option<CString>>,
    /// Current threat context level (Normal / Elevated / High / Critical).
    pub threat_context: ThreatContext,
    /// In-memory room cache; written through to vault on every mutation.
    pub rooms: Mutex<Vec<Room>>,
    /// Whether Layer 2/3 identity keys are currently unlocked.
    pub identity_unlocked: bool,
    /// ID of the conversation currently displayed in the Flutter UI.
    ///
    /// Used for read-receipt priority escalation (§16.9.3).
    pub active_conversation: Mutex<Option<[u8; 16]>>,
    /// Contact store: all peers we have completed pairing with.
    pub contacts: Mutex<ContactStore>,
    /// VPN routing manager (client / relay / exit-node mode).
    pub vpn: Mutex<VpnManager>,
    /// App Connector configuration (§13.15).
    pub app_connector_config: Mutex<AppConnectorConfig>,
    /// Whether the pre-committed distress message is enabled.
    pub distress_message_enabled: Mutex<bool>,
    /// Whether periodic liveness signals are enabled.
    pub liveness_signal_enabled: Mutex<bool>,
    /// Whether automatic wipe on repeated wrong PIN attempts is enabled.
    pub wrong_pin_wipe_enabled: Mutex<bool>,
    /// Wrong-PIN wipe threshold.
    pub wrong_pin_wipe_threshold: Mutex<u8>,
    /// Whether remote erase is enabled.
    pub remote_wipe_enabled: Mutex<bool>,
    /// Highest unlocked feature tier (0 = social .. 4 = power).
    pub active_tier: Mutex<u8>,
    /// Mesh participation profile (0 = minimal, 1 = standard, 2 = generous).
    pub bandwidth_profile: Mutex<u8>,
    /// Persisted mask metadata for the identity & masks UI.
    pub masks: Mutex<Vec<crate::identity::mask::MaskMetadata>>,
    /// Backend-owned directory of discoverable Gardens.
    pub discoverable_gardens: Mutex<Vec<GardenDirectoryEntry>>,
    /// Backend-owned snapshot of Android proximity transport state.
    pub android_proximity_state: Mutex<AndroidProximityState>,
    /// Backend-owned Android startup/unlock snapshot.
    pub android_startup_state: Mutex<AndroidStartupState>,
    /// Backend-owned cache of gossiped service records.
    pub service_registry: Mutex<ServiceStore>,
    /// Registered devices participating in this shared identity.
    pub registered_devices: Mutex<Vec<RegisteredDevice>>,
    /// Per-room message cache.  Key = room_id hex, value = JSON message list.
    pub messages: Mutex<std::collections::HashMap<String, Vec<serde_json::Value>>>,
    /// Loaded self-identity (Layer 2 keys).  `Some` after unlock.
    pub identity: Mutex<Option<SelfIdentity>>,
    /// Loaded mesh identity (transport-facing WireGuard keypair).
    pub mesh_identity: Mutex<Option<MeshIdentity>>,
    /// Pending backend events drained by `mi_poll_events()`.
    ///
    /// Each entry is `{"type": "EventName", "data": {...}}`.
    pub event_queue: Mutex<std::collections::VecDeque<serde_json::Value>>,
    /// Per-transport enable/disable state.
    pub transport_flags: Mutex<TransportFlags>,
    /// Node operating mode: 0 = client, 1 = relay, 2 = server.
    pub node_mode: Mutex<u8>,
    /// SDR/RF transport manager (LoRa, HackRF, LimeSDR, etc.).
    pub sdr: Mutex<crate::transport::rf_sdr::SdrManager>,
    /// Whether LAN UDP broadcast discovery is currently running.
    pub mdns_running: Mutex<bool>,
    /// Peers discovered on the local network (ephemeral; cleared on disable).
    pub mdns_discovered: Mutex<Vec<serde_json::Value>>,
    /// UDP socket for LAN presence broadcasts (SO_BROADCAST, 0.0.0.0:7235).
    pub lan_discovery_socket: Mutex<Option<std::net::UdpSocket>>,
    /// Monotonic instant of the next scheduled LAN presence announce (~5 s).
    pub lan_next_announce: Mutex<std::time::Instant>,
    /// Cooldown cache: endpoint → last time we initiated a TCP handshake.
    ///
    /// Prevents re-initiating the challenge-response for recently-seen peers.
    pub lan_discovery_seen: Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// Endpoints queued for the LAN discovery TCP handshake (§4.9.5).
    ///
    /// Populated by `handle_lan_presence_packet`; drained by
    /// `advance_lan_discovery_handshakes`.
    pub lan_discovery_pending: Mutex<Vec<String>>,
    /// Active file-transfer descriptors (in-progress send/receive).
    pub file_transfers: Mutex<Vec<serde_json::Value>>,
    /// Per-transfer file I/O state, keyed by transfer_id.
    pub active_file_io: Mutex<std::collections::HashMap<String, FileIoState>>,
    /// Locally published file metadata for the distributed-files UI.
    pub published_files: Mutex<Vec<crate::files::hosted::HostedFileEntry>>,
    /// Overlay network clients (Tailscale, ZeroTier).
    pub overlay: Mutex<crate::transport::overlay_client::OverlayManager>,
    /// Backend-owned transport availability and diversity state.
    pub transport_manager: Mutex<TransportManager>,
    /// Current Layer 1 activity state for cover-traffic policy.
    pub layer1_activity_state: Mutex<DeviceActivityState>,
    /// Current Layer 1 cover-traffic parameters.
    pub layer1_cover_traffic: Mutex<CoverTrafficParams>,
    /// Whether backend startup has activated Layer 1 participation.
    pub layer1_participation_started: Mutex<bool>,
    /// Gossip engine: network map propagation (§4.1, §4.5).
    pub gossip: Mutex<crate::network::gossip::GossipEngine>,
    /// Notification dispatcher: jitter, coalescing, threat suppression (§14).
    pub notifications: Mutex<crate::notifications::NotificationDispatcher>,
    /// Groups the user belongs to (persisted to vault).
    pub groups: Mutex<Vec<crate::groups::group::Group>>,
    /// Double Ratchet sessions per peer.
    ///
    /// Not persisted to vault by default; rebuilt from static DH on demand.
    /// Optional vault persistence is performed by `save_ratchet_sessions`.
    pub ratchet_sessions: Mutex<std::collections::HashMap<PeerId, DoubleRatchetSession>>,
    /// Pending X3DH init headers: (eph_pub [32], encrypted_ik [48]).
    ///
    /// Included in every outgoing message until the peer replies, confirming
    /// it has derived the matching session.
    pub x3dh_pending: X3dhPendingMap,
    /// Pending PQXDH extension headers: (kem_ciphertext, kem_binding).
    ///
    /// Set alongside `x3dh_pending` when PQXDH was used; cleared on first reply.
    pub pqxdh_pending: PqxdhPendingMap,
    /// Clearnet TCP listener socket (non-blocking).
    pub clearnet_listener: Mutex<Option<std::net::TcpListener>>,
    /// Active identified clearnet connections: peer_id_hex → stream.
    pub clearnet_connections: Mutex<std::collections::HashMap<String, std::net::TcpStream>>,
    /// Pending incoming connections not yet identified by a first message.
    pub clearnet_pending_incoming: Mutex<Vec<(std::net::TcpStream, Vec<u8>)>>,
    /// Per-peer receive buffers for partial TCP frames.
    pub clearnet_recv_buffers: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    /// Clearnet TCP listen port (default 7234).
    pub clearnet_port: Mutex<u16>,
    /// Outbox: messages that failed TCP delivery, retried each poll cycle.
    ///
    /// Each entry: `(peer_id_hex, endpoint, encrypted_envelope_bytes)`.
    pub outbox: Mutex<Vec<(String, String, Vec<u8>)>>,
    /// Active call state: `(call_state, remote_peer_hex)`.
    ///
    /// `None` when no call is in progress (§10.1.6).
    pub active_call: Mutex<Option<(crate::calls::CallState, String)>>,
    /// Four-plane routing table (§6.1, §6.4).
    pub routing_table: Mutex<RoutingTable>,
    /// Announcement processor: deduplicates and propagates reachability
    /// announcements (§6.2).
    pub announcement_processor: Mutex<AnnouncementProcessor>,
    /// Packet deduplication cache: prevents forwarding loops (§6.6).
    pub dedup_cache: Mutex<DeduplicationCache>,
    /// Module enable/disable configuration (§17.13).
    pub module_config: Mutex<crate::services::module_system::ModuleConfig>,
    /// Mesh routing coordinator: bridges routing table with transport layer.
    ///
    /// Held for `Drop` and future use; not yet wired to inbound/outbound paths.
    pub _mesh: MeshCoordinator,
    /// Per-peer WireGuard sessions for link-layer encryption (§5.2).
    pub wireguard_sessions: Mutex<crate::transport::wireguard::WireGuardSessionStore>,
    /// Store-and-forward server (§6.8): buffers messages for offline peers.
    pub sf_server: Mutex<StoreForwardServer>,
    /// Tunnel-coordination gossip state keyed by mesh WireGuard public keys.
    pub tunnel_gossip: Mutex<crate::routing::tunnel_gossip::TunnelGossipProcessor>,
    /// Per-peer last-received timestamp for keepalive tracking.
    pub clearnet_last_rx: Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// Per-peer last-keepalive-sent timestamp, throttled to once per interval.
    pub clearnet_last_keepalive_tx: Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// Tor transport (§5.3).  `Some` when Tor is enabled and bootstrapped.
    pub tor_transport: Mutex<Option<crate::transport::tor::TorTransport>>,
    /// Pending WireGuard initiator handshakes awaiting the responder's reply.
    ///
    /// Keyed by responder `PeerId`; consumed by `wg_complete_handshake`.
    pub pending_wg_handshakes: Mutex<
        std::collections::HashMap<PeerId, crate::transport::wireguard::PendingInitiatorHandshake>,
    >,
    /// Deduplication cache for inbound message IDs (HIGH-4).
    ///
    /// Prevents replay attacks where an attacker or network glitch re-delivers
    /// a previously processed message.  Bounded per room (LRU, 10 000 entries)
    /// to prevent unbounded memory growth.  Persisted to vault across restarts.
    pub dedup_msg_cache: Mutex<crate::messaging::delivery::DeliveredMessageCache>,
    /// Pending message requests from unpaired senders (§10.1.1).
    ///
    /// Messages arriving via `message_request` frames from peers who are NOT
    /// in the contact store land here instead of the main inbox.  Persisted to
    /// vault so the queue survives app restarts.  Rate-limited to 5 requests
    /// per unique sender and 200 total entries; requests older than 30 days
    /// are pruned on load.
    pub pending_message_requests: Mutex<Vec<serde_json::Value>>,
    /// Stop flag for the Tailscale background map-poll thread (§5.23).
    ///
    /// `None` when no poll thread is running.  `Some(flag)` while the thread
    /// is alive — setting the flag to `false` asks the thread to exit on its
    /// next iteration.  The `Arc` allows the thread and the runtime to both
    /// hold a handle; dropping the outer `Option` does not stop the thread
    /// immediately, only the flag does.
    pub tailscale_poll_active: Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
    /// Live ZeroTier UDP transport (§5.22).
    ///
    /// `Some` after a successful `sync_zerotier_client` call.  Held here (not
    /// in `OverlayManager`) because `ZeroTierTransport` owns a `UdpSocket`
    /// and cannot be serialised to JSON.  The `Arc` is shared with the
    /// background receive thread started by `start_recv()`.
    pub zerotier_transport: Mutex<Option<std::sync::Arc<crate::transport::zerotier::ZeroTierTransport>>>,
}

// SAFETY: All mutable state is wrapped in `Mutex`, making MeshRuntime safe
// to share across threads.  The raw pointer used in FFI is never aliased
// while Rust code holds a reference.
unsafe impl Send for MeshRuntime {}
unsafe impl Sync for MeshRuntime {}

impl MeshRuntime {
    /// Construct a new, empty `MeshRuntime` for the given data directory.
    ///
    /// No vault files are read here; call `load_from_vault` after unlocking
    /// the identity to populate rooms, contacts, settings, and messages.
    pub fn new(data_dir: String) -> Self {
        Self {
            data_dir,
            vault: None,
            last_response: Mutex::new(None),
            last_error: Mutex::new(None),
            threat_context: ThreatContext::Normal,
            rooms: Mutex::new(Vec::new()),
            identity_unlocked: false,
            active_conversation: Mutex::new(None),
            contacts: Mutex::new(ContactStore::new()),
            vpn: Mutex::new(VpnManager::new()),
            app_connector_config: Mutex::new(AppConnectorConfig::default()),
            distress_message_enabled: Mutex::new(false),
            liveness_signal_enabled: Mutex::new(false),
            wrong_pin_wipe_enabled: Mutex::new(false),
            wrong_pin_wipe_threshold: Mutex::new(default_wrong_pin_wipe_threshold()),
            remote_wipe_enabled: Mutex::new(false),
            active_tier: Mutex::new(0),
            bandwidth_profile: Mutex::new(default_bandwidth_profile()),
            masks: Mutex::new(Vec::new()),
            discoverable_gardens: Mutex::new(Vec::new()),
            android_proximity_state: Mutex::new(AndroidProximityState::default()),
            android_startup_state: Mutex::new(AndroidStartupState::default()),
            service_registry: Mutex::new(ServiceStore::new()),
            registered_devices: Mutex::new(Vec::new()),
            messages: Mutex::new(std::collections::HashMap::new()),
            identity: Mutex::new(None),
            mesh_identity: Mutex::new(None),
            event_queue: Mutex::new(std::collections::VecDeque::new()),
            transport_flags: Mutex::new(TransportFlags::default()),
            node_mode: Mutex::new(0),
            sdr: Mutex::new(crate::transport::rf_sdr::SdrManager::new()),
            mdns_running: Mutex::new(false),
            mdns_discovered: Mutex::new(Vec::new()),
            lan_discovery_socket: Mutex::new(None),
            lan_next_announce: Mutex::new(std::time::Instant::now()),
            lan_discovery_seen: Mutex::new(std::collections::HashMap::new()),
            lan_discovery_pending: Mutex::new(Vec::new()),
            file_transfers: Mutex::new(Vec::new()),
            active_file_io: Mutex::new(std::collections::HashMap::new()),
            published_files: Mutex::new(Vec::new()),
            overlay: Mutex::new(crate::transport::overlay_client::OverlayManager::new()),
            transport_manager: Mutex::new(TransportManager::new()),
            layer1_activity_state: Mutex::new(DeviceActivityState::Backgrounded),
            layer1_cover_traffic: Mutex::new(cover_traffic_for_state(
                DeviceActivityState::Backgrounded,
            )),
            layer1_participation_started: Mutex::new(false),
            gossip: Mutex::new(crate::network::gossip::GossipEngine::new()),
            notifications: Mutex::new(crate::notifications::NotificationDispatcher::new(
                crate::notifications::NotificationConfig::default(),
            )),
            groups: Mutex::new(Vec::new()),
            ratchet_sessions: Mutex::new(std::collections::HashMap::new()),
            clearnet_listener: Mutex::new(None),
            clearnet_connections: Mutex::new(std::collections::HashMap::new()),
            clearnet_pending_incoming: Mutex::new(Vec::new()),
            clearnet_recv_buffers: Mutex::new(std::collections::HashMap::new()),
            clearnet_port: Mutex::new(7_234),
            outbox: Mutex::new(Vec::new()),
            x3dh_pending: Mutex::new(std::collections::HashMap::new()),
            pqxdh_pending: Mutex::new(std::collections::HashMap::new()),
            active_call: Mutex::new(None),
            module_config: Mutex::new(crate::services::module_system::ModuleConfig::default()),
            _mesh: MeshCoordinator::new(),
            wireguard_sessions: Mutex::new(
                crate::transport::wireguard::WireGuardSessionStore::new(),
            ),
            routing_table: Mutex::new(RoutingTable::new()),
            // The announcement processor needs our own address, which is
            // only known after identity unlock.  We use all-zeros as a
            // placeholder and replace it in `load_from_vault`.
            announcement_processor: Mutex::new(AnnouncementProcessor::new(
                DeviceAddress([0u8; 32]),
                10, // default link latency estimate: 10 ms
            )),
            dedup_cache: Mutex::new(DeduplicationCache::new()),
            sf_server: Mutex::new(StoreForwardServer::new_client()),
            tunnel_gossip: Mutex::new(crate::routing::tunnel_gossip::TunnelGossipProcessor::new(
                [0u8; 32],
            )),
            clearnet_last_rx: Mutex::new(std::collections::HashMap::new()),
            clearnet_last_keepalive_tx: Mutex::new(std::collections::HashMap::new()),
            tor_transport: Mutex::new(None),
            pending_wg_handshakes: Mutex::new(std::collections::HashMap::new()),
            dedup_msg_cache: Mutex::new(crate::messaging::delivery::DeliveredMessageCache::new()),
            pending_message_requests: Mutex::new(Vec::new()),
            // No background poll thread is running at startup.
            tailscale_poll_active: Mutex::new(None),
            // No ZeroTier transport socket is active at startup.
            zerotier_transport: Mutex::new(None),
        }
    }

    // -----------------------------------------------------------------------
    // Core event helpers
    // -----------------------------------------------------------------------

    /// Push an event onto the queue.
    ///
    /// Flutter receives it on the next `mi_poll_events` call.  The event is
    /// a JSON object `{"type": "<name>", "data": <payload>}`.
    pub fn push_event(&self, event_type: &str, data: serde_json::Value) {
        // Build the envelope and append it to the back of the queue.
        let event = serde_json::json!({
            "type": event_type,
            "data": data,
        });
        self.event_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(event);
    }

    /// Push a `TransferUpdated` event for an active file transfer.
    ///
    /// Looks up the transfer by ID in the in-memory list and pushes a
    /// `TransferUpdated` event with its current `FileTransferModel` JSON.
    /// The Flutter `FilesState` listens to this event to update progress bars.
    pub fn push_transfer_update(&self, transfer_id: &str) {
        // Find the transfer JSON by its ID field.
        let transfer_json = {
            let transfers = self
                .file_transfers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            transfers
                .iter()
                .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(transfer_id))
                .cloned()
        };
        // Only push if the transfer still exists (may have been removed concurrently).
        if let Some(t) = transfer_json {
            self.push_event("TransferUpdated", t);
        }
    }

    // -----------------------------------------------------------------------
    // Response / error helpers used by the FFI shim
    // -----------------------------------------------------------------------

    /// Store a JSON response string and return a stable pointer to it.
    ///
    /// The `CString` is kept alive inside `last_response` so the pointer
    /// remains valid until the next FFI call that calls `set_response` or
    /// `set_error`.  Flutter must copy the string before making another call.
    pub fn set_response(&self, json: &str) -> *const std::os::raw::c_char {
        // Build a NUL-terminated CString from the JSON; replace invalid bytes
        // with a safe error message so we never return a null pointer for a
        // non-null context.
        let cstr = CString::new(json)
            .unwrap_or_else(|_| CString::new(r#"{"error":"response encoding error"}"#).unwrap());
        let ptr = cstr.as_ptr();
        *self.last_response.lock().unwrap_or_else(|e| e.into_inner()) = Some(cstr);
        ptr
    }

    /// Store an error string in `last_error` and return a stable pointer.
    ///
    /// Same lifetime contract as `set_response`.  The error is also appended
    /// to the event queue as an `Error` event so Flutter can display it.
    pub fn set_error(&self, msg: &str) -> *const std::os::raw::c_char {
        // Push an Error event so Flutter can display it in the UI.
        self.push_event("Error", serde_json::json!({ "message": msg }));
        let cstr = CString::new(msg).unwrap_or_else(|_| CString::new("encoding error").unwrap());
        let ptr = cstr.as_ptr();
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(cstr);
        ptr
    }
}

// ---------------------------------------------------------------------------
// Free helpers used by both service sub-modules and the FFI shim
// ---------------------------------------------------------------------------

/// Write a length-prefixed TCP frame to the stream.
///
/// Frame format: `[4-byte big-endian length][payload]`.
/// Rejects payloads larger than 4 MiB to prevent allocating attacker-controlled
/// buffers on the receiving end.
pub fn write_tcp_frame(stream: &mut std::net::TcpStream, payload: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    // Hard cap at 4 MiB — any larger frame is either a bug or an attack.
    if payload.len() > 4 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame payload exceeds 4 MiB limit",
        ));
    }
    // Write length prefix followed by payload in one logical write sequence.
    let len_bytes = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

/// Try to read one complete length-prefixed frame from a receive buffer.
///
/// Returns `Some(payload)` and drains the consumed bytes from `buf` when a
/// full frame is available.  Returns `None` when more data is needed.
///
/// Discards the buffer completely if the declared length exceeds 4 MiB —
/// that indicates garbage data or a malformed/malicious frame, and continuing
/// to accumulate bytes would only waste memory.
pub fn try_read_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    // Need at least 4 bytes for the length header.
    if buf.len() < 4 {
        return None;
    }
    let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    // Reject oversized frames to prevent allocation attacks.
    if frame_len > 4 * 1024 * 1024 {
        buf.clear();
        return None;
    }
    // Check whether the full payload has arrived.
    if buf.len() < 4 + frame_len {
        return None;
    }
    // Extract and drain the frame bytes.
    let payload = buf[4..4 + frame_len].to_vec();
    buf.drain(..4 + frame_len);
    Some(payload)
}

/// Extract the sender peer_id hex from a raw frame payload.
///
/// Parses only the top-level JSON `"sender"` field without decrypting the
/// message body.  Used to identify which peer sent a frame so we can key
/// the TCP connection map.
///
/// Validates that the sender is exactly 64 hex characters (32 bytes).
pub fn extract_frame_sender(frame_payload: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(frame_payload).ok()?;
    let sender = v.get("sender").and_then(|s| s.as_str())?;
    // A valid peer ID is exactly 32 bytes = 64 hex characters.
    if sender.len() == 64 && sender.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(sender.to_string())
    } else {
        None
    }
}

/// Detect the primary outbound-capable local IP address.
///
/// Uses a connect-without-send trick: binding a UDP socket and calling
/// `connect()` lets the OS select the right interface without any actual
/// network traffic.
pub fn local_clearnet_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // Target is a well-known public address; only OS routing is queried.
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Fill `dest` with cryptographically secure random bytes.
///
/// Returns `true` on success, `false` if the OS RNG is unavailable.
/// Callers must check the return value and propagate the failure as an
/// error rather than panicking — panicking through FFI is undefined behaviour.
pub fn try_random_fill(dest: &mut [u8]) -> bool {
    use rand_core::RngCore;
    // OsRng::fill_bytes() panics on OS failure in rand_core 0.6.
    // Use catch_unwind so RNG failures degrade gracefully instead of aborting.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rand_core::OsRng.fill_bytes(dest);
    }))
    .is_ok()
}

/// Construct the `SettingsUpdated` payload JSON for a `push_event` call.
///
/// Called whenever any transport flag, node mode, or threat context changes
/// so Flutter's `SettingsState` receives an up-to-date snapshot.
pub fn build_settings_json(
    flags: &TransportFlags,
    node_mode: u8,
    threat_context: &ThreatContext,
    peer_id: &str,
    ed25519_pub: &str,
    clearnet_port: u16,
    active_tier: u8,
    bandwidth_profile: u8,
    layer1_status: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "nodeMode":          node_mode,
        "enableTor":         flags.tor,
        "enableClearnet":    flags.clearnet,
        "meshDiscovery":     flags.mesh_discovery,
        "allowRelays":       flags.allow_relays,
        "enableI2p":         flags.i2p,
        "enableBluetooth":   flags.bluetooth,
        "enableRf":          flags.rf,
        "threatContext":     *threat_context as u8,
        "pairingCode":       peer_id,
        "localPeerId":       peer_id,
        "publicKey":         ed25519_pub,
        "clearnetPort":      clearnet_port,
        "activeTier":        active_tier.min(4),
        "bandwidthProfile":  bandwidth_profile.min(2),
        "layer1Status":      layer1_status,
    })
}

// ---------------------------------------------------------------------------
// Session bootstrap helpers
// ---------------------------------------------------------------------------

/// X3DH init header wire fields: (eph_pub [32], encrypted_ik [48]).
pub type X3dhWireHeader = ([u8; 32], [u8; 48]);

/// PQXDH extension wire fields: (kem_ciphertext, kem_binding [32]).
pub type PqxdhWireExt = (Vec<u8>, [u8; 32]);

/// Bootstrap a Double Ratchet session with a contact using the best available
/// key agreement protocol.
///
/// Priority:
/// 1. X3DH/PQXDH (if the contact has a preauth key advertised).
/// 2. Static DH fallback (for legacy contacts without a preauth key).
///
/// Returns `(session, Option<X3DH_header>, Option<PQXDH_extension>)`.
/// When X3DH was used, the caller must store the header in `x3dh_pending`
/// and include it in every outgoing message until Bob replies.
pub fn bootstrap_ratchet_session(
    our_id: &SelfIdentity,
    contact: &crate::pairing::contact::ContactRecord,
) -> Result<
    (
        DoubleRatchetSession,
        Option<X3dhWireHeader>,
        Option<PqxdhWireExt>,
    ),
    String,
> {
    // Try X3DH/PQXDH first when the contact advertises a preauth key.
    if let Some(preauth_bytes) = contact.preauth_key {
        if let Ok((session, header, pq_ext)) =
            x3dh_bootstrap_session(our_id, contact, &preauth_bytes)
        {
            return Ok((session, Some(header), pq_ext));
        }
    }
    // Fall back to the static DH path for legacy or minimal contacts.
    static_dh_bootstrap_session(our_id, contact).map(|s| (s, None, None))
}

/// X3DH/PQXDH session bootstrap (preferred path).
///
/// Returns `(session, init_header, Option<pqxdh_ext>)`.
/// The init header must be embedded in the first outgoing encrypted message
/// so Bob can derive his matching ratchet session.
fn x3dh_bootstrap_session(
    our_id: &SelfIdentity,
    contact: &crate::pairing::contact::ContactRecord,
    bob_preauth_bytes: &[u8; 32],
) -> Result<(DoubleRatchetSession, X3dhWireHeader, Option<PqxdhWireExt>), String> {
    use crate::crypto::x3dh::{x3dh_initiate, PreauthBundle, ENCRYPTED_IK_SIZE};
    use x25519_dalek::PublicKey as X25519Public;

    // Build Bob's bundle from the contact record.
    // Build Bob's bundle from the contact record, including the KEM
    // signature that binds the post-quantum key to Bob's identity.
    let bob_bundle = PreauthBundle {
        identity_ed25519_pub: contact.ed25519_public,
        identity_x25519_pub: X25519Public::from(contact.x25519_public),
        preauth_x25519_pub: X25519Public::from(*bob_preauth_bytes),
        preauth_kem_pub: contact.kem_encapsulation_key.clone(),
        preauth_sig: contact.preauth_key_sig.clone(),
        kem_sig: contact.kem_sig.clone(),
    };

    let ik_pub_bytes = *our_id.x25519_pub.as_bytes();
    let output = x3dh_initiate(&our_id.x25519_secret, &ik_pub_bytes, &bob_bundle)
        .map_err(|e| format!("X3DH initiate failed: {e}"))?;

    let header = output.header.ok_or("X3DH header missing")?;
    let master = output.master_secret.as_bytes();

    // Sanity-check the encrypted IK size to catch protocol mismatches early.
    debug_assert_eq!(header.encrypted_ik_pub.len(), ENCRYPTED_IK_SIZE);

    // Alice is always the DR initiator in X3DH.
    // The initial ratchet key is Bob's SPK (preauth_x25519_pub), not his IK.
    let session = DoubleRatchetSession::init_sender(master, bob_preauth_bytes)
        .map_err(|e| format!("DR init_sender (X3DH) failed: {e}"))?;

    // Extract optional PQXDH extension.
    let pq_ext = output
        .pqxdh_header
        .map(|ph| (ph.kem_ciphertext, ph.kem_binding));

    Ok((session, (header.eph_pub, header.encrypted_ik_pub), pq_ext))
}

/// Static DH session bootstrap (fallback for contacts without a preauth key).
///
/// Computes `shared = our_x25519_secret × their_x25519_pub`, derives a master
/// secret via HKDF-SHA256, and assigns roles by comparing peer ID bytes
/// lexicographically so both sides agree without coordination.
fn static_dh_bootstrap_session(
    our_id: &SelfIdentity,
    contact: &crate::pairing::contact::ContactRecord,
) -> Result<DoubleRatchetSession, String> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
    use zeroize::{Zeroize, Zeroizing};

    let their_pub = X25519Public::from(contact.x25519_public);
    let shared = our_id.x25519_secret.diffie_hellman(&their_pub);

    // Salt = XOR of both peer IDs: commutative so both sides derive the same value.
    let our_id_bytes = our_id.peer_id().0;
    let their_id_bytes = contact.peer_id.0;
    let mut salt = [0u8; 32];
    for i in 0..32 {
        salt[i] = our_id_bytes[i] ^ their_id_bytes[i];
    }

    // Zeroizing<> ensures the master secret is wiped on any return path.
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut master = Zeroizing::new([0u8; 32]);
    hk.expand(b"MeshInfinity_session_bootstrap_v1", &mut *master)
        .map_err(|_| "HKDF expand failed for session bootstrap".to_string())?;

    // Smaller peer_id bytes → initiator (Alice role per Signal convention).
    let session = if our_id_bytes < their_id_bytes {
        DoubleRatchetSession::init_sender(&master, &contact.x25519_public)
            .map_err(|e| format!("init_sender failed: {e}"))?
    } else {
        let our_secret_bytes = our_id.x25519_secret.to_bytes();
        let our_secret_copy = X25519Secret::from(our_secret_bytes);
        let our_pub_bytes = *our_id.x25519_pub.as_bytes();
        DoubleRatchetSession::init_receiver(&master, our_secret_copy, &our_pub_bytes)
    };

    // Explicitly zeroize the salt since it derives from peer IDs.
    salt.zeroize();
    Ok(session)
}
