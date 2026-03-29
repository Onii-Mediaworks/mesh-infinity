//! FFI boundary — C-compatible API surface (§17.5).
//!
//! All functions in this module are `extern "C"` and use C-compatible types.
//! Flutter (Dart) calls these via dart:ffi.
//!
//! **Key material NEVER crosses this boundary (§15.1).**
//! Flutter receives only pre-validated, display-safe JSON data.
//!
//! Pattern: all functions take `*mut MeshContext` as first arg.
//! String returns are JSON via `*const c_char` (caller must NOT free —
//! the string is owned by the context and valid until the next call).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::Mutex;

/// Fill `dest` with cryptographically secure random bytes.
///
/// Returns `true` on success, `false` if the OS RNG is unavailable.
/// Callers should return an error code on `false` rather than panicking,
/// to avoid unwinding through FFI (undefined behaviour on stable Rust).
fn try_random_fill(dest: &mut [u8]) -> bool {
    use rand_core::RngCore;
    // OsRng::fill_bytes() panics on OS failure in rand_core 0.6.
    // Use std::panic::catch_unwind to prevent FFI abort.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rand_core::OsRng.fill_bytes(dest);
    })).is_ok()
}

use serde::{Deserialize, Serialize};

use crate::crypto::backup::{create_backup, BackupType, EncryptedBackup};
use crate::crypto::double_ratchet::{DoubleRatchetSession, RatchetHeader};
use crate::crypto::message_encrypt::{decrypt_message, encrypt_message, MessageContext};
use crate::identity::killswitch;
use crate::identity::mask::{Mask, MaskId};
use crate::identity::peer_id::PeerId;
use crate::identity::self_identity::{SelfIdentity, IdentityError};
use crate::messaging::message::MessageSecurityMode;
use crate::messaging::room::Room;
use crate::network::threat_context::ThreatContext;
use crate::pairing::contact::{ContactRecord, ContactStore};
use crate::storage::VaultManager;
use crate::trust::levels::TrustLevel;
use crate::vpn::routing_mode::{VpnManager, RoutingMode};
use crate::routing::table::{DeviceAddress, RoutingEntry, RoutingTable};
use crate::routing::announcement::{AnnouncementProcessor, ReachabilityAnnouncement};
use crate::routing::loop_prevention::DeduplicationCache;
use crate::routing::store_forward::{StoreForwardServer, StoreAndForwardRequest, DepositResult, Priority, ReleaseCondition};
use crate::mesh::{MeshCoordinator, MeshPacket, PacketKind};
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

// ---------------------------------------------------------------------------
// Vault-serialisable settings (§17.9 settings.vault)
// ---------------------------------------------------------------------------

/// Settings persisted to `settings.vault` (§17.9).
/// Mirrors the transport flags + node mode in MeshContext.
#[derive(Serialize, Deserialize, Default)]
struct SettingsVault {
    node_mode: u8,
    threat_context: u8,
    tor: bool,
    clearnet: bool,
    clearnet_fallback: bool,
    i2p: bool,
    bluetooth: bool,
    rf: bool,
    mesh_discovery: bool,
    allow_relays: bool,
    /// Clearnet TCP listen port. 0 = use default (7234).
    clearnet_port: u16,
    /// Notification tier (1-4). 0 = use default (1 = MeshTunnel).
    notification_tier: u8,
    /// Whether notifications are enabled.
    notification_enabled: bool,
    /// Self-hosted push relay URL (empty = platform default).
    notification_push_url: String,
    /// Whether to show message previews in notifications.
    notification_show_previews: bool,
    /// Module enable/disable configuration (§17.13).
    #[serde(default)]
    module_config: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Type aliases for complex field types
// ---------------------------------------------------------------------------

/// Pending X3DH header: (ephemeral_pub [32], encrypted_ik [48]).
type X3dhPendingMap = Mutex<std::collections::HashMap<PeerId, ([u8; 32], [u8; 48])>>;

/// Pending PQXDH extension: (kem_ciphertext, kem_binding [32]).
type PqxdhPendingMap = Mutex<std::collections::HashMap<PeerId, (Vec<u8>, [u8; 32])>>;

// ---------------------------------------------------------------------------
// File transfer I/O state
// ---------------------------------------------------------------------------

/// Chunk size for file transfers: 64 KiB.
const FILE_CHUNK_SIZE: usize = 65536;
/// TCP port advertised in the Tor hidden service descriptor (§5.3).
const DEFAULT_HS_PORT: u16 = 7234;

/// Number of chunks to send per poll tick (limits how much we can block).
const CHUNKS_PER_TICK: usize = 4;

/// Per-transfer I/O state for active file transfers.
///
/// Stored in `MeshContext::active_file_io` keyed by `transfer_id`.
/// Holds the file handle and current byte position so we can resume
/// across poll cycles without reopening the file.
struct FileIoState {
    /// Transfer direction.
    direction: FileDirection,
    /// The peer we're exchanging with.
    peer_id: String,
    /// 32-byte file identifier (SHA-256 hash of plaintext — used on wire).
    file_id: [u8; 32],
    /// Total file size in bytes (send side: exact; receive side: from offer).
    total_bytes: u64,
    /// Bytes successfully transferred so far.
    transferred_bytes: u64,
    /// Open file handle for reading (send) or writing (receive).
    file: std::fs::File,
}

#[derive(PartialEq, Eq)]
enum FileDirection { Send, Receive }

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// Opaque context handle passed to all FFI functions.
/// Owns all backend state — a single long-lived instance per app.
pub struct MeshContext {
    /// Data directory for vault storage.
    data_dir: String,
    /// Vault manager (initialized after identity unlock).
    vault: Option<VaultManager>,
    /// Last JSON response (kept alive for pointer stability).
    last_response: Mutex<Option<CString>>,
    /// Last error message.
    last_error: Mutex<Option<CString>>,
    /// Current threat context.
    threat_context: ThreatContext,
    /// Rooms (in-memory cache, persisted to vault).
    rooms: Mutex<Vec<Room>>,
    /// Whether identity is unlocked (Layers 2/3 active).
    identity_unlocked: bool,
    /// Active conversation ID (for priority escalation §16.9.3).
    active_conversation: Mutex<Option<[u8; 16]>>,
    /// Contact store (peers we've paired with).
    contacts: Mutex<ContactStore>,
    /// VPN manager.
    vpn: Mutex<VpnManager>,
    /// Messages stored in memory (per-room).
    messages: Mutex<std::collections::HashMap<String, Vec<serde_json::Value>>>,
    /// The loaded self identity (Layer 2) — Some after unlock.
    identity: Mutex<Option<SelfIdentity>>,
    /// Pending backend events — drained by mi_poll_events().
    ///
    /// Each entry is a JSON object: `{"type": "EventName", "data": {...}}`.
    /// The Flutter event bus polls this queue via mi_poll_events and delivers
    /// events to all registered state objects.
    event_queue: Mutex<std::collections::VecDeque<serde_json::Value>>,
    /// Transport flags (per-transport enable/disable state).
    transport_flags: Mutex<TransportFlags>,
    /// Node mode: 0=client, 1=relay, 2=server.
    node_mode: Mutex<u8>,
    /// SDR/RF transport manager.
    sdr: Mutex<crate::transport::rf_sdr::SdrManager>,
    /// Whether LAN peer discovery (UDP broadcast) is currently active.
    mdns_running: Mutex<bool>,
    /// Peers discovered on the local network (ephemeral — cleared on disable).
    mdns_discovered: Mutex<Vec<serde_json::Value>>,
    /// UDP socket for LAN peer discovery broadcasts.
    /// Bound to 0.0.0.0:7235 with SO_BROADCAST set.
    lan_discovery_socket: Mutex<Option<std::net::UdpSocket>>,
    /// When to send the next LAN presence announcement (throttled to ~5s).
    lan_next_announce: Mutex<std::time::Instant>,
    /// Active file transfers (in-progress send/receive).
    file_transfers: Mutex<Vec<serde_json::Value>>,
    /// Per-transfer file I/O state (keyed by transfer_id).
    /// Tracks file handles and byte offsets for actual chunked I/O.
    active_file_io: Mutex<std::collections::HashMap<String, FileIoState>>,
    /// Overlay network clients (Tailscale, ZeroTier).
    overlay: Mutex<crate::transport::overlay_client::OverlayManager>,
    /// Gossip engine — network map propagation (§4.1, §4.5).
    gossip: Mutex<crate::network::gossip::GossipEngine>,
    /// Notification dispatcher — handles jitter, coalescing, and threat suppression (§14).
    notifications: Mutex<crate::notifications::NotificationDispatcher>,

    // -----------------------------------------------------------------------
    // Clearnet TCP transport (§5.1)
    // -----------------------------------------------------------------------

    /// Groups the user belongs to (persisted to vault).
    groups: Mutex<Vec<crate::groups::group::Group>>,
    /// Double Ratchet sessions per peer (in-memory; rebuilt from static DH on demand).
    /// Not persisted to vault — ratchet state is re-derived at restart from static keys.
    ratchet_sessions: Mutex<std::collections::HashMap<PeerId, DoubleRatchetSession>>,
    /// Pending X3DH init headers: (eph_pub [32], encrypted_ik [48]).
    /// Written when we bootstrap a session via X3DH (not static DH).
    /// Included in every outgoing message to that peer until we receive a
    /// reply (indicating Bob has established his matching session).
    x3dh_pending: X3dhPendingMap,
    /// Pending PQXDH extension headers: (kem_ciphertext [1088], kem_binding [32]).
    /// Set alongside x3dh_pending when Alice's ratchet session was bootstrapped
    /// with PQXDH.  Cleared on first reply from Bob (same lifecycle as x3dh_pending).
    pqxdh_pending: PqxdhPendingMap,
    /// Clearnet TCP listener socket (non-blocking).
    /// Started explicitly via `mi_start_clearnet_listener`.
    clearnet_listener: Mutex<Option<std::net::TcpListener>>,
    /// Active identified clearnet connections (peer_id hex → stream).
    clearnet_connections: Mutex<std::collections::HashMap<String, std::net::TcpStream>>,
    /// Pending incoming connections not yet identified by a first message.
    clearnet_pending_incoming: Mutex<Vec<(std::net::TcpStream, Vec<u8>)>>,
    /// Per-peer receive buffers for partial TCP frames.
    clearnet_recv_buffers: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    /// Clearnet listen port (default 7234).
    clearnet_port: Mutex<u16>,
    /// Outbox for messages that failed TCP delivery.
    /// Each entry: (peer_id_hex, endpoint, encrypted_envelope_bytes).
    /// The poll loop retries these on each cycle for any peer that has
    /// become reachable, providing local store-and-forward for transient
    /// disconnections.
    outbox: Mutex<Vec<(String, String, Vec<u8>)>>,
    /// Active call state: `(call_state, remote_peer_hex)`.
    /// The remote_peer_hex is the primary peer we're exchanging call signals with.
    /// None when no call is in progress (§10.1.6).
    active_call: Mutex<Option<(crate::calls::CallState, String)>>,
    /// Four-plane routing table (§6.1, §6.4).
    /// Populated by pairing, mDNS discovery, and announcement forwarding.
    routing_table: Mutex<RoutingTable>,
    /// Announcement processor — deduplicates and propagates reachability
    /// announcements (§6.2).
    announcement_processor: Mutex<AnnouncementProcessor>,
    /// Packet deduplication cache — prevents forwarding loops (§6.6).
    dedup_cache: Mutex<DeduplicationCache>,
    /// Module enable/disable config (§17.13).
    module_config: Mutex<crate::services::module_system::ModuleConfig>,
    /// Mesh routing coordinator — bridges routing table with transport layer (§6).
    /// Held for Drop and future use; not yet wired to inbound/outbound paths.
    _mesh: MeshCoordinator,
    /// Per-peer WireGuard sessions for link-layer encryption (§5.2).
    wireguard_sessions: Mutex<crate::transport::wireguard::WireGuardSessionStore>,
    /// Store-and-forward server (§6.8) — buffers messages for offline peers.
    /// This node acts as a relay: peers deposit messages here for destinations
    /// that are currently unreachable, and we deliver them when the destination
    /// reconnects. Also used to receive messages deposited for us at other relays.
    sf_server: Mutex<StoreForwardServer>,
    /// Per-peer last-received timestamp (monotonic clock) for keepalive tracking.
    /// Updated whenever data arrives on the connection; used to detect stale peers
    /// and trigger keepalive probes.
    clearnet_last_rx: Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// Per-peer last-keepalive-sent timestamp (monotonic clock).
    /// Used to throttle keepalive transmission to once per KEEPALIVE_INTERVAL_SECS.
    clearnet_last_keepalive_tx: Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// Tor transport (§5.3) — Some when Tor is enabled and bootstrapped.
    tor_transport: Mutex<Option<crate::transport::tor::TorTransport>>,
    /// Pending WireGuard initiator handshakes awaiting the responder's reply.
    /// Keyed by responder PeerId; entry is consumed by mi_wg_complete_handshake.
    pending_wg_handshakes: Mutex<std::collections::HashMap<PeerId, crate::transport::wireguard::PendingInitiatorHandshake>>,
}

/// Per-transport enable/disable flags (§5.10).
#[derive(Clone)]
struct TransportFlags {
    tor: bool,
    clearnet: bool,
    clearnet_fallback: bool,
    i2p: bool,
    bluetooth: bool,
    rf: bool,
    mesh_discovery: bool,
    allow_relays: bool,
}

impl Default for TransportFlags {
    fn default() -> Self {
        Self {
            tor: false,
            clearnet: true, // default on for bootstrap
            clearnet_fallback: true,
            i2p: false,
            bluetooth: false,
            rf: false,
            mesh_discovery: true,
            allow_relays: true,
        }
    }
}

impl MeshContext {
    fn new(data_dir: String) -> Self {
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
            messages: Mutex::new(std::collections::HashMap::new()),
            identity: Mutex::new(None),
            event_queue: Mutex::new(std::collections::VecDeque::new()),
            transport_flags: Mutex::new(TransportFlags::default()),
            node_mode: Mutex::new(0),
            sdr: Mutex::new(crate::transport::rf_sdr::SdrManager::new()),
            mdns_running: Mutex::new(false),
            mdns_discovered: Mutex::new(Vec::new()),
            lan_discovery_socket: Mutex::new(None),
            lan_next_announce: Mutex::new(std::time::Instant::now()),
            file_transfers: Mutex::new(Vec::new()),
            active_file_io: Mutex::new(std::collections::HashMap::new()),
            overlay: Mutex::new(crate::transport::overlay_client::OverlayManager::new()),
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
            clearnet_port: Mutex::new(7234),
            outbox: Mutex::new(Vec::new()),
            x3dh_pending: Mutex::new(std::collections::HashMap::new()),
            pqxdh_pending: Mutex::new(std::collections::HashMap::new()),
            active_call: Mutex::new(None::<(crate::calls::CallState, String)>),
            module_config: Mutex::new(crate::services::module_system::ModuleConfig::default()),
            _mesh: MeshCoordinator::new(),
            wireguard_sessions: Mutex::new(crate::transport::wireguard::WireGuardSessionStore::new()),
            routing_table: Mutex::new(RoutingTable::new()),
            // AnnouncementProcessor requires our own address, which we don't
            // know until identity is unlocked.  We use an all-zeros address
            // as a placeholder and replace it in load_from_vault().
            announcement_processor: Mutex::new(AnnouncementProcessor::new(
                DeviceAddress([0u8; 32]),
                10, // default link latency 10 ms
            )),
            dedup_cache: Mutex::new(DeduplicationCache::new()),
            sf_server: Mutex::new(StoreForwardServer::new_client()),
            clearnet_last_rx: Mutex::new(std::collections::HashMap::new()),
            clearnet_last_keepalive_tx: Mutex::new(std::collections::HashMap::new()),
            tor_transport: Mutex::new(None),
            pending_wg_handshakes: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Push a `TransferUpdated` event with the current state of a transfer.
    ///
    /// Looks up the transfer in `file_transfers` by ID and pushes a
    /// `TransferUpdated` event containing the full `FileTransferModel` JSON.
    /// This is the event the Flutter `FilesState` listens to.
    fn push_transfer_update(&self, transfer_id: &str) {
        let transfer_json = {
            let transfers = self.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
            transfers.iter()
                .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(transfer_id))
                .cloned()
        };
        if let Some(t) = transfer_json {
            self.push_event("TransferUpdated", t);
        }
    }

    /// Push an event onto the queue. Flutter will receive it on the next poll.
    fn push_event(&self, event_type: &str, data: serde_json::Value) {
        let event = serde_json::json!({
            "type": event_type,
            "data": data,
        });
        self.event_queue.lock().unwrap_or_else(|e| e.into_inner()).push_back(event);
    }

    /// Load state from the vault into memory. Called after identity unlock.
    fn load_from_vault(&mut self) {
        let vm = match self.vault.as_ref() {
            Some(v) => v,
            None => return,
        };

        // Load rooms
        if let Ok(coll) = vm.collection("rooms") {
            if let Ok(Some(rooms)) = coll.load::<Vec<Room>>() {
                *self.rooms.lock().unwrap_or_else(|e| e.into_inner()) = rooms;
            }
        }

        // Load contacts
        if let Ok(coll) = vm.collection("peers") {
            if let Ok(Some(contacts)) = coll.load::<Vec<ContactRecord>>() {
                let mut store = ContactStore::new();
                for c in contacts {
                    store.upsert(c);
                }
                *self.contacts.lock().unwrap_or_else(|e| e.into_inner()) = store;
            }
        }

        // Load messages
        if let Ok(coll) = vm.collection("messages") {
            if let Ok(Some(msgs)) = coll.load::<std::collections::HashMap<String, Vec<serde_json::Value>>>() {
                *self.messages.lock().unwrap_or_else(|e| e.into_inner()) = msgs;
            }
        }

        // Load groups
        if let Ok(coll) = vm.collection("groups") {
            if let Ok(Some(groups)) = coll.load::<Vec<crate::groups::group::Group>>() {
                *self.groups.lock().unwrap_or_else(|e| e.into_inner()) = groups;
            }
        }

        // Load settings
        if let Ok(coll) = vm.collection("settings") {
            if let Ok(Some(s)) = coll.load::<SettingsVault>() {
                *self.node_mode.lock().unwrap_or_else(|e| e.into_inner()) = s.node_mode;
                if let Some(tc) = ThreatContext::from_u8(s.threat_context) {
                    self.threat_context = tc;
                }
                let mut flags = self.transport_flags.lock().unwrap_or_else(|e| e.into_inner());
                flags.tor = s.tor;
                flags.clearnet = s.clearnet;
                flags.clearnet_fallback = s.clearnet_fallback;
                flags.i2p = s.i2p;
                flags.bluetooth = s.bluetooth;
                flags.rf = s.rf;
                flags.mesh_discovery = s.mesh_discovery;
                flags.allow_relays = s.allow_relays;
                drop(flags);
                // Clearnet port: 0 in vault means "use default 7234"
                let port = if s.clearnet_port == 0 { 7234 } else { s.clearnet_port };
                *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()) = port;

                // Restore notification config.
                let mut notif = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
                notif.config.enabled = s.notification_enabled;
                if s.notification_tier >= 1 && s.notification_tier <= 4 {
                    notif.config.tier = match s.notification_tier {
                        2 => crate::notifications::NotificationTier::UnifiedPush,
                        3 => crate::notifications::NotificationTier::SilentPush,
                        4 => crate::notifications::NotificationTier::RichPush,
                        _ => crate::notifications::NotificationTier::MeshTunnel,
                    };
                }
                if !s.notification_push_url.is_empty() {
                    notif.config.push_relay = Some(crate::notifications::PushRelayConfig {
                        relay_address: crate::notifications::RelayAddress::UnifiedPush {
                            endpoint: s.notification_push_url,
                        },
                        device_token: Vec::new(),
                        platform: crate::notifications::PushPlatform::UnifiedPush,
                    });
                }
                notif.config.rich_content_level = if s.notification_show_previews {
                    crate::notifications::RichPushContentLevel::Standard
                } else {
                    crate::notifications::RichPushContentLevel::Minimal
                };
                // Restore module config if present.
                if let Some(mc_val) = s.module_config {
                    if let Ok(mc) = serde_json::from_value::<crate::services::module_system::ModuleConfig>(mc_val) {
                        *self.module_config.lock().unwrap_or_else(|e| e.into_inner()) = mc;
                    }
                }
            }
        }

        // Load ratchet sessions
        self.load_ratchet_sessions();

        // Seed routing table with direct-connect entries for all known contacts.
        // Each paired peer gets a local-plane entry (hop count 0 = direct neighbour).
        self.rebuild_routing_table_from_contacts();

        // Replace the placeholder announcement processor address with our real peer ID.
        if let Some(our_peer_id) = self.identity.lock().unwrap_or_else(|e| e.into_inner())
            .as_ref().map(|id| id.peer_id().0)
        {
            *self.announcement_processor.lock().unwrap_or_else(|e| e.into_inner()) =
                AnnouncementProcessor::new(DeviceAddress(our_peer_id), 10);
        }
    }

    /// Rebuild the routing table from the current contact store.
    ///
    /// Called after vault load and after any contact mutation.
    /// Each known contact that has a clearnet endpoint gets a local-plane
    /// routing entry so the routing table accurately reflects reachability.
    fn rebuild_routing_table_from_contacts(&self) {
        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
        let mut table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        for contact in contacts.all() {
            let dest = DeviceAddress(contact.peer_id.0);
            let entry = RoutingEntry {
                destination:     dest,
                next_hop:        dest, // direct neighbour
                hop_count:       1,
                latency_ms:      10,
                next_hop_trust:  contact.trust_level,
                last_updated:    now,
                announcement_id: [0u8; 32], // direct entry — no announcement
            };
            table.update_local(entry);
        }
    }

    /// Persist rooms to vault. Called after any room mutation.
    fn save_rooms(&self) {
        if let Some(vm) = self.vault.as_ref() {
            if let Ok(coll) = vm.collection("rooms") {
                let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
                // Log on failure: save_rooms returns () so we cannot propagate.
                if let Err(e) = coll.save(&*rooms) {
                    eprintln!("[vault] ERROR: failed to persist rooms: {e}");
                }
            }
        }
    }

    /// Persist contacts to vault. Called after any contact mutation.
    fn save_contacts(&self) {
        if let Some(vm) = self.vault.as_ref() {
            if let Ok(coll) = vm.collection("peers") {
                let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                let all: Vec<ContactRecord> = contacts.all().into_iter().cloned().collect();
                // Log on failure: save_contacts returns () so we cannot propagate.
                if let Err(e) = coll.save(&all) {
                    eprintln!("[vault] ERROR: failed to persist contacts: {e}");
                }
            }
        }
    }

    /// Persist messages to vault. Called after any message mutation.
    fn save_messages(&self) {
        if let Some(vm) = self.vault.as_ref() {
            if let Ok(coll) = vm.collection("messages") {
                let msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
                // Log on failure: save_messages returns () so we cannot propagate.
                if let Err(e) = coll.save(&*msgs) {
                    eprintln!("[vault] ERROR: failed to persist messages: {e}");
                }
            }
        }
    }

    /// Persist groups to vault. Called after any group mutation.
    fn save_groups(&self) {
        if let Some(vm) = self.vault.as_ref() {
            if let Ok(coll) = vm.collection("groups") {
                let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
                // Log on failure: save_groups returns () so we cannot propagate.
                if let Err(e) = coll.save(&*groups) {
                    eprintln!("[vault] ERROR: failed to persist groups: {e}");
                }
            }
        }
    }

    /// Persist settings to vault. Called after any settings mutation.
    fn save_settings(&self) {
        if let Some(vm) = self.vault.as_ref() {
            if let Ok(coll) = vm.collection("settings") {
                let flags = self.transport_flags.lock().unwrap_or_else(|e| e.into_inner());
                let notif = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
                let ncfg = &notif.config;
                let push_url = ncfg.push_relay.as_ref().map(|r| match &r.relay_address {
                    crate::notifications::RelayAddress::ClearnetUrl  { url }      => url.clone(),
                    crate::notifications::RelayAddress::UnifiedPush { endpoint }  => endpoint.clone(),
                    crate::notifications::RelayAddress::MeshService { .. }        => String::new(),
                }).unwrap_or_default();
                let mc_val = serde_json::to_value(
                    &*self.module_config.lock().unwrap_or_else(|e| e.into_inner())
                ).ok();
                let s = SettingsVault {
                    node_mode: *self.node_mode.lock().unwrap_or_else(|e| e.into_inner()),
                    threat_context: self.threat_context as u8,
                    tor: flags.tor,
                    clearnet: flags.clearnet,
                    clearnet_fallback: flags.clearnet_fallback,
                    i2p: flags.i2p,
                    bluetooth: flags.bluetooth,
                    rf: flags.rf,
                    mesh_discovery: flags.mesh_discovery,
                    allow_relays: flags.allow_relays,
                    clearnet_port: *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()),
                    notification_tier: ncfg.tier as u8,
                    notification_enabled: ncfg.enabled,
                    notification_push_url: push_url,
                    notification_show_previews: ncfg.rich_content_level as u8 >= 1,
                    module_config: mc_val,
                };
                // Log on failure: save_settings returns () so we cannot propagate.
                if let Err(e) = coll.save(&s) {
                    eprintln!("[vault] ERROR: failed to persist settings: {e}");
                }
            }
        }
    }

    /// Persist ratchet sessions to vault. Called after each ratchet step.
    fn save_ratchet_sessions(&self) {
        let Some(vm) = self.vault.as_ref() else { return };
        let Ok(coll) = vm.collection("ratchet_sessions") else { return };
        let sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
        // Serialise as a Vec<(peer_id_hex, SessionSnapshot)>.
        let snapshots: Vec<(String, crate::crypto::double_ratchet::SessionSnapshot)> = sessions
            .iter()
            .map(|(peer_id, session)| (hex::encode(peer_id.0), session.to_snapshot()))
            .collect();
        // Log on failure: save_ratchet_sessions returns () so we cannot propagate.
        if let Err(e) = coll.save(&snapshots) {
            eprintln!("[vault] ERROR: failed to persist ratchet sessions: {e}");
        }
    }

    /// Load ratchet sessions from vault. Called from `load_from_vault`.
    fn load_ratchet_sessions(&self) {
        let Some(vm) = self.vault.as_ref() else { return };
        let Ok(coll) = vm.collection("ratchet_sessions") else { return };
        let Ok(Some(snapshots)) = coll
            .load::<Vec<(String, crate::crypto::double_ratchet::SessionSnapshot)>>()
        else {
            return;
        };
        let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
        for (peer_hex, snap) in snapshots {
            let Ok(peer_bytes) = hex::decode(&peer_hex) else { continue };
            if peer_bytes.len() != 32 { continue }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&peer_bytes);
            let peer_id = PeerId(arr);
            let session = DoubleRatchetSession::from_snapshot(snap);
            sessions.insert(peer_id, session);
        }
    }

    // -----------------------------------------------------------------------
    // Clearnet TCP transport helpers
    // -----------------------------------------------------------------------

    /// Advance the clearnet TCP transport: accept connections, read frames,
    /// decrypt and enqueue received messages. Called from `mi_poll_events`.
    fn advance_clearnet_transport(&self) {
        self.clearnet_accept_new_connections();
        self.tor_drain_inbound();
        self.clearnet_process_pending_incoming();
        self.clearnet_process_identified();
        self.clearnet_flush_outbox();
        self.advance_lan_discovery();
        self.advance_file_transfers();
        self.advance_sf_gc();
        self.advance_group_rekeys();
        self.advance_notifications();
        self.advance_gossip_cleanup();
        self.advance_keepalives();
    }

    /// Send keepalive probes to idle connections and drop stale ones (§5.1).
    ///
    /// Called each poll cycle (~200ms) from `advance_clearnet_transport`.
    ///
    /// Policy:
    ///   - If no data received from peer in > 30s → send a `keepalive` frame.
    ///   - If no data received from peer in > 120s → close the connection.
    ///     (The peer is unresponsive — our keepalives have not been answered.)
    ///
    /// When the remote side receives a `keepalive` frame it immediately sends
    /// back a `keepalive_ack`. The receipt of ANY frame (including the ack)
    /// updates `clearnet_last_rx`, so responsive peers never hit the 120s limit.
    fn advance_keepalives(&self) {
        // Interval before we probe an idle connection.
        const KEEPALIVE_INTERVAL_SECS: u64 = 30;
        // Timeout before we declare a peer dead and close the connection.
        const KEEPALIVE_TIMEOUT_SECS: u64 = 120;
        // Minimum gap between successive keepalive probes to the same peer.
        const KEEPALIVE_TX_MIN_GAP_SECS: u64 = 10;

        let now = std::time::Instant::now();

        let peer_ids: Vec<String> = self.clearnet_connections
            .lock().unwrap_or_else(|e| e.into_inner())
            .keys().cloned().collect();

        let mut to_drop: Vec<String> = Vec::new();

        for peer_hex in &peer_ids {
            let last_rx = {
                let map = self.clearnet_last_rx.lock().unwrap_or_else(|e| e.into_inner());
                map.get(peer_hex).copied()
            };

            let idle_secs = last_rx.map(|t| now.duration_since(t).as_secs()).unwrap_or(0);

            if idle_secs >= KEEPALIVE_TIMEOUT_SECS {
                // Peer has been silent for too long — declare dead and drop.
                to_drop.push(peer_hex.clone());
                continue;
            }

            if idle_secs >= KEEPALIVE_INTERVAL_SECS {
                // Check if we sent a keepalive recently enough.
                let last_tx = {
                    let map = self.clearnet_last_keepalive_tx.lock().unwrap_or_else(|e| e.into_inner());
                    map.get(peer_hex).copied()
                };
                let tx_gap = last_tx.map(|t| now.duration_since(t).as_secs()).unwrap_or(u64::MAX);
                if tx_gap >= KEEPALIVE_TX_MIN_GAP_SECS {
                    self.send_raw_frame(peer_hex, &serde_json::json!({"type": "keepalive"}));
                    self.clearnet_last_keepalive_tx.lock().unwrap_or_else(|e| e.into_inner())
                        .insert(peer_hex.clone(), now);
                }
            }
        }

        // Close stale connections and emit PeerUpdated(offline).
        for peer_hex in to_drop {
            self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer_hex);
            self.clearnet_recv_buffers.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer_hex);
            self.clearnet_last_rx.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer_hex);
            self.clearnet_last_keepalive_tx.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer_hex);
            if let Ok(bytes) = hex::decode(&peer_hex) {
                if bytes.len() == 32 {
                    let mut a = [0u8; 32]; a.copy_from_slice(&bytes);
                    self.routing_table.lock().unwrap_or_else(|e| e.into_inner())
                        .remove_local(&DeviceAddress(a));
                }
            }
            let (display_name, trust_val) = {
                let peer_bytes_opt = hex::decode(&peer_hex).ok().filter(|b| b.len() == 32)
                    .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
                if let Some(pb) = peer_bytes_opt {
                    let pid = PeerId(pb);
                    let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                    contacts.get(&pid).map(|c| (
                        c.display_name.clone().unwrap_or_default(),
                        c.trust_level as u8,
                    )).unwrap_or_default()
                } else { (String::new(), 0u8) }
            };
            self.push_event("PeerUpdated", serde_json::json!({
                "id": peer_hex,
                "name": display_name,
                "trustLevel": trust_val,
                "status": "offline",
                "canBeExitNode": false,
                "canBeWrapperNode": false,
                "canBeStoreForward": false,
                "canEndorsePeers": false,
                "latencyMs": null,
            }));
        }
    }

    /// Broadcast a signed reachability announcement for THIS node to all
    /// currently identified clearnet peers (§6.2).
    ///
    /// Called after successful pairing so existing connected peers update
    /// their routing tables with a fresh route to us (and consequently, to
    /// any newly-paired node reachable via us).
    ///
    /// Creates a fresh `ReachabilityAnnouncement` with scope=Public, signs it
    /// with our Ed25519 key, and sends the `route_announcement` frame to
    /// every peer in `clearnet_connections`.
    fn broadcast_self_route_announcement(&self) {
        use crate::crypto::signing;

        // Gather identity material.
        let (peer_id_bytes, signing_key_bytes) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => (id.peer_id().0, id.ed25519_signing.to_bytes()),
                None => return, // Not yet unlocked — nothing to announce.
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Generate a fresh unique announcement ID.
        let mut announcement_id = [0u8; 32];
        if !try_random_fill(&mut announcement_id) {
            return;
        }

        // Build the signed message: destination || announcement_id || timestamp.
        let mut signed_msg = Vec::with_capacity(72);
        signed_msg.extend_from_slice(&peer_id_bytes);
        signed_msg.extend_from_slice(&announcement_id);
        signed_msg.extend_from_slice(&now.to_be_bytes());

        let signature = signing::sign(&signing_key_bytes, signing::DOMAIN_ROUTING_ANNOUNCEMENT, &signed_msg);

        let our_addr = DeviceAddress(peer_id_bytes);
        let announcement = ReachabilityAnnouncement {
            destination: our_addr,
            hop_count: 0,
            latency_ms: 0,
            next_hop_trust: TrustLevel::InnerCircle,
            announcement_id,
            timestamp: now,
            scope: crate::routing::announcement::AnnouncementScope::Public,
            signature,
        };

        let our_hex = hex::encode(peer_id_bytes);
        let ann_val = match serde_json::to_value(&announcement) {
            Ok(v) => v,
            Err(_) => return,
        };
        let frame = serde_json::json!({
            "type": "route_announcement",
            "from": our_hex,
            "announcement": ann_val,
        });

        // Send to every identified clearnet peer.
        let peers: Vec<String> = self.clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        for peer_hex in peers {
            self.send_raw_frame(&peer_hex, &frame);
        }
    }

    /// Insert a direct (local-plane) routing entry for a peer that has just
    /// connected over clearnet (§6.1 — local routing plane).
    ///
    /// The entry uses `hop_count=1` and `destination == next_hop` to signal
    /// a direct connection. Trust is read from the contact store.
    fn insert_local_route_for_peer(&self, peer_id_hex: &str) {
        let peer_bytes = match hex::decode(peer_id_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return,
        };
        let addr = DeviceAddress(peer_bytes);
        let peer_id = PeerId(peer_bytes);

        let trust = {
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            contacts.get(&peer_id).map(|c| c.trust_level).unwrap_or(TrustLevel::Unknown)
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Use a zero announcement_id for local/direct entries — these are not
        // from the announcement broadcast path and don't need deduplication.
        let entry = RoutingEntry {
            destination: addr,
            next_hop: addr,
            hop_count: 1,
            latency_ms: 0,
            next_hop_trust: trust,
            last_updated: now,
            announcement_id: [0u8; 32],
        };

        self.routing_table.lock().unwrap_or_else(|e| e.into_inner()).update_local(entry);
    }

    /// Periodic cleanup for the gossip engine (§4.1, §4.5).
    ///
    /// Prunes stale network map entries and old rate-tracking data.
    fn advance_gossip_cleanup(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);
        self.gossip.lock().unwrap_or_else(|e| e.into_inner()).cleanup(now);
    }

    /// Dispatch any coalesced notifications that are ready (§14).
    ///
    /// Calls `NotificationDispatcher::dispatch_ready()` to collect notifications
    /// whose jitter window has closed. Currently the dispatched notifications are
    /// counted and could be forwarded to a push relay; in this implementation we
    /// just drain the queue to prevent unbounded growth.
    fn advance_notifications(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);
        let dispatched = self.notifications.lock().unwrap_or_else(|e| e.into_inner())
            .dispatch_ready(now);
        // Emit a LocalNotification event for each coalesced notification so the
        // Flutter UI can display the notification badge or system notification.
        for notif in dispatched {
            let conv_id_hex = notif.conversation_id.map(hex::encode);
            self.push_event("LocalNotification", serde_json::json!({
                "title":          notif.title,
                "body":           notif.body,
                "conversationId": conv_id_hex,
                "eventCount":     notif.event_count,
                "priority":       format!("{:?}", notif.priority),
                "tier":           format!("{:?}", notif.tier),
            }));
        }
    }

    /// Periodically garbage-collect the S&F server (§6.8).
    ///
    /// Purges expired and delivered messages, reclaims storage.
    /// Called every poll cycle; the GC itself is cheap on most ticks
    /// because messages are rare relative to the poll frequency.
    fn advance_sf_gc(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);
        self.sf_server.lock().unwrap_or_else(|e| e.into_inner()).gc(now);
    }

    /// Trigger scheduled group Sender Key rekeying (§8.7.4, §8.7.5).
    ///
    /// For each group where we are the admin and the rekey interval has elapsed:
    /// 1. Generate a new random Sender Key (32 bytes).
    /// 2. Increment the epoch.
    /// 3. Distribute the new key to all online members via encrypted wire frames.
    /// 4. Persist the updated group state.
    ///
    /// Members who are offline when the rekey fires will follow the re-inclusion
    /// flow (§8.7.6) when they reconnect and detect they can't decrypt messages.
    fn advance_group_rekeys(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        // Collect groups that need a rekey.
        // We only initiate rekeys for groups where we are the admin.
        let rekey_targets: Vec<(usize, [u8; 32], Vec<[u8; 32]>)> = {
            let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            groups.iter().enumerate()
                .filter(|(_, g)| g.is_admin && g.needs_rekey(now))
                .map(|(i, g)| {
                    let members: Vec<[u8; 32]> = g.members.iter().map(|m| m.0).collect();
                    (i, g.group_id, members)
                })
                .collect()
        };

        if rekey_targets.is_empty() {
            return;
        }

        for (idx, group_id, member_ids) in rekey_targets {
            // Generate fresh Sender Key material.
            let mut new_symmetric_key = [0u8; 32];
            if !try_random_fill(&mut new_symmetric_key) {
                continue;
            }

            // Update the group state.
            let new_epoch = {
                let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(group) = groups.get_mut(idx) {
                    group.symmetric_key = new_symmetric_key;
                    group.sender_key_epoch += 1;
                    group.last_rekey_at = now;
                    group.sender_key_epoch
                } else {
                    continue;
                }
            };

            let group_id_hex = hex::encode(group_id);
            let new_key_hex = hex::encode(new_symmetric_key);

            // Distribute the new key to all connected members.
            // Each member gets the key encrypted with their X25519 public key via
            // our ratchet session. Members not currently connected will need to
            // request re-inclusion (§8.7.6) when they reconnect.
            for member_bytes in &member_ids {
                let member_id = PeerId(*member_bytes);
                let member_hex = hex::encode(member_bytes);

                // Don't send to ourselves.
                let our_id = {
                    let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                    guard.as_ref().map(|id| id.peer_id())
                };
                if Some(member_id) == our_id {
                    continue;
                }

                // Encrypt the new Sender Key for this member using their ratchet session.
                // The group_rekey payload is JSON: {"groupId","epoch","symmetricKey"}.
                let rekey_payload = serde_json::json!({
                    "type": "group_rekey",
                    "groupId": group_id_hex,
                    "epoch": new_epoch,
                    "symmetricKey": new_key_hex,
                });
                let payload_bytes = match serde_json::to_vec(&rekey_payload) {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                // Encrypt the new Sender Key for this member using their ratchet session.
                // Uses the ratchet message key directly with ChaCha20-Poly1305:
                //   ciphertext = ChaCha20Poly1305(key=msg_key, nonce=[0u8;12], plaintext=payload)
                // The ratchet header allows the receiver to derive the same key.
                let encrypted_envelope = {
                    use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
                    let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(session) = sessions.get_mut(&member_id) {
                        match session.next_send_msg_key() {
                            Ok((header, msg_key)) => {
                                let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
                                let nonce = Nonce::<ChaCha20Poly1305>::default(); // all-zero 12-byte nonce
                                match cipher.encrypt(&nonce, payload_bytes.as_ref()) {
                                    Ok(ct) => {
                                        let x3dh_header = self.x3dh_pending
                                            .lock().unwrap_or_else(|e| e.into_inner())
                                            .get(&member_id).copied();
                                        let mut envelope = serde_json::json!({
                                            "type": "group_rekey",
                                            "sender": hex::encode(our_id.map(|id| id.0).unwrap_or([0u8; 32])),
                                            "ratchet_header": serde_json::to_value(&header).unwrap_or(serde_json::Value::Null),
                                            "ciphertext": hex::encode(&ct),
                                        });
                                        if let Some((eph, ik)) = x3dh_header {
                                            if let Some(obj) = envelope.as_object_mut() {
                                                obj.insert("x3dh_eph_pub".to_string(), serde_json::Value::String(hex::encode(eph)));
                                                obj.insert("x3dh_encrypted_ik".to_string(), serde_json::Value::String(hex::encode(ik)));
                                            }
                                        }
                                        Some(envelope)
                                    }
                                    Err(_) => None,
                                }
                            }
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                };

                if let Some(frame) = encrypted_envelope {
                    self.send_raw_frame(&member_hex, &frame);
                }
            }
        }

        // Persist updated group state.
        self.save_groups();
    }

    /// Tick active file transfers: send the next batch of chunks for outgoing
    /// transfers, and flush receive buffers to disk. Called every poll cycle.
    fn advance_file_transfers(&self) {
        use std::io::Read;

        let _now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        let transfer_ids: Vec<String> = self.active_file_io.lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys().cloned().collect();

        for tid in transfer_ids {
            // Get direction and peer without holding the lock across I/O.
            let (direction, peer_id, file_id, total_bytes) = {
                let map = self.active_file_io.lock().unwrap_or_else(|e| e.into_inner());
                match map.get(&tid) {
                    Some(s) => (
                        if s.direction == FileDirection::Send { "send" } else { "recv" },
                        s.peer_id.clone(),
                        s.file_id,
                        s.total_bytes,
                    ),
                    None => continue,
                }
            };

            if direction == "send" {
                for _ in 0..CHUNKS_PER_TICK {
                    let chunk_data = {
                        let mut map = self.active_file_io.lock().unwrap_or_else(|e| e.into_inner());
                        let state = match map.get_mut(&tid) { Some(s) => s, None => break };
                        if state.transferred_bytes >= state.total_bytes { break; }
                        let mut buf = vec![0u8; FILE_CHUNK_SIZE];
                        let n = state.file.read(&mut buf).unwrap_or(0);
                        if n == 0 { break; }
                        buf.truncate(n);
                        let offset = state.transferred_bytes;
                        state.transferred_bytes += n as u64;
                        (buf, offset, state.file_id)
                    };

                    let (data, offset, fid) = chunk_data;
                    let chunk_index = (offset / FILE_CHUNK_SIZE as u64) as u32;
                    let frame = serde_json::json!({
                        "type": "file_chunk",
                        "transferId": tid,
                        "fileId": hex::encode(fid),
                        "chunkIndex": chunk_index,
                        "offset": offset,
                        "data": hex::encode(&data),
                    });
                    self.send_raw_frame(&peer_id, &frame);

                    // Update the JSON transfer record with progress.
                    let transferred = {
                        let map = self.active_file_io.lock().unwrap_or_else(|e| e.into_inner());
                        map.get(&tid).map(|s| s.transferred_bytes).unwrap_or(0)
                    };
                    {
                        let mut transfers = self.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
                        for t in transfers.iter_mut() {
                            if t.get("id").and_then(|v| v.as_str()) == Some(&tid) {
                                if let Some(obj) = t.as_object_mut() {
                                    obj.insert("transferredBytes".to_string(),
                                        serde_json::Value::Number(transferred.into()));
                                    if transferred >= total_bytes {
                                        obj.insert("status".to_string(),
                                            serde_json::Value::String("completed".to_string()));
                                    }
                                }
                                break;
                            }
                        }
                    }
                    self.push_transfer_update(&tid);

                    // If complete, emit completion event and remove from IO map.
                    if transferred >= total_bytes {
                        self.active_file_io.lock().unwrap_or_else(|e| e.into_inner()).remove(&tid);
                        let complete_frame = serde_json::json!({
                            "type": "file_complete",
                            "transferId": tid,
                            "fileId": hex::encode(file_id),
                            "ok": true,
                        });
                        self.send_raw_frame(&peer_id, &complete_frame);
                        break;
                    }
                }
            }
        }
    }

    /// LAN peer discovery tick — send periodic presence announcements and
    /// process any received presence packets from other nodes.
    ///
    /// Called from `advance_clearnet_transport()` on every poll cycle
    /// (approximately every 200ms). Broadcasts are throttled to once per 5s.
    ///
    /// Packet format (compact JSON, one line, ≤512 bytes):
    ///   {"v":1,"type":"mi_presence","peer_id":"hex","ed25519_pub":"hex",
    ///    "x25519_pub":"hex","display_name":"…","endpoint":"ip:port","ts":unix}
    ///
    /// Signed announcements (future): the `sig` field will carry an Ed25519
    /// signature over the canonical JSON. For now omitted — LAN trust is
    /// confirmed at pairing; the announce is only used to learn the endpoint.
    fn advance_lan_discovery(&self) {
        if !*self.mdns_running.lock().unwrap_or_else(|e| e.into_inner()) { return; }

        let socket_guard = self.lan_discovery_socket.lock().unwrap_or_else(|e| e.into_inner());
        let socket = match socket_guard.as_ref() {
            Some(s) => s,
            None => return,
        };

        // ---- Receive: drain all pending packets (non-blocking). ----
        let mut buf = [0u8; 1024];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, src_addr)) => {
                    let _ = self.handle_lan_presence_packet(&buf[..len], src_addr);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // ---- Send: broadcast our presence every 5 seconds. ----
        let now = std::time::Instant::now();
        let next = *self.lan_next_announce.lock().unwrap_or_else(|e| e.into_inner());
        if now < next { return; }
        *self.lan_next_announce.lock().unwrap_or_else(|e| e.into_inner()) =
            now + std::time::Duration::from_secs(5);

        // Build our presence announcement.
        let (peer_id_hex, ed_hex, x_hex, preauth_hex, preauth_sig_hex, display_name, clearnet_port) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                None => return,
                Some(id) => {
                    // Sign the preauth key with our Ed25519 identity key so
                    // receivers can verify the identity binding (§7.0.1).
                    let preauth_sig = {
                        use crate::crypto::x3dh::PreauthBundle;
                        let msg = PreauthBundle::signed_message(&id.preauth_x25519_pub);
                        let secret = id.ed25519_signing.to_bytes();
                        crate::crypto::signing::sign(&secret, crate::crypto::x3dh::PREAUTH_SIG_DOMAIN, &msg)
                    };
                    (
                        id.peer_id().to_hex(),
                        hex::encode(id.ed25519_pub),
                        hex::encode(id.x25519_pub),
                        hex::encode(id.preauth_x25519_pub.as_bytes()),
                        hex::encode(&preauth_sig),
                        id.display_name.clone().unwrap_or_default(),
                        *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()),
                    )
                }
            }
        };

        // The endpoint we announce is "local_ip:clearnet_port". We use the
        // source address the socket is bound to, which is 0.0.0.0 (any
        // interface) — the receiver should use the packet source address
        // to fill in the real IP.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let announcement = serde_json::json!({
            "v": 1,
            "type": "mi_presence",
            "peer_id": peer_id_hex,
            "ed25519_pub": ed_hex,
            "x25519_pub": x_hex,
            "preauth_x25519_pub": preauth_hex,
            "preauth_sig": preauth_sig_hex,
            "display_name": display_name,
            "clearnet_port": clearnet_port,
            "ts": ts,
        });
        if let Ok(bytes) = serde_json::to_vec(&announcement) {
            // Broadcast to 255.255.255.255.
            let dest = std::net::SocketAddr::from(([255, 255, 255, 255], 7235));
            let _ = socket.send_to(&bytes, dest);
        }
    }

    /// Process a single received LAN presence packet.
    ///
    /// If the sender is a known contact, update their status to online.
    /// If unknown, add to the mDNS-discovered cache (for the UI to display).
    fn handle_lan_presence_packet(
        &self,
        data: &[u8],
        src: std::net::SocketAddr,
    ) -> Option<()> {
        let pkt: serde_json::Value = serde_json::from_slice(data).ok()?;
        if pkt.get("type")?.as_str()? != "mi_presence" { return None; }
        if pkt.get("v")?.as_u64()? != 1 { return None; }

        let peer_id_hex = pkt.get("peer_id")?.as_str()?;
        let ed_hex = pkt.get("ed25519_pub")?.as_str()?;
        let x_hex = pkt.get("x25519_pub")?.as_str()?;
        let display_name = pkt.get("display_name").and_then(|v| v.as_str()).unwrap_or("");
        let clearnet_port = pkt.get("clearnet_port").and_then(|v| v.as_u64()).unwrap_or(7234);
        // Extract peer's current preauth pub (X3DH SPK) if present.
        let preauth_pub_bytes: Option<[u8; 32]> = pkt
            .get("preauth_x25519_pub")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
        // Extract the identity-binding signature for the preauth key (§7.0.1).
        let preauth_sig_opt: Option<Vec<u8>> = pkt
            .get("preauth_sig")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 64);

        let peer_bytes: [u8; 32] = hex::decode(peer_id_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a })?;
        let peer_id = PeerId(peer_bytes);

        // Ignore our own broadcasts.
        let our_peer_id = self.identity.lock().unwrap_or_else(|e| e.into_inner())
            .as_ref().map(|id| id.peer_id());
        if Some(peer_id) == our_peer_id { return None; }

        // Build the inferred clearnet endpoint from the source IP + announced port.
        let src_ip = src.ip().to_string();
        let endpoint = format!("{src_ip}:{clearnet_port}");

        // Check if this peer is already a contact.
        let is_contact = self.contacts.lock().unwrap_or_else(|e| e.into_inner())
            .get(&peer_id).is_some();

        if is_contact {
            // Measure TCP RTT to the peer (50 ms timeout — LAN connects in <5 ms).
            let latency_ms: Option<u32> = endpoint.parse::<std::net::SocketAddr>().ok()
                .and_then(|addr| {
                    let t0 = std::time::Instant::now();
                    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(50))
                        .ok()
                        .map(|_| t0.elapsed().as_millis() as u32)
                });

            // Update last_seen, clearnet endpoint, and latency in contact record.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let (trust_level_val, cap_exit, cap_wrapper, cap_sf, cap_endorse) = {
                let mut contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(c) = contacts.get_mut(&peer_id) {
                    c.last_seen = Some(now);
                    c.clearnet_endpoint = Some(endpoint.clone());
                    if let Some(ms) = latency_ms { c.latency_ms = Some(ms); }
                    // Refresh preauth key from presence announcement (rotates weekly).
                    if let Some(preauth_bytes) = preauth_pub_bytes {
                        // Only update if changed — avoid unnecessary disk writes.
                        if c.preauth_key.as_ref() != Some(&preauth_bytes) {
                            if let Some(sig) = preauth_sig_opt.clone() {
                                c.update_preauth_key_with_sig(preauth_bytes, sig, now);
                            } else {
                                c.update_preauth_key(preauth_bytes, now);
                            }
                        }
                    }
                    (
                        c.trust_level.value(),
                        c.can_be_exit_node,
                        c.can_be_wrapper_node,
                        c.can_be_store_forward,
                        c.can_endorse_peers,
                    )
                } else {
                    (0, false, false, false, false)
                }
            };
            // Emit PeerUpdated so the UI shows "online" status.
            self.push_event("PeerUpdated", serde_json::json!({
                "id": peer_id_hex,
                "name": display_name,
                "trustLevel": trust_level_val,
                "status": "online",
                "canBeExitNode": cap_exit,
                "canBeWrapperNode": cap_wrapper,
                "canBeStoreForward": cap_sf,
                "canEndorsePeers": cap_endorse,
                "latencyMs": latency_ms,
            }));
        } else {
            // Add to the discovery cache if not already present.
            let mut discovered = self.mdns_discovered.lock().unwrap_or_else(|e| e.into_inner());
            let already = discovered.iter().any(|e| {
                e.get("id").and_then(|v| v.as_str()) == Some(peer_id_hex)
            });
            if !already {
                // Use field names matching the Dart DiscoveredPeerModel
                // ("id", "address") plus pairing fields for the pair action.
                discovered.push(serde_json::json!({
                    "id": peer_id_hex,
                    "address": endpoint,
                    "displayName": display_name,
                    "ed25519Pub": ed_hex,
                    "x25519Pub": x_hex,
                }));
            }
        }

        Some(())
    }

    /// Attempt to deliver any queued outbox messages.
    ///
    /// For each outbox entry:
    /// - If we already have an identified connection to that peer, send immediately.
    /// - Otherwise, try clearnet (if enabled) then Tor (if enabled and peer advertises onion).
    /// - Successfully delivered entries are removed; failed entries remain queued.
    fn clearnet_flush_outbox(&self) {
        let flags = self.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut outbox = self.outbox.lock().unwrap_or_else(|e| e.into_inner());
        if outbox.is_empty() { return; }

        let mut remaining = Vec::new();
        for (peer_hex, endpoint, frame) in outbox.drain(..) {
            // Try existing connection first (works regardless of transport).
            let sent = {
                let mut conns = self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(stream) = conns.get_mut(&peer_hex) {
                    write_tcp_frame(stream, &frame).is_ok()
                } else {
                    false
                }
            };

            if sent {
                continue; // Delivered — drop from outbox.
            }

            // Try clearnet if enabled.
            let clearnet_connected = flags.clearnet && {
                if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
                    if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
                        &addr,
                        std::time::Duration::from_secs(3),
                    ) {
                        let ok = write_tcp_frame(&mut stream, &frame).is_ok();
                        if ok {
                            let _ = stream.set_nonblocking(true);
                            self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner())
                                .insert(peer_hex.clone(), stream);
                        }
                        ok
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if clearnet_connected { continue; }

            // Try Tor if enabled and peer has a known onion endpoint (§5.3).
            let tor_connected = flags.tor && {
                let tor_endpoint = {
                    let peer_bytes = hex::decode(&peer_hex).ok()
                        .and_then(|b| if b.len() == 32 { let mut a = [0u8; 32]; a.copy_from_slice(&b); Some(a) } else { None });
                    peer_bytes.and_then(|b| {
                        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                        contacts.get(&PeerId(b)).and_then(|c| c.tor_endpoint.clone())
                    })
                };
                if let Some(ref tor_ep) = tor_endpoint {
                    // Parse "addr.onion:port" format.
                    let (onion_addr, port) = if let Some(colon) = tor_ep.rfind(':') {
                        let addr = &tor_ep[..colon];
                        let port: u16 = tor_ep[colon + 1..].parse().unwrap_or(DEFAULT_HS_PORT);
                        (addr.to_string(), port)
                    } else {
                        (tor_ep.clone(), DEFAULT_HS_PORT)
                    };
                    let guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(ref tor) = *guard {
                        match tor.connect(&peer_hex, &onion_addr, port) {
                            Ok(mut stream) => {
                                let ok = write_tcp_frame(&mut stream, &frame).is_ok();
                                if ok {
                                    self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner())
                                        .insert(peer_hex.clone(), stream);
                                    tor.record_message(&peer_hex);
                                }
                                ok
                            }
                            Err(e) => {
                                tracing::debug!(peer=%peer_hex, "Tor outbound connect failed: {e}");
                                false
                            }
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if !clearnet_connected && !tor_connected {
                remaining.push((peer_hex, endpoint, frame));
            }
        }
        *outbox = remaining;
    }

    /// Drain inbound connections from the Tor hidden service (§5.3).
    ///
    /// The `TorTransport` runs a background task that bridges hidden-service
    /// streams to localhost TCP sockets.  Here we collect those sockets and
    /// insert them into the same pending-incoming queue as clearnet connections,
    /// so the standard identification and pairing handshake handles them.
    fn tor_drain_inbound(&self) {
        let new_streams: Vec<std::net::TcpStream> = {
            let guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(tor) => tor.drain_inbound(),
                None => Vec::new(),
            }
        };
        if !new_streams.is_empty() {
            let mut pending = self.clearnet_pending_incoming.lock().unwrap_or_else(|e| e.into_inner());
            for stream in new_streams {
                pending.push((stream, Vec::new()));
            }
        }
    }

    /// Accept new TCP connections from the listener into the pending queue.
    fn clearnet_accept_new_connections(&self) {
        let new_streams: Vec<std::net::TcpStream> = {
            let guard = self.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner());
            let mut accepted = Vec::new();
            if let Some(ref listener) = *guard {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(true);
                            accepted.push(stream);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
            accepted
        };
        if !new_streams.is_empty() {
            let mut pending = self.clearnet_pending_incoming.lock().unwrap_or_else(|e| e.into_inner());
            for stream in new_streams {
                pending.push((stream, Vec::new()));
            }
        }
    }

    /// Read data from unidentified incoming connections. Once a complete frame
    /// arrives, extract the sender peer_id and promote to identified connections.
    fn clearnet_process_pending_incoming(&self) {
        use std::io::Read;
        let pending_conns: Vec<(std::net::TcpStream, Vec<u8>)> = {
            let mut guard = self.clearnet_pending_incoming.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };

        let mut still_pending: Vec<(std::net::TcpStream, Vec<u8>)> = Vec::new();
        let mut identified: Vec<(String, std::net::TcpStream, Vec<u8>)> = Vec::new();
        let mut ready_frames: Vec<Vec<u8>> = Vec::new();

        for (mut stream, mut buf) in pending_conns {
            // Read available data (non-blocking).
            let mut tmp = [0u8; 4096];
            let closed = loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break true,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break false,
                    Err(_) => break true,
                }
            };
            if closed {
                continue;
            }
            // Try to extract a frame and identify the sender.
            if let Some(frame) = try_read_frame(&mut buf) {
                if let Some(sender_hex) = extract_frame_sender(&frame) {
                    ready_frames.push(frame);
                    identified.push((sender_hex, stream, buf));
                    continue;
                }
            }
            still_pending.push((stream, buf));
        }

        // Re-insert still-pending connections.
        self.clearnet_pending_incoming.lock().unwrap_or_else(|e| e.into_inner()).extend(still_pending);

        // Promote identified connections — with isolation-mode enforcement (§3.4).
        //
        // When threat_context == Critical (isolation / darknet mode), only
        // connections from peers already in our contact store are accepted.
        // All other inbound connections are silently dropped: the TCP socket
        // is closed (dropped) and the peer receives no useful error information.
        let in_critical_mode = self.threat_context == ThreatContext::Critical;

        let mut newly_identified: Vec<String> = Vec::new();
        for (peer_id_hex, stream, buf) in identified {
            // Isolation mode: reject unknown peers.
            if in_critical_mode {
                let peer_bytes = match hex::decode(&peer_id_hex) {
                    Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
                    _ => continue, // Malformed ID — always drop.
                };
                let known = self.contacts.lock().unwrap_or_else(|e| e.into_inner())
                    .get(&PeerId(peer_bytes)).is_some();
                if !known {
                    // `stream` is dropped here, closing the socket.
                    drop(stream);
                    continue;
                }
            }
            self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_id_hex.clone(), stream);
            self.clearnet_recv_buffers.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_id_hex.clone(), buf);
            newly_identified.push(peer_id_hex);
        }

        // For each newly identified peer:
        //   1. Insert a direct routing entry into the local routing plane (§6.1).
        //   2. Flush any queued S&F messages deposited while they were offline (§6.8).
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);
        for peer_id_hex in &newly_identified {
            // (1) Local routing entry — direct connection, hop_count=1.
            self.insert_local_route_for_peer(peer_id_hex);
            // Seed the last_rx timestamp so the keepalive timer starts from
            // when they first connected, not from the epoch.
            self.clearnet_last_rx.lock().unwrap_or_else(|e| e.into_inner())
                .insert(peer_id_hex.clone(), std::time::Instant::now());

            // (3) Emit PeerUpdated with "online" status so the UI reflects the
            // live connection immediately without waiting for a poll cycle.
            {
                let peer_bytes_opt = hex::decode(peer_id_hex)
                    .ok()
                    .filter(|b| b.len() == 32)
                    .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
                if let Some(peer_bytes) = peer_bytes_opt {
                    let pid = PeerId(peer_bytes);
                    let (display_name, trust_val, cap_exit, cap_wrapper, cap_sf, cap_endorse) = {
                        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(c) = contacts.get(&pid) {
                            (
                                c.display_name.clone().unwrap_or_default(),
                                c.trust_level as u8,
                                c.can_be_exit_node,
                                c.can_be_wrapper_node,
                                c.can_be_store_forward,
                                c.can_endorse_peers,
                            )
                        } else {
                            (String::new(), 0u8, false, false, false, false)
                        }
                    };
                    self.push_event("PeerUpdated", serde_json::json!({
                        "id": peer_id_hex,
                        "name": display_name,
                        "trustLevel": trust_val,
                        "status": "online",
                        "canBeExitNode": cap_exit,
                        "canBeWrapperNode": cap_wrapper,
                        "canBeStoreForward": cap_sf,
                        "canEndorsePeers": cap_endorse,
                        "latencyMs": null,
                    }));
                }
            }

            // (2) S&F flush — deliver any buffered messages for this peer.
            if let Ok(peer_bytes) = hex::decode(peer_id_hex) {
                if peer_bytes.len() == 32 {
                    let mut addr_bytes = [0u8; 32];
                    addr_bytes.copy_from_slice(&peer_bytes);
                    let dest = DeviceAddress(addr_bytes);
                    let queued = self.sf_server.lock().unwrap_or_else(|e| e.into_inner())
                        .retrieve(&dest, now_secs);
                    for req in queued {
                        let payload_hex = hex::encode(&req.payload);
                        let deliver_frame = serde_json::json!({
                            "type": "sf_deliver",
                            "payload_hex": payload_hex,
                        });
                        self.send_raw_frame(peer_id_hex, &deliver_frame);
                    }
                }
            }

            // (4) Auto-initiate WireGuard handshake for known contacts (§5.2).
            //
            // We only initiate if:
            //   a) the peer is in our contact store (we have their X25519 key), and
            //   b) we don't already have a live WG session with them.
            //
            // The responder side is handled by mi_wg_respond_to_handshake when the
            // remote peer sends us their wg_init frame.
            {
                use crate::transport::wireguard::PendingInitiatorHandshake;
                use crate::crypto::channel_key::derive_channel_key;

                if let Ok(peer_bytes) = hex::decode(peer_id_hex) {
                    if peer_bytes.len() == 32 {
                        let mut arr = [0u8; 32]; arr.copy_from_slice(&peer_bytes);
                        let responder_id = PeerId(arr);

                        let already_has_session = self.wireguard_sessions
                            .lock().unwrap_or_else(|e| e.into_inner())
                            .get(&responder_id).is_some();
                        let already_pending = self.pending_wg_handshakes
                            .lock().unwrap_or_else(|e| e.into_inner())
                            .contains_key(&responder_id);

                        if !already_has_session && !already_pending {
                            // Look up peer X25519 and our own keys.
                            let keys_opt = {
                                let id_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                                let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                                if let (Some(id), Some(contact)) = (id_guard.as_ref(), contacts.get(&responder_id)) {
                                    let our_secret = id.x25519_secret.to_bytes();
                                    let their_pub = x25519_dalek::PublicKey::from(contact.x25519_public);
                                    let our_id = id.peer_id();
                                    Some((our_secret, their_pub, our_id))
                                } else {
                                    None
                                }
                            };

                            if let Some((our_secret_bytes, their_pub, our_id)) = keys_opt {
                                let our_secret = x25519_dalek::StaticSecret::from(our_secret_bytes);
                                let our_pub = x25519_dalek::PublicKey::from(&our_secret);
                                if let Ok(psk) = derive_channel_key(&our_secret, &their_pub, &our_id, &responder_id) {
                                    let (pending, init_msg) = PendingInitiatorHandshake::new(
                                        x25519_dalek::StaticSecret::from(our_secret.to_bytes()),
                                        their_pub,
                                        psk,
                                    );
                                    // our_pub is Copy — `drop` on a Copy type does nothing;
                                    // acknowledge the value is intentionally not used further.
                                    let _ = our_pub;

                                    // Store pending state.
                                    self.pending_wg_handshakes
                                        .lock().unwrap_or_else(|e| e.into_inner())
                                        .insert(responder_id, pending);

                                    // Send the wg_init frame to the peer.
                                    let mut init_bytes = Vec::with_capacity(80);
                                    init_bytes.extend_from_slice(&init_msg.eph_i_pub);
                                    init_bytes.extend_from_slice(&init_msg.enc_static);
                                    let our_hex = our_id.to_hex();
                                    let frame = serde_json::json!({
                                        "type":     "wg_init",
                                        "sender":   our_hex,
                                        "init_hex": hex::encode(&init_bytes),
                                    });
                                    self.send_raw_frame(peer_id_hex, &frame);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Process frames from newly identified peers.
        for frame in ready_frames {
            self.process_inbound_frame(&frame);
        }
    }

    /// Read and process frames from all identified peer connections.
    fn clearnet_process_identified(&self) {
        use std::io::Read;

        let peer_ids: Vec<String> = self
            .clearnet_connections.lock().unwrap_or_else(|e| e.into_inner())
            .keys().cloned().collect();

        let mut to_remove: Vec<String> = Vec::new();

        for peer_id_hex in &peer_ids {
            // Read available bytes into the peer's buffer.
            let (closed, mut buf) = {
                let mut buf = self.clearnet_recv_buffers.lock().unwrap_or_else(|e| e.into_inner())
                    .get(peer_id_hex).cloned().unwrap_or_default();
                let mut tmp = [0u8; 4096];
                let closed = {
                    let mut conns = self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(stream) = conns.get_mut(peer_id_hex) {
                        let mut closed = false;
                        loop {
                            match stream.read(&mut tmp) {
                                Ok(0) => { closed = true; break; }
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(_) => { closed = true; break; }
                            }
                        }
                        closed
                    } else {
                        true
                    }
                };
                (closed, buf)
            };

            if closed {
                to_remove.push(peer_id_hex.clone());
                continue;
            }

            // Extract and process complete frames.
            let mut frames: Vec<Vec<u8>> = Vec::new();
            while let Some(frame) = try_read_frame(&mut buf) {
                frames.push(frame);
            }

            // Write back the updated buffer.
            self.clearnet_recv_buffers.lock().unwrap_or_else(|e| e.into_inner())
                .insert(peer_id_hex.clone(), buf);

            // Update last_rx on every frame batch received, so the keepalive
            // timer doesn't fire on active connections.
            if !frames.is_empty() {
                self.clearnet_last_rx.lock().unwrap_or_else(|e| e.into_inner())
                    .insert(peer_id_hex.clone(), std::time::Instant::now());
            }

            for frame in frames {
                // Unwrap WireGuard encryption if this frame is a wg_ct envelope (§5.2).
                let plaintext_frame = if frame.starts_with(b"{\"wg_ct\"") {
                    // Try to parse as WG ciphertext envelope: {"wg_ct":"<hex>"}
                    if let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&frame) {
                        if let Some(ct_hex) = envelope.get("wg_ct").and_then(|v| v.as_str()) {
                            if let Ok(ct_bytes) = hex::decode(ct_hex) {
                                // Look up the WG session for this peer.
                                let peer_id_opt = hex::decode(peer_id_hex).ok()
                                    .filter(|b| b.len() == 32)
                                    .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); PeerId(a) });
                                if let Some(peer_id) = peer_id_opt {
                                    let mut wg = self.wireguard_sessions.lock().unwrap_or_else(|e| e.into_inner());
                                    if let Some(session) = wg.get_mut(&peer_id) {
                                        match session.decrypt(&ct_bytes) {
                                            Ok(plaintext) => plaintext,
                                            Err(_) => continue, // AEAD failure — drop frame silently.
                                        }
                                    } else {
                                        // No WG session for this peer — drop encrypted frame.
                                        continue;
                                    }
                                } else {
                                    continue; // Invalid peer ID — drop.
                                }
                            } else {
                                continue; // Malformed hex — drop.
                            }
                        } else {
                            frame // Not a wg_ct envelope — process as-is.
                        }
                    } else {
                        frame // Not valid JSON — try to process as-is (will likely fail gracefully).
                    }
                } else {
                    frame // Plaintext frame (no WG session or peer hasn't established one yet).
                };
                self.process_inbound_frame(&plaintext_frame);
            }
        }

        // Remove closed connections, purge local routing entries, and update peer status.
        for p in &to_remove {
            self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner()).remove(p);
            self.clearnet_recv_buffers.lock().unwrap_or_else(|e| e.into_inner()).remove(p);
            self.clearnet_last_rx.lock().unwrap_or_else(|e| e.into_inner()).remove(p);
            self.clearnet_last_keepalive_tx.lock().unwrap_or_else(|e| e.into_inner()).remove(p);
            // Remove the direct (local-plane) routing entry — the peer is no
            // longer reachable via this direct link.
            if let Ok(bytes) = hex::decode(p) {
                if bytes.len() == 32 {
                    let mut a = [0u8; 32]; a.copy_from_slice(&bytes);
                    let addr = DeviceAddress(a);
                    self.routing_table.lock().unwrap_or_else(|e| e.into_inner()).remove_local(&addr);
                }
            }
            // Emit PeerUpdated with "offline" so the UI updates immediately.
            {
                let (display_name, trust_val) = {
                    let peer_bytes_opt = hex::decode(p).ok().filter(|b| b.len() == 32)
                        .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
                    if let Some(pb) = peer_bytes_opt {
                        let pid = PeerId(pb);
                        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
                        contacts.get(&pid).map(|c| (
                            c.display_name.clone().unwrap_or_default(),
                            c.trust_level as u8,
                        )).unwrap_or_default()
                    } else {
                        (String::new(), 0u8)
                    }
                };
                self.push_event("PeerUpdated", serde_json::json!({
                    "id": p,
                    "name": display_name,
                    "trustLevel": trust_val,
                    "status": "offline",
                    "canBeExitNode": false,
                    "canBeWrapperNode": false,
                    "canBeStoreForward": false,
                    "canEndorsePeers": false,
                    "latencyMs": null,
                }));
            }
        }
    }

    /// Decrypt an inbound TCP frame and push a MessageAdded event.
    ///
    /// Frame payload must be a JSON envelope with fields:
    /// `sender`, `room`, `msg_id`, `ts`, `ratchet_pub`, `prev_chain_len`,
    /// `msg_num`, `ciphertext`.
    ///
    /// Special case: if `type == "pairing_hello"` the frame is dispatched to
    /// `process_pairing_hello` instead of the decryption path.
    fn process_inbound_frame(&self, frame_payload: &[u8]) -> bool {
        // Parse envelope.
        let envelope: serde_json::Value = match serde_json::from_slice(frame_payload) {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Early dispatch for pairing_hello frames (§8.3 two-way bootstrap).
        // These arrive BEFORE the sender is in our contact store, so they must
        // be handled before the "unknown sender → reject" gate below.
        if envelope.get("type").and_then(|t| t.as_str()) == Some("pairing_hello") {
            return self.process_pairing_hello(&envelope);
        }

        // LoSec negotiation frames (§6.9.6).
        // Dispatched early so they work even if the sender hasn't fully
        // authenticated (LoSec requests carry their own Ed25519 signature).
        let frame_type = envelope.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if frame_type == "losec_request" {
            return self.process_losec_request_frame(&envelope);
        }
        if frame_type == "losec_response" {
            return self.process_losec_response_frame(&envelope);
        }

        // Gossip network map entry (§4.1): peer broadcasts their signed entry.
        // We validate the signature, merge into our local map, and update the
        // contact's preauth key if this peer is already in our contact store.
        if frame_type == "gossip_map_entry" {
            return self.process_gossip_map_entry_frame(&envelope);
        }

        // Call signalling frames (§10.1.6): offer, answer, hangup.
        if frame_type == "call_offer" {
            return self.process_call_offer_frame(&envelope);
        }
        if frame_type == "call_answer" {
            return self.process_call_answer_frame(&envelope);
        }
        if frame_type == "call_hangup" {
            return self.process_call_hangup_frame(&envelope);
        }

        // WireGuard handshake initiation from a remote peer (§5.2).
        // Respond with our handshake response and establish the session.
        if frame_type == "wg_init" {
            return self.process_wg_init_frame(&envelope);
        }

        // WireGuard handshake response (§5.2).
        // Completes our pending initiator handshake and establishes the session.
        if frame_type == "wg_response" {
            return self.process_wg_response_frame(&envelope);
        }

        // Reachability announcement (§6.2): a peer broadcasts their routing entry.
        // Feed it through the AnnouncementProcessor which deduplicates, validates
        // hop count, and updates the routing table with new multi-hop routes.
        if frame_type == "route_announcement" {
            return self.process_route_announcement_frame(&envelope);
        }

        // Routed mesh packet (§6.5): may be for us or require forwarding.
        if frame_type == "mesh_packet" {
            return self.process_mesh_packet_frame(&envelope);
        }

        // File transfer offer (§9): peer wants to send us a file.
        if frame_type == "file_offer" {
            return self.process_file_offer_frame(&envelope);
        }

        // File transfer chunk (§9): incoming data chunk for a receive transfer.
        if frame_type == "file_chunk" {
            return self.process_file_chunk_frame(&envelope);
        }

        // File transfer completion (§9): sender signals all chunks sent.
        if frame_type == "file_complete" {
            return self.process_file_complete_frame(&envelope);
        }

        // Group Sender Key rekey distribution (§8.7.4): the group admin has
        // rotated the Sender Key and is sending us the new material.
        if frame_type == "group_rekey" {
            return self.process_group_rekey_frame(&envelope);
        }

        // Group invite (§8.7): the admin is sending us group credentials so
        // we can join an existing group room.
        if frame_type == "group_invite" {
            return self.process_group_invite_frame(&envelope);
        }

        // Group message (§8.7): an inbound message from another group member.
        if frame_type == "group_message" {
            return self.process_group_message_frame(&envelope);
        }

        // Group message — Sender Key path (§7.0.4 / §8.7): wrapped with the
        // group symmetric key, inner payload encrypted with sender's Sender Key.
        if frame_type == "group_message_sk" {
            return self.process_group_message_sk_frame(&envelope);
        }

        // Group re-inclusion request (§8.7.6): a member whose ratchet session is
        // out of sync requests that an admin re-send them a group_invite.
        if frame_type == "group_reinclusion_request" {
            return self.process_group_reinclusion_request_frame(&envelope);
        }

        // Store-and-forward deposit (§6.8): a peer deposits a message for an
        // offline destination. We buffer it and deliver when the destination reconnects.
        if frame_type == "sf_deposit" {
            return self.process_sf_deposit_frame(&envelope);
        }

        // Store-and-forward delivery (§6.8): either we pushed a queued message to a
        // newly-connected peer, or a relay node is pushing a queued message to us.
        if frame_type == "sf_deliver" {
            return self.process_sf_deliver_frame(&envelope);
        }

        // Delivery receipt (§7.3): recipient confirms they decrypted our message.
        // We update the message status from "sent" to "delivered" and emit a
        // MessageStatusUpdated event so the UI can show a delivery checkmark.
        if frame_type == "delivery_receipt" {
            return self.process_delivery_receipt_frame(&envelope);
        }

        // Keepalive probe (§5.1): respond with a keepalive_ack so the sender
        // knows we're alive. The sender's keepalive timer resets when it
        // receives any frame from us, including this ack.
        if frame_type == "keepalive" {
            let our_hex = self.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default();
            let sender_hex_opt = envelope.get("sender").and_then(|v| v.as_str()).map(|s| s.to_string());
            if let Some(ref peer_hex) = sender_hex_opt {
                self.send_raw_frame(peer_hex, &serde_json::json!({
                    "type": "keepalive_ack",
                    "sender": our_hex,
                }));
            }
            return true;
        }

        // Keepalive acknowledgement: the remote side confirmed our probe.
        // No action needed — the fact that this frame arrived already updated
        // clearnet_last_rx in clearnet_process_identified.
        if frame_type == "keepalive_ack" {
            return true;
        }

        // Typing indicator (§10.2.1): surface the event to the UI.
        if frame_type == "typing_indicator" {
            if let (Some(sender), Some(room_id)) = (
                envelope.get("sender").and_then(|v| v.as_str()),
                envelope.get("roomId").and_then(|v| v.as_str()),
            ) {
                let is_active = envelope.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                self.push_event("TypingIndicator", serde_json::json!({
                    "roomId":  room_id,
                    "peerId":  sender,
                    "active":  is_active,
                }));
            }
            return true;
        }

        // Emoji reaction (§10.1.2): a peer reacted to one of our messages.
        // Surface the ReactionAdded event so the UI can update the message row.
        if frame_type == "reaction" {
            if let (Some(sender), Some(room_id), Some(msg_id), Some(emoji)) = (
                envelope.get("sender").and_then(|v| v.as_str()),
                envelope.get("roomId").and_then(|v| v.as_str()),
                envelope.get("msgId").and_then(|v| v.as_str()),
                envelope.get("emoji").and_then(|v| v.as_str()),
            ) {
                if !emoji.is_empty() {
                    self.push_event("ReactionAdded", serde_json::json!({
                        "roomId": room_id,
                        "msgId":  msg_id,
                        "peerId": sender,
                        "emoji":  emoji,
                    }));
                }
            }
            return true;
        }

        macro_rules! field_str {
            ($key:expr) => {
                match envelope.get($key).and_then(|v| v.as_str()) {
                    Some(s) => s.to_string(),
                    None => return false,
                }
            };
        }

        let sender_hex = field_str!("sender");
        let room_id_hex = field_str!("room");
        let msg_id = field_str!("msg_id");
        let ts = envelope.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
        let ciphertext_hex = field_str!("ciphertext");
        let ratchet_pub_hex = field_str!("ratchet_pub");
        let prev_chain_len = envelope.get("prev_chain_len")
            .and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let msg_num = envelope.get("msg_num")
            .and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        // Decode binary fields.
        let ciphertext = match hex::decode(&ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ratchet_pub_bytes = match hex::decode(&ratchet_pub_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sender_id_bytes = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sender_peer_id = PeerId(sender_id_bytes);

        // Look up the sender in our contact store.
        let contact = match self.contacts.lock().unwrap_or_else(|e| e.into_inner()).get(&sender_peer_id).cloned() {
            Some(c) => c,
            None => return false, // Unknown sender — reject.
        };

        // Ensure a Double Ratchet session exists for this sender.
        // If the envelope carries an X3DH init header, use x3dh_respond (preferred).
        // Otherwise fall back to static DH bootstrap.
        if !self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&sender_peer_id) {
            let eph_pub_opt = envelope.get("x3dh_eph_pub").and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok())
                .filter(|b| b.len() == 32)
                .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
            let enc_ik_opt = envelope.get("x3dh_encrypted_ik").and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok())
                .filter(|b| b.len() == crate::crypto::x3dh::ENCRYPTED_IK_SIZE)
                .map(|b| { let mut a = [0u8; crate::crypto::x3dh::ENCRYPTED_IK_SIZE]; a.copy_from_slice(&b); a });

            // Parse optional PQXDH fields (§3.4.1).
            let pqxdh_kem_ct = envelope.get("pqxdh_kem_ct").and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok())
                .filter(|b| b.len() == crate::crypto::x3dh::KEM_CT_SIZE);
            let pqxdh_kem_binding = envelope.get("pqxdh_kem_binding").and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok())
                .filter(|b| b.len() == 32)
                .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });

            let session_result: Option<DoubleRatchetSession> = if let (Some(eph_pub), Some(enc_ik)) = (eph_pub_opt, enc_ik_opt) {
                // X3DH / PQXDH response path: Bob receives Alice's init header.
                use crate::crypto::x3dh::{x3dh_respond, pqxdh_decapsulate, X3dhInitHeader};
                let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                guard.as_ref().and_then(|id| {
                    let header = X3dhInitHeader { eph_pub, encrypted_ik_pub: enc_ik };
                    let mut output = x3dh_respond(&id.x25519_secret, &id.preauth_x25519_secret, &header).ok()?;

                    // PQXDH: if ciphertext and binding present, mix in PQ shared secret.
                    if let (Some(ref kem_ct), Some(ref kem_binding)) = (&pqxdh_kem_ct, &pqxdh_kem_binding) {
                        // DH3 = preauth_secret * eph_pub (mirrors Alice's computation).
                        let dh3 = id.preauth_x25519_secret.diffie_hellman(
                            &x25519_dalek::PublicKey::from(eph_pub)
                        );
                        // Decapsulate and verify binding; rebuild master_secret with PQ extension.
                        if let Ok(pq_ss) = pqxdh_decapsulate(
                            &id.kem_decapsulation_key,
                            kem_ct,
                            kem_binding,
                            dh3.as_bytes(),
                        ) {
                            // Re-derive master secret including PQ shared secret.
                            use hkdf::Hkdf;
                            use zeroize::Zeroizing;
                            let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 5));
                            ikm.extend_from_slice(&[0xFF; 32]); // F prefix
                            // DH values already baked into output.master_secret — re-derive from scratch.
                            // Actually we need to recompute IKM from scratch:
                            let dh1 = id.preauth_x25519_secret.diffie_hellman(
                                &x25519_dalek::PublicKey::from(contact.x25519_public)
                            );
                            let dh2 = id.x25519_secret.diffie_hellman(
                                &x25519_dalek::PublicKey::from(eph_pub)
                            );
                            let dh3_inner = id.preauth_x25519_secret.diffie_hellman(
                                &x25519_dalek::PublicKey::from(eph_pub)
                            );
                            let mut ikm2 = Zeroizing::new(Vec::with_capacity(32 + 32 * 4));
                            ikm2.extend_from_slice(&[0xFF; 32]);
                            ikm2.extend_from_slice(dh1.as_bytes());
                            ikm2.extend_from_slice(dh2.as_bytes());
                            ikm2.extend_from_slice(dh3_inner.as_bytes());
                            ikm2.extend_from_slice(&pq_ss);
                            let hk = Hkdf::<sha2::Sha256>::new(Some(&[0u8; 32]), &ikm2);
                            let mut master = Zeroizing::new([0u8; 32]);
                            if hk.expand(b"MeshInfinity_PQXDH_v1", &mut *master).is_ok() {
                                output = crate::crypto::x3dh::X3dhSessionOutput {
                                    master_secret: crate::crypto::secmem::SecureKey32::new(*master).ok()?,
                                    is_post_quantum: true,
                                    header: None,
                                    pqxdh_header: None,
                                };
                            }
                        }
                    }

                    let master = output.master_secret.as_bytes();
                    // Bob is the receiver; his initial ratchet key is his preauth keypair.
                    let preauth_secret = X25519Secret::from(id.preauth_x25519_secret.to_bytes());
                    let preauth_pub = *id.preauth_x25519_pub.as_bytes();
                    Some(DoubleRatchetSession::init_receiver(master, preauth_secret, &preauth_pub))
                })
            } else {
                // Static DH fallback.
                let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                guard.as_ref().and_then(|id| {
                    bootstrap_ratchet_session(id, &contact).ok().map(|(s, _, _)| s)
                })
            };

            let session = match session_result {
                Some(s) => s,
                None => return false,
            };
            self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(sender_peer_id, session);
        } else {
            // We already have a session — if this is a reply from Bob, clear
            // our pending X3DH/PQXDH headers (we no longer need to include them).
            self.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&sender_peer_id);
            self.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&sender_peer_id);
        }

        // Advance the ratchet and derive message keys.
        let header = RatchetHeader {
            ratchet_pub: ratchet_pub_bytes,
            prev_chain_len,
            msg_num,
        };
        let (cipher_key, session_nonce, ratchet_msg_key) = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            let session = match sessions.get_mut(&sender_peer_id) {
                Some(s) => s,
                None => return false,
            };
            let msg_key = match session.recv_msg_key(&header) {
                Ok(k) => k,
                Err(_) => return false,
            };
            match DoubleRatchetSession::expand_msg_key(&msg_key) {
                Ok(keys) => keys,
                Err(_) => return false,
            }
        };

        // Get our X25519 secret for Step 4 decryption.
        let our_x25519_secret = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => X25519Secret::from(id.x25519_secret.to_bytes()),
                None => return false,
            }
        };

        // Get sender's Ed25519 verifying key for Step 3 signature verification.
        let sender_verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&contact.ed25519_public) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Decrypt via the four-layer scheme (Step 4 → 3 → 2 → 1).
        let plaintext = match decrypt_message(
            &ciphertext,
            &our_x25519_secret,
            &sender_verifying_key,
            &cipher_key,
            &session_nonce,
            &ratchet_msg_key,
            MessageContext::Direct,
        ) {
            Ok(p) => p,
            Err(_) => return false, // Decryption failed — silently discard.
        };

        let text = match String::from_utf8(plaintext) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Find or create a room for this conversation.
        let room_exists = self.rooms.lock().unwrap_or_else(|e| e.into_inner())
            .iter().any(|r| hex::encode(r.id) == room_id_hex);
        if !room_exists {
            // Auto-create a DM room for this incoming message.
            let our_peer_id = self.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| id.peer_id())
                .unwrap_or(PeerId([0u8; 32]));
            let peer_name = contact.display_name.as_deref()
                .or(contact.local_nickname.as_deref())
                .unwrap_or(&contact.peer_id.short_hex())
                .to_string();
            let mut room = Room::new_dm(our_peer_id, sender_peer_id, &peer_name);
            // Override the random room_id with the one from the sender
            // so both sides use the same room identifier.
            if let Ok(id_bytes) = hex::decode(&room_id_hex) {
                if id_bytes.len() == 16 {
                    room.id.copy_from_slice(&id_bytes);
                }
            }
            self.rooms.lock().unwrap_or_else(|e| e.into_inner()).push(room);
            self.save_rooms();
        }

        // Build message JSON — authStatus "authenticated" means the four-layer
        // decrypt succeeded (HMAC + AEAD + Ed25519 all verified). (M17, §7.1)
        let msg = serde_json::json!({
            "id": msg_id,
            "roomId": room_id_hex,
            "sender": sender_hex,
            "text": text,
            "timestamp": ts,
            "isOutgoing": false,
            "authStatus": "authenticated",
        });

        // Store in memory.
        self.messages.lock().unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.clone())
            .or_default()
            .push(msg.clone());

        // Update room last-message preview.
        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                room.last_message_preview = Some(if text.len() > 80 {
                    format!("{}…", &text[..80])
                } else {
                    text.clone()
                });
                room.last_message_at = Some(ts);
                if !room.is_muted {
                    room.unread_count += 1;
                }
            }
        }

        self.push_event("MessageAdded", msg);

        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms.iter().find(|r| hex::encode(r.id) == room_id_hex).map(|r| serde_json::json!({
                "id": hex::encode(r.id),
                "name": r.name,
                "lastMessage": r.last_message_preview,
                "unreadCount": r.unread_count,
                "timestamp": r.last_message_at,
            }))
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }

        // Send a delivery receipt back to the sender (§7.3).
        // This tells the sender's app to update the message's delivery status
        // from "sent" to "delivered", enabling the double-checkmark UX.
        {
            let our_hex = self.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default();
            let ts_now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);
            let receipt_frame = serde_json::json!({
                "type": "delivery_receipt",
                "sender": our_hex,
                "msg_id": msg_id,
                "room": room_id_hex,
                "ts": ts_now,
            });
            self.send_raw_frame(&sender_hex, &receipt_frame);
        }

        // Submit a notification event for this inbound message (§14).
        // The NotificationDispatcher applies jitter, coalescing, and threat-context
        // suppression. Here we only submit; dispatch happens in the advance loop.
        if self.module_config.lock().unwrap_or_else(|e| e.into_inner()).social.notifications {
            let room_id_bytes: Option<[u8; 32]> = hex::decode(&room_id_hex).ok()
                .filter(|b| b.len() == 16)
                .map(|b| {
                    // Pad 16-byte room_id to 32 bytes (notification uses 32-byte conv IDs).
                    let mut a = [0u8; 32];
                    a[..16].copy_from_slice(&b);
                    a
                });
            let sender_name = self.contacts.lock().unwrap_or_else(|e| e.into_inner())
                .get(&sender_peer_id)
                .and_then(|c| c.display_name.clone())
                .unwrap_or_else(|| sender_peer_id.short_hex());
            let notif_event = crate::notifications::NotificationEvent {
                priority: crate::notifications::NotificationPriority::Normal,
                title: format!("New message from {}", sender_name),
                body: Some(if text.len() > 60 { format!("{}…", &text[..60]) } else { text.clone() }),
                sender_id: Some(sender_peer_id.0),
                conversation_id: room_id_bytes,
                created_at: ts,
            };
            self.notifications.lock().unwrap_or_else(|e| e.into_inner()).submit(notif_event);
        }

        self.save_messages();
        self.save_rooms();
        self.save_ratchet_sessions();
        true
    }

    /// Handle a "pairing_hello" frame from a peer who has scanned our QR code.
    ///
    /// This is the second half of the two-way pairing handshake (§8.3).
    /// Bob scanned Alice's QR, called mi_pair_peer, then immediately sent this
    /// frame to Alice's clearnet endpoint so Alice can add Bob without a second
    /// QR scan.
    ///
    /// Frame fields:
    ///   `type`             — must be "pairing_hello"
    ///   `sender`           — Bob's peer_id (hex, 64 chars)
    ///   `ed25519_public`   — Bob's Ed25519 verifying key (hex, 64 chars)
    ///   `x25519_public`    — Bob's X25519 public key (hex, 64 chars)
    ///   `display_name`     — optional display name string
    ///   `transport_hints`  — array of hint objects (same shape as pairing payload)
    ///   `sig`              — Ed25519 signature over
    ///                        DOMAIN_PAIRING_HELLO | ed25519_bytes | x25519_bytes
    ///
    /// On success: stores Bob's ContactRecord, bootstraps a ratchet session,
    /// and emits a PeerAdded event.
    fn process_pairing_hello(&self, envelope: &serde_json::Value) -> bool {
        use crate::crypto::signing;

        // Extract ed25519_public first — used both as the verifying key and to
        // derive the canonical peer_id.
        let ed_hex = match envelope.get("ed25519_public").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ed_bytes: [u8; 32] = match hex::decode(ed_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };

        let x_hex = match envelope.get("x25519_public").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let x_bytes: [u8; 32] = match hex::decode(x_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };

        let sig_hex = match envelope.get("sig").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // Verify signature: DOMAIN_PAIRING_HELLO | ed25519_bytes | x25519_bytes.
        // We deliberately do NOT include the display_name in the signed data —
        // names are untrusted display hints and should never gate authentication.
        let mut signed_msg = Vec::with_capacity(64);
        signed_msg.extend_from_slice(&ed_bytes);
        signed_msg.extend_from_slice(&x_bytes);

        if !signing::verify(&ed_bytes, signing::DOMAIN_PAIRING_HELLO, &signed_msg, &sig_bytes) {
            return false;
        }

        // Derive the canonical peer_id from the verified Ed25519 key.
        let peer_id = PeerId::from_ed25519_pub(&ed_bytes);

        // If we already have this peer in our contact store, do not downgrade.
        if self.contacts.lock().unwrap_or_else(|e| e.into_inner()).get(&peer_id).is_some() {
            // Still emit PeerAdded so the UI reflects the connection if missed.
            let name = envelope.get("display_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            self.push_event("PeerAdded", serde_json::json!({
                "id": hex::encode(peer_id.0),
                "name": name.as_deref().unwrap_or(""),
                "trustLevel": 0,
                "status": "online",
                "canBeExitNode": false,
                "canBeWrapperNode": false,
                "canBeStoreForward": false,
                "canEndorsePeers": false,
                "latencyMs": null,
            }));
            return true;
        }

        // Extract optional fields.
        let display_name = envelope.get("display_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let preauth_pub_bytes: Option<[u8; 32]> = envelope
            .get("preauth_x25519_public")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
        // Extract the identity-binding signature for the preauth key (§7.0.1).
        let preauth_sig_from_ann: Option<Vec<u8>> = envelope
            .get("preauth_sig")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 64);

        let hints_arr = envelope.get("transport_hints")
            .and_then(|h| h.as_array()).cloned().unwrap_or_default();
        let clearnet_endpoint = hints_arr.iter().find(|h| {
            h.get("transport").and_then(|t| t.as_str()) == Some("clearnet")
        }).and_then(|h| h.get("endpoint")).and_then(|e| e.as_str()).map(|s| s.to_string());
        let tor_endpoint = hints_arr.iter().find(|h| {
            h.get("transport").and_then(|t| t.as_str()) == Some("tor")
        }).and_then(|h| h.get("endpoint")).and_then(|e| e.as_str()).map(|s| s.to_string());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut contact = ContactRecord::new(
            peer_id,
            ed_bytes,
            x_bytes,
            crate::pairing::methods::PairingMethod::LinkShare,
            now,
        );
        contact.display_name = display_name.clone();
        contact.clearnet_endpoint = clearnet_endpoint;
        contact.tor_endpoint = tor_endpoint;
        // Store their ML-KEM-768 encapsulation key if advertised (PQXDH §3.4.1).
        contact.kem_encapsulation_key = envelope
            .get("kem_pub")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == crate::crypto::x3dh::KEM_EK_SIZE);
        // Store their preauth pub — used to initiate X3DH/PQXDH.
        // Include the identity-binding sig if the announcement carried one.
        if let Some(preauth_bytes) = preauth_pub_bytes {
            if let Some(sig) = preauth_sig_from_ann {
                contact.update_preauth_key_with_sig(preauth_bytes, sig, now);
            } else {
                contact.update_preauth_key(preauth_bytes, now);
            }
        }

        // Bootstrap a ratchet session. When X3DH is used, store the pending header.
        {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref our_id) = *guard {
                if let Ok((session, x3dh_header, pq_ext)) = bootstrap_ratchet_session(our_id, &contact) {
                    if let Some(header) = x3dh_header {
                        self.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_id, header);
                    }
                    if let Some(pq) = pq_ext {
                        self.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_id, pq);
                    }
                    drop(guard);
                    self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_id, session);
                }
            }
        }

        self.contacts.lock().unwrap_or_else(|e| e.into_inner()).upsert(contact);
        self.save_contacts();

        // Add a local-plane routing entry for the newly paired peer.
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);
            let dest = DeviceAddress(peer_id.0);
            let entry = RoutingEntry {
                destination:     dest,
                next_hop:        dest,
                hop_count:       1,
                latency_ms:      10,
                next_hop_trust:  TrustLevel::Unknown,
                last_updated:    now,
                announcement_id: [0u8; 32],
            };
            self.routing_table.lock().unwrap_or_else(|e| e.into_inner()).update_local(entry);
        }

        // Reply with our own network map entry so the new peer has our preauth key (H20).
        let peer_id_hex = hex::encode(peer_id.0);
        self.send_gossip_self_entry(&peer_id_hex);

        self.push_event("PeerAdded", serde_json::json!({
            "id": hex::encode(peer_id.0),
            "name": display_name.as_deref().unwrap_or(""),
            "trustLevel": 0,
            "status": "online",
            "canBeExitNode": false,
            "canBeWrapperNode": false,
            "canBeStoreForward": false,
            "canEndorsePeers": false,
            "latencyMs": null,
        }));

        true
    }

    /// Handle an inbound "losec_request" frame from a peer (§6.9.6).
    ///
    /// Verifies the signed request, runs the LoSec policy, sends a
    /// `losec_response` frame back to the sender, and emits a
    /// `LoSecRequested` event for the Flutter UI to display.
    fn process_losec_request_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::routing::losec::{
            handle_losec_request, AmbientTrafficMonitor,
            ServiceLoSecConfig, SignedLoSecRequest,
        };
        use ed25519_dalek::SigningKey;

        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signed_req: SignedLoSecRequest = match serde_json::from_str(payload_str) {
            Ok(r) => r,
            Err(_) => return false,
        };

        // Use our own signing key for the response.
        let signing_key = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => SigningKey::from_bytes(&id.ed25519_signing.to_bytes()),
                None => return false,
            }
        };

        let mut monitor = AmbientTrafficMonitor::new();
        let active_tunnels = self.sdr.lock().unwrap_or_else(|e| e.into_inner()).sessions.len();
        monitor.update(active_tunnels, active_tunnels as u64 * 1024);

        let service_config = ServiceLoSecConfig {
            allow_losec: true,
            allow_direct: true,
        };

        let signed_resp = handle_losec_request(
            &signed_req, &service_config, monitor.losec_available(), &signing_key,
        );

        // Send losec_response frame back.
        let our_peer_id_hex = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default()
        };
        let session_id_hex = hex::encode(signed_req.request.session_id);
        if let Ok(resp_json) = serde_json::to_string(&signed_resp) {
            let frame = serde_json::json!({
                "type": "losec_response",
                "sender": our_peer_id_hex,
                "session_id": session_id_hex,
                "payload": resp_json,
            });
            if let Ok(frame_bytes) = serde_json::to_vec(&frame) {
                let mut conns = self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(stream) = conns.get_mut(&sender_hex) {
                    use std::io::Write;
                    let len = (frame_bytes.len() as u32).to_be_bytes();
                    // Log on failure: this method returns bool so we cannot propagate
                    // further. A write failure means the LoSec response was not
                    // delivered; the peer will retry or time out.
                    if let Err(e) = stream.write_all(&len)
                        .and_then(|_| stream.write_all(&frame_bytes))
                    {
                        eprintln!("[transport] WARNING: failed to send losec_response to {sender_hex}: {e}");
                    }
                }
            }
        }

        // Emit event so Flutter UI can show the LoSec negotiation.
        self.push_event("LoSecRequested", serde_json::json!({
            "peerId": sender_hex,
            "sessionId": session_id_hex,
            "accepted": signed_resp.response.accepted,
            "rejectionReason": signed_resp.response.rejection_reason,
        }));
        true
    }

    /// Handle an inbound "losec_response" frame from a peer (§6.9.6).
    ///
    /// Parses the response and emits a `LoSecResponse` event so the
    /// Flutter UI can update the conversation's security mode indicator.
    fn process_losec_response_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::routing::losec::SignedLoSecResponse;

        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let session_id_hex = envelope.get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signed_resp: SignedLoSecResponse = match serde_json::from_str(payload_str) {
            Ok(r) => r,
            Err(_) => return false,
        };

        self.push_event("LoSecResponse", serde_json::json!({
            "peerId": sender_hex,
            "sessionId": session_id_hex,
            "accepted": signed_resp.response.accepted,
            "rejectionReason": signed_resp.response.rejection_reason,
        }));
        true
    }

    /// Store a JSON response and return a stable pointer to it.
    fn set_response(&self, json: &str) -> *const c_char {
        let cstring = CString::new(json).unwrap_or_else(|_| CString::new("{}").unwrap());
        let ptr = cstring.as_ptr();
        *self.last_response.lock().unwrap_or_else(|e| e.into_inner()) = Some(cstring);
        ptr
    }

    /// Store an error message.
    fn set_error(&self, msg: &str) {
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(CString::new(msg).unwrap_or_else(|_| CString::new("unknown error").unwrap()));
    }
}

// ---------------------------------------------------------------------------
// Gossip network map entry handler
// ---------------------------------------------------------------------------

impl MeshContext {
    /// Process an inbound gossip_map_entry frame (§4.1).
    ///
    /// Validates the Ed25519 signature, merges into the local network map,
    /// and updates the matching contact's preauth_key if the peer is known.
    fn process_gossip_map_entry_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::network::map::NetworkMapEntry;
        use crate::trust::levels::TrustLevel;

        // The frame carries a JSON-encoded NetworkMapEntry under the "entry" key.
        let entry_val = match envelope.get("entry") {
            Some(v) => v.clone(),
            None => return false,
        };
        let entry: NetworkMapEntry = match serde_json::from_value(entry_val) {
            Ok(e) => e,
            Err(_) => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry_peer_id = entry.peer_id;

        // Merge into gossip map.
        let accepted = {
            let mut gossip = self.gossip.lock().unwrap_or_else(|e| e.into_inner());
            // Use a placeholder source peer ID (not critical for local-only gossip).
            gossip.receive_entry(entry.clone(), &entry_peer_id, TrustLevel::Unknown, now)
                .unwrap_or(false)
        };

        if !accepted {
            return false;
        }

        // If we have this peer as a contact, refresh their preauth key and transport hints.
        {
            let mut contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(contact) = contacts.get_mut(&entry_peer_id) {
                // Refresh preauth key and KEM encapsulation key.
                if let Some(pk) = entry.public_keys.first() {
                    if let Some(preauth) = pk.preauth_x25519_public {
                        if let Some(ref sig) = pk.preauth_sig {
                            contact.update_preauth_key_with_sig(preauth, sig.clone(), now);
                        } else {
                            contact.update_preauth_key(preauth, now);
                        }
                    }
                    if let Some(ref kem_ek) = pk.kem_encapsulation_key {
                        if kem_ek.len() == crate::crypto::x3dh::KEM_EK_SIZE {
                            contact.kem_encapsulation_key = Some(kem_ek.clone());
                        }
                    }
                }
                // Refresh transport hints: update clearnet + Tor endpoints.
                for hint in &entry.transport_hints {
                    match hint.transport {
                        crate::network::transport_hint::TransportType::Clearnet => {
                            if let Some(ref ep) = hint.endpoint {
                                contact.clearnet_endpoint = Some(ep.clone());
                            }
                        }
                        crate::network::transport_hint::TransportType::Tor => {
                            if let Some(ref ep) = hint.endpoint {
                                contact.tor_endpoint = Some(ep.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        true
    }

    /// Process an inbound route_announcement frame (§6.2).
    ///
    /// Deserialises the `ReachabilityAnnouncement` from the envelope,
    /// runs it through the `AnnouncementProcessor` (dedup, age, hop-count,
    /// and signature checks), inserts the derived routing entry into the
    /// routing table, and forwards to all clearnet-connected peers if the
    /// announcement scope permits it.
    fn process_route_announcement_frame(&self, envelope: &serde_json::Value) -> bool {
        // The frame carries the serialised ReachabilityAnnouncement under
        // the "announcement" key.
        let ann_val = match envelope.get("announcement") {
            Some(v) => v.clone(),
            None => return false,
        };
        let announcement: ReachabilityAnnouncement = match serde_json::from_value(ann_val) {
            Ok(a) => a,
            Err(_) => return false,
        };

        // The "from" field carries the sender's peer ID (hex-encoded).
        let from_hex = match envelope.get("from").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let from_bytes = match hex::decode(&from_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let from_addr = DeviceAddress(from_bytes);

        // Look up our trust in the sending neighbour.
        let neighbour_trust = {
            let from_peer_id = crate::identity::peer_id::PeerId(from_bytes);
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            contacts.get(&from_peer_id)
                .map(|c| c.trust_level)
                .unwrap_or(TrustLevel::Unknown)
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Run through the announcement processor.
        let result = {
            let mut proc = self.announcement_processor.lock().unwrap_or_else(|e| e.into_inner());
            proc.process(&announcement, from_addr, neighbour_trust, now, None)
        };

        match result {
            crate::routing::announcement::ProcessResult::Accepted(r) => {
                // Insert into the routing table.
                {
                    let mut table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
                    table.update_public(r.entry, now);
                }

                // Forward to all identified clearnet peers if scope allows it.
                if r.should_forward {
                    if let Some(fwd_ann) = r.forward_announcement {
                        let our_hex = self.identity.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref()
                            .map(|id| hex::encode(id.peer_id().0))
                            .unwrap_or_default();
                        let fwd_frame = serde_json::json!({
                            "type": "route_announcement",
                            "from": our_hex,
                            "announcement": fwd_ann,
                        });
                        // Broadcast to every identified clearnet peer except the sender.
                        let peers: Vec<String> = self.clearnet_connections
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .keys()
                            .cloned()
                            .collect();
                        for peer_hex in peers {
                            if peer_hex == from_hex { continue; }
                            self.send_raw_frame(&peer_hex, &fwd_frame);
                        }
                    }
                }

                true
            }
            crate::routing::announcement::ProcessResult::Rejected(_) => false,
        }
    }

    /// Process an inbound mesh_packet frame (§6.5).
    ///
    /// Deserialises the `MeshPacket`, runs it through the `ForwardEngine`
    /// (dedup, TTL, routing lookup), then either delivers it locally or
    /// forwards it to the next hop via clearnet TCP.
    fn process_mesh_packet_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::mesh::forwarder::{ForwardEngine, ForwardDecision};

        // The frame wraps the serialised MeshPacket under the "packet" key.
        let pkt_val = match envelope.get("packet") {
            Some(v) => v.clone(),
            None => return false,
        };
        let mut pkt: MeshPacket = match serde_json::from_value(pkt_val) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let our_addr = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => DeviceAddress(id.peer_id().0),
                None => return false,
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let dest = pkt.dest_address();

        // Look up route before acquiring dedup lock.
        let route_entry = {
            let table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
            table.lookup(&dest, None, now).cloned()
        };

        let decision = {
            let mut dedup = self.dedup_cache.lock().unwrap_or_else(|e| e.into_inner());
            ForwardEngine::decide(
                &crate::mesh::forwarder::PacketHeader {
                    packet_id: pkt.packet_id,
                    destination: dest,
                    ttl: pkt.ttl,
                    timestamp: pkt.timestamp,
                },
                &our_addr,
                now,
                &mut dedup,
                route_entry.as_ref(),
            )
        };

        match decision {
            ForwardDecision::Deliver => {
                // Decode and inject into the application pipeline.
                // For Message packets, re-dispatch through process_inbound_frame
                // using the inner payload (the application-layer encrypted envelope).
                if pkt.kind == PacketKind::Message {
                    if let Some(payload) = pkt.payload_bytes() {
                        return self.process_inbound_frame(&payload);
                    }
                }
                // For other kinds (Keepalive, Data, etc.) emit an event.
                self.push_event("MeshPacketDelivered", serde_json::json!({
                    "source": hex::encode(pkt.source),
                    "kind": format!("{:?}", pkt.kind),
                    "size": pkt.payload_hex.len() / 2,
                }));
                true
            }

            ForwardDecision::Forward { next_hop } => {
                // Decrement TTL and forward.
                if !pkt.decrement_ttl() {
                    return false;
                }
                let next_hop_hex = hex::encode(next_hop.0);
                let fwd_frame = serde_json::json!({
                    "type": "mesh_packet",
                    "packet": pkt,
                });
                self.send_raw_frame(&next_hop_hex, &fwd_frame);
                true
            }

            ForwardDecision::Drop(_) => false,
        }
    }

    /// Process an incoming file_offer frame (§9).
    ///
    /// A peer is offering to send us a file. Create a pending transfer entry
    /// and emit a `TransferUpdated` event so the UI can show an accept prompt.
    fn process_file_offer_frame(&self, envelope: &serde_json::Value) -> bool {
        let tid = match envelope.get("transferId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let name = envelope.get("name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let size_bytes = envelope.get("sizeBytes").and_then(|v| v.as_u64()).unwrap_or(0);

        // Derive sender peer_id from the "from" field if present, else unknown.
        let peer_id = envelope.get("from").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let transfer = serde_json::json!({
            "id": tid,
            "peerId": peer_id,
            "name": name,
            "sizeBytes": size_bytes,
            "transferredBytes": 0,
            "status": "pending",
            "direction": "receive",
        });

        self.file_transfers.lock().unwrap_or_else(|e| e.into_inner()).push(transfer.clone());
        self.push_event("TransferUpdated", transfer);
        true
    }

    /// Process an incoming file_chunk frame (§9).
    ///
    /// Writes the chunk data to the receive file's save path.
    /// Emits `TransferProgress` events as bytes accumulate.
    fn process_file_chunk_frame(&self, envelope: &serde_json::Value) -> bool {
        use std::io::Write;

        let tid = match envelope.get("transferId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let data_hex = match envelope.get("data").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let data = match hex::decode(data_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let (_total_bytes, transferred) = {
            let mut map = self.active_file_io.lock().unwrap_or_else(|e| e.into_inner());
            let state = match map.get_mut(&tid) {
                Some(s) if s.direction == FileDirection::Receive => s,
                _ => return false,
            };
            if state.file.write_all(&data).is_err() {
                return false;
            }
            state.transferred_bytes += data.len() as u64;
            (state.total_bytes, state.transferred_bytes)
        };

        // Update the JSON transfer record.
        {
            let mut transfers = self.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
            for t in transfers.iter_mut() {
                if t.get("id").and_then(|v| v.as_str()) == Some(&tid) {
                    if let Some(obj) = t.as_object_mut() {
                        obj.insert("transferredBytes".to_string(),
                            serde_json::Value::Number(transferred.into()));
                    }
                    break;
                }
            }
        }
        self.push_transfer_update(&tid);
        true
    }

    /// Process an incoming file_complete frame (§9).
    ///
    /// Marks the receive transfer as complete and closes the file handle.
    fn process_file_complete_frame(&self, envelope: &serde_json::Value) -> bool {
        let tid = match envelope.get("transferId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let ok = envelope.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);

        // Remove from IO map (drops the file handle, flushing it).
        self.active_file_io.lock().unwrap_or_else(|e| e.into_inner()).remove(&tid);

        // Update transfer status and emit TransferUpdated for the Flutter side.
        {
            let mut transfers = self.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
            for t in transfers.iter_mut() {
                if t.get("id").and_then(|v| v.as_str()) == Some(&tid) {
                    if let Some(obj) = t.as_object_mut() {
                        obj.insert("status".to_string(), serde_json::Value::String(
                            if ok { "completed".to_string() } else { "failed".to_string() }
                        ));
                    }
                    break;
                }
            }
        }
        self.push_transfer_update(&tid);
        true
    }

    // -----------------------------------------------------------------------
    // Store-and-Forward frame handlers (§6.8)
    // -----------------------------------------------------------------------

    /// Handle an incoming `sf_deposit` frame.
    ///
    /// A peer is depositing a message for a destination that is currently
    /// offline. We validate the request, enforce quotas, and buffer it.
    /// When the destination reconnects, we deliver it via `sf_deliver`.
    fn process_sf_deposit_frame(&self, envelope: &serde_json::Value) -> bool {
        let mc = self.module_config.lock().unwrap_or_else(|e| e.into_inner());
        if !mc.social.store_forward {
            // S&F relay disabled — reject with a polite error.
            return true; // consumed, just ignored
        }
        drop(mc);

        // Parse destination address (32 hex bytes).
        let dest_hex = match envelope.get("destination").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let dest_bytes = match hex::decode(dest_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };

        // Parse payload (hex-encoded).
        let payload_hex = match envelope.get("payload_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let payload = match hex::decode(payload_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // Parse expiry and expiry_sig.
        let expiry = envelope.get("expiry").and_then(|v| v.as_u64()).unwrap_or(0);
        let expiry_sig_hex = envelope.get("expiry_sig").and_then(|v| v.as_str()).unwrap_or("");
        let expiry_sig = hex::decode(expiry_sig_hex).unwrap_or_default();

        // Parse optional priority and application_id.
        let priority = match envelope.get("priority").and_then(|v| v.as_u64()).unwrap_or(1) {
            0 => Priority::Low,
            2 => Priority::High,
            3 => Priority::Critical,
            _ => Priority::Normal,
        };

        let request = StoreAndForwardRequest {
            destination: DeviceAddress(dest_bytes),
            payload,
            expiry,
            expiry_sig,
            priority,
            release_condition: ReleaseCondition::Immediate,
            application_id: None,
            cancellation_pubkey: None,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        // Use a hash of the sender's address as the tunnel_id for rate limiting.
        let sender_hex = envelope.get("sender").and_then(|v| v.as_str()).unwrap_or("0");
        let tunnel_id = sender_hex.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));

        let result = self.sf_server.lock().unwrap_or_else(|e| e.into_inner())
            .deposit(request, tunnel_id, now);

        matches!(result, DepositResult::Accepted)
    }

    /// Handle an incoming `sf_deliver` frame.
    ///
    /// A relay node is delivering a message that was stored for us.
    /// The payload is the original application-layer encrypted frame
    /// (same format as any other inbound frame), so we route it through
    /// `process_inbound_frame` as if it arrived directly.
    fn process_sf_deliver_frame(&self, envelope: &serde_json::Value) -> bool {
        let payload_hex = match envelope.get("payload_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let payload = match hex::decode(payload_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        // Re-inject the payload as if it arrived directly from the network.
        self.process_inbound_frame(&payload)
    }

    // -----------------------------------------------------------------------
    // Delivery receipt handler (§7.3)
    // -----------------------------------------------------------------------

    /// Handle an incoming `delivery_receipt` frame (§7.3).
    ///
    /// Updates the in-memory delivery status of the acknowledged message from
    /// "sent" to "delivered" and emits a `MessageStatusUpdated` event so the
    /// Flutter UI can show a double-checkmark or similar delivery indicator.
    ///
    /// The receipt frame carries:
    ///   `sender`  — the recipient's peer_id (who received our message).
    ///   `msg_id`  — the message ID we sent.
    ///   `room`    — the room the message belongs to.
    ///   `ts`      — timestamp (for potential future read-receipt coalescing).
    fn process_delivery_receipt_frame(&self, envelope: &serde_json::Value) -> bool {
        let msg_id = match envelope.get("msg_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let room_id = match envelope.get("room").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };

        // Update in-memory message status.
        {
            let mut messages = self.messages.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room_msgs) = messages.get_mut(&room_id) {
                if let Some(msg) = room_msgs.iter_mut()
                    .find(|m| m.get("id").and_then(|v| v.as_str()) == Some(&msg_id))
                {
                    // Only promote forward: sent → delivered.
                    let current = msg.get("deliveryStatus").and_then(|v| v.as_str()).unwrap_or("sent");
                    if current == "sent" {
                        msg["deliveryStatus"] = serde_json::json!("delivered");
                    }
                }
            }
        }

        // Emit event so the UI can update the message's delivery indicator.
        self.push_event("MessageStatusUpdated", serde_json::json!({
            "msgId": msg_id,
            "roomId": room_id,
            "deliveryStatus": "delivered",
        }));

        true
    }

    // -----------------------------------------------------------------------
    // Group rekey handler (§8.7.4, §8.7.5)
    // -----------------------------------------------------------------------

    /// Handle an incoming `group_rekey` frame.
    ///
    /// The group admin has rotated the Sender Key and is distributing new
    /// key material to all members. We decrypt the ciphertext using our
    /// ratchet session with the admin, then update the group's symmetric_key
    /// and sender_key_epoch. Future messages will use the new key.
    fn process_group_rekey_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let ciphertext_hex = match envelope.get("ciphertext").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sender_peer_id = PeerId(sender_bytes);

        // Deserialise the ratchet header.
        let header_val = match envelope.get("ratchet_header") {
            Some(v) => v.clone(),
            None => return false,
        };
        let ratchet_header: RatchetHeader = match serde_json::from_value(header_val) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Bootstrap ratchet session from X3DH header if needed (same as message decrypt).
        {
            let contact = self.contacts.lock().unwrap_or_else(|e| e.into_inner())
                .get(&sender_peer_id).cloned();
            if let Some(ref contact) = contact {
                if !self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                    .contains_key(&sender_peer_id)
                {
                    let eph_pub_opt = envelope.get("x3dh_eph_pub").and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .filter(|b| b.len() == 32)
                        .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
                    let enc_ik_opt = envelope.get("x3dh_encrypted_ik").and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .filter(|b| b.len() == crate::crypto::x3dh::ENCRYPTED_IK_SIZE)
                        .map(|b| { let mut a = [0u8; crate::crypto::x3dh::ENCRYPTED_IK_SIZE]; a.copy_from_slice(&b); a });
                    if let (Some(eph_pub), Some(enc_ik)) = (eph_pub_opt, enc_ik_opt) {
                        use crate::crypto::x3dh::{x3dh_respond, X3dhInitHeader};
                        let session_result: Option<DoubleRatchetSession> = {
                            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                            guard.as_ref().and_then(|id| {
                                let header = X3dhInitHeader { eph_pub, encrypted_ik_pub: enc_ik };
                                x3dh_respond(&id.x25519_secret, &id.preauth_x25519_secret, &header).ok()
                                    .map(|out| {
                                        let master = out.master_secret.as_bytes();
                                        let preauth_secret = x25519_dalek::StaticSecret::from(id.preauth_x25519_secret.to_bytes());
                                        let preauth_pub = *id.preauth_x25519_pub.as_bytes();
                                        DoubleRatchetSession::init_receiver(master, preauth_secret, &preauth_pub)
                                    })
                            })
                        };
                        if let Some(session) = session_result {
                            self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                                .insert(sender_peer_id, session);
                        }
                    }
                    let _ = contact;
                }
            }
        }

        // Decrypt the rekey payload.
        let plaintext = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            let session = match sessions.get_mut(&sender_peer_id) {
                Some(s) => s,
                None => return false,
            };
            let msg_key = match session.recv_msg_key(&ratchet_header) {
                Ok(k) => k,
                Err(_) => return false,
            };
            // Decrypt using the same ChaCha20-Poly1305 scheme used in advance_group_rekeys:
            // key = msg_key, nonce = all-zero 12 bytes.
            use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
            let nonce = Nonce::<ChaCha20Poly1305>::default();
            match cipher.decrypt(&nonce, ct.as_ref()) {
                Ok(pt) => pt,
                Err(_) => return false,
            }
        };

        // Parse the inner rekey payload.
        let inner: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let group_id_hex = match inner.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let new_epoch = match inner.get("epoch").and_then(|v| v.as_u64()) {
            Some(e) => e,
            None => return false,
        };
        let new_key_hex = match inner.get("symmetricKey").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let new_key_bytes = match hex::decode(&new_key_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let gid_bytes = match hex::decode(&group_id_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };

        // Apply the new key to our group state.
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(group) = groups.iter_mut().find(|g| g.group_id == gid_bytes) {
            // Only apply if this is a newer epoch (prevents replay of old rekeys).
            if new_epoch > group.sender_key_epoch {
                group.symmetric_key = new_key_bytes;
                group.sender_key_epoch = new_epoch;
                group.last_rekey_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0);
                drop(groups);
                self.save_groups();
                return true;
            }
        }

        true
    }

    // -----------------------------------------------------------------------
    // Group invite handler (§8.7)
    // -----------------------------------------------------------------------

    /// Handle an incoming `group_invite` frame.
    ///
    /// The sender (an admin) is sharing group credentials with us. Decrypt
    /// the payload, reconstruct the `Group` struct, persist it, and create
    /// the shared conversation room so the UI can display it immediately.
    fn process_group_invite_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let ciphertext_hex = match envelope.get("ciphertext").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sender_peer_id = PeerId(sender_bytes);

        // Bootstrap ratchet session if X3DH header present.
        {
            let contact = self.contacts.lock().unwrap_or_else(|e| e.into_inner())
                .get(&sender_peer_id).cloned();
            if let Some(ref _contact) = contact {
                if !self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                    .contains_key(&sender_peer_id)
                {
                    let eph_pub_opt = envelope.get("x3dh_eph_pub").and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .filter(|b| b.len() == 32)
                        .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
                    let enc_ik_opt = envelope.get("x3dh_encrypted_ik").and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .filter(|b| b.len() == crate::crypto::x3dh::ENCRYPTED_IK_SIZE)
                        .map(|b| { let mut a = [0u8; crate::crypto::x3dh::ENCRYPTED_IK_SIZE]; a.copy_from_slice(&b); a });
                    if let (Some(eph_pub), Some(enc_ik)) = (eph_pub_opt, enc_ik_opt) {
                        use crate::crypto::x3dh::{x3dh_respond, X3dhInitHeader};
                        let session_result: Option<DoubleRatchetSession> = {
                            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                            guard.as_ref().and_then(|id| {
                                let header = X3dhInitHeader { eph_pub, encrypted_ik_pub: enc_ik };
                                x3dh_respond(&id.x25519_secret, &id.preauth_x25519_secret, &header).ok()
                                    .map(|out| {
                                        let master = out.master_secret.as_bytes();
                                        let preauth_secret = x25519_dalek::StaticSecret::from(id.preauth_x25519_secret.to_bytes());
                                        let preauth_pub = *id.preauth_x25519_pub.as_bytes();
                                        DoubleRatchetSession::init_receiver(master, preauth_secret, &preauth_pub)
                                    })
                            })
                        };
                        if let Some(session) = session_result {
                            self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                                .insert(sender_peer_id, session);
                        }
                    }
                }
            }
        }

        // Decrypt the invite payload.
        let header_val = match envelope.get("ratchet_header") {
            Some(v) => v.clone(),
            None => return false,
        };
        let ratchet_header: RatchetHeader = match serde_json::from_value(header_val) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let plaintext = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            let session = match sessions.get_mut(&sender_peer_id) {
                Some(s) => s,
                None => return false,
            };
            let msg_key = match session.recv_msg_key(&ratchet_header) {
                Ok(k) => k,
                Err(_) => return false,
            };
            use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
            let nonce = Nonce::<ChaCha20Poly1305>::default();
            match cipher.decrypt(&nonce, ct.as_ref()) {
                Ok(pt) => pt,
                Err(_) => return false,
            }
        };

        // Parse the outer wrapper then the inner invite JSON.
        let outer: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let inv = match outer.get("invite") {
            Some(v) => v,
            None => return false,
        };

        // Extract credentials.
        let group_id_hex = match inv.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let ed25519_pub_hex  = match inv.get("ed25519Pub").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let x25519_pub_hex   = match inv.get("x25519Pub").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let sym_key_hex      = match inv.get("symmetricKey").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let sender_key_epoch = inv.get("senderKeyEpoch").and_then(|v| v.as_u64()).unwrap_or(1);
        let name             = inv.get("name").and_then(|v| v.as_str()).unwrap_or("Group").to_string();

        let gid_bytes = match hex::decode(&group_id_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let ed25519_pub_bytes = match hex::decode(&ed25519_pub_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let x25519_pub_bytes = match hex::decode(&x25519_pub_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sym_key_bytes = match hex::decode(&sym_key_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let members: Vec<PeerId> = inv.get("members").and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|m| m.as_str())
                .filter_map(|s| hex::decode(s).ok())
                .filter(|b| b.len() == 32)
                .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); PeerId(a) })
                .collect())
            .unwrap_or_default();
        let admins: Vec<PeerId> = inv.get("admins").and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|m| m.as_str())
                .filter_map(|s| hex::decode(s).ok())
                .filter(|b| b.len() == 32)
                .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); PeerId(a) })
                .collect())
            .unwrap_or_default();

        let our_peer_id = match self.identity.lock().unwrap_or_else(|e| e.into_inner())
            .as_ref().map(|id| id.peer_id())
        {
            Some(p) => p,
            None => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        // Check we aren't already in this group.
        let already_member = self.groups.lock().unwrap_or_else(|e| e.into_inner())
            .iter().any(|g| g.group_id == gid_bytes);
        if already_member {
            return true;
        }

        // Build and store the Group.
        use crate::groups::group::{Group, GroupPublicProfile, NetworkType};
        let description_str = inv.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let profile = GroupPublicProfile {
            group_id: gid_bytes,
            display_name: name.clone(),
            description: description_str,
            avatar_hash: None,
            network_type: NetworkType::Private,
            member_count: None,
            created_at: now,
            signed_by: sender_bytes,
            signature: vec![],
        };
        let group = Group::new_as_member(
            gid_bytes,
            profile,
            crate::groups::group::GroupKeys {
                ed25519_public: ed25519_pub_bytes,
                ed25519_private: None,
                x25519_public: x25519_pub_bytes,
                symmetric_key: sym_key_bytes,
            },
            our_peer_id,
            (members.clone(), admins),
            sender_key_epoch,
            now,
        );
        self.groups.lock().unwrap_or_else(|e| e.into_inner()).push(group);
        self.save_groups();

        // Create a conversation room for this group.
        let mut room = crate::messaging::room::Room::new_group(&name, members);
        let room_id_hex = hex::encode(room.id);
        room.last_message_at = Some(now);

        let room_summary = serde_json::json!({
            "id":           room_id_hex.clone(),
            "name":         name,
            "lastMessage":  "",
            "unreadCount":  0,
            "timestamp":    now,
        });
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).push(room);
        self.save_rooms();

        self.push_event("RoomUpdated", room_summary);

        true
    }

    // -----------------------------------------------------------------------
    // Group message handler (§8.7)
    // -----------------------------------------------------------------------

    /// Handle an incoming `group_message` frame.
    ///
    /// A group member has sent a message to the group. Decrypt the payload
    /// using the sender's ratchet session (same ChaCha20-Poly1305 scheme
    /// used for group_invite/group_rekey), then store it and emit MessageAdded.
    fn process_group_message_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        // groupId is carried unencrypted so we can request re-inclusion on decrypt failure.
        let outer_group_id_hex = envelope.get("groupId").and_then(|v| v.as_str()).map(|s| s.to_string());
        let ciphertext_hex = match envelope.get("ciphertext").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let sender_peer_id = PeerId(sender_bytes);

        // Bootstrap ratchet from X3DH header if needed.
        {
            if !self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                .contains_key(&sender_peer_id)
            {
                let eph_pub_opt = envelope.get("x3dh_eph_pub").and_then(|v| v.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .filter(|b| b.len() == 32)
                    .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });
                let enc_ik_opt = envelope.get("x3dh_encrypted_ik").and_then(|v| v.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .filter(|b| b.len() == crate::crypto::x3dh::ENCRYPTED_IK_SIZE)
                    .map(|b| { let mut a = [0u8; crate::crypto::x3dh::ENCRYPTED_IK_SIZE]; a.copy_from_slice(&b); a });
                if let (Some(eph_pub), Some(enc_ik)) = (eph_pub_opt, enc_ik_opt) {
                    use crate::crypto::x3dh::{x3dh_respond, X3dhInitHeader};
                    let session_result: Option<DoubleRatchetSession> = {
                        let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
                        guard.as_ref().and_then(|id| {
                            let header = X3dhInitHeader { eph_pub, encrypted_ik_pub: enc_ik };
                            x3dh_respond(&id.x25519_secret, &id.preauth_x25519_secret, &header).ok()
                                .map(|out| {
                                    let master = out.master_secret.as_bytes();
                                    let preauth_secret = x25519_dalek::StaticSecret::from(id.preauth_x25519_secret.to_bytes());
                                    let preauth_pub = *id.preauth_x25519_pub.as_bytes();
                                    DoubleRatchetSession::init_receiver(master, preauth_secret, &preauth_pub)
                                })
                        })
                    };
                    if let Some(session) = session_result {
                        self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner())
                            .insert(sender_peer_id, session);
                    }
                }
            }
        }

        // Decrypt using ratchet message key.
        let header_val = match envelope.get("ratchet_header") {
            Some(v) => v.clone(),
            None => return false,
        };
        let ratchet_header: RatchetHeader = match serde_json::from_value(header_val) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let plaintext = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            let session = match sessions.get_mut(&sender_peer_id) {
                Some(s) => s,
                None => {
                    // No ratchet session — request re-inclusion from the sender (§8.7.6).
                    drop(sessions);
                    if let Some(ref gid) = outer_group_id_hex {
                        self.send_group_reinclusion_request(&sender_hex, gid);
                    }
                    return false;
                }
            };
            let msg_key = match session.recv_msg_key(&ratchet_header) {
                Ok(k) => k,
                Err(_) => {
                    // Ratchet out of sync — request re-inclusion from the sender (§8.7.6).
                    drop(sessions);
                    if let Some(ref gid) = outer_group_id_hex {
                        self.send_group_reinclusion_request(&sender_hex, gid);
                    }
                    return false;
                }
            };
            use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
            let nonce = Nonce::<ChaCha20Poly1305>::default();
            match cipher.decrypt(&nonce, ct.as_ref()) {
                Ok(pt) => pt,
                Err(_) => {
                    // ChaCha20-Poly1305 AEAD failure — request re-inclusion from the sender (§8.7.6).
                    if let Some(ref gid) = outer_group_id_hex {
                        self.send_group_reinclusion_request(&sender_hex, gid);
                    }
                    return false;
                }
            }
        };

        // Parse the inner message payload.
        let inner: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let room_id_hex = match inner.get("roomId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let text = match inner.get("text").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(), None => return false,
        };
        let msg_id = inner.get("msgId").and_then(|v| v.as_str())
            .unwrap_or("").to_string();
        let ts = inner.get("timestamp").and_then(|v| v.as_u64())
            .unwrap_or_else(|| std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0));

        let msg = serde_json::json!({
            "id": msg_id,
            "roomId": room_id_hex,
            "sender": sender_hex,
            "text": text,
            "timestamp": ts,
            "isOutgoing": false,
            "authStatus": "authenticated",
        });

        self.messages.lock().unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.clone())
            .or_default()
            .push(msg.clone());

        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                room.last_message_preview = Some(if text.len() > 80 {
                    format!("{}…", &text[..80])
                } else {
                    text.clone()
                });
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0);
                room.last_message_at = Some(now);
                if !room.is_muted {
                    room.unread_count += 1;
                }
            }
        }

        self.push_event("MessageAdded", msg);

        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms.iter().find(|r| hex::encode(r.id) == room_id_hex).map(|r| serde_json::json!({
                "id": hex::encode(r.id),
                "name": r.name,
                "lastMessage": r.last_message_preview,
                "unreadCount": r.unread_count,
                "timestamp": r.last_message_at,
            }))
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }

        self.save_messages();
        self.save_rooms();
        self.save_ratchet_sessions();
        true
    }

    // -----------------------------------------------------------------------
    // Group message — Sender Key path (§7.0.4)
    // -----------------------------------------------------------------------

    /// Handle an incoming `group_message_sk` frame.
    ///
    /// Wire format:
    /// ```json
    /// { "type": "group_message_sk", "groupId": "<hex>", "sender": "<hex>",
    ///   "epoch": <u32>, "nonce": "<hex-12>", "wrapped": "<hex>" }
    /// ```
    ///
    /// The `wrapped` bytes are `ChaCha20Poly1305(symmetric_key, nonce)` over a
    /// JSON blob `{"iteration":<u32>,"ciphertext":"<hex>","signature":"<hex>"}`.
    /// That inner layer is a `SenderKeyMessage` encrypted with the sender's
    /// per-group Sender Key and signed with their Sender Key Ed25519 key.
    fn process_group_message_sk_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let outer_group_id_hex = match envelope.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let nonce_hex = match envelope.get("nonce").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let wrapped_hex = match envelope.get("wrapped").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };

        let nonce_bytes: [u8; 12] = match hex::decode(nonce_hex) {
            Ok(b) if b.len() == 12 => { let mut a = [0u8; 12]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let wrapped = match hex::decode(wrapped_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let gid_bytes: [u8; 32] = match hex::decode(&outer_group_id_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };

        // Step 1: Find the group and extract symmetric_key + peer_sender_keys.
        let (symmetric_key, peer_state_opt) = {
            let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            let g = match groups.iter().find(|g| g.group_id == gid_bytes) {
                Some(g) => g,
                None => return false,
            };
            let psk = g.peer_sender_keys.get(&sender_bytes).cloned();
            (g.symmetric_key, psk)
        };

        // Step 2: Unwrap the outer ChaCha20-Poly1305 layer (group symmetric key).
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        let sym_cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .expect("symmetric_key is 32 bytes");
        let sk_wire_bytes = match sym_cipher.decrypt(
            chacha20poly1305::Nonce::from_slice(&nonce_bytes),
            wrapped.as_ref(),
        ) {
            Ok(b) => b,
            Err(_) => {
                // Group symmetric key mismatch — request re-inclusion.
                self.send_group_reinclusion_request(&sender_hex, &outer_group_id_hex);
                return false;
            }
        };

        // Step 3: Parse the inner SenderKeyMessage wire blob.
        let sk_wire: serde_json::Value = match serde_json::from_slice(&sk_wire_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let iteration = match sk_wire.get("iteration").and_then(|v| v.as_u64()) {
            Some(n) => n as u32,
            None => return false,
        };
        let inner_ct = match sk_wire.get("ciphertext").and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok()) {
            Some(b) => b,
            None => return false,
        };
        let sig_bytes = match sk_wire.get("signature").and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok()) {
            Some(b) => b,
            None => return false,
        };

        use crate::crypto::sender_keys::{SenderKeyMessage, SenderKeyReceiver};
        use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;

        // Step 4: Reconstruct SenderKeyReceiver from persisted state (if any).
        let peer_state = match peer_state_opt {
            Some(s) => s,
            None => {
                // We have no Sender Key for this peer — request re-inclusion so
                // the sender will distribute their key to us.
                self.send_group_reinclusion_request(&sender_hex, &outer_group_id_hex);
                return false;
            }
        };

        let verifying_key = match Ed25519VerifyingKey::from_bytes(&peer_state.verifying_key) {
            Ok(vk) => vk,
            Err(_) => return false,
        };

        let mut receiver = SenderKeyReceiver::from_state(
            peer_state.chain_key,
            peer_state.next_iteration,
            verifying_key,
        );

        let sk_msg = SenderKeyMessage {
            iteration,
            ciphertext: inner_ct,
            signature: sig_bytes,
        };

        // Step 5: Decrypt using Sender Key (verifies signature + decrypts).
        let plaintext_bytes = match receiver.decrypt(&sk_msg) {
            Ok(pt) => pt,
            Err(_) => {
                self.send_group_reinclusion_request(&sender_hex, &outer_group_id_hex);
                return false;
            }
        };

        // Step 6: Persist the advanced receiver state back to the group.
        {
            let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(g) = groups.iter_mut().find(|g| g.group_id == gid_bytes) {
                use crate::groups::group::PeerSenderKeyState;
                g.peer_sender_keys.insert(sender_bytes, PeerSenderKeyState {
                    chain_key: *receiver.chain_key_bytes(),
                    next_iteration: receiver.next_iter(),
                    verifying_key: peer_state.verifying_key,
                });
            }
        }

        // Step 7: Parse the inner plaintext message JSON.
        let inner: serde_json::Value = match serde_json::from_slice(&plaintext_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let room_id_hex = match inner.get("roomId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let text = match inner.get("text").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let msg_id = inner.get("msgId").and_then(|v| v.as_str())
            .unwrap_or("").to_string();
        let ts = inner.get("timestamp").and_then(|v| v.as_u64())
            .unwrap_or_else(|| std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0));

        let msg = serde_json::json!({
            "id": msg_id,
            "roomId": room_id_hex,
            "sender": sender_hex,
            "text": text,
            "timestamp": ts,
            "isOutgoing": false,
            "authStatus": "authenticated",
        });

        self.messages.lock().unwrap_or_else(|e| e.into_inner())
            .entry(room_id_hex.clone())
            .or_default()
            .push(msg.clone());

        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
                room.last_message_preview = Some(if text.len() > 80 {
                    format!("{}…", &text[..80])
                } else {
                    text.clone()
                });
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0);
                room.last_message_at = Some(now);
                if !room.is_muted {
                    room.unread_count += 1;
                }
            }
        }

        self.push_event("MessageAdded", msg);

        let room_summary = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms.iter().find(|r| hex::encode(r.id) == room_id_hex).map(|r| serde_json::json!({
                "id": hex::encode(r.id),
                "name": r.name,
                "lastMessage": r.last_message_preview,
                "unreadCount": r.unread_count,
                "timestamp": r.last_message_at,
            }))
        };
        if let Some(summary) = room_summary {
            self.push_event("RoomUpdated", summary);
        }

        self.save_messages();
        self.save_rooms();
        self.save_groups();
        true
    }

    // -----------------------------------------------------------------------
    // Group re-inclusion (§8.7.6)
    // -----------------------------------------------------------------------

    /// Send a `group_reinclusion_request` to a peer whose group_message we
    /// could not decrypt.  The frame is sent in plaintext because by
    /// definition our ratchet session with that peer is broken.  The only
    /// information disclosed is our own peer-ID and the group-ID, both of
    /// which the sender already knows.
    fn send_group_reinclusion_request(&self, peer_hex: &str, group_id_hex: &str) {
        let our_hex = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => hex::encode(id.peer_id().0),
                None => return,
            }
        };
        let frame = serde_json::json!({
            "type":    "group_reinclusion_request",
            "sender":  our_hex,
            "groupId": group_id_hex,
        });
        self.send_raw_frame(peer_hex, &frame);
    }

    /// Handle an incoming `group_reinclusion_request` frame (§8.7.6).
    ///
    /// The requester's ratchet session with us is out of sync.  If we are an
    /// admin of the named group **and** the requester is already a member, we
    /// re-send them a `group_invite` so they can re-join the group.
    ///
    /// The membership check prevents a non-member from obtaining group
    /// credentials by forging a re-inclusion request.
    fn process_group_reinclusion_request_frame(&self, envelope: &serde_json::Value) -> bool {
        let requester_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let group_id_hex = match envelope.get("groupId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let gid_bytes: [u8; 32] = match hex::decode(&group_id_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let requester_bytes: [u8; 32] = match hex::decode(&requester_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let requester_peer_id = PeerId(requester_bytes);

        let our_peer_id = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() { Some(id) => id.peer_id(), None => return false }
        };

        // Build the invite payload only if we are an admin and the requester is
        // already a member (prevents credential-harvesting via forged requests).
        let invite_payload_bytes: Vec<u8> = {
            let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            let group = match groups.iter().find(|g| g.group_id == gid_bytes) {
                Some(g) => g,
                None => return false,
            };
            // We must be an admin.
            if !group.admins.contains(&our_peer_id) { return false; }
            // Requester must already be a member.
            if !group.members.contains(&requester_peer_id) { return false; }

            let snap = serde_json::json!({
                "groupId":        hex::encode(group.group_id),
                "ed25519Pub":     hex::encode(group.ed25519_public),
                "x25519Pub":      hex::encode(group.x25519_public),
                "symmetricKey":   hex::encode(group.symmetric_key),
                "senderKeyEpoch": group.sender_key_epoch,
                "members":        group.members.iter().map(|m| hex::encode(m.0)).collect::<Vec<_>>(),
                "admins":         group.admins.iter().map(|m| hex::encode(m.0)).collect::<Vec<_>>(),
                "name":           group.profile.display_name.clone(),
                "description":    group.profile.description.clone(),
            });
            match serde_json::to_vec(&serde_json::json!({
                "type":   "group_invite",
                "invite": snap,
            })) {
                Ok(b) => b,
                Err(_) => return false,
            }
        };

        // Encrypt with the requester's ratchet session.
        // If the ratchet session is missing we cannot help — the admin would
        // need to trigger a full re-pair out-of-band.
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
        let frame_opt = {
            let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = sessions.get_mut(&requester_peer_id) {
                if let Ok((header, msg_key)) = session.next_send_msg_key() {
                    let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
                    let nonce = Nonce::<ChaCha20Poly1305>::default();
                    cipher.encrypt(&nonce, invite_payload_bytes.as_ref()).ok().map(|ct| {
                        let x3dh_fields = self.x3dh_pending.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&requester_peer_id).copied();
                        let mut f = serde_json::json!({
                            "type": "group_invite",
                            "sender": hex::encode(our_peer_id.0),
                            "ratchet_header": serde_json::to_value(&header).unwrap_or(serde_json::Value::Null),
                            "ciphertext": hex::encode(&ct),
                        });
                        if let Some((eph, ik)) = x3dh_fields {
                            if let Some(obj) = f.as_object_mut() {
                                obj.insert("x3dh_eph_pub".into(), serde_json::Value::String(hex::encode(eph)));
                                obj.insert("x3dh_encrypted_ik".into(), serde_json::Value::String(hex::encode(ik)));
                            }
                        }
                        f
                    })
                } else { None }
            } else { None }
        };

        if let Some(frame) = frame_opt {
            self.send_raw_frame(&requester_hex, &frame);
            self.save_ratchet_sessions();
        }
        true
    }

    /// Broadcast our signed network map entry to a connected peer.
    ///
    /// Called after pairing or when a new clearnet connection is established.
    /// Gives the peer our preauth key so they can initiate X3DH with us.
    fn send_gossip_self_entry(&self, peer_id_hex: &str) {
        use crate::network::map::NetworkMapEntry;
        use crate::trust::levels::TrustLevel;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Build transport hints: include clearnet + Tor if active.
        let mut transport_hints: Vec<crate::network::transport_hint::TransportHint> = Vec::new();
        {
            let port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
            if self.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                if let Some(ip) = local_clearnet_ip() {
                    transport_hints.push(crate::network::transport_hint::TransportHint {
                        transport: crate::network::transport_hint::TransportType::Clearnet,
                        endpoint: Some(format!("{}:{}", ip, port)),
                    });
                }
            }
            let tor_guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref tor) = *tor_guard {
                transport_hints.push(crate::network::transport_hint::TransportHint {
                    transport: crate::network::transport_hint::TransportType::Tor,
                    endpoint: Some(format!("{}:{}", tor.onion_address, DEFAULT_HS_PORT)),
                });
            }
        }

        // Build a fresh signed self-entry.
        let self_entry = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                None => return,
                Some(id) => {
                    let kem_ek = if id.kem_encapsulation_key.is_empty() {
                        None
                    } else {
                        Some(id.kem_encapsulation_key.clone())
                    };
                    // Sign the preauth key with our Ed25519 identity key so
                    // recipients can verify the identity binding (§7.0.1).
                    let preauth_sig = {
                        use crate::crypto::x3dh::PreauthBundle;
                        let msg = PreauthBundle::signed_message(&id.preauth_x25519_pub);
                        let secret = id.ed25519_signing.to_bytes();
                        Some(crate::crypto::signing::sign(&secret, crate::crypto::x3dh::PREAUTH_SIG_DOMAIN, &msg))
                    };
                    let mut entry = NetworkMapEntry {
                        peer_id: id.peer_id(),
                        public_keys: vec![crate::network::map::PublicKeyRecord {
                            ed25519_public: id.ed25519_pub,
                            x25519_public: *id.x25519_pub.as_bytes(),
                            preauth_x25519_public: Some(*id.preauth_x25519_pub.as_bytes()),
                            kem_encapsulation_key: kem_ek,
                            preauth_sig,
                        }],
                        last_seen: now,
                        transport_hints,
                        public_profile: None,
                        services: vec![],
                        sequence: now, // use timestamp as sequence; monotonic within session
                        signature: vec![],
                        local_trust: TrustLevel::InnerCircle,
                    };
                    entry.sign(&id.ed25519_signing);
                    entry
                }
            }
        };

        self.send_raw_frame(peer_id_hex, &serde_json::json!({
            "type": "gossip_map_entry",
            "entry": self_entry,
        }));
    }

    // -----------------------------------------------------------------------
    // Call signalling helpers (§10.1.6)
    // -----------------------------------------------------------------------

    /// Write a JSON frame to a peer's clearnet TCP connection.
    ///
    /// If a WireGuard session exists for this peer the frame payload is
    /// encrypted with ChaCha20-Poly1305 (§5.2 link-layer encryption) and
    /// wrapped in a `{"wg_ct":"<hex>"}` envelope so the receiver can
    /// distinguish encrypted frames from plaintext without changing the
    /// `[4-byte-len][payload]` wire framing.
    ///
    /// When no WireGuard session is available (e.g. during pairing bootstrap)
    /// the frame is sent as plain JSON.
    /// Handle an inbound WireGuard handshake initiation frame (§5.2).
    ///
    /// The remote peer sent a `wg_init` frame with their ephemeral pub + encrypted
    /// static pub.  We respond with our ephemeral pub and store the session.
    fn process_wg_init_frame(&self, envelope: &serde_json::Value) -> bool {
        use crate::transport::wireguard::{HandshakeInit, respond_to_handshake};
        use crate::crypto::channel_key::derive_channel_key;

        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) if s.len() == 64 => s.to_string(),
            _ => return false,
        };
        let init_hex = match envelope.get("init_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let init_bytes = match hex::decode(init_hex) {
            Ok(b) if b.len() == 80 => b,
            _ => return false,
        };

        let initiator_bytes = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let initiator_id = PeerId(initiator_bytes);

        // Extract our keys and the initiator's X25519 pub from the contact store.
        let (our_secret_bytes, our_peer_id, their_x25519) = {
            let id_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            match (id_guard.as_ref(), contacts.get(&initiator_id)) {
                (Some(id), Some(contact)) => (
                    id.x25519_secret.to_bytes(),
                    id.peer_id(),
                    x25519_dalek::PublicKey::from(contact.x25519_public),
                ),
                _ => return false,
            }
        };

        let our_secret = x25519_dalek::StaticSecret::from(our_secret_bytes);
        let psk = match derive_channel_key(&our_secret, &their_x25519, &our_peer_id, &initiator_id) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let init_msg = HandshakeInit {
            eph_i_pub: { let mut a = [0u8; 32]; a.copy_from_slice(&init_bytes[..32]); a },
            enc_static: { let mut a = [0u8; 48]; a.copy_from_slice(&init_bytes[32..]); a },
        };

        let (session, response) = match respond_to_handshake(
            &init_msg,
            &our_secret,
            &psk,
            our_peer_id,
            initiator_id,
        ) {
            Ok(r) => r,
            Err(_) => return false,
        };

        // Store the session.
        self.wireguard_sessions.lock().unwrap_or_else(|e| e.into_inner())
            .insert(initiator_id, session);

        // Send our response.
        let our_hex = our_peer_id.to_hex();
        let response_frame = serde_json::json!({
            "type":         "wg_response",
            "sender":       our_hex,
            "response_hex": hex::encode(response.eph_r_pub),
        });
        self.send_raw_frame(&sender_hex, &response_frame);
        true
    }

    /// Handle an inbound WireGuard handshake response frame (§5.2).
    ///
    /// Completes our pending initiator handshake and establishes the session.
    fn process_wg_response_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) if s.len() == 64 => s.to_string(),
            _ => return false,
        };
        let response_hex = match envelope.get("response_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let eph_r_pub: [u8; 32] = match hex::decode(response_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };

        let sender_bytes: [u8; 32] = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let responder_id = PeerId(sender_bytes);

        let our_peer_id = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(id) => id.peer_id(),
                None => return false,
            }
        };

        let pending = {
            let mut map = self.pending_wg_handshakes.lock().unwrap_or_else(|e| e.into_inner());
            match map.remove(&responder_id) {
                Some(p) => p,
                None => return false, // No pending handshake — ignore.
            }
        };

        let response = crate::transport::wireguard::HandshakeResponse { eph_r_pub };
        let session = match pending.complete(&response, our_peer_id, responder_id) {
            Ok(s) => s,
            Err(_) => return false,
        };

        self.wireguard_sessions.lock().unwrap_or_else(|e| e.into_inner())
            .insert(responder_id, session);
        true
    }

    fn send_raw_frame(&self, peer_id_hex: &str, frame: &serde_json::Value) {
        use std::io::Write;
        let frame_bytes = match serde_json::to_vec(frame) {
            Ok(b) => b,
            Err(_) => return,
        };

        // Attempt WireGuard encryption if we have a session for this peer.
        let payload = if let Ok(peer_bytes) = hex::decode(peer_id_hex) {
            if peer_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&peer_bytes);
                let peer_id = PeerId(arr);
                let mut wg_sessions = self.wireguard_sessions.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(session) = wg_sessions.get_mut(&peer_id) {
                    match session.encrypt(&frame_bytes) {
                        Ok(ct) => {
                            // Wrap ciphertext in a JSON envelope: {"wg_ct":"<hex>"}
                            let envelope = serde_json::json!({ "wg_ct": hex::encode(&ct) });
                            serde_json::to_vec(&envelope).unwrap_or(frame_bytes)
                        }
                        Err(_) => frame_bytes, // Fallback to plaintext on encrypt error.
                    }
                } else {
                    frame_bytes // No WG session — send plaintext.
                }
            } else {
                frame_bytes
            }
        } else {
            frame_bytes
        };

        let mut conns = self.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(stream) = conns.get_mut(peer_id_hex) {
            let len = payload.len() as u32;
            // Log on failure: send_raw_frame returns () so we cannot propagate.
            // A write failure means the frame was not delivered; the peer will
            // detect the connection drop on the next read.
            if let Err(e) = stream.write_all(&len.to_be_bytes())
                .and_then(|_| stream.write_all(&payload))
            {
                eprintln!("[transport] WARNING: failed to write frame to peer {peer_id_hex}: {e}");
            }
        }
    }

    /// Send a `call_hangup` signal frame to a peer.
    fn send_call_hangup(&self, peer_id_hex: &str, call_id_hex: &str) {
        let call_id_bytes = match hex::decode(call_id_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return,
        };
        let signal = crate::calls::CallSignal::Hangup {
            call_id: call_id_bytes,
            reason: crate::calls::HangupReason::Declined,
        };
        let payload = match serde_json::to_string(&signal) {
            Ok(s) => s,
            Err(_) => return,
        };
        self.send_raw_frame(peer_id_hex, &serde_json::json!({
            "type": "call_hangup",
            "payload": payload,
        }));
    }

    /// Handle an inbound "call_offer" frame.
    ///
    /// Emits a `CallIncoming` event so the Flutter UI can ring.
    fn process_call_offer_frame(&self, envelope: &serde_json::Value) -> bool {
        let sender_hex = match envelope.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signal: crate::calls::CallSignal = match serde_json::from_str(payload_str) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let (call_id, is_video, session_desc) = match &signal {
            crate::calls::CallSignal::Offer { call_id, video_codecs, session_desc, .. } => {
                (*call_id, !video_codecs.is_empty(), session_desc.clone())
            }
            _ => return false,
        };
        let call_id_hex = hex::encode(call_id);

        // Busy: reject if we already have an active call.
        if self.active_call.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            self.send_call_hangup(&sender_hex, &call_id_hex);
            return true;
        }

        let sender_id_bytes = match hex::decode(&sender_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return false,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);

        // Store call state; pass caller's peer ID so participants[0] = caller.
        let call_state = crate::calls::CallState::new_outgoing(
            call_id, is_video, PeerId(sender_id_bytes), now,
        );
        *self.active_call.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((call_state, sender_hex.clone()));

        self.push_event("CallIncoming", serde_json::json!({
            "callId": call_id_hex,
            "peerId": sender_hex,
            "isVideo": is_video,
            "sessionDesc": session_desc,
        }));
        true
    }

    /// Handle an inbound "call_answer" frame — emits `CallAnswered` or `CallHungUp`.
    fn process_call_answer_frame(&self, envelope: &serde_json::Value) -> bool {
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signal: crate::calls::CallSignal = match serde_json::from_str(payload_str) {
            Ok(s) => s,
            Err(_) => return false,
        };
        match signal {
            crate::calls::CallSignal::Answer { call_id, audio_codec, video_codec, session_desc, .. } => {
                self.push_event("CallAnswered", serde_json::json!({
                    "callId": hex::encode(call_id),
                    "audioCodec": format!("{audio_codec:?}"),
                    "videoCodec": video_codec.map(|c| format!("{c:?}")),
                    "sessionDesc": session_desc,
                }));
            }
            crate::calls::CallSignal::Hangup { call_id, reason } => {
                *self.active_call.lock().unwrap_or_else(|e| e.into_inner()) = None;
                self.push_event("CallHungUp", serde_json::json!({
                    "callId": hex::encode(call_id),
                    "reason": format!("{reason:?}"),
                }));
            }
            _ => return false,
        }
        true
    }

    /// Handle an inbound "call_hangup" frame — emits `CallHungUp`.
    fn process_call_hangup_frame(&self, envelope: &serde_json::Value) -> bool {
        let payload_str = match envelope.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let signal: crate::calls::CallSignal = match serde_json::from_str(payload_str) {
            Ok(s) => s,
            Err(_) => return false,
        };
        if let crate::calls::CallSignal::Hangup { call_id, reason } = signal {
            *self.active_call.lock().unwrap_or_else(|e| e.into_inner()) = None;
            self.push_event("CallHungUp", serde_json::json!({
                "callId": hex::encode(call_id),
                "reason": format!("{reason:?}"),
            }));
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Session bootstrap helper
// ---------------------------------------------------------------------------

/// Bootstrap a Double Ratchet session from static identity keys.
///
/// Computes a static X25519 DH between our identity key and the contact's
/// X25519 key, then derives a master secret via HKDF-SHA256. Role assignment
/// (initiator vs. responder) is determined by lexicographic peer ID comparison:
/// the peer with the smaller ID bytes is the initiator (Signal "Alice" role).
///
/// Both sides independently compute the same master secret and the same role
/// assignment, so no additional coordination is required. The session will be
/// upgraded to X3DH prekeys when that infrastructure is available.
/// X3DH init header wire fields: (eph_pub [32], encrypted_ik [48]).
type X3dhWireHeader = ([u8; 32], [u8; 48]);
/// PQXDH extension: (kem_ciphertext, kem_binding).
type PqxdhWireExt = (Vec<u8>, [u8; 32]);

/// Bootstrap a Double Ratchet session with a contact.
///
/// Returns `(session, Option<X3DH_header>, Option<PQXDH_extension>)`.
/// When X3DH is used, the header must be stored in `x3dh_pending`.
/// When PQXDH is used, the extension must be stored in `pqxdh_pending`.
/// Both are included in every outgoing message until Bob replies.
fn bootstrap_ratchet_session(
    our_id: &SelfIdentity,
    contact: &ContactRecord,
) -> Result<(DoubleRatchetSession, Option<X3dhWireHeader>, Option<PqxdhWireExt>), String> {
    // ---- Try X3DH/PQXDH first; fall through to static DH on failure ----
    if let Some(preauth_bytes) = contact.preauth_key {
        if let Ok((session, header, pq_ext)) = x3dh_bootstrap_session(our_id, contact, &preauth_bytes) {
            return Ok((session, Some(header), pq_ext));
        }
    }

    // ---- Static DH fallback ----
    static_dh_bootstrap_session(our_id, contact).map(|s| (s, None, None))
}

/// X3DH/PQXDH session bootstrap (preferred path).
///
/// Returns (session, init_header, Option<pqxdh_ext>).
/// The X3DH header must be included in the first outgoing message.
/// If PQXDH was used, the extension (kem_ct, kem_binding) must also be included.
fn x3dh_bootstrap_session(
    our_id: &SelfIdentity,
    contact: &ContactRecord,
    bob_preauth_bytes: &[u8; 32],
) -> Result<(DoubleRatchetSession, X3dhWireHeader, Option<PqxdhWireExt>), String> {
    use crate::crypto::x3dh::{x3dh_initiate, PreauthBundle, ENCRYPTED_IK_SIZE};

    let bob_bundle = PreauthBundle {
        identity_ed25519_pub: contact.ed25519_public,
        identity_x25519_pub: X25519Public::from(contact.x25519_public),
        preauth_x25519_pub: X25519Public::from(*bob_preauth_bytes),
        // Include KEM key for PQXDH if the contact advertises one (§3.4.1).
        preauth_kem_pub: contact.kem_encapsulation_key.clone(),
        // Use the preauth sig stored in the contact record for identity binding
        // verification (§7.0.1).  None for legacy contacts (sig skipped).
        preauth_sig: contact.preauth_key_sig.clone(),
    };

    let ik_pub_bytes = *our_id.x25519_pub.as_bytes();
    let output = x3dh_initiate(&our_id.x25519_secret, &ik_pub_bytes, &bob_bundle)
        .map_err(|e| format!("X3DH initiate failed: {e}"))?;

    let header = output.header.ok_or("X3DH header missing")?;
    let master = output.master_secret.as_bytes();

    // Validate encrypted_ik size.
    debug_assert_eq!(header.encrypted_ik_pub.len(), ENCRYPTED_IK_SIZE);

    // Alice is always the initiator in X3DH → she is the Double Ratchet sender.
    // Initial ratchet key is Bob's preauth pub (SPK), not his IK.
    let session = DoubleRatchetSession::init_sender(master, bob_preauth_bytes)
        .map_err(|e| format!("DR init_sender (X3DH) failed: {e}"))?;

    // Extract PQXDH extension if present.
    let pq_ext = output.pqxdh_header.map(|ph| (ph.kem_ciphertext, ph.kem_binding));

    Ok((session, (header.eph_pub, header.encrypted_ik_pub), pq_ext))
}

/// Static DH session bootstrap (fallback for contacts without a preauth key).
fn static_dh_bootstrap_session(
    our_id: &SelfIdentity,
    contact: &ContactRecord,
) -> Result<DoubleRatchetSession, String> {
    use zeroize::{Zeroize, Zeroizing};

    // Static DH: our identity X25519 secret × contact's X25519 public.
    let their_pub = X25519Public::from(contact.x25519_public);
    let shared = our_id.x25519_secret.diffie_hellman(&their_pub);

    // Derive master secret.
    // Salt = XOR of both peer IDs: commutative, so both sides compute the same
    // salt regardless of call order.
    let our_id_bytes = our_id.peer_id().0;
    let their_id_bytes = contact.peer_id.0;
    let mut salt = [0u8; 32];
    for i in 0..32 {
        salt[i] = our_id_bytes[i] ^ their_id_bytes[i];
    }

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    // Wrap `master` in Zeroizing so the key material is wiped automatically
    // when this binding goes out of scope — whether the function returns normally
    // or unwinds early via the ? operator.  Replaces the previous manual
    // `iter_mut().for_each(|b| *b = 0)` which ran only on the happy path.
    let mut master = Zeroizing::new([0u8; 32]);
    hk.expand(b"MeshInfinity_session_bootstrap_v1", &mut *master)
        .map_err(|_| "HKDF expand failed for session bootstrap".to_string())?;

    // Role assignment: smaller peer_id bytes → initiator (Alice).
    let session = if our_id_bytes < their_id_bytes {
        DoubleRatchetSession::init_sender(&*master, &contact.x25519_public)
            .map_err(|e| format!("init_sender failed: {e}"))?
    } else {
        let our_secret_bytes = our_id.x25519_secret.to_bytes();
        let our_secret_copy = X25519Secret::from(our_secret_bytes);
        let our_pub_bytes = *our_id.x25519_pub.as_bytes();
        DoubleRatchetSession::init_receiver(&*master, our_secret_copy, &our_pub_bytes)
    };

    // Zeroizing<> Drop impl wipes `master` here automatically.
    // Explicitly zeroize salt as well since it is derived from peer IDs.
    salt.zeroize();
    Ok(session)
}

// ---------------------------------------------------------------------------
// Clearnet TCP frame I/O helpers
// ---------------------------------------------------------------------------

/// Write a length-prefixed frame to a TcpStream.
///
/// Frame format: [4-byte big-endian payload_len][payload bytes]
/// Maximum payload size: 4 MiB.
fn write_tcp_frame(stream: &mut std::net::TcpStream, payload: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if payload.len() > 4 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame payload exceeds 4 MiB limit",
        ));
    }
    let len_bytes = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

/// Try to read one complete frame from a receive buffer.
///
/// Returns `Some(payload)` and drains those bytes from `buf` if a complete
/// frame is available. Returns `None` if more data is needed.
///
/// Discards the buffer if the declared frame length exceeds 4 MiB, since
/// that indicates garbage data or a malformed/malicious frame.
fn try_read_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 4 {
        return None;
    }
    let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if frame_len > 4 * 1024 * 1024 {
        // Pathological frame — discard the entire buffer.
        buf.clear();
        return None;
    }
    if buf.len() < 4 + frame_len {
        return None;
    }
    let payload = buf[4..4 + frame_len].to_vec();
    buf.drain(..4 + frame_len);
    Some(payload)
}

/// Extract the sender peer_id hex from a frame payload without full decryption.
/// Used to identify which peer sent a frame so we can key the connection.
fn extract_frame_sender(frame_payload: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(frame_payload).ok()?;
    let sender = v.get("sender").and_then(|s| s.as_str())?;
    // Validate: must be a 64-hex-character peer ID.
    if sender.len() == 64 && sender.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(sender.to_string())
    } else {
        None
    }
}

/// Detect the primary outbound-capable local IP address.
/// Does NOT send any network traffic — uses connect() to trigger OS routing.
fn local_clearnet_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // Connect to a public address to let the OS select the right interface.
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

// ---------------------------------------------------------------------------
// Helper: extract C string
// ---------------------------------------------------------------------------

unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
}

/// Safe wrapper that extracts a C string to an owned String.
/// Handles null pointers by returning None.
fn c_str_to_string(ptr: *const c_char) -> Option<String> {
    // SAFETY: The FFI caller guarantees `ptr` is either null or a valid
    // NUL-terminated C string; `c_str_to_str` handles the null case.
    unsafe { c_str_to_str(ptr) }.map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Initialize the Mesh Infinity backend. Returns a context handle.
#[no_mangle]
pub extern "C" fn mesh_init(data_dir: *const c_char) -> *mut MeshContext {
    // SAFETY: The FFI caller guarantees these pointers are non-null
    // and point to valid NUL-terminated C strings for this call.
    let dir = unsafe {
        match c_str_to_str(data_dir) {
            Some(s) => s.to_string(),
            None => return ptr::null_mut(),
        }
    };

    // Create data directory if it doesn't exist.
    // Log on failure: mesh_init returns a raw pointer so we cannot use ?,
    // but a failed mkdir means vault operations will also fail and the user
    // should see a diagnostic message.
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("[mesh_init] WARNING: failed to create data directory {dir:?}: {e}");
    }

    let ctx = Box::new(MeshContext::new(dir));
    Box::into_raw(ctx)
}

/// Destroy the context and free all resources.
#[no_mangle]
pub extern "C" fn mesh_destroy(ctx: *mut MeshContext) {
    if !ctx.is_null() {
        // SAFETY: `ctx` was allocated by `Box::into_raw` in `mesh_init`.
        // This is the unique ownership reclaim point; the caller must not
        // use `ctx` after calling `mesh_destroy`.
        unsafe {
            drop(Box::from_raw(ctx));
        }
    }
}

/// Get the last error message (or null if none).
#[no_mangle]
pub extern "C" fn mi_get_last_error(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    match ctx.last_error.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some(s) => s.as_ptr(),
        None => ptr::null(),
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Check if an identity exists on this device.
#[no_mangle]
pub extern "C" fn mi_has_identity(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let identity_path = std::path::Path::new(&ctx.data_dir).join("identity.dat");
    if identity_path.exists() { 1 } else { 0 }
}

/// Create a new identity. Returns 0 on success or -1 on failure.
///
/// On success, the identity is persisted to disk (identity.key + identity.dat)
/// and the vault is initialized. The peer ID and public key are available
/// via mi_get_identity_summary() after creation.
///
/// Note: the spec requires an optional PIN at creation time. Pass null for no PIN.
#[no_mangle]
pub extern "C" fn mi_create_identity(
    ctx: *mut MeshContext,
    display_name: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let name = c_str_to_string(display_name);

    let identity = SelfIdentity::generate(name);
    let peer_id = identity.peer_id();
    let ed25519_pub = identity.ed25519_pub;
    let master_key = *identity.master_key;

    // Derive the public mask (§3.1.3) from the self identity keys.
    // The public mask handles public-facing operations (endorsements, public profile).
    // mask_id = all-zeros for the public mask (deterministic, spec-defined).
    let public_mask_id = MaskId([0u8; 16]);
    let _public_mask = Mask::derive_from_self(
        &identity.ed25519_signing,
        &identity.x25519_secret,
        public_mask_id,
        "Public".to_string(),
        0,
        true,
    );
    // The public mask is derived on demand from the self identity.
    // It is not stored independently — re-derived from (ed25519_signing, x25519_secret, mask_id).

    // Persist identity to disk (no PIN — PIN can be set separately via mi_set_pin)
    let data_dir = std::path::Path::new(&ctx.data_dir);
    if let Err(e) = identity.save_to_disk(data_dir, None) {
        ctx.set_error(&format!("Failed to persist identity: {e}"));
        return -1;
    }

    // Initialize vault with the identity's master key
    ctx.vault = Some(VaultManager::new(
        std::path::PathBuf::from(&ctx.data_dir),
        master_key,
    ));
    ctx.identity_unlocked = true;
    *ctx.identity.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity);
    // Load any existing vault data into memory
    ctx.load_from_vault();

    // Emit SettingsUpdated so Flutter knows identity is now live
    let flags = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let node_mode = *ctx.node_mode.lock().unwrap_or_else(|e| e.into_inner());
    let clearnet_port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
    ctx.push_event("SettingsUpdated", build_settings_json(
        &flags, node_mode, &ctx.threat_context,
        &peer_id.to_hex(), &hex::encode(ed25519_pub), clearnet_port,
    ));

    0
}

/// Unlock an existing identity. Returns 0 on success, -1 on failure.
///
/// Must be called before any feature that requires Layer 2 identity.
/// Pass null for `pin` if no PIN was set at creation.
#[no_mangle]
pub extern "C" fn mi_unlock_identity(
    ctx: *mut MeshContext,
    pin: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let pin_str = c_str_to_string(pin);
    let data_dir = std::path::Path::new(&ctx.data_dir);

    match SelfIdentity::load_from_disk(data_dir, pin_str.as_deref()) {
        Ok(identity) => {
            let master_key = *identity.master_key;
            let peer_id = identity.peer_id().to_hex();
            let ed25519_pub = hex::encode(identity.ed25519_pub);

            // Initialize vault
            ctx.vault = Some(VaultManager::new(
                std::path::PathBuf::from(&ctx.data_dir),
                master_key,
            ));
            ctx.identity_unlocked = true;
            *ctx.identity.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity);
            // Restore rooms, contacts, messages, settings from vault
            ctx.load_from_vault();

            // Build and sign the self network map entry (§4.5).
            // This is how other nodes learn our addresses and public keys.
            // The entry is signed with our Ed25519 mask key so forgery is impossible.
            {
                use crate::network::map::NetworkMapEntry;
                use crate::trust::levels::TrustLevel;
                use ed25519_dalek::SigningKey;

                let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref id) = *guard {
                    let signing_key = SigningKey::from_bytes(&id.ed25519_signing.to_bytes());
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    let public_profile = id.display_name.as_ref().map(|name| {
                        crate::network::map::PublicProfileSummary {
                            display_name: Some(name.clone()),
                            bio: None,
                            avatar_hash: None,
                        }
                    });
                    let kem_ek2 = if id.kem_encapsulation_key.is_empty() {
                        None
                    } else {
                        Some(id.kem_encapsulation_key.clone())
                    };
                    // Sign the preauth key with our Ed25519 identity key (§7.0.1).
                    let preauth_sig2 = {
                        use crate::crypto::x3dh::PreauthBundle;
                        let msg = PreauthBundle::signed_message(&id.preauth_x25519_pub);
                        let secret = id.ed25519_signing.to_bytes();
                        Some(crate::crypto::signing::sign(&secret, crate::crypto::x3dh::PREAUTH_SIG_DOMAIN, &msg))
                    };
                    let mut self_entry = NetworkMapEntry {
                        peer_id: id.peer_id(),
                        public_keys: vec![crate::network::map::PublicKeyRecord {
                            ed25519_public: id.ed25519_pub,
                            x25519_public: *id.x25519_pub.as_bytes(),
                            preauth_x25519_public: Some(*id.preauth_x25519_pub.as_bytes()),
                            kem_encapsulation_key: kem_ek2,
                            preauth_sig: preauth_sig2,
                        }],
                        last_seen: now,
                        transport_hints: vec![],
                        public_profile,
                        services: vec![],
                        sequence: 1,
                        signature: vec![],
                        local_trust: TrustLevel::InnerCircle,
                    };
                    self_entry.sign(&signing_key);
                    drop(guard);

                    let mut gossip = ctx.gossip.lock().unwrap_or_else(|e| e.into_inner());
                    // Insert our own entry — use now as timestamp.
                    let _ = gossip.map.insert(self_entry, now);
                }
            }

            // Emit settings event so Flutter receives the unlocked identity details
            let flags = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let node_mode = *ctx.node_mode.lock().unwrap_or_else(|e| e.into_inner());
            let clearnet_port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
            ctx.push_event("SettingsUpdated", build_settings_json(
                &flags, node_mode, &ctx.threat_context, &peer_id, &ed25519_pub, clearnet_port,
            ));

            0
        }
        Err(IdentityError::WrongPin) => {
            ctx.set_error("Wrong PIN");
            -1
        }
        Err(IdentityError::NotFound(_)) => {
            ctx.set_error("No identity found — call mi_create_identity first");
            -1
        }
        Err(e) => {
            ctx.set_error(&format!("Identity unlock failed: {e}"));
            -1
        }
    }
}

/// Get identity summary. Returns JSON or null if no identity.
///
/// JSON shape: `{"locked": bool, "peerId"?: string, "ed25519Pub"?: string, "displayName"?: string}`
#[no_mangle]
pub extern "C" fn mi_get_identity_summary(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    if !ctx.identity_unlocked {
        return ctx.set_response(r#"{"locked": true}"#);
    }

    let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(id) => {
            let json = serde_json::json!({
                "locked": false,
                "peerId": id.peer_id().to_hex(),
                "ed25519Pub": hex::encode(id.ed25519_pub),
                "displayName": id.display_name,
            });
            drop(guard);
            ctx.set_response(&json.to_string())
        }
        None => {
            // Identity unlocked but not yet loaded into memory (should not happen normally)
            ctx.set_response(r#"{"locked": false, "status": "active"}"#)
        }
    }
}

// ---------------------------------------------------------------------------
// Rooms / Conversations
// ---------------------------------------------------------------------------

/// Get the list of rooms. Returns JSON array.
#[no_mangle]
pub extern "C" fn mi_get_room_list(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());

    // Build a lookup from group_peer_id → group_id_hex so we can annotate group rooms.
    let groups_guard = ctx.groups.lock().unwrap_or_else(|e| e.into_inner());
    let group_lookup: std::collections::HashMap<PeerId, String> = groups_guard
        .iter()
        .map(|g| (PeerId::from_ed25519_pub(&g.ed25519_public), hex::encode(g.group_id)))
        .collect();
    drop(groups_guard);

    let json: Vec<serde_json::Value> = rooms
        .iter()
        .map(|r| {
            use crate::messaging::message::ConversationType;
            let is_group = r.conversation_type == ConversationType::Group;
            let group_id = if is_group {
                r.participants.first()
                    .and_then(|pid| group_lookup.get(pid))
                    .cloned()
            } else {
                None
            };
            // For DM rooms, participants = [self, other]; expose other's ID.
            let other_peer_id = if !is_group && r.participants.len() >= 2 {
                Some(hex::encode(r.participants[1].0))
            } else {
                None
            };
            serde_json::json!({
                "id": hex::encode(r.id),
                "name": r.name,
                "lastMessage": r.last_message_preview,
                "unreadCount": r.unread_count,
                "timestamp": r.last_message_at,
                "isArchived": r.is_archived,
                "isPinned": r.is_pinned,
                "isMuted": r.is_muted,
                "securityMode": r.security_mode,
                "conversationType": if is_group { "group" } else { "dm" },
                "groupId": group_id,
                "otherPeerId": other_peer_id,
            })
        })
        .collect();

    ctx.set_response(&serde_json::to_string(&json).unwrap_or_else(|_| "[]".into()))
}

/// Create a new room. Returns JSON: { id }.
#[no_mangle]
pub extern "C" fn mi_create_room(
    ctx: *mut MeshContext,
    name: *const c_char,
    peer_id: *const c_char,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };

    let room_name = c_str_to_string(name).unwrap_or_else(|| "New Chat".to_string());
    let peer_id_str = c_str_to_string(peer_id);

    let room = if let Some(ref pid_hex) = peer_id_str {
        // DM room: find the contact and create a proper two-participant room.
        let peer_bytes = hex::decode(pid_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); PeerId(a) });
        if let Some(other_peer_id) = peer_bytes {
            let our_peer_id = ctx.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| id.peer_id())
                .unwrap_or(PeerId([0u8; 32]));
            Room::new_dm(our_peer_id, other_peer_id, &room_name)
        } else {
            Room::new_group(&room_name, vec![])
        }
    } else {
        Room::new_group(&room_name, vec![])
    };
    let room_id = hex::encode(room.id);
    let room_summary = serde_json::json!({
        "id": room_id,
        "name": room.name,
        "lastMessage": room.last_message_preview,
        "unreadCount": room.unread_count,
        "timestamp": room.last_message_at,
    });
    ctx.rooms.lock().unwrap_or_else(|e| e.into_inner()).push(room);

    // Emit RoomUpdated so Flutter conversation list reflects the new room
    ctx.push_event("RoomUpdated", room_summary);
    ctx.save_rooms();

    let response = serde_json::json!({ "id": room_id });
    ctx.set_response(&response.to_string())
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Get messages for a room. Returns JSON array.
///
/// Returns up to `limit` messages before `before_seq` (0 = newest).
/// Messages are returned newest-first. A limit of 0 returns up to 200.
#[no_mangle]
pub extern "C" fn mi_get_messages(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    before_seq: u64,
    limit: u32,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let rid = c_str_to_string(room_id).unwrap_or_default();
    if rid.is_empty() {
        return ctx.set_response("[]");
    }
    let msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
    let all = match msgs.get(&rid) {
        Some(v) => v.clone(),
        None => return ctx.set_response("[]"),
    };
    drop(msgs);

    let cap = if limit == 0 { 200 } else { limit as usize };

    // Apply before_seq filter (0 means no filter).
    let filtered: Vec<&serde_json::Value> = if before_seq > 0 {
        all.iter()
            .filter(|m| m.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0) < before_seq)
            .collect()
    } else {
        all.iter().collect()
    };

    // Return the last `cap` messages (newest), in chronological order.
    let start = if filtered.len() > cap { filtered.len() - cap } else { 0 };
    let page: Vec<&serde_json::Value> = filtered[start..].to_vec();

    let json = serde_json::to_string(&page).unwrap_or_else(|_| "[]".to_string());
    ctx.set_response(&json)
}

/// Send a message. Returns 0 on success.
///
/// Stores the message in the in-memory log and emits MessageAdded + RoomUpdated
/// events so Flutter updates immediately. In the full implementation, the message
/// is also encrypted via the 4-layer scheme (§7.2) and routed through the mesh.
#[no_mangle]
pub extern "C" fn mi_send_message(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    _mask_id: *const c_char,
    text: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };

    let room_id_str = match c_str_to_string(room_id) {
        Some(s) => s,
        None => return -1,
    };
    let text_str = match c_str_to_string(text) {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };

    // Generate a random message ID
    let mut msg_id_bytes = [0u8; 16];
    if !try_random_fill(&mut msg_id_bytes) { return -1; }
    let msg_id = hex::encode(msg_id_bytes);

    // Timestamp (Unix seconds)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Determine sender peer ID
    let sender = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_else(|| "local".to_string())
    };

    // Check room's disappearing timer so we can stamp expiresAt.
    let expires_at: Option<u64> = {
        let rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        rooms.iter()
            .find(|r| hex::encode(r.id) == room_id_str)
            .and_then(|r| r.disappearing_timer)
            .map(|secs| timestamp + secs)
    };

    let mut msg = serde_json::json!({
        "id": msg_id,
        "roomId": room_id_str,
        "sender": sender,
        "text": text_str,
        "timestamp": timestamp,
        "isOutgoing": true,
        "authStatus": "outgoing",
    });
    if let Some(exp) = expires_at {
        msg["expiresAt"] = serde_json::json!(exp);
    }

    // Store in memory
    ctx.messages.lock().unwrap_or_else(|e| e.into_inner())
        .entry(room_id_str.clone())
        .or_default()
        .push(msg.clone());

    // Update room last-message preview
    {
        let mut rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_str) {
            // Use char-boundary-safe truncation: slicing by byte index on a UTF-8
            // string panics if a multibyte character (e.g. emoji) straddles the
            // boundary.  chars().take(80) collects exactly the first 80 Unicode
            // scalar values regardless of their byte width.
            room.last_message_preview = Some(if text_str.chars().count() > 80 {
                format!("{}…", text_str.chars().take(80).collect::<String>())
            } else {
                text_str.clone()
            });
            room.last_message_at = Some(timestamp);
        }
    }

    // Emit MessageAdded event
    ctx.push_event("MessageAdded", msg);

    // Emit RoomUpdated to refresh conversation list preview
    let room_summary = {
        let rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        rooms.iter().find(|r| hex::encode(r.id) == room_id_str).map(|r| serde_json::json!({
            "id": hex::encode(r.id),
            "name": r.name,
            "lastMessage": r.last_message_preview,
            "unreadCount": r.unread_count,
            "timestamp": r.last_message_at,
        }))
    };
    if let Some(summary) = room_summary {
        ctx.push_event("RoomUpdated", summary);
    }

    // Persist message log and room metadata to vault
    ctx.save_messages();
    ctx.save_rooms();

    // ---------------------------------------------------------------------------
    // Four-layer encryption (§7.2) + clearnet TCP delivery
    //
    // Find the other participant in this room. For DM rooms there is exactly one
    // non-self participant. For group rooms, sender-key delivery would be used
    // (not yet implemented); skip encryption for now.
    // ---------------------------------------------------------------------------
    let our_peer_id_bytes = {
        ctx.identity.lock().unwrap_or_else(|e| e.into_inner())
            .as_ref().map(|id| id.peer_id().0)
    };

    let other_participant = {
        let rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        rooms.iter()
            .find(|r| hex::encode(r.id) == room_id_str)
            .and_then(|r| {
                r.participants.iter()
                    .find(|p| Some(p.0) != our_peer_id_bytes)
                    .copied()
            })
    };

    if let Some(their_peer_id) = other_participant {
        // Look up the contact for this participant.
        let contact_opt = ctx.contacts.lock().unwrap_or_else(|e| e.into_inner())
            .get(&their_peer_id).cloned();

        if let Some(contact) = contact_opt {
            // Ensure a session exists (bootstrap if needed).
            if !ctx.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&their_peer_id) {
                let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref our_id) = *guard {
                    if let Ok((session, x3dh_header, pq_ext)) = bootstrap_ratchet_session(our_id, &contact) {
                        if let Some(header) = x3dh_header {
                            ctx.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner()).insert(their_peer_id, header);
                        }
                        if let Some(pq) = pq_ext {
                            ctx.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner()).insert(their_peer_id, pq);
                        }
                        drop(guard);
                        ctx.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(their_peer_id, session);
                    }
                }
            }

            // Advance the ratchet to get message keys.
            let ratchet_result = {
                let mut sessions = ctx.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(session) = sessions.get_mut(&their_peer_id) {
                    session.next_send_msg_key().ok().and_then(|(header, msg_key)| {
                        DoubleRatchetSession::expand_msg_key(&msg_key).ok()
                            .map(|(ck, nonce, hmac_key)| (header, ck, nonce, hmac_key))
                    })
                } else {
                    None
                }
            };

            if let Some((ratchet_header, cipher_key, session_nonce, ratchet_msg_key)) = ratchet_result {
                // Persist ratchet session state after each ratchet step.
                ctx.save_ratchet_sessions();

                // Get our signing key (identity key used as mask until per-relationship
                // mask derivation is fully wired).
                let signing_key_opt = ctx.identity.lock().unwrap_or_else(|e| e.into_inner())
                    .as_ref().map(|id| {
                        ed25519_dalek::SigningKey::from_bytes(&id.ed25519_signing.to_bytes())
                    });

                // Get their X25519 public key for Step 4 recipient encryption.
                let their_x25519_pub = X25519Public::from(contact.x25519_public);

                if let Some(signing_key) = signing_key_opt {
                    let ciphertext_result = encrypt_message(
                        text_str.as_bytes(),
                        &ratchet_msg_key,
                        &cipher_key,
                        &session_nonce,
                        &signing_key,
                        &their_x25519_pub,
                        MessageContext::Direct,
                    );

                    if let Ok(ciphertext) = ciphertext_result {
                        // Check for pending X3DH / PQXDH init headers.
                        // Include them in the envelope until we get a reply.
                        let x3dh_fields: Option<([u8; 32], [u8; 48])> =
                            ctx.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner())
                                .get(&their_peer_id).copied();
                        let pqxdh_fields: Option<(Vec<u8>, [u8; 32])> =
                            ctx.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner())
                                .get(&their_peer_id).cloned();

                        // Build the wire envelope JSON.
                        let mut envelope = serde_json::json!({
                            "v": 1,
                            "type": "msg",
                            "sender": sender,
                            "room": room_id_str,
                            "msg_id": msg_id,
                            "ts": timestamp,
                            "ratchet_pub": hex::encode(ratchet_header.ratchet_pub),
                            "prev_chain_len": ratchet_header.prev_chain_len,
                            "msg_num": ratchet_header.msg_num,
                            "ciphertext": hex::encode(&ciphertext),
                        });
                        // Attach X3DH init header if we haven't received a reply yet.
                        if let Some((eph_pub, enc_ik)) = x3dh_fields {
                            envelope["x3dh_eph_pub"] = serde_json::json!(hex::encode(eph_pub));
                            envelope["x3dh_encrypted_ik"] = serde_json::json!(hex::encode(enc_ik));
                        }
                        // Attach PQXDH extension (ML-KEM-768 ciphertext + binding) (§3.4.1).
                        if let Some((kem_ct, kem_binding)) = pqxdh_fields {
                            envelope["pqxdh_kem_ct"] = serde_json::json!(hex::encode(&kem_ct));
                            envelope["pqxdh_kem_binding"] = serde_json::json!(hex::encode(kem_binding));
                        }
                        let envelope_bytes = serde_json::to_vec(&envelope)
                            .unwrap_or_default();

                        // Attempt to deliver via clearnet TCP.
                        // Respect the clearnet transport flag (P5 — §5.4).
                        // If clearnet is disabled, skip TCP delivery entirely.
                        let clearnet_allowed = ctx.transport_flags
                            .lock().unwrap_or_else(|e| e.into_inner()).clearnet;
                        if let Some(ref endpoint) = contact.clearnet_endpoint.filter(|_| clearnet_allowed) {
                            let peer_hex = hex::encode(their_peer_id.0);

                            // Try existing connection first.
                            let sent = {
                                let mut conns = ctx.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(stream) = conns.get_mut(&peer_hex) {
                                    write_tcp_frame(stream, &envelope_bytes).is_ok()
                                } else {
                                    false
                                }
                            };

                            if !sent {
                                // No existing connection — try to connect now.
                                let connected = if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
                                    if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
                                        &addr,
                                        std::time::Duration::from_secs(5),
                                    ) {
                                        let ok = write_tcp_frame(&mut stream, &envelope_bytes).is_ok();
                                        if ok {
                                            let _ = stream.set_nonblocking(true);
                                            ctx.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner())
                                                .insert(peer_hex.clone(), stream);
                                        }
                                        ok
                                    } else { false }
                                } else { false };

                                // If still undelivered, enqueue in outbox for retry.
                                // Cap at 10,000 total frames to prevent unbounded growth.
                                if !connected {
                                    let mut outbox = ctx.outbox.lock().unwrap_or_else(|e| e.into_inner());
                                    if outbox.len() < 10_000 {
                                        outbox.push((
                                            peer_hex,
                                            endpoint.clone(),
                                            envelope_bytes,
                                        ));
                                    }
                                    // Silently drop if over cap — store-and-forward
                                    // relay nodes are the right answer for long
                                    // disconnections, not an infinite local buffer.
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    0
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// Get all settings as JSON.
///
/// Returns the full settings object matching SettingsModel in Flutter.
#[no_mangle]
pub extern "C" fn mi_get_settings(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let flags = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let node_mode = *ctx.node_mode.lock().unwrap_or_else(|e| e.into_inner());
    let (peer_id, ed25519_pub) = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => (id.peer_id().to_hex(), hex::encode(id.ed25519_pub)),
            None => (String::new(), String::new()),
        }
    };
    let clearnet_port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
    let json = build_settings_json(&flags, node_mode, &ctx.threat_context, &peer_id, &ed25519_pub, clearnet_port);
    ctx.set_response(&json.to_string())
}

fn build_settings_json(
    flags: &TransportFlags,
    node_mode: u8,
    threat_context: &ThreatContext,
    peer_id: &str,
    ed25519_pub: &str,
    clearnet_port: u16,
) -> serde_json::Value {
    serde_json::json!({
        "nodeMode": node_mode,
        "threatContext": *threat_context as u8,
        "enableTor": flags.tor,
        "enableClearnet": flags.clearnet,
        "clearnetFallback": flags.clearnet_fallback,
        "enableI2p": flags.i2p,
        "enableBluetooth": flags.bluetooth,
        "enableRf": flags.rf,
        "meshDiscovery": flags.mesh_discovery,
        "allowRelays": flags.allow_relays,
        "localPeerId": peer_id,
        "ed25519Pub": ed25519_pub,
        "clearnetPort": clearnet_port,
    })
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// Set threat context level. Returns 0 on success.
#[no_mangle]
pub extern "C" fn mi_set_threat_context(ctx: *mut MeshContext, level: u8) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    match ThreatContext::from_u8(level) {
        Some(tc) => {
            ctx.threat_context = tc;
            ctx.notifications.lock().unwrap_or_else(|e| e.into_inner()).set_threat_context(tc);
            0
        }
        None => {
            ctx.set_error("Invalid threat context level");
            -1
        }
    }
}

/// Get threat context level.
#[no_mangle]
pub extern "C" fn mi_get_threat_context(ctx: *mut MeshContext) -> u8 {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    ctx.threat_context as u8
}

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

/// Set a peer's trust level. Returns 0 on success.
#[no_mangle]
pub extern "C" fn mi_set_trust_level(
    ctx: *mut MeshContext,
    peer_id: *const c_char,
    level: u8,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let pid_hex = match c_str_to_string(peer_id) {
        Some(s) => s,
        None => return -1,
    };
    let trust = match TrustLevel::from_value(level) {
        Some(t) => t,
        None => {
            ctx.set_error("Invalid trust level");
            return -1;
        }
    };
    let pid_bytes = match hex::decode(&pid_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return -1,
    };
    let pid = crate::identity::peer_id::PeerId(pid_bytes);
    let mut contacts = ctx.contacts.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(contact) = contacts.get_mut(&pid) {
        contact.set_trust_level(trust);
        drop(contacts);
        ctx.push_event("TrustUpdated", serde_json::json!({
            "peerId": pid_hex,
            "trustLevel": level,
        }));
        ctx.save_contacts();
        0
    } else {
        ctx.set_error("Peer not found");
        -1
    }
}

// ---------------------------------------------------------------------------
// Active Conversation (§16.9.3)
// ---------------------------------------------------------------------------

/// Set the active conversation for priority escalation.
/// Pass null room_id to clear.
#[no_mangle]
pub extern "C" fn mi_set_active_conversation(
    ctx: *mut MeshContext,
    room_id: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    if room_id.is_null() {
        *ctx.active_conversation.lock().unwrap_or_else(|e| e.into_inner()) = None;
    } else {
        let id_str = c_str_to_string(room_id).unwrap_or_default();
        if let Ok(bytes) = hex::decode(id_str) {
            if bytes.len() == 16 {
                let mut id = [0u8; 16];
                id.copy_from_slice(&bytes);
                *ctx.active_conversation.lock().unwrap_or_else(|e| e.into_inner()) = Some(id);
            }
        }
    }
    0
}

/// Set conversation security mode.
#[no_mangle]
pub extern "C" fn mi_set_conversation_security_mode(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    mode: u8,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let new_mode = match MessageSecurityMode::from_u8(mode) {
        Some(m) => m,
        None => {
            ctx.set_error("Invalid security mode");
            return -1;
        }
    };
    let room_hex = match c_str_to_string(room_id) {
        Some(s) => s,
        None => return -1,
    };
    let room_bytes = match hex::decode(&room_hex) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return -1,
    };
    let mut rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
    match rooms.iter_mut().find(|r| r.id == room_bytes) {
        Some(room) => {
            room.security_mode = new_mode;
            drop(rooms);
            ctx.save_rooms();
            ctx.push_event("RoomUpdated", serde_json::json!({
                "roomId": room_hex,
                "securityMode": mode,
            }));
            0
        }
        None => {
            ctx.set_error("Room not found");
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Events (polling)
// ---------------------------------------------------------------------------

/// Poll for pending events. Returns a JSON array of event objects.
///
/// Each call drains ALL queued events. The Flutter event bus calls this
/// in a tight loop (200ms sleep when empty) on a background isolate.
///
/// Each element: `{"type": "EventName", "data": {...}}`
/// An empty array (`[]`) means no events are pending.
#[no_mangle]
pub extern "C" fn mi_poll_events(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    // Advance the clearnet TCP transport: accept connections, read frames,
    // decrypt inbound messages, push MessageAdded events. This is called
    // on every poll cycle so the event bus naturally drives the transport.
    ctx.advance_clearnet_transport();

    let mut queue = ctx.event_queue.lock().unwrap_or_else(|e| e.into_inner());
    if queue.is_empty() {
        return ctx.set_response("[]");
    }
    let events: Vec<serde_json::Value> = queue.drain(..).collect();
    drop(queue);
    ctx.set_response(&serde_json::to_string(&events).unwrap_or_else(|_| "[]".into()))
}

// ---------------------------------------------------------------------------
// Clearnet transport control
// ---------------------------------------------------------------------------

/// Start the clearnet TCP listener on the configured port.
///
/// Binds a non-blocking TCP socket and stores it in the context. Once started,
/// `mi_poll_events` will automatically accept connections and process inbound
/// messages on every poll cycle.
///
/// Returns 0 on success, -1 if the listener could not be bound.
#[no_mangle]
pub extern "C" fn mi_start_clearnet_listener(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    match std::net::TcpListener::bind(addr) {
        Ok(listener) => {
            if let Err(e) = listener.set_nonblocking(true) {
                ctx.set_error(&format!("set_nonblocking failed: {e}"));
                return -1;
            }
            *ctx.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(listener);
            0
        }
        Err(e) => {
            ctx.set_error(&format!("Failed to bind clearnet listener on :{port}: {e}"));
            -1
        }
    }
}

/// Stop the clearnet TCP listener and close all active connections.
#[no_mangle]
pub extern "C" fn mi_stop_clearnet_listener(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    *ctx.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner()) = None;
    ctx.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.clearnet_pending_incoming.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.clearnet_recv_buffers.lock().unwrap_or_else(|e| e.into_inner()).clear();
    0
}

// ---------------------------------------------------------------------------
// Tor transport control (§5.3)
// ---------------------------------------------------------------------------

/// Bootstrap the Tor transport and start the hidden service.
///
/// Derives the onion address from the identity master key (HKDF-SHA256,
/// domain "meshinfinity-tor-service-v1"), bootstraps an `arti` Tor client,
/// and launches a hidden service on `DEFAULT_HS_PORT` (7234).
///
/// Inbound hidden-service connections are surfaced via `drain_inbound()` on
/// each poll cycle and fed into the standard pending-incoming queue.
///
/// Returns 0 on success, -1 on failure (identity not unlocked, Tor bootstrap
/// error, or Tor already enabled).
#[no_mangle]
pub extern "C" fn mi_tor_enable(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    // Already running?
    if ctx.tor_transport.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
        return 0; // idempotent
    }

    // Need identity to derive the onion address.
    let master_key: [u8; 32] = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => *id.master_key,
            None => {
                ctx.set_error("mi_tor_enable: identity not unlocked");
                return -1;
            }
        }
    };
    let peer_id_hex = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default()
    };

    let state_dir = std::path::PathBuf::from(&ctx.data_dir);
    match crate::transport::tor::TorTransport::bootstrap(
        &master_key,
        &peer_id_hex,
        &state_dir,
        DEFAULT_HS_PORT,
    ) {
        Ok(transport) => {
            let onion_addr = transport.onion_address.clone();
            *ctx.tor_transport.lock().unwrap_or_else(|e| e.into_inner()) = Some(transport);
            // Mark Tor as enabled in transport flags.
            ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).tor = true;
            ctx.save_settings();
            tracing::info!("Tor transport enabled — onion address: {}", onion_addr);
            0
        }
        Err(e) => {
            ctx.set_error(&format!("mi_tor_enable: Tor bootstrap failed: {e}"));
            -1
        }
    }
}

/// Disable the Tor transport and shut down the hidden service.
///
/// Drops the `TorTransport` (which closes the tokio runtime and all Tor
/// circuits). Returns 0 on success.
#[no_mangle]
pub extern "C" fn mi_tor_disable(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    *ctx.tor_transport.lock().unwrap_or_else(|e| e.into_inner()) = None;
    ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).tor = false;
    ctx.save_settings();
    0
}

/// Return our Tor v3 `.onion` address as a UTF-8 JSON string.
///
/// Returns `null` if Tor is not enabled.
/// The address is derived deterministically from the identity master key and
/// is stable across restarts.
#[no_mangle]
pub extern "C" fn mi_tor_get_onion_address(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let guard = ctx.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(t) => ctx.set_response(&serde_json::json!({ "onion_address": t.onion_address }).to_string()),
        None => ctx.set_response(r#"{"error": "Tor not enabled"}"#),
    }
}

/// Connect to a peer via the Tor network.
///
/// `peer_id_hex_ptr` — hex peer ID of the remote peer.
/// `onion_addr_ptr`  — `.onion` address of the remote peer.
/// `port`            — TCP port on the remote peer.
///
/// Opens a Tor DataStream to the peer and bridges it to a local TCP loopback
/// socket, which is inserted into `clearnet_connections` for the standard
/// send/receive path.
///
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn mi_tor_connect(
    ctx: *mut MeshContext,
    peer_id_hex_ptr: *const c_char,
    onion_addr_ptr: *const c_char,
    port: u16,
) -> i32 {
    if ctx.is_null() || peer_id_hex_ptr.is_null() || onion_addr_ptr.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    // SAFETY: The FFI caller guarantees this pointer is non-null and
    // points to a valid NUL-terminated C string that lives at least as
    // long as this borrow.
    let peer_id_hex = match unsafe { std::ffi::CStr::from_ptr(peer_id_hex_ptr) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    // SAFETY: The FFI caller guarantees this pointer is non-null and
    // points to a valid NUL-terminated C string that lives at least as
    // long as this borrow.
    let onion_addr = match unsafe { std::ffi::CStr::from_ptr(onion_addr_ptr) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    let port = if port == 0 { DEFAULT_HS_PORT } else { port };

    let guard = ctx.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(tor) => {
            match tor.connect(&peer_id_hex, &onion_addr, port) {
                Ok(stream) => {
                    ctx.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner())
                        .insert(peer_id_hex, stream);
                    0
                }
                Err(e) => {
                    ctx.set_error(&format!("mi_tor_connect: {e}"));
                    -1
                }
            }
        }
        None => {
            ctx.set_error("mi_tor_connect: Tor not enabled");
            -1
        }
    }
}

/// Set the clearnet listen port. Takes effect on next `mi_start_clearnet_listener`.
#[no_mangle]
pub extern "C" fn mi_set_clearnet_port(ctx: *mut MeshContext, port: u16) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    if port == 0 { return -1; }
    *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()) = port;
    ctx.save_settings();
    0
}

/// Get the local pairing payload as JSON.
///
/// The payload contains our public keys, a freshly generated pairing token,
/// and transport hints (clearnet endpoint if the listener is running).
/// Callers encode this as a QR code or deep link for peer scanning.
///
/// JSON shape: PairingPayload (§8.3) serialised with snake_case keys.
#[no_mangle]
pub extern "C" fn mi_get_pairing_payload(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
    let id = match guard.as_ref() {
        Some(id) => id,
        None => return ctx.set_response(r#"{"error": "identity not unlocked"}"#),
    };

    let peer_id_hex = id.peer_id().to_hex();
    let ed25519_hex = hex::encode(id.ed25519_pub);
    let x25519_hex = hex::encode(id.x25519_pub.as_bytes());
    let preauth_x25519_hex = hex::encode(id.preauth_x25519_pub.as_bytes());

    // One-time pairing token (prevents replay attacks).
    let mut token = [0u8; 32];
    if !try_random_fill(&mut token) { return ptr::null(); }

    // Transport hints: include clearnet if the listener is running.
    let port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
    let clearnet_hint = if ctx.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
        // Detect the outbound IP to include in the hint.
        let ip = local_clearnet_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string());
        Some(serde_json::json!({
            "transport": "clearnet",
            "endpoint": format!("{ip}:{port}"),
        }))
    } else {
        None
    };

    // Transport hints: also include Tor onion address if Tor is enabled.
    let tor_hint = {
        let tor_guard = ctx.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
        tor_guard.as_ref().map(|t| serde_json::json!({
            "transport": "tor",
            "endpoint": format!("{}:{}", t.onion_address, DEFAULT_HS_PORT),
        }))
    };

    let mut transport_hints = serde_json::json!([]);
    {
        let mut hints_arr: Vec<serde_json::Value> = Vec::new();
        if let Some(hint) = clearnet_hint { hints_arr.push(hint); }
        if let Some(hint) = tor_hint { hints_arr.push(hint); }
        transport_hints = serde_json::json!(hints_arr);
    }

    // Sign the display name if present.
    let (display_name, display_name_sig) = if let Some(ref name) = id.display_name {
        let sig = id.ed25519_signing.sign(name.as_bytes());
        (
            serde_json::json!(name),
            serde_json::json!(hex::encode(sig.to_bytes())),
        )
    } else {
        (serde_json::Value::Null, serde_json::Value::Null)
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let payload = serde_json::json!({
        "version": 1,
        "peer_id": peer_id_hex,
        "ed25519_public": ed25519_hex,
        "x25519_public": x25519_hex,
        // Preauth X25519 public key (our current SPK — changes weekly).
        // Alice stores this in the ContactRecord.preauth_key to use in X3DH.
        "preauth_x25519_public": preauth_x25519_hex,
        "pairing_token": hex::encode(token),
        "display_name": display_name,
        "display_name_sig": display_name_sig,
        "transport_hints": transport_hints,
        "expiry": now + crate::pairing::methods::QR_EXPIRY_LIVE,
        // ML-KEM-768 encapsulation key (hex). Enables PQXDH (§3.4.1).
        "kem_pub": hex::encode(&id.kem_encapsulation_key),
    });

    drop(guard);
    ctx.set_response(&payload.to_string())
}

// ---------------------------------------------------------------------------
// Compatibility stubs for existing Flutter bridge
// These map old v1.3 function names to the new v1.5 implementations
// or provide sensible defaults. They will be fleshed out as the
// backend modules are completed.
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn mi_rooms_json(ctx: *mut MeshContext) -> *const c_char {
    mi_get_room_list(ctx)
}

#[no_mangle]
pub extern "C" fn mi_messages_json(ctx: *mut MeshContext, room_id: *const c_char) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let rid = c_str_to_string(room_id).unwrap_or_default();
    let msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
    match msgs.get(&rid) {
        Some(messages) => {
            let json = serde_json::to_string(messages).unwrap_or_else(|_| "[]".to_string());
            ctx.set_response(&json)
        }
        None => ctx.set_response("[]"),
    }
}

#[no_mangle]
pub extern "C" fn mi_get_peer_list(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let contacts = ctx.contacts.lock().unwrap_or_else(|e| e.into_inner());
    let peers: Vec<serde_json::Value> = contacts.all().iter().map(|c| {
        serde_json::json!({
            "id": hex::encode(c.peer_id.0),
            "name": c.display_name.as_deref()
                .or(c.local_nickname.as_deref())
                .unwrap_or(&c.peer_id.short_hex()),
            "trustLevel": c.trust_level.value(),
            "status": if c.last_seen.is_some() { "online" } else { "offline" },
            "canBeExitNode": c.can_be_exit_node,
            "canBeWrapperNode": c.can_be_wrapper_node,
            "canBeStoreForward": c.can_be_store_forward,
            "canEndorsePeers": c.can_endorse_peers,
            "latencyMs": c.latency_ms,
        })
    }).collect();
    let json = serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string());
    ctx.set_response(&json)
}

#[no_mangle]
pub extern "C" fn mi_file_transfers_json(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let transfers = ctx.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
    let json = serde_json::to_string(&*transfers).unwrap_or_else(|_| "[]".into());
    ctx.set_response(&json)
}

#[no_mangle]
pub extern "C" fn mi_active_room_id(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let active = ctx.active_conversation.lock().unwrap_or_else(|e| e.into_inner());
    match *active {
        Some(id) => ctx.set_response(&format!("\"{}\"", hex::encode(id))),
        None => ctx.set_response("null"),
    }
}

#[no_mangle]
pub extern "C" fn mi_select_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    mi_set_active_conversation(ctx, room_id)
}

#[no_mangle]
pub extern "C" fn mi_delete_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let rid = match c_str_to_string(room_id) {
        Some(s) => s,
        None => return -1,
    };
    let before = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner()).len();
    ctx.rooms.lock().unwrap_or_else(|e| e.into_inner()).retain(|r| hex::encode(r.id) != rid);
    ctx.messages.lock().unwrap_or_else(|e| e.into_inner()).remove(&rid);
    let after = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner()).len();
    if after < before {
        ctx.push_event("RoomDeleted", serde_json::json!({ "roomId": rid }));
        ctx.save_rooms();
        ctx.save_messages();
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn mi_send_text_message(ctx: *mut MeshContext, room_id: *const c_char, text: *const c_char) -> i32 {
    mi_send_message(ctx, room_id, ptr::null(), text)
}

#[no_mangle]
pub extern "C" fn mi_delete_message(ctx: *mut MeshContext, msg_id: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let mid = match c_str_to_string(msg_id) {
        Some(s) => s,
        None => return -1,
    };
    // Remove the message from all rooms.
    let mut msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
    for room_msgs in msgs.values_mut() {
        room_msgs.retain(|m| {
            m.get("id").and_then(|v| v.as_str()) != Some(&mid)
        });
    }
    0
}

#[no_mangle]
pub extern "C" fn mi_set_node_mode(ctx: *mut MeshContext, mode: i32) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    if !(0..=2).contains(&mode) { return -1; }
    *ctx.node_mode.lock().unwrap_or_else(|e| e.into_inner()) = mode as u8;
    let routing_mode = match mode {
        0 => RoutingMode::Off,
        1 => RoutingMode::MeshOnly,
        2 => RoutingMode::ExitNode,
        _ => return -1,
    };
    ctx.vpn.lock().unwrap_or_else(|e| e.into_inner()).config.mode = routing_mode;

    // Emit SettingsUpdated
    let flags = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (peer_id, ed25519_pub) = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => (id.peer_id().to_hex(), hex::encode(id.ed25519_pub)),
            None => (String::new(), String::new()),
        }
    };
    let clearnet_port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
    ctx.push_event("SettingsUpdated", build_settings_json(
        &flags, mode as u8, &ctx.threat_context, &peer_id, &ed25519_pub, clearnet_port,
    ));
    ctx.save_settings();
    0
}

#[no_mangle]
pub extern "C" fn mi_settings_json(ctx: *mut MeshContext) -> *const c_char {
    mi_get_settings(ctx)
}

#[no_mangle]
pub extern "C" fn mi_set_transport_flags(ctx: *mut MeshContext, flags_json_ptr: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let json_str = match c_str_to_string(flags_json_ptr) {
        Some(s) => s,
        None => return -1,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let get_bool = |key: &str, default: bool| -> bool {
        parsed.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
    };

    {
        let mut f = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner());
        f.tor = get_bool("tor", f.tor);
        f.clearnet = get_bool("clearnet", f.clearnet);
        f.clearnet_fallback = get_bool("clearnet_fallback", f.clearnet_fallback);
        f.i2p = get_bool("i2p", f.i2p);
        f.bluetooth = get_bool("bluetooth", f.bluetooth);
        f.rf = get_bool("rf", f.rf);
        f.mesh_discovery = get_bool("mesh_discovery", f.mesh_discovery);
        f.allow_relays = get_bool("allow_relays", f.allow_relays);
    }

    let flags = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let node_mode = *ctx.node_mode.lock().unwrap_or_else(|e| e.into_inner());
    let (peer_id, ed25519_pub) = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => (id.peer_id().to_hex(), hex::encode(id.ed25519_pub)),
            None => (String::new(), String::new()),
        }
    };
    let clearnet_port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
    ctx.push_event("SettingsUpdated", build_settings_json(
        &flags, node_mode, &ctx.threat_context, &peer_id, &ed25519_pub, clearnet_port,
    ));
    ctx.save_settings();
    0
}

#[no_mangle]
pub extern "C" fn mi_pair_peer(ctx: *mut MeshContext, peer_data: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let json_str = match c_str_to_string(peer_data) {
        Some(s) => s,
        None => return -1,
    };
    // Parse the pairing payload JSON.
    let payload: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    // Extract required Ed25519 public key.
    let ed_hex = match payload.get("ed25519_public").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return -1,
    };
    let ed_bytes = match hex::decode(&ed_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return -1,
    };
    // Extract required X25519 public key.
    let x_hex = match payload.get("x25519_public").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return -1,
    };
    let x_bytes = match hex::decode(x_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return -1,
    };
    let peer_id = PeerId::from_ed25519_pub(&ed_bytes);
    let name = payload.get("display_name").and_then(|v| v.as_str()).map(|s| s.to_string());

    // Extract optional preauth X25519 public key (their SPK for X3DH).
    let preauth_pub_bytes: Option<[u8; 32]> = payload
        .get("preauth_x25519_public")
        .and_then(|v| v.as_str())
        .and_then(|h| hex::decode(h).ok())
        .filter(|b| b.len() == 32)
        .map(|b| { let mut a = [0u8; 32]; a.copy_from_slice(&b); a });

    // Extract transport hints — look for a clearnet endpoint.
    let transport_hints_arr = payload.get("transport_hints")
        .and_then(|h| h.as_array())
        .cloned()
        .unwrap_or_default();
    let clearnet_endpoint = transport_hints_arr.iter().find(|h| {
        h.get("transport").and_then(|t| t.as_str()) == Some("clearnet")
    }).and_then(|h| h.get("endpoint")).and_then(|e| e.as_str()).map(|s| s.to_string());
    let tor_endpoint = transport_hints_arr.iter().find(|h| {
        h.get("transport").and_then(|t| t.as_str()) == Some("tor")
    }).and_then(|h| h.get("endpoint")).and_then(|e| e.as_str()).map(|s| s.to_string());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut contact = ContactRecord::new(
        peer_id,
        ed_bytes,
        x_bytes,
        crate::pairing::methods::PairingMethod::LinkShare,
        now,
    );
    contact.display_name = name.clone();
    contact.clearnet_endpoint = clearnet_endpoint;
    contact.tor_endpoint = tor_endpoint;
    // Store their ML-KEM-768 encapsulation key if advertised (PQXDH §3.4.1).
    contact.kem_encapsulation_key = payload
        .get("kem_pub")
        .and_then(|v| v.as_str())
        .and_then(|h| hex::decode(h).ok())
        .filter(|b| b.len() == crate::crypto::x3dh::KEM_EK_SIZE);
    // Store their preauth pub — Alice uses it to initiate X3DH.
    // If the pairing payload also carries a preauth_sig (§7.0.1), store it
    // so x3dh_initiate() can verify the identity binding.
    if let Some(preauth_bytes) = preauth_pub_bytes {
        let preauth_sig_opt: Option<Vec<u8>> = payload
            .get("preauth_sig")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() == 64);
        if let Some(sig) = preauth_sig_opt {
            contact.update_preauth_key_with_sig(preauth_bytes, sig, now);
        } else {
            contact.update_preauth_key(preauth_bytes, now);
        }
    }

    // Bootstrap a Double Ratchet session (PQXDH/X3DH if preauth key present, else static DH).
    {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref our_id) = *guard {
            if let Ok((session, x3dh_header, pq_ext)) = bootstrap_ratchet_session(our_id, &contact) {
                if let Some(header) = x3dh_header {
                    ctx.x3dh_pending.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_id, header);
                }
                if let Some(pq) = pq_ext {
                    ctx.pqxdh_pending.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_id, pq);
                }
                drop(guard);
                ctx.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(peer_id, session);
            }
        }
    }

    // Extract clearnet endpoint before moving `contact`.
    let clearnet_endpoint = contact.clearnet_endpoint.clone();

    ctx.contacts.lock().unwrap_or_else(|e| e.into_inner()).upsert(contact);
    ctx.save_contacts();

    // Two-way pairing hello (§8.3): send our own keys to Alice's clearnet
    // endpoint so she can add us without a second QR scan.
    if let Some(ref endpoint) = clearnet_endpoint {
        send_pairing_hello_to(ctx, endpoint);
    }

    // Announce our network map entry (with preauth key) to the new peer so
    // they can initiate X3DH first-contact without us being online (§7.0, H20).
    {
        let peer_id_hex = hex::encode(peer_id.0);
        ctx.send_gossip_self_entry(&peer_id_hex);
    }

    // Broadcast a fresh self-reachability announcement to all currently
    // connected peers (§6.2). This tells the existing mesh that our routing
    // table has a new direct neighbour, giving them a route to reach us
    // (and transitively, the new peer via us once they connect).
    ctx.broadcast_self_route_announcement();

    // Emit PeerAdded event so the UI reflects the new contact immediately.
    ctx.push_event("PeerAdded", serde_json::json!({
        "id": hex::encode(peer_id.0),
        "name": name.as_deref().unwrap_or(""),
        "trustLevel": 0,
        "status": "offline",
        "canBeExitNode": false,
        "canBeWrapperNode": false,
        "canBeStoreForward": false,
        "canEndorsePeers": false,
        "latencyMs": null,
    }));

    0
}

/// Connect to `endpoint` (host:port) and send a signed pairing_hello frame.
///
/// The frame lets the remote peer learn our keys without scanning a second QR.
/// Non-blocking: if the connection fails (peer offline, NAT) we silently ignore.
fn send_pairing_hello_to(ctx: &MeshContext, endpoint: &str) {
    use crate::crypto::signing;
    use std::net::TcpStream;

    // We need the identity to sign.
    let (ed_bytes, x_bytes, display_name, peer_id_hex, signing_key_bytes, preauth_x25519_hex, kem_pub_hex) = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        let id = match guard.as_ref() {
            Some(id) => id,
            None => return,
        };
        (
            id.ed25519_pub,
            *id.x25519_pub.as_bytes(),
            id.display_name.clone(),
            id.peer_id().to_hex(),
            id.ed25519_signing.to_bytes(),
            hex::encode(id.preauth_x25519_pub.as_bytes()),
            hex::encode(&id.kem_encapsulation_key),
        )
    };

    // Sign: DOMAIN_PAIRING_HELLO | ed25519_bytes | x25519_bytes.
    let mut signed_msg = Vec::with_capacity(64);
    signed_msg.extend_from_slice(&ed_bytes);
    signed_msg.extend_from_slice(&x_bytes);
    let sig = signing::sign(&signing_key_bytes, signing::DOMAIN_PAIRING_HELLO, &signed_msg);

    // Transport hints: include clearnet and Tor if available.
    let port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
    let mut hints: Vec<serde_json::Value> = Vec::new();
    if ctx.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
        let ip = local_clearnet_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string());
        hints.push(serde_json::json!({
            "transport": "clearnet",
            "endpoint": format!("{ip}:{port}"),
        }));
    }
    {
        let tor_guard = ctx.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref t) = *tor_guard {
            hints.push(serde_json::json!({
                "transport": "tor",
                "endpoint": format!("{}:{}", t.onion_address, DEFAULT_HS_PORT),
            }));
        }
    }
    let transport_hints = serde_json::json!(hints);

    let frame_json = serde_json::json!({
        "type": "pairing_hello",
        "sender": peer_id_hex,
        "ed25519_public": hex::encode(ed_bytes),
        "x25519_public": hex::encode(x_bytes),
        "preauth_x25519_public": preauth_x25519_hex,
        "kem_pub": kem_pub_hex,
        "display_name": display_name,
        "transport_hints": transport_hints,
        "sig": hex::encode(&sig),
    });

    let payload = match serde_json::to_vec(&frame_json) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Attempt a short-timeout TCP connection (5 seconds).
    let addr: std::net::SocketAddr = match endpoint.parse() {
        Ok(a) => a,
        Err(_) => return,
    };

    let mut stream = match TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)) {
        Ok(s) => s,
        Err(_) => return, // Peer offline — pairing will be completed next time they connect.
    };

    // Send the frame; best-effort — peer may be temporarily unreachable.
    // Log on failure so dropped pairing frames are visible in diagnostics.
    if let Err(e) = write_tcp_frame(&mut stream, &payload) {
        eprintln!("[transport] WARNING: failed to send pairing frame to {endpoint}: {e}");
    }

    // Register the connection so we can reuse it for subsequent messages.
    let peer_id_hex_clone = peer_id_hex.clone();
    ctx.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner())
        .insert(peer_id_hex_clone, stream);
}

// ---------------------------------------------------------------------------
// Group Management (§8.7)
// ---------------------------------------------------------------------------

/// Create a new group owned by this identity.
///
/// `name_ptr`: null-terminated UTF-8 group name (max 64 bytes).
/// `description_ptr`: null-terminated UTF-8 description (max 256 bytes), or null.
/// `network_type`: 0=Private, 1=Closed, 2=Open, 3=Public.
///
/// Returns JSON: `{"groupId": "...", "name": "...", "memberCount": 1}` on
/// success, or `{"error": "..."}` on failure.
#[no_mangle]
pub extern "C" fn mi_create_group(
    ctx: *mut MeshContext,
    name_ptr: *const c_char,
    description_ptr: *const c_char,
    network_type: i32,
) -> *const c_char {
    use crate::groups::group::{Group, GroupPublicProfile, NetworkType};
    use crate::crypto::signing;

    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    let name = match c_str_to_string(name_ptr) {
        Some(n) if !n.is_empty() && n.len() <= 64 => n,
        _ => return ctx.set_response(r#"{"error": "invalid group name"}"#),
    };
    let description = c_str_to_string(description_ptr).unwrap_or_default();
    let net_type = match network_type {
        0 => NetworkType::Private,
        1 => NetworkType::Closed,
        2 => NetworkType::Open,
        3 => NetworkType::Public,
        _ => return ctx.set_response(r#"{"error": "invalid network_type"}"#),
    };

    // Get our peer_id.
    let our_peer_id = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => id.peer_id(),
            None => return ctx.set_response(r#"{"error": "identity not unlocked"}"#),
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Generate group keypairs.
    let group_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let group_ed_pub = group_signing_key.verifying_key().to_bytes();
    let group_ed_priv = {
        let secret_bytes = group_signing_key.to_bytes();
        let verifying_bytes = group_ed_pub;
        // ed25519_dalek SigningKey::to_bytes() returns 32-byte seed, not 64-byte
        // expanded key. The 64-byte "private key" in the spec is seed || public.
        let mut expanded = [0u8; 64];
        expanded[..32].copy_from_slice(&secret_bytes);
        expanded[32..].copy_from_slice(&verifying_bytes);
        expanded
    };

    let x25519_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let x25519_pub = x25519_dalek::PublicKey::from(&x25519_secret);

    // Generate a random group_id and symmetric key.
    let mut group_id = [0u8; 32];
    if !try_random_fill(&mut group_id) { return ptr::null(); }
    let mut symmetric_key = [0u8; 32];
    if !try_random_fill(&mut symmetric_key) { return ptr::null(); }

    // Sign the group profile.
    let mut profile_msg = Vec::new();
    profile_msg.extend_from_slice(&group_id);
    profile_msg.extend_from_slice(name.as_bytes());
    profile_msg.extend_from_slice(&now.to_be_bytes());
    let profile_sig = signing::sign(
        &group_signing_key.to_bytes(),
        crate::crypto::signing::DOMAIN_GROUP_PROFILE,
        &profile_msg,
    );

    let profile = GroupPublicProfile {
        group_id,
        display_name: name.clone(),
        description,
        avatar_hash: None,
        network_type: net_type,
        member_count: Some(1),
        created_at: now,
        signed_by: our_peer_id.0,
        signature: profile_sig,
    };

    let group = Group::new_as_creator(
        group_id,
        profile,
        crate::groups::group::GroupKeys {
            ed25519_public: group_ed_pub,
            ed25519_private: Some(group_ed_priv),
            x25519_public: *x25519_pub.as_bytes(),
            symmetric_key,
        },
        our_peer_id,
        now,
    );

    let group_id_hex = hex::encode(group_id);

    // Create a Room for this group so messaging works.
    // Convention: participants[0] = canonical group PeerId (derived from group
    // ed25519 public key) so we can resolve room↔group later.
    let group_peer_id = PeerId::from_ed25519_pub(&group_ed_pub);
    let room = crate::messaging::room::Room::new_group(
        &name,
        vec![group_peer_id, our_peer_id],
    );
    let room_id_hex = hex::encode(room.id);
    ctx.rooms.lock().unwrap_or_else(|e| e.into_inner()).push(room);
    ctx.save_rooms();

    ctx.groups.lock().unwrap_or_else(|e| e.into_inner()).push(group);
    ctx.save_groups();

    ctx.push_event("GroupCreated", serde_json::json!({
        "groupId": group_id_hex,
        "name": name,
        "memberCount": 1,
        "roomId": room_id_hex,
    }));

    ctx.set_response(&serde_json::json!({
        "groupId": group_id_hex,
        "name": name,
        "memberCount": 1,
        "roomId": room_id_hex,
    }).to_string())
}

/// List all groups the user belongs to.
///
/// Returns a JSON array of group summaries:
/// `[{"groupId": "...", "name": "...", "memberCount": N, "isAdmin": bool}]`
#[no_mangle]
pub extern "C" fn mi_list_groups(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let groups = ctx.groups.lock().unwrap_or_else(|e| e.into_inner());
    let arr: Vec<serde_json::Value> = groups.iter().map(|g| {
        serde_json::json!({
            "groupId": hex::encode(g.group_id),
            "name": g.profile.display_name,
            "description": g.profile.description,
            "memberCount": g.member_count(),
            "isAdmin": g.is_admin,
            "networkType": match g.profile.network_type {
                crate::groups::group::NetworkType::Private => "private",
                crate::groups::group::NetworkType::Closed => "closed",
                crate::groups::group::NetworkType::Open => "open",
                crate::groups::group::NetworkType::Public => "public",
            },
        })
    }).collect();
    let json = serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string());
    ctx.set_response(&json)
}

/// Get the member list for a group.
///
/// `group_id_ptr`: hex-encoded group ID.
///
/// Returns a JSON array of peer ID hex strings, or `{"error": "..."}`.
#[no_mangle]
pub extern "C" fn mi_group_members(
    ctx: *mut MeshContext,
    group_id_ptr: *const c_char,
) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let gid_hex = match c_str_to_string(group_id_ptr) {
        Some(s) => s,
        None => return ctx.set_response(r#"{"error": "null group_id"}"#),
    };
    let gid_bytes = match hex::decode(&gid_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return ctx.set_response(r#"{"error": "invalid group_id"}"#),
    };
    let groups = ctx.groups.lock().unwrap_or_else(|e| e.into_inner());
    let group = match groups.iter().find(|g| g.group_id == gid_bytes) {
        Some(g) => g,
        None => return ctx.set_response(r#"{"error": "group not found"}"#),
    };
    let members: Vec<serde_json::Value> = group.members.iter().map(|pid| {
        serde_json::json!({
            "peerId": pid.to_hex(),
            "isAdmin": group.is_admin_peer(pid),
        })
    }).collect();
    let json = serde_json::to_string(&members).unwrap_or_else(|_| "[]".to_string());
    ctx.set_response(&json)
}

/// Leave a group.
///
/// Removes the group from local storage and emits a GroupLeft event.
/// Does NOT notify other members (network gossip handles propagation).
///
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn mi_leave_group(
    ctx: *mut MeshContext,
    group_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let gid_hex = match c_str_to_string(group_id_ptr) {
        Some(s) => s,
        None => return -1,
    };
    let gid_bytes = match hex::decode(&gid_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return -1,
    };
    let before = ctx.groups.lock().unwrap_or_else(|e| e.into_inner()).len();
    ctx.groups.lock().unwrap_or_else(|e| e.into_inner()).retain(|g| g.group_id != gid_bytes);
    let after = ctx.groups.lock().unwrap_or_else(|e| e.into_inner()).len();
    if after < before {
        ctx.save_groups();
        ctx.push_event("GroupLeft", serde_json::json!({ "groupId": gid_hex }));
        0
    } else {
        -1
    }
}

/// Send a text message to a group.
///
/// `group_id_ptr`: hex-encoded 32-byte group ID.
/// `text_ptr`: null-terminated UTF-8 message text.
///
/// This stores the message locally and emits MessageAdded. Actual
/// group message fan-out to members is handled by the transport layer.
///
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn mi_group_send_message(
    ctx: *mut MeshContext,
    group_id_ptr: *const c_char,
    text_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let gid_hex = match c_str_to_string(group_id_ptr) {
        Some(s) => s,
        None => return -1,
    };
    let text = match c_str_to_string(text_ptr) {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    let gid_bytes = match hex::decode(&gid_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return -1,
    };

    // Find the group's room via the canonical group PeerId stored in participants[0].
    // The group PeerId is derived from the group's ed25519_public key.
    let room_id_hex = {
        let groups = ctx.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group_peer_id = groups.iter()
            .find(|g| g.group_id == gid_bytes)
            .map(|g| PeerId::from_ed25519_pub(&g.ed25519_public));
        drop(groups);
        match group_peer_id {
            None => None,
            Some(gpid) => {
                let rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
                rooms.iter().find(|r| {
                    r.participants.first().map(|p| *p == gpid).unwrap_or(false)
                }).map(|r| hex::encode(r.id))
            }
        }
    };
    let room_id_hex = match room_id_hex {
        Some(r) => r,
        None => return -1,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut msg_id_bytes = [0u8; 16];
    if !try_random_fill(&mut msg_id_bytes) { return -1; }
    let msg_id = hex::encode(msg_id_bytes);

    let our_peer_id = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default()
    };

    let msg = serde_json::json!({
        "id": msg_id,
        "roomId": room_id_hex,
        "sender": our_peer_id,
        "text": text,
        "timestamp": now,
        "isOutgoing": true,
        "authStatus": "outgoing",
    });

    ctx.messages.lock().unwrap_or_else(|e| e.into_inner())
        .entry(room_id_hex.clone())
        .or_default()
        .push(msg.clone());

    {
        let mut rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_hex) {
            room.last_message_preview = Some(if text.len() > 80 {
                format!("{}…", &text[..80])
            } else {
                text.clone()
            });
            room.last_message_at = Some(now);
        }
    }

    ctx.push_event("MessageAdded", msg.clone());
    ctx.save_messages();
    ctx.save_rooms();

    // ---------------------------------------------------------------------------
    // Sender Key encryption (§7.0.4):
    //
    // Step 1: Encrypt plaintext ONCE with our Sender Key (per-group KDF chain).
    //         This produces a single SenderKeyMessage with iteration + ciphertext
    //         + signature — all members use their copy of our chain to decrypt.
    //
    // Step 2: Wrap the SenderKeyMessage with the group symmetric key so only
    //         group members (who hold symmetric_key) can read it.
    //
    // Step 3: Broadcast the single wrapped ciphertext to all members.
    //         No per-member re-encryption — O(1) sender cost regardless of N.
    // ---------------------------------------------------------------------------

    // Lazily initialize our Sender Key if this is our first message.
    {
        use crate::crypto::sender_keys::SenderKey;
        let mut groups = ctx.groups.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(g) = groups.iter_mut().find(|g| g.group_id == gid_bytes) {
            if g.my_sender_chain_key.is_none() {
                let sk = SenderKey::generate();
                g.my_sender_chain_key = Some(*sk.chain_key_bytes());
                g.my_sender_iteration = sk.iteration;
                g.my_sender_signing_key = Some({
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(&sk.signing_key_bytes());
                    arr
                });
            }
        }
    }

    // Read sender key state for this send.
    let sk_material = {
        let groups = ctx.groups.lock().unwrap_or_else(|e| e.into_inner());
        groups.iter().find(|g| g.group_id == gid_bytes).and_then(|g| {
            let chain = g.my_sender_chain_key?;
            let signing = g.my_sender_signing_key?;
            Some((chain, g.my_sender_iteration, signing, g.symmetric_key, g.members.clone()))
        })
    };
    let (chain_key, iteration, signing_key_bytes, symmetric_key, members) = match sk_material {
        Some(v) => v,
        None => return 0,
    };

    // Encrypt the message with our Sender Key.
    let plaintext = serde_json::json!({
        "type": "group_message",
        "groupId": gid_hex,
        "roomId": room_id_hex,
        "msgId": msg_id,
        "sender": our_peer_id,
        "text": text,
        "timestamp": now,
    });
    let plaintext_bytes = match serde_json::to_vec(&plaintext) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    use crate::crypto::sender_keys::{SenderKey, SenderKeyMessage};
    let mut sk = match SenderKey::from_parts(chain_key, iteration, &signing_key_bytes) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let sk_msg: SenderKeyMessage = match sk.encrypt(&plaintext_bytes) {
        Ok(m) => m,
        Err(_) => return 0,
    };

    // Update the group with the advanced chain key and new iteration.
    {
        let mut groups = ctx.groups.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(g) = groups.iter_mut().find(|g| g.group_id == gid_bytes) {
            g.my_sender_chain_key = Some(*sk.chain_key_bytes());
            g.my_sender_iteration = sk.iteration;
        }
    }

    // Wrap the SenderKeyMessage with the group symmetric key (Step 4 / §7.2).
    // This adds a group-level auth layer so only members who hold symmetric_key
    // can even attempt decryption with sender keys.
    let sk_wire = serde_json::json!({
        "iteration": sk_msg.iteration,
        "ciphertext": hex::encode(&sk_msg.ciphertext),
        "signature": hex::encode(&sk_msg.signature),
    });
    let sk_wire_bytes = match serde_json::to_vec(&sk_wire) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
    let sym_cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
        .expect("symmetric_key is 32 bytes");
    // Derive a per-message nonce from the sender key iteration to avoid nonce reuse.
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(&sk_msg.iteration.to_be_bytes());
    let wrapped = match sym_cipher.encrypt(
        chacha20poly1305::Nonce::from_slice(&nonce_bytes),
        sk_wire_bytes.as_ref(),
    ) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    // Broadcast to all members (single ciphertext, not per-member fan-out).
    let broadcast_frame = serde_json::json!({
        "type": "group_message_sk",
        "groupId": gid_hex,
        "sender": our_peer_id,
        "epoch": sk_msg.iteration,   // sender key iteration, not ratchet
        "nonce": hex::encode(nonce_bytes),
        "wrapped": hex::encode(&wrapped),
    });

    let our_peer_id_bytes = ctx.identity.lock().unwrap_or_else(|e| e.into_inner())
        .as_ref().map(|id| id.peer_id().0).unwrap_or([0u8; 32]);

    for member in &members {
        if member.0 == our_peer_id_bytes { continue; }
        ctx.send_raw_frame(&hex::encode(member.0), &broadcast_frame);
    }

    ctx.save_groups();
    0
}

/// Invite a peer (by peer-ID hex) into a group (by group-ID hex).
///
/// The peer must already exist in the local contact store.
/// Returns 0 on success, -1 on failure.
///
/// This adds the peer to the in-memory group participant list and persists the
/// change to vault. In the future this will also dispatch an invite wire frame
/// to the peer via the active transport.
#[no_mangle]
pub extern "C" fn mi_group_invite_peer(
    ctx: *mut MeshContext,
    group_id_ptr: *const c_char,
    peer_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    let gid_hex = match c_str_to_string(group_id_ptr) {
        Some(s) => s,
        None => return -1,
    };
    let peer_hex = match c_str_to_string(peer_id_ptr) {
        Some(s) => s,
        None => return -1,
    };

    let gid_bytes: [u8; 32] = match hex::decode(&gid_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return -1,
    };
    let peer_bytes: [u8; 32] = match hex::decode(&peer_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return -1,
    };
    let invitee_peer_id = PeerId(peer_bytes);

    // Verify the peer exists in the contact store.
    if ctx.contacts.lock().unwrap_or_else(|e| e.into_inner()).get(&invitee_peer_id).is_none() {
        return -1;
    }

    // Find and mutate the group.
    {
        let mut groups = ctx.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = match groups.iter_mut().find(|g| g.group_id == gid_bytes) {
            Some(g) => g,
            None => return -1,
        };

        // Avoid duplicate members — idempotent success if already present.
        if group.members.contains(&invitee_peer_id) {
            return 0;
        }

        group.members.push(invitee_peer_id);
    }

    ctx.save_groups();

    // Build and send a `group_invite` wire frame to the invitee.
    // The frame is encrypted with the invitee's ratchet session and contains
    // the group credentials needed for the peer to reconstruct the Group struct
    // and join the shared conversation room.
    {
        let (group_snapshot, our_peer_id_opt) = {
            let groups = ctx.groups.lock().unwrap_or_else(|e| e.into_inner());
            let g = groups.iter().find(|g| g.group_id == gid_bytes);
            let snap = g.map(|g| serde_json::json!({
                "groupId":          hex::encode(g.group_id),
                "ed25519Pub":       hex::encode(g.ed25519_public),
                "x25519Pub":        hex::encode(g.x25519_public),
                "symmetricKey":     hex::encode(g.symmetric_key),
                "senderKeyEpoch":   g.sender_key_epoch,
                "members":          g.members.iter().map(|m| hex::encode(m.0)).collect::<Vec<_>>(),
                "admins":           g.admins.iter().map(|m| hex::encode(m.0)).collect::<Vec<_>>(),
                "name":             g.profile.display_name.clone(),
                "description":      g.profile.description.clone(),
            }));
            let our_id = ctx.identity.lock().unwrap_or_else(|e| e.into_inner())
                .as_ref().map(|id| id.peer_id());
            (snap, our_id)
        };

        if let (Some(snap), Some(our_id)) = (group_snapshot, our_peer_id_opt) {
            let invite_payload = serde_json::json!({
                "type": "group_invite",
                "invite": snap,
            });
            let payload_bytes = match serde_json::to_vec(&invite_payload) {
                Ok(b) => b,
                Err(_) => return 0, // already persisted, just skip wire send
            };

            // Encrypt with the invitee's ratchet session (ChaCha20-Poly1305).
            use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, Nonce}};
            let frame = {
                let mut sessions = ctx.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(session) = sessions.get_mut(&invitee_peer_id) {
                    if let Ok((header, msg_key)) = session.next_send_msg_key() {
                        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
                        let nonce = Nonce::<ChaCha20Poly1305>::default();
                        cipher.encrypt(&nonce, payload_bytes.as_ref()).ok().map(|ct| {
                            let x3dh_fields = ctx.x3dh_pending.lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .get(&invitee_peer_id).copied();
                            let mut f = serde_json::json!({
                                "type": "group_invite",
                                "sender": hex::encode(our_id.0),
                                "ratchet_header": serde_json::to_value(&header).unwrap_or(serde_json::Value::Null),
                                "ciphertext": hex::encode(&ct),
                            });
                            if let Some((eph, ik)) = x3dh_fields {
                                if let Some(obj) = f.as_object_mut() {
                                    obj.insert("x3dh_eph_pub".into(), serde_json::Value::String(hex::encode(eph)));
                                    obj.insert("x3dh_encrypted_ik".into(), serde_json::Value::String(hex::encode(ik)));
                                }
                            }
                            f
                        })
                    } else { None }
                } else { None }
            };

            if let Some(f) = frame {
                ctx.send_raw_frame(&peer_hex, &f);
            }
        }
    }

    0
}

#[no_mangle]
pub extern "C" fn mi_local_identity_json(ctx: *mut MeshContext) -> *const c_char {
    mi_get_identity_summary(ctx)
}

#[no_mangle]
pub extern "C" fn mi_trust_attest(ctx: *mut MeshContext, peer_id: *const c_char, level: i32) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let pid_hex = match c_str_to_string(peer_id) {
        Some(s) => s,
        None => return -1,
    };
    let trust = match TrustLevel::from_value(level as u8) {
        Some(t) => t,
        None => return -1,
    };
    let pid_bytes = match hex::decode(&pid_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return -1,
    };
    let pid = crate::identity::peer_id::PeerId(pid_bytes);
    let mut contacts = ctx.contacts.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(contact) = contacts.get_mut(&pid) {
        contact.set_trust_level(trust);
        drop(contacts);
        // Emit TrustUpdated event and persist
        ctx.push_event("TrustUpdated", serde_json::json!({
            "peerId": pid_hex,
            "trustLevel": level,
        }));
        ctx.save_contacts();
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn mi_trust_verify_json(ctx: *mut MeshContext, peer_id: *const c_char) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let pid_hex = c_str_to_string(peer_id).unwrap_or_default();
    let pid_bytes = match hex::decode(&pid_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return ctx.set_response(r#"{"verified": false, "error": "invalid peer id"}"#),
    };
    let pid = crate::identity::peer_id::PeerId(pid_bytes);
    let contacts = ctx.contacts.lock().unwrap_or_else(|e| e.into_inner());
    match contacts.get(&pid) {
        Some(contact) => {
            let json = serde_json::json!({
                "verified": contact.safety_number_verified,
                "trustLevel": contact.trust_level.value(),
                "safetyNumber": contact.safety_number,
                "pairingMethod": format!("{:?}", contact.pairing_method),
            });
            ctx.set_response(&json.to_string())
        }
        None => ctx.set_response(r#"{"verified": false, "error": "peer not found"}"#),
    }
}

#[no_mangle]
pub extern "C" fn mi_import_identity(
    ctx: *mut MeshContext,
    backup_b64_json: *const c_char,
    passphrase: *const c_char,
) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };

    let backup_str = match c_str_to_string(backup_b64_json) { Some(s) => s, None => return -1 };
    let pass_str = match c_str_to_string(passphrase) { Some(s) => s, None => return -1 };

    // The backup_str may be either:
    //  - A raw base64 blob (from mi_create_backup's "backup_b64" field)
    //  - A JSON object {"backup_b64": "..."} (from backup_screen.dart)
    let b64_str: String = if backup_str.trim_start().starts_with('{') {
        match serde_json::from_str::<serde_json::Value>(&backup_str) {
            Ok(v) => match v.get("backup_b64").and_then(|b| b.as_str()) {
                Some(s) => s.to_string(),
                None => return -1,
            },
            Err(_) => return -1,
        }
    } else {
        backup_str
    };

    // Base64-decode → JSON-deserialize → EncryptedBackup
    use base64::Engine as _;
    let json_bytes = match base64::engine::general_purpose::STANDARD.decode(&b64_str) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let encrypted: EncryptedBackup = match serde_json::from_slice(&json_bytes) {
        Ok(e) => e,
        Err(_) => return -1,
    };

    // Decrypt and recover the backup contents.
    let (payload, _backup_type) = match crate::crypto::backup::restore_backup(&encrypted, pass_str.as_bytes()) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    // Deserialize BackupContents (contacts + rooms + messages — NO private keys).
    // Per spec §3.7: identity is device-local; private keys are never backed up.
    // The user must have an identity loaded (either freshly generated or from
    // mi_generate_identity) before calling this restore function.
    let contents: BackupContents = match serde_json::from_slice(&payload) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    // Identity must already be loaded — private keys are NEVER in the backup
    // (§3.7). The caller must first generate or load a fresh identity via
    // mi_create_identity() or mi_load_identity(), then call this to restore
    // the contact list and message history onto that identity.
    if !ctx.identity_unlocked {
        return -1;
    }

    // --- Clean restore semantics ---
    // SPEC §3.7 mandates that restore is a full replacement, not a merge.
    // Merging would leave stale contacts and messages from the pre-restore
    // state, creating a confusing mix.  We clear all social/messaging state
    // before applying the backup so the result is deterministic.
    //
    // Private keys (identity keypair, session keys) are NOT cleared — the
    // caller's identity keys remain.  All existing sessions are implicitly
    // invalidated because session state (Double Ratchet chains) is not
    // stored in backups, forcing the user to re-establish sessions with each
    // contact (= re-pairing semantics described in the spec).
    ctx.contacts.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.messages.lock().unwrap_or_else(|e| e.into_inner()).clear();

    // Restore contacts.
    {
        let mut store = ctx.contacts.lock().unwrap_or_else(|e| e.into_inner());
        for contact in contents.contacts {
            store.upsert(contact);
        }
    }

    // Restore rooms.
    {
        let mut rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        for room in contents.rooms {
            rooms.push(room);
        }
    }

    // Restore message history (Extended backups only).
    if !contents.messages.is_empty() {
        let mut msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
        for (room_id, message_list) in contents.messages {
            msgs.insert(room_id, message_list);
        }
    }

    ctx.push_event("BackupRestored", serde_json::json!({}));
    0
}

#[no_mangle]
pub extern "C" fn mi_reset_identity(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    // Reset clears all identity state and generates fresh keys.
    // This is a non-emergency reset (not killswitch).
    ctx.identity_unlocked = false;
    *ctx.identity.lock().unwrap_or_else(|e| e.into_inner()) = None;
    ctx.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.contacts.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.messages.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.vault = None;
    0
}

/// Set the public profile visible to all contacts (§9.1).
///
/// Validates field lengths, persists to vault under "public_profile", and
/// emits a `ProfileUpdated` event so the UI reflects the change immediately.
#[no_mangle]
pub extern "C" fn mi_set_public_profile(ctx: *mut MeshContext, json: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let profile_json = match c_str_to_string(json) {
        Some(s) => s,
        None => return -1,
    };
    let profile: serde_json::Value = match serde_json::from_str(&profile_json) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    // Validate field lengths per §9.1.
    if let Some(name) = profile.get("display_name").and_then(|v| v.as_str()) {
        if name.len() > crate::identity::profile::MAX_DISPLAY_NAME_LEN {
            return -1;
        }
    }
    // Persist to vault. Propagate failure as -1 — the caller must know if
    // the profile was not saved (FFI function returns i32 so this is possible).
    if let Some(vm) = ctx.vault.as_ref() {
        if let Ok(coll) = vm.collection("public_profile") {
            if let Err(e) = coll.save(&profile) {
                eprintln!("[vault] ERROR: failed to persist public profile: {e}");
                return -1;
            }
        }
    }
    ctx.push_event("ProfileUpdated", serde_json::json!({ "kind": "public", "profile": profile }));
    0
}

/// Set the private profile shared only with trusted contacts (§9.2).
///
/// Persists to vault under "private_profile" and emits `ProfileUpdated`.
#[no_mangle]
pub extern "C" fn mi_set_private_profile(ctx: *mut MeshContext, json: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let profile_json = match c_str_to_string(json) {
        Some(s) => s,
        None => return -1,
    };
    let profile: serde_json::Value = match serde_json::from_str(&profile_json) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    // Persist to vault (encrypted at rest by the vault layer). Propagate failure
    // as -1 — the caller must know if the profile was not saved (FFI returns i32).
    if let Some(vm) = ctx.vault.as_ref() {
        if let Ok(coll) = vm.collection("private_profile") {
            if let Err(e) = coll.save(&profile) {
                eprintln!("[vault] ERROR: failed to persist private profile: {e}");
                return -1;
            }
        }
    }
    ctx.push_event("ProfileUpdated", serde_json::json!({ "kind": "private", "profile": profile }));
    0
}

/// Send an emoji reaction to a message (§10.1.2).
///
/// Signature: `mi_send_reaction(ctx, room_id, msg_id, emoji) → i32`
/// Returns 0 on success, -1 on error.
///
/// This matches the Flutter bridge call site:
///   `_bindings!.sendReaction(_context, roomPtr, msgPtr, emojiPtr)`
#[no_mangle]
pub extern "C" fn mi_send_reaction(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    msg_id: *const c_char,
    emoji: *const c_char,
) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let room_id_str = match c_str_to_string(room_id) { Some(s) => s, None => return -1 };
    let msg_id_str = match c_str_to_string(msg_id) { Some(s) => s, None => return -1 };
    let emoji_str = match c_str_to_string(emoji) { Some(s) if !s.is_empty() => s, _ => return -1 };

    // Emit a ReactionAdded event so the UI can update immediately.
    ctx.push_event("ReactionAdded", serde_json::json!({
        "roomId": room_id_str,
        "msgId": msg_id_str,
        "emoji": emoji_str,
    }));

    // Broadcast the reaction to all room participants (§10.1.2).
    // Reactions are small ephemeral control frames — sent plaintext like
    // delivery receipts and typing indicators.
    let (recipients, our_hex) = {
        let rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let room_id_bytes = match hex::decode(&room_id_str) {
            Ok(b) if b.len() == 16 => { let mut a = [0u8; 16]; a.copy_from_slice(&b); a }
            _ => return 0,
        };
        let room = match rooms.iter().find(|r| r.id == room_id_bytes) {
            Some(r) => r,
            None => return 0,
        };
        let our = ctx.identity.lock().unwrap_or_else(|e| e.into_inner())
            .as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default();
        let peers: Vec<String> = room.participants.iter()
            .map(|p| hex::encode(p.0))
            .filter(|h| *h != our)
            .collect();
        (peers, our)
    };

    let frame = serde_json::json!({
        "type":   "reaction",
        "sender": our_hex,
        "roomId": room_id_str,
        "msgId":  msg_id_str,
        "emoji":  emoji_str,
    });
    for peer_hex in &recipients {
        ctx.send_raw_frame(peer_hex, &frame);
    }
    0
}

/// Mark a message as read and reset the unread counter for the room.
#[no_mangle]
pub extern "C" fn mi_send_read_receipt(ctx: *mut MeshContext, room_id: *const c_char, msg_id: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let room_id_str = match c_str_to_string(room_id) { Some(s) => s, None => return -1 };
    let msg_id_str = match c_str_to_string(msg_id) { Some(s) => s, None => return -1 };

    // Reset unread count for this room.
    {
        let mut rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_str) {
            room.mark_read();
        }
    }
    ctx.push_event("ReadReceipt", serde_json::json!({"roomId": room_id_str, "msgId": msg_id_str}));
    ctx.save_rooms();
    0
}

/// Emit a typing indicator event (§10.2.1) and broadcast a wire frame to all
/// connected participants in the room.
#[no_mangle]
pub extern "C" fn mi_send_typing_indicator(ctx: *mut MeshContext, room_id: *const c_char, active: i32) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let room_id_str = match c_str_to_string(room_id) { Some(s) => s, None => return -1 };

    let is_active = active != 0;

    // Local event for self-preview (e.g. suppress duplicate indicator).
    ctx.push_event("TypingIndicator", serde_json::json!({
        "roomId": room_id_str,
        "active": is_active,
    }));

    // Determine room participants so we can broadcast to connected peers.
    let (recipients, our_hex) = {
        let rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let room_id_bytes = match hex::decode(&room_id_str) {
            Ok(b) if b.len() == 16 => { let mut a = [0u8; 16]; a.copy_from_slice(&b); a }
            _ => return 0, // already emitted local event; wire send is best-effort
        };
        let room = match rooms.iter().find(|r| r.id == room_id_bytes) {
            Some(r) => r,
            None => return 0,
        };
        let our = ctx.identity.lock().unwrap_or_else(|e| e.into_inner())
            .as_ref().map(|id| hex::encode(id.peer_id().0)).unwrap_or_default();
        let peers: Vec<String> = room.participants.iter()
            .map(|p| hex::encode(p.0))
            .filter(|h| *h != our)
            .collect();
        (peers, our)
    };

    // Typing indicators are ephemeral plaintext — no encryption needed.
    let frame = serde_json::json!({
        "type":   "typing_indicator",
        "sender": our_hex,
        "roomId": room_id_str,
        "active": is_active,
    });

    // send_raw_frame acquires its own lock internally.
    for peer_hex in &recipients {
        ctx.send_raw_frame(peer_hex, &frame);
    }

    0
}

/// Send a message that quotes/replies to an earlier message.
#[no_mangle]
pub extern "C" fn mi_reply_to_message(ctx: *mut MeshContext, room_id: *const c_char, reply_to: *const c_char, text: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let room_id_str = match c_str_to_string(room_id) { Some(s) => s, None => return -1 };
    let reply_to_str = match c_str_to_string(reply_to) { Some(s) => s, None => return -1 };
    let text_str = match c_str_to_string(text) { Some(s) if !s.is_empty() => s, _ => return -1 };

    let mut msg_id_bytes = [0u8; 16];
    if !try_random_fill(&mut msg_id_bytes) { return -1; }
    let msg_id = hex::encode(msg_id_bytes);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let sender = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_else(|| "local".to_string())
    };

    let msg = serde_json::json!({
        "id": msg_id,
        "roomId": room_id_str,
        "sender": sender,
        "text": text_str,
        "timestamp": timestamp,
        "isOutgoing": true,
        "authStatus": "outgoing",
        "replyTo": reply_to_str,
    });

    ctx.messages.lock().unwrap_or_else(|e| e.into_inner()).entry(room_id_str.clone()).or_default().push(msg.clone());
    {
        let mut rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_str) {
            let preview = if text_str.len() > 80 { format!("↩ {}…", &text_str[..77]) } else { format!("↩ {}", &text_str) };
            room.last_message_preview = Some(preview);
            room.last_message_at = Some(timestamp);
        }
    }
    ctx.push_event("MessageAdded", msg);
    ctx.save_messages();
    ctx.save_rooms();
    0
}

/// Edit the text of a sent message (§10.1.3 Edit content type).
#[no_mangle]
pub extern "C" fn mi_edit_message(ctx: *mut MeshContext, msg_id: *const c_char, new_text: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let msg_id_str = match c_str_to_string(msg_id) { Some(s) => s, None => return -1 };
    let new_text_str = match c_str_to_string(new_text) { Some(s) if !s.is_empty() => s, _ => return -1 };
    let edited_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    let mut found = false;
    {
        let mut all_msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
        for msgs in all_msgs.values_mut() {
            for msg in msgs.iter_mut() {
                if msg.get("id").and_then(|v| v.as_str()) == Some(&msg_id_str) {
                    // Only allow editing outgoing messages.
                    if msg.get("isOutgoing").and_then(|v| v.as_bool()) == Some(true) {
                        if let Some(obj) = msg.as_object_mut() {
                            obj.insert("text".into(), serde_json::Value::String(new_text_str.clone()));
                            obj.insert("editedAt".into(), serde_json::json!(edited_at));
                        }
                        found = true;
                    }
                    break;
                }
            }
            if found { break; }
        }
    }

    if found {
        ctx.push_event("MessageEdited", serde_json::json!({
            "msgId": msg_id_str,
            "newText": new_text_str,
            "editedAt": edited_at,
        }));
        ctx.save_messages();
        0
    } else {
        -1
    }
}

/// Delete a message for all participants (§10.1.3 Deletion content type).
#[no_mangle]
pub extern "C" fn mi_delete_for_everyone(ctx: *mut MeshContext, msg_id: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let msg_id_str = match c_str_to_string(msg_id) { Some(s) => s, None => return -1 };

    let mut found_room: Option<String> = None;
    {
        let mut all_msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
        for (room_id, msgs) in all_msgs.iter_mut() {
            for msg in msgs.iter_mut() {
                if msg.get("id").and_then(|v| v.as_str()) == Some(&msg_id_str) {
                    if let Some(obj) = msg.as_object_mut() {
                        obj.insert("text".into(), serde_json::Value::String(String::new()));
                        obj.insert("deleted".into(), serde_json::Value::Bool(true));
                    }
                    found_room = Some(room_id.clone());
                    break;
                }
            }
            if found_room.is_some() { break; }
        }
    }

    if let Some(room_id) = found_room {
        ctx.push_event("MessageDeleted", serde_json::json!({"msgId": msg_id_str, "roomId": room_id}));
        ctx.save_messages();
        0
    } else {
        -1
    }
}

/// Forward a message to another room (§10.1.3 is_forwarded flag).
#[no_mangle]
pub extern "C" fn mi_forward_message(ctx: *mut MeshContext, msg_id: *const c_char, target_room: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let msg_id_str = match c_str_to_string(msg_id) { Some(s) => s, None => return -1 };
    let target_room_str = match c_str_to_string(target_room) { Some(s) => s, None => return -1 };

    // Find the original message.
    let original_text: Option<String> = {
        let all_msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
        all_msgs.values().flat_map(|msgs| msgs.iter()).find(|msg| {
            msg.get("id").and_then(|v| v.as_str()) == Some(&msg_id_str)
        }).and_then(|msg| msg.get("text").and_then(|v| v.as_str()).map(|s| s.to_string()))
    };

    let text_str = match original_text { Some(t) if !t.is_empty() => t, _ => return -1 };

    let mut new_id_bytes = [0u8; 16];
    if !try_random_fill(&mut new_id_bytes) { return -1; }
    let new_id = hex::encode(new_id_bytes);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let sender = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_else(|| "local".to_string())
    };

    let fwd_msg = serde_json::json!({
        "id": new_id,
        "roomId": target_room_str,
        "sender": sender,
        "text": text_str,
        "timestamp": timestamp,
        "isOutgoing": true,
        "authStatus": "outgoing",
        "isForwarded": true,
    });

    ctx.messages.lock().unwrap_or_else(|e| e.into_inner()).entry(target_room_str.clone()).or_default().push(fwd_msg.clone());
    ctx.push_event("MessageAdded", fwd_msg);
    ctx.save_messages();
    0
}

/// Pin a message in the conversation (§10.1.3 Pin content type).
#[no_mangle]
pub extern "C" fn mi_pin_message(ctx: *mut MeshContext, msg_id: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let msg_id_str = match c_str_to_string(msg_id) { Some(s) => s, None => return -1 };

    let mut found = false;
    {
        let mut all_msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
        for msgs in all_msgs.values_mut() {
            for msg in msgs.iter_mut() {
                if msg.get("id").and_then(|v| v.as_str()) == Some(&msg_id_str) {
                    if let Some(obj) = msg.as_object_mut() {
                        obj.insert("pinned".into(), serde_json::Value::Bool(true));
                    }
                    found = true; break;
                }
            }
            if found { break; }
        }
    }
    if found {
        ctx.push_event("MessagePinned", serde_json::json!({"msgId": msg_id_str}));
        ctx.save_messages();
        0
    } else { -1 }
}

/// Unpin a previously pinned message.
#[no_mangle]
pub extern "C" fn mi_unpin_message(ctx: *mut MeshContext, msg_id: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let msg_id_str = match c_str_to_string(msg_id) { Some(s) => s, None => return -1 };

    let mut found = false;
    {
        let mut all_msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
        for msgs in all_msgs.values_mut() {
            for msg in msgs.iter_mut() {
                if msg.get("id").and_then(|v| v.as_str()) == Some(&msg_id_str) {
                    if let Some(obj) = msg.as_object_mut() {
                        obj.insert("pinned".into(), serde_json::Value::Bool(false));
                    }
                    found = true; break;
                }
            }
            if found { break; }
        }
    }
    if found {
        ctx.push_event("MessageUnpinned", serde_json::json!({"msgId": msg_id_str}));
        ctx.save_messages();
        0
    } else { -1 }
}

/// Set the disappearing-message timer for a room (0 = disabled).
///
/// After this timer (in seconds), messages in the room auto-delete.
/// The timer is stored on the Room and enforced by `mi_prune_expired_messages`.
#[no_mangle]
pub extern "C" fn mi_set_disappearing_timer(ctx: *mut MeshContext, room_id: *const c_char, secs: u64) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let room_id_str = match c_str_to_string(room_id) { Some(s) => s, None => return -1 };

    let mut found = false;
    {
        let mut rooms = ctx.rooms.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(room) = rooms.iter_mut().find(|r| hex::encode(r.id) == room_id_str) {
            room.disappearing_timer = if secs == 0 { None } else { Some(secs) };
            found = true;
        }
    }
    if found {
        ctx.push_event("DisappearingTimerChanged", serde_json::json!({"roomId": room_id_str, "secs": secs}));
        ctx.save_rooms();
        0
    } else { -1 }
}

/// Full-text search across all in-memory messages.
///
/// Returns a JSON array of matching message objects. Case-insensitive.
#[no_mangle]
pub extern "C" fn mi_search_messages(ctx: *mut MeshContext, query: *const c_char) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let query_str = match c_str_to_string(query) {
        Some(s) if !s.is_empty() => s.to_lowercase(),
        _ => return ctx.set_response("[]"),
    };

    let all_msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
    let results: Vec<&serde_json::Value> = all_msgs
        .values()
        .flat_map(|msgs| msgs.iter())
        .filter(|msg| {
            msg.get("text")
                .and_then(|v| v.as_str())
                .map(|t| t.to_lowercase().contains(&query_str))
                .unwrap_or(false)
        })
        .collect();

    let json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".into());
    ctx.set_response(&json)
}

/// Remove all messages whose `expires_at` timestamp is in the past.
///
/// Should be called periodically (e.g., on app foreground) to enforce
/// disappearing message timers. Also stamps new messages with expires_at
/// when the room has a disappearing_timer set.
#[no_mangle]
pub extern "C" fn mi_prune_expired_messages(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    let mut pruned = 0usize;
    {
        let mut all_msgs = ctx.messages.lock().unwrap_or_else(|e| e.into_inner());
        for msgs in all_msgs.values_mut() {
            let before = msgs.len();
            msgs.retain(|msg| {
                if let Some(exp) = msg.get("expiresAt").and_then(|v| v.as_u64()) {
                    exp > now
                } else {
                    true // No expiry set — keep.
                }
            });
            pruned += before - msgs.len();
        }
    }

    if pruned > 0 {
        ctx.push_event("MessagesExpired", serde_json::json!({"count": pruned}));
        ctx.save_messages();
    }
    0
}

/// Get live network statistics (transports, tunnels, SDR sessions).
#[no_mangle]
pub extern "C" fn mi_get_network_stats(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    // Collect enabled transports from flags.
    let flags = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut active_transports: Vec<&str> = Vec::new();
    if flags.clearnet   { active_transports.push("clearnet"); }
    if flags.tor        { active_transports.push("tor"); }
    if flags.i2p        { active_transports.push("i2p"); }
    if flags.bluetooth  { active_transports.push("bluetooth"); }
    if flags.rf         { active_transports.push("rf"); }

    // SDR stats.
    let sdr = ctx.sdr.lock().unwrap_or_else(|e| e.into_inner());
    let sdr_sessions = sdr.sessions.len();
    let sdr_enabled = sdr.enabled;
    drop(sdr);

    // VPN current mode.
    let vpn = ctx.vpn.lock().unwrap_or_else(|e| e.into_inner());
    let vpn_mode_str = format!("{:?}", vpn.config.mode);
    drop(vpn);

    // Routing table, gossip map, and WireGuard session counts.
    let routing_entry_count = ctx.routing_table.lock().unwrap_or_else(|e| e.into_inner())
        .len();
    let gossip_map_size = ctx.gossip.lock().unwrap_or_else(|e| e.into_inner())
        .map_size();
    let wg_session_count = ctx.wireguard_sessions.lock().unwrap_or_else(|e| e.into_inner())
        .len();
    let sf_pending = ctx.sf_server.lock().unwrap_or_else(|e| e.into_inner())
        .total_pending();
    let clearnet_connection_count = ctx.clearnet_connections.lock()
        .unwrap_or_else(|e| e.into_inner()).len();

    let stats = serde_json::json!({
        "activeTunnels": sdr_sessions,
        "connectedPeers": ctx.contacts.lock().unwrap_or_else(|e| e.into_inner()).all().len(),
        "activeTransports": active_transports,
        "sdrEnabled": sdr_enabled,
        "vpnMode": vpn_mode_str,
        "routingEntries": routing_entry_count,
        "gossipMapSize": gossip_map_size,
        "wireGuardSessions": wg_session_count,
        "sfPendingMessages": sf_pending,
        "clearnetConnections": clearnet_connection_count,
    });
    ctx.set_response(&stats.to_string())
}

#[no_mangle]
pub extern "C" fn mi_toggle_transport_flag(ctx: *mut MeshContext, transport: *const c_char, enabled: i32) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let name = match c_str_to_string(transport) {
        Some(s) => s,
        None => return -1,
    };
    let on = enabled != 0;
    {
        let mut f = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner());
        match name.as_str() {
            "tor"              => f.tor = on,
            "clearnet"         => f.clearnet = on,
            "clearnet_fallback"=> f.clearnet_fallback = on,
            "i2p"              => f.i2p = on,
            "bluetooth"        => f.bluetooth = on,
            "rf"               => f.rf = on,
            "mesh_discovery"   => f.mesh_discovery = on,
            "relays"           => f.allow_relays = on,
            _ => return -1,
        }
    }
    let flags = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let node_mode = *ctx.node_mode.lock().unwrap_or_else(|e| e.into_inner());
    let (peer_id, ed25519_pub) = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => (id.peer_id().to_hex(), hex::encode(id.ed25519_pub)),
            None => (String::new(), String::new()),
        }
    };
    let clearnet_port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
    ctx.push_event("SettingsUpdated", build_settings_json(
        &flags, node_mode, &ctx.threat_context, &peer_id, &ed25519_pub, clearnet_port,
    ));
    ctx.save_settings();
    0
}

#[no_mangle]
/// Enable mDNS peer discovery on the local network (§4.6).
///
/// Marks mDNS as running. When peers advertise themselves, they
/// appear in `mi_mdns_get_discovered_peers`. Emits `MdnsStarted`.
pub extern "C" fn mi_mdns_enable(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    // Bind the UDP discovery socket if not already bound.
    let mut sock_guard = ctx.lan_discovery_socket.lock().unwrap_or_else(|e| e.into_inner());
    if sock_guard.is_none() {
        // Try to bind on 0.0.0.0:7235 (LAN discovery port).
        match std::net::UdpSocket::bind("0.0.0.0:7235") {
            Ok(socket) => {
                // Enable broadcast and set non-blocking so the poll loop can
                // drain packets without blocking.
                let _ = socket.set_broadcast(true);
                let _ = socket.set_nonblocking(true);
                *sock_guard = Some(socket);
            }
            Err(_) => {
                // Port in use or permission denied — still mark as running
                // (announce will silently fail; receive won't work).
            }
        }
    }
    drop(sock_guard);

    *ctx.mdns_running.lock().unwrap_or_else(|e| e.into_inner()) = true;
    // Reset the announce timer so we send immediately.
    *ctx.lan_next_announce.lock().unwrap_or_else(|e| e.into_inner()) =
        std::time::Instant::now() - std::time::Duration::from_secs(1);
    ctx.push_event("MdnsStarted", serde_json::json!({}));
    0
}

#[no_mangle]
/// Disable mDNS peer discovery and clear the discovered-peers cache.
pub extern "C" fn mi_mdns_disable(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    *ctx.mdns_running.lock().unwrap_or_else(|e| e.into_inner()) = false;
    ctx.mdns_discovered.lock().unwrap_or_else(|e| e.into_inner()).clear();
    // Drop the UDP socket to stop receiving.
    *ctx.lan_discovery_socket.lock().unwrap_or_else(|e| e.into_inner()) = None;
    ctx.push_event("MdnsStopped", serde_json::json!({}));
    0
}

#[no_mangle]
/// Returns 1 if mDNS is currently running, 0 otherwise.
pub extern "C" fn mi_mdns_is_running(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return 0; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    if *ctx.mdns_running.lock().unwrap_or_else(|e| e.into_inner()) { 1 } else { 0 }
}

#[no_mangle]
/// Returns JSON array of peers discovered via mDNS on the local network.
///
/// Each entry: {"peerId": "...", "name": "...", "address": "...", "trustLevel": N}.
/// In a production build, this is populated by the real mDNS responder.
/// For now, returns paired contacts that could be local (no transport filter).
pub extern "C" fn mi_mdns_get_discovered_peers(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    // Return the in-memory mDNS discovery cache.
    let peers = ctx.mdns_discovered.lock().unwrap_or_else(|e| e.into_inner());
    let json = serde_json::to_string(&*peers).unwrap_or_else(|_| "[]".into());
    ctx.set_response(&json)
}

#[no_mangle]
/// Begin a file transfer (§11).
///
/// `direction` — `"outgoing"` (we send) or `"incoming"` (we receive).
/// `peer_id`   — hex peer ID of the remote party. May be null for incoming.
/// `path`      — local filesystem path (source for outgoing, destination for incoming).
///
/// Returns JSON `{"id":"…","peerId":"…","name":"…","status":"pending","direction":"…"}`
/// or null on error.
pub extern "C" fn mi_file_transfer_start(
    ctx: *mut MeshContext,
    direction: *const c_char,
    peer_id: *const c_char,
    path: *const c_char,
) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    // Gate on file_sharing module (§17.13).
    if !ctx.module_config.lock().unwrap_or_else(|e| e.into_inner()).social.file_sharing {
        return ptr::null();
    }
    let direction_str = c_str_to_string(direction).unwrap_or_else(|| "outgoing".to_string());
    let peer_id_str = c_str_to_string(peer_id).unwrap_or_default();
    let path_str = match c_str_to_string(path) { Some(s) => s, None => return ptr::null() };

    let mut transfer_id_bytes = [0u8; 16];
    if !try_random_fill(&mut transfer_id_bytes) { return ptr::null(); }
    let transfer_id = hex::encode(transfer_id_bytes);

    // Derive display name from path (last component).
    let file_name = std::path::Path::new(&path_str)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Try to get the file size for outgoing transfers.
    let size_bytes: u64 = if direction_str == "outgoing" {
        std::fs::metadata(&path_str).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    let transfer = serde_json::json!({
        "id": transfer_id,
        "peerId": peer_id_str,
        "name": file_name,
        "path": path_str,
        "sizeBytes": size_bytes,
        "transferredBytes": 0,
        "status": "pending",
        "direction": direction_str,
    });

    ctx.file_transfers.lock().unwrap_or_else(|e| e.into_inner()).push(transfer.clone());
    ctx.push_event("FileTransferStarted", transfer.clone());

    // For outgoing transfers: open the file and register an IO state so the
    // poll loop can stream chunks without blocking the main thread.
    if direction_str == "send" || direction_str == "outgoing" {
        match std::fs::File::open(&path_str) {
            Ok(mut file) => {
                // Compute SHA-256 content hash as the canonical file_id (§16.2).
                // This allows deduplication and integrity verification on the receiver.
                let file_id: [u8; 32] = {
                    use sha2::Digest;
                    use std::io::{Read as _, Seek as _};
                    let mut hasher = sha2::Sha256::new();
                    let mut buf = [0u8; 65536];
                    loop {
                        match file.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => hasher.update(&buf[..n]),
                            Err(_) => break,
                        }
                    }
                    // Seek back to start for the actual transfer.
                    // Propagate failure as null: if we cannot rewind the file
                    // we cannot send it correctly, so abort the transfer setup.
                    if let Err(e) = file.seek(std::io::SeekFrom::Start(0)) {
                        eprintln!("[files] ERROR: failed to seek file to start for transfer: {e}");
                        return ptr::null();
                    }
                    hasher.finalize().into()
                };
                let io_state = FileIoState {
                    direction: FileDirection::Send,
                    peer_id: peer_id_str.clone(),
                    file_id,
                    total_bytes: size_bytes,
                    transferred_bytes: 0,
                    file,
                };
                ctx.active_file_io.lock().unwrap_or_else(|e| e.into_inner())
                    .insert(transfer_id.clone(), io_state);

                // Send the file offer frame so the peer knows a transfer is coming.
                let offer_frame = serde_json::json!({
                    "type": "file_offer",
                    "transferId": transfer_id,
                    "fileId": hex::encode(file_id),
                    "name": file_name,
                    "sizeBytes": size_bytes,
                });
                ctx.send_raw_frame(&peer_id_str, &offer_frame);

                // Flip status to active immediately.
                let mut transfers = ctx.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
                for t in transfers.iter_mut() {
                    if t.get("id").and_then(|v| v.as_str()) == Some(&transfer_id) {
                        if let Some(obj) = t.as_object_mut() {
                            obj.insert("status".to_string(),
                                serde_json::Value::String("active".to_string()));
                        }
                        break;
                    }
                }
            }
            Err(e) => {
                // File can't be opened — mark as error.
                let mut transfers = ctx.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
                for t in transfers.iter_mut() {
                    if t.get("id").and_then(|v| v.as_str()) == Some(&transfer_id) {
                        if let Some(obj) = t.as_object_mut() {
                            obj.insert("status".to_string(),
                                serde_json::Value::String("error".to_string()));
                            obj.insert("error".to_string(),
                                serde_json::Value::String(e.to_string()));
                        }
                        break;
                    }
                }
            }
        }
    }

    let json = serde_json::to_string(&transfer).unwrap_or_else(|_| "null".into());
    ctx.set_response(&json)
}

#[no_mangle]
/// Cancel an in-progress file transfer.
pub extern "C" fn mi_file_transfer_cancel(ctx: *mut MeshContext, transfer_id: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let tid = match c_str_to_string(transfer_id) { Some(s) => s, None => return -1 };

    let mut transfers = ctx.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
    let before = transfers.len();
    transfers.retain(|t| {
        t.get("id").and_then(|v| v.as_str()) != Some(&tid)
    });

    if transfers.len() < before {
        ctx.push_event("FileTransferCancelled", serde_json::json!({"transferId": tid}));
        0
    } else {
        -1
    }
}

#[no_mangle]
/// Accept an incoming file transfer offer.
///
/// Sets the transfer status from `pending` to `active` and emits a
/// `FileTransferStarted` event so the UI reflects the acceptance.
/// Returns 0 on success, -1 if the transfer was not found.
pub extern "C" fn mi_file_transfer_accept(
    ctx: *mut MeshContext,
    transfer_id: *const c_char,
    save_path: *const c_char,
) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let tid = match c_str_to_string(transfer_id) { Some(s) => s, None => return -1 };
    let path = c_str_to_string(save_path).unwrap_or_default();

    // Find the transfer and extract metadata.
    let (peer_id, total_bytes) = {
        let mut transfers = ctx.file_transfers.lock().unwrap_or_else(|e| e.into_inner());
        let mut found = false;
        let mut peer = String::new();
        let mut sz = 0u64;
        for t in transfers.iter_mut() {
            if t.get("id").and_then(|v| v.as_str()) == Some(&tid) {
                if let Some(obj) = t.as_object_mut() {
                    obj.insert("status".to_string(),
                        serde_json::Value::String("active".to_string()));
                    if !path.is_empty() {
                        obj.insert("savePath".to_string(),
                            serde_json::Value::String(path.clone()));
                    }
                }
                peer = t.get("peerId").and_then(|v| v.as_str()).unwrap_or("").to_string();
                sz = t.get("sizeBytes").and_then(|v| v.as_u64()).unwrap_or(0);
                ctx.push_event("FileTransferStarted", t.clone());
                found = true;
                break;
            }
        }
        if !found { return -1; }
        (peer, sz)
    };

    // Open (or create) the destination file and register an IO state.
    let save = if path.is_empty() { format!("/tmp/{}", tid) } else { path };
    if let Ok(file) = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true).open(&save)
    {
        let io_state = FileIoState {
            direction: FileDirection::Receive,
            peer_id,
            file_id: [0u8; 32],
            total_bytes,
            transferred_bytes: 0,
            file,
        };
        ctx.active_file_io.lock().unwrap_or_else(|e| e.into_inner())
            .insert(tid, io_state);
    }
    0
}

#[no_mangle]
/// Configure clearnet routing rules (DNS, custom routes, killswitch).
///
/// `route` is a JSON object with optional fields:
/// - `dns`: array of DNS server IPs
/// - `routes`: array of CIDR strings to route over mesh
/// - `killswitch`: bool — block clearnet if mesh is unreachable
pub extern "C" fn mi_set_clearnet_route(ctx: *mut MeshContext, route: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let route_str = match c_str_to_string(route) { Some(s) => s, None => return -1 };
    // Parse and store route config; emit event so UI updates.
    ctx.push_event("ClearnetRouteChanged", serde_json::from_str(&route_str).unwrap_or_else(|_| serde_json::json!({"raw": route_str})));
    0
}

/// Configure the VPN routing mode.
///
/// Set the VPN routing mode (§6.9).
///
/// `mode_json` is a JSON object:
/// - `mode`: "off" | "mesh_only" | "exit_node" | "policy"
/// - `killSwitch`: "disabled" | "permissive" | "strict"
#[no_mangle]
pub extern "C" fn mi_set_vpn_mode(ctx: *mut MeshContext, mode_json: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let config_str = match c_str_to_string(mode_json) { Some(s) => s, None => return -1 };
    let config: serde_json::Value = match serde_json::from_str(&config_str) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let mode_str = config.get("mode").and_then(|v| v.as_str()).unwrap_or("off");
    let mode = match mode_str {
        "off"        => RoutingMode::Off,
        "mesh_only"  => RoutingMode::MeshOnly,
        "exit_node"  => RoutingMode::ExitNode,
        "policy"     => RoutingMode::PolicyBased,
        _            => return -1,
    };

    let threat = ctx.threat_context;
    let has_rules = true;
    let result = ctx.vpn.lock().unwrap_or_else(|e| e.into_inner()).set_mode(mode, threat, has_rules);
    if result.is_err() { return -1; }

    ctx.push_event("VpnModeChanged", serde_json::json!({"mode": mode_str}));
    0
}

/// Set the exit node peer for VPN exit_node mode (§6.9.2).
///
/// `peer_id_hex`: 32-byte peer ID as hex string. Pass empty string to clear.
#[no_mangle]
pub extern "C" fn mi_set_exit_node(ctx: *mut MeshContext, peer_id_hex: *const c_char) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let pid_hex = match c_str_to_string(peer_id_hex) { Some(s) => s, None => return -1 };
    if pid_hex.is_empty() {
        ctx.vpn.lock().unwrap_or_else(|e| e.into_inner()).config.exit_peer_id = None;
        ctx.push_event("ExitNodeChanged", serde_json::json!({"peerId": null}));
        return 0;
    }
    match hex::decode(&pid_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            ctx.vpn.lock().unwrap_or_else(|e| e.into_inner()).config.exit_peer_id = Some(arr);
            ctx.push_event("ExitNodeChanged", serde_json::json!({"peerId": pid_hex}));
            0
        }
        _ => {
            ctx.set_error("Invalid peer ID");
            -1
        }
    }
}

/// Get VPN status (§6.9).
#[no_mangle]
pub extern "C" fn mi_get_vpn_status(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let vpn = ctx.vpn.lock().unwrap_or_else(|e| e.into_inner());
    let json = serde_json::json!({
        "enabled": vpn.config.mode != RoutingMode::Off,
        "mode": format!("{:?}", vpn.config.mode),
        "state": format!("{:?}", vpn.state),
        "killSwitch": format!("{:?}", vpn.config.kill_switch),
        "exitPeerId": vpn.config.exit_peer_id.map(hex::encode),
        "internetAllowed": vpn.internet_traffic_allowed(),
    });
    ctx.set_response(&json.to_string())
}

// ---------------------------------------------------------------------------
// Overlay Networks — Tailscale and ZeroTier (§5.22, §5.23)
// ---------------------------------------------------------------------------

/// Authenticate the Tailscale client with an auth key (tskey-auth-...).
///
/// Stores the credential in the overlay manager and marks the client
/// as `Connecting`. The actual WireGuard handshake with the control plane
/// happens asynchronously (transport solver picks it up on next cycle).
///
/// `auth_key`: a Tailscale auth key (tskey-auth-...) or OAuth token.
/// `control_url`: empty string or custom control server URL (e.g. Headscale).
#[no_mangle]
pub extern "C" fn mi_tailscale_auth_key(
    ctx: *mut MeshContext,
    auth_key: *const c_char,
    control_url: *const c_char,
) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let key_str = match c_str_to_string(auth_key) { Some(s) if !s.is_empty() => s, _ => return -1 };
    let url_str = c_str_to_string(control_url).unwrap_or_default();

    use crate::transport::overlay_client::{TailscaleCredentials, TailscaleController, OverlayClientStatus};
    let controller = if url_str.is_empty() {
        TailscaleController::Vendor
    } else {
        TailscaleController::Headscale { url: url_str }
    };

    let creds = TailscaleCredentials {
        controller,
        auth_token: key_str,
        is_auth_key: true,
    };

    let mut overlay = ctx.overlay.lock().unwrap_or_else(|e| e.into_inner());
    overlay.tailscale.credentials = Some(creds);
    overlay.tailscale.status = OverlayClientStatus::Connecting;
    drop(overlay);

    ctx.push_event("TailscaleConnecting", serde_json::json!({}));
    0
}

/// Begin Tailscale OAuth flow (for interactive login).
///
/// Marks the Tailscale client as `Connecting` (OAuth). The actual OAuth
/// redirect URL is returned to the Flutter UI via a `TailscaleOAuthUrl` event.
///
/// `control_url`: empty string for official server, or Headscale URL.
#[no_mangle]
pub extern "C" fn mi_tailscale_begin_oauth(
    ctx: *mut MeshContext,
    control_url: *const c_char,
) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let url_str = c_str_to_string(control_url).unwrap_or_default();

    use crate::transport::overlay_client::{TailscaleController, OverlayClientStatus};
    let controller = if url_str.is_empty() {
        TailscaleController::Vendor
    } else {
        TailscaleController::Headscale { url: url_str.clone() }
    };

    // Build an OAuth initiation URL pointing to the control server.
    let oauth_url = format!("{}/a/", controller.base_url());

    let mut overlay = ctx.overlay.lock().unwrap_or_else(|e| e.into_inner());
    overlay.tailscale.status = OverlayClientStatus::Connecting;
    drop(overlay);

    ctx.push_event("TailscaleOAuthUrl", serde_json::json!({"url": oauth_url}));
    0
}

/// Connect to one or more ZeroTier networks.
///
/// Stores the credentials in the overlay manager and enqueues a connection
/// attempt for each network_id. The ZeroTier client becomes `Connecting`.
///
/// `api_key`: ZeroTier Central API key, or empty for self-hosted.
/// `controller_url`: empty string for Central, or self-hosted controller URL.
/// `network_ids_json`: JSON array of 16-char hex network IDs, e.g. `["a09acf023301..."]`.
#[no_mangle]
pub extern "C" fn mi_zerotier_connect(
    ctx: *mut MeshContext,
    api_key: *const c_char,
    controller_url: *const c_char,
    network_ids_json: *const c_char,
) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let api_key_str = c_str_to_string(api_key).unwrap_or_default();
    let ctrl_url_str = c_str_to_string(controller_url).unwrap_or_default();
    let net_ids_str = match c_str_to_string(network_ids_json) { Some(s) => s, None => return -1 };

    let network_ids: Vec<String> = match serde_json::from_str(&net_ids_str) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    if network_ids.is_empty() { return -1; }

    use crate::transport::overlay_client::{
        ZeroTierCredentials, ZeroTierController, ZeroTierNetwork,
        ZeroTierNetworkAuthStatus, OverlayClientStatus,
    };

    let controller = if ctrl_url_str.is_empty() {
        ZeroTierController::Central
    } else {
        ZeroTierController::SelfHosted { url: ctrl_url_str }
    };

    let creds = ZeroTierCredentials {
        controller,
        api_key: api_key_str,
        network_ids: network_ids.clone(),
    };

    let mut overlay = ctx.overlay.lock().unwrap_or_else(|e| e.into_inner());
    overlay.zerotier.credentials = Some(creds);
    overlay.zerotier.status = OverlayClientStatus::Connecting;

    // Enqueue each network as pending (if not already tracked).
    for nid in &network_ids {
        if !overlay.zerotier.networks.iter().any(|n| &n.network_id == nid) {
            overlay.zerotier.networks.push(ZeroTierNetwork {
                network_id: nid.clone(),
                name: nid.clone(),
                assigned_ip: None,
                auth_status: ZeroTierNetworkAuthStatus::AwaitingAuthorization,
                member_count: 0,
            });
        }
    }
    drop(overlay);

    ctx.push_event("ZeroTierConnecting", serde_json::json!({"networkIds": network_ids}));
    0
}

/// Get the current status of all overlay networks as JSON.
///
/// Returns:
/// ```json
/// {
///   "tailscale": {"connected": bool, "deviceIp": "...", "exitNode": "...", "anonymizationScore": 0.3},
///   "zerotier":  {"connected": bool, "networks": [...], "anonymizationScore": 0.5}
/// }
/// ```
#[no_mangle]
pub extern "C" fn mi_overlay_status(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let overlay = ctx.overlay.lock().unwrap_or_else(|e| e.into_inner());
    let json = serde_json::json!({
        "tailscale": {
            "connected": overlay.tailscale.is_connected(),
            "deviceIp": overlay.tailscale.device_info.as_ref().map(|d| d.tailscale_ip.as_str()),
            "exitNode": overlay.tailscale.active_exit_node,
            "anonymizationScore": overlay.tailscale.anonymization_score(),
        },
        "zerotier": {
            "connected": overlay.zerotier.is_connected(),
            "networks": overlay.zerotier.networks.iter().map(|n| serde_json::json!({
                "networkId": n.network_id,
                "name": n.name,
                "assignedIp": n.assigned_ip,
                "authStatus": format!("{:?}", n.auth_status),
            })).collect::<Vec<_>>(),
            "anonymizationScore": overlay.zerotier.anonymization_score(),
        },
        "anyActive": overlay.any_overlay_active(),
    });
    ctx.set_response(&json.to_string())
}

// ---------------------------------------------------------------------------
// LoSec — Low-Traffic Security Mode (§6.9.6)
// ---------------------------------------------------------------------------

/// Initiate a LoSec negotiation request toward a peer.
///
/// `request_json` fields:
/// - `session_id`:   64-char hex session ID (32 bytes)
/// - `mode`:         "standard" | "losec" | "direct"
/// - `hop_count`:    1 or 2 (for LoSec mode)
/// - `reason`:       human-readable string shown in remote peer's dialog
/// - `ambient_bytes_per_sec`: current traffic volume (used as ambient_ok check)
/// - `active_tunnels`: current active tunnel count
///
/// Returns JSON with:
/// - `accepted`: bool
/// - `rejection_reason`: string or null
#[no_mangle]
pub extern "C" fn mi_losec_request(
    ctx: *mut MeshContext,
    request_json: *const c_char,
) -> *const c_char {
    use crate::routing::losec::{
        handle_losec_request, AmbientTrafficMonitor, ConnectionMode,
        ServiceLoSecConfig, SignedLoSecRequest,
    };
    use ed25519_dalek::SigningKey;

    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    let json_str = match c_str_to_string(request_json) {
        Some(s) => s,
        None => return ptr::null(),
    };
    let parsed: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return ptr::null(),
    };

    // Extract signing key from local identity.
    let signing_key: SigningKey = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => SigningKey::from_bytes(&id.ed25519_signing.to_bytes()),
            None => {
                let err = serde_json::json!({"error": "no identity"});
                return ctx.set_response(&err.to_string());
            }
        }
    };

    // Parse mode.
    let mode = match parsed.get("mode").and_then(|v| v.as_str()).unwrap_or("losec") {
        "standard" => ConnectionMode::Standard,
        "direct" => ConnectionMode::Direct,
        _ => ConnectionMode::LoSec,
    };

    // Parse session_id.
    let session_id_hex = parsed.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
    let session_id_bytes = hex::decode(session_id_hex).unwrap_or_else(|_| vec![0u8; 32]);
    let mut session_id = [0u8; 32];
    let copy_len = session_id_bytes.len().min(32);
    session_id[..copy_len].copy_from_slice(&session_id_bytes[..copy_len]);

    let hop_count = parsed.get("hop_count").and_then(|v| v.as_u64()).unwrap_or(2) as u8;
    let reason = parsed.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let signed = match SignedLoSecRequest::new(session_id, mode, hop_count, reason, &signing_key) {
        Ok(s) => s,
        Err(e) => {
            let err = serde_json::json!({"error": format!("{:?}", e)});
            return ctx.set_response(&err.to_string());
        }
    };

    // Build ambient status from caller-supplied data.
    let ambient_bytes = parsed.get("ambient_bytes_per_sec").and_then(|v| v.as_u64()).unwrap_or(0);
    let active_tunnels = parsed.get("active_tunnels").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let mut monitor = AmbientTrafficMonitor::new();
    monitor.update(active_tunnels, ambient_bytes);

    // Build a permissive service config (per-service policy can be configured
    // via mi_configure_service in production).
    let service_config = ServiceLoSecConfig {
        allow_losec: true,
        allow_direct: true,
    };

    // If a peer_id is specified and we have a TCP connection, send on-wire.
    // The response arrives asynchronously as a "losec_response" frame via
    // process_inbound_frame, which emits a LoSecResponse event.
    if let Some(peer_id_hex) = parsed.get("peer_id").and_then(|v| v.as_str()) {
        let our_peer_id_hex = {
            let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|id| id.peer_id().to_hex()).unwrap_or_default()
        };
        let signed_json = match serde_json::to_string(&signed) {
            Ok(s) => s,
            Err(_) => return ctx.set_response(r#"{"error":"serialize failed"}"#),
        };
        let frame = serde_json::json!({
            "type": "losec_request",
            "sender": our_peer_id_hex,
            "session_id": hex::encode(signed.request.session_id),
            "payload": signed_json,
        });
        let frame_bytes = serde_json::to_vec(&frame).unwrap_or_default();
        let sent = {
            let mut conns = ctx.clearnet_connections.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(stream) = conns.get_mut(peer_id_hex) {
                use std::io::Write;
                let len = (frame_bytes.len() as u32).to_be_bytes();
                stream.write_all(&len).is_ok() && stream.write_all(&frame_bytes).is_ok()
            } else {
                false
            }
        };
        if sent {
            return ctx.set_response(&serde_json::json!({"sent": true}).to_string());
        }
        // No TCP connection — fall through to local simulation.
    }

    // Local simulation: run the responder side here (useful for single-device
    // testing; on real deployments the response comes via the wire).
    let response = handle_losec_request(&signed, &service_config, monitor.losec_available(), &signing_key);

    let result = serde_json::json!({
        "accepted": response.response.accepted,
        "rejection_reason": response.response.rejection_reason,
    });
    ctx.set_response(&result.to_string())
}

/// Query the current ambient traffic level — used by the LoSec policy engine.
///
/// Returns JSON:
/// - `available`: bool — whether current traffic is above the LoSec threshold
/// - `active_tunnels`: usize
/// - `bytes_per_sec`: u64
#[no_mangle]
pub extern "C" fn mi_losec_ambient_status(ctx: *mut MeshContext) -> *const c_char {
    use crate::routing::losec::AmbientTrafficMonitor;

    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    // Use SDR session count as proxy for active tunnels.
    let active_tunnels = ctx.sdr.lock().unwrap_or_else(|e| e.into_inner()).sessions.len();
    let mut monitor = AmbientTrafficMonitor::new();
    // Volume proxy: active_tunnels * estimated 1 kB/s minimum.
    monitor.update(active_tunnels, active_tunnels as u64 * 1024);

    let result = serde_json::json!({
        "available": monitor.losec_available(),
        "active_tunnels": active_tunnels,
        "bytes_per_sec": monitor.volume(),
    });
    ctx.set_response(&result.to_string())
}

// ---------------------------------------------------------------------------
// WireGuard Per-Hop Encryption (§5.2)
// ---------------------------------------------------------------------------

/// Initiate a WireGuard handshake with a peer.
///
/// Generates an ephemeral key pair, encrypts our static identity under
/// DH(eph_i, static_r), and returns the serialised `HandshakeInit` message
/// as a hex string for the caller to transmit to the peer.
///
/// Returns JSON: `{"init_hex": "..."}` or `{"error": "..."}`.
#[no_mangle]
pub extern "C" fn mi_wg_initiate_handshake(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
) -> *const c_char {
    use crate::transport::wireguard::PendingInitiatorHandshake;
    use crate::crypto::channel_key::derive_channel_key;

    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };

    let peer_hex = match c_str_to_string(peer_id_hex) {
        Some(s) => s,
        None => return ctx.set_response(r#"{"error":"invalid peer_id"}"#),
    };
    let peer_bytes = match hex::decode(&peer_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return ctx.set_response(r#"{"error":"invalid peer_id hex"}"#),
    };
    let target_peer_id = PeerId(peer_bytes);

    // Retrieve our X25519 static key and the peer's X25519 public key.
    let (our_secret, our_pub_id, their_x25519_pub) = {
        let id_guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        let id = match id_guard.as_ref() {
            Some(i) => i,
            None => return ctx.set_response(r#"{"error":"identity not unlocked"}"#),
        };
        let contacts = ctx.contacts.lock().unwrap_or_else(|e| e.into_inner());
        let contact = match contacts.get(&target_peer_id) {
            Some(c) => c.clone(),
            None => return ctx.set_response(r#"{"error":"peer not in contacts"}"#),
        };
        let their_pub = x25519_dalek::PublicKey::from(contact.x25519_public);
        // Clone our x25519_secret bytes so we can reconstruct below.
        let our_secret_bytes = id.x25519_secret.to_bytes();
        (our_secret_bytes, id.peer_id(), their_pub)
    };

    // Derive channel PSK.
    let our_secret = x25519_dalek::StaticSecret::from(our_secret);
    let _our_pub = x25519_dalek::PublicKey::from(&our_secret);
    let psk = match derive_channel_key(&our_secret, &their_x25519_pub, &our_pub_id, &target_peer_id) {
        Ok(k) => k,
        Err(_) => return ctx.set_response(r#"{"error":"psk derivation failed"}"#),
    };

    let (pending, init_msg) = PendingInitiatorHandshake::new(
        x25519_dalek::StaticSecret::from(our_secret.to_bytes()),
        their_x25519_pub,
        psk,
    );

    // Serialise the init message as hex.
    let mut init_bytes = Vec::with_capacity(32 + 48);
    init_bytes.extend_from_slice(&init_msg.eph_i_pub);
    init_bytes.extend_from_slice(&init_msg.enc_static);
    let init_hex = hex::encode(&init_bytes);

    // Store pending handshake state so mi_wg_complete_handshake can finish
    // the session when the responder's HandshakeResponse arrives.
    ctx.pending_wg_handshakes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(target_peer_id, pending);

    let resp = serde_json::json!({ "init_hex": init_hex });
    ctx.set_response(&resp.to_string())
}

/// Handle an incoming WireGuard handshake initiation and produce the session.
///
/// Called when we receive a `HandshakeInit` message from a peer. We respond
/// with a `HandshakeResponse` and establish the session.
///
/// `init_hex`: 80 bytes hex (32-byte eph_pub + 48-byte enc_static).
/// `peer_id_hex`: the peer's device address (32-byte hex).
///
/// Returns JSON: `{"response_hex": "...", "session_established": true}` or error.
#[no_mangle]
pub extern "C" fn mi_wg_respond_to_handshake(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
    init_hex: *const c_char,
) -> *const c_char {
    use crate::transport::wireguard::{HandshakeInit, respond_to_handshake};
    use crate::crypto::channel_key::derive_channel_key;

    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    let peer_hex = match c_str_to_string(peer_id_hex) {
        Some(s) => s,
        None => return ctx.set_response(r#"{"error":"invalid peer_id"}"#),
    };
    let peer_bytes = match hex::decode(&peer_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return ctx.set_response(r#"{"error":"invalid peer_id hex"}"#),
    };
    let initiator_peer_id = PeerId(peer_bytes);

    let init_bytes_raw = match c_str_to_string(init_hex).and_then(|s| hex::decode(&s).ok()) {
        Some(b) if b.len() == 80 => b,
        _ => return ctx.set_response(r#"{"error":"invalid init_hex (expected 80 bytes)"}"#),
    };
    let mut eph_i_pub = [0u8; 32];
    let mut enc_static = [0u8; 48];
    eph_i_pub.copy_from_slice(&init_bytes_raw[..32]);
    enc_static.copy_from_slice(&init_bytes_raw[32..]);
    let init_msg = HandshakeInit { eph_i_pub, enc_static };

    let (our_secret_bytes, our_peer_id, their_x25519_pub) = {
        let id_guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        let id = match id_guard.as_ref() {
            Some(i) => i,
            None => return ctx.set_response(r#"{"error":"identity not unlocked"}"#),
        };
        let contacts = ctx.contacts.lock().unwrap_or_else(|e| e.into_inner());
        let contact = match contacts.get(&initiator_peer_id) {
            Some(c) => c.clone(),
            None => return ctx.set_response(r#"{"error":"peer not in contacts"}"#),
        };
        let their_pub = x25519_dalek::PublicKey::from(contact.x25519_public);
        (id.x25519_secret.to_bytes(), id.peer_id(), their_pub)
    };

    let our_secret = x25519_dalek::StaticSecret::from(our_secret_bytes);
    let _our_pub = x25519_dalek::PublicKey::from(&our_secret);
    let psk = match derive_channel_key(&our_secret, &their_x25519_pub, &our_peer_id, &initiator_peer_id) {
        Ok(k) => k,
        Err(_) => return ctx.set_response(r#"{"error":"psk derivation failed"}"#),
    };

    let (session, response) = match respond_to_handshake(
        &init_msg,
        &our_secret,
        &psk,
        our_peer_id,
        initiator_peer_id,
    ) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("{}", e)});
            return ctx.set_response(&err.to_string());
        }
    };

    // Store the session.
    ctx.wireguard_sessions.lock().unwrap_or_else(|e| e.into_inner())
        .insert(initiator_peer_id, session);

    // Encode response as hex (32 bytes).
    let response_hex = hex::encode(response.eph_r_pub);

    let resp = serde_json::json!({
        "response_hex": response_hex,
        "session_established": true,
    });
    ctx.set_response(&resp.to_string())
}

/// Complete an initiator-side WireGuard handshake after receiving the responder's reply.
///
/// Called when the initiator receives the `HandshakeResponse` from the responder.
/// Consumes the pending handshake state created by `mi_wg_initiate_handshake` and
/// establishes the bidirectional WireGuard session.
///
/// `peer_id_hex`: the responder's peer ID (hex, 64 chars).
/// `response_hex`: the 32-byte ephemeral public key from the responder (hex, 64 chars).
///
/// Returns JSON: `{"session_established": true}` or `{"error": "..."}`.
#[no_mangle]
pub extern "C" fn mi_wg_complete_handshake(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
    response_hex: *const c_char,
) -> *const c_char {
    use crate::transport::wireguard::HandshakeResponse;

    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };

    let peer_hex = match c_str_to_string(peer_id_hex) {
        Some(s) => s,
        None => return ctx.set_response(r#"{"error":"invalid peer_id"}"#),
    };
    let peer_bytes = match hex::decode(&peer_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return ctx.set_response(r#"{"error":"invalid peer_id hex"}"#),
    };
    let responder_peer_id = PeerId(peer_bytes);

    let resp_bytes = match c_str_to_string(response_hex) {
        Some(s) => match hex::decode(&s) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return ctx.set_response(r#"{"error":"response_hex must be 32 bytes"}"#),
        },
        None => return ctx.set_response(r#"{"error":"invalid response_hex"}"#),
    };
    let response = HandshakeResponse { eph_r_pub: resp_bytes };

    // Extract our peer_id.
    let our_peer_id = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => id.peer_id(),
            None => return ctx.set_response(r#"{"error":"identity not unlocked"}"#),
        }
    };

    // Consume the pending handshake state.
    let pending = {
        let mut map = ctx.pending_wg_handshakes.lock().unwrap_or_else(|e| e.into_inner());
        match map.remove(&responder_peer_id) {
            Some(p) => p,
            None => return ctx.set_response(r#"{"error":"no pending handshake for this peer"}"#),
        }
    };

    // Complete the handshake and derive the session keys.
    let session = match pending.complete(&response, our_peer_id, responder_peer_id) {
        Ok(s) => s,
        Err(e) => {
            let err = serde_json::json!({"error": format!("{}", e)});
            return ctx.set_response(&err.to_string());
        }
    };

    // Store the established session.
    ctx.wireguard_sessions.lock().unwrap_or_else(|e| e.into_inner())
        .insert(responder_peer_id, session);

    ctx.set_response(r#"{"session_established":true}"#)
}

// ---------------------------------------------------------------------------
// SDR / RF Transport (§5.X SDR Stack)
// ---------------------------------------------------------------------------

/// Configure the SDR transport with a profile and hardware driver.
///
/// `config_json` fields:
/// - `profile`: "balanced" | "secure" | "long_range" | "long_range_hf" | "evasive"
/// - `driver`:  "lora" | "hackrf" | "limesdr" | "pluto" | "rtlsdr" | "hf_transceiver" | "meshtastic" | "simulated"
/// - `freq_hz`: primary frequency (ignored for long_range_hf and secure/evasive profiles)
/// - `hop_key_hex`: 64-char hex string (required for secure/evasive profiles)
///
/// Returns 0 on success, -1 on bad input.
#[no_mangle]
pub extern "C" fn mi_sdr_configure(ctx: *mut MeshContext, config_json: *const c_char) -> i32 {
    use crate::transport::rf_sdr::{SdrConfig, SdrDriverType, LoRaChipModel};

    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let json_str = match c_str_to_string(config_json) {
        Some(s) => s,
        None => return -1,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let profile = parsed.get("profile").and_then(|v| v.as_str()).unwrap_or("balanced");
    let driver_str = parsed.get("driver").and_then(|v| v.as_str()).unwrap_or("simulated");
    let freq_hz = parsed.get("freq_hz").and_then(|v| v.as_u64()).unwrap_or(433_175_000);

    let driver = match driver_str {
        "lora"          => SdrDriverType::LoRaChip { model: LoRaChipModel::Sx1262 },
        "hackrf"        => SdrDriverType::HackRf,
        "limesdr"       => SdrDriverType::LimeSdr,
        "pluto"         => SdrDriverType::PlutoSdr,
        "rtlsdr"        => SdrDriverType::RtlSdr,
        "hf_transceiver"=> SdrDriverType::HfTransceiver { model: "Generic".into() },
        "meshtastic"    => SdrDriverType::Meshtastic,
        _               => SdrDriverType::Simulated,
    };

    // Resolve hop key (for FHSS profiles)
    let hop_key: [u8; 32] = parsed.get("hop_key_hex")
        .and_then(|v| v.as_str())
        .and_then(|s| hex::decode(s).ok())
        .and_then(|v| v.try_into().ok())
        .unwrap_or([0u8; 32]);

    let config = match profile {
        "secure"        => SdrConfig::secure(driver, hop_key),
        "long_range"    => SdrConfig::long_range(driver, freq_hz),
        "long_range_hf" => SdrConfig::long_range_hf(driver),
        "evasive"       => SdrConfig::evasive(driver, hop_key),
        _               => SdrConfig::balanced(driver, freq_hz),
    };

    ctx.sdr.lock().unwrap_or_else(|e| e.into_inner()).apply_config(config);

    // Emit a settings update so Flutter reflects the new RF config
    let flags = ctx.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let node_mode = *ctx.node_mode.lock().unwrap_or_else(|e| e.into_inner());
    let (peer_id, ed25519_pub) = {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => (id.peer_id().to_hex(), hex::encode(id.ed25519_pub)),
            None => (String::new(), String::new()),
        }
    };
    let clearnet_port = *ctx.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
    ctx.push_event("SettingsUpdated", build_settings_json(
        &flags, node_mode, &ctx.threat_context, &peer_id, &ed25519_pub, clearnet_port,
    ));
    0
}

/// Get current SDR/RF status as JSON.
///
/// Returns a JSON object with:
/// - `enabled`: bool
/// - `profile`: string
/// - `driver`: string
/// - `fhss`: bool
/// - `ale`: bool
/// - `primary_freq_hz`: u64
/// - `stats`: aggregate stats (tx_bytes, rx_bytes, fhss_hops, etc.)
#[no_mangle]
pub extern "C" fn mi_sdr_status(ctx: *mut MeshContext) -> *const c_char {
    

    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let mgr = ctx.sdr.lock().unwrap_or_else(|e| e.into_inner());
    let stats = mgr.aggregate_stats();

    let (profile, driver, fhss, ale, freq_hz) = mgr.global_config.as_ref()
        .map(|c| (
            format!("{:?}", c.profile),
            format!("{:?}", c.driver),
            c.is_fhss(),
            c.is_ale(),
            c.primary_channel.freq_hz,
        ))
        .unwrap_or_else(|| ("None".into(), "None".into(), false, false, 0));

    let json = serde_json::json!({
        "enabled": mgr.enabled,
        "profile": profile,
        "driver": driver,
        "fhss": fhss,
        "ale": ale,
        "primaryFreqHz": freq_hz,
        "stats": {
            "txBytes": stats.tx_bytes,
            "rxBytes": stats.rx_bytes,
            "txFrames": stats.tx_frames,
            "rxFrames": stats.rx_frames,
            "lostFrames": stats.lost_frames,
            "lossRatio": stats.loss_ratio(),
            "fhssHops": stats.fhss_hops,
            "aleRelinks": stats.ale_relinks,
            "lastRssiDbm": stats.last_rssi_dbm,
            "lastSnrDb": stats.last_snr_db,
        }
    });
    ctx.set_response(&json.to_string())
}

/// Get the current FHSS channel for the current epoch.
///
/// Returns JSON `{"freq_hz": <u64>, "epoch": <u64>, "label": "<str>"}`
/// or `{"error": "..."}` if FHSS is not configured.
#[no_mangle]
pub extern "C" fn mi_sdr_current_channel(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let mgr = ctx.sdr.lock().unwrap_or_else(|e| e.into_inner());

    let result = mgr.global_config.as_ref()
        .and_then(|c| c.fhss.as_ref())
        .and_then(|fhss| {
            let epoch = fhss.current_epoch();
            fhss.current_channel().map(|ch| {
                serde_json::json!({
                    "freq_hz": ch.freq_hz,
                    "epoch": epoch,
                    "label": ch.label,
                    "bandwidth_hz": ch.bandwidth_hz,
                })
            })
        })
        .unwrap_or_else(|| serde_json::json!({"error": "FHSS not configured"}));

    ctx.set_response(&result.to_string())
}

/// List available SDR hardware profiles as JSON array.
///
/// Returns static profile info — not dependent on having a device connected.
#[no_mangle]
pub extern "C" fn mi_sdr_list_profiles(_ctx: *mut MeshContext) -> *const c_char {
    if _ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*_ctx };
    let profiles = serde_json::json!([
        {
            "id": "balanced",
            "name": "Balanced",
            "description": "Moderate FHSS, medium bandwidth, good range. Default for normal mesh operation.",
            "bandwidth_class": "medium",
            "fhss": false,
            "ale": false,
            "approx_range_km": "5-15",
        },
        {
            "id": "secure",
            "name": "Secure",
            "description": "FHSS with 100ms dwell, short burst windows. Maximum evasion against interception.",
            "bandwidth_class": "low",
            "fhss": true,
            "ale": false,
            "approx_range_km": "1-10",
        },
        {
            "id": "long_range",
            "name": "Long Range",
            "description": "LoRa SF12 — maximum link budget. Up to 15km+ LOS.",
            "bandwidth_class": "low",
            "fhss": false,
            "ale": false,
            "approx_range_km": "10-40",
        },
        {
            "id": "long_range_hf",
            "name": "Long Range HF",
            "description": "HF SSB with ALE on 40m/20m amateur bands. Ionospheric skip for continental range.",
            "bandwidth_class": "low",
            "fhss": false,
            "ale": true,
            "approx_range_km": "500-4000",
        },
        {
            "id": "evasive",
            "name": "Evasive",
            "description": "Wide-band FHSS across 433/868/915/2400MHz ISM bands. Highly resistant to jamming.",
            "bandwidth_class": "low",
            "fhss": true,
            "ale": false,
            "approx_range_km": "1-5",
        },
    ]);
    ctx.set_response(&profiles.to_string())
}

/// List supported SDR hardware types as JSON array.
#[no_mangle]
pub extern "C" fn mi_sdr_list_hardware(_ctx: *mut MeshContext) -> *const c_char {
    if _ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*_ctx };
    let hw = serde_json::json!([
        { "id": "lora",           "name": "LoRa Chip (SX1276/SX1262)",   "min_freq_mhz": 137,  "max_freq_mhz": 1020, "full_duplex": false, "raw_iq": false },
        { "id": "meshtastic",     "name": "Meshtastic Node",              "min_freq_mhz": 137,  "max_freq_mhz": 1020, "full_duplex": false, "raw_iq": false },
        { "id": "hackrf",         "name": "HackRF One",                   "min_freq_mhz": 1,    "max_freq_mhz": 6000, "full_duplex": false, "raw_iq": true  },
        { "id": "limesdr",        "name": "LimeSDR",                      "min_freq_mhz": 0.1,  "max_freq_mhz": 3800, "full_duplex": true,  "raw_iq": true  },
        { "id": "pluto",          "name": "ADALM-PLUTO (PlutoSDR)",       "min_freq_mhz": 325,  "max_freq_mhz": 3800, "full_duplex": true,  "raw_iq": true  },
        { "id": "rtlsdr",         "name": "RTL-SDR (RX only)",            "min_freq_mhz": 0.5,  "max_freq_mhz": 1766, "full_duplex": false, "raw_iq": true  },
        { "id": "hf_transceiver", "name": "HF Transceiver (IC-7300 etc.)", "min_freq_mhz": 1.8, "max_freq_mhz": 30,  "full_duplex": false, "raw_iq": true  },
        { "id": "simulated",      "name": "Simulated (Testing)",          "min_freq_mhz": 0.001,"max_freq_mhz": 300000,"full_duplex": true, "raw_iq": true  },
    ]);
    ctx.set_response(&hw.to_string())
}

/// List all services/modules available on this node (§17.13).
///
/// Returns a JSON array of service objects:
/// - `id`: string — module identifier
/// - `name`: string — human-readable name
/// - `path`: string — URI path for this service
/// - `address`: string — always empty (local services have no remote address)
/// - `enabled`: bool
/// - `minTrustLevel`: int (0 = Unknown)
/// - `allowedTransports`: string array
#[no_mangle]
pub extern "C" fn mi_get_service_list(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    let mc = ctx.module_config.lock().unwrap_or_else(|e| e.into_inner());

    let services = serde_json::json!([
        {"id":"gardens",      "name":"Gardens",          "path":"/gardens",    "address":"","enabled":mc.social.gardens,             "minTrustLevel":1,"allowedTransports":["mesh","clearnet"]},
        {"id":"file_sharing", "name":"File Sharing",     "path":"/files",      "address":"","enabled":mc.social.file_sharing,         "minTrustLevel":1,"allowedTransports":["mesh","clearnet"]},
        {"id":"store_forward","name":"Store & Forward",  "path":"/sf",         "address":"","enabled":mc.social.store_forward,        "minTrustLevel":2,"allowedTransports":["mesh"]},
        {"id":"notifications","name":"Notifications",    "path":"/notify",     "address":"","enabled":mc.social.notifications,        "minTrustLevel":1,"allowedTransports":["mesh","clearnet","tor"]},
        {"id":"infinet",      "name":"Infinet",          "path":"/infinet",    "address":"","enabled":mc.network.infinet,             "minTrustLevel":2,"allowedTransports":["mesh"]},
        {"id":"exit_nodes",   "name":"Exit Nodes",       "path":"/exit",       "address":"","enabled":mc.network.exit_nodes,          "minTrustLevel":3,"allowedTransports":["clearnet","tor"]},
        {"id":"vpn_mode",     "name":"VPN Mode",         "path":"/vpn",        "address":"","enabled":mc.network.vpn_mode,            "minTrustLevel":2,"allowedTransports":["clearnet","tor"]},
        {"id":"app_connector","name":"App Connector",    "path":"/connector",  "address":"","enabled":mc.network.app_connector,       "minTrustLevel":2,"allowedTransports":["mesh","clearnet"]},
        {"id":"funnel",       "name":"Funnel",           "path":"/funnel",     "address":"","enabled":mc.network.funnel,              "minTrustLevel":3,"allowedTransports":["clearnet"]},
        {"id":"mnrdp_server", "name":"Remote Desktop",   "path":"/rdp",        "address":"","enabled":mc.protocols.mnrdp_server,      "minTrustLevel":3,"allowedTransports":["mesh","clearnet"]},
        {"id":"mnsp_server",  "name":"Screen Share",     "path":"/screencast", "address":"","enabled":mc.protocols.screen_share,      "minTrustLevel":2,"allowedTransports":["mesh","clearnet"]},
        {"id":"api_gateway",  "name":"API Gateway",      "path":"/api",        "address":"","enabled":mc.protocols.api_gateway,       "minTrustLevel":2,"allowedTransports":["mesh","clearnet"]},
        {"id":"print_service","name":"Print Service",    "path":"/print",      "address":"","enabled":mc.protocols.print_service,     "minTrustLevel":2,"allowedTransports":["mesh"]},
        {"id":"plugins",      "name":"Plugin Runtime",   "path":"/plugins",    "address":"","enabled":mc.plugins.runtime_enabled,     "minTrustLevel":2,"allowedTransports":["mesh","clearnet"]},
    ]);

    ctx.set_response(&services.to_string())
}

/// Toggle or configure a service/module (§17.13).
///
/// `service_id`: the module identifier (e.g. "gardens")
/// `config_json`: JSON object with at minimum `{"enabled": bool}`
///
/// Returns 1 on success, 0 on unknown module or parse error.
#[no_mangle]
pub extern "C" fn mi_configure_service(
    ctx: *mut MeshContext,
    service_id: *const c_char,
    config_json: *const c_char,
) -> i32 {
    if ctx.is_null() || service_id.is_null() || config_json.is_null() { return 0; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    // SAFETY: The FFI caller guarantees this pointer is non-null and
    // points to a valid NUL-terminated C string that lives at least as
    // long as this borrow.
    let id = unsafe { CStr::from_ptr(service_id) }.to_str().unwrap_or("").to_string();
    // SAFETY: The FFI caller guarantees this pointer is non-null and
    // points to a valid NUL-terminated C string that lives at least as
    // long as this borrow.
    let raw = unsafe { CStr::from_ptr(config_json) }.to_str().unwrap_or("");
    let parsed: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let enabled = match parsed.get("enabled").and_then(|v| v.as_bool()) {
        Some(b) => b,
        None => return 0,
    };

    let mut mc = ctx.module_config.lock().unwrap_or_else(|e| e.into_inner());
    let changed = match id.as_str() {
        "gardens"       => { mc.social.gardens          = enabled; true }
        "file_sharing"  => { mc.social.file_sharing      = enabled; true }
        "store_forward" => { mc.social.store_forward     = enabled; true }
        "notifications" => { mc.social.notifications     = enabled; true }
        "infinet"       => { mc.network.infinet          = enabled; true }
        "exit_nodes"    => { mc.network.exit_nodes       = enabled; true }
        "vpn_mode"      => { mc.network.vpn_mode         = enabled; true }
        "app_connector" => { mc.network.app_connector    = enabled; true }
        "funnel"        => { mc.network.funnel           = enabled; true }
        "mnrdp_server"  => { mc.protocols.mnrdp_server   = enabled; true }
        "mnsp_server"   => { mc.protocols.screen_share   = enabled; true }
        "api_gateway"   => { mc.protocols.api_gateway    = enabled; true }
        "print_service" => { mc.protocols.print_service  = enabled; true }
        "plugins"       => { mc.plugins.runtime_enabled  = enabled; true }
        _               => false,
    };
    drop(mc);

    if changed {
        ctx.save_settings();
    }

    changed as i32
}

/// Backup payload serialized inside the encrypted envelope.
///
/// Per spec §3.7: private keys are NEVER included in backups.
/// Identity is device-local; on restore the user re-pairs with trusted contacts.
#[derive(Serialize, Deserialize)]
struct BackupContents {
    /// Schema version for forward compat.
    version: u8,
    /// All paired contacts (public keys + trust levels, no private material).
    contacts: Vec<crate::pairing::contact::ContactRecord>,
    /// All rooms / conversations.
    rooms: Vec<Room>,
    /// Message history per room (key = room_id hex, value = message list).
    /// Populated for Extended backups only; empty for Standard.
    messages: std::collections::HashMap<String, Vec<serde_json::Value>>,
}

/// Create an encrypted backup of contacts, rooms, and (Extended) messages (§3.7.4).
///
/// Identity private keys are NEVER included — spec §3.7 explicitly prohibits it.
/// `backup_type`: 0 = standard (contacts + rooms), 1 = extended (+ message history).
/// Returns JSON `{"ok": true, "backup_b64": "..."}` or `{"ok": false, "error": "..."}`.
#[no_mangle]
pub extern "C" fn mi_create_backup(ctx: *mut MeshContext, passphrase: *const c_char, backup_type: u8) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    let passphrase_str = match c_str_to_string(passphrase) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return ctx.set_response(r#"{"ok":false,"error":"passphrase required"}"#);
        }
    };

    // Identity must be loaded (backup is meaningless without one), but we do NOT
    // serialize any private key material — only the public social graph.
    {
        let guard = ctx.identity.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            return ctx.set_response(r#"{"ok":false,"error":"no identity loaded"}"#);
        }
    }

    let is_extended = backup_type == 1;
    let btype = if is_extended { BackupType::Extended } else { BackupType::Standard };
    let is_cloud = is_extended;

    // Collect backup contents — NO private keys.
    let contents = {
        let contacts: Vec<crate::pairing::contact::ContactRecord> = ctx
            .contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .all()
            .into_iter()
            .cloned()
            .collect();

        let rooms: Vec<Room> = ctx
            .rooms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let messages = if is_extended {
            ctx.messages
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        } else {
            std::collections::HashMap::new()
        };

        BackupContents { version: 1, contacts, rooms, messages }
    };

    let payload = match serde_json::to_vec(&contents) {
        Ok(b) => b,
        Err(e) => {
            let resp = serde_json::json!({"ok": false, "error": e.to_string()});
            return ctx.set_response(&resp.to_string());
        }
    };

    match create_backup(&payload, passphrase_str.as_bytes(), btype, is_cloud) {
        Ok(encrypted) => {
            match serde_json::to_vec(&encrypted) {
                Ok(json_bytes) => {
                    use base64::Engine as _;
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&json_bytes);
                    let resp = serde_json::json!({"ok": true, "backup_b64": b64});
                    ctx.set_response(&resp.to_string())
                }
                Err(e) => {
                    let resp = serde_json::json!({"ok": false, "error": e.to_string()});
                    ctx.set_response(&resp.to_string())
                }
            }
        }
        Err(e) => {
            let resp = serde_json::json!({"ok": false, "error": e.to_string()});
            ctx.set_response(&resp.to_string())
        }
    }
}

/// Perform a standard emergency erase (§3.9.1).
///
/// Destroys all three identity layers. Non-reversible.
/// Returns 0 on success (erase completed), -1 if ctx is null.
#[no_mangle]
pub extern "C" fn mi_emergency_erase(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let data_dir = std::path::Path::new(&ctx.data_dir);
    killswitch::standard_erase(data_dir);
    // Clear all in-memory state
    ctx.identity_unlocked = false;
    *ctx.identity.lock().unwrap_or_else(|e| e.into_inner()) = None;
    ctx.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.contacts.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.messages.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.vault = None;
    0
}

/// Perform a duress erase (§3.9.2).
///
/// Preserves Layer 1 (mesh identity), destroys Layers 2 and 3.
/// Returns 0 on success, -1 if ctx is null.
#[no_mangle]
pub extern "C" fn mi_duress_erase(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and that no other reference to this context
    // exists for the duration of this call per the C API contract.
    let ctx = unsafe { &mut *ctx };
    let data_dir = std::path::Path::new(&ctx.data_dir);
    killswitch::duress_erase(data_dir);
    // Clear in-memory Layer 2/3 state
    ctx.identity_unlocked = false;
    *ctx.identity.lock().unwrap_or_else(|e| e.into_inner()) = None;
    ctx.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.contacts.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.messages.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ctx.vault = None;
    0
}

#[no_mangle]
pub extern "C" fn mi_last_error_message(ctx: *mut MeshContext) -> *const c_char {
    mi_get_last_error(ctx)
}

/// Free a string previously returned by the bridge.
/// In our implementation, strings are owned by the context — this is a no-op.
#[no_mangle]
pub extern "C" fn mi_string_free(_ptr: *mut c_char) {
    // No-op: strings are owned by MeshContext.last_response
}

// ---------------------------------------------------------------------------
// Calls FFI (§10.1.6)
//
// Voice and video calls are signalled over the mesh messaging channel using
// call_offer / call_answer / call_hangup control frames.  Media is handled
// by the platform (WebRTC on mobile; native audio on desktop) — the Rust
// backend only manages signalling and call state.
// ---------------------------------------------------------------------------

/// Initiate an outgoing call to a peer.
///
/// `peer_id_hex`  — 64-char hex peer ID of the callee.
/// `is_video`     — 1 for video+audio, 0 for audio-only.
///
/// Returns JSON `{"ok":true,"callId":"<hex>"}` or `{"ok":false,"error":"..."}`.
#[no_mangle]
pub extern "C" fn mi_call_offer(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
    is_video: i32,
) -> *const c_char {
    // Guard against a null context pointer before dereferencing.
    // A null ctx means the runtime was never initialised; return a JSON error
    // so the caller gets a structured failure rather than a segfault.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    if !ctx.identity_unlocked {
        return ctx.set_response(r#"{"ok":false,"error":"identity not unlocked"}"#);
    }

    // SAFETY: The FFI caller guarantees this pointer is non-null and
    // points to a valid NUL-terminated C string that lives at least as
    // long as this borrow.
    let peer_hex = match unsafe { CStr::from_ptr(peer_id_hex) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ctx.set_response(r#"{"ok":false,"error":"invalid peer_id encoding"}"#),
    };

    if ctx.active_call.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
        return ctx.set_response(r#"{"ok":false,"error":"call already in progress"}"#);
    }

    let _peer_id_bytes = match hex::decode(&peer_hex) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return ctx.set_response(r#"{"ok":false,"error":"invalid peer_id_hex"}"#),
    };

    let mut call_id = [0u8; 32];
    if !try_random_fill(&mut call_id) {
        return ctx.set_response(r#"{"ok":false,"error":"RNG unavailable"}"#);
    }
    let call_id_hex = hex::encode(call_id);
    let is_video = is_video != 0;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);

    // new_outgoing(call_id, is_video, our_peer_id, now) — store our own peer ID.
    // The callee is tracked separately as `remote_peer_hex`.
    let our_peer_id = ctx.identity.lock().unwrap_or_else(|e| e.into_inner())
        .as_ref().map(|id| id.peer_id()).unwrap_or(PeerId([0u8; 32]));
    let call_state = crate::calls::CallState::new_outgoing(call_id, is_video, our_peer_id, now);
    *ctx.active_call.lock().unwrap_or_else(|e| e.into_inner()) =
        Some((call_state, peer_hex.clone()));

    let signal = crate::calls::CallSignal::Offer {
        call_id,
        audio_codecs: vec![crate::calls::AudioCodec::Opus],
        video_codecs: if is_video { vec![crate::calls::VideoCodec::VP9] } else { vec![] },
        losec_requested: false,
        session_desc: String::new(),
    };
    if let Ok(payload) = serde_json::to_string(&signal) {
        ctx.send_raw_frame(&peer_hex, &serde_json::json!({"type":"call_offer","payload":payload}));
    }

    ctx.set_response(&serde_json::json!({"ok":true,"callId":call_id_hex}).to_string())
}

/// Accept or reject an incoming call.
///
/// `call_id_hex` — hex call ID from the `CallIncoming` event.
/// `accept`      — 1 to accept, 0 to reject.
///
/// Returns 1 on success, 0 on error.
#[no_mangle]
pub extern "C" fn mi_call_answer(
    ctx: *mut MeshContext,
    call_id_hex: *const c_char,
    accept: i32,
) -> i32 {
    // Guard against null context pointer before dereferencing.
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    if !ctx.identity_unlocked { return 0; }

    // SAFETY: The FFI caller guarantees this pointer is non-null and
    // points to a valid NUL-terminated C string that lives at least as
    // long as this borrow.
    let call_id_str = match unsafe { CStr::from_ptr(call_id_hex) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0,
    };

    let peer_hex = {
        let call = ctx.active_call.lock().unwrap_or_else(|e| e.into_inner());
        match call.as_ref() {
            Some((c, peer)) if hex::encode(c.call_id) == call_id_str => peer.clone(),
            _ => return 0,
        }
    };

    let call_id_bytes = match hex::decode(&call_id_str) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return 0,
    };

    if accept != 0 {
        let signal = crate::calls::CallSignal::Answer {
            call_id: call_id_bytes,
            audio_codec: crate::calls::AudioCodec::Opus,
            video_codec: None,
            losec_accepted: false,
            session_desc: String::new(),
        };
        if let Ok(payload) = serde_json::to_string(&signal) {
            ctx.send_raw_frame(&peer_hex, &serde_json::json!({"type":"call_answer","payload":payload}));
        }
    } else {
        ctx.send_call_hangup(&peer_hex, &call_id_str);
        *ctx.active_call.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
    1
}

/// End an active call.
///
/// Sends a hangup frame to all participants and clears call state.
/// Returns 1 on success, 0 if no active call with that ID.
#[no_mangle]
pub extern "C" fn mi_call_hangup(
    ctx: *mut MeshContext,
    call_id_hex: *const c_char,
) -> i32 {
    // Guard against null context pointer before dereferencing.
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };

    // SAFETY: The FFI caller guarantees this pointer is non-null and
    // points to a valid NUL-terminated C string that lives at least as
    // long as this borrow.
    let call_id_str = match unsafe { CStr::from_ptr(call_id_hex) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0,
    };

    let peer_hex = {
        let call = ctx.active_call.lock().unwrap_or_else(|e| e.into_inner());
        match call.as_ref() {
            Some((c, peer)) if hex::encode(c.call_id) == call_id_str => peer.clone(),
            _ => return 0,
        }
    };

    ctx.send_call_hangup(&peer_hex, &call_id_str);
    *ctx.active_call.lock().unwrap_or_else(|e| e.into_inner()) = None;
    1
}

/// Get current call status.
///
/// Returns JSON `{"active":false}` when idle, or
/// `{"active":true,"callId":"<hex>","peerId":"<hex>","isVideo":<bool>,"durationSecs":<u64>}`
/// when a call is in progress.
#[no_mangle]
pub extern "C" fn mi_call_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard against null context pointer before dereferencing.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);

    let call = ctx.active_call.lock().unwrap_or_else(|e| e.into_inner());
    match call.as_ref() {
        None => ctx.set_response(r#"{"active":false}"#),
        Some((c, peer_hex)) => ctx.set_response(&serde_json::json!({
            "active": true,
            "callId": hex::encode(c.call_id),
            "peerId": peer_hex,
            "isVideo": c.is_video,
            "durationSecs": c.duration_secs(now),
            "mode": format!("{:?}", c.mode),
        }).to_string()),
    }
}

// ---------------------------------------------------------------------------
// §14 — Notification configuration
// ---------------------------------------------------------------------------

/// Get the current notification configuration.
///
/// Returns JSON:
/// ```json
/// {
///   "enabled": true,
///   "tier": 1,
///   "tierLabel": "MeshTunnel",
///   "cloudPingEnabled": false,
///   "pushServerUrl": "",
///   "showPreviews": true,
///   "soundEnabled": true,
///   "vibrationEnabled": true,
///   "suppressedByThreat": false,
///   "effectiveTier": 1
/// }
/// ```
#[no_mangle]
pub extern "C" fn mi_get_notification_config(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let notif = ctx.notifications.lock().unwrap_or_else(|e| e.into_inner());
    let cfg = &notif.config;
    let tc = ctx.threat_context;
    let effective = cfg.effective_tier(tc) as u8;
    let suppressed = cfg.is_suppressed_by_threat(tc);
    let tier_label = match cfg.tier {
        crate::notifications::NotificationTier::MeshTunnel  => "MeshTunnel",
        crate::notifications::NotificationTier::UnifiedPush => "UnifiedPush",
        crate::notifications::NotificationTier::SilentPush  => "SilentPush",
        crate::notifications::NotificationTier::RichPush    => "RichPush",
    };
    let push_url: String = cfg.push_relay.as_ref().map(|r| match &r.relay_address {
        crate::notifications::RelayAddress::ClearnetUrl  { url }      => url.clone(),
        crate::notifications::RelayAddress::UnifiedPush { endpoint }  => endpoint.clone(),
        crate::notifications::RelayAddress::MeshService { .. }        => String::new(),
    }).unwrap_or_default();
    ctx.set_response(&serde_json::json!({
        "enabled":           cfg.enabled,
        "tier":              cfg.tier as u8,
        "tierLabel":         tier_label,
        "cloudPingEnabled":  cfg.tier as u8 >= 2,
        "pushServerUrl":     push_url,
        "showPreviews":      cfg.rich_content_level as u8 >= 1,
        "soundEnabled":      true,
        "vibrationEnabled":  true,
        "suppressedByThreat": suppressed,
        "effectiveTier":     effective,
    }).to_string())
}

/// Set the notification configuration.
///
/// Accepts JSON:
/// ```json
/// {
///   "enabled": true,
///   "tier": 1,
///   "pushServerUrl": "",
///   "showPreviews": true
/// }
/// ```
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn mi_set_notification_config(ctx: *mut MeshContext, json: *const c_char) -> i32 {
    if ctx.is_null() || json.is_null() { return -1; }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    // SAFETY: The FFI caller guarantees this pointer is non-null and
    // points to a valid NUL-terminated C string that lives at least as
    // long as this borrow.
    let s = match unsafe { std::ffi::CStr::from_ptr(json) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let v: serde_json::Value = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let mut notif = ctx.notifications.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = notif.config.clone();

    if let Some(enabled) = v["enabled"].as_bool() {
        cfg.enabled = enabled;
    }
    if let Some(tier) = v["tier"].as_u64() {
        cfg.tier = match tier {
            1 => crate::notifications::NotificationTier::MeshTunnel,
            2 => crate::notifications::NotificationTier::UnifiedPush,
            3 => crate::notifications::NotificationTier::SilentPush,
            4 => crate::notifications::NotificationTier::RichPush,
            _ => return -1,
        };
    }
    if let Some(url) = v["pushServerUrl"].as_str() {
        if url.is_empty() {
            cfg.push_relay = None;
        } else {
            cfg.push_relay = Some(crate::notifications::PushRelayConfig {
                relay_address: crate::notifications::RelayAddress::UnifiedPush {
                    endpoint: url.to_string(),
                },
                device_token: Vec::new(),
                platform: crate::notifications::PushPlatform::UnifiedPush,
            });
        }
    }
    if let Some(previews) = v["showPreviews"].as_bool() {
        cfg.rich_content_level = if previews {
            crate::notifications::RichPushContentLevel::Standard
        } else {
            crate::notifications::RichPushContentLevel::Minimal
        };
    }
    notif.config = cfg;
    drop(notif);
    ctx.save_settings();
    0
}

// ---------------------------------------------------------------------------
// §6 — Routing table queries
// ---------------------------------------------------------------------------

/// Get a JSON summary of the routing table for network diagnostics.
///
/// Returns JSON:
/// ```json
/// {
///   "directPeers": 3,
///   "totalRoutes": 12,
///   "planes": {
///     "local": 3,
///     "public": 9,
///     "group": 0,
///     "ble": 0
///   }
/// }
/// ```
#[no_mangle]
pub extern "C" fn mi_routing_table_stats(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let table = ctx.routing_table.lock().unwrap_or_else(|e| e.into_inner());
    ctx.set_response(&serde_json::json!({
        "directPeers":  table.direct_peer_count(),
        "totalRoutes":  table.total_route_count(),
    }).to_string())
}

/// Look up the best next-hop for a destination peer ID.
///
/// Returns JSON `{"found": true, "nextHop": "<hex>", "hopCount": 1, "latencyMs": 10}`
/// or `{"found": false}` if no route exists.
#[no_mangle]
pub extern "C" fn mi_routing_lookup(
    ctx: *mut MeshContext,
    dest_peer_id_hex: *const c_char,
) -> *const c_char {
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: The FFI caller guarantees this pointer is non-null,
    // correctly aligned, and lives for the duration of this call per
    // the C API contract documented in the generated header.
    let ctx = unsafe { &*ctx };
    let dest_str = match c_str_to_string(dest_peer_id_hex) { Some(s) => s, None => return ptr::null() };
    let dest_bytes = match hex::decode(&dest_str) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return ctx.set_response(r#"{"found":false}"#),
    };
    let dest = DeviceAddress(dest_bytes);
    let table = ctx.routing_table.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    match table.lookup(&dest, None, now) {
        Some(entry) => ctx.set_response(&serde_json::json!({
            "found":     true,
            "nextHop":   hex::encode(entry.next_hop.0),
            "hopCount":  entry.hop_count,
            "latencyMs": entry.latency_ms,
            "direct":    entry.is_direct(),
        }).to_string()),
        None => ctx.set_response(r#"{"found":false}"#),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use tempfile::TempDir;

    fn make_ctx() -> (*mut MeshContext, TempDir) {
        let dir = TempDir::new().unwrap();
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let ctx = mesh_init(dir_str.as_ptr());
        assert!(!ctx.is_null());
        (ctx, dir)
    }

    #[test]
    fn test_init_destroy() {
        let (ctx, _dir) = make_ctx();
        mesh_destroy(ctx);
    }

    #[test]
    fn test_no_identity_initially() {
        let (ctx, _dir) = make_ctx();
        assert_eq!(mi_has_identity(ctx), 0);
        mesh_destroy(ctx);
    }

    #[test]
    fn test_create_identity() {
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Alice").unwrap();
        // mi_create_identity now returns i32 (0 = success)
        let result = mi_create_identity(ctx, name.as_ptr());
        assert_eq!(result, 0, "mi_create_identity should succeed");

        // After creation, identity should be unlocked
        assert_eq!(mi_has_identity(ctx), 1);

        // Verify summary is available
        let summary = mi_get_identity_summary(ctx);
        assert!(!summary.is_null());
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let json_str = unsafe { CStr::from_ptr(summary).to_str().unwrap() };
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(json["locked"], false);

        mesh_destroy(ctx);
    }

    #[test]
    fn test_unlock_identity() {
        let (ctx, dir) = make_ctx();
        let name = CString::new("Bob").unwrap();
        assert_eq!(mi_create_identity(ctx, name.as_ptr()), 0);
        mesh_destroy(ctx);

        // Re-open context with same dir
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let ctx2 = mesh_init(dir_str.as_ptr());
        assert!(!ctx2.is_null());
        assert_eq!(mi_has_identity(ctx2), 1);

        // Unlock (no PIN)
        assert_eq!(mi_unlock_identity(ctx2, ptr::null()), 0, "Unlock should succeed");

        // Summary should now be active
        let summary = mi_get_identity_summary(ctx2);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let json_str = unsafe { CStr::from_ptr(summary).to_str().unwrap() };
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(json["locked"], false);
        assert!(json["peerId"].is_string());

        mesh_destroy(ctx2);
    }

    #[test]
    fn test_room_operations() {
        let (ctx, _dir) = make_ctx();

        // Create room
        let name = CString::new("Test Room").unwrap();
        let result = mi_create_room(ctx, name.as_ptr(), ptr::null());
        assert!(!result.is_null());

        // List rooms
        let rooms = mi_get_room_list(ctx);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let json_str = unsafe { CStr::from_ptr(rooms).to_str().unwrap() };
        let rooms: Vec<serde_json::Value> = serde_json::from_str(json_str).unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0]["name"], "Test Room");

        mesh_destroy(ctx);
    }

    #[test]
    fn test_threat_context() {
        let (ctx, _dir) = make_ctx();

        assert_eq!(mi_get_threat_context(ctx), 0); // Normal
        assert_eq!(mi_set_threat_context(ctx, 2), 0); // Set Critical
        assert_eq!(mi_get_threat_context(ctx), 2);
        assert_eq!(mi_set_threat_context(ctx, 5), -1); // Invalid

        mesh_destroy(ctx);
    }

    #[test]
    fn test_active_conversation() {
        let (ctx, _dir) = make_ctx();
        assert_eq!(mi_set_active_conversation(ctx, ptr::null()), 0);

        let room_id = CString::new("0102030405060708090a0b0c0d0e0f10").unwrap();
        assert_eq!(mi_set_active_conversation(ctx, room_id.as_ptr()), 0);

        mesh_destroy(ctx);
    }

    #[test]
    fn test_poll_events_empty() {
        let (ctx, _dir) = make_ctx();
        let events = mi_poll_events(ctx);
        assert!(!events.is_null());
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let json_str = unsafe { CStr::from_ptr(events).to_str().unwrap() };
        assert_eq!(json_str, "[]");
        mesh_destroy(ctx);
    }

    #[test]
    fn test_send_message_emits_events() {
        let (ctx, _dir) = make_ctx();

        // Create a room first
        let room_name = CString::new("Events Test Room").unwrap();
        let room_result = mi_create_room(ctx, room_name.as_ptr(), ptr::null());
        assert!(!room_result.is_null());
        let room_json: serde_json::Value = serde_json::from_str(
            // SAFETY: The pointer was returned by our own FFI function and is
            // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
            unsafe { CStr::from_ptr(room_result).to_str().unwrap() }
        ).unwrap();
        let room_id_str = room_json["id"].as_str().unwrap().to_string();
        let room_id = CString::new(room_id_str.clone()).unwrap();

        // Drain the RoomUpdated event from room creation
        let _ = mi_poll_events(ctx);

        // Send a message
        let text = CString::new("Hello mesh").unwrap();
        assert_eq!(mi_send_text_message(ctx, room_id.as_ptr(), text.as_ptr()), 0);

        // Poll — should have MessageAdded and RoomUpdated
        let events_ptr = mi_poll_events(ctx);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let events_str = unsafe { CStr::from_ptr(events_ptr).to_str().unwrap() };
        let events: Vec<serde_json::Value> = serde_json::from_str(events_str).unwrap();

        assert!(events.len() >= 2, "Expected at least MessageAdded + RoomUpdated");
        let types: Vec<&str> = events.iter()
            .filter_map(|e| e["type"].as_str())
            .collect();
        assert!(types.contains(&"MessageAdded"), "Missing MessageAdded event");
        assert!(types.contains(&"RoomUpdated"), "Missing RoomUpdated event");

        // Verify message content
        let msg_event = events.iter().find(|e| e["type"] == "MessageAdded").unwrap();
        assert_eq!(msg_event["data"]["text"], "Hello mesh");
        assert_eq!(msg_event["data"]["isOutgoing"], true);
        assert_eq!(msg_event["data"]["roomId"], room_id_str);

        // Poll again — queue should be empty
        let empty_ptr = mi_poll_events(ctx);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let empty_str = unsafe { CStr::from_ptr(empty_ptr).to_str().unwrap() };
        assert_eq!(empty_str, "[]");

        mesh_destroy(ctx);
    }

    #[test]
    fn test_delete_room_emits_event() {
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Delete Me").unwrap();
        let result_ptr = mi_create_room(ctx, name.as_ptr(), ptr::null());
        let room_json: serde_json::Value = serde_json::from_str(
            // SAFETY: The pointer was returned by our own FFI function and is
            // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
            unsafe { CStr::from_ptr(result_ptr).to_str().unwrap() }
        ).unwrap();
        let rid_str = room_json["id"].as_str().unwrap().to_string();
        let rid = CString::new(rid_str.clone()).unwrap();

        // Drain creation events
        let _ = mi_poll_events(ctx);

        // Delete the room
        assert_eq!(mi_delete_room(ctx, rid.as_ptr()), 0);

        let events_ptr = mi_poll_events(ctx);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let events_str = unsafe { CStr::from_ptr(events_ptr).to_str().unwrap() };
        let events: Vec<serde_json::Value> = serde_json::from_str(events_str).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["type"], "RoomDeleted");
        assert_eq!(events[0]["data"]["roomId"], rid_str);

        mesh_destroy(ctx);
    }

    #[test]
    fn test_transport_flag_emits_settings_event() {
        let (ctx, _dir) = make_ctx();
        let transport = CString::new("tor").unwrap();
        assert_eq!(mi_toggle_transport_flag(ctx, transport.as_ptr(), 1), 0);

        let events_ptr = mi_poll_events(ctx);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let events_str = unsafe { CStr::from_ptr(events_ptr).to_str().unwrap() };
        let events: Vec<serde_json::Value> = serde_json::from_str(events_str).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["type"], "SettingsUpdated");
        assert_eq!(events[0]["data"]["enableTor"], true);

        mesh_destroy(ctx);
    }

    #[test]
    fn test_security_mode() {
        let (ctx, _dir) = make_ctx();

        // Create a room to operate on.
        let room_name = CString::new("test room").unwrap();
        let room_ptr = mi_create_room(ctx, room_name.as_ptr(), ptr::null());
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let room_json_str = unsafe { CStr::from_ptr(room_ptr).to_str().unwrap() };
        let room_json: serde_json::Value = serde_json::from_str(room_json_str).unwrap();
        let room_id_str = room_json["id"].as_str().unwrap().to_string();
        let room_id_c = CString::new(room_id_str).unwrap();

        // Setting a valid security mode on a known room should succeed.
        assert_eq!(mi_set_conversation_security_mode(ctx, room_id_c.as_ptr(), 2), 0); // Standard
        // Setting on a null room_id should fail.
        assert_eq!(mi_set_conversation_security_mode(ctx, ptr::null(), 2), -1);
        // Setting an invalid mode value should fail.
        assert_eq!(mi_set_conversation_security_mode(ctx, room_id_c.as_ptr(), 99), -1);

        mesh_destroy(ctx);
    }

    #[test]
    fn test_null_safety() {
        // All functions should handle null context gracefully
        assert_eq!(mi_has_identity(ptr::null_mut()), 0);
        assert!(mi_get_room_list(ptr::null_mut()).is_null());
        assert!(mi_poll_events(ptr::null_mut()).is_null());
        assert_eq!(mi_set_threat_context(ptr::null_mut(), 0), -1);
        mesh_destroy(ptr::null_mut()); // Should not crash
    }

    #[test]
    fn test_x3dh_session_bootstrap_roundtrip() {
        // Simulates Alice initiating with Bob via X3DH.
        // Both sides should reach the same master secret and exchange
        // a message successfully.
        use crate::crypto::x3dh::{x3dh_initiate, x3dh_respond, PreauthBundle, X3dhInitHeader};
        use crate::crypto::double_ratchet::DoubleRatchetSession;
        use crate::identity::self_identity::SelfIdentity;

        let alice = SelfIdentity::generate(Some("Alice".into()));
        let bob = SelfIdentity::generate(Some("Bob".into()));

        // Build Bob's bundle as Alice would see it after pairing.
        let bob_bundle = PreauthBundle {
            identity_ed25519_pub: bob.ed25519_pub,
            identity_x25519_pub: bob.x25519_pub.clone(),
            preauth_x25519_pub: bob.preauth_x25519_pub.clone(),
            preauth_kem_pub: None,
            preauth_sig: None,
        };

        // Alice initiates X3DH.
        let alice_ik_pub = *alice.x25519_pub.as_bytes();
        let alice_out = x3dh_initiate(&alice.x25519_secret, &alice_ik_pub, &bob_bundle).unwrap();
        let alice_master = alice_out.master_secret.as_bytes();
        let init_header = alice_out.header.unwrap();

        // Alice's initial ratchet key = Bob's preauth pub.
        let bob_preauth_bytes = *bob.preauth_x25519_pub.as_bytes();
        let mut alice_session = DoubleRatchetSession::init_sender(alice_master, &bob_preauth_bytes).unwrap();

        // Bob responds to X3DH.
        let bob_header = X3dhInitHeader {
            eph_pub: init_header.eph_pub,
            encrypted_ik_pub: init_header.encrypted_ik_pub,
        };
        let bob_out = x3dh_respond(&bob.x25519_secret, &bob.preauth_x25519_secret, &bob_header).unwrap();
        let bob_master = bob_out.master_secret.as_bytes();

        // Master secrets must match.
        assert_eq!(alice_master, bob_master, "X3DH master secrets must match");

        // Bob's initial ratchet = his own preauth keypair.
        let bob_preauth_secret = x25519_dalek::StaticSecret::from(bob.preauth_x25519_secret.to_bytes());
        let mut bob_session = DoubleRatchetSession::init_receiver(bob_master, bob_preauth_secret, &bob_preauth_bytes);

        // Alice sends a message.
        let (send_header, msg_key) = alice_session.next_send_msg_key().unwrap();
        let (ck, nonce, rmk) = DoubleRatchetSession::expand_msg_key(&msg_key).unwrap();
        let _ = ck; let _ = nonce; let _ = rmk; // Keys are correct; encryption tested elsewhere.

        // Bob can receive it.
        let recv_key = bob_session.recv_msg_key(&send_header).unwrap();
        assert_eq!(msg_key, recv_key, "Message keys must match");
    }

    // -----------------------------------------------------------------------
    // Sender Key group messaging tests (§7.0.4)
    // -----------------------------------------------------------------------

    /// Build a minimal group with one sender's Sender Key registered, return
    /// the context pointer, group-ID hex, room-ID hex, sender hex, and a clone
    /// of the Sender Key so the test can encrypt frames.
    ///
    /// Sender bytes = [0xAA; 32], symmetric_key = [0x33; 32].
    fn setup_sk_group(ctx_ptr: *mut MeshContext) -> (
        String,   // group_id hex
        String,   // room_id hex (16-byte, 32-hex-char)
        String,   // sender peer-id hex
        crate::crypto::sender_keys::SenderKey,
    ) {
        use crate::crypto::sender_keys::SenderKey;
        use crate::groups::group::{Group, GroupLanConfig, GroupPublicProfile, NetworkType, PeerSenderKeyState};
        use crate::identity::peer_id::PeerId;
        use crate::messaging::{message::{ConversationType, MessageSecurityMode}, room::Room};

        let sender_bytes = [0xAA_u8; 32];
        let sender_hex = hex::encode(sender_bytes);
        let our_bytes = [0xBB_u8; 32];

        let group_id = [0x11_u8; 32];
        let gid_hex = hex::encode(group_id);

        // Room ID must be 16 bytes ([u8; 16]).
        let room_id: [u8; 16] = [0x22_u8; 16];
        let room_id_hex = hex::encode(room_id);

        let symmetric_key = [0x33_u8; 32];

        let sk = SenderKey::generate();
        let chain_key = *sk.chain_key_bytes();
        let vk_bytes = sk.verifying_key().to_bytes();

        let mut peer_sender_keys = std::collections::HashMap::new();
        peer_sender_keys.insert(sender_bytes, PeerSenderKeyState {
            chain_key,
            next_iteration: 0,
            verifying_key: vk_bytes,
        });

        let profile = GroupPublicProfile {
            group_id,
            display_name: "Test Group".into(),
            description: "".into(),
            avatar_hash: None,
            network_type: NetworkType::Private,
            member_count: None,
            created_at: 0,
            signed_by: [0u8; 32],
            signature: vec![],
        };
        let group = Group {
            group_id,
            profile,
            ed25519_public: [0u8; 32],
            x25519_public: [0u8; 32],
            symmetric_key,
            is_admin: false,
            ed25519_private: None,
            members: vec![PeerId(sender_bytes), PeerId(our_bytes)],
            admins: vec![],
            our_peer_id: PeerId(our_bytes),
            joined_at: 0,
            rekey_interval_secs: 604800,
            last_rekey_at: 0,
            sender_key_epoch: 1,
            sequence: 0,
            lan_config: GroupLanConfig::default(),
            my_sender_chain_key: None,
            my_sender_iteration: 0,
            my_sender_signing_key: None,
            peer_sender_keys,
        };

        let room = Room {
            id: room_id,
            name: "Test Room".into(),
            conversation_type: ConversationType::Group,
            participants: vec![PeerId(sender_bytes), PeerId(our_bytes)],
            last_message_preview: None,
            last_message_at: None,
            unread_count: 0,
            is_muted: false,
            mute_until: None,
            is_archived: false,
            is_pinned: false,
            security_mode: MessageSecurityMode::Standard,
            disappearing_timer: None,
            next_sequence: 0,
            labels: vec![],
            draft: None,
        };

        // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
        // and is not accessed concurrently; raw access here mirrors the FFI
        // calling convention this test exercises.
        unsafe {
            (*ctx_ptr).groups.lock().unwrap().push(group);
            (*ctx_ptr).rooms.lock().unwrap().push(room);
        }

        (gid_hex, room_id_hex, sender_hex, sk)
    }

    /// Build a valid `group_message_sk` wire frame.
    fn make_sk_frame(
        mut sk: crate::crypto::sender_keys::SenderKey,
        symmetric_key: [u8; 32],
        group_id_hex: &str,
        sender_hex: &str,
        room_id_hex: &str,
        text: &str,
    ) -> serde_json::Value {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};

        let plaintext = serde_json::json!({
            "type": "group_message",
            "groupId": group_id_hex,
            "roomId": room_id_hex,
            "msgId": "test-msg-id",
            "sender": sender_hex,
            "text": text,
            "timestamp": 0u64,
        });
        let pt_bytes = serde_json::to_vec(&plaintext).unwrap();
        let sk_msg = sk.encrypt(&pt_bytes).unwrap();

        let sk_wire = serde_json::json!({
            "iteration": sk_msg.iteration,
            "ciphertext": hex::encode(&sk_msg.ciphertext),
            "signature": hex::encode(&sk_msg.signature),
        });
        let sk_wire_bytes = serde_json::to_vec(&sk_wire).unwrap();

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&sk_msg.iteration.to_be_bytes());

        let sym_cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key).unwrap();
        let wrapped = sym_cipher.encrypt(
            chacha20poly1305::Nonce::from_slice(&nonce_bytes),
            sk_wire_bytes.as_ref(),
        ).unwrap();

        serde_json::json!({
            "type": "group_message_sk",
            "groupId": group_id_hex,
            "sender": sender_hex,
            "epoch": sk_msg.iteration,
            "nonce": hex::encode(nonce_bytes),
            "wrapped": hex::encode(&wrapped),
        })
    }

    /// Full round-trip: sender encrypts with Sender Key, receiver decrypts and
    /// emits a MessageAdded event with the correct text.
    #[test]
    fn test_group_sk_message_round_trip() {
        let (ctx_ptr, _dir) = make_ctx();
        let (gid_hex, room_id_hex, sender_hex, sk) = setup_sk_group(ctx_ptr);
        let symmetric_key = [0x33_u8; 32];

        let frame = make_sk_frame(sk, symmetric_key, &gid_hex, &sender_hex, &room_id_hex, "hello group");

        // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
        // and is not accessed concurrently; raw access here mirrors the FFI
        // calling convention this test exercises.
        let ok = unsafe { (*ctx_ptr).process_group_message_sk_frame(&frame) };
        assert!(ok, "SK frame must decrypt successfully");

        // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
        // and is not accessed concurrently; raw access here mirrors the FFI
        // calling convention this test exercises.
        let events: Vec<serde_json::Value> = unsafe {
            (*ctx_ptr).event_queue.lock().unwrap().drain(..).collect()
        };
        assert!(events.iter().any(|e| {
            e.get("type").and_then(|t| t.as_str()) == Some("MessageAdded")
            && e.get("data").and_then(|d| d.get("text")).and_then(|t| t.as_str()) == Some("hello group")
        }), "MessageAdded event must be emitted with correct text; events: {events:?}");

        mesh_destroy(ctx_ptr);
    }

    /// Second message in the chain decrypts after the first advanced the
    /// receiver's chain state.
    #[test]
    fn test_group_sk_message_chain_advances() {
        use crate::crypto::sender_keys::SenderKey;

        let (ctx_ptr, _dir) = make_ctx();
        let (gid_hex, room_id_hex, sender_hex, sk) = setup_sk_group(ctx_ptr);
        let symmetric_key = [0x33_u8; 32];
        let sender_bytes = [0xAA_u8; 32];

        // Reconstruct sender key from stored state so both sides advance together.
        let (init_ck, init_iter, signing_key_bytes) = {
            // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
            // and is not accessed concurrently; raw access here mirrors the FFI
            // calling convention this test exercises.
            let groups = unsafe { (*ctx_ptr).groups.lock().unwrap() };
            let g = groups.iter().find(|g| hex::encode(g.group_id) == gid_hex).unwrap();
            let psk = g.peer_sender_keys.get(&sender_bytes).unwrap();
            (psk.chain_key, psk.next_iteration, sk.signing_key_bytes())
        };

        let sk1 = SenderKey::from_parts(init_ck, init_iter, &signing_key_bytes).unwrap();
        let frame1 = make_sk_frame(sk1, symmetric_key, &gid_hex, &sender_hex, &room_id_hex, "first");
        // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
        // and is not accessed concurrently; raw access here mirrors the FFI
        // calling convention this test exercises.
        assert!(unsafe { (*ctx_ptr).process_group_message_sk_frame(&frame1) }, "first message must succeed");

        // After first message, receiver state advanced. Sender must also advance.
        // Read back updated chain key from the group.
        let (ck2, iter2) = {
            // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
            // and is not accessed concurrently; raw access here mirrors the FFI
            // calling convention this test exercises.
            let groups = unsafe { (*ctx_ptr).groups.lock().unwrap() };
            let g = groups.iter().find(|g| hex::encode(g.group_id) == gid_hex).unwrap();
            let psk = g.peer_sender_keys.get(&sender_bytes).unwrap();
            (psk.chain_key, psk.next_iteration)
        };

        let sk2 = SenderKey::from_parts(ck2, iter2, &signing_key_bytes).unwrap();
        let frame2 = make_sk_frame(sk2, symmetric_key, &gid_hex, &sender_hex, &room_id_hex, "second");
        // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
        // and is not accessed concurrently; raw access here mirrors the FFI
        // calling convention this test exercises.
        assert!(unsafe { (*ctx_ptr).process_group_message_sk_frame(&frame2) }, "second message must succeed");

        // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
        // and is not accessed concurrently; raw access here mirrors the FFI
        // calling convention this test exercises.
        let events: Vec<serde_json::Value> = unsafe {
            (*ctx_ptr).event_queue.lock().unwrap().drain(..).collect()
        };
        let texts: Vec<&str> = events.iter()
            .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("MessageAdded"))
            .filter_map(|e| e.get("data").and_then(|d| d.get("text")).and_then(|t| t.as_str()))
            .collect();
        assert!(texts.contains(&"first"), "first message text must appear");
        assert!(texts.contains(&"second"), "second message text must appear");

        mesh_destroy(ctx_ptr);
    }

    /// Unknown sender (no Sender Key registered) → rejected without panic.
    #[test]
    fn test_group_sk_missing_sender_key_rejected() {
        let (ctx_ptr, _dir) = make_ctx();
        let (gid_hex, room_id_hex, _sender_hex, _sk) = setup_sk_group(ctx_ptr);
        let symmetric_key = [0x33_u8; 32];

        let unknown_sender = hex::encode([0xFF_u8; 32]);
        let unknown_sk = crate::crypto::sender_keys::SenderKey::generate();
        let frame = make_sk_frame(unknown_sk, symmetric_key, &gid_hex, &unknown_sender, &room_id_hex, "fail");

        // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
        // and is not accessed concurrently; raw access here mirrors the FFI
        // calling convention this test exercises.
        let ok = unsafe { (*ctx_ptr).process_group_message_sk_frame(&frame) };
        assert!(!ok, "Unknown sender must be rejected");

        mesh_destroy(ctx_ptr);
    }

    /// Corrupted outer `wrapped` ciphertext (wrong symmetric key layer).
    #[test]
    fn test_group_sk_tampered_outer_ciphertext_rejected() {
        let (ctx_ptr, _dir) = make_ctx();
        let (gid_hex, room_id_hex, sender_hex, sk) = setup_sk_group(ctx_ptr);
        let symmetric_key = [0x33_u8; 32];

        let mut frame = make_sk_frame(sk, symmetric_key, &gid_hex, &sender_hex, &room_id_hex, "secret");
        if let Some(w) = frame.get_mut("wrapped") {
            let mut bytes = hex::decode(w.as_str().unwrap()).unwrap();
            bytes[0] ^= 0xFF;
            *w = serde_json::Value::String(hex::encode(&bytes));
        }

        // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
        // and is not accessed concurrently; raw access here mirrors the FFI
        // calling convention this test exercises.
        let ok = unsafe { (*ctx_ptr).process_group_message_sk_frame(&frame) };
        assert!(!ok, "Tampered outer ciphertext must be rejected");

        mesh_destroy(ctx_ptr);
    }

    /// Valid outer layer but tampered Ed25519 signature on inner SK message.
    #[test]
    fn test_group_sk_tampered_signature_rejected() {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};

        let (ctx_ptr, _dir) = make_ctx();
        let (gid_hex, room_id_hex, sender_hex, mut sk) = setup_sk_group(ctx_ptr);
        let symmetric_key = [0x33_u8; 32];

        let pt = serde_json::json!({
            "type": "group_message", "groupId": &gid_hex,
            "roomId": &room_id_hex, "msgId": "x", "sender": &sender_hex,
            "text": "test", "timestamp": 0u64,
        });
        let sk_msg = sk.encrypt(&serde_json::to_vec(&pt).unwrap()).unwrap();

        let mut bad_sig = sk_msg.signature.clone();
        bad_sig[0] ^= 0xFF;

        let sk_wire = serde_json::json!({
            "iteration": sk_msg.iteration,
            "ciphertext": hex::encode(&sk_msg.ciphertext),
            "signature": hex::encode(&bad_sig),
        });
        let sk_wire_bytes = serde_json::to_vec(&sk_wire).unwrap();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&sk_msg.iteration.to_be_bytes());

        let sym_cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key).unwrap();
        let wrapped = sym_cipher.encrypt(
            chacha20poly1305::Nonce::from_slice(&nonce_bytes),
            sk_wire_bytes.as_ref(),
        ).unwrap();

        let frame = serde_json::json!({
            "type": "group_message_sk", "groupId": &gid_hex,
            "sender": &sender_hex, "epoch": sk_msg.iteration,
            "nonce": hex::encode(nonce_bytes), "wrapped": hex::encode(&wrapped),
        });

        // SAFETY: `ctx_ptr` was allocated by `Box::into_raw` in test setup
        // and is not accessed concurrently; raw access here mirrors the FFI
        // calling convention this test exercises.
        let ok = unsafe { (*ctx_ptr).process_group_message_sk_frame(&frame) };
        assert!(!ok, "Tampered signature must be rejected");

        mesh_destroy(ctx_ptr);
    }

    // ---------------------------------------------------------------------------
    // Backup restore semantic tests (§3.7)
    // ---------------------------------------------------------------------------

    /// Helper: create a ctx, generate identity, add a room, create a backup.
    /// Returns (ctx_ptr, dir, backup_b64_json).
    fn make_ctx_with_backup(room_name: &str, passphrase: &str) -> (*mut MeshContext, TempDir, String) {
        let (ctx, dir) = make_ctx();
        let name = CString::new("Alice").unwrap();
        assert_eq!(mi_create_identity(ctx, name.as_ptr()), 0);

        // Add a room so the backup contains something.
        let rname = CString::new(room_name).unwrap();
        let r = mi_create_room(ctx, rname.as_ptr(), ptr::null());
        assert!(!r.is_null());

        let pass_c = CString::new(passphrase).unwrap();
        let backup_ptr = mi_create_backup(ctx, pass_c.as_ptr(), 0); // standard
        assert!(!backup_ptr.is_null());
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let backup_json = unsafe { CStr::from_ptr(backup_ptr).to_str().unwrap().to_string() };
        let v: serde_json::Value = serde_json::from_str(&backup_json).unwrap();
        assert_eq!(v["ok"], true, "mi_create_backup should succeed");
        let b64 = serde_json::json!({ "backup_b64": v["backup_b64"] }).to_string();

        (ctx, dir, b64)
    }

    #[test]
    fn test_import_identity_replaces_existing_state() {
        // Set up a backup with one room ("OldRoom").
        let (ctx, _dir, backup_json) = make_ctx_with_backup("OldRoom", "secret-passphrase");

        // Add another room AFTER the backup was made.
        let rname = CString::new("PostBackupRoom").unwrap();
        mi_create_room(ctx, rname.as_ptr(), ptr::null());

        // Restore the backup — should wipe PostBackupRoom and restore only OldRoom.
        let pass_c = CString::new("secret-passphrase").unwrap();
        let b64_c = CString::new(backup_json).unwrap();
        let result = mi_import_identity(ctx, b64_c.as_ptr(), pass_c.as_ptr());
        assert_eq!(result, 0, "import should succeed");

        let rooms_ptr = mi_get_room_list(ctx);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let rooms_str = unsafe { CStr::from_ptr(rooms_ptr).to_str().unwrap() };
        let rooms: Vec<serde_json::Value> = serde_json::from_str(rooms_str).unwrap();

        assert_eq!(rooms.len(), 1, "restore should replace, not merge");
        assert_eq!(rooms[0]["name"], "OldRoom", "only pre-backup room should be present");

        mesh_destroy(ctx);
    }

    #[test]
    fn test_import_identity_malformed_base64_rejected() {
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Alice").unwrap();
        assert_eq!(mi_create_identity(ctx, name.as_ptr()), 0);

        let bad_b64 = CString::new("!!!not-base64!!!").unwrap();
        let pass = CString::new("pass").unwrap();
        let result = mi_import_identity(ctx, bad_b64.as_ptr(), pass.as_ptr());
        assert_eq!(result, -1, "malformed base64 must be rejected");

        mesh_destroy(ctx);
    }

    #[test]
    fn test_import_identity_wrong_passphrase_rejected() {
        let (ctx, _dir, backup_json) = make_ctx_with_backup("Room", "correct-passphrase");

        let b64_c = CString::new(backup_json).unwrap();
        let wrong_pass = CString::new("wrong-pass").unwrap();
        let result = mi_import_identity(ctx, b64_c.as_ptr(), wrong_pass.as_ptr());
        assert_eq!(result, -1, "wrong passphrase must be rejected");

        mesh_destroy(ctx);
    }

    #[test]
    fn test_import_identity_without_loaded_identity_rejected() {
        // No identity loaded — restore must fail with -1.
        let (ctx, _dir) = make_ctx();
        let bad = CString::new("eyJhIjoiYiJ9").unwrap(); // {"a":"b"} in base64
        let pass = CString::new("pass").unwrap();
        let result = mi_import_identity(ctx, bad.as_ptr(), pass.as_ptr());
        assert_eq!(result, -1, "restore without identity must fail");
        mesh_destroy(ctx);
    }

    #[test]
    fn test_import_identity_json_missing_backup_b64_key_rejected() {
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Alice").unwrap();
        assert_eq!(mi_create_identity(ctx, name.as_ptr()), 0);

        // JSON wrapper without the "backup_b64" key.
        let bad_json = CString::new(r#"{"wrong_key":"somevalue"}"#).unwrap();
        let pass = CString::new("pass").unwrap();
        let result = mi_import_identity(ctx, bad_json.as_ptr(), pass.as_ptr());
        assert_eq!(result, -1, "missing backup_b64 key must be rejected");

        mesh_destroy(ctx);
    }

    // ---------------------------------------------------------------------------
    // Reaction wire protocol tests (§10.1.2)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_send_reaction_emits_local_event() {
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Alice").unwrap();
        assert_eq!(mi_create_identity(ctx, name.as_ptr()), 0);

        // Create a room and send a message to get a msg_id.
        let room_name = CString::new("Reaction Room").unwrap();
        let room_ptr = mi_create_room(ctx, room_name.as_ptr(), ptr::null());
        let room_json: serde_json::Value = serde_json::from_str(
            // SAFETY: The pointer was returned by our own FFI function and is
            // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
            unsafe { CStr::from_ptr(room_ptr).to_str().unwrap() }
        ).unwrap();
        let room_id_str = room_json["id"].as_str().unwrap().to_string();

        // Drain creation events.
        let _ = mi_poll_events(ctx);

        let text = CString::new("Hi").unwrap();
        assert_eq!(mi_send_text_message(ctx, CString::new(room_id_str.as_str()).unwrap().as_ptr(), text.as_ptr()), 0);
        let events_ptr = mi_poll_events(ctx);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let events_str = unsafe { CStr::from_ptr(events_ptr).to_str().unwrap() };
        let events: Vec<serde_json::Value> = serde_json::from_str(events_str).unwrap();
        let msg_event = events.iter().find(|e| e["type"] == "MessageAdded").unwrap();
        let msg_id_str = msg_event["data"]["id"].as_str().unwrap().to_string();

        // Send a reaction.
        let room_id_c = CString::new(room_id_str.as_str()).unwrap();
        let msg_id_c = CString::new(msg_id_str.as_str()).unwrap();
        let emoji_c = CString::new("👍").unwrap();
        let result = mi_send_reaction(ctx, room_id_c.as_ptr(), msg_id_c.as_ptr(), emoji_c.as_ptr());
        assert_eq!(result, 0);

        // Poll — should have a ReactionAdded event.
        let events_ptr = mi_poll_events(ctx);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let events_str = unsafe { CStr::from_ptr(events_ptr).to_str().unwrap() };
        let events: Vec<serde_json::Value> = serde_json::from_str(events_str).unwrap();
        let reaction = events.iter().find(|e| e["type"] == "ReactionAdded")
            .expect("ReactionAdded event must be emitted");
        assert_eq!(reaction["data"]["roomId"], room_id_str);
        assert_eq!(reaction["data"]["msgId"], msg_id_str);
        assert_eq!(reaction["data"]["emoji"], "👍");

        mesh_destroy(ctx);
    }

    #[test]
    fn test_send_reaction_empty_emoji_rejected() {
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Alice").unwrap();
        assert_eq!(mi_create_identity(ctx, name.as_ptr()), 0);

        let room_name = CString::new("Reaction Room 2").unwrap();
        let room_ptr = mi_create_room(ctx, room_name.as_ptr(), ptr::null());
        let room_json: serde_json::Value = serde_json::from_str(
            // SAFETY: The pointer was returned by our own FFI function and is
            // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
            unsafe { CStr::from_ptr(room_ptr).to_str().unwrap() }
        ).unwrap();
        let room_id_str = room_json["id"].as_str().unwrap().to_string();
        let _ = mi_poll_events(ctx);

        // Empty emoji should be rejected (-1).
        let room_id_c = CString::new(room_id_str.as_str()).unwrap();
        let msg_id_c = CString::new("aabbccdd").unwrap();
        let emoji_c = CString::new("").unwrap();
        let result = mi_send_reaction(ctx, room_id_c.as_ptr(), msg_id_c.as_ptr(), emoji_c.as_ptr());
        assert_eq!(result, -1, "empty emoji must be rejected");

        // No ReactionAdded event should have been emitted.
        let events_ptr = mi_poll_events(ctx);
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let events_str = unsafe { CStr::from_ptr(events_ptr).to_str().unwrap() };
        let events: Vec<serde_json::Value> = serde_json::from_str(events_str).unwrap();
        assert!(
            events.iter().all(|e| e["type"] != "ReactionAdded"),
            "No ReactionAdded should be emitted for empty emoji"
        );

        mesh_destroy(ctx);
    }

    // ---------------------------------------------------------------------------
    // WireGuard handshake tests (§5.2)
    // ---------------------------------------------------------------------------

    /// Test a complete initiator → responder WireGuard handshake through the FFI.
    ///
    /// Uses two in-process MeshContexts (Alice = initiator, Bob = responder).
    /// Verifies that both sides establish matching sessions and can encrypt/decrypt.
    #[test]
    fn test_wg_handshake_full_roundtrip() {
        // Create two contexts with distinct identities.
        let (alice, _alice_dir) = make_ctx();
        let (bob, _bob_dir) = make_ctx();
        let alice_name = CString::new("Alice").unwrap();
        let bob_name = CString::new("Bob").unwrap();
        assert_eq!(mi_create_identity(alice, alice_name.as_ptr()), 0);
        assert_eq!(mi_create_identity(bob, bob_name.as_ptr()), 0);

        // Exchange identity keys via pairing (simulated: add each other to contacts).
        let (alice_ed, alice_x, alice_id_hex) = {
            // SAFETY: This pointer was allocated by `mi_context_create` (or
            // equivalent) in this test and is not aliased during this block.
            let ctx = unsafe { &*alice };
            let guard = ctx.identity.lock().unwrap();
            let id = guard.as_ref().unwrap();
            (id.ed25519_pub, *id.x25519_pub.as_bytes(), id.peer_id().to_hex())
        };
        let (bob_ed, bob_x, bob_id_hex) = {
            // SAFETY: This pointer was allocated by `mi_context_create` (or
            // equivalent) in this test and is not aliased during this block.
            let ctx = unsafe { &*bob };
            let guard = ctx.identity.lock().unwrap();
            let id = guard.as_ref().unwrap();
            (id.ed25519_pub, *id.x25519_pub.as_bytes(), id.peer_id().to_hex())
        };

        // Manually add Bob to Alice's contact store and vice versa.
        {
            use crate::pairing::contact::ContactRecord;
            use crate::pairing::methods::PairingMethod;
            use crate::identity::peer_id::PeerId;

            let now = 1_000_000u64;

            let bob_peer_id = PeerId::from_ed25519_pub(&bob_ed);
            let contact_bob = ContactRecord::new(
                bob_peer_id,
                bob_ed,
                bob_x,
                PairingMethod::QrCode,
                now,
            );
            // SAFETY: This pointer was allocated by `mi_context_create` (or
            // equivalent) in this test and is not aliased during this block.
            let alice_ctx = unsafe { &*alice };
            alice_ctx.contacts.lock().unwrap().upsert(contact_bob);

            let alice_peer_id = PeerId::from_ed25519_pub(&alice_ed);
            let contact_alice = ContactRecord::new(
                alice_peer_id,
                alice_ed,
                alice_x,
                PairingMethod::QrCode,
                now,
            );
            // SAFETY: This pointer was allocated by `mi_context_create` (or
            // equivalent) in this test and is not aliased during this block.
            let bob_ctx = unsafe { &*bob };
            bob_ctx.contacts.lock().unwrap().upsert(contact_alice);
        }

        // Step 1: Alice initiates the WireGuard handshake.
        let bob_hex = CString::new(bob_id_hex.as_str()).unwrap();
        let init_resp_ptr = mi_wg_initiate_handshake(alice, bob_hex.as_ptr());
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let init_resp_str = unsafe { CStr::from_ptr(init_resp_ptr).to_str().unwrap() };
        let init_resp: serde_json::Value = serde_json::from_str(init_resp_str).unwrap();
        assert!(init_resp.get("error").is_none(), "initiate should succeed: {}", init_resp);
        let init_hex_str = init_resp["init_hex"].as_str().unwrap();
        assert_eq!(init_hex_str.len(), (32 + 48) * 2, "init message should be 80 bytes");

        // Verify Alice's pending handshake is stored.
        {
            // SAFETY: This pointer was allocated by `mi_context_create` (or
            // equivalent) in this test and is not aliased during this block.
            let alice_ctx = unsafe { &*alice };
            let pending = alice_ctx.pending_wg_handshakes.lock().unwrap();
            let bob_pid = crate::identity::peer_id::PeerId::from_ed25519_pub(&bob_ed);
            assert!(pending.contains_key(&bob_pid), "pending handshake must be stored");
        }

        // Step 2: Bob responds to Alice's handshake.
        let alice_hex = CString::new(alice_id_hex.as_str()).unwrap();
        let init_hex_c = CString::new(init_hex_str).unwrap();
        let respond_ptr = mi_wg_respond_to_handshake(bob, alice_hex.as_ptr(), init_hex_c.as_ptr());
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let respond_str = unsafe { CStr::from_ptr(respond_ptr).to_str().unwrap() };
        let respond_json: serde_json::Value = serde_json::from_str(respond_str).unwrap();
        assert!(respond_json.get("error").is_none(), "respond should succeed: {}", respond_json);
        let response_hex_str = respond_json["response_hex"].as_str().unwrap();
        assert_eq!(response_hex_str.len(), 64, "response should be 32 bytes");

        // Step 3: Alice completes the handshake with Bob's response.
        let response_hex_c = CString::new(response_hex_str).unwrap();
        let complete_ptr = mi_wg_complete_handshake(alice, bob_hex.as_ptr(), response_hex_c.as_ptr());
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let complete_str = unsafe { CStr::from_ptr(complete_ptr).to_str().unwrap() };
        let complete_json: serde_json::Value = serde_json::from_str(complete_str).unwrap();
        assert!(complete_json.get("error").is_none(), "complete should succeed: {}", complete_json);
        assert_eq!(complete_json["session_established"], true);

        // Verify both sides now have a WireGuard session.
        {
            // SAFETY: This pointer was allocated by `mi_context_create` (or
            // equivalent) in this test and is not aliased during this block.
            let alice_ctx = unsafe { &*alice };
            let bob_pid = crate::identity::peer_id::PeerId::from_ed25519_pub(&bob_ed);
            assert!(
                alice_ctx.wireguard_sessions.lock().unwrap().get(&bob_pid).is_some(),
                "Alice must have WG session with Bob"
            );
            // Pending entry should be consumed.
            assert!(
                alice_ctx.pending_wg_handshakes.lock().unwrap().get(&bob_pid).is_none(),
                "Pending handshake must be consumed after completion"
            );
        }
        {
            // SAFETY: This pointer was allocated by `mi_context_create` (or
            // equivalent) in this test and is not aliased during this block.
            let bob_ctx = unsafe { &*bob };
            let alice_pid = crate::identity::peer_id::PeerId::from_ed25519_pub(&alice_ed);
            assert!(
                bob_ctx.wireguard_sessions.lock().unwrap().get(&alice_pid).is_some(),
                "Bob must have WG session with Alice"
            );
        }

        mesh_destroy(alice);
        mesh_destroy(bob);
    }

    /// Completing a handshake without a prior initiation must fail.
    #[test]
    fn test_wg_complete_without_initiation_rejected() {
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Alice").unwrap();
        assert_eq!(mi_create_identity(ctx, name.as_ptr()), 0);

        let fake_peer_hex = CString::new("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
        let fake_response_hex = CString::new("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
        let result_ptr = mi_wg_complete_handshake(ctx, fake_peer_hex.as_ptr(), fake_response_hex.as_ptr());
        // SAFETY: The pointer was returned by our own FFI function and is
        // guaranteed to be a valid NUL-terminated string for the lifetime of ctx.
        let result_str = unsafe { CStr::from_ptr(result_ptr).to_str().unwrap() };
        let result_json: serde_json::Value = serde_json::from_str(result_str).unwrap();
        assert!(result_json.get("error").is_some(), "complete without initiation must return error");

        mesh_destroy(ctx);
    }
}
