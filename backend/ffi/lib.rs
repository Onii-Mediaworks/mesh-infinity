// FFI Bridge for Mesh Infinity
// Provides a C-compatible interface for Flutter integration.

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::path::Path;
use x25519_dalek::StaticSecret as X25519StaticSecret;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crate::auth::persistence::{IdentityStore, PersistedIdentity};
use crate::auth::web_of_trust::VerificationMethod as WotVerificationMethod;
use crate::backend::{
    FileTransferSummary, HostedServicePolicy, HostedServiceSummary, IdentitySummary, LocalProfile,
    MeshInfinityService, Message, NodeMode, PeerSummary, PreloadedIdentity, ReconnectSyncSnapshot,
    RoomSummary, ServiceConfig, Settings,
};
use crate::core::TrustLevel;
use crate::core::{MeshConfig, MeshInfinityError, PeerId, Result, TransportType};
use crate::crypto::{BackupManager, EncryptedBackup};
use crossbeam_channel::{Receiver, RecvTimeoutError};
use serde_json::{json, Value};

// Helper to safely handle mutex locks in FFI context
fn safe_lock<T>(mutex: &Mutex<T>) -> std::result::Result<std::sync::MutexGuard<'_, T>, String> {
    mutex
        .lock()
        .map_err(|e| format!("Mutex lock poisoned: {}", e))
}

// Macro to catch panics at FFI boundaries
#[allow(unused_macros)]
macro_rules! ffi_catch_panic {
    ($body:expr, $default:expr) => {
        match panic::catch_unwind(panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    format!("Panic: {}", s)
                } else if let Some(s) = e.downcast_ref::<String>() {
                    format!("Panic: {}", s)
                } else {
                    "Unknown panic".to_string()
                };
                set_last_error(&msg);
                $default
            }
        }
    };
}

#[repr(C)]
pub struct FfiMeshConfig {
    pub config_path: *const c_char,
    pub log_level: u8,
    pub enable_tor: bool,
    pub enable_clearnet: bool,
    pub mesh_discovery: bool,
    pub allow_relays: bool,
    pub enable_i2p: bool,
    pub enable_bluetooth: bool,
    pub enable_rf: bool,
    pub wireguard_port: u16,
    pub max_peers: u32,
    pub max_connections: u32,
    pub node_mode: u8,
}

#[repr(C)]
pub struct FfiPeerInfo {
    pub peer_id: [u8; 32],
    pub public_key: [u8; 32],
    pub trust_level: u8,
    pub available_transports: u32,
}

#[repr(C)]
pub struct FfiMessage {
    pub sender_id: [u8; 32],
    pub target_id: [u8; 32],
    pub payload: *const u8,
    pub payload_len: usize,
    pub timestamp: u64,
}

#[repr(C)]
pub struct MeshContext {
    _private: [u8; 0],
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";
const MAX_TEXT_LEN: usize = 8192;
const MAX_NAME_LEN: usize = 128;
const MAX_ID_LEN: usize = 128;
const MAX_KEY_LEN: usize = 4096;
const MAX_EVENTS: usize = 256;

static MESH_STATE: Mutex<Option<Arc<Mutex<ServiceHandle>>>> = Mutex::new(None);
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
static IDENTITY_STORE: Mutex<Option<IdentityStore>> = Mutex::new(None);
static CONFIG_DIR_OVERRIDE: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

struct ServiceHandle {
    service: MeshInfinityService,
    events: Arc<Mutex<VecDeque<BackendEvent>>>,
    shutdown: Arc<AtomicBool>,
    message_thread: Option<JoinHandle<()>>,
    transfer_thread: Option<JoinHandle<()>>,
}

impl ServiceHandle {
    /// Construct a new instance.
    fn new(service: MeshInfinityService) -> Self {
        let events = Arc::new(Mutex::new(VecDeque::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let message_receiver = service.register_message_listener();
        let transfer_receiver = service.register_transfer_listener();

        let message_thread = Some(spawn_listener(
            message_receiver,
            Arc::clone(&events),
            Arc::clone(&shutdown),
            BackendEvent::MessageAdded,
        ));

        let transfer_thread = Some(spawn_listener(
            transfer_receiver,
            Arc::clone(&events),
            Arc::clone(&shutdown),
            BackendEvent::TransferUpdated,
        ));

        Self {
            service,
            events,
            shutdown,
            message_thread,
            transfer_thread,
        }
    }

    /// Push event.
    fn push_event(&self, event: BackendEvent) {
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= MAX_EVENTS {
                events.pop_front();
            }
            events.push_back(event);
        }
    }

    /// Drain events.
    fn drain_events(&self, max: usize) -> Vec<BackendEvent> {
        let Ok(mut events) = self.events.lock() else {
            return Vec::new();
        };
        let mut drained = Vec::new();
        for _ in 0..max {
            if let Some(event) = events.pop_front() {
                drained.push(event);
            } else {
                break;
            }
        }
        drained
    }

    /// Shutdown.
    fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.message_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.transfer_thread.take() {
            let _ = handle.join();
        }
    }
}

enum BackendEvent {
    MessageAdded(Message),
    RoomUpdated(RoomSummary),
    RoomDeleted(String),
    MessageDeleted { room_id: String, message_id: String },
    PeerUpdated(PeerSummary),
    TransferUpdated(FileTransferSummary),
    SettingsUpdated(Settings),
    ActiveRoomChanged(Option<String>),
    TrustUpdated { peer_id: String, trust_level: i32 },
}

fn spawn_listener<T: Send + 'static>(
    receiver: Receiver<T>,
    events: Arc<Mutex<VecDeque<BackendEvent>>>,
    shutdown: Arc<AtomicBool>,
    mapper: fn(T) -> BackendEvent,
) -> JoinHandle<()> {
    std::thread::spawn(move || loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(item) => {
                let event = mapper(item);
                if let Ok(mut queue) = events.lock() {
                    if queue.len() >= MAX_EVENTS {
                        queue.pop_front();
                    }
                    queue.push_back(event);
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    })
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mesh_init(config: *const FfiMeshConfig) -> *mut MeshContext {
    if config.is_null() {
        set_last_error("config pointer was null");
        return std::ptr::null_mut();
    }

    let config = unsafe { config_ref(config) };
    let defaults = MeshConfig::default();
    let rust_config = MeshConfig {
        config_path: if config.config_path.is_null() {
            None
        } else {
            let c_str = unsafe { CStr::from_ptr(config.config_path) };
            Some(c_str.to_string_lossy().into_owned())
        },
        log_level: config.log_level,
        enable_tor: config.enable_tor,
        enable_clearnet: config.enable_clearnet,
        mesh_discovery: config.mesh_discovery,
        allow_relays: config.allow_relays,
        enable_i2p: config.enable_i2p,
        enable_bluetooth: config.enable_bluetooth,
        enable_rf: config.enable_rf,
        wireguard_port: if config.wireguard_port == 0 {
            defaults.wireguard_port
        } else {
            config.wireguard_port
        },
        max_peers: if config.max_peers == 0 {
            defaults.max_peers
        } else {
            config.max_peers as usize
        },
        max_connections: if config.max_connections == 0 {
            defaults.max_connections
        } else {
            config.max_connections as usize
        },
    };

    // Resolve config directory: use the caller-supplied path or fall back to
    // a platform default so identity persistence works without explicit config.
    let config_dir = if let Ok(override_guard) = CONFIG_DIR_OVERRIDE.lock() {
        override_guard.clone().unwrap_or_else(|| {
            rust_config
                .config_path
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::var("HOME")
                        .map(|h| std::path::PathBuf::from(h).join(".mesh-infinity"))
                        .unwrap_or_else(|_| std::path::PathBuf::from(".mesh-infinity"))
                })
        })
    } else {
        rust_config
            .config_path
            .as_deref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".mesh-infinity"))
                    .unwrap_or_else(|_| std::path::PathBuf::from(".mesh-infinity"))
            })
    };

    // Set up the identity store for later FFI operations.
    let store = IdentityStore::new(&config_dir);
    if let Ok(mut store_guard) = IDENTITY_STORE.lock() {
        *store_guard = Some(IdentityStore::new(&config_dir));
    }

    // Try to load a persisted identity from disk.
    let preloaded_identity = if store.exists() {
        match store.load() {
            Ok(persisted) => {
                let ed25519_ok: Option<[u8; 32]> =
                    persisted.ed25519_secret.as_slice().try_into().ok();
                let x25519_ok: Option<[u8; 32]> =
                    persisted.x25519_secret.as_slice().try_into().ok();
                match (ed25519_ok, x25519_ok) {
                    (Some(ed25519), Some(x25519)) => {
                        let profile = LocalProfile {
                            public_display_name: persisted.public_display_name,
                            identity_is_public: persisted.identity_is_public,
                            private_display_name: persisted.private_display_name,
                            private_bio: persisted.private_bio,
                        };
                        Some(PreloadedIdentity {
                            ed25519_secret: ed25519,
                            x25519_secret: x25519,
                            name: persisted.name,
                            profile,
                        })
                    }
                    _ => {
                        set_last_error("Persisted identity has malformed key material");
                        None
                    }
                }
            }
            Err(e) => {
                set_last_error(format!("Failed to load persisted identity: {}", e));
                None
            }
        }
    } else {
        None
    };

    let service_config = ServiceConfig {
        initial_mode: node_mode_from_u8(config.node_mode),
        mesh_config: rust_config,
        identity_name: None,
        preloaded_identity,
    };

    let Ok(mut state) = MESH_STATE.lock() else {
        set_last_error("Failed to acquire mesh state lock");
        return std::ptr::null_mut();
    };

    // If already initialized, return the existing instance (idempotent)
    if let Some(existing) = state.as_ref() {
        return Arc::into_raw(Arc::clone(existing)) as *mut MeshContext;
    }

    // Create new service
    let service = MeshInfinityService::new(service_config);
    let handle = ServiceHandle::new(service);
    let arc_handle = Arc::new(Mutex::new(handle));

    *state = Some(arc_handle.clone());

    Arc::into_raw(arc_handle) as *mut MeshContext
}

/// Override the config directory for identity persistence.
///
/// This must be called before `mesh_init` to take effect.
#[no_mangle]
pub extern "C" fn mi_set_config_dir(path_ptr: *const c_char) -> i32 {
    if path_ptr.is_null() {
        set_last_error("config path pointer was null");
        return -1;
    }

    let path = match read_cstr(path_ptr, 4096, "config_path") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return -1;
        }
    };

    let trimmed = path.trim();
    if trimmed.is_empty() {
        set_last_error("config path was empty");
        return -1;
    }

    let mut guard = CONFIG_DIR_OVERRIDE.lock().unwrap();
    *guard = Some(std::path::PathBuf::from(trimmed));
    0
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_MainActivity_nativeSetConfigDir(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    path: jni::objects::JString,
) -> jni::sys::jint {
    let Ok(path_str) = env.get_string(&path) else {
        set_last_error("Failed to read config dir from Java");
        return -1;
    };
    let trimmed = path_str.to_string_lossy();
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        set_last_error("config path was empty");
        return -1;
    }
    let mut guard = CONFIG_DIR_OVERRIDE.lock().unwrap();
    *guard = Some(std::path::PathBuf::from(trimmed));
    0
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mesh_send_message(ctx: *mut MeshContext, message: *const FfiMessage) -> i32 {
    if ctx.is_null() || message.is_null() {
        set_last_error("message pointer was null");
        return -1;
    }

    let message = unsafe { message_ref(message) };
    if message.payload.is_null() || message.payload_len == 0 {
        set_last_error("message payload was empty");
        return -1;
    }

    if message.payload_len > MAX_TEXT_LEN {
        set_last_error("message payload too large");
        return rust_error_to_c_code(&MeshInfinityError::InvalidMessageFormat);
    }

    let payload = unsafe { std::slice::from_raw_parts(message.payload, message.payload_len) };
    let text = match std::str::from_utf8(payload) {
        Ok(value) => value,
        Err(_) => {
            set_last_error("message payload was not valid utf-8");
            return rust_error_to_c_code(&MeshInfinityError::InvalidMessageFormat);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let Ok(mut guard) = service.lock() else {
        set_last_error("Failed to acquire service lock");
        return -1;
    };
    match guard.service.send_message(text) {
        Ok(()) => {
            push_room_update(&mut guard, None);
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn mesh_receive_messages(
    ctx: *mut MeshContext,
    callback: extern "C" fn(*const FfiMessage, *mut c_void),
    user_data: *mut c_void,
) {
    if ctx.is_null() {
        return;
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(_) => return,
    };

    let events = {
        let guard = service.lock().unwrap();
        guard.drain_events(MAX_EVENTS)
    };

    for event in events {
        if let BackendEvent::MessageAdded(message) = event {
            let bytes = message.text.as_bytes();
            let ffi_message = FfiMessage {
                sender_id: [0u8; 32],
                target_id: [0u8; 32],
                payload: bytes.as_ptr(),
                payload_len: bytes.len(),
                timestamp: 0,
            };
            callback(&ffi_message as *const FfiMessage, user_data);
        }
    }
}

#[no_mangle]
pub extern "C" fn mesh_destroy(ctx: *mut MeshContext) {
    if ctx.is_null() {
        return;
    }

    // Validate the context pointer matches our stored state before dereferencing
    let Ok(mut state) = MESH_STATE.lock() else {
        set_last_error("Failed to acquire mesh state lock during destroy");
        return;
    };

    if state.is_none() {
        set_last_error("Attempted to destroy uninitialized mesh context");
        return;
    }

    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<ServiceHandle>) };
    if let Ok(mut guard) = arc.lock() {
        guard.shutdown();
    }

    *state = None;
}

#[no_mangle]
pub extern "C" fn mesh_infinity_ffi_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn mi_rooms_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let rooms = service.lock().unwrap().service.rooms();
    let value = Value::Array(rooms.iter().map(room_to_json).collect());
    json_to_c_string(value)
}

#[no_mangle]
pub extern "C" fn mi_messages_json(ctx: *mut MeshContext, room_id: *const c_char) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let messages = if room_id.is_null() {
        service.lock().unwrap().service.messages_for_active_room()
    } else {
        match read_cstr(room_id, MAX_ID_LEN, "room_id") {
            Ok(id) => service.lock().unwrap().service.messages_for_room(&id),
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let value = Value::Array(messages.iter().map(message_to_json).collect());
    json_to_c_string(value)
}

#[no_mangle]
pub extern "C" fn mi_sync_room_messages_json(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    after_message_id: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let room_id = match read_cstr(room_id, MAX_ID_LEN, "room_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let after_message_id = if after_message_id.is_null() {
        None
    } else {
        match read_cstr(after_message_id, MAX_ID_LEN, "after_message_id") {
            Ok(value) => Some(value),
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let messages = match service
        .lock()
        .unwrap()
        .service
        .sync_room_messages_since(&room_id, after_message_id.as_deref())
    {
        Ok(items) => items,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let value = Value::Array(messages.iter().map(message_to_json).collect());
    json_to_c_string(value)
}

#[no_mangle]
pub extern "C" fn mi_resumable_file_transfers_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let transfers = service.lock().unwrap().service.resumable_file_transfers();
    let value = Value::Array(transfers.iter().map(transfer_to_json).collect());
    json_to_c_string(value)
}

#[no_mangle]
pub extern "C" fn mi_passive_ack_checkpoint_json(
    ctx: *mut MeshContext,
    peer_id: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let peer_id = match read_cstr(peer_id, MAX_ID_LEN, "peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let parsed_peer_id = match parse_peer_id(&peer_id) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let checkpoint = service
        .lock()
        .unwrap()
        .service
        .passive_ack_checkpoint(&parsed_peer_id);

    json_to_c_string(json!({
        "peerId": peer_id_string(&parsed_peer_id),
        "checkpoint": checkpoint,
    }))
}

#[no_mangle]
pub extern "C" fn mi_compact_passive_state(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let removed = service.lock().unwrap().service.compact_passive_state();
    json_to_c_string(json!({ "removed": removed }))
}

#[no_mangle]
pub extern "C" fn mi_compact_file_transfers(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let removed = service.lock().unwrap().service.compact_file_transfers();
    json_to_c_string(json!({ "removed": removed }))
}

#[no_mangle]
pub extern "C" fn mi_reconnect_sync_snapshot_json(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    after_message_id: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let room_id = match read_cstr(room_id, MAX_ID_LEN, "room_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let after_message_id = if after_message_id.is_null() {
        None
    } else {
        match read_cstr(after_message_id, MAX_ID_LEN, "after_message_id") {
            Ok(value) => Some(value),
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let snapshot = match service
        .lock()
        .unwrap()
        .service
        .reconnect_sync_snapshot(&room_id, after_message_id.as_deref())
    {
        Ok(snapshot) => snapshot,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    json_to_c_string(reconnect_snapshot_to_json(&snapshot))
}

#[no_mangle]
pub extern "C" fn mi_peers_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let peers = service.lock().unwrap().service.peers();
    let value = Value::Array(peers.iter().map(peer_to_json).collect());
    json_to_c_string(value)
}

#[no_mangle]
pub extern "C" fn mi_get_peer_list(ctx: *mut MeshContext) -> *mut c_char {
    mi_peers_json(ctx)
}

#[no_mangle]
pub extern "C" fn mi_file_transfers_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let transfers = service.lock().unwrap().service.file_transfers();
    let value = Value::Array(transfers.iter().map(transfer_to_json).collect());
    json_to_c_string(value)
}

#[no_mangle]
pub extern "C" fn mi_settings_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let settings = service.lock().unwrap().service.settings();
    json_to_c_string(settings_to_json(&settings))
}

#[no_mangle]
pub extern "C" fn mi_local_identity_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let identity = service.lock().unwrap().service.local_identity_summary();
    match identity {
        Some(identity) => json_to_c_string(identity_to_json(&identity)),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn mi_trust_attest(
    ctx: *mut MeshContext,
    endorser_peer_id: *const c_char,
    target_peer_id: *const c_char,
    trust_level: i32,
    verification_method: u8,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let endorser = match read_cstr(endorser_peer_id, MAX_ID_LEN, "endorser_peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };
    let target = match read_cstr(target_peer_id, MAX_ID_LEN, "target_peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let endorser_peer_id = match parse_peer_id(&endorser) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };
    let target_peer_id = match parse_peer_id(&target) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let trust_level = trust_level_from_i32(trust_level);
    let method = verification_method_from_u8(verification_method);

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    match guard
        .service
        .trust_attest(&endorser_peer_id, &target_peer_id, trust_level, method)
    {
        Ok(()) => {
            guard.push_event(BackendEvent::TrustUpdated {
                peer_id: peer_id_string(&target_peer_id),
                trust_level: trust_level as i32,
            });
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_trust_verify_json(
    ctx: *mut MeshContext,
    target_peer_id: *const c_char,
    markers_json: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let target = match read_cstr(target_peer_id, MAX_ID_LEN, "target_peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let markers_json = if markers_json.is_null() {
        "[]".to_string()
    } else {
        match read_cstr(markers_json, MAX_KEY_LEN, "markers_json") {
            Ok(value) => value,
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let target_peer_id = match parse_peer_id(&target) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let markers = match parse_trust_markers(&markers_json) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let trust_level = service
        .lock()
        .unwrap()
        .service
        .trust_verify(&target_peer_id, markers);

    json_to_c_string(json!({
        "peerId": peer_id_string(&target_peer_id),
        "trustLevel": trust_level as i32,
    }))
}

#[no_mangle]
pub extern "C" fn mi_active_room_id(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let room_id = service.lock().unwrap().service.active_room_id();
    match room_id {
        Some(id) => string_to_c_string(&id),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn mi_create_room(ctx: *mut MeshContext, name: *const c_char) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let name = match read_cstr(name, MAX_NAME_LEN, "room name") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let guard = service.lock().unwrap();
    match guard.service.create_room(&name) {
        Ok(room_id) => {
            if let Some(room) = guard
                .service
                .rooms()
                .into_iter()
                .find(|room| room.id == room_id)
            {
                guard.push_event(BackendEvent::RoomUpdated(room.clone()));
                guard.push_event(BackendEvent::ActiveRoomChanged(Some(room_id.clone())));
            }
            string_to_c_string(&room_id)
        }
        Err(err) => {
            set_last_error(err.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_select_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let room_id = match read_cstr(room_id, MAX_ID_LEN, "room_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    match guard.service.select_room(&room_id) {
        Ok(()) => {
            if let Some(room) = guard
                .service
                .rooms()
                .into_iter()
                .find(|room| room.id == room_id)
            {
                guard.push_event(BackendEvent::RoomUpdated(room.clone()));
            }
            guard.push_event(BackendEvent::ActiveRoomChanged(Some(room_id)));
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_delete_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let room_id = match read_cstr(room_id, MAX_ID_LEN, "room_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    let active_before = guard.service.active_room_id();
    match guard.service.delete_room(&room_id) {
        Ok(()) => {
            guard.push_event(BackendEvent::RoomDeleted(room_id.clone()));
            let active_after = guard.service.active_room_id();
            if active_before != active_after {
                guard.push_event(BackendEvent::ActiveRoomChanged(active_after));
            }
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_send_text_message(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    text: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let text = match read_cstr(text, MAX_TEXT_LEN, "message text") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let room_id = if room_id.is_null() {
        None
    } else {
        match read_cstr(room_id, MAX_ID_LEN, "room_id") {
            Ok(value) => Some(value),
            Err(err) => {
                set_last_error(err.to_string());
                return rust_error_to_c_code(&err);
            }
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let mut guard = service.lock().unwrap();
    let target_room_id = room_id.clone();
    let result = if let Some(room_id) = room_id.as_deref() {
        guard.service.send_message_to_room(room_id, &text)
    } else {
        guard.service.send_message(&text)
    };

    match result {
        Ok(()) => {
            push_room_update(&mut guard, target_room_id);
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_delete_message(ctx: *mut MeshContext, message_id: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let message_id = match read_cstr(message_id, MAX_ID_LEN, "message_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    match guard.service.delete_message(&message_id) {
        Ok(room_id) => {
            if let Some(room) = guard
                .service
                .rooms()
                .into_iter()
                .find(|room| room.id == room_id)
            {
                guard.push_event(BackendEvent::RoomUpdated(room.clone()));
            }
            guard.push_event(BackendEvent::MessageDeleted {
                room_id,
                message_id,
            });
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_set_node_mode(ctx: *mut MeshContext, mode: u8) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    let node_mode = node_mode_from_u8(mode);
    guard.service.set_node_mode(node_mode);
    let settings = guard.service.settings();
    guard.push_event(BackendEvent::SettingsUpdated(settings));
    0
}

#[no_mangle]
pub extern "C" fn mi_set_transport_flags(
    ctx: *mut MeshContext,
    enable_tor: u8,
    enable_clearnet: u8,
    mesh_discovery: u8,
    allow_relays: u8,
    enable_i2p: u8,
    enable_bluetooth: u8,
    enable_rf: u8,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    guard.service.set_enable_tor(enable_tor != 0);
    guard.service.set_enable_clearnet(enable_clearnet != 0);
    guard.service.set_mesh_discovery(mesh_discovery != 0);
    guard.service.set_allow_relays(allow_relays != 0);
    guard.service.set_enable_i2p(enable_i2p != 0);
    guard.service.set_enable_bluetooth(enable_bluetooth != 0);
    guard.service.set_enable_rf(enable_rf != 0);
    let settings = guard.service.settings();
    guard.push_event(BackendEvent::SettingsUpdated(settings));
    0
}

#[no_mangle]
pub extern "C" fn mi_pair_peer(ctx: *mut MeshContext, code: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let code = match read_cstr(code, MAX_ID_LEN, "pairing code") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    match guard.service.pair_peer(&code) {
        Ok(()) => {
            if let Some(peer) = guard.service.peers().first().cloned() {
                guard.push_event(BackendEvent::PeerUpdated(peer));
            }
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_poll_events(ctx: *mut MeshContext, max_events: u32) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let max_events = if max_events == 0 {
        MAX_EVENTS
    } else {
        usize::min(max_events as usize, MAX_EVENTS)
    };

    let events = service.lock().unwrap().drain_events(max_events);
    let value = Value::Array(events.iter().map(event_to_json).collect());
    json_to_c_string(value)
}

#[no_mangle]
pub extern "C" fn mi_last_error_message() -> *mut c_char {
    match take_last_error() {
        Some(message) => string_to_c_string(&message),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn mi_has_identity(ctx: *mut MeshContext) -> u8 {
    if ctx.is_null() {
        return 0;
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(_) => return 0,
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(_) => return 0,
    };

    if guard.service.is_identity_persisted() {
        1
    } else {
        0
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mi_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    unsafe { free_c_string(value) };
}

// mDNS Discovery FFI functions

#[no_mangle]
pub extern "C" fn mi_mdns_enable(ctx: *mut MeshContext, port: u16) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(
            "context was null".to_string(),
        ));
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return rust_error_to_c_code(&err);
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return rust_error_to_c_code(&MeshInfinityError::LockError(err));
        }
    };

    match service_handle.service.enable_mdns(port) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("Failed to enable mDNS: {}", e));
            rust_error_to_c_code(&e)
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_mdns_disable(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(
            "context was null".to_string(),
        ));
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return rust_error_to_c_code(&err);
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return rust_error_to_c_code(&MeshInfinityError::LockError(err));
        }
    };

    match service_handle.service.disable_mdns() {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("Failed to disable mDNS: {}", e));
            rust_error_to_c_code(&e)
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_mdns_is_running(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(
            "context was null".to_string(),
        ));
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return rust_error_to_c_code(&err);
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return rust_error_to_c_code(&MeshInfinityError::LockError(err));
        }
    };

    if service_handle.service.is_mdns_running() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mi_mdns_get_discovered_peers(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return std::ptr::null_mut();
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return std::ptr::null_mut();
        }
    };

    match service_handle.service.get_discovered_peers() {
        Ok(peers) => {
            let peers_json: Vec<Value> = peers
                .iter()
                .map(|peer| {
                    json!({
                        "id": peer.id,
                        "name": peer.name,
                        "trustLevel": peer.trust_level,
                        "status": peer.status,
                    })
                })
                .collect();

            json_to_c_string(Value::Array(peers_json))
        }
        Err(e) => {
            set_last_error(format!("Failed to get discovered peers: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Export discovery jumpstart payload JSON.
///
/// `limit` controls maximum number of peers embedded in payload.
#[no_mangle]
pub extern "C" fn mi_discovery_export_jumpstart(
    ctx: *mut MeshContext,
    limit: usize,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return std::ptr::null_mut();
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return std::ptr::null_mut();
        }
    };

    match service_handle.service.export_discovery_jumpstart(limit) {
        Ok(payload) => string_to_c_string(&payload),
        Err(e) => {
            set_last_error(format!("Failed to export jumpstart payload: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Import discovery jumpstart payload JSON.
///
/// Returns number of peers ingested, or negative error code.
#[no_mangle]
pub extern "C" fn mi_discovery_import_jumpstart(
    ctx: *mut MeshContext,
    payload_json: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(
            "context was null".to_string(),
        ));
    }

    let payload = match read_cstr(payload_json, 1024 * 1024, "payload_json") {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("Invalid payload JSON string: {}", e));
            return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(e.to_string()));
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return rust_error_to_c_code(&err);
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return rust_error_to_c_code(&MeshInfinityError::LockError(err));
        }
    };

    match service_handle.service.import_discovery_jumpstart(&payload) {
        Ok(count) => i32::try_from(count).unwrap_or(i32::MAX),
        Err(e) => {
            set_last_error(format!("Failed to import jumpstart payload: {}", e));
            rust_error_to_c_code(&e)
        }
    }
}

/// Get network statistics (bytes sent/received, active connections)
/// Returns JSON: {"bytesSent": 0, "bytesReceived": 0, "activeConnections": 0}
#[no_mangle]
pub extern "C" fn mi_get_network_stats(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return std::ptr::null_mut();
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return std::ptr::null_mut();
        }
    };

    let stats = guard.service.network_stats();

    json_to_c_string(json!({
        "bytesSent": stats.bytes_sent,
        "bytesReceived": stats.bytes_received,
        "activeConnections": stats.active_connections,
        "pendingRoutes": stats.pending_routes,
        "deliveredRoutes": stats.delivered_routes,
        "failedRoutes": stats.failed_routes,
        "packetsLost": 0,
        "avgLatencyMs": 0,
        "bandwidthKbps": 0,
    }))
}

/// Start a file transfer (send or host)
/// direction: "send" or "host"
/// peer_id: target peer ID for send, null for host
/// file_path: path to the file
/// Returns transfer ID as JSON string or null on error
#[no_mangle]
pub extern "C" fn mi_file_transfer_start(
    ctx: *mut MeshContext,
    direction: *const c_char,
    _peer_id: *const c_char,
    file_path: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let direction_str = match read_cstr(direction, 16, "direction") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let peer_id = if _peer_id.is_null() {
        String::new()
    } else {
        match read_cstr(_peer_id, 256, "peer_id") {
            Ok(value) => value,
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let file_path_str = match read_cstr(file_path, 4096, "file_path") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let file_name = Path::new(&file_path_str)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .unwrap_or_else(|| file_path_str.clone());
    let file_size = std::fs::metadata(&file_path_str)
        .map(|meta| meta.len())
        .unwrap_or(0);

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return std::ptr::null_mut();
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return std::ptr::null_mut();
        }
    };

    let resolved_peer_id = if peer_id.trim().is_empty() {
        guard.service.settings().local_peer_id
    } else {
        peer_id.clone()
    };

    let result = match direction_str.as_str() {
        "send" => {
            if peer_id.trim().is_empty() {
                set_last_error("peer_id is required for send direction");
                return std::ptr::null_mut();
            }
            guard
                .service
                .queue_file_send(&resolved_peer_id, &file_name, file_size)
        }
        "host" | "receive" => {
            guard
                .service
                .queue_file_receive(&resolved_peer_id, &file_name, file_size)
        }
        _ => {
            set_last_error("direction must be 'send' or 'host'");
            return std::ptr::null_mut();
        }
    };

    match result {
        Ok(transfer_id) => json_to_c_string(json!({
            "transferId": transfer_id,
            "status": "pending",
        })),
        Err(e) => {
            set_last_error(format!("Failed to queue file transfer: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Cancel an active file transfer
/// transfer_id: ID of the transfer to cancel
/// Returns 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn mi_file_transfer_cancel(
    ctx: *mut MeshContext,
    transfer_id: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let transfer_id = match read_cstr(transfer_id, 256, "transfer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return -1;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return -1;
        }
    };

    match guard.service.cancel_file_transfer(&transfer_id) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("Failed to update transfer state: {}", e));
            rust_error_to_c_code(&e)
        }
    }
}

/// Get status of a specific file transfer
/// transfer_id: ID of the transfer
/// Returns JSON with transfer status or null on error
#[no_mangle]
pub extern "C" fn mi_file_transfer_status(
    ctx: *mut MeshContext,
    transfer_id: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let _transfer_id = match read_cstr(transfer_id, 256, "transfer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return std::ptr::null_mut();
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return std::ptr::null_mut();
        }
    };

    let transfer = guard.service.file_transfer(&_transfer_id);

    match transfer {
        Some(item) => json_to_c_string(json!({
            "transferId": item.id,
            "status": item.status,
            "name": item.name,
            "direction": item.direction,
            "peerId": item.peer_id,
            "sizeBytes": item.size_bytes,
            "transferredBytes": item.transferred_bytes,
        })),
        None => {
            set_last_error("Transfer not found");
            std::ptr::null_mut()
        }
    }
}

/// Gets list of configured services
/// Returns JSON array of services or empty array on error
#[no_mangle]
pub extern "C" fn mi_get_service_list(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return json_to_c_string(json!([]));
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return json_to_c_string(json!([]));
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return json_to_c_string(json!([]));
        }
    };

    let services = guard.service.hosted_services();
    let value = Value::Array(services.iter().map(hosted_service_to_json).collect());
    json_to_c_string(value)
}

/// Configures a service with the given parameters
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn mi_configure_service(
    ctx: *mut MeshContext,
    service_id: *const c_char,
    config_json: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let service_id = match read_cstr(service_id, 256, "service_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let config_json = match read_cstr(config_json, 4096, "config_json") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let parsed: Value = match serde_json::from_str(&config_json) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(format!("invalid config_json: {}", err));
            return 0;
        }
    };

    let name = parsed
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(&service_id)
        .to_string();
    let path = parsed
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let address = parsed
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let enabled = parsed
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let min_trust_level = parsed
        .get("minTrustLevel")
        .and_then(Value::as_i64)
        .map(|value| trust_level_from_i32(value as i32))
        .unwrap_or(TrustLevel::Trusted);
    let allowed_transports = parsed
        .get("allowedTransports")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str())
                .filter_map(transport_type_from_name)
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| {
            vec![
                TransportType::Tor,
                TransportType::I2P,
                TransportType::Bluetooth,
            ]
        });

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    match guard.service.configure_hosted_service_with_policy(
        &service_id,
        &name,
        &path,
        &address,
        enabled,
        HostedServicePolicy {
            min_trust_level,
            allowed_transports,
        },
    ) {
        Ok(()) => 1,
        Err(err) => {
            set_last_error(err.to_string());
            0
        }
    }
}

/// Checks whether a peer/transport tuple is allowed to access a hosted service.
/// Returns 1 when allowed, 0 when denied or on error.
#[no_mangle]
pub extern "C" fn mi_check_service_access(
    ctx: *mut MeshContext,
    service_id: *const c_char,
    peer_id: *const c_char,
    transport_name: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let service_id = match read_cstr(service_id, 256, "service_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let peer_id = match read_cstr(peer_id, 256, "peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let transport_name = match read_cstr(transport_name, 64, "transport_name") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let peer_id = match parse_peer_id(&peer_id) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let transport = match transport_type_from_name(&transport_name) {
        Some(value) => value,
        None => {
            set_last_error(format!("unknown transport: {}", transport_name));
            return 0;
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    match guard
        .service
        .hosted_service_access_allowed(&service_id, &peer_id, transport)
    {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(err) => {
            set_last_error(err.to_string());
            0
        }
    }
}

/// Toggles a transport flag (enable/disable transport)
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn mi_toggle_transport_flag(
    ctx: *mut MeshContext,
    transport_name: *const c_char,
    enabled: i32,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let transport_name = match read_cstr(transport_name, 64, "transport_name") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let enabled = enabled != 0;

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    match transport_name.to_ascii_lowercase().as_str() {
        "tor" => guard.service.set_enable_tor(enabled),
        "clearnet" => guard.service.set_enable_clearnet(enabled),
        "mesh_discovery" | "mdns" | "discovery" => guard.service.set_mesh_discovery(enabled),
        "relay" | "relays" => guard.service.set_allow_relays(enabled),
        "i2p" => guard.service.set_enable_i2p(enabled),
        "bluetooth" => guard.service.set_enable_bluetooth(enabled),
        "rf" => guard.service.set_enable_rf(enabled),
        _ => {
            set_last_error(format!("Unknown transport flag: {}", transport_name));
            return 0;
        }
    }
    1
}

/// Sets VPN route configuration
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn mi_set_vpn_route(ctx: *mut MeshContext, route_config_json: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let route_config = match read_cstr(route_config_json, 4096, "route_config_json") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    guard.service.set_vpn_route_config(route_config);
    1
}

/// Sets clearnet route configuration
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn mi_set_clearnet_route(
    ctx: *mut MeshContext,
    route_config_json: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let route_config = match read_cstr(route_config_json, 4096, "route_config_json") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    guard.service.set_clearnet_route_config(route_config);
    1
}

// ---------------------------------------------------------------------------
// Identity persistence FFI
// ---------------------------------------------------------------------------

/// Persist the current in-memory identity to disk for the first time.
///
/// Identity material (keypair, DH key) is already generated by `mesh_init`.
/// This call encrypts it into `identity.dat` / `identity.key` under the
/// config directory and marks `hasIdentity()` as true for future launches.
///
/// `name_ptr` may be null (no display name).
#[no_mangle]
pub extern "C" fn mi_create_identity(ctx: *mut MeshContext, name_ptr: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let name = if name_ptr.is_null() {
        None
    } else {
        match read_cstr(name_ptr, MAX_NAME_LEN, "name") {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }
            Err(e) => {
                set_last_error(e.to_string());
                return -1;
            }
        }
    };

    let service = match get_service() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let mut guard = service.lock().unwrap();

    if let Some(n) = name.clone() {
        if let Err(e) = guard.service.set_identity_name(Some(n)) {
            set_last_error(e.to_string());
            return -1;
        }
    }

    let (ed25519, x25519) = match guard.service.primary_secret_key_bytes() {
        Some(keys) => keys,
        None => {
            set_last_error("No primary identity available");
            return -1;
        }
    };

    let profile = guard.service.local_profile().clone();
    let persisted = PersistedIdentity {
        ed25519_secret: ed25519.to_vec(),
        x25519_secret: x25519.to_vec(),
        name,
        public_display_name: profile.public_display_name,
        identity_is_public: profile.identity_is_public,
        private_display_name: profile.private_display_name,
        private_bio: profile.private_bio,
    };

    let store_guard = IDENTITY_STORE.lock().unwrap();
    let store = match store_guard.as_ref() {
        Some(s) => s,
        None => {
            set_last_error("Identity store not initialised");
            return -1;
        }
    };

    if let Err(e) = store.save(&persisted) {
        set_last_error(e.to_string());
        return -1;
    }

    guard.service.set_identity_persisted(true);
    0
}

/// Update the public profile fields and re-persist the identity.
///
/// Expects JSON: `{"displayName":"Alice","isPublic":false}`
#[no_mangle]
pub extern "C" fn mi_set_public_profile(ctx: *mut MeshContext, json_ptr: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let json_str = match read_cstr(json_ptr, MAX_KEY_LEN, "json") {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };

    let parsed: Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("Invalid JSON: {}", e));
            return -1;
        }
    };

    let display_name = parsed
        .get("displayName")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let is_public = parsed
        .get("isPublic")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let service = match get_service() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let mut guard = service.lock().unwrap();

    let mut profile = guard.service.local_profile().clone();
    profile.public_display_name = display_name;
    profile.identity_is_public = is_public;
    guard.service.set_local_profile(profile);

    if let Err(e) = persist_identity(&mut guard.service) {
        set_last_error(e.to_string());
        return -1;
    }
    0
}

/// Update the private profile fields and re-persist the identity.
///
/// Expects JSON: `{"displayName":"Alice Smith","bio":"..."}`
#[no_mangle]
pub extern "C" fn mi_set_private_profile(ctx: *mut MeshContext, json_ptr: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let json_str = match read_cstr(json_ptr, MAX_KEY_LEN, "json") {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };

    let parsed: Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("Invalid JSON: {}", e));
            return -1;
        }
    };

    let display_name = parsed
        .get("displayName")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let bio = parsed
        .get("bio")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let service = match get_service() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let mut guard = service.lock().unwrap();

    let mut profile = guard.service.local_profile().clone();
    profile.private_display_name = display_name;
    profile.private_bio = bio;
    guard.service.set_local_profile(profile);

    if let Err(e) = persist_identity(&mut guard.service) {
        set_last_error(e.to_string());
        return -1;
    }
    0
}

/// Import an identity from an encrypted backup.
///
/// `backup_json_ptr` is the JSON-serialised `EncryptedBackup` payload.
/// `passphrase_ptr` is the passphrase used to decrypt it.
///
/// On success the new identity is persisted to disk and the service switches
/// to it immediately.
#[no_mangle]
pub extern "C" fn mi_import_identity(
    ctx: *mut MeshContext,
    backup_json_ptr: *const c_char,
    passphrase_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let backup_json = match read_cstr(backup_json_ptr, 1024 * 1024, "backup_json") {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let passphrase = match read_cstr(passphrase_ptr, MAX_KEY_LEN, "passphrase") {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };

    let backup: EncryptedBackup = match serde_json::from_str(&backup_json) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("Invalid backup JSON: {}", e));
            return -1;
        }
    };

    let manager = BackupManager::new();
    let (keypair_bytes, _trust_store, _network_map, settings) =
        match manager.restore_backup(&backup, &passphrase) {
            Ok(result) => result,
            Err(e) => {
                set_last_error(e.to_string());
                return -1;
            }
        };

    if keypair_bytes.len() < 32 {
        set_last_error("Backup keypair too short");
        return -1;
    }

    let ed25519: [u8; 32] = match keypair_bytes[..32].try_into() {
        Ok(b) => b,
        Err(_) => {
            set_last_error("Failed to extract ed25519 secret key from backup");
            return -1;
        }
    };

    // Generate a fresh X25519 DH secret — the backup format does not preserve it.
    let dh_secret = X25519StaticSecret::new(rand_core::OsRng);
    let x25519 = dh_secret.to_bytes();

    let name = settings.display_name.clone();
    let profile = LocalProfile::default();

    let service = match get_service() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let mut guard = service.lock().unwrap();

    if let Err(e) =
        guard
            .service
            .load_identity_from_bytes(ed25519, x25519, name.clone(), profile.clone())
    {
        set_last_error(e.to_string());
        return -1;
    }

    let persisted = PersistedIdentity {
        ed25519_secret: ed25519.to_vec(),
        x25519_secret: x25519.to_vec(),
        name,
        public_display_name: profile.public_display_name,
        identity_is_public: profile.identity_is_public,
        private_display_name: profile.private_display_name,
        private_bio: profile.private_bio,
    };

    let store_guard = IDENTITY_STORE.lock().unwrap();
    let store = match store_guard.as_ref() {
        Some(s) => s,
        None => {
            set_last_error("Identity store not initialised");
            return -1;
        }
    };

    if let Err(e) = store.save(&persisted) {
        set_last_error(e.to_string());
        return -1;
    }

    0
}

/// Killswitch: overwrite the keyfile with random bytes and remove all identity
/// files, permanently destroying the on-disk identity.
///
/// The in-memory identity remains active until the next restart.
#[no_mangle]
pub extern "C" fn mi_reset_identity(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let store_guard = IDENTITY_STORE.lock().unwrap();
    let store = match store_guard.as_ref() {
        Some(s) => s,
        None => {
            set_last_error("Identity store not initialised");
            return -1;
        }
    };

    if let Err(e) = store.destroy() {
        set_last_error(e.to_string());
        return -1;
    }

    if let Ok(service) = get_service() {
        if let Ok(mut guard) = service.lock() {
            guard.service.set_identity_persisted(false);
        }
    }

    0
}

// Helper: serialise the current service identity + profile and re-save to disk.
fn persist_identity(service: &mut MeshInfinityService) -> Result<()> {
    let (ed25519, x25519) = service
        .primary_secret_key_bytes()
        .ok_or(MeshInfinityError::AuthError("No primary identity".to_string()))?;

    let summary = service.local_identity_summary();
    let name = summary.and_then(|s| s.name);
    let profile = service.local_profile().clone();

    let persisted = PersistedIdentity {
        ed25519_secret: ed25519.to_vec(),
        x25519_secret: x25519.to_vec(),
        name,
        public_display_name: profile.public_display_name,
        identity_is_public: profile.identity_is_public,
        private_display_name: profile.private_display_name,
        private_bio: profile.private_bio,
    };

    let store_guard = IDENTITY_STORE
        .lock()
        .map_err(|_| MeshInfinityError::LockError("IDENTITY_STORE poisoned".to_string()))?;
    let store = store_guard
        .as_ref()
        .ok_or(MeshInfinityError::InvalidConfiguration(
            "Identity store not initialised".to_string(),
        ))?;

    store.save(&persisted)
}

/// Get service.
fn get_service() -> Result<Arc<Mutex<ServiceHandle>>> {
    MESH_STATE
        .lock()
        .unwrap()
        .clone()
        .ok_or(MeshInfinityError::ResourceUnavailable)
}

unsafe fn config_ref<'a>(ptr: *const FfiMeshConfig) -> &'a FfiMeshConfig {
    &*ptr
}

unsafe fn message_ref<'a>(ptr: *const FfiMessage) -> &'a FfiMessage {
    &*ptr
}

unsafe fn free_c_string(value: *mut c_char) {
    let _ = CString::from_raw(value);
}

/// Read cstr.
fn read_cstr(ptr: *const c_char, max_len: usize, field: &str) -> Result<String> {
    if ptr.is_null() {
        return Err(MeshInfinityError::InvalidConfiguration(format!(
            "{field} pointer was null"
        )));
    }
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let bytes = c_str.to_bytes();
    if bytes.len() > max_len {
        return Err(MeshInfinityError::InvalidConfiguration(format!(
            "{field} exceeded max length"
        )));
    }
    std::str::from_utf8(bytes)
        .map(|value| value.to_string())
        .map_err(|_| {
            MeshInfinityError::InvalidConfiguration(format!("{field} was not valid utf-8"))
        })
}

/// Parse peer id.
fn parse_peer_id(value: &str) -> Result<[u8; 32]> {
    let mut hex = String::new();
    for ch in value.chars() {
        if ch.is_ascii_hexdigit() {
            hex.push(ch);
        }
    }

    if hex.len() < 16 {
        return Err(MeshInfinityError::InvalidConfiguration(
            "peer_id too short".to_string(),
        ));
    }

    let mut bytes = [0u8; 32];
    let available = hex.len() / 2;
    let count = usize::min(bytes.len(), available);
    for (i, slot) in bytes.iter_mut().enumerate().take(count) {
        let idx = i * 2;
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).map_err(|_| {
            MeshInfinityError::InvalidConfiguration("peer_id was not valid hex".to_string())
        })?;
        *slot = byte;
    }
    Ok(bytes)
}

/// Parse trust markers.
fn parse_trust_markers(json_str: &str) -> Result<Vec<(PeerId, PeerId, TrustLevel, SystemTime)>> {
    let parsed: Value = serde_json::from_str(json_str)
        .map_err(|err| MeshInfinityError::DeserializationError(err.to_string()))?;
    let array = parsed.as_array().cloned().unwrap_or_default();
    let mut markers = Vec::new();

    for marker in array {
        let obj = marker.as_object().ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("invalid trust marker".to_string())
        })?;
        let endorser = obj
            .get("endorser")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                MeshInfinityError::InvalidConfiguration("missing endorser".to_string())
            })?;
        let target = obj
            .get("target")
            .and_then(|value| value.as_str())
            .ok_or_else(|| MeshInfinityError::InvalidConfiguration("missing target".to_string()))?;
        let trust_level = obj
            .get("trustLevel")
            .and_then(|value| value.as_i64())
            .unwrap_or(0) as i32;
        let timestamp = obj
            .get("timestamp")
            .and_then(|value| value.as_i64())
            .unwrap_or(0);

        let endorser = parse_peer_id(endorser)?;
        let target = parse_peer_id(target)?;
        let trust_level = trust_level_from_i32(trust_level);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp.max(0) as u64);
        markers.push((endorser, target, trust_level, timestamp));
    }

    Ok(markers)
}

/// Set last error.
fn set_last_error(message: impl Into<String>) {
    *LAST_ERROR.lock().unwrap() = Some(message.into());
}

/// Take last error.
fn take_last_error() -> Option<String> {
    LAST_ERROR.lock().unwrap().take()
}

/// Json to c string.
fn json_to_c_string(value: Value) -> *mut c_char {
    match serde_json::to_string(&value) {
        Ok(serialized) => string_to_c_string(&serialized),
        Err(err) => {
            set_last_error(err.to_string());
            std::ptr::null_mut()
        }
    }
}

/// String to c string.
fn string_to_c_string(value: &str) -> *mut c_char {
    match CString::new(value) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Room to json.
fn room_to_json(room: &RoomSummary) -> Value {
    json!({
        "id": room.id,
        "title": room.name,
        "preview": room.last_message,
        "lastSeen": room.timestamp,
        "unreadCount": room.unread_count,
        "threadType": if room.id.starts_with("dm-") { "direct" } else { "group" },
    })
}

/// Message to json.
fn message_to_json(message: &Message) -> Value {
    json!({
        "id": message.id,
        "roomId": message.room_id,
        "sender": message.sender,
        "text": message.text,
        "timestamp": message.timestamp,
        "isOutgoing": message.is_outgoing,
    })
}

/// Peer to json.
fn peer_to_json(peer: &PeerSummary) -> Value {
    json!({
        "id": peer.id,
        "name": peer.name,
        "trustLevel": peer.trust_level,
        "status": peer.status,
    })
}

/// Identity to json.
fn identity_to_json(identity: &IdentitySummary) -> Value {
    json!({
        "peerId": peer_id_string(&identity.peer_id),
        "publicKey": hex_encode(&identity.public_key),
        "dhPublicKey": hex_encode(&identity.dh_public),
        "name": identity.name,
    })
}

/// Transfer to json.
fn transfer_to_json(transfer: &FileTransferSummary) -> Value {
    json!({
        "id": transfer.id,
        "peerId": transfer.peer_id,
        "name": transfer.name,
        "sizeBytes": transfer.size_bytes,
        "transferredBytes": transfer.transferred_bytes,
        "status": transfer.status,
        "direction": transfer.direction,
    })
}

/// Reconnect snapshot to json.
fn reconnect_snapshot_to_json(snapshot: &ReconnectSyncSnapshot) -> Value {
    json!({
        "missedMessages": snapshot
            .missed_messages
            .iter()
            .map(message_to_json)
            .collect::<Vec<_>>(),
        "resumableTransfers": snapshot
            .resumable_transfers
            .iter()
            .map(transfer_to_json)
            .collect::<Vec<_>>(),
    })
}

/// Hosted service to json.
fn hosted_service_to_json(service: &HostedServiceSummary) -> Value {
    json!({
        "id": service.id,
        "name": service.name,
        "path": service.path,
        "address": service.address,
        "enabled": service.enabled,
        "minTrustLevel": service.min_trust_level,
        "allowedTransports": service.allowed_transports,
    })
}

/// Parse transport type from user-facing transport name.
fn transport_type_from_name(name: &str) -> Option<TransportType> {
    match name.to_ascii_lowercase().as_str() {
        "tor" => Some(TransportType::Tor),
        "i2p" => Some(TransportType::I2P),
        "bluetooth" => Some(TransportType::Bluetooth),
        "rf" => Some(TransportType::Rf),
        "clearnet" => Some(TransportType::Clearnet),
        _ => None,
    }
}

/// Settings to json.
fn settings_to_json(settings: &Settings) -> Value {
    json!({
        "nodeMode": node_mode_label(settings.node_mode),
        "enableTor": settings.enable_tor,
        "enableClearnet": settings.enable_clearnet,
        "meshDiscovery": settings.mesh_discovery,
        "allowRelays": settings.allow_relays,
        "enableI2p": settings.enable_i2p,
        "enableBluetooth": settings.enable_bluetooth,
        "enableRf": settings.enable_rf,
        "pairingCode": settings.pairing_code,
        "localPeerId": settings.local_peer_id,
    })
}

/// Peer id string.
fn peer_id_string(peer_id: &PeerId) -> String {
    hex_encode(peer_id)
}

/// Hex encode.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Push room update.
fn push_room_update(guard: &mut ServiceHandle, room_id: Option<String>) {
    let target_room_id = room_id.or_else(|| guard.service.active_room_id());
    if let Some(room_id) = target_room_id {
        if let Some(room) = guard
            .service
            .rooms()
            .into_iter()
            .find(|room| room.id == room_id)
        {
            guard.push_event(BackendEvent::RoomUpdated(room));
        }
    }
}

/// Node mode from u8.
fn node_mode_from_u8(mode: u8) -> NodeMode {
    match mode {
        1 => NodeMode::Server,
        2 => NodeMode::Dual,
        _ => NodeMode::Client,
    }
}

/// Node mode label.
fn node_mode_label(mode: NodeMode) -> &'static str {
    match mode {
        NodeMode::Client => "client",
        NodeMode::Server => "server",
        NodeMode::Dual => "dual",
    }
}

/// Trust level from i32.
fn trust_level_from_i32(level: i32) -> TrustLevel {
    match level {
        3 => TrustLevel::HighlyTrusted,
        2 => TrustLevel::Trusted,
        1 => TrustLevel::Caution,
        _ => TrustLevel::Untrusted,
    }
}

/// Verification method from u8.
fn verification_method_from_u8(method: u8) -> WotVerificationMethod {
    match method {
        1 => WotVerificationMethod::InPerson,
        2 => WotVerificationMethod::SharedSecret,
        3 => WotVerificationMethod::TrustedIntroduction,
        4 => WotVerificationMethod::PKI,
        _ => WotVerificationMethod::SharedSecret,
    }
}

/// Event to json.
fn event_to_json(event: &BackendEvent) -> Value {
    match event {
        BackendEvent::MessageAdded(message) => json!({
            "type": "message_added",
            "roomId": message.room_id,
            "message": message_to_json(message),
        }),
        BackendEvent::RoomUpdated(room) => json!({
            "type": "room_updated",
            "room": room_to_json(room),
        }),
        BackendEvent::RoomDeleted(room_id) => json!({
            "type": "room_deleted",
            "roomId": room_id,
        }),
        BackendEvent::PeerUpdated(peer) => json!({
            "type": "peer_updated",
            "peer": peer_to_json(peer),
        }),
        BackendEvent::MessageDeleted {
            room_id,
            message_id,
        } => json!({
            "type": "message_deleted",
            "roomId": room_id,
            "messageId": message_id,
        }),
        BackendEvent::TransferUpdated(transfer) => json!({
            "type": "transfer_updated",
            "transfer": transfer_to_json(transfer),
        }),
        BackendEvent::SettingsUpdated(settings) => json!({
            "type": "settings_updated",
            "settings": settings_to_json(settings),
        }),
        BackendEvent::ActiveRoomChanged(room_id) => json!({
            "type": "active_room_changed",
            "roomId": room_id,
        }),
        BackendEvent::TrustUpdated {
            peer_id,
            trust_level,
        } => json!({
            "type": "trust_updated",
            "peerId": peer_id,
            "trustLevel": trust_level,
        }),
    }
}

/// Rust error to c code.
fn rust_error_to_c_code(err: &MeshInfinityError) -> i32 {
    match err {
        MeshInfinityError::InvalidConfiguration(_) => -100,
        MeshInfinityError::NetworkError(_) => -200,
        MeshInfinityError::CryptoError(_) => -300,
        MeshInfinityError::AuthError(_) => -400,
        MeshInfinityError::TransportError(_) => -500,
        MeshInfinityError::WireGuardError(_) => -600,
        MeshInfinityError::DiscoveryError(_) => -700,
        MeshInfinityError::FileTransferError(_) => -800,
        MeshInfinityError::ExitNodeError(_) => -900,
        MeshInfinityError::AppGatewayError(_) => -1000,
        MeshInfinityError::SecurityError(_) => -1100,
        MeshInfinityError::NoAvailableTransport => -501,
        MeshInfinityError::NoActiveSession => -502,
        MeshInfinityError::PeerNotFound(_) => -503,
        MeshInfinityError::ConnectionTimeout => -504,
        MeshInfinityError::InvalidMessageFormat => -505,
        MeshInfinityError::InsufficientTrust => -506,
        MeshInfinityError::UntrustedPeer => -509,
        MeshInfinityError::ConnectionRejected(_) => -510,
        MeshInfinityError::ProtocolMismatch => -511,
        MeshInfinityError::ResourceUnavailable => -507,
        MeshInfinityError::OperationNotSupported => -508,
        MeshInfinityError::IoError(_) => -1001,
        MeshInfinityError::SerializationError(_) => -1002,
        MeshInfinityError::DeserializationError(_) => -1003,
        MeshInfinityError::LockError(_) => -1004,
        MeshInfinityError::InvalidInput(_) => -1005,
        MeshInfinityError::VpnRoutingNotEnabled => -1006,
        MeshInfinityError::InsufficientPrivileges(_) => -1007,
    }
}
