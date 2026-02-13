// FFI Bridge for Mesh Infinity
// Provides a C-compatible interface for Flutter integration.

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crossbeam_channel::{Receiver, RecvTimeoutError};
use crate::backend::{
    FileTransferSummary, IdentitySummary, Message, MeshInfinityService, NodeMode, PeerSummary,
    RoomSummary, ServiceConfig, Settings,
};
use crate::core::{MeshConfig, MeshInfinityError, PeerId, Result};
use crate::auth::web_of_trust::VerificationMethod as WotVerificationMethod;
use crate::core::TrustLevel;
use serde_json::{json, Value};

// Helper to safely handle mutex locks in FFI context
fn safe_lock<T>(mutex: &Mutex<T>) -> std::result::Result<std::sync::MutexGuard<T>, String> {
    mutex.lock().map_err(|e| format!("Mutex lock poisoned: {}", e))
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

struct ServiceHandle {
    service: MeshInfinityService,
    events: Arc<Mutex<VecDeque<BackendEvent>>>,
    shutdown: Arc<AtomicBool>,
    message_thread: Option<JoinHandle<()>>,
    transfer_thread: Option<JoinHandle<()>>,
}

impl ServiceHandle {
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

    fn push_event(&self, event: BackendEvent) {
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= MAX_EVENTS {
                events.pop_front();
            }
            events.push_back(event);
        }
    }

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
pub extern "C" fn mesh_init(config: *const FfiMeshConfig) -> *mut MeshContext {
    if config.is_null() {
        set_last_error("config pointer was null");
        return std::ptr::null_mut();
    }

    let config = unsafe { &*config };
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

    let service_config = ServiceConfig {
        initial_mode: node_mode_from_u8(config.node_mode),
        mesh_config: rust_config,
        identity_name: None,
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

#[no_mangle]
pub extern "C" fn mesh_send_message(ctx: *mut MeshContext, message: *const FfiMessage) -> i32 {
    if ctx.is_null() || message.is_null() {
        set_last_error("message pointer was null");
        return -1;
    }

    let message = unsafe { &*message };
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
pub extern "C" fn mi_messages_json(
    ctx: *mut MeshContext,
    room_id: *const c_char,
) -> *mut c_char {
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
            if let Some(room) = guard.service.rooms().into_iter().find(|room| room.id == room_id) {
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
            if let Some(room) = guard.service.rooms().into_iter().find(|room| room.id == room_id) {
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
            if let Some(room) = guard.service.rooms().into_iter().find(|room| room.id == room_id) {
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

    if guard.service.local_identity_summary().is_some() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mi_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    unsafe {
        let _ = CString::from_raw(value);
    }
}

// mDNS Discovery FFI functions

#[no_mangle]
pub extern "C" fn mi_mdns_enable(ctx: *mut MeshContext, port: u16) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let Ok(state) = MESH_STATE.lock() else {
        set_last_error("Failed to acquire mesh state lock");
        return -1;
    };

    let Some(handle) = state.as_ref() else {
        set_last_error("Mesh not initialized");
        return -1;
    };

    let Ok(service_handle) = handle.lock() else {
        set_last_error("Failed to acquire service lock");
        return -1;
    };

    match service_handle.service.enable_mdns(port) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("Failed to enable mDNS: {}", e));
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_mdns_disable(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let Ok(state) = MESH_STATE.lock() else {
        set_last_error("Failed to acquire mesh state lock");
        return -1;
    };

    let Some(handle) = state.as_ref() else {
        set_last_error("Mesh not initialized");
        return -1;
    };

    let Ok(service_handle) = handle.lock() else {
        set_last_error("Failed to acquire service lock");
        return -1;
    };

    match service_handle.service.disable_mdns() {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("Failed to disable mDNS: {}", e));
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mi_mdns_is_running(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let Ok(state) = MESH_STATE.lock() else {
        set_last_error("Failed to acquire mesh state lock");
        return -1;
    };

    let Some(handle) = state.as_ref() else {
        set_last_error("Mesh not initialized");
        return -1;
    };

    let Ok(service_handle) = handle.lock() else {
        set_last_error("Failed to acquire service lock");
        return -1;
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

    let Ok(state) = MESH_STATE.lock() else {
        set_last_error("Failed to acquire mesh state lock");
        return std::ptr::null_mut();
    };

    let Some(handle) = state.as_ref() else {
        set_last_error("Mesh not initialized");
        return std::ptr::null_mut();
    };

    let Ok(service_handle) = handle.lock() else {
        set_last_error("Failed to acquire service lock");
        return std::ptr::null_mut();
    };

    match service_handle.service.get_discovered_peers() {
        Ok(peers) => {
            let peers_json: Vec<Value> = peers.iter().map(|peer| {
                json!({
                    "id": peer.id,
                    "name": peer.name,
                    "trustLevel": peer.trust_level,
                    "status": peer.status,
                })
            }).collect();

            json_to_c_string(Value::Array(peers_json))
        }
        Err(e) => {
            set_last_error(format!("Failed to get discovered peers: {}", e));
            std::ptr::null_mut()
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

    // TODO: Implement actual network statistics collection
    // For now, return placeholder values
    let stats = json!({
        "bytesSent": 0,
        "bytesReceived": 0,
        "activeConnections": 0,
        "packetsLost": 0,
        "avgLatencyMs": 0,
        "bandwidthKbps": 0,
    });

    json_to_c_string(stats)
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

    let _direction_str = match read_cstr(direction, 16, "direction") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let _file_path_str = match read_cstr(file_path, 4096, "file_path") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    // TODO: Implement actual file transfer initiation
    // For now, return a placeholder transfer ID
    let transfer_id = format!("transfer_{}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());

    json_to_c_string(json!({
        "transferId": transfer_id,
        "status": "pending",
        "message": "File transfer requires full implementation"
    }))
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

    let _transfer_id = match read_cstr(transfer_id, 256, "transfer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return -1;
        }
    };

    // TODO: Implement actual transfer cancellation
    set_last_error("File transfer cancellation requires full implementation");
    -2 // Not implemented
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

    // TODO: Implement actual transfer status retrieval
    json_to_c_string(json!({
        "transferId": _transfer_id,
        "status": "unknown",
        "progress": 0,
        "message": "Transfer status requires full implementation"
    }))
}

/// Gets list of configured services
/// Returns JSON array of services or empty array on error
#[no_mangle]
pub extern "C" fn mi_get_service_list(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return json_to_c_string(json!([]));
    }

    // TODO: Implement actual service list retrieval from backend
    json_to_c_string(json!([
        {
            "id": "example-service-1",
            "name": "Example Service",
            "type": "http",
            "status": "inactive",
            "port": 8080,
            "protocol": "http",
        }
    ]))
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

    let _service_id = match read_cstr(service_id, 256, "service_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let _config_json = match read_cstr(config_json, 4096, "config_json") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    // TODO: Implement actual service configuration
    set_last_error("Service configuration not yet implemented");
    0
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

    let _transport_name = match read_cstr(transport_name, 64, "transport_name") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let _enabled = enabled != 0;

    // TODO: Implement actual transport flag toggling
    // This should update backend settings and enable/disable the specified transport
    set_last_error("Transport flag toggling not yet implemented");
    0
}

/// Sets VPN route configuration
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn mi_set_vpn_route(
    ctx: *mut MeshContext,
    route_config_json: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let _route_config = match read_cstr(route_config_json, 4096, "route_config_json") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    // TODO: Implement actual VPN route configuration
    // This should configure exit node routing through the mesh
    set_last_error("VPN route configuration not yet implemented");
    0
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

    let _route_config = match read_cstr(route_config_json, 4096, "route_config_json") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    // TODO: Implement actual clearnet route configuration
    // This should configure direct routing without mesh
    set_last_error("Clearnet route configuration not yet implemented");
    0
}

fn get_service() -> Result<Arc<Mutex<ServiceHandle>>> {
    MESH_STATE
        .lock()
        .unwrap()
        .clone()
        .ok_or(MeshInfinityError::ResourceUnavailable)
}

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
    for i in 0..count {
        let idx = i * 2;
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).map_err(|_| {
            MeshInfinityError::InvalidConfiguration("peer_id was not valid hex".to_string())
        })?;
        bytes[i] = byte;
    }
    Ok(bytes)
}

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
            .ok_or_else(|| {
                MeshInfinityError::InvalidConfiguration("missing target".to_string())
            })?;
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

fn set_last_error(message: impl Into<String>) {
    *LAST_ERROR.lock().unwrap() = Some(message.into());
}

fn take_last_error() -> Option<String> {
    LAST_ERROR.lock().unwrap().take()
}

fn json_to_c_string(value: Value) -> *mut c_char {
    match serde_json::to_string(&value) {
        Ok(serialized) => string_to_c_string(&serialized),
        Err(err) => {
            set_last_error(err.to_string());
            std::ptr::null_mut()
        }
    }
}

fn string_to_c_string(value: &str) -> *mut c_char {
    match CString::new(value) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

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

fn peer_to_json(peer: &PeerSummary) -> Value {
    json!({
        "id": peer.id,
        "name": peer.name,
        "trustLevel": peer.trust_level,
        "status": peer.status,
    })
}

fn identity_to_json(identity: &IdentitySummary) -> Value {
    json!({
        "peerId": peer_id_string(&identity.peer_id),
        "publicKey": hex_encode(&identity.public_key),
        "dhPublicKey": hex_encode(&identity.dh_public),
        "name": identity.name,
    })
}

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

fn settings_to_json(settings: &Settings) -> Value {
    json!({
        "nodeMode": node_mode_label(settings.node_mode),
        "enableTor": settings.enable_tor,
        "enableClearnet": settings.enable_clearnet,
        "meshDiscovery": settings.mesh_discovery,
        "allowRelays": settings.allow_relays,
        "enableI2p": settings.enable_i2p,
        "enableBluetooth": settings.enable_bluetooth,
        "pairingCode": settings.pairing_code,
        "localPeerId": settings.local_peer_id,
    })
}

fn peer_id_string(peer_id: &PeerId) -> String {
    hex_encode(peer_id)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

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

fn node_mode_from_u8(mode: u8) -> NodeMode {
    match mode {
        1 => NodeMode::Server,
        2 => NodeMode::Dual,
        _ => NodeMode::Client,
    }
}

fn node_mode_label(mode: NodeMode) -> &'static str {
    match mode {
        NodeMode::Client => "client",
        NodeMode::Server => "server",
        NodeMode::Dual => "dual",
    }
}

fn trust_level_from_i32(level: i32) -> TrustLevel {
    match level {
        3 => TrustLevel::HighlyTrusted,
        2 => TrustLevel::Trusted,
        1 => TrustLevel::Caution,
        _ => TrustLevel::Untrusted,
    }
}

fn verification_method_from_u8(method: u8) -> WotVerificationMethod {
    match method {
        1 => WotVerificationMethod::InPerson,
        2 => WotVerificationMethod::SharedSecret,
        3 => WotVerificationMethod::TrustedIntroduction,
        4 => WotVerificationMethod::PKI,
        _ => WotVerificationMethod::SharedSecret,
    }
}

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
        BackendEvent::MessageDeleted { room_id, message_id } => json!({
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
        BackendEvent::TrustUpdated { peer_id, trust_level } => json!({
            "type": "trust_updated",
            "peerId": peer_id,
            "trustLevel": trust_level,
        }),
    }
}

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
    }
}
