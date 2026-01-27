// FFI Bridge for NetInfinity
// Provides a C-compatible interface for Flutter integration.

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, OnceCell};
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::{Receiver, RecvTimeoutError};
use crate::backend::{
    FileTransferSummary, Message, NetInfinityService, NodeMode, PeerSummary, RoomSummary,
    ServiceConfig, Settings,
};
use crate::core::{MeshConfig, NetInfinityError, Result};
use serde_json::{json, Value};

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

const MAX_TEXT_LEN: usize = 8192;
const MAX_NAME_LEN: usize = 128;
const MAX_ID_LEN: usize = 128;
const MAX_EVENTS: usize = 256;

static MESH_STATE: OnceCell<Arc<Mutex<ServiceHandle>>> = OnceCell::new();
static LAST_ERROR: OnceCell<Mutex<Option<String>>> = OnceCell::new();

struct ServiceHandle {
    service: NetInfinityService,
    events: Arc<Mutex<VecDeque<BackendEvent>>>,
    shutdown: Arc<AtomicBool>,
    message_thread: Option<JoinHandle<()>>,
    transfer_thread: Option<JoinHandle<()>>,
}

impl ServiceHandle {
    fn new(service: NetInfinityService) -> Self {
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
        let mut events = self.events.lock().unwrap();
        if events.len() >= MAX_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }

    fn drain_events(&self, max: usize) -> Vec<BackendEvent> {
        let mut events = self.events.lock().unwrap();
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
    PeerUpdated(PeerSummary),
    TransferUpdated(FileTransferSummary),
    SettingsUpdated(Settings),
    ActiveRoomChanged(Option<String>),
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
                let mut queue = events.lock().unwrap();
                if queue.len() >= MAX_EVENTS {
                    queue.pop_front();
                }
                queue.push_back(event);
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

    let service = NetInfinityService::new(service_config);
    let handle = ServiceHandle::new(service);
    let arc_handle = Arc::new(Mutex::new(handle));

    if MESH_STATE.set(arc_handle.clone()).is_err() {
        set_last_error("mesh already initialized");
        return std::ptr::null_mut();
    }

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
        return rust_error_to_c_code(&NetInfinityError::InvalidMessageFormat);
    }

    let payload = unsafe { std::slice::from_raw_parts(message.payload, message.payload_len) };
    let text = match std::str::from_utf8(payload) {
        Ok(value) => value,
        Err(_) => {
            set_last_error("message payload was not valid utf-8");
            return rust_error_to_c_code(&NetInfinityError::InvalidMessageFormat);
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
    match guard.service.send_message(text) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn mesh_receive_messages(
    ctx: *mut MeshContext,
    callback: extern fn(*const FfiMessage, *mut c_void),
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

    unsafe {
        let _ = Arc::from_raw(ctx);
    }

    if let Some(state) = MESH_STATE.take() {
        if let Ok(mut guard) = state.lock() {
            guard.shutdown();
        }
    }
}

#[no_mangle]
pub extern "C" fn net_infinity_ffi_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn ni_rooms_json(ctx: *mut MeshContext) -> *mut c_char {
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
pub extern "C" fn ni_messages_json(
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
pub extern "C" fn ni_peers_json(ctx: *mut MeshContext) -> *mut c_char {
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
pub extern "C" fn ni_settings_json(ctx: *mut MeshContext) -> *mut c_char {
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
pub extern "C" fn ni_active_room_id(ctx: *mut MeshContext) -> *mut c_char {
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
pub extern "C" fn ni_create_room(ctx: *mut MeshContext, name: *const c_char) -> *mut c_char {
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

    let mut guard = service.lock().unwrap();
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
pub extern "C" fn ni_select_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
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

    let mut guard = service.lock().unwrap();
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
pub extern "C" fn ni_send_text_message(
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
    let result = if let Some(room_id) = room_id {
        guard.service.send_message_to_room(&room_id, &text)
    } else {
        guard.service.send_message(&text)
    };

    match result {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn ni_set_node_mode(ctx: *mut MeshContext, mode: u8) -> i32 {
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

    let mut guard = service.lock().unwrap();
    let node_mode = node_mode_from_u8(mode);
    guard.service.set_node_mode(node_mode);
    let settings = guard.service.settings();
    guard.push_event(BackendEvent::SettingsUpdated(settings));
    0
}

#[no_mangle]
pub extern "C" fn ni_pair_peer(ctx: *mut MeshContext, code: *const c_char) -> i32 {
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

    let mut guard = service.lock().unwrap();
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
pub extern "C" fn ni_poll_events(ctx: *mut MeshContext, max_events: u32) -> *mut c_char {
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
pub extern "C" fn ni_last_error_message() -> *mut c_char {
    match take_last_error() {
        Some(message) => string_to_c_string(&message),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn ni_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    unsafe {
        let _ = CString::from_raw(value);
    }
}

fn get_service() -> Result<Arc<Mutex<ServiceHandle>>> {
    MESH_STATE
        .get()
        .cloned()
        .ok_or(NetInfinityError::ResourceUnavailable)
}

fn read_cstr(ptr: *const c_char, max_len: usize, field: &str) -> Result<String> {
    if ptr.is_null() {
        return Err(NetInfinityError::InvalidConfiguration(format!(
            "{field} pointer was null"
        )));
    }
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let bytes = c_str.to_bytes();
    if bytes.len() > max_len {
        return Err(NetInfinityError::InvalidConfiguration(format!(
            "{field} exceeded max length"
        )));
    }
    std::str::from_utf8(bytes)
        .map(|value| value.to_string())
        .map_err(|_| {
            NetInfinityError::InvalidConfiguration(format!("{field} was not valid utf-8"))
        })
}

fn set_last_error(message: impl Into<String>) {
    let store = LAST_ERROR.get_or_init(|| Mutex::new(None));
    *store.lock().unwrap() = Some(message.into());
}

fn take_last_error() -> Option<String> {
    let store = LAST_ERROR.get_or_init(|| Mutex::new(None));
    store.lock().unwrap().take()
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
        BackendEvent::PeerUpdated(peer) => json!({
            "type": "peer_updated",
            "peer": peer_to_json(peer),
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
    }
}

fn rust_error_to_c_code(err: &NetInfinityError) -> i32 {
    match err {
        NetInfinityError::InvalidConfiguration(_) => -100,
        NetInfinityError::NetworkError(_) => -200,
        NetInfinityError::CryptoError(_) => -300,
        NetInfinityError::AuthError(_) => -400,
        NetInfinityError::TransportError(_) => -500,
        NetInfinityError::WireGuardError(_) => -600,
        NetInfinityError::DiscoveryError(_) => -700,
        NetInfinityError::FileTransferError(_) => -800,
        NetInfinityError::ExitNodeError(_) => -900,
        NetInfinityError::AppGatewayError(_) => -1000,
        NetInfinityError::SecurityError(_) => -1100,
        NetInfinityError::NoAvailableTransport => -501,
        NetInfinityError::NoActiveSession => -502,
        NetInfinityError::PeerNotFound(_) => -503,
        NetInfinityError::ConnectionTimeout => -504,
        NetInfinityError::InvalidMessageFormat => -505,
        NetInfinityError::InsufficientTrust => -506,
        NetInfinityError::ResourceUnavailable => -507,
        NetInfinityError::OperationNotSupported => -508,
        NetInfinityError::IoError(_) => -1001,
        NetInfinityError::SerializationError(_) => -1002,
        NetInfinityError::DeserializationError(_) => -1003,
    }
}
