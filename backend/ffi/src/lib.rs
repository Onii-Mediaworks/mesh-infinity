// FFI Bridge for SeasonCom
// This module provides the C-compatible interface for Flutter integration

use std::os::raw::c_char;
use std::ffi::{CStr, CString};
use std::sync::{Arc, Mutex, OnceCell};
use net-infinity_core::*;
use libc::*;

// FFI-safe types
#[repr(C)]
pub struct MeshConfig {
    pub config_path: *const c_char,
    pub log_level: u8,
    pub enable_tor: bool,
    pub enable_clearnet: bool,
}

#[repr(C)]
pub struct PeerInfo {
    pub peer_id: [u8; 32],
    pub public_key: [u8; 32],
    pub trust_level: u8,
    pub available_transports: u32, // Bitmask
}

#[repr(C)]
pub struct Message {
    pub sender_id: [u8; 32],
    pub target_id: [u8; 32],
    pub payload: *const u8,
    pub payload_len: usize,
    pub timestamp: u64,
}

// Opaque pointer for MeshContext
#[repr(C)]
pub struct MeshContext {
    _private: [u8; 0],
}

// Global state
static MESH_STATE: OnceCell<Arc<Mutex<MeshService>>> = OnceCell::new();

// Initialize the mesh network
#[no_mangle]
pub extern "C" fn mesh_init(config: *const MeshConfig) -> *mut MeshContext {
    if config.is_null() {
        return std::ptr::null_mut();
    }
    
    let config = unsafe { &*config };
    
    // Convert C config to Rust config
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
        ..Default::default()
    };
    
    // Initialize mesh service
    let mesh_service = MeshService::new(rust_config);
    
    // Store in global state
    let arc_service = Arc::new(Mutex::new(mesh_service));
    if MESH_STATE.set(arc_service.clone()).is_err() {
        return std::ptr::null_mut();
    }
    
    // Return opaque pointer
    Arc::into_raw(arc_service) as *mut MeshContext
}

// Send a message
#[no_mangle]
pub extern "C" fn mesh_send_message(
    ctx: *mut MeshContext,
    message: *const Message
) -> i32 {
    if ctx.is_null() || message.is_null() {
        return -1;
    }
    
    let message = unsafe { &*message };
    let payload = unsafe { std::slice::from_raw_parts(message.payload, message.payload_len) };
    
    let service = MESH_STATE.get().unwrap();
    let mut service_guard = service.lock().unwrap();
    
    match service_guard.send_message(message.target_id, payload) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

// Receive messages (callback-based)
#[no_mangle]
pub extern "C" fn mesh_receive_messages(
    ctx: *mut MeshContext,
    callback: extern fn(*const Message, *mut c_void),
    user_data: *mut c_void
) {
    // This would be implemented with proper async handling
    // For now, just a stub
}

// Destroy mesh context
#[no_mangle]
pub extern "C" fn mesh_destroy(ctx: *mut MeshContext) {
    if !ctx.is_null() {
        unsafe {
            let _ = Arc::from_raw(ctx);
        }
        MESH_STATE.take();
    }
}

// Helper function to convert Rust error to C-compatible error code
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

// Main mesh service (would be implemented in core)
pub struct MeshService {
    config: MeshConfig,
}

impl MeshService {
    pub fn new(config: MeshConfig) -> Self {
        Self { config }
    }
    
    pub fn send_message(&mut self, target_id: [u8; 32], payload: &[u8]) -> Result<()> {
        // Implementation would go here
        Ok(())
    }
}