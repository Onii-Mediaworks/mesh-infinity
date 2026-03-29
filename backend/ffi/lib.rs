//! FFI boundary — C-compatible API surface (§17.5).
//!
//! THIS FILE IS A THIN C ABI BOUNDARY ONLY.
//!
//! ## Architecture
//!
//! `MeshContext` is an opaque wrapper around `Box<MeshRuntime>`.  Every
//! `pub unsafe extern "C"` function does exactly three things:
//!   1. Null-check and parse FFI arguments (strings, ints, structs).
//!   2. Call the corresponding method on `MeshRuntime` (via `Deref`).
//!   3. Return the result as an integer code or JSON pointer.
//!
//! No business logic belongs here.  If you find yourself writing more than
//! ~15 lines inside an `extern "C"` fn body, move the logic to `service/`.
//!
//! ## Key material policy (§15.1)
//!
//! No key material ever crosses this boundary.  All returned strings are
//! pre-validated, display-safe JSON produced by the service layer.
//!
//! ## Pointer ownership
//!
//! Flutter calls `mesh_init()` once and receives a `*mut MeshContext`.
//! It holds this pointer for the app lifetime and passes it to every
//! other function.  It must call `mesh_destroy()` exactly once at shutdown.
//! Rust owns the memory; Flutter never frees it directly.
//!
//! ## Return conventions
//!
//! - Integer functions return `0` on success, `-1` on failure.
//! - Pointer functions return `null` on failure; non-null on success.
//! - JSON strings are owned by the context (`last_response`) and are valid
//!   until the next FFI call that writes to `last_response`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::service::MeshRuntime;

// ---------------------------------------------------------------------------
// Opaque context handle
// ---------------------------------------------------------------------------

/// Opaque handle passed to every FFI function.
///
/// Wraps a heap-allocated `MeshRuntime`.  Flutter holds a raw pointer;
/// all lifetime management is explicit via `mesh_init` / `mesh_destroy`.
pub struct MeshContext(Box<MeshRuntime>);

impl std::ops::Deref for MeshContext {
    type Target = MeshRuntime;
    /// Deref to the inner `MeshRuntime` so shims can call service methods
    /// directly without an extra `.0` dereference layer.
    fn deref(&self) -> &MeshRuntime { &self.0 }
}

impl std::ops::DerefMut for MeshContext {
    /// Mutable deref for methods that mutate `MeshRuntime` state.
    fn deref_mut(&mut self) -> &mut MeshRuntime { &mut self.0 }
}

// ---------------------------------------------------------------------------
// FFI config struct (matches Dart-side FfiMeshConfig)
// ---------------------------------------------------------------------------

/// Configuration struct passed from Dart to `mesh_init`.
///
/// Layout must match the Dart `FfiMeshConfig` struct exactly (field order,
/// alignment, sizes).  Both sides use `#[repr(C)]` / `@Packed` for a
/// stable ABI.  See `frontend/lib/backend/backend_bridge.dart`.
#[repr(C)]
pub struct FfiMeshConfig {
    /// NUL-terminated UTF-8 path to the data directory.  Null = use default.
    pub config_path: *const c_char,
    /// Logging verbosity: 0 = off, 1 = error, 2 = info, 3 = debug, 4 = trace.
    pub log_level: u8,
    /// 1 = route traffic through Tor, 0 = disabled.
    pub enable_tor: u8,
    /// 1 = allow direct clearnet connections, 0 = disabled.
    pub enable_clearnet: u8,
    /// 1 = enable local-network peer discovery (mDNS/UDP broadcast).
    pub mesh_discovery: u8,
    /// 1 = allow this node to relay traffic for other peers.
    pub allow_relays: u8,
    /// 1 = route traffic through I2P garlic routing.
    pub enable_i2p: u8,
    /// 1 = enable BLE peer discovery and transport.
    pub enable_bluetooth: u8,
    /// 1 = enable SDR/RF transport (LoRa etc.).
    pub enable_rf: u8,
    /// UDP port for the WireGuard tunnel.  0 = OS-assigned.
    pub wireguard_port: u16,
    /// Maximum peers to maintain.  0 = no limit.
    pub max_peers: u32,
    /// Maximum simultaneous network connections.  0 = no limit.
    pub max_connections: u32,
    /// Node operating mode: 0 = leaf, 1 = relay, 2 = gateway.
    pub node_mode: u8,
}

// ---------------------------------------------------------------------------
// Pre-init error storage
// ---------------------------------------------------------------------------

// Thread-local store for errors that occur before a `MeshContext` exists.
// `mi_last_error_message(null)` reads from here after a failed `mesh_init`.
thread_local! {
    static PREINIT_ERROR: std::cell::RefCell<Option<CString>> =
        const { std::cell::RefCell::new(None) };
}

/// Store `msg` in the pre-init thread-local error slot.
///
/// Called only from `mesh_init` before a `MeshContext` is available.
fn set_preinit_error(msg: &str) {
    PREINIT_ERROR.with(|e| {
        // `CString::new` only fails on interior NUL bytes; use a fallback.
        *e.borrow_mut() = CString::new(msg)
            .ok()
            .or_else(|| CString::new("init error").ok());
    });
}

// ---------------------------------------------------------------------------
// Private helper: C string → &str
// ---------------------------------------------------------------------------

/// Convert a raw C string pointer to a Rust `&str`.
///
/// Returns `None` if the pointer is null or contains invalid UTF-8.
///
/// # Safety
/// Caller must guarantee the pointer is either null or points to a valid,
/// NUL-terminated C string that lives at least as long as the returned borrow.
unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    // Null pointers are treated as "no value provided" throughout the API.
    if ptr.is_null() { return None; }
    // SAFETY: caller guarantees non-null, NUL-terminated.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Initialise the Mesh Infinity backend and return an opaque context handle.
///
/// `config` must point to a fully-initialised `FfiMeshConfig`.  Dart allocates
/// it with `calloc<FfiMeshConfig>()` (zero-initialised) and fills all fields.
///
/// Returns null on failure; call `mi_last_error_message(null)` for details.
///
/// # Safety
/// `config` must be non-null, correctly aligned, and remain valid for the
/// duration of this call.  All other pointer fields inside `config` must be
/// null or point to valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn mesh_init(config: *const FfiMeshConfig) -> *mut MeshContext {
    // Null config pointer is a programming error on the Dart side.
    if config.is_null() {
        set_preinit_error("mesh_init: config pointer is null");
        return ptr::null_mut();
    }

    // SAFETY: caller guarantees config is valid and aligned for this call.
    let cfg = unsafe { &*config };

    // Resolve the data-directory path: use the supplied path or a platform default.
    let dir = if cfg.config_path.is_null() {
        // Default: $HOME/.mesh-infinity (Linux/macOS) or %APPDATA%\mesh-infinity (Windows).
        dirs_next::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("mesh-infinity")
            .to_string_lossy()
            .into_owned()
    } else {
        // SAFETY: config_path is non-null; caller guarantees valid NUL-terminated UTF-8.
        match unsafe { c_str_to_str(cfg.config_path) } {
            Some(s) => s.to_string(),
            None => {
                set_preinit_error("mesh_init: config_path is not valid UTF-8");
                return ptr::null_mut();
            }
        }
    };

    // Create the data directory if it does not exist yet.
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("[mesh_init] WARNING: failed to create data directory {dir:?}: {e}");
    }

    // Allocate the context on the heap and hand ownership to Flutter.
    let ctx = Box::new(MeshContext(Box::new(MeshRuntime::new(dir))));
    Box::into_raw(ctx)
}

/// Destroy the context and free all resources.
///
/// Must be called exactly once at app shutdown.  After this call, `ctx` is
/// invalid and must not be used again.
///
/// # Safety
/// `ctx` must have been returned by `mesh_init` and not yet destroyed.
/// No other thread may hold a reference to `ctx` at the time of this call.
#[no_mangle]
pub unsafe extern "C" fn mesh_destroy(ctx: *mut MeshContext) {
    // Null ctx is a no-op rather than a hard error for defensive robustness.
    if !ctx.is_null() {
        // SAFETY: `ctx` was allocated by `Box::into_raw` in `mesh_init`; this
        // is the unique ownership-reclaim point.
        unsafe { drop(Box::from_raw(ctx)); }
    }
}

// ---------------------------------------------------------------------------
// Error retrieval
// ---------------------------------------------------------------------------

/// Return the last error string stored in the context.
///
/// Returns null if no error has been set since the last successful call.
/// The pointer is valid until the next FFI call that writes `last_error`.
///
/// # Safety
/// `ctx` must be non-null and point to a valid `MeshContext`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_last_error(ctx: *mut MeshContext) -> *const c_char {
    // Guard: a null ctx means the runtime was never initialised.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null, valid for the duration of this call.
    let ctx = unsafe { &*ctx };
    // Return the stored error pointer if one exists, null otherwise.
    match ctx.last_error.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some(s) => s.as_ptr(),
        None => ptr::null(),
    }
}

/// Return the last error string.
///
/// - If `ctx` is non-null: returns the post-init error stored in the context.
/// - If `ctx` is null: returns the pre-init error from thread-local storage.
///
/// # Safety
/// `ctx` must be null or a valid `MeshContext` pointer.
#[no_mangle]
pub unsafe extern "C" fn mi_last_error_message(ctx: *mut MeshContext) -> *const c_char {
    // Null ctx → read from the pre-init thread-local error store.
    if ctx.is_null() {
        return PREINIT_ERROR.with(|e| {
            e.borrow().as_ref().map(|s| s.as_ptr()).unwrap_or(ptr::null())
        });
    }
    // Non-null ctx → delegate to the standard error accessor.
    unsafe { mi_get_last_error(ctx) }
}

/// No-op free stub.
///
/// Strings are owned by the context's `last_response` field — Flutter must
/// not free them.  This stub exists for ABI completeness.
///
/// # Safety
/// `_ptr` is ignored.  Passing any pointer is safe; no memory is freed.
#[no_mangle]
pub unsafe extern "C" fn mi_string_free(_ptr: *mut c_char) {
    // No-op: string lifetime is tied to the MeshContext, not the caller.
}

// ---------------------------------------------------------------------------
// Identity (§3)
// ---------------------------------------------------------------------------

/// Check whether an identity file exists on this device.
///
/// Returns 1 if an identity exists, 0 otherwise.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_has_identity(ctx: *mut MeshContext) -> i32 {
    // Return 0 rather than panicking on a null context.
    if ctx.is_null() { return 0; }
    // SAFETY: caller guarantees non-null, valid for this call.
    let ctx = unsafe { &*ctx };
    // Delegate the file-existence check to the service layer.
    if ctx.has_identity() { 1 } else { 0 }
}

/// Create a new identity with an optional display name.
///
/// Generates fresh Ed25519, X25519, preauth-X25519, and ML-KEM-768 key pairs,
/// persists to `identity.dat`, and initialises the vault.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `display_name` may be null (treated as no name), or a valid NUL-terminated
/// UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn mi_create_identity(
    ctx: *mut MeshContext,
    display_name: *const c_char,
) -> i32 {
    // Guard: reject null context immediately.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null and exclusive access during this call.
    let ctx = unsafe { &mut *ctx };
    // Parse optional display name (null → None).
    let name = unsafe { c_str_to_str(display_name) }.map(|s| s.to_string());
    // Dispatch to service layer; map Ok/Err to 0/-1.
    match ctx.create_identity(name) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Unlock an existing identity from disk.
///
/// Pass null `pin` if no PIN was set.  On success restores vault state and
/// emits `SettingsUpdated`.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `pin` may be null or a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn mi_unlock_identity(
    ctx: *mut MeshContext,
    pin: *const c_char,
) -> i32 {
    // Guard: reject null context immediately.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Parse optional PIN string.
    let pin_str = unsafe { c_str_to_str(pin) }.map(|s| s.to_string());
    // Delegate to service layer.
    match ctx.unlock_identity(pin_str) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Return the current identity summary as a JSON string.
///
/// JSON shape: `{"locked":bool,"peerId"?:string,"ed25519Pub"?:string,"displayName"?:string}`.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_identity_summary(ctx: *mut MeshContext) -> *const c_char {
    // Guard: a null ctx cannot hold a summary.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer and store the response string.
    ctx.set_response(&ctx.get_identity_summary())
}

/// Alias for `mi_get_identity_summary` (legacy name).
///
/// # Safety
/// Same as `mi_get_identity_summary`.
#[no_mangle]
pub unsafe extern "C" fn mi_local_identity_json(ctx: *mut MeshContext) -> *const c_char {
    // Forward to the canonical implementation.
    unsafe { mi_get_identity_summary(ctx) }
}

/// Import social state from an encrypted backup (§3.7).
///
/// `backup_b64_json` may be raw base64 or `{"backup_b64":"..."}`.
/// Identity private keys are never restored — only contacts, rooms, messages.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// Both string arguments must be non-null, valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_import_identity(
    ctx: *mut MeshContext,
    backup_b64_json: *const c_char,
    passphrase: *const c_char,
) -> i32 {
    // Guard: reject null context.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Parse required string arguments.
    let backup_str = match unsafe { c_str_to_str(backup_b64_json) } {
        Some(s) => s,
        None => return -1,
    };
    let pass_str = match unsafe { c_str_to_str(passphrase) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    match ctx.import_identity_backup(backup_str, pass_str) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Non-emergency wipe of in-memory identity and social state.
///
/// Does not remove files from disk.  Call to implement a logout flow.
///
/// Returns 0 (always succeeds if ctx is non-null).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_reset_identity(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx is a no-op.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Delegate wipe to service layer.
    ctx.reset_identity();
    0
}

/// Set the public profile visible to all contacts (§9.1).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `json` must be non-null, valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_public_profile(
    ctx: *mut MeshContext,
    json: *const c_char,
) -> i32 {
    // Guard: reject null context.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse JSON argument.
    let profile_json = match unsafe { c_str_to_str(json) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch to service layer.
    match ctx.set_public_profile(profile_json) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Set the private profile shared only with trusted contacts (§9.2).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `json` must be non-null, valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_private_profile(
    ctx: *mut MeshContext,
    json: *const c_char,
) -> i32 {
    // Guard: reject null context.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse JSON argument.
    let profile_json = match unsafe { c_str_to_str(json) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch to service layer.
    match ctx.set_private_profile(profile_json) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

// ---------------------------------------------------------------------------
// Backup (§3.7)
// ---------------------------------------------------------------------------

/// Create an encrypted backup of contacts, rooms, and optionally messages.
///
/// `backup_type`: 0 = Standard (contacts + rooms), 1 = Extended (+ messages).
/// Returns JSON `{"ok":true,"backup_b64":"..."}` or `{"ok":false,"error":"..."}`.
///
/// # Safety
/// `ctx` must be non-null.  `passphrase` must be non-null, valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_create_backup(
    ctx: *mut MeshContext,
    passphrase: *const c_char,
    backup_type: u8,
) -> *const c_char {
    // Guard: null ctx cannot create a backup.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required passphrase.
    let pass = match unsafe { c_str_to_str(passphrase) } {
        Some(s) => s,
        None => return ctx.set_response(r#"{"ok":false,"error":"passphrase required"}"#),
    };
    // Delegate to service layer and return the result JSON.
    ctx.set_response(&ctx.create_backup(pass, backup_type))
}

// ---------------------------------------------------------------------------
// Emergency / duress erase (§3.9)
// ---------------------------------------------------------------------------

/// Standard emergency erase: destroy all identity layers (§3.9.1).
///
/// Returns 0 on success, -1 if ctx is null.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_emergency_erase(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot be erased.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Dispatch to service layer for the actual wipe.
    ctx.emergency_erase();
    0
}

/// Duress erase: preserve Layer 1, destroy Layers 2 and 3 (§3.9.2).
///
/// Returns 0 on success, -1 if ctx is null.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_duress_erase(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot be erased.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Dispatch duress wipe to service layer.
    ctx.duress_erase();
    0
}

// ---------------------------------------------------------------------------
// Rooms / Conversations
// ---------------------------------------------------------------------------

/// Return the full room list as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_room_list(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no rooms.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate room list serialisation to service layer.
    ctx.set_response(&ctx.get_room_list())
}

/// Alias for `mi_get_room_list` (legacy name).
///
/// # Safety
/// Same as `mi_get_room_list`.
#[no_mangle]
pub unsafe extern "C" fn mi_rooms_json(ctx: *mut MeshContext) -> *const c_char {
    // Forward to the canonical implementation.
    unsafe { mi_get_room_list(ctx) }
}

/// Create a new room.  `peer_id` may be null for a standalone room.
///
/// Returns JSON `{"id":"...","name":"..."}` or null on failure.
///
/// # Safety
/// `ctx` must be non-null.  `name` must be non-null, valid UTF-8.
/// `peer_id` may be null or a valid hex peer-ID string.
#[no_mangle]
pub unsafe extern "C" fn mi_create_room(
    ctx: *mut MeshContext,
    name: *const c_char,
    peer_id: *const c_char,
) -> *const c_char {
    // Guard: null ctx cannot hold rooms.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Parse room name; default to "New Chat" if null.
    let room_name = unsafe { c_str_to_str(name) }.unwrap_or("New Chat");
    // Parse optional peer ID for DM rooms.
    let pid_str = unsafe { c_str_to_str(peer_id) };
    // Delegate room creation to service layer.
    match ctx.create_room(room_name, pid_str) {
        Ok(id_hex) => {
            let json = serde_json::json!({"id": id_hex, "name": room_name}).to_string();
            ctx.set_response(&json)
        }
        Err(e) => { ctx.set_error(&e); ptr::null() }
    }
}

/// Delete a room and its message history.
///
/// Returns 0 on success, -1 if the room was not found.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be non-null, valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_delete_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    // Guard: reject null context.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch to service layer; map bool result to 0/-1.
    if ctx.delete_room(rid) { 0 } else { -1 }
}

/// Return messages for a room as a JSON array.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be non-null, valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_get_messages(
    ctx: *mut MeshContext,
    room_id: *const c_char,
) -> *const c_char {
    // Guard: null ctx has no messages.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    let rid = unsafe { c_str_to_str(room_id) }.unwrap_or("");
    // Delegate to service layer.
    ctx.set_response(&ctx.get_messages(rid))
}

/// Alias for `mi_get_messages` (legacy name).
///
/// # Safety
/// Same as `mi_get_messages`.
#[no_mangle]
pub unsafe extern "C" fn mi_messages_json(
    ctx: *mut MeshContext,
    room_id: *const c_char,
) -> *const c_char {
    // Forward to the canonical implementation.
    unsafe { mi_get_messages(ctx, room_id) }
}

/// Return the active conversation room ID as a JSON string (`"null"` if none).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_active_room_id(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no active room.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate active-room query to service layer.
    ctx.set_response(&ctx.active_room_id())
}

/// Alias for `mi_set_active_conversation` (legacy name).
///
/// # Safety
/// Same as `mi_set_active_conversation`.
#[no_mangle]
pub unsafe extern "C" fn mi_select_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    // Forward to the canonical implementation.
    unsafe { mi_set_active_conversation(ctx, room_id) }
}

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

/// Send a text message to a room.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` and `text` must be valid UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn mi_send_text_message(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    text: *const c_char,
) -> i32 {
    // Guard: null ctx cannot send messages.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let rid = match unsafe { c_str_to_str(room_id) } { Some(s) => s, None => return -1 };
    let txt = match unsafe { c_str_to_str(text) } { Some(s) if !s.is_empty() => s, _ => return -1 };
    // Dispatch to service layer.
    if ctx.send_text_message(rid, txt) { 0 } else { -1 }
}

/// Send a message (full form with optional security mode override).
///
/// Delegates to `mi_send_text_message` — the `security_mode` parameter is
/// reserved for future use.
///
/// # Safety
/// Same as `mi_send_text_message`.
#[no_mangle]
pub unsafe extern "C" fn mi_send_message(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    _security_mode: *const c_char,
    text: *const c_char,
) -> i32 {
    // Forward to the text-message implementation.
    unsafe { mi_send_text_message(ctx, room_id, text) }
}

/// Delete a message from local storage (local-only).
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null.  `msg_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_delete_message(
    ctx: *mut MeshContext,
    msg_id: *const c_char,
) -> i32 {
    // Guard: null ctx cannot delete messages.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required message-ID argument.
    let mid = match unsafe { c_str_to_str(msg_id) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    ctx.delete_message(mid);
    0
}

/// Send a reaction emoji to a message and broadcast it to room participants.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  All string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_send_reaction(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    msg_id: *const c_char,
    emoji: *const c_char,
) -> i32 {
    // Guard: reject null context.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse all three required arguments.
    let rid   = match unsafe { c_str_to_str(room_id) } { Some(s) => s, None => return -1 };
    let mid   = match unsafe { c_str_to_str(msg_id)  } { Some(s) => s, None => return -1 };
    let emj   = match unsafe { c_str_to_str(emoji)   } { Some(s) if !s.is_empty() => s, _ => return -1 };
    // Delegate to service layer.
    if ctx.send_reaction(rid, mid, emj) { 0 } else { -1 }
}

/// Mark a message as read and reset the room's unread counter.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_send_read_receipt(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    msg_id: *const c_char,
) -> i32 {
    // Guard: null ctx has no rooms to mark read.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let rid = match unsafe { c_str_to_str(room_id) } { Some(s) => s, None => return -1 };
    let mid = match unsafe { c_str_to_str(msg_id)  } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    ctx.send_read_receipt(rid, mid);
    0
}

/// Emit a typing indicator and broadcast it to room participants.
///
/// `active`: non-zero = currently typing, 0 = stopped.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_send_typing_indicator(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    active: i32,
) -> i32 {
    // Guard: null ctx cannot broadcast typing events.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    let rid = match unsafe { c_str_to_str(room_id) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    ctx.send_typing_indicator(rid, active != 0);
    0
}

/// Send a reply message that quotes an earlier message.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  All string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_reply_to_message(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    reply_to: *const c_char,
    text: *const c_char,
) -> i32 {
    // Guard: null ctx cannot send messages.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Parse all three required arguments.
    let rid   = match unsafe { c_str_to_str(room_id)  } { Some(s) => s, None => return -1 };
    let rto   = match unsafe { c_str_to_str(reply_to) } { Some(s) => s, None => return -1 };
    let txt   = match unsafe { c_str_to_str(text)     } { Some(s) if !s.is_empty() => s, _ => return -1 };
    // Delegate to service layer.
    if ctx.reply_to_message(rid, rto, txt) { 0 } else { -1 }
}

/// Edit the text of a previously sent message (own messages only).
///
/// Returns 0 on success, -1 if the message was not found or not editable.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_edit_message(
    ctx: *mut MeshContext,
    msg_id: *const c_char,
    new_text: *const c_char,
) -> i32 {
    // Guard: null ctx has no messages to edit.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let mid  = match unsafe { c_str_to_str(msg_id)   } { Some(s) => s, None => return -1 };
    let ntxt = match unsafe { c_str_to_str(new_text) } { Some(s) if !s.is_empty() => s, _ => return -1 };
    // Delegate to service layer.
    if ctx.edit_message(mid, ntxt) { 0 } else { -1 }
}

/// Delete a message for all participants.
///
/// Returns 0 on success, -1 if not found.
///
/// # Safety
/// `ctx` must be non-null.  `msg_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_delete_for_everyone(
    ctx: *mut MeshContext,
    msg_id: *const c_char,
) -> i32 {
    // Guard: null ctx has no messages.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required message-ID argument.
    let mid = match unsafe { c_str_to_str(msg_id) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    if ctx.delete_for_everyone(mid).is_some() { 0 } else { -1 }
}

/// Forward a message to a different room.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_forward_message(
    ctx: *mut MeshContext,
    msg_id: *const c_char,
    target_room: *const c_char,
) -> i32 {
    // Guard: null ctx cannot forward messages.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Parse required arguments.
    let mid  = match unsafe { c_str_to_str(msg_id)     } { Some(s) => s, None => return -1 };
    let tgt  = match unsafe { c_str_to_str(target_room)} { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    if ctx.forward_message(mid, tgt) { 0 } else { -1 }
}

/// Pin a message in the conversation.
///
/// Returns 0 on success, -1 if not found.
///
/// # Safety
/// `ctx` must be non-null.  `msg_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_pin_message(ctx: *mut MeshContext, msg_id: *const c_char) -> i32 {
    // Guard: null ctx has no messages.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required argument.
    let mid = match unsafe { c_str_to_str(msg_id) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    if ctx.pin_message(mid) { 0 } else { -1 }
}

/// Unpin a previously pinned message.
///
/// Returns 0 on success, -1 if not found.
///
/// # Safety
/// `ctx` must be non-null.  `msg_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_unpin_message(ctx: *mut MeshContext, msg_id: *const c_char) -> i32 {
    // Guard: null ctx has no messages.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required argument.
    let mid = match unsafe { c_str_to_str(msg_id) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    if ctx.unpin_message(mid) { 0 } else { -1 }
}

/// Set or clear the disappearing-message timer for a room (0 = disabled).
///
/// Returns 0 on success, -1 if the room was not found.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_disappearing_timer(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    secs: u64,
) -> i32 {
    // Guard: null ctx has no rooms.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    let rid = match unsafe { c_str_to_str(room_id) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    if ctx.set_disappearing_timer(rid, secs) { 0 } else { -1 }
}

/// Full-text search across all in-memory messages.
///
/// Returns a JSON array of matching message objects.
///
/// # Safety
/// `ctx` must be non-null.  `query` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_search_messages(
    ctx: *mut MeshContext,
    query: *const c_char,
) -> *const c_char {
    // Guard: null ctx has no messages to search.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse optional query (null → empty → returns []).
    let q = unsafe { c_str_to_str(query) }.unwrap_or("");
    // Delegate full-text search to service layer.
    ctx.set_response(&ctx.search_messages(q))
}

/// Remove expired messages from all rooms.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_prune_expired_messages(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot prune.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate expiry pruning to service layer.
    ctx.prune_expired_messages();
    0
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

/// Return the peer list as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_peer_list(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no peers.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate peer-list serialisation to service layer.
    ctx.set_response(&ctx.get_peer_list())
}

/// Pair with a peer by accepting their pairing payload (§8.3).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `peer_data` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_pair_peer(ctx: *mut MeshContext, peer_data: *const c_char) -> i32 {
    // Guard: reject null context.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse the pairing payload JSON string.
    let json_str = match unsafe { c_str_to_str(peer_data) } { Some(s) => s, None => return -1 };
    // Delegate pairing to service layer.
    match ctx.pair_peer(json_str) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Return the local pairing payload as JSON.
///
/// The payload contains our public keys, a fresh pairing token, and transport hints.
/// Encode as a QR code for peer scanning.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_pairing_payload(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no identity to advertise.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate payload construction to service layer.
    match ctx.get_pairing_payload() {
        Ok(json)  => ctx.set_response(&json),
        Err(e)    => ctx.set_response(&serde_json::json!({"error": e}).to_string()),
    }
}

/// Set a peer's trust level.
///
/// Returns 0 on success, -1 if the peer was not found.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_trust_level(
    ctx: *mut MeshContext,
    peer_id: *const c_char,
    level: u8,
) -> i32 {
    // Guard: null ctx has no contacts.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse the peer-ID hex string.
    let pid_hex = match unsafe { c_str_to_str(peer_id) } { Some(s) => s, None => return -1 };
    // Delegate trust update to service layer.
    match ctx.set_trust_level(pid_hex, level) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Alias for `mi_set_trust_level` (trust attestation variant).
///
/// # Safety
/// Same as `mi_set_trust_level`.
#[no_mangle]
pub unsafe extern "C" fn mi_trust_attest(
    ctx: *mut MeshContext,
    peer_id: *const c_char,
    level: i32,
) -> i32 {
    // Forward to canonical implementation with a u8 cast.
    unsafe { mi_set_trust_level(ctx, peer_id, level as u8) }
}

/// Return trust verification details for a peer as JSON.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_trust_verify_json(
    ctx: *mut MeshContext,
    peer_id: *const c_char,
) -> *const c_char {
    // Guard: null ctx has no contacts.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse the peer-ID hex string.
    let pid_hex = unsafe { c_str_to_str(peer_id) }.unwrap_or("");
    // Delegate to service layer.
    ctx.set_response(&ctx.trust_verify(pid_hex))
}

// ---------------------------------------------------------------------------
// File transfers
// ---------------------------------------------------------------------------

/// Return active file transfers as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_file_transfers_json(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no transfers.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.get_file_transfers())
}

/// Start a file transfer.
///
/// `direction`: `"outgoing"` or `"incoming"`.
/// `peer_id`:   hex peer ID of the remote party (may be null for incoming).
/// `path`:      local filesystem path (source for outgoing, destination for incoming).
///
/// Returns JSON `{"id":"...","status":"pending",...}` or null on error.
///
/// # Safety
/// `ctx` must be non-null.  `direction`, `path` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_file_transfer_start(
    ctx: *mut MeshContext,
    direction: *const c_char,
    peer_id: *const c_char,
    path: *const c_char,
) -> *const c_char {
    // Guard: null ctx cannot start transfers.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let dir  = unsafe { c_str_to_str(direction) }.unwrap_or("outgoing");
    let pid  = unsafe { c_str_to_str(peer_id)   }.unwrap_or("");
    let p    = match unsafe { c_str_to_str(path) } { Some(s) => s, None => return ptr::null() };
    // Delegate transfer initiation to service layer.
    match ctx.start_file_transfer(dir, pid, p) {
        Ok(json) => ctx.set_response(&json),
        Err(_)   => ptr::null(),
    }
}

/// Cancel an active file transfer.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `transfer_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_file_transfer_cancel(
    ctx: *mut MeshContext,
    transfer_id: *const c_char,
) -> i32 {
    // Guard: null ctx has no transfers.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required transfer-ID argument.
    let tid = match unsafe { c_str_to_str(transfer_id) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.cancel_file_transfer(tid) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Accept an incoming file transfer.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_file_transfer_accept(
    ctx: *mut MeshContext,
    transfer_id: *const c_char,
    save_path: *const c_char,
) -> i32 {
    // Guard: null ctx cannot accept transfers.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let tid  = match unsafe { c_str_to_str(transfer_id) } { Some(s) => s, None => return -1 };
    let path = match unsafe { c_str_to_str(save_path)   } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.accept_file_transfer(tid, path) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

// ---------------------------------------------------------------------------
// Events (polling)
// ---------------------------------------------------------------------------

/// Poll for pending backend events.
///
/// Drains all queued events and advances the clearnet transport loop.
/// Returns a JSON array; `[]` means no events are pending.
/// Each element: `{"type":"EventName","data":{...}}`.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_poll_events(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no events.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Advance all transports (TCP, Tor, LAN, file, gossip, keepalives, etc.).
    ctx.advance_clearnet_transport();
    // Drain the event queue and return as JSON.
    let mut queue = ctx.event_queue.lock().unwrap_or_else(|e| e.into_inner());
    if queue.is_empty() {
        return ctx.set_response("[]");
    }
    let events: Vec<serde_json::Value> = queue.drain(..).collect();
    drop(queue);
    ctx.set_response(&serde_json::to_string(&events).unwrap_or_else(|_| "[]".into()))
}

// ---------------------------------------------------------------------------
// Network — settings and threat context
// ---------------------------------------------------------------------------

/// Return the current backend settings as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_settings(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no settings.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate settings serialisation to service layer.
    ctx.set_response(&ctx.get_settings())
}

/// Alias for `mi_get_settings` (legacy name).
///
/// # Safety
/// Same as `mi_get_settings`.
#[no_mangle]
pub unsafe extern "C" fn mi_settings_json(ctx: *mut MeshContext) -> *const c_char {
    // Forward to canonical implementation.
    unsafe { mi_get_settings(ctx) }
}

/// Set the threat context level (0 = Normal … 4 = Critical).
///
/// Returns 0 on success, -1 if the level is invalid.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_set_threat_context(ctx: *mut MeshContext, level: u8) -> i32 {
    // Guard: null ctx cannot have its threat context updated.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Delegate to service layer.
    match ctx.set_threat_context(level) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Return the current threat context level as a `u8`.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_threat_context(ctx: *mut MeshContext) -> u8 {
    // Guard: return Normal (0) for a null context.
    if ctx.is_null() { return 0; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.get_threat_context()
}

/// Set the active conversation for read-receipt priority escalation (§16.9.3).
///
/// Pass null `room_id` to clear the active conversation.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` may be null or a valid hex room-ID string.
#[no_mangle]
pub unsafe extern "C" fn mi_set_active_conversation(
    ctx: *mut MeshContext,
    room_id: *const c_char,
) -> i32 {
    // Guard: null ctx has no conversations.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Null → clear; non-null → parse and set.
    let id_str = unsafe { c_str_to_str(room_id) };
    // Delegate to service layer.
    ctx.set_active_conversation(id_str);
    0
}

/// Set the message security mode for a room (§6.7).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_conversation_security_mode(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    mode: u8,
) -> i32 {
    // Guard: null ctx has no rooms.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    let rid = match unsafe { c_str_to_str(room_id) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.set_conversation_security_mode(rid, mode) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Set the node operating mode (0 = client, 1 = relay, 2 = server).
///
/// Returns 0 on success, -1 if the mode is invalid.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_set_node_mode(ctx: *mut MeshContext, mode: i32) -> i32 {
    // Guard: null ctx cannot change modes.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Validate and cast the mode value.
    if !(0..=2).contains(&mode) { return -1; }
    // Delegate to service layer.
    match ctx.set_node_mode(mode as u8) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Apply a JSON transport-flags patch to the current flag set.
///
/// Each key in `flags_json` is optional; missing keys leave the current value
/// unchanged.  Emits `SettingsUpdated` and persists to vault.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `flags_json_ptr` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_transport_flags(
    ctx: *mut MeshContext,
    flags_json_ptr: *const c_char,
) -> i32 {
    // Guard: null ctx has no transport flags.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(flags_json_ptr) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.set_transport_flags(json_str) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Toggle a single transport flag by name.
///
/// Valid names: `"tor"`, `"clearnet"`, `"clearnet_fallback"`, `"i2p"`,
/// `"bluetooth"`, `"rf"`, `"mesh_discovery"`, `"relays"`.
///
/// Returns 0 on success, -1 if the name is unrecognised.
///
/// # Safety
/// `ctx` must be non-null.  `transport` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_toggle_transport_flag(
    ctx: *mut MeshContext,
    transport: *const c_char,
    enabled: i32,
) -> i32 {
    // Guard: null ctx has no flags.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required transport-name argument.
    let name = match unsafe { c_str_to_str(transport) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.toggle_transport_flag(name, enabled != 0) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Return live network statistics as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_network_stats(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no stats.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate stats collection to service layer.
    ctx.set_response(&ctx.get_network_stats())
}

// ---------------------------------------------------------------------------
// Clearnet transport control (§5.1)
// ---------------------------------------------------------------------------

/// Start the clearnet TCP listener on the configured port.
///
/// Returns 0 on success, -1 if the listener could not be bound.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_start_clearnet_listener(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx has no listener to start.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate listener startup to service layer.
    match ctx.start_clearnet_listener() {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Stop the clearnet TCP listener and close all active connections.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_stop_clearnet_listener(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx has nothing to stop.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate listener teardown to service layer.
    ctx.stop_clearnet_listener();
    0
}

/// Set the clearnet TCP listen port.  Takes effect on next listener start.
///
/// Returns 0 on success, -1 if port is 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_set_clearnet_port(ctx: *mut MeshContext, port: u16) -> i32 {
    // Guard: null ctx has no port to configure.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    match ctx.set_clearnet_port(port) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Configure VPN routing rules from a JSON object.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `route` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_clearnet_route(
    ctx: *mut MeshContext,
    route: *const c_char,
) -> i32 {
    // Guard: null ctx has no routing table to update.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(route) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.set_clearnet_route(json_str) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

// ---------------------------------------------------------------------------
// Tor transport control (§5.3)
// ---------------------------------------------------------------------------

/// Bootstrap the Tor transport and start the hidden service.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tor_enable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot enable Tor.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate Tor bootstrap to service layer.
    match ctx.tor_enable() {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Disable the Tor transport and shut down the hidden service.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tor_disable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot disable Tor.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate Tor teardown to service layer.
    ctx.tor_disable();
    0
}

/// Return our Tor v3 `.onion` address as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tor_get_onion_address(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no Tor address.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    match ctx.tor_get_onion_address() {
        Ok(addr) => ctx.set_response(&serde_json::json!({"onion_address": addr}).to_string()),
        Err(_)   => ctx.set_response(r#"{"error":"Tor not enabled"}"#),
    }
}

/// Connect to a peer via the Tor network.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tor_connect(
    ctx: *mut MeshContext,
    peer_id_hex_ptr: *const c_char,
    onion_addr_ptr: *const c_char,
    port: u16,
) -> i32 {
    // Guard: null ctx or null string args are immediate failures.
    if ctx.is_null() || peer_id_hex_ptr.is_null() || onion_addr_ptr.is_null() { return -1; }
    // SAFETY: caller guarantees all pointers are valid.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let peer_id_hex = match unsafe { c_str_to_str(peer_id_hex_ptr) } { Some(s) => s, None => return -1 };
    let onion_addr  = match unsafe { c_str_to_str(onion_addr_ptr)  } { Some(s) => s, None => return -1 };
    // Delegate Tor connection to service layer.
    match ctx.tor_connect(peer_id_hex, onion_addr, port) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

// ---------------------------------------------------------------------------
// mDNS / LAN discovery (§4.6)
// ---------------------------------------------------------------------------

/// Enable mDNS peer discovery on the local network.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mdns_enable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot enable mDNS.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate mDNS startup to service layer.
    ctx.mdns_enable();
    0
}

/// Disable mDNS peer discovery and clear the discovered-peers cache.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mdns_disable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot disable mDNS.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate mDNS teardown to service layer.
    ctx.mdns_disable();
    0
}

/// Returns 1 if mDNS is currently running, 0 otherwise.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mdns_is_running(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx → mDNS is not running.
    if ctx.is_null() { return 0; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate status query to service layer.
    if ctx.mdns_is_running() { 1 } else { 0 }
}

/// Return mDNS-discovered peers as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mdns_get_discovered_peers(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no discovered peers.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate peer-list retrieval to service layer.
    ctx.set_response(&ctx.mdns_get_discovered_peers())
}

// ---------------------------------------------------------------------------
// VPN routing (§6.9)
// ---------------------------------------------------------------------------

/// Set the VPN routing mode.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `mode_json` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_vpn_mode(ctx: *mut MeshContext, mode_json: *const c_char) -> i32 {
    // Guard: null ctx has no VPN to configure.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(mode_json) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.set_vpn_mode(json_str) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Set or clear the exit-node peer.  Pass an empty string to clear.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id_hex` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_exit_node(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
) -> i32 {
    // Guard: null ctx has no VPN.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required peer-ID argument.
    let pid = unsafe { c_str_to_str(peer_id_hex) }.unwrap_or("");
    // Delegate to service layer.
    match ctx.set_exit_node(pid) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Return the current VPN status as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_vpn_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no VPN status.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.get_vpn_status())
}

// ---------------------------------------------------------------------------
// Overlay network (Tailscale, ZeroTier) (§5.5)
// ---------------------------------------------------------------------------

/// Authenticate Tailscale with an auth key.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_auth_key(
    ctx: *mut MeshContext,
    auth_key: *const c_char,
    control_url: *const c_char,
) -> i32 {
    // Guard: null ctx cannot authenticate.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let key = match unsafe { c_str_to_str(auth_key)   } { Some(s) => s, None => return -1 };
    let url = unsafe { c_str_to_str(control_url) }.unwrap_or("");
    // Delegate to service layer.
    match ctx.tailscale_auth_key(key, url) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Begin Tailscale OAuth flow.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `control_url` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_begin_oauth(
    ctx: *mut MeshContext,
    control_url: *const c_char,
) -> i32 {
    // Guard: null ctx cannot initiate OAuth.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required URL argument.
    let url = unsafe { c_str_to_str(control_url) }.unwrap_or("");
    // Delegate to service layer.
    match ctx.tailscale_begin_oauth(url) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Connect to a ZeroTier network.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_connect(
    ctx: *mut MeshContext,
    api_key: *const c_char,
    controller_url: *const c_char,
    network_ids_json: *const c_char,
) -> i32 {
    // Guard: null ctx cannot connect to ZeroTier.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let key        = match unsafe { c_str_to_str(api_key) }         { Some(s) => s, None => return -1 };
    let controller = match unsafe { c_str_to_str(controller_url) }  { Some(s) => s, None => return -1 };
    let networks   = unsafe { c_str_to_str(network_ids_json) }.unwrap_or("[]");
    // Delegate to service layer.
    match ctx.zerotier_connect(key, controller, networks) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Return overlay network status as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_overlay_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no overlay.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.overlay_status())
}

// ---------------------------------------------------------------------------
// LoSec (§5.4)
// ---------------------------------------------------------------------------

/// Process a LoSec connection-mode request.
///
/// Returns JSON `{"accepted":bool,"rejection_reason":?string}`.
///
/// # Safety
/// `ctx` must be non-null.  `request_json` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_losec_request(
    ctx: *mut MeshContext,
    request_json: *const c_char,
) -> *const c_char {
    // Guard: null ctx cannot process LoSec requests.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(request_json) } { Some(s) => s, None => return ptr::null() };
    // Delegate to service layer.
    match ctx.losec_request(json_str) {
        Ok(json) => ctx.set_response(&json),
        Err(e)   => ctx.set_response(&serde_json::json!({"error": e}).to_string()),
    }
}

/// Return the current LoSec ambient traffic status as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_losec_ambient_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no ambient status.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.losec_ambient_status())
}

// ---------------------------------------------------------------------------
// WireGuard (§5.2)
// ---------------------------------------------------------------------------

/// Initiate a WireGuard handshake with a peer.
///
/// Returns JSON `{"init_hex":"..."}` or `{"error":"..."}`.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id_hex` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_wg_initiate_handshake(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
) -> *const c_char {
    // Guard: null ctx cannot initiate WireGuard.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required peer-ID argument.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } { Some(s) => s, None => return ptr::null() };
    // Delegate to service layer.
    match ctx.wg_initiate_handshake(peer_hex) {
        Ok(json) => ctx.set_response(&json),
        Err(e)   => ctx.set_response(&serde_json::json!({"error": e}).to_string()),
    }
}

/// Respond to an incoming WireGuard handshake initiation.
///
/// Returns JSON `{"response_hex":"..."}` or `{"error":"..."}`.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_wg_respond_to_handshake(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
    init_hex: *const c_char,
) -> *const c_char {
    // Guard: null ctx cannot handle WireGuard.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let peer_hex  = match unsafe { c_str_to_str(peer_id_hex) } { Some(s) => s, None => return ptr::null() };
    let init_hex_ = match unsafe { c_str_to_str(init_hex)    } { Some(s) => s, None => return ptr::null() };
    // Delegate to service layer.
    match ctx.wg_respond_to_handshake(peer_hex, init_hex_) {
        Ok(json) => ctx.set_response(&json),
        Err(e)   => ctx.set_response(&serde_json::json!({"error": e}).to_string()),
    }
}

/// Complete a WireGuard handshake by processing the responder's reply.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_wg_complete_handshake(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
    response_hex: *const c_char,
) -> i32 {
    // Guard: null ctx cannot complete handshakes.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) }  { Some(s) => s, None => return -1 };
    let resp_hex = match unsafe { c_str_to_str(response_hex) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.wg_complete_handshake(peer_hex, resp_hex) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

// ---------------------------------------------------------------------------
// SDR/RF transport (§5.6)
// ---------------------------------------------------------------------------

/// Configure the SDR/RF transport.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `config_json` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_configure(
    ctx: *mut MeshContext,
    config_json: *const c_char,
) -> i32 {
    // Guard: null ctx cannot configure SDR.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(config_json) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.sdr_configure(json_str) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Return SDR/RF transport status as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no SDR.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.sdr_status())
}

/// Return the current FHSS channel as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_current_channel(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no SDR channel.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.sdr_current_channel())
}

/// Return the list of SDR RF profiles as JSON.
///
/// # Safety
/// `_ctx` is unused but retained for ABI consistency.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_list_profiles(_ctx: *mut MeshContext) -> *const c_char {
    // Profiles are static; no context required.  Delegate to service method.
    // We need a static CString for the response pointer lifetime.
    // Build the list from MeshRuntime if available, else use fallback.
    if _ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*_ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.sdr_list_profiles())
}

/// Return the list of detected SDR hardware as JSON.
///
/// # Safety
/// `_ctx` is unused but retained for ABI consistency.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_list_hardware(_ctx: *mut MeshContext) -> *const c_char {
    // Hardware detection is static; delegate to service layer.
    if _ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*_ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.sdr_list_hardware())
}

// ---------------------------------------------------------------------------
// Groups (§10.3)
// ---------------------------------------------------------------------------

/// Create a new group.
///
/// Returns JSON `{"groupId":"...","name":"..."}` or null on failure.
///
/// # Safety
/// `ctx` must be non-null.  `name` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_create_group(
    ctx: *mut MeshContext,
    name: *const c_char,
    _member_ids: *const c_char,
) -> *const c_char {
    // Guard: null ctx cannot create groups.
    if ctx.is_null() { return ptr::null(); }
    // Parse required group name argument.
    let gname = match unsafe { c_str_to_str(name) } { Some(s) => s, None => return ptr::null() };
    // Parse optional member IDs (JSON array of hex peer IDs).
    let members_str = unsafe { c_str_to_str(_member_ids) }.unwrap_or("[]");
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    let ctx_mut = unsafe { &mut *ctx };
    match ctx_mut.create_group(gname, members_str) {
        Ok(ref json) => ctx_mut.set_response(json),
        Err(ref e)   => { ctx_mut.set_error(e); ptr::null() }
    }
}

/// Return the list of groups as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_list_groups(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no groups.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.list_groups())
}

/// Return the member list for a group as a JSON array.
///
/// # Safety
/// `ctx` must be non-null.  `group_id_hex` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_group_members(
    ctx: *mut MeshContext,
    group_id_hex: *const c_char,
) -> *const c_char {
    // Guard: null ctx has no groups.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required group-ID argument.
    let gid = match unsafe { c_str_to_str(group_id_hex) } { Some(s) => s, None => return ptr::null() };
    // Delegate to service layer.
    ctx.set_response(&ctx.group_members(gid))
}

/// Leave a group.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `group_id_hex` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_leave_group(
    ctx: *mut MeshContext,
    group_id_hex: *const c_char,
) -> i32 {
    // Guard: null ctx cannot leave groups.
    if ctx.is_null() { return -1; }
    // Parse required group-ID argument.
    let gid = match unsafe { c_str_to_str(group_id_hex) } { Some(s) => s, None => return -1 };
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    let ctx_mut = unsafe { &mut *ctx };
    match ctx_mut.leave_group(gid) {
        Ok(()) => 0,
        Err(ref e) => { ctx_mut.set_error(e); -1 }
    }
}

/// Send a message to a group.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_group_send_message(
    ctx: *mut MeshContext,
    group_id_hex: *const c_char,
    text: *const c_char,
) -> i32 {
    // Guard: null ctx cannot send group messages.
    if ctx.is_null() { return -1; }
    // Parse required arguments.
    let gid = match unsafe { c_str_to_str(group_id_hex) } { Some(s) => s, None => return -1 };
    let txt = match unsafe { c_str_to_str(text) } { Some(s) if !s.is_empty() => s, _ => return -1 };
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    let ctx_mut = unsafe { &mut *ctx };
    if ctx_mut.group_send_message(gid, txt) { 0 } else { -1 }
}

/// Invite a peer to a group.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_group_invite_peer(
    ctx: *mut MeshContext,
    group_id_hex: *const c_char,
    peer_id_hex: *const c_char,
) -> i32 {
    // Guard: null ctx cannot invite peers.
    if ctx.is_null() { return -1; }
    // Parse required arguments.
    let gid = match unsafe { c_str_to_str(group_id_hex) } { Some(s) => s, None => return -1 };
    let pid = match unsafe { c_str_to_str(peer_id_hex)  } { Some(s) => s, None => return -1 };
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    let ctx_mut = unsafe { &mut *ctx };
    if ctx_mut.group_invite_peer(gid, pid) { 0 } else { -1 }
}

// ---------------------------------------------------------------------------
// Calls (§12)
// ---------------------------------------------------------------------------

/// Initiate an outgoing call to a peer.
///
/// Returns JSON `{"ok":true,"callId":"..."}` or `{"ok":false,"error":"..."}`.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id_hex` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_call_offer(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
    is_video: i32,
) -> *const c_char {
    // Guard: null ctx cannot initiate calls.
    if ctx.is_null() || peer_id_hex.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required peer-ID argument.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } { Some(s) => s, None => return ptr::null() };
    // Delegate to service layer.
    match ctx.call_offer(peer_hex, is_video != 0, "") {
        Ok(call_id) => ctx.set_response(&serde_json::json!({"ok":true,"callId":call_id}).to_string()),
        Err(e)      => ctx.set_response(&serde_json::json!({"ok":false,"error":e}).to_string()),
    }
}

/// Answer an incoming call.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `session_desc` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_call_answer(
    ctx: *mut MeshContext,
    session_desc: *const c_char,
) -> i32 {
    // Guard: null ctx cannot answer calls.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse optional session description.
    let sdp = unsafe { c_str_to_str(session_desc) }.unwrap_or("");
    // Delegate to service layer.
    match ctx.call_answer(sdp) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Hang up the active call.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_call_hangup(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx has no active call.
    if ctx.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    match ctx.call_hangup() {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

/// Return the current call status as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_call_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no call status.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.call_status())
}

// ---------------------------------------------------------------------------
// Notifications (§14)
// ---------------------------------------------------------------------------

/// Return the current notification configuration as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_notification_config(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no notification config.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.get_notification_config())
}

/// Update the notification configuration.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `json` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_notification_config(
    ctx: *mut MeshContext,
    json: *const c_char,
) -> i32 {
    // Guard: null ctx cannot update notification config.
    if ctx.is_null() || json.is_null() { return -1; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(json) } { Some(s) => s, None => return -1 };
    // Delegate to service layer.
    match ctx.set_notification_config(json_str) {
        Ok(()) => 0,
        Err(e) => { ctx.set_error(&e); -1 }
    }
}

// ---------------------------------------------------------------------------
// Service list (§17.13)
// ---------------------------------------------------------------------------

/// Return the module/service list as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_service_list(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no services.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.get_service_list())
}

/// Toggle or configure a service/module.
///
/// Returns 1 if the service ID was recognised, 0 otherwise.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_configure_service(
    ctx: *mut MeshContext,
    service_id: *const c_char,
    config_json: *const c_char,
) -> i32 {
    // Guard: null ctx or null args → failure.
    if ctx.is_null() || service_id.is_null() || config_json.is_null() { return 0; }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let sid  = match unsafe { c_str_to_str(service_id)  } { Some(s) => s, None => return 0 };
    let json = match unsafe { c_str_to_str(config_json) } { Some(s) => s, None => return 0 };
    // Delegate to service layer.
    if ctx.configure_service(sid, json) { 1 } else { 0 }
}

// ---------------------------------------------------------------------------
// Routing table queries (§6)
// ---------------------------------------------------------------------------

/// Return routing table statistics as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_routing_table_stats(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no routing table.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.routing_table_stats())
}

/// Look up the best next-hop for a destination peer ID.
///
/// Returns JSON `{"found":true,...}` or `{"found":false}`.
///
/// # Safety
/// `ctx` must be non-null.  `dest_peer_id_hex` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_routing_lookup(
    ctx: *mut MeshContext,
    dest_peer_id_hex: *const c_char,
) -> *const c_char {
    // Guard: null ctx has no routing table.
    if ctx.is_null() { return ptr::null(); }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required destination peer-ID argument.
    let dest = match unsafe { c_str_to_str(dest_peer_id_hex) } {
        Some(s) => s,
        None => return ctx.set_response(r#"{"found":false}"#),
    };
    // Delegate to service layer.
    ctx.set_response(&ctx.routing_lookup(dest))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use tempfile::TempDir;

    /// Helper: create a fresh context pointing at a temp directory.
    fn make_ctx() -> (*mut MeshContext, TempDir) {
        let dir = TempDir::new().unwrap();
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        // Build a fully-initialised FfiMeshConfig with all fields zero.
        let config = FfiMeshConfig {
            config_path:     dir_str.as_ptr(),
            log_level:       0,
            enable_tor:      0,
            enable_clearnet: 0,
            mesh_discovery:  0,
            allow_relays:    0,
            enable_i2p:      0,
            enable_bluetooth:0,
            enable_rf:       0,
            wireguard_port:  0,
            max_peers:       100,
            max_connections: 100,
            node_mode:       0,
        };
        // SAFETY: config pointer is valid for the duration of this call.
        let ctx = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx.is_null());
        (ctx, dir)
    }

    #[test]
    fn test_init_destroy() {
        // Verify that init and destroy do not crash.
        let (ctx, _dir) = make_ctx();
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_no_identity_initially() {
        // A fresh context must report no identity.
        let (ctx, _dir) = make_ctx();
        assert_eq!(unsafe { mi_has_identity(ctx) }, 0);
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_create_identity() {
        // Create an identity and verify the summary reports unlocked.
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Alice").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);
        assert_eq!(unsafe { mi_has_identity(ctx) }, 1);

        // Summary must parse and report locked = false.
        let summary = unsafe { mi_get_identity_summary(ctx) };
        assert!(!summary.is_null());
        // SAFETY: returned by our own FFI and valid until next call.
        let json_str = unsafe { CStr::from_ptr(summary).to_str().unwrap() };
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(json["locked"], false);

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_unlock_identity() {
        // Create an identity, destroy the context, then re-open and unlock.
        let (ctx, dir) = make_ctx();
        let name = CString::new("Bob").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);
        unsafe { mesh_destroy(ctx) };

        // Re-open context pointing at the same directory.
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let config2 = FfiMeshConfig {
            config_path:     dir_str.as_ptr(),
            log_level:       0, enable_tor: 0, enable_clearnet: 0,
            mesh_discovery:  0, allow_relays: 0, enable_i2p: 0,
            enable_bluetooth:0, enable_rf: 0, wireguard_port: 0,
            max_peers: 100, max_connections: 100, node_mode: 0,
        };
        // SAFETY: config2 pointer is valid for this call.
        let ctx2 = unsafe { mesh_init(&config2 as *const FfiMeshConfig) };
        assert!(!ctx2.is_null());
        assert_eq!(unsafe { mi_has_identity(ctx2) }, 1);

        // Unlock without a PIN (none was set at creation).
        assert_eq!(unsafe { mi_unlock_identity(ctx2, ptr::null()) }, 0);

        // Summary must report unlocked with a valid peerId.
        let summary = unsafe { mi_get_identity_summary(ctx2) };
        // SAFETY: returned by our own FFI and valid until next call.
        let json_str = unsafe { CStr::from_ptr(summary).to_str().unwrap() };
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(json["locked"], false);
        assert!(json["peerId"].is_string());

        unsafe { mesh_destroy(ctx2) };
    }

    #[test]
    fn test_room_operations() {
        // Create a room and verify it appears in the list.
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Test Room").unwrap();
        let result = unsafe { mi_create_room(ctx, name.as_ptr(), ptr::null()) };
        assert!(!result.is_null());

        // Room list must contain exactly the one new room.
        let rooms = unsafe { mi_get_room_list(ctx) };
        // SAFETY: returned by our own FFI and valid until next call.
        let json_str = unsafe { CStr::from_ptr(rooms).to_str().unwrap() };
        let rooms: Vec<serde_json::Value> = serde_json::from_str(json_str).unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0]["name"], "Test Room");

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_threat_context() {
        // Verify get/set round-trip and invalid level rejection.
        let (ctx, _dir) = make_ctx();
        assert_eq!(unsafe { mi_get_threat_context(ctx) }, 0); // Normal
        assert_eq!(unsafe { mi_set_threat_context(ctx, 2) }, 0);
        assert_eq!(unsafe { mi_get_threat_context(ctx) }, 2);
        assert_eq!(unsafe { mi_set_threat_context(ctx, 5) }, -1); // Invalid
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_active_conversation() {
        // Verify setting and clearing the active conversation.
        let (ctx, _dir) = make_ctx();
        assert_eq!(unsafe { mi_set_active_conversation(ctx, ptr::null()) }, 0);
        let room_id = CString::new("0102030405060708090a0b0c0d0e0f10").unwrap();
        assert_eq!(unsafe { mi_set_active_conversation(ctx, room_id.as_ptr()) }, 0);
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_poll_events_empty() {
        // An empty event queue must return a valid JSON empty array.
        let (ctx, _dir) = make_ctx();
        let events = unsafe { mi_poll_events(ctx) };
        assert!(!events.is_null());
        // SAFETY: returned by our own FFI and valid until next call.
        let json_str = unsafe { CStr::from_ptr(events).to_str().unwrap() };
        assert_eq!(json_str, "[]");
        unsafe { mesh_destroy(ctx) };
    }
}
