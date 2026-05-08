//! Network settings and threat context FFI shims (§4, §6).
//! Each function is a thin C-ABI wrapper (null-check → delegate → return).
//! No business logic lives here.

use std::os::raw::c_char;
use std::ptr;

use super::{c_str_to_str, MeshContext};


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
    if ctx.is_null() {
        return ptr::null();
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_threat_context(level) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return the current threat context level as a `u8`.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_threat_context(ctx: *mut MeshContext) -> u8 {
    // Guard: return Normal (0) for a null context.
    if ctx.is_null() {
        return 0;
    }
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
    if ctx.is_null() {
        return -1;
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_conversation_security_mode(rid, mode) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Validate and cast the mode value.
    if !(0..=2).contains(&mode) {
        return -1;
    }
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_node_mode(mode as u8) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Persist the mesh participation profile (0 = minimal, 1 = standard, 2 = generous).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_set_bandwidth_profile(ctx: *mut MeshContext, profile: u8) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.set_bandwidth_profile(profile) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Persist the highest unlocked feature tier (0 = social .. 4 = power).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_set_active_tier(ctx: *mut MeshContext, tier: u8) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.set_active_tier(tier) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(flags_json_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_transport_flags(json_str) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required transport-name argument.
    let name = match unsafe { c_str_to_str(transport) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.toggle_transport_flag(name, enabled != 0) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return live network statistics as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_network_stats(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no stats.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate stats collection to service layer.
    ctx.set_response(&ctx.get_network_stats())
}

/// Return a privacy-safe diagnostic report as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_diagnostic_report(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_diagnostic_report_json())
}

/// Return the backend-owned Android VPN enforcement policy as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_android_vpn_policy(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_android_vpn_policy())
}

