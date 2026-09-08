//! Backup, offline transport bundle, and emergency-erase FFI shims (§3.7, §5.28, §3.9).
//! Each function is a thin C-ABI wrapper (null-check → delegate → return).
//! No business logic lives here.

use std::os::raw::c_char;
use std::ptr;

use super::{c_str_to_str, MeshContext};

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
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required passphrase.
    let pass = match unsafe { c_str_to_str(passphrase) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // No value available.
        None => return ctx.set_response(r#"{"ok":false,"error":"passphrase required"}"#),
    };
    // Delegate to service layer and return the result JSON.
    ctx.set_response(&ctx.create_backup(pass, backup_type))
}

// ---------------------------------------------------------------------------
// Offline transport bundle (§5.28)
// ---------------------------------------------------------------------------

/// Create an encrypted offline bundle for a specific recipient and return it
/// as a heap-allocated byte buffer.
///
/// `packets_json`: JSON array of hex-encoded packet strings,
///                 e.g. `["deadbeef...", "cafebabe..."]`.
/// `source_id_hex`: 64-hex-char sender peer ID.
/// `dest_id_hex`: 64-hex-char recipient peer ID.
/// `recipient_x25519_pub_hex`: 64-hex-char recipient X25519 public key.
/// `out_len`: set to the number of bytes in the returned buffer.
///
/// Returns a pointer to a freshly allocated buffer containing the `.mib`
/// bytes, or null on error.  The caller must pass the pointer to
/// `mi_free_bytes()` when done.
///
/// # Safety
/// `ctx` must be non-null.  All string args must be valid UTF-8.
/// `out_len` must point to a valid `usize`.
#[no_mangle]
pub unsafe extern "C" fn mi_create_offline_bundle(
    ctx: *mut MeshContext,
    packets_json: *const std::os::raw::c_char,
    source_id_hex: *const std::os::raw::c_char,
    dest_id_hex: *const std::os::raw::c_char,
    recipient_x25519_pub_hex: *const std::os::raw::c_char,
    out_len: *mut usize,
) -> *mut u8 {
    if ctx.is_null()
        || packets_json.is_null()
        || source_id_hex.is_null()
        || dest_id_hex.is_null()
        || recipient_x25519_pub_hex.is_null()
        || out_len.is_null()
    {
        return std::ptr::null_mut();
    }

    let packets_str = match unsafe { std::ffi::CStr::from_ptr(packets_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let source_hex = match unsafe { std::ffi::CStr::from_ptr(source_id_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let dest_hex = match unsafe { std::ffi::CStr::from_ptr(dest_id_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let recip_hex = match unsafe { std::ffi::CStr::from_ptr(recipient_x25519_pub_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Parse JSON array of hex-encoded packets.
    let packet_hex_arr: Vec<String> = match serde_json::from_str(packets_str) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };
    let packets: Vec<Vec<u8>> = packet_hex_arr
        .iter()
        .filter_map(|h| hex::decode(h).ok())
        .collect();
    if packets.len() != packet_hex_arr.len() {
        return std::ptr::null_mut(); // hex decode error
    }

    let source_bytes = match hex::decode(source_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return std::ptr::null_mut(),
    };
    let dest_bytes = match hex::decode(dest_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return std::ptr::null_mut(),
    };
    let recip_pub = match hex::decode(recip_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return std::ptr::null_mut(),
    };

    let bundle = match crate::transport::offline_bundle::OfflineBundle::create_for_recipient(
        &packets,
        source_bytes,
        dest_bytes,
        &recip_pub,
    ) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let bytes = bundle.encrypted_bytes;
    unsafe { *out_len = bytes.len() };

    // Transfer ownership to the caller.  `mi_free_bytes` must be called later.
    let mut boxed = bytes.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    ptr
}

/// Import an encrypted offline bundle and inject the inner mesh packets into
/// the routing layer.
///
/// `data_ptr`: pointer to the raw `.mib` file bytes.
/// `data_len`: byte count.
/// `recipient_x25519_secret_hex`: 64-hex-char recipient X25519 private key.
///
/// Returns JSON `{"ok":true,"packet_count":N}` or `{"ok":false,"error":"..."}`.
///
/// # Safety
/// `ctx` must be non-null.  `data_ptr` must point to `data_len` valid bytes.
/// `recipient_x25519_secret_hex` must be a valid UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn mi_import_offline_bundle(
    ctx: *mut MeshContext,
    data_ptr: *const u8,
    data_len: usize,
    recipient_x25519_secret_hex: *const std::os::raw::c_char,
) -> *const std::os::raw::c_char {
    if ctx.is_null() || data_ptr.is_null() || recipient_x25519_secret_hex.is_null() {
        // Can't call set_response on a null ctx; return a static null-terminated string.
        return c"{\"ok\":false,\"error\":\"null pointer\"}".as_ptr();
    }

    let ctx_ref = unsafe { &*ctx };

    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    let secret_hex = match unsafe { std::ffi::CStr::from_ptr(recipient_x25519_secret_hex) }.to_str()
    {
        Ok(s) => s,
        Err(_) => {
            return ctx_ref.set_response("{\"ok\":false,\"error\":\"invalid UTF-8 in secret hex\"}")
        }
    };

    let secret_bytes: [u8; 32] = match hex::decode(secret_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return ctx_ref
                .set_response("{\"ok\":false,\"error\":\"secret_hex must be 64 hex chars\"}")
        }
    };

    let (_bundle, parsed) = match crate::transport::offline_bundle::OfflineBundle::open_as_recipient(
        data,
        &secret_bytes,
    ) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("{{\"ok\":false,\"error\":\"{}\" }}", e);
            return ctx_ref.set_response(&msg);
        }
    };

    let packet_count = parsed.packets.len();

    // Inject each inner packet into the routing layer as an inbound mesh packet.
    for pkt in &parsed.packets {
        ctx_ref.ingest_tun_packet(pkt);
    }

    let resp = format!("{{\"ok\":true,\"packet_count\":{packet_count}}}");
    ctx_ref.set_response(&resp)
}

/// Free a buffer allocated by `mi_create_offline_bundle`.
///
/// # Safety
/// `ptr` must be a pointer returned by `mi_create_offline_bundle` and `len`
/// must be the value written to `out_len` by that call.  Calling this on any
/// other pointer is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn mi_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // Reconstruct the Box<[u8]> from the raw parts and let it drop.
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    let _ = unsafe { Box::from_raw(slice as *mut [u8]) };
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
    if ctx.is_null() {
        return -1;
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Dispatch duress wipe to service layer.
    ctx.duress_erase();
    0
}
