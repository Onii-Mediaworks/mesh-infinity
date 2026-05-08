//! File transfer FFI shims (§13).
//! Each function is a thin C-ABI wrapper (null-check → delegate → return).
//! No business logic lives here.

use std::os::raw::c_char;
use std::ptr;

use super::{c_str_to_str, MeshContext};

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
    if ctx.is_null() {
        return ptr::null();
    }
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
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let dir = unsafe { c_str_to_str(direction) }.unwrap_or("outgoing");
    // Identify the peer for this operation.
    let pid = unsafe { c_str_to_str(peer_id) }.unwrap_or("");
    // Dispatch based on the variant to apply type-specific logic.
    let p = match unsafe { c_str_to_str(path) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate transfer initiation to service layer.
    // Dispatch on the variant.
    match ctx.start_file_transfer(dir, pid, p) {
        Ok(json) => ctx.set_response(&json),
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(_) => ptr::null(),
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required transfer-ID argument.
    let tid = match unsafe { c_str_to_str(transfer_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.cancel_file_transfer(tid) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let tid = match unsafe { c_str_to_str(transfer_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let path = match unsafe { c_str_to_str(save_path) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.accept_file_transfer(tid, path) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}
