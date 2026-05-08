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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_file_transfers_json(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no transfers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_file_transfer_start(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    direction: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    path: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot start transfers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute dir for this protocol step.
    let dir = unsafe { c_str_to_str(direction) }.unwrap_or("outgoing");
    // Identify the peer for this operation.
    // Compute pid for this protocol step.
    let pid = unsafe { c_str_to_str(peer_id) }.unwrap_or("");
    // Dispatch based on the variant to apply type-specific logic.
    // Compute p for this protocol step.
    let p = match unsafe { c_str_to_str(path) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate transfer initiation to service layer.
    // Dispatch on the variant.
    match ctx.start_file_transfer(dir, pid, p) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_file_transfer_cancel(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    transfer_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no transfers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required transfer-ID argument.
    // Compute tid for this protocol step.
    let tid = match unsafe { c_str_to_str(transfer_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.cancel_file_transfer(tid) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_file_transfer_accept(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    transfer_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    save_path: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot accept transfers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute tid for this protocol step.
    let tid = match unsafe { c_str_to_str(transfer_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute path for this protocol step.
    let path = match unsafe { c_str_to_str(save_path) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.accept_file_transfer(tid, path) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}
