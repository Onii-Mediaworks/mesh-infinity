//! Application feature FFI shims — groups, calls, notifications, services, garden, screen lock (§10–§22).
//! Each function is a thin C-ABI wrapper (null-check → delegate → return).
//! No business logic lives here.

use std::os::raw::c_char;
use std::ptr;

use super::{c_str_to_str, MeshContext};

// Groups (§10.3)
// ---------------------------------------------------------------------------

/// Create a new group.
///
/// Returns JSON `{"groupId":"...","name":"..."}` or null on failure.
///
/// # Safety
/// `ctx` must be non-null.  `name` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_create_group(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    name: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    _member_ids: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot create groups.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // Parse required group name argument.
    // Compute gname for this protocol step.
    let gname = match unsafe { c_str_to_str(name) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Parse optional member IDs (JSON array of hex peer IDs).
    // Compute members str for this protocol step.
    let members_str = unsafe { c_str_to_str(_member_ids) }.unwrap_or("[]");
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    // Compute ctx mut for this protocol step.
    let ctx_mut = unsafe { &mut *ctx };
    // Dispatch based on the variant to apply type-specific logic.
    // Dispatch on the variant.
    match ctx_mut.create_group(gname, members_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(ref json) => ctx_mut.set_response(json),
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(ref e) => {
            ctx_mut.set_error(e);
            ptr::null()
        }
    }
}

/// Return the list of groups as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_list_groups(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no groups.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.list_groups())
}

/// Return the member list for a group as a JSON array.
///
/// # Safety
/// `ctx` must be non-null.  `group_id_hex` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_group_members(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    group_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx has no groups.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required group-ID argument.
    // Compute gid for this protocol step.
    let gid = match unsafe { c_str_to_str(group_id_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.group_members(gid))
}

/// Leave a group.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `group_id_hex` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_leave_group(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    group_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot leave groups.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // Parse required group-ID argument.
    // Compute gid for this protocol step.
    let gid = match unsafe { c_str_to_str(group_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    // Compute ctx mut for this protocol step.
    let ctx_mut = unsafe { &mut *ctx };
    // Dispatch based on the variant to apply type-specific logic.
    // Dispatch on the variant.
    match ctx_mut.leave_group(gid) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(ref e) => {
            ctx_mut.set_error(e);
            -1
        }
    }
}

/// Send a message to a group.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_group_send_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    group_id_hex: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    text: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot send group messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // Parse required arguments.
    // Compute gid for this protocol step.
    let gid = match unsafe { c_str_to_str(group_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute txt for this protocol step.
    let txt = match unsafe { c_str_to_str(text) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    // Compute ctx mut for this protocol step.
    let ctx_mut = unsafe { &mut *ctx };
    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    if ctx_mut.group_send_message(gid, txt) {
        0
    } else {
        -1
    }
}

/// Invite a peer to a group.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_group_invite_peer(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    group_id_hex: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot invite peers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // Parse required arguments.
    // Compute gid for this protocol step.
    let gid = match unsafe { c_str_to_str(group_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute pid for this protocol step.
    let pid = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    // Compute ctx mut for this protocol step.
    let ctx_mut = unsafe { &mut *ctx };
    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    if ctx_mut.group_invite_peer(gid, pid) {
        0
    } else {
        -1
    }
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_call_offer(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id_hex: *const c_char,
    // Execute this protocol step.
    is_video: i32,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot initiate calls.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() || peer_id_hex.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required peer-ID argument.
    // Compute peer hex for this protocol step.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.call_offer(peer_hex, is_video != 0, "") {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(call_id) => {
            ctx.set_response(&serde_json::json!({"ok":true,"callId":call_id}).to_string())
        }
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => ctx.set_response(&serde_json::json!({"ok":false,"error":e}).to_string()),
    }
}

/// Answer an incoming call.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `session_desc` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_call_answer(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    session_desc: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot answer calls.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse optional session description.
    // Compute sdp for this protocol step.
    let sdp = unsafe { c_str_to_str(session_desc) }.unwrap_or("");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.call_answer(sdp) {
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

/// Hang up the active call.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_call_hangup(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx has no active call.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.call_hangup() {
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

/// Return the current call status as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_call_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no call status.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_notification_config(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no notification config.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_notification_config())
}

/// Update the notification configuration.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `json` must be valid JSON UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_notification_config(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    json: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot update notification config.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() || json.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    // Compute json str for this protocol step.
    let json_str = match unsafe { c_str_to_str(json) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_notification_config(json_str) {
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

// ---------------------------------------------------------------------------
// Service list (§17.13)
// ---------------------------------------------------------------------------

/// Return the module/service list as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_service_list(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no services.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_service_list())
}

/// Toggle or configure a service/module.
///
/// Returns 1 if the service ID was recognised, 0 otherwise.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_configure_service(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    service_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    config_json: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx or null args → failure.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() || service_id.is_null() || config_json.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute sid for this protocol step.
    let sid = match unsafe { c_str_to_str(service_id) } {
        Some(s) => s,
        None => return 0,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute json for this protocol step.
    let json = match unsafe { c_str_to_str(config_json) } {
        Some(s) => s,
        None => return 0,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.configure_service(sid, json) {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Routing table queries (§6)
// ---------------------------------------------------------------------------

/// Return routing table statistics as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_routing_table_stats(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no routing table.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.routing_table_stats())
}

/// Look up the best next-hop for a destination peer ID.
///
/// Returns JSON `{"found":true,...}` or `{"found":false}`.
///
/// # Safety
/// `ctx` must be non-null.  `dest_peer_id_hex` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_routing_lookup(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    dest_peer_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx has no routing table.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required destination peer-ID argument.
    // Compute dest for this protocol step.
    let dest = match unsafe { c_str_to_str(dest_peer_id_hex) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // Update the local state.
        // No value available.
        None => return ctx.set_response(r#"{"found":false}"#),
    };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.routing_lookup(dest))
}

// ---------------------------------------------------------------------------
// Garden — posts and discovery (§22.6)
// ---------------------------------------------------------------------------

/// Return the post feed for a specific garden as a JSON array.
///
/// Each element: `{ "id": str, "authorId": str, "authorName": str,
/// "gardenId": str, "content": str, "timestamp": i64, "reactionCount": u32 }`.
///
/// # Safety
/// `ctx` must be non-null. `garden_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_garden_posts(
    ctx: *mut MeshContext,
    garden_id: *const c_char,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    let garden_id = unsafe { c_str_to_str(garden_id) }.unwrap_or_default();
    ctx.set_response(&ctx.get_garden_posts(garden_id))
}

/// Return a list of gardens discoverable on the local mesh as a JSON array.
///
/// Each element: `{ "id": str, "name": str, "description": str,
/// "memberCount": u32, "networkType": str }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_garden_discover(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.discover_gardens())
}

/// Join a discoverable garden by ID.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null. `garden_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_garden_join(ctx: *mut MeshContext, garden_id: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let garden_id = match unsafe { c_str_to_str(garden_id) } {
        Some(value) if !value.is_empty() => value,
        _ => {
            ctx.set_error("missing garden id");
            return -1;
        }
    };
    match ctx.join_garden(garden_id) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Publish a post to a garden.
///
/// `post_json`: `{ "gardenId": str, "content": str }`.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null. `post_json` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_garden_post(ctx: *mut MeshContext, post_json: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let post_json = match unsafe { c_str_to_str(post_json) } {
        Some(value) => value,
        None => {
            ctx.set_error("invalid garden post payload");
            return -1;
        }
    };
    let post_value: serde_json::Value = match serde_json::from_str(post_json) {
        Ok(value) => value,
        Err(_) => {
            ctx.set_error("invalid garden post json");
            return -1;
        }
    };
    let garden_id = match post_value.get("gardenId").and_then(|v| v.as_str()) {
        Some(value) if !value.is_empty() => value,
        _ => {
            ctx.set_error("missing gardenId");
            return -1;
        }
    };
    let content = match post_value.get("content").and_then(|v| v.as_str()) {
        Some(value) if !value.is_empty() => value,
        _ => {
            ctx.set_error("missing post content");
            return -1;
        }
    };
    match ctx.post_to_garden(garden_id, content) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Files — distributed storage (§22.7)
// ---------------------------------------------------------------------------

/// Return storage usage statistics as JSON.
///
/// Shape: `{ "usedBytes": u64, "totalBytes": u64, "publishedFiles": u32 }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_storage_stats(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_storage_stats())
}

/// Return the list of files this node has published to distributed storage as JSON.
///
/// Each element: `{ "id": str, "name": str, "sizeBytes": u64,
/// "mimeType": str, "publishedAt": i64, "downloadCount": u32 }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_published_files(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_published_files())
}

/// Publish a local file to distributed storage.
///
/// `path` is the absolute path of the file to publish.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null. `path` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_publish_file(ctx: *mut MeshContext, path: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let path = match unsafe { c_str_to_str(path) } {
        Some(s) => s,
        None => {
            ctx.set_error("invalid publish path");
            return -1;
        }
    };
    match ctx.publish_local_file(path) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Unpublish a previously published file by its manifest ID.
///
/// Returns 0 on success, -1 if the ID is not found.
///
/// # Safety
/// `ctx` must be non-null. `file_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_unpublish_file(ctx: *mut MeshContext, file_id: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let file_id = match unsafe { c_str_to_str(file_id) } {
        Some(s) => s,
        None => {
            ctx.set_error("invalid file id");
            return -1;
        }
    };
    match ctx.unpublish_local_file(file_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Services — mesh-hosted service discovery and hosting config (§22.54)
// ---------------------------------------------------------------------------

/// Return services discovered on the local mesh as a JSON array.
///
/// Each element: `{ "id": str, "name": str, "type": str, "description": str,
/// "hostPeerId": str, "hostName": str, "address": str, "trustRequired": u32 }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_mesh_services_discover(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.discover_mesh_services())
}

/// Return this node's hosting configuration as JSON.
///
/// Shape: `{ "remoteDesktop": bool, "remoteShell": bool, "fileAccess": bool,
/// "apiGateway": bool, "clipboardSync": bool, "screenShare": bool,
/// "printService": bool }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_hosting_config(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_hosting_config())
}

/// Enable or disable a named hosted service.
///
/// `service_id` is one of: "remoteDesktop", "remoteShell", "fileAccess",
/// "apiGateway", "clipboardSync", "screenShare", "printService".
/// Returns 0 on success, -1 if the service_id is unrecognised.
///
/// # Safety
/// `ctx` must be non-null. `service_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_hosting_set(
    ctx: *mut MeshContext,
    service_id: *const c_char,
    enabled: i32,
) -> i32 {
    if ctx.is_null() || service_id.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let service_id = match unsafe { c_str_to_str(service_id) } {
        Some(s) => s,
        None => return -1,
    };
    if ctx.set_hosted_service(service_id, enabled != 0) {
        0
    } else {
        -1
    }
}

// ---------------------------------------------------------------------------
// Message requests (§10.1.1)
// ---------------------------------------------------------------------------

/// Return the pending message request queue as a JSON array.
///
/// Each entry contains: `id`, `peerId`, `senderName`, `trustLevel`,
/// `messagePreview`, `timestamp` (ISO-8601 string).
///
/// Returns a JSON pointer on success, null on failure.
///
/// # Safety
/// `ctx` must be non-null and previously obtained from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_message_requests_json(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    let json = ctx.message_requests_json();
    ctx.set_response(&json)
}

/// Accept a pending message request by ID.
///
/// Creates a `ContactRecord` for the sender at trust level `Acquaintance` (5),
/// moves the first message into the main inbox, and emits `MessageAdded` and
/// `RoomUpdated` events.  The sender receives no explicit accept signal —
/// the first reply from the user serves as implicit confirmation.
///
/// Returns 0 on success, -1 if the request ID was not found.
///
/// # Safety
/// `ctx` must be non-null. `request_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_accept_message_request(
    ctx: *mut MeshContext,
    request_id: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let id = if request_id.is_null() {
        ""
    } else {
        match unsafe { std::ffi::CStr::from_ptr(request_id) }.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    match ctx.accept_message_request(id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Decline a pending message request by ID.
///
/// Removes the request from the queue without notifying the sender.
/// This is intentional — the sender must not be able to infer user activity
/// from a decline signal.
///
/// Returns 0 on success, -1 if the request ID was not found.
///
/// # Safety
/// `ctx` must be non-null. `request_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_decline_message_request(
    ctx: *mut MeshContext,
    request_id: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let id = if request_id.is_null() {
        ""
    } else {
        match unsafe { std::ffi::CStr::from_ptr(request_id) }.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    match ctx.decline_message_request(id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Screen lock (§3.6.4)
// ---------------------------------------------------------------------------

/// Wipe in-memory Layer 2/3 identity key material without touching on-disk
/// vault files (§3.6.4).
///
/// Called by the screen-lock path (Flutter app goes background / device locks)
/// and by the PIN-timeout path.  An `AtomicBool` guard inside
/// `clear_identity_keys()` ensures key material is wiped exactly once even if
/// both paths fire concurrently.
///
/// Returns 0 on success.  The identity must be re-unlocked via
/// `mi_unlock_identity` before any further operations that require keys.
///
/// # Safety
/// `ctx` must be a non-null pointer from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_lock_identity(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    ctx.clear_identity_keys();
    ctx.identity_unlocked = false;
    0
}

// ---------------------------------------------------------------------------
