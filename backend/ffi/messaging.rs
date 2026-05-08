//! Rooms and messaging FFI shims (§10, §11).
//! Each function is a thin C-ABI wrapper (null-check → delegate → return).
//! No business logic lives here.

use std::os::raw::c_char;
use std::ptr;

use super::{c_str_to_str, MeshContext};

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
    if ctx.is_null() {
        return ptr::null();
    }
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
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Parse room name; default to "New Chat" if null.
    let room_name = unsafe { c_str_to_str(name) }.unwrap_or("New Chat");
    // Parse optional peer ID for DM rooms.
    let pid_str = unsafe { c_str_to_str(peer_id) };
    // Delegate room creation to service layer.
    // Dispatch on the variant.
    match ctx.create_room(room_name, pid_str) {
        Ok(id_hex) => {
            // Serialize to the wire format for transmission or storage.
            let json = serde_json::json!({"id": id_hex, "name": room_name}).to_string();
            ctx.set_response(&json)
        }
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            ptr::null()
        }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    let rid = match unsafe { c_str_to_str(room_id) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // No value available.
        None => return -1,
    };
    // Dispatch to service layer; map bool result to 0/-1.
    if ctx.delete_room(rid) {
        0
    } else {
        -1
    }
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
    if ctx.is_null() {
        return ptr::null();
    }
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
    if ctx.is_null() {
        return ptr::null();
    }
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
    unsafe { crate::ffi::network::mi_set_active_conversation(ctx, room_id) }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let txt = match unsafe { c_str_to_str(text) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // Dispatch to service layer.
    if ctx.send_text_message(rid, txt) {
        0
    } else {
        -1
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required message-ID argument.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse all three required arguments.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let emj = match unsafe { c_str_to_str(emoji) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // Delegate to service layer.
    if ctx.send_reaction(rid, mid, emj) {
        0
    } else {
        -1
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Parse all three required arguments.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let rto = match unsafe { c_str_to_str(reply_to) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let txt = match unsafe { c_str_to_str(text) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // Delegate to service layer.
    if ctx.reply_to_message(rid, rto, txt) {
        0
    } else {
        -1
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let ntxt = match unsafe { c_str_to_str(new_text) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // Delegate to service layer.
    if ctx.edit_message(mid, ntxt) {
        0
    } else {
        -1
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required message-ID argument.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    if ctx.delete_for_everyone(mid).is_some() {
        0
    } else {
        -1
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    let ctx = unsafe { &mut *ctx };
    // Parse required arguments.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let tgt = match unsafe { c_str_to_str(target_room) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    if ctx.forward_message(mid, tgt) {
        0
    } else {
        -1
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required argument.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    if ctx.pin_message(mid) {
        0
    } else {
        -1
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required argument.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    if ctx.unpin_message(mid) {
        0
    } else {
        -1
    }
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
    if ctx.set_disappearing_timer(rid, secs) {
        0
    } else {
        -1
    }
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
    if ctx.is_null() {
        return ptr::null();
    }
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
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate expiry pruning to service layer.
    ctx.prune_expired_messages();
    0
}

