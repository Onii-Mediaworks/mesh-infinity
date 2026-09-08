//! Event polling FFI shims (§14.1).
//! Each function is a thin C-ABI wrapper (null-check → delegate → return).
//! No business logic lives here.

use std::os::raw::c_char;
use std::ptr;

use super::MeshContext;

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
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Advance all transports (TCP, Tor, LAN, file, gossip, keepalives, etc.).
    ctx.advance_clearnet_transport();
    // Drain the event queue and return as JSON.
    let mut queue = ctx.event_queue.lock().unwrap_or_else(|e| e.into_inner());
    // Validate the input length to prevent out-of-bounds access.
    if queue.is_empty() {
        // Return the result to the caller.
        return ctx.set_response("[]");
    }
    // Serialize to the wire format for transmission or storage.
    let events: Vec<serde_json::Value> = queue.drain(..).collect();
    // Execute this step in the protocol sequence.
    drop(queue);
    // Apply the closure to each element.
    ctx.set_response(&serde_json::to_string(&events).unwrap_or_else(|_| "[]".into()))
}
