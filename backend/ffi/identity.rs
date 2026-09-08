//! Identity FFI shims — thin C-ABI wrappers for identity operations (§3).
//!
//! Each function:
//!   1. Null-checks the context pointer.
//!   2. Calls the corresponding `MeshRuntime` method.
//!   3. Returns the result as an integer code or JSON pointer.
//!
//! No business logic lives here.

use std::os::raw::c_char;
use std::ptr;

use super::{c_str_to_str, MeshContext};

/// Check whether an identity file exists on this device.
/// Returns 1 if an identity exists, 0 otherwise.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_has_identity(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    let ctx = unsafe { &*ctx };
    if ctx.has_identity() {
        1
    } else {
        0
    }
}

/// Create a new identity with an optional display name.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `display_name` may be null or a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn mi_create_identity(
    ctx: *mut MeshContext,
    display_name: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let name = unsafe { c_str_to_str(display_name) }.map(str::to_string);
    match ctx.create_identity(name) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Unlock an existing identity from disk.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `pin` may be null or a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn mi_unlock_identity(ctx: *mut MeshContext, pin: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let pin_str = unsafe { c_str_to_str(pin) }.map(str::to_string);
    match ctx.unlock_identity(pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return security configuration for app-lock and emergency-erase settings.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_security_config(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_security_config())
}

/// Persist backend-owned security settings from a JSON payload.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `config_json` must be valid UTF-8 NUL-terminated JSON.
#[no_mangle]
pub unsafe extern "C" fn mi_set_security_config(
    ctx: *mut MeshContext,
    config_json: *const c_char,
) -> i32 {
    if ctx.is_null() || config_json.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(json) = (unsafe { c_str_to_str(config_json) }) else {
        ctx.set_error("Security config must be valid UTF-8");
        return -1;
    };
    match ctx.set_security_config(json) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Set or replace the app PIN on the currently unlocked identity.
///
/// # Safety
/// `ctx` must be non-null.  `pin` must be valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_pin(ctx: *mut MeshContext, pin: *const c_char) -> i32 {
    if ctx.is_null() || pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let Some(pin_str) = (unsafe { c_str_to_str(pin) }).map(str::to_string) else {
        ctx.set_error("PIN must be valid UTF-8");
        return -1;
    };
    match ctx.set_pin(pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Change the app PIN after verifying the current PIN.
///
/// # Safety
/// `ctx`, `current_pin`, `new_pin` must be non-null valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_change_pin(
    ctx: *mut MeshContext,
    current_pin: *const c_char,
    new_pin: *const c_char,
) -> i32 {
    if ctx.is_null() || current_pin.is_null() || new_pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let Some(current) = (unsafe { c_str_to_str(current_pin) }).map(str::to_string) else {
        ctx.set_error("Current PIN must be valid UTF-8");
        return -1;
    };
    let Some(new) = (unsafe { c_str_to_str(new_pin) }).map(str::to_string) else {
        ctx.set_error("New PIN must be valid UTF-8");
        return -1;
    };
    match ctx.change_pin(current, new) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Remove the app PIN after verifying the current PIN.
///
/// # Safety
/// `ctx` and `current_pin` must be non-null valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_remove_pin(ctx: *mut MeshContext, current_pin: *const c_char) -> i32 {
    if ctx.is_null() || current_pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let Some(pin_str) = (unsafe { c_str_to_str(current_pin) }).map(str::to_string) else {
        ctx.set_error("Current PIN must be valid UTF-8");
        return -1;
    };
    match ctx.remove_pin(pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Set or replace the duress PIN on the currently unlocked identity.
///
/// # Safety
/// `ctx` and `pin` must be non-null valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_duress_pin(ctx: *mut MeshContext, pin: *const c_char) -> i32 {
    if ctx.is_null() || pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(pin_str) = (unsafe { c_str_to_str(pin) }).map(str::to_string) else {
        ctx.set_error("Duress PIN must be valid UTF-8");
        return -1;
    };
    match ctx.set_duress_pin(pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Change the duress PIN after verifying the current duress PIN.
///
/// # Safety
/// `ctx`, `current_pin`, `new_pin` must be non-null valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_change_duress_pin(
    ctx: *mut MeshContext,
    current_pin: *const c_char,
    new_pin: *const c_char,
) -> i32 {
    if ctx.is_null() || current_pin.is_null() || new_pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(current) = (unsafe { c_str_to_str(current_pin) }).map(str::to_string) else {
        ctx.set_error("Current duress PIN must be valid UTF-8");
        return -1;
    };
    let Some(new) = (unsafe { c_str_to_str(new_pin) }).map(str::to_string) else {
        ctx.set_error("New duress PIN must be valid UTF-8");
        return -1;
    };
    match ctx.change_duress_pin(current, new) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Remove the duress PIN after verifying the current duress PIN.
///
/// # Safety
/// `ctx` and `current_pin` must be non-null valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_remove_duress_pin(
    ctx: *mut MeshContext,
    current_pin: *const c_char,
) -> i32 {
    if ctx.is_null() || current_pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(pin_str) = (unsafe { c_str_to_str(current_pin) }).map(str::to_string) else {
        ctx.set_error("Current duress PIN must be valid UTF-8");
        return -1;
    };
    match ctx.remove_duress_pin(pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return the current identity summary as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_identity_summary(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_identity_summary())
}

/// Alias for `mi_get_identity_summary` (legacy name).
///
/// # Safety
/// Same as `mi_get_identity_summary`.
#[no_mangle]
pub unsafe extern "C" fn mi_local_identity_json(ctx: *mut MeshContext) -> *const c_char {
    unsafe { mi_get_identity_summary(ctx) }
}

/// Return the current device list as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_devices_json(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_devices_json())
}

/// Create a device-enrollment request payload for linking this device.
///
/// # Safety
/// `ctx` must be non-null; `device_name` must be null or valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_create_device_enrollment_request(
    ctx: *mut MeshContext,
    device_name: *const c_char,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    let name = if device_name.is_null() {
        None
    } else {
        match unsafe { c_str_to_str(device_name) } {
            Some(s) => Some(s.to_string()),
            None => {
                ctx.set_error("Device name must be valid UTF-8");
                return ptr::null();
            }
        }
    };
    match ctx.create_device_enrollment_request(name) {
        Ok(payload) => ctx.set_response(&payload),
        Err(e) => {
            ctx.set_error(&e);
            ptr::null()
        }
    }
}

/// Complete a device-enrollment request on the primary device.
///
/// # Safety
/// `ctx` and `request_json` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn mi_complete_device_enrollment(
    ctx: *mut MeshContext,
    request_json: *const c_char,
) -> *const c_char {
    if ctx.is_null() || request_json.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &mut *ctx };
    let Some(json) = (unsafe { c_str_to_str(request_json) }).map(str::to_string) else {
        ctx.set_error("Device enrollment request must be valid UTF-8");
        return ptr::null();
    };
    match ctx.complete_device_enrollment(&json) {
        Ok(payload) => ctx.set_response(&payload),
        Err(e) => {
            ctx.set_error(&e);
            ptr::null()
        }
    }
}

/// Accept a device-enrollment package on the target device.
///
/// # Safety
/// `ctx` and `package_json` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn mi_accept_device_enrollment(
    ctx: *mut MeshContext,
    package_json: *const c_char,
) -> i32 {
    if ctx.is_null() || package_json.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let Some(json) = (unsafe { c_str_to_str(package_json) }).map(str::to_string) else {
        ctx.set_error("Device enrollment package must be valid UTF-8");
        return -1;
    };
    match ctx.accept_device_enrollment(&json) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Remove a registered secondary device from the shared identity.
///
/// # Safety
/// `ctx` and `device_id` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn mi_remove_device(ctx: *mut MeshContext, device_id: *const c_char) -> i32 {
    if ctx.is_null() || device_id.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(id) = (unsafe { c_str_to_str(device_id) }) else {
        ctx.set_error("Device id must be valid UTF-8");
        return -1;
    };
    match ctx.remove_device(id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return stored mask metadata as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_masks_json(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_masks_json())
}

/// Create a new mask from a JSON payload.
///
/// # Safety
/// `ctx` must be non-null; `mask_json` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_create_mask(ctx: *mut MeshContext, mask_json: *const c_char) -> i32 {
    if ctx.is_null() || mask_json.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(json) = (unsafe { c_str_to_str(mask_json) }) else {
        ctx.set_error("Mask payload must be valid UTF-8");
        return -1;
    };
    match ctx.create_mask(json) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Import social state from an encrypted backup (§3.7).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.
/// Both string arguments must be non-null valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_import_identity(
    ctx: *mut MeshContext,
    backup_b64_json: *const c_char,
    passphrase: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let Some(backup_str) = (unsafe { c_str_to_str(backup_b64_json) }) else {
        return -1;
    };
    let Some(pass_str) = (unsafe { c_str_to_str(passphrase) }) else {
        return -1;
    };
    match ctx.import_identity_backup(backup_str, pass_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Non-emergency wipe of in-memory identity and social state.
///
/// Returns 0 (always succeeds if ctx is non-null).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_reset_identity(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    ctx.reset_identity();
    0
}

/// Set the public profile visible to all contacts (§9.1).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null; `json` must be non-null valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_public_profile(ctx: *mut MeshContext, json: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(profile_json) = (unsafe { c_str_to_str(json) }) else {
        return -1;
    };
    match ctx.set_public_profile(profile_json) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Set the private profile shared only with trusted contacts (§9.2).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null; `json` must be non-null valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_private_profile(ctx: *mut MeshContext, json: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(profile_json) = (unsafe { c_str_to_str(json) }) else {
        return -1;
    };
    match ctx.set_private_profile(profile_json) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}
