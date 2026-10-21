//! FFI surface for protocol server configuration (§22.54.4–§22.54.9).
//!
//! # Conventions
//!
//! Getters return a JSON string owned by the context (`set_response`);
//! Flutter copies it and calls `mi_string_free`.  Setters take a JSON
//! string, return `0` on success and `-1` on failure, and store the reason
//! with `set_error` so `mi_last_error_message` can show it.  Every pointer
//! is null-checked and every string is validated as UTF-8 before use — the
//! JSON itself is untrusted and is parsed by the typed validators in
//! `services::server_config`.
//!
//! # Functions
//!
//! | Rust symbol                   | Direction | Payload                        |
//! |-------------------------------|-----------|--------------------------------|
//! | `mi_mnrdp_config`             | get       | `MnrdpServerConfig`            |
//! | `mi_mnrdp_config_set`         | set       | `MnrdpServerConfig`            |
//! | `mi_mnsp_config`              | get       | `MnspServerConfig`             |
//! | `mi_mnsp_config_set`          | set       | `MnspServerConfig`             |
//! | `mi_mnfp_config`              | get       | `MnfpServerConfig`             |
//! | `mi_mnfp_config_set`          | set       | `MnfpServerConfig`             |
//! | `mi_api_gateway_config`       | get       | `ApiGatewayConfig`             |
//! | `mi_api_gateway_config_set`   | set       | `ApiGatewayConfig`             |
//! | `mi_print_config`             | get       | `PrintServiceConfig`           |
//! | `mi_print_config_set`         | set       | `PrintServiceConfig`           |
//! | `mi_service_host_facts`       | get       | host facts (see runtime docs)  |
//! | `mi_print_queues`             | get       | `[IppPrinter]`                 |
//! | `mi_print_queue_probe`        | get       | `IppPrinter` for one URL       |

use std::os::raw::c_char;
use std::ptr;

use super::{c_str_to_str, MeshContext};
use crate::service::MeshRuntime;
use crate::services::server_config::ServerConfigError;

/// Shared body of every getter: null-check, then hand back the JSON.
///
/// # Safety
/// `ctx` must be null or a live context from `mesh_init`.
unsafe fn get_json(
    ctx: *mut MeshContext,
    read: impl FnOnce(&MeshRuntime) -> String,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&read(ctx))
}

/// Shared body of every setter: null-check, UTF-8 check, then the typed
/// save; a failure is recorded as the last error.
///
/// # Safety
/// `ctx` must be null or a live context; `json` null or NUL-terminated.
unsafe fn set_json(
    ctx: *mut MeshContext,
    json: *const c_char,
    write: impl FnOnce(&MeshRuntime, &str) -> Result<(), ServerConfigError>,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(json) = (unsafe { c_str_to_str(json) }) else {
        ctx.set_error("configuration must be valid UTF-8 JSON");
        return -1;
    };
    match write(ctx, json) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Remote Desktop (§22.54.5)
// ---------------------------------------------------------------------------

/// Return the Remote Desktop server settings as JSON.
///
/// # Safety
/// `ctx` must be null or a live context from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mnrdp_config(ctx: *mut MeshContext) -> *const c_char {
    unsafe { get_json(ctx, MeshRuntime::get_mnrdp_config) }
}

/// Replace the Remote Desktop server settings from JSON.  Returns 0 on
/// success, -1 on a validation or parse failure (see `mi_last_error_message`).
///
/// # Safety
/// `ctx` must be null or a live context; `json` null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn mi_mnrdp_config_set(ctx: *mut MeshContext, json: *const c_char) -> i32 {
    unsafe { set_json(ctx, json, MeshRuntime::set_mnrdp_config) }
}

// ---------------------------------------------------------------------------
// Remote Shell (§22.54.6)
// ---------------------------------------------------------------------------

/// Return the Remote Shell server settings as JSON.
///
/// # Safety
/// `ctx` must be null or a live context from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mnsp_config(ctx: *mut MeshContext) -> *const c_char {
    unsafe { get_json(ctx, MeshRuntime::get_mnsp_config) }
}

/// Replace the Remote Shell server settings from JSON.
///
/// # Safety
/// `ctx` must be null or a live context; `json` null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn mi_mnsp_config_set(ctx: *mut MeshContext, json: *const c_char) -> i32 {
    unsafe { set_json(ctx, json, MeshRuntime::set_mnsp_config) }
}

// ---------------------------------------------------------------------------
// File Access (§22.54.7)
// ---------------------------------------------------------------------------

/// Return the File Access server settings as JSON.
///
/// # Safety
/// `ctx` must be null or a live context from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mnfp_config(ctx: *mut MeshContext) -> *const c_char {
    unsafe { get_json(ctx, MeshRuntime::get_mnfp_config) }
}

/// Replace the File Access server settings from JSON.
///
/// # Safety
/// `ctx` must be null or a live context; `json` null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn mi_mnfp_config_set(ctx: *mut MeshContext, json: *const c_char) -> i32 {
    unsafe { set_json(ctx, json, MeshRuntime::set_mnfp_config) }
}

// ---------------------------------------------------------------------------
// API Gateway (§22.54.8)
// ---------------------------------------------------------------------------

/// Return the API Gateway settings as JSON.
///
/// # Safety
/// `ctx` must be null or a live context from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_api_gateway_config(ctx: *mut MeshContext) -> *const c_char {
    unsafe { get_json(ctx, MeshRuntime::get_api_gateway_config) }
}

/// Replace the API Gateway settings from JSON.
///
/// # Safety
/// `ctx` must be null or a live context; `json` null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn mi_api_gateway_config_set(
    ctx: *mut MeshContext,
    json: *const c_char,
) -> i32 {
    unsafe { set_json(ctx, json, MeshRuntime::set_api_gateway_config) }
}

// ---------------------------------------------------------------------------
// Print Services (§22.54.9)
// ---------------------------------------------------------------------------

/// Return the Print Services settings as JSON.
///
/// # Safety
/// `ctx` must be null or a live context from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_print_config(ctx: *mut MeshContext) -> *const c_char {
    unsafe { get_json(ctx, MeshRuntime::get_print_config) }
}

/// Replace the Print Services settings from JSON.
///
/// # Safety
/// `ctx` must be null or a live context; `json` null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn mi_print_config_set(ctx: *mut MeshContext, json: *const c_char) -> i32 {
    unsafe { set_json(ctx, json, MeshRuntime::set_print_config) }
}

/// Return the IPP queues the local spooler reports, as a JSON array.
/// Blocks for up to a few seconds while the spooler is contacted.
///
/// # Safety
/// `ctx` must be null or a live context from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_print_queues(ctx: *mut MeshContext) -> *const c_char {
    unsafe { get_json(ctx, MeshRuntime::print_queues) }
}

/// Probe one IPP queue URL for its name and capabilities.  Returns JSON on
/// success or null on failure (see `mi_last_error_message`).
///
/// # Safety
/// `ctx` must be null or a live context; `url` null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn mi_print_queue_probe(
    ctx: *mut MeshContext,
    url: *const c_char,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    let Some(url) = (unsafe { c_str_to_str(url) }) else {
        ctx.set_error("printer address must be valid UTF-8");
        return ptr::null();
    };
    match ctx.print_queue_probe(url) {
        Ok(json) => ctx.set_response(&json),
        Err(e) => {
            ctx.set_error(&e.to_string());
            ptr::null()
        }
    }
}

// ---------------------------------------------------------------------------
// Host facts
// ---------------------------------------------------------------------------

/// Return platform facts the configuration screens need (adapter
/// availability, default user, shells) as JSON.
///
/// # Safety
/// `ctx` must be null or a live context from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_service_host_facts(ctx: *mut MeshContext) -> *const c_char {
    unsafe { get_json(ctx, MeshRuntime::service_host_facts) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{mesh_destroy, mi_last_error_message};
    use std::ffi::{CStr, CString};

    /// A live context in a temporary data directory.
    fn context() -> (tempfile::TempDir, *mut MeshContext) {
        let dir = tempfile::TempDir::new().unwrap();
        let runtime = MeshRuntime::new(dir.path().to_string_lossy().into_owned());
        (dir, Box::into_raw(Box::new(MeshContext(Box::new(runtime)))))
    }

    fn read(ptr: *const c_char) -> String {
        assert!(!ptr.is_null());
        unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string()
    }

    fn last_error(ctx: *mut MeshContext) -> String {
        read(unsafe { mi_last_error_message(ctx) })
    }

    #[test]
    fn null_context_is_handled_everywhere() {
        let json = CString::new("{}").unwrap();
        unsafe {
            assert!(mi_mnrdp_config(ptr::null_mut()).is_null());
            assert!(mi_mnsp_config(ptr::null_mut()).is_null());
            assert!(mi_mnfp_config(ptr::null_mut()).is_null());
            assert!(mi_api_gateway_config(ptr::null_mut()).is_null());
            assert!(mi_print_config(ptr::null_mut()).is_null());
            assert!(mi_service_host_facts(ptr::null_mut()).is_null());
            assert!(mi_print_queues(ptr::null_mut()).is_null());
            assert!(mi_print_queue_probe(ptr::null_mut(), json.as_ptr()).is_null());
            assert_eq!(mi_mnrdp_config_set(ptr::null_mut(), json.as_ptr()), -1);
            assert_eq!(mi_mnsp_config_set(ptr::null_mut(), json.as_ptr()), -1);
            assert_eq!(mi_mnfp_config_set(ptr::null_mut(), json.as_ptr()), -1);
            assert_eq!(
                mi_api_gateway_config_set(ptr::null_mut(), json.as_ptr()),
                -1
            );
            assert_eq!(mi_print_config_set(ptr::null_mut(), json.as_ptr()), -1);
        }
    }

    #[test]
    fn null_and_invalid_json_pointers_are_errors() {
        let (_dir, ctx) = context();
        unsafe {
            assert_eq!(mi_mnrdp_config_set(ctx, ptr::null()), -1);
            assert!(last_error(ctx).contains("UTF-8"));
            let bad = CString::new([0xffu8, 0xfe, b'{']).unwrap();
            assert_eq!(mi_api_gateway_config_set(ctx, bad.as_ptr()), -1);
            assert!(mi_print_queue_probe(ctx, ptr::null()).is_null());
            mesh_destroy(ctx);
        }
    }

    #[test]
    fn getters_return_defaults_and_setters_round_trip() {
        let (_dir, ctx) = context();
        unsafe {
            let before = read(mi_mnrdp_config(ctx));
            let v: serde_json::Value = serde_json::from_str(&before).unwrap();
            assert_eq!(v["view_floor"], 5);
            assert_eq!(v["max_sessions"], 2);

            let update =
                CString::new(r#"{"view_floor":6,"input_floor":6,"max_sessions":3}"#).unwrap();
            assert_eq!(mi_mnrdp_config_set(ctx, update.as_ptr()), 0);
            let after: serde_json::Value =
                serde_json::from_str(&read(mi_mnrdp_config(ctx))).unwrap();
            assert_eq!(after["view_floor"], 6);
            assert_eq!(after["max_sessions"], 3);

            let gateway: serde_json::Value =
                serde_json::from_str(&read(mi_api_gateway_config(ctx))).unwrap();
            assert_eq!(gateway["upstream_url"], "http://127.0.0.1:8080");
            let print: serde_json::Value =
                serde_json::from_str(&read(mi_print_config(ctx))).unwrap();
            assert!(print["printers"].as_array().unwrap().is_empty());
            mesh_destroy(ctx);
        }
    }

    #[test]
    fn rejected_payloads_report_the_field_and_keep_state() {
        let (_dir, ctx) = context();
        unsafe {
            let below_floor = CString::new(r#"{"view_floor":1}"#).unwrap();
            assert_eq!(mi_mnrdp_config_set(ctx, below_floor.as_ptr()), -1);
            assert!(last_error(ctx).starts_with("view_floor:"));
            let v: serde_json::Value = serde_json::from_str(&read(mi_mnrdp_config(ctx))).unwrap();
            assert_eq!(v["view_floor"], 5);

            let garbage = CString::new("{\"shares\": [1, 2").unwrap();
            assert_eq!(mi_mnfp_config_set(ctx, garbage.as_ptr()), -1);
            assert!(last_error(ctx).starts_with("malformed configuration"));

            let open_proxy = CString::new(r#"{"upstream_url":"http://169.254.169.254/"}"#).unwrap();
            assert_eq!(mi_api_gateway_config_set(ctx, open_proxy.as_ptr()), -1);
            assert!(last_error(ctx).contains("only forwards to services on this device"));

            let remote_printer = CString::new(r#"{"printers":[{"ipp_url":"ipp://8.8.8.8/p","printer_name":"x","min_trust_level":5}]}"#).unwrap();
            assert_eq!(mi_print_config_set(ctx, remote_printer.as_ptr()), -1);
            mesh_destroy(ctx);
        }
    }

    #[test]
    fn errors_never_leak_the_payload_wholesale() {
        // A hostile payload must not be echoed back in the error text, where
        // it could reach logs or the Error event stream.
        let (_dir, ctx) = context();
        unsafe {
            let secret = "SECRET-TOKEN-DO-NOT-LOG";
            let payload =
                CString::new(format!(r#"{{"upstream_url":"http://{secret}.example/"}}"#)).unwrap();
            assert_eq!(mi_api_gateway_config_set(ctx, payload.as_ptr()), -1);
            assert!(!last_error(ctx).contains(secret));
            mesh_destroy(ctx);
        }
    }

    #[test]
    fn host_facts_and_queues_are_json() {
        let (_dir, ctx) = context();
        unsafe {
            let facts: serde_json::Value =
                serde_json::from_str(&read(mi_service_host_facts(ctx))).unwrap();
            assert!(facts["mnsp"]["shells"].is_array());
            let probe_url = CString::new("ipp://203.0.113.9/ipp/print").unwrap();
            assert!(mi_print_queue_probe(ctx, probe_url.as_ptr()).is_null());
            assert!(last_error(ctx).contains("local network"));
            mesh_destroy(ctx);
        }
    }
}
