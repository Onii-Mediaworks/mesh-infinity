//! Shared fuzz harness for FFI-facing JSON payloads.
//!
//! The real C ABI layer receives NUL-terminated UTF-8 strings from Dart and
//! forwards those strings into service-layer JSON handlers. This module keeps
//! the fuzz boundary at that service handoff so malformed JSON, wrong types,
//! oversized fields, and semantically invalid payloads are exercised without
//! requiring unsafe pointer construction in every harness.

use crate::service::MeshRuntime;
use crate::testing::arbitrary::ByteCursor;

const MAX_FFI_JSON_BYTES: usize = 4096;

/// Exercise one bounded FFI JSON payload against a representative service hook.
pub fn run_ffi_json_input(data: &[u8]) {
    let mut cursor = ByteCursor::new(data);
    let case = cursor.take_u8() % 10;
    let payload_bytes = cursor.take_bytes(MAX_FFI_JSON_BYTES);
    let Ok(payload) = std::str::from_utf8(payload_bytes) else {
        return;
    };

    let runtime = MeshRuntime::new("/tmp/mesh-infinity-fuzz-ffi-json".to_string());

    match case {
        0 => {
            let _ = runtime.set_security_config(payload);
        }
        1 => {
            let _ = runtime.update_android_proximity_state(payload);
        }
        2 => {
            let _ = runtime.update_android_startup_state(payload);
        }
        3 => {
            let _ = runtime.set_vpn_mode(payload);
        }
        4 => {
            let _ = runtime.set_app_connector_config(payload);
        }
        5 => {
            let _ = runtime.set_notification_config(payload);
        }
        6 => {
            let _ = runtime.set_public_profile(payload);
        }
        7 => {
            let _ = runtime.set_private_profile(payload);
        }
        8 => {
            let _ = runtime.sdr_configure(payload);
        }
        _ => {
            let _ = runtime.set_clearnet_route(payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run_ffi_json_input;
    use crate::testing::invariants::assert_no_panic_on_bytes;

    #[test]
    fn ffi_json_input_never_panics_on_malformed_json() {
        assert_no_panic_on_bytes("run_ffi_json_input", b"\x00\xff{not-json", |data| {
            run_ffi_json_input(data)
        });
    }

    #[test]
    fn ffi_json_input_accepts_representative_security_config() {
        run_ffi_json_input(b"\x00\x40{\"wrongPinWipeEnabled\":true,\"wrongPinWipeThreshold\":5}");
    }
}
