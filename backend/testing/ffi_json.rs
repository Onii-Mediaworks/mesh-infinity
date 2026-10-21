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
    // Fifteen handlers: the ten original settings hooks plus the five
    // protocol-server configuration setters of §22.54.5–§22.54.9.
    let case = cursor.take_u8() % 15;
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
        9 => {
            let _ = runtime.set_clearnet_route(payload);
        }
        10 => {
            let _ = runtime.set_mnrdp_config(payload);
        }
        11 => {
            let _ = runtime.set_mnsp_config(payload);
        }
        12 => {
            let _ = runtime.set_mnfp_config(payload);
        }
        13 => {
            let _ = runtime.set_api_gateway_config(payload);
        }
        _ => {
            let _ = runtime.set_print_config(payload);
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

    #[test]
    fn ffi_json_input_exercises_every_server_config_setter() {
        // Cases 10–14 route to the §22.54 setters; hostile shapes must be
        // typed rejections, never panics.
        for case in 10u8..15 {
            for payload in [
                &b"{}"[..],
                b"{\"view_floor\":-1}",
                b"{\"shares\":[{\"name\":\"\",\"root_path\":\"/\",\"access\":\"Nope\"}]}",
                b"[1,2,3]",
                b"{\"printers\":[{\"ipp_url\":\"ipp://8.8.8.8/\",\"printer_name\":\"x\",\"min_trust_level\":9}]}",
                b"\xff\xfe",
            ] {
                let mut input = vec![case, payload.len() as u8];
                input.extend_from_slice(payload);
                assert_no_panic_on_bytes("run_ffi_json_input", &input, |data| {
                    run_ffi_json_input(data)
                });
            }
        }
    }

    #[test]
    fn ffi_json_corpus_replays_without_panic() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/fuzz_ffi_json_inputs");
        crate::testing::corpus::assert_corpus_dir_exists(&dir);
        let entries = crate::testing::corpus::load_corpus_entries(&dir).expect("read corpus");
        assert!(
            entries.len() >= 7,
            "corpus must seed every settings handler"
        );
        for (path, bytes) in entries {
            assert_no_panic_on_bytes(&path.display().to_string(), &bytes, |data| {
                run_ffi_json_input(data)
            });
        }
    }
}
