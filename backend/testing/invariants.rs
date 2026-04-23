//! Shared security invariant helpers for tests, fuzz harnesses, and simulators.
//!
//! These helpers are intentionally generic. They provide common checks that
//! security-sensitive tests can reuse without rewriting the same assertions in
//! multiple places.

use std::panic::{self, AssertUnwindSafe};

use serde_json::Value;

/// Field names that must never appear in diagnostics, public events, or other
/// outward-facing JSON where secrets or personal data would be a leak.
pub const FORBIDDEN_PUBLIC_FIELDS: &[&str] = &[
    "text",
    "content",
    "body",
    "private_key",
    "secret",
    "seed",
    "display_name",
    "name",
    "email",
    "phone",
    "address",
    "ip",
    "host",
];

/// Assert that running a byte-processing function on attacker-controlled input
/// does not panic.
pub fn assert_no_panic_on_bytes<F, T>(label: &str, input: &[u8], func: F)
where
    F: FnOnce(&[u8]) -> T,
{
    let result = panic::catch_unwind(AssertUnwindSafe(|| func(input)));
    assert!(
        result.is_ok(),
        "{label} panicked on attacker-controlled input"
    );
}

/// Assert that outward-facing JSON does not contain forbidden field names.
pub fn assert_no_forbidden_json_fields(value: &Value, forbidden_fields: &[&str]) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                assert!(
                    !forbidden_fields
                        .iter()
                        .any(|candidate| key.eq_ignore_ascii_case(candidate)),
                    "forbidden outward-facing field present: {key}"
                );
                assert_no_forbidden_json_fields(nested, forbidden_fields);
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_no_forbidden_json_fields(item, forbidden_fields);
            }
        }
        _ => {}
    }
}

/// Convenience wrapper for the project's default outward-facing field denylist.
pub fn assert_no_forbidden_public_fields(value: &Value) {
    assert_no_forbidden_json_fields(value, FORBIDDEN_PUBLIC_FIELDS);
}
