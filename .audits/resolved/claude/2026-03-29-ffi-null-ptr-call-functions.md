## Resolution Status: RESOLVED

# Null Pointer Dereference in Call FFI Functions — `peer_id_hex` and `call_id_hex` Unchecked
**Date:** 2026-03-29
**Auditor:** claude-sonnet-4-6
**Status:** UNRESOLVED
**Severity:** High

## Issue

Three FFI functions check `ctx.is_null()` but do NOT check their string pointer arguments
for null before dereferencing:

- `backend/ffi/lib.rs:9726` (`mi_call_offer`): `peer_id_hex: *const c_char` passed to
  `CStr::from_ptr(peer_id_hex)` without a prior null check.
- `backend/ffi/lib.rs:9797` (`mi_call_answer`): `call_id_hex: *const c_char` passed to
  `CStr::from_ptr(call_id_hex)` without a prior null check.
- `backend/ffi/lib.rs:9854` (`mi_call_hangup`): Same issue as mi_call_answer.

A null pointer passed from Dart for any of these will cause undefined behaviour inside
`CStr::from_ptr`, crashing the process. On iOS and Android, this terminates the app.

The correct pattern is already used elsewhere, e.g. `mi_tor_connect` (line 6027):
```rust
if ctx.is_null() || peer_id_hex_ptr.is_null() || onion_addr_ptr.is_null() { return -1; }
```

## Resolution
*(fill in when resolved)*

Add null checks for all string pointer parameters before the first `CStr::from_ptr` call
in each affected function:
```rust
if ctx.is_null() || peer_id_hex.is_null() { return ptr::null(); }
```
For `mi_call_answer` and `mi_call_hangup`, the check should be:
```rust
if ctx.is_null() || call_id_hex.is_null() { return 0; }
```
