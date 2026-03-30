# Missing Bounds Checking for FFI Parameters
**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
The FFI boundary in `backend/ffi/lib.rs` lacks proper bounds checking for several parameters:
- No validation of `config_path` pointer validity beyond null check
- No bounds checking for string parameters that could lead to buffer overflows
- No validation of numeric parameters like `wireguard_port`, `max_peers`, `max_connections` for reasonable ranges
- No sanitization of user-provided network addresses

These issues could potentially lead to memory safety vulnerabilities when handling FFI calls from Flutter.

## Resolution  (fill in when resolved)
<what was changed and where>