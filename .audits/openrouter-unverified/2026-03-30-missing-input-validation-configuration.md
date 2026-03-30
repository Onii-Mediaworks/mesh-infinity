# Missing Input Validation for Configuration Parameters
**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
The configuration parsing in `backend/ffi/lib.rs` (FfiMeshConfig struct) lacks comprehensive input validation:
- No validation of configuration file format or content
- No protection against malicious configuration files
- No secure default configuration values
- No bounds checking for numeric parameters like `wireguard_port`, `max_peers`, `max_connections`

These deficiencies could lead to invalid configurations being accepted, potentially causing unexpected behavior or security issues.

## Resolution  (fill in when resolved)
<what was changed and where>