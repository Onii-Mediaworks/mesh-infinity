# Missing Thread Safety Annotations
**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
The Rust backend uses async operations extensively but lacks explicit thread safety annotations for shared state:
- No `Send`/`Sync` trait implementations for shared data structures
- No explicit synchronization mechanisms for concurrent access to cryptographic material
- No thread safety analysis for the KDF chain operations in `backend/crypto/primitives.rs`

These omissions could lead to race conditions when multiple async tasks access shared cryptographic state.

## Resolution  (fill in when resolved)
<what was changed and where>