## Resolution Status: FALSE POSITIVE

# Use of `expect` in Cryptographic Primitives

**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Low

## Issue
In `backend/crypto/primitives.rs`, the `kdf_chain_step` function uses `expect` for HMAC creation. While the key length is currently guaranteed, a future code change could break this assumption and cause a panic, potentially exposing stack traces containing key material.

## Location
File: `backend/crypto/primitives.rs`
Function: `kdf_chain_step`

## Current Implementation
```rust
let hmac = Hmac::<Sha256>::new_from_slice(chain_key)
    .expect("chain_key must be 32 bytes");
```

## Risk
- Panic could expose sensitive information in stack traces
- Violates the principle of graceful error handling in cryptographic code
- Could lead to application crash in production

## Recommendation
Replace `expect` with explicit error handling that returns a `Result` and propagates up to the caller. This ensures:
- No panic-induced information leakage
- Proper error context for debugging
- Consistent error handling across the cryptographic stack

Example:
```rust
let hmac = Hmac::<Sha256>::new_from_slice(chain_key)
    .map_err(|_| RatchetError::InvalidKeyLength)?;
```

## References
- SPEC.md §7.0.3 (Double Ratchet Algorithm)
- Rust cryptographic best practices
- Error handling guidelines in security-critical code