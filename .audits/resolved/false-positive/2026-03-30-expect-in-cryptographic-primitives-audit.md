## Resolution Status: FALSE POSITIVE

# Use of `expect` in Cryptographic Primitives
**Date:** 2026-03-30
**Auditor:** claude
**Status:** UNRESOLVED
**Severity:** High

## Issue
The codebase uses `expect()` in cryptographic primitives, which can expose sensitive information through panic messages. This violates the principle of least privilege and could lead to information leakage in security-critical paths.

## Location
- `backend/crypto/primitives.rs` - `kdf_chain_step` function
- Multiple other files across the codebase

## Current Implementation
In `backend/crypto/primitives.rs`, the `kdf_chain_step` function uses `expect` for HMAC creation:
```rust
let hmac = Hmac::<Sha256>::new_from_slice(chain_key)
    .expect("chain_key must be 32 bytes");
```

## Risk
- Panic could expose sensitive information in stack traces
- Violates the principle of least privilege
- Could lead to application crash in production
- Potential for information leakage through error messages

## Recommendation
Replace `expect` with explicit error handling that returns a `Result` and propagates up to the caller. This ensures:
- No panic-induced information leakage
- Proper error context for debugging
- Consistent error handling across the cryptographic stack

## Example
```rust
let hmac = Hmac::<Sha256>::new_from_slice(chain_key)
    .map_err(|_| RatchetError::InvalidKeyLength)?;
```

## References
- SPEC.md §7.0.3 (Double Ratchet Algorithm)
- Rust cryptographic best practices
- Error handling guidelines in security-critical code