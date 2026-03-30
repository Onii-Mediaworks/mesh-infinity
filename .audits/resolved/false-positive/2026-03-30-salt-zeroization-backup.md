## Resolution Status: FALSE POSITIVE

# Missing Salt Zeroization in Backup Key Derivation

**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Low

## Issue
In `backend/crypto/backup.rs`, the `derive_backup_key` function does not explicitly zeroize the Argon2id salt after key derivation. This could lead to the salt being retained in memory longer than necessary, potentially exposing it to forensic analysis or memory scraping attacks.

## Location
File: `backend/crypto/backup.rs`
Function: `derive_backup_key`

## Current Implementation
The function generates or uses a salt for Argon2id key derivation but does not explicitly clear it from memory after the derivation is complete. While Rust's ownership system will eventually drop the salt, there's no guarantee when this happens or whether the memory will be zeroized.

## Risk
- Salt values could be exposed in memory dumps
- Potential for cryptographic weakness if salt is reused inadvertently
- Violates the principle of minimizing secret material lifetime in memory

## Recommendation
1. Use `Zeroizing` wrapper for the salt buffer
2. Explicitly zeroize the salt immediately after the `hash_password_into` call
3. Ensure the salt is not copied to other locations without zeroization
4. Consider using `clear_on_drop` for all temporary cryptographic buffers

Example:
```rust
let mut salt = Zeroizing::new([0u8; 16]);
// ... fill salt ...
argon2.hash_password_into(passphrase, &*salt, &mut *output)?;
salt.zeroize(); // Explicit zeroization
```

## References
- SPEC.md §3.7.4 (Backup, Restore, and Safety Numbers)
- Secure memory management best practices
- Zeroization patterns in Rust cryptographic code