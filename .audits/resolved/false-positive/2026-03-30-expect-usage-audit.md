## Resolution Status: FALSE POSITIVE

# Comprehensive Audit of `expect()` Usage
**Date:** 2026-03-30
**Auditor:** claude
**Status:** UNRESOLVED
**Severity:** High

## Issue
The codebase contains numerous instances of `expect()` usage, particularly in security-critical paths. Using `expect()` can cause panics that may expose sensitive information through stack traces, violate the principle of least privilege, and lead to application crashes in production.

## Scope
This audit identified `expect()` usage across multiple modules:
- Cryptographic primitives (`backend/crypto/primitives.rs`)
- Identity management (`backend/identity/self_identity.rs`)
- Transport layers (WireGuard, Tor, KCP, etc.)
- Messaging and routing
- FFI boundary

## Critical Findings

### 1. Cryptographic Primitives
**Location**: `backend/crypto/primitives.rs:80, 102`
```rust
let hmac = Hmac::<Sha256>::new_from_slice(chain_key)
    .expect("HMAC-SHA256 accepts any key length — [u8;32] is always valid");
```
**Risk**: While the key length is guaranteed by type, a future code change could break this assumption, causing a panic that exposes cryptographic material.

### 2. Identity Operations
**Location**: `backend/identity/self_identity.rs:282, 956, 963, 997, etc.`
```rust
let json = serde_json::to_vec(&metadata).expect("IdentityMetadata serialization is infallible");
```
**Risk**: Serialization failures could panic, potentially exposing identity information.

### 3. Transport Layer
**Location**: `backend/transport/wireguard.rs:168, 181-182`
```rust
let nonce_val = u64::from_le_bytes(packet[..8].try_into().unwrap());
let mut high = self.recv_high.lock().unwrap();
```
**Risk**: Panic in network processing could lead to denial of service and information leakage.

### 4. FFI Boundary
**Location**: `backend/ffi/lib.rs:321, 1901, etc.`
```rust
match ctx.last_error.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
```
**Risk**: Panics crossing FFI boundary can crash the entire application and expose memory.

## Impact Assessment
- **Confidentiality**: Stack traces may reveal sensitive cryptographic keys or internal state
- **Integrity**: Panics can lead to inconsistent state and data corruption
- **Availability**: Cascading failures from unhandled panics can cause denial of service

## Recommendations

### 1. Replace `expect()` with proper error handling
```rust
// Before
let result = operation.expect("error message");

// After
let result = operation.map_err(|e| {
    log::debug!("Operation failed: {}", e);
    Error::OperationFailed
})?;
```

### 2. Use `unwrap_or_else` for fallback values
```rust
let value = option.unwrap_or_else(|| default_value);
```

### 3. Implement graceful degradation
For operations that truly cannot fail (e.g., HKDF output length), document the invariant and use `debug_assert!` instead:
```rust
debug_assert!(output.len() == 32, "HKDF output length invariant");
let output = hk.expand(info, &mut out).map_err(|_| Error::InvalidOutputLength)?;
```

### 4. Add panic handlers in critical sections
```rust
std::panic::set_hook(Box::new(|info| {
    // Log panic securely without exposing sensitive data
    log::error!("Panic occurred: {}", info);
    // Optionally report to monitoring system
}));
```

### 5. Audit all FFI-exposed functions
Ensure no `expect()` or `unwrap()` can be triggered from FFI calls. Use `catch_unwind` at FFI boundaries if necessary.

## Priority Actions
1. **Immediate**: Replace `expect()` in cryptographic operations
2. **High**: Audit and fix all `expect()` in FFI-reachable code
3. **Medium**: Replace `expect()` in transport layer background threads
4. **Low**: Replace `expect()` in test code (acceptable but could be improved)

## References
- AGENTS.md: Security Audit Protocol
- README.md: Panic safety requirements
- SPEC.md: Error handling guidelines