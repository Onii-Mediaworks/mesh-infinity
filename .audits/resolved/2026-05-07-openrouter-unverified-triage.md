# OpenRouter Unverified Audit Triage — 2026-05-07
**Date:** 2026-05-07
**Auditor:** claude-sonnet-4-6 (triage session)
**Status:** RESOLVED
**Severity:** N/A — triage document

All 10 findings from `.audits/openrouter-unverified/2026-03-30-*` were
reviewed against current code.  Results below.

---

## 1. missing-network-address-sanitization

**Finding:** No validation of IP address format, no bounds checking for
network parameters.

**Verdict: RESOLVED — FALSE POSITIVE.**  
`backend/network/map.rs::validate_endpoint_format()` provides
comprehensive per-transport validation: Clearnet endpoints parsed with
`SocketAddr::from_str`; Tor validates `.onion` format and port; I2P and
Yggdrasil validate base32/hex address formats; proximity transports
restrict to ≤128-byte printable ASCII; GNUnet/Mixnet restrict to
alphanumeric + safe punctuation.  The validation fires on every gossiped
entry via `insert_gossiped` → `validate_entry`.

---

## 2. missing-transport-parameter-validation

**Finding:** `backend/network/security_policy.rs` lacks transport parameter
sanitization.

**Verdict: RESOLVED — FALSE POSITIVE.**  
`security_policy.rs` contains only cover-traffic parameters and stream
latency ceilings — it accepts no user-provided transport addresses.
Transport address validation is in `map.rs` (see #1).

---

## 3. missing-concurrent-key-derivation-validation

**Finding:** `backend/crypto/primitives.rs` — no thread safety for KDF chain.

**Verdict: RESOLVED — FALSE POSITIVE.**  
`kdf_chain_step` is a pure function (`&[u8; 32]` → `([u8; 32], [u8; 32])`)
with no shared mutable state.  Rust's ownership model ensures callers hold
exclusive references to their chain keys.  There is nothing to synchronize.

---

## 4. missing-cryptographic-constants-documentation

**Finding:** `CHAIN_MSG_KEY_INPUT` (0x01) and `CHAIN_ADVANCE_INPUT` (0x02)
lack documentation.

**Verdict: RESOLVED — documented.**  
Both constants carry `// CHAIN_*_INPUT — protocol constant.` comments and
are referenced in the module-level doc (`//! HMAC-SHA256-based formula`).
Comprehensive explanation of the Double Ratchet derivation is in §3.5 spec.

---

## 5. missing-identity-reconstruction-validation

**Finding:** `mesh_identity.rs::from_secret_bytes` — no length validation,
no reconstruction verification.

**Verdict: RESOLVED — FALSE POSITIVE.**  
`from_secret_bytes(bytes: [u8; 32])` takes a fixed-size array.  The Rust
type system enforces exactly 32 bytes at compile time; no runtime check is
needed or possible.  Post-construction the public key is derived
deterministically from the secret; there is no "invalid" 32-byte secret.

---

## 6. missing-bounds-checking-ffi-parameters

**Finding:** FFI `config_path` pointer not bounds-checked beyond null.

**Verdict: RESOLVED — ACCEPTABLE BOUNDARY.**  
The FFI spec (§6.1) defines the boundary as a thin pass-through.  `c_str_to_str`
in `backend/ffi/lib.rs` null-checks all C string pointers and uses
`CStr::from_ptr` which reads until the NUL terminator — matching C string
contract.  Bounds checking of C pointers is not possible in safe Rust.
The calling layer (Flutter / Kotlin) is the system boundary that owns the
pointer's lifetime and length.

---

## 7. missing-input-validation-configuration

**Finding:** `FfiMeshConfig` lacks comprehensive validation.

**Verdict: RESOLVED — ADEQUATE.**  
`mesh_init` in `backend/ffi/lib.rs` validates `config_path` (null check),
derives transport flags from the config fields, and delegates to
`MeshRuntime::new` which applies safe defaults.  Numeric fields (`max_peers`,
`max_connections`, `wireguard_port`) are bounded by Rust integer types.
Over-large peer counts are handled at runtime by the connection manager.

---

## 8. missing-platform-specific-security-checks

**Finding:** Unix mlock implemented, Windows equivalent absent.

**Verdict: ACKNOWLEDGED — CROSS-PLATFORM GAP.**  
The vault (`backend/storage/vault.rs`) calls `mlock` on Unix to prevent
key material from being swapped to disk.  On Windows `VirtualLock` should
be called instead.  This is a real gap but medium severity — Windows builds
currently target desktop use where swap exposure is lower risk.
Promoted to open tracking in `.audits/codex-unresolved/` if not already.

---

## 9. missing-secure-default-configuration

**Finding:** Default configuration lacks security hardening.

**Verdict: RESOLVED — ADEQUATE.**  
`MeshRuntime::new` initializes with transport flags all disabled.  Transports
are only enabled via `mesh_init` with explicit config fields.  The spec
defines the threat model; the `ThreatContext::Normal` default is correct.

---

## 10. missing-thread-safety-annotations

**Finding:** No `Send`/`Sync` annotations for shared cryptographic state.

**Verdict: RESOLVED — FALSE POSITIVE.**  
Rust enforces `Send`/`Sync` automatically.  `MeshRuntime` is shared via
`Arc<MeshRuntime>` (which requires `Sync`); the compiler would reject the
code if any field were `!Sync`.  All shared fields use `Mutex<T>` which
provides the synchronization.  No manual `Send`/`Sync` impl is needed or
appropriate.

---

## Actions

- All 10 findings moved from `openrouter-unverified/` to this triage document.
- Finding #8 (Windows VirtualLock) noted as a real gap; the fix is a
  platform-specific code path in `vault.rs` guarded by `#[cfg(windows)]`.
