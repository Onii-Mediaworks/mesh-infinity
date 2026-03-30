# Missing Cryptographic Constants Documentation
**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
The cryptographic implementation in `backend/crypto/primitives.rs` uses several important constants that are critical to the protocol's security properties but lack comprehensive documentation:
- `CHAIN_MSG_KEY_INPUT` (line 30) - HMAC input byte for deriving message keys
- `CHAIN_ADVANCE_INPUT` (line 37) - HMAC input byte for advancing chain keys
- `ZERO_SALT` (line 46) - Zero-byte salt for HKDF operations

These constants follow Signal Protocol conventions but are only briefly mentioned in comments. The lack of detailed documentation makes it difficult to verify their correct usage and could lead to implementation errors.

## Resolution  (fill in when resolved)
<what was changed and where>