## Resolution Status: RESOLVED

# Nonce Overflow Risk in WireGuard Implementation

**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
In `backend/transport/wireguard.rs`, the `WireGuardSession::encrypt` function does not handle nonce overflow when `u64::MAX` is reached. This could lead to nonce reuse, which compromises forward secrecy and could allow attackers to decrypt messages.

## Location
File: `backend/transport/wireguard.rs`
Function: `WireGuardSession::encrypt`

## Current Implementation
The WireGuard session uses a monotonically increasing nonce for encryption but lacks checks for when the nonce counter reaches its maximum value (`u64::MAX`). When this happens, the nonce would wrap around to zero, causing nonce reuse.

## Risk
Nonce reuse in ChaCha20-Poly1305 encryption can lead to:
- Loss of confidentiality
- Potential plaintext recovery attacks
- Compromise of forward secrecy

## Recommendation
1. Add explicit session renegotiation logic before nonce overflow occurs
2. Implement a hard limit (e.g., 2^40 packets) with automatic key rotation
3. When approaching the limit, initiate a rekeying process similar to the existing 7-day rotation
4. Ensure both peers synchronize on the rekeying to prevent communication disruption

## References
- SPEC.md §5.2 (WireGuard — Primary Per-Hop Link Encryption)
- RFC 8471 (WireGuard: Next Generation Kernel Network Tunnel)
- Best practices for nonce management in stream ciphers