# Missing Rate Limiting on Pairing Attempts

**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
The Mesh Infinity pairing flow lacks explicit rate-limiting on pairing attempts, which could allow attackers to perform brute-force attacks against weak PINs or attempt to flood the system with pairing requests.

## Location
Pairing flow across multiple files:
- `backend/pairing/handshake.rs`
- `backend/pairing/methods.rs`
- `backend/identity/pin.rs`
- Frontend pairing screens

## Current Implementation
While the PIN system includes exponential backoff (attempts 1-5 no delay, 6=30s, 7=2m, 8=10m, 9=1h, 10=24h, 11+=72h), there is no network-level or system-level rate limiting on pairing attempt frequency.

## Risk
- Brute-force attacks on weak PINs (especially 4-digit PINs)
- Resource exhaustion through pairing request flooding
- Potential to bypass PIN timing protections through parallel attempts
- Increased attack surface for adversaries

## Recommendation
1. Implement rate limiting at the network layer for pairing requests
2. Add per-peer and global pairing attempt counters with time windows
3. Consider implementing CAPTCHA or proof-of-work for high-frequency attempts
4. Log pairing attempt patterns for attack detection
5. Ensure rate limits are applied consistently across all pairing methods (QR, manual key, etc.)

## References
- SPEC.md §3.10 (App PIN)
- Brute-force protection best practices
- Rate limiting in authentication systems