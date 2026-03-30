# Missing Challenge Message Size Validation in Pairing Handshake

**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
In `backend/pairing/handshake.rs`, there is no validation of `ChallengeMessage` size before processing. This could allow attackers to send oversized payloads, potentially leading to denial-of-service through excessive memory allocation or processing time.

## Location
File: `backend/pairing/handshake.rs`
Functions: Processing of `ChallengeMessage` in the Sigma protocol handshake

## Current Implementation
The code processes incoming `ChallengeMessage` without checking its size against reasonable limits, allowing potentially large payloads to be processed.

## Risk
- Denial-of-service through memory exhaustion
- Denial-of-service through excessive CPU usage
- Potential buffer overflow if size checks are missing in deserialization
- Resource exhaustion attacks

## Recommendation
1. Add explicit size validation for `ChallengeMessage` before processing
2. Define a reasonable maximum size based on protocol requirements
3. Return an error for messages exceeding the maximum size
4. Consider adding similar size checks for other message types in the pairing flow
5. Log oversized message attempts for attack detection

## References
- SPEC.md §3.5.4 (Sigma Protocol — Zero-Knowledge Proof of Key Possession)
- Input validation best practices
- DoS prevention in network protocols