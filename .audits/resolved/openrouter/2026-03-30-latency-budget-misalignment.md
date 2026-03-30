## Resolution Status: RESOLVED
# Latency Budget Misalignment in Security Policy

**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Low

## Issue
In `backend/network/security_policy.rs`, the `stream_latency_ceiling` function returns 100ms for both `RemoteDesktop` and `ScreenShare` activity types, but the SPEC.md requires 100ms only for `RemoteDesktop`. `ScreenShare` should have a different latency ceiling according to the specification.

## Location
File: `backend/network/security_policy.rs`
Function: `stream_latency_ceiling`

## Current Implementation
```rust
match self {
    ActivityType::RemoteDesktop => 100,
    ActivityType::ScreenShare => 100,  // Should be different per spec
    // ...
}
```

## Risk
- Incorrect latency ceiling could affect transport selection
- May violate timing guarantees specified in SPEC.md
- Could lead to suboptimal performance or security tradeoffs

## Recommendation
1. Review SPEC.md to determine the correct latency ceiling for `ScreenShare`
2. Update the function to return the spec-compliant value
3. Add unit tests to ensure these values remain correct
4. Consider making these configurable per deployment while maintaining minimum security standards

## References
- SPEC.md §16.9 (Message Delivery Latency Optimisation)
- SPEC.md §16.10 (Real-Time Stream Performance)
- Network security policy requirements