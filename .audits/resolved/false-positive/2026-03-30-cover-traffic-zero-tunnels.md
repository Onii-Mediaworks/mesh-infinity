## Resolution Status: FALSE POSITIVE

# Cover Traffic Zero Tunnel State Risk

**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
In `backend/network/security_policy.rs`, the `cover_traffic_for_state` function for `ExplicitDisconnect` sets `target_tunnels_min = 0`, which could allow accidental zero-tunnel states if the state transition is mishandled.

## Location
File: `backend/network/security_policy.rs`
Function: `cover_traffic_for_state`
State: `ExplicitDisconnect`

## Current Implementation
The function sets `target_tunnels_min = 0` for the `ExplicitDisconnect` state, which would eliminate cover traffic requirements when transitioning to this state.

## Risk
- Loss of cover traffic violates the invariant that cover traffic is never zero while connected
- Could expose network activity patterns to observers
- May violate threat model requirements for maintaining cover traffic

## Recommendation
1. Ensure that `ExplicitDisconnect` state transitions only occur after explicit user-initiated disconnect
2. Add defensive checks to prevent `target_tunnels_min` from dropping to 0 without proper validation
3. Maintain cover traffic requirements until the user explicitly confirms disconnect
4. Add unit tests to verify that cover traffic is maintained during state transitions

## References
- SPEC.md §15.5 (Cover Traffic)
- Threat model requirements for maintaining network cover
- State transition invariants