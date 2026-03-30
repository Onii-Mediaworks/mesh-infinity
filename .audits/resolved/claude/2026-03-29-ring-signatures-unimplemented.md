## Resolution Status: RESOLVED

# AOS Ring Signatures Claimed Implemented But Missing Entirely
**Date:** 2026-03-29
**Auditor:** claude-sonnet-4-6
**Status:** UNRESOLVED
**Severity:** High

## Issue

`backend/crypto/lib.rs:10` lists "AOS ring signatures (§3.5.2)" in the module docstring
as an implemented feature.

`backend/groups/group.rs:184` returns `true` from `uses_ring_signatures()` for Private
and Closed group types.

Tests at `backend/groups/group.rs:564–567` assert `uses_ring_signatures()` returns true
for Private/Closed groups.

However, a full-codebase search for `ring_sign`, `ring_verify`, `lsag`, `aos_ring`,
or `ring_sig` in production code returns ZERO results. The ring signature functions
do not exist.

This means:
1. Private and Closed groups send messages WITHOUT the membership-deniability property
   that the spec requires. Member identities are exposed to routing nodes.
2. The module docstring is a false security claim.
3. Tests at lines 564–567 test only a boolean flag, not any cryptographic property.
   This is a Standard 2 violation (tests must represent the threat model).
4. AGENTS.md explicitly prohibits stubs and non-functional code.

## Resolution
*(fill in when resolved)*

Implement LSAG (Linkable Spontaneous Anonymous Group) signatures as the AOS variant
specified in §3.5.2. Until implemented:
- Remove "AOS ring signatures (§3.5.2)" from the `backend/crypto/lib.rs` module docstring.
- Have `uses_ring_signatures()` return `false` unconditionally until the implementation lands.
- Replace the useless boolean tests with tests that verify actual ring-sign/verify
  round trips once implemented.
