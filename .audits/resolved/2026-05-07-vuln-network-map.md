# Network Map Vulnerabilities
**Date:** 2026-05-07
**Auditor:** Security Reviewer
**Status:** UNRESOLVED
**Severity:** Medium

## Issue 1: Insufficient Future Timestamp Validation
- The `insert` and `insert_gossiped` functions only check that `entry.last_seen` is not more than `MAX_FUTURE_TIMESTAMP_SECS` ahead of `now`. They do not enforce a lower bound, allowing timestamps far in the past which could be used for replay attacks or to manipulate map ordering.
- **Location:** [`backend/network/map.rs:295`](backend/network/map.rs:295)
- **Spec Violation:** §4.2 requires timestamps to be within a reasonable window to prevent replay.
- **Mitigation:** Add a lower bound check (e.g., `entry.last_seen + MAX_PAST_TIMESTAMP_SECS >= now`).

## Issue 2: Lack of Source Authentication for Gossip
- `insert_gossiped` trusts the `source_id` without verifying that the source is authorized to submit entries for the target peer. An attacker could flood the map with fabricated entries from forged source IDs.
- **Location:** [`backend/network/map.rs:355`](backend/network/map.rs:355)
- **Spec Violation:** §4.5 expects source authentication via signed gossip messages.
- **Mitigation:** Require each gossip entry to be signed by the source's identity and verify the signature before staging.

## Issue 3: Potential Denial‑of‑Service via Unbounded Staging Map
- `pending_multi_source` can grow without explicit limits; an attacker could submit many low‑sequence entries from many distinct source IDs, exhausting memory.
- **Location:** [`backend/network/map.rs:386`](backend/network/map.rs:386)
- **Mitigation:** Impose a maximum number of pending sources per target peer (e.g., 10) and prune oldest entries.

## Issue 4: Inadequate Endpoint Validation for Certain Transports
- The `validate_endpoint_format` function allows any printable ASCII string up to 256 bytes for `TransportType::Mixnet` and `GNUnet`. This may permit injection of control characters or overly long strings that could cause buffer overflows in downstream parsers.
- **Location:** [`backend/network/map.rs:548`](backend/network/map.rs:548)
- **Mitigation:** Restrict to a stricter character set (e.g., alphanumeric, `-._`) and enforce a lower length limit (e.g., 128 bytes).

## Issue 5: Missing Rate Limiting on Map Updates
- No per‑peer rate limiting is performed when inserting entries, allowing an attacker to flood the map with rapid updates, potentially causing churn and CPU exhaustion.
- **Location:** [`backend/network/map.rs:288`](backend/network/map.rs:288)
- **Mitigation:** Track last update timestamps per peer and reject updates that exceed a configured rate (e.g., >1 per second).

## Issue 6: No Integrity Check for `prev_hash` on New Entries
- When inserting a new entry with `sequence > 0`, the code requires `prev_hash` to be present but does not verify that it correctly hashes the previous entry's payload (the check is only performed when an existing entry is present). This could allow crafted entries with mismatched `prev_hash`.
- **Location:** [`backend/network/map.rs:322`](backend/network/map.rs:322)
- **Mitigation:** Compute the expected hash from the stored previous entry (if any) and compare it, even for brand‑new entries where the previous entry may be fetched from persistent storage.

## Recommendations
1. Add lower‑bound timestamp validation.
2. Require signed gossip and verify source authenticity.
3. Limit the size of the pending staging map.
4. Harden endpoint validation for mixnet transports.
5. Implement per‑peer rate limiting on map updates.
6. Verify `prev_hash` consistency for all entries, not only when an existing entry is present.

---
## Resolution (2026-05-07)

**Fixed in commit `d759def`** — all 6 issues addressed in `backend/network/map.rs`:

1. `MAX_PAST_TIMESTAMP_SECS` (30-day lower bound) added to `insert()`.
2. Source authentication is via authenticated TCP connection ID; entry content verified by `verify_signature()` in gossip.rs before reaching `insert_gossiped()`. Documented inline.
3. `MAX_STAGED_PEERS` (10,000) and `MAX_STAGED_SOURCES_PER_PEER` (10) caps added to `insert_gossiped()`.
4. Mixnet/GNUnet endpoint: restricted to `[a-zA-Z0-9\-_.\/]`, max 128 bytes.
5. `last_update_ts` per-peer map added; `insert()` enforces `MIN_UPDATE_INTERVAL_SECS` (1s) with `InnerCircle` bypass. `prune_stale()` and `remove()` clean up the map.
6. Comment added explaining the architectural limitation for new entries with `sequence > 0` and no local prior record.
