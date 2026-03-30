## Resolution Status: RESOLVED
# No Message ID Deduplication — Delivered Messages Can Be Replayed
**Date:** 2026-03-29
**Auditor:** claude-sonnet-4-6
**Status:** UNRESOLVED
**Severity:** High

## Issue

`backend/messaging/delivery.rs` implements a delivery state machine but contains no
per-message deduplication: there is no set of seen `msg_id` values that would reject a
previously-delivered message.

`backend/ffi/lib.rs:1918` (`process_inbound_frame`) accepts inbound messages by
decrypting them and pushing to the store. It dispatches on `type` field but does NOT
check whether the `msg_id` has already been delivered.

The Double Ratchet in `double_ratchet.rs:72` provides a `DuplicateMessage` error for
duplicate ciphertext within an active session — but this protection is lost if:
1. The DR session snapshot is loaded from vault after a restart (the in-memory state
   resets, so old message numbers may be re-processed).
2. A relay node replays a captured clearnet frame after a session reload.

The `DeduplicationCache` in `backend/routing/loop_prevention.rs` is for routing
packet deduplication (announcement IDs), NOT message content.

The delivery receipt in the spec (§7.3) is noted as authenticated, but the inbound
processing path does not verify receipts against a stored set of delivered IDs.

## Resolution
*(fill in when resolved)*

Maintain a per-room delivered-message-ID set (bounded LRU or bloom filter, persisted in
vault) keyed by `msg_id`. In `process_inbound_frame`, after extracting `msg_id` from
the envelope, check the set before decrypting. If the ID is already present, discard
silently. Add the ID after successful decryption and storage. Size the LRU to at least
10,000 entries per room to cover normal usage.
