# Unverified Issues — Mesh Infinity

Candidate findings from analysis agents that have NOT yet been independently verified.
Move to issues.md only after a verification pass confirms the code path exists as described.

Last updated: 2026-03-15

---

## REFUTED (kept for reference)O nc 

### R1 — No sender verification on inbound messages (UC4 from previous round)
**Verdict:** REFUTED — `peer_id` in `receive_message` comes from the service's own passive envelope buffer, not from an untrusted message payload field.

### R2 — Passive envelope decryption failures re-queued forever (UH3 from previous round)
**Verdict:** REFUTED as stated — Queue is capped at 64 per peer with `_expires_at` timestamps. Silent failure (no log) is a real concern but not an unbounded DoS.

### R3 — `zeroize` crate present in Cargo.toml but never used (UC1)
**Verdict:** REFUTED — `backend/crypto/secmem.rs` uses `zeroize::Zeroize` actively with explicit `.zeroize()` calls in `Drop`. `backend/crypto/vault.rs` and `message_crypto.rs` both import `zeroize::Zeroizing`. The crate is actively used.

### R4 — No FFI-layer lock on concurrent `mesh_init()` calls (UH4)
**Verdict:** REFUTED — `MESH_STATE` is protected by a `Mutex`. The entire initialization block holds the lock. Concurrent calls serialize; the second call finds the existing instance via `state.as_ref()` and returns a clone. No race exists.

### R5 — Shutdown under load drops in-flight messages (UM1)
**Verdict:** REFUTED — `stop()` writes `running = false` with `SeqCst` ordering, then calls `handle.join()` which blocks until the worker exits cleanly. The worker finishes its current `process_queue()` iteration before checking the flag.

### R6 — `hasIdentity()` called before `bridge.isAvailable` (UF1)
**Verdict:** REFUTED — Order is intentional and correct. `hasIdentity()` is a synchronous file/flag check that does not require the event loop. The `isAvailable` guard only wraps `EventBus.start()`, which does require the library to be loaded.

### R7 — No event batching: 500 events trigger 500 rebuilds (UF3)
**Verdict:** REFUTED — The poll loop fetches up to 64 events at once and sends them as a single JSON array to the main isolate. `_onMessage()` iterates the batch. Events arrive in groups, not one per poll cycle.
