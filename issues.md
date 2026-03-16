# Known Issues — Mesh Infinity

Independently verified findings only. Every item here was confirmed by a separate
verification agent reading the actual source lines, not just the description.
Unverified findings live in issues-unverified.md.
Last updated: 2026-03-15

---

## CRITICAL

### C4 — I2P transport allocates 4 GB heap buffer from untrusted 4-byte length prefix — OOM DoS
**File:** `backend/transport/i2p.rs:898-909`
**Verified at:** line 898 `u32::from_be_bytes(len_bytes) as usize`; line 903 `if total_len < 12 { return Err(...) }`; line 908 `let mut frame = vec![0u8; total_len]`. Only a minimum check exists; no maximum check.
**Scenario:** Any peer (trusted or untrusted) can send `[0xFF, 0xFF, 0xFF, 0xFF]` as a length prefix. The code checks `total_len < 12` but not `total_len > MAX`. The 4 GB allocation follows immediately. On any mobile device this is an instant OOM crash.
**Fix:** Add an upper bound check (e.g. `if total_len > 65_536 { return Err(...) }`) before the allocation.

### C1 — Unsafe `as` casts in event parsing throw silently on type mismatch
**File:** `frontend/lib/backend/event_models.dart:123, 132-133, 175, 187-188`
**Verified at:** lines 123 (`data['roomId'] as String`), 132, 133, 175, 187, 188
**Scenario:** If the backend emits a field as `null` or the wrong type (version mismatch, memory corruption, protocol change), the `as` cast throws `TypeError`. The catch-all in `_onMessage` swallows it and the event is silently lost. No user indication, no log entry.
**Fix:** Check type before casting: `if (data['roomId'] is! String) { /* log, return null */ }`.

### C2 — Background event isolate can die silently — UI goes permanently stale
**File:** `frontend/lib/backend/event_bus.dart:137-144`
**Verified at:** line 137 — `Isolate.spawn(..., errorsAreFatal: false)` with no `onError:` or `onExit:` listener.
**Scenario:** Any unhandled exception in the poll loop kills the isolate. No notification reaches the main isolate. No restart logic exists. All subsequent backend events are lost for the app session with no indication to the user.
**Fix:** Attach `onError:` and `onExit:` listeners. Restart the isolate on unexpected exit. Add a heartbeat so the main isolate can detect a hung isolate.

### C3 — Use-after-free: background isolate can poll freed context pointer
**File:** `frontend/lib/backend/event_bus.dart:153-160, 234-243`
**Verified at:** line 156 (`_isolate?.kill(priority: Isolate.immediate)`) — kill is not synchronous; line 243 (`Pointer<Void>.fromAddress(msg.contextAddress)`) — pointer is reconstructed with no lifetime guarantee.
**Scenario:** `stop()` kills the isolate and (elsewhere) calls `mesh_destroy(ctx)`. If the isolate is blocked inside an FFI call when the kill arrives, `mesh_destroy` may run before the FFI call returns. The Rust side is executing with freed memory. Undefined behaviour.
**Fix:** Signal the isolate to exit cleanly before destroying the context. Wait for confirmation that the isolate has left the FFI call before calling `mesh_destroy`.

---

## HIGH

### H8 — Key file permissions race window on non-Android write
**File:** `backend/auth/persistence.rs:921-946`
**Verified at:** line 921 `std::fs::write(self.key_path(), key)?` — creates file at process umask (typically 0644); line 946 `std::fs::set_permissions(..., 0o600)?` — narrows permissions afterward. Comments at lines 928-937 acknowledge the pattern.
**Scenario:** Between the two calls on a multi-user system, the plaintext key file is world-readable. Another process or user can read the key in this window.
**Fix:** Use `OpenOptions::new().mode(0o600).write(true).create_new(true)` to set permissions at creation, eliminating the window.

### H9 — TOCTOU on key existence check in `save()` — duplicate identity generation
**File:** `backend/auth/persistence.rs:706-724`
**Verified at:** line 706 `if self.key_exists() { ... } else { generate and store }` with no file lock or mutex protecting the sequence.
**Scenario:** Two concurrent threads both call `save()`. Both see `key_exists() == false`. Both generate different random keys and both call `store_key_bytes()`. Last write wins; the other key is silently discarded, producing an inconsistent identity.
**Fix:** Hold a file lock across the check-then-act sequence, or use an atomic create (O_CREAT | O_EXCL) so the second writer gets an error rather than silently overwriting.

### H10 — Non-atomic key+data write — inconsistent identity state on crash
**File:** `backend/auth/persistence.rs:706-777`
**Verified at:** line 722 `self.store_key_bytes(&k)?` writes/stores the key first; line 777 `std::fs::write(self.data_path(), &data)?` writes the data file second. If the process crashes or the data write fails after the key write, the keystore contains a key with no matching data file.
**Scenario:** On next launch, code finds the key but no data file → identity in an unrecoverable limbo state. Retrying will generate a different key, leaving the stored key orphaned forever.
**Fix:** Write the data file first (it has no sensitive standalone value). Only commit the key to the keystore once the data file is durably on disk. On failure, roll back by deleting the partial data file.

### H11 — Messages dropped silently when retry budget exhausts — no passive outbox fallback
**File:** `backend/core/mesh/routing.rs:339-361`
**Verified at:** lines 344-361 — when `should_retry()` returns false, only `ack_tracker.record_failed()` is called. No `enqueue_passive_fallback()` call exists in the retry-exhaustion path. `backend/service/mod.rs` lines 960-979 show the passive fallback is only enqueued on the **initial** `route_message()` failure.
**Scenario:** A message that initially routes but then exhausts all retries is silently discarded. The sender sees no error; the recipient never receives the message.
**Fix:** Call `enqueue_passive_fallback()` from the retry-exhaustion branch, the same way the service layer does for initial failures.

### H12 — Routing table accepts unvalidated neighbor reachability claims — graph poisoning
**File:** `backend/core/mesh/routing.rs:545-555`
**Verified at:** lines 545-555 — `RoutingTable::update_graph(peer, neighbors)` inserts the claimed neighbor edges directly via `self.graph.insert(peer, edges)` with no signature or challenge-response verification.
**Scenario:** A malicious peer announces it can reach any other peer in the network. The graph is poisoned to route messages through attacker-controlled hops, enabling traffic interception and deanonymization.
**Fix:** Do not accept reachability claims at face value. Require signed proofs of reachability (e.g., the claimed neighbor must co-sign the edge announcement) or limit graph updates to peers with a verified direct connection.

### H13 — No explicit timeout on Tor `connect()` — routing worker thread can block 30–60 s
**File:** `backend/transport/tor.rs:402-421`
**Verified at:** lines 402-421 — `tokio::task::block_in_place` wraps `handle.block_on(client.connect(...))` with no `tokio::time::timeout`. No timeout layer is visible. I2P sets explicit 10-second read/write timeouts; Tor does not.
**Scenario:** Connecting to an unreachable Tor onion address waits for the full circuit-build timeout (30–60 seconds on a slow network), blocking the routing worker thread during that window. All other message routing is stalled.
**Fix:** Wrap the `connect()` future in `tokio::time::timeout(Duration::from_secs(30), ...)`. Return an error if the timeout fires.

### H1 — Poisoned mutex cascade: any single panic permanently kills all FFI calls
**File:** `backend/ffi/lib.rs` — 33 confirmed instances of `.lock().unwrap()`
**Verified at:** lines 892, 953, 1086, 1228, 1269, 1272, 1350, 1400, 1516, 1550, 1662, 1711, 1747, 1788, 1879, 2018, 2069, 2133, 2195, 2269, 2331, 2390, 2446, 2506, 2590, 3673, 3701, 3762, 3820, 3912, 3933, 3961, 4128, 4133
**Scenario:** Any thread panic while holding the service mutex poisons it. Every subsequent `.lock().unwrap()` call on that mutex also panics — cascading across all FFI entry points. One bad network packet reaching a `.expect()` can make the entire backend permanently unreachable for the session. The safe pattern (`let Ok(g) = lock() else { ... }`) is already used correctly in a few places.
**Fix:** Replace every `.lock().unwrap()` with the safe `let Ok`/`else` pattern consistently.

### H2 — System RNG failure panics in FFI context
**File:** `backend/service/mod.rs:743, 753`
**Verified at:** line 743 (`fill(&mut bytes).expect("system RNG unavailable")`), line 753 (same pattern).
**Scenario:** If `getrandom` fails (entropy exhausted, OS failure), this panics inside an `extern "C"` function. Unwinding through FFI is undefined behaviour; in practice it aborts the process with no error message.
**Fix:** Return `Result` from these functions. Propagate entropy failure to the FFI boundary as a negative return code.

### H3 — Race condition: event arrives after ChangeNotifier is disposed
**File:** `frontend/lib/features/messaging/messaging_state.dart` and all other state files
**Verified at:** `dispose()` calls `_sub?.cancel()` (line 501); no `_disposed` guard exists on any `notifyListeners()` call.
**Scenario:** Stream subscription cancellation is asynchronous. An event can arrive between the cancel call and the subscription actually closing. `notifyListeners()` called on a disposed `ChangeNotifier` throws a framework assertion.
**Fix:** Set `bool _disposed = false`; assign `true` at the top of `dispose()`. Guard every `notifyListeners()`: `if (_disposed) return;`.

### H4 — Race condition: room deleted while message send is in-flight
**File:** `frontend/lib/features/messaging/messaging_state.dart:315-317`
**Verified at:** lines 315-317 — `_activeRoomId` is read on line 316 then used on line 317 with no local capture.
**Scenario:** A `RoomDeletedEvent` arriving between those two lines sets `_activeRoomId = null`. The bridge receives `null` as the room ID.
**Fix:** Capture `_activeRoomId` into a local at the top of `sendMessage`. Null-check the local. Pass only the local to the bridge.

### H5 — Network toggle desync: state only re-fetched on success
**File:** `frontend/lib/features/network/network_state.dart:268-279`
**Verified at:** lines 268-279 — re-fetch inside `if (ok)` block only.
**Scenario:** If the backend rejects a toggle, the UI is not corrected and shows the intended state rather than the actual backend state.
**Fix:** Re-fetch settings unconditionally after every toggle.

---

## RUST SAFETY

### RS1 — Unvalidated `Arc::from_raw` in `mesh_destroy` — double-free / use-after-free
**File:** `backend/ffi/lib.rs:1140-1165`
**Verified at:** line 1147 checks `MESH_STATE.is_none()`; line 1156 calls `Arc::from_raw(ctx as *const ...)` using the caller-provided pointer, NOT the stored pointer. No validation that `ctx` matches what `mesh_init` returned. MESH_STATE check and `Arc::from_raw` are not atomic (lock released before reconstruction).
**Scenario:** Calling `mesh_destroy` twice with the same pointer reconstructs an `Arc` from freed memory → double-free. Concurrent FFI calls can hold the Arc while `mesh_destroy` drops it → use-after-free.
**Fix:** Store the raw pointer value in `MESH_STATE`. Atomically swap to `None` and validate `ctx` matches before calling `Arc::from_raw`.

### RS2 — `slice::from_raw_parts` trusts caller-provided length without bounds validation
**File:** `backend/ffi/lib.rs:1003`
**Verified at:** line 999 checks `is_null()` only; line 1003 calls `slice::from_raw_parts(message.payload, message.payload_len)` with no further validation.
**Scenario:** Dart could pass a 10-byte buffer with `payload_len = 8192`. The null check passes; the slice construction succeeds; subsequent UTF-8 scanning reads 8,182 bytes past the buffer end. Out-of-bounds read, potential information disclosure or crash.
**Fix:** Document and enforce at the Dart bridge layer that `payload_len` must exactly match the allocated buffer size. Consider an additional sanity bound check in Rust.

### RS3 — Android Keystore exceptions discarded — opaque error string only
**File:** `backend/auth/keystore.rs:420-438`
**Verified at:** lines 420-438 — `exception_describe()` prints to logcat only (return value discarded); exception cleared; generic string `"Android keystore raised exception"` returned.
**Scenario:** Device locked, hardware unavailable, and user-wiped identity all produce the same error string. The Dart layer cannot provide appropriate UX for any of these.
**Fix:** Before clearing the exception, use JNI to call `Throwable.getClass().getName()` and `Throwable.getMessage()`. Include both in the error string.

### RS4 — Android key migration leaves plaintext key on disk if cleanup fails
**File:** `backend/auth/persistence.rs:504, 565`
**Verified at:** `let _ = std::fs::remove_file(self.key_path())` at both lines — error silently discarded. Function returns `Ok(())` regardless.
**Scenario:** After wrapping the identity key with Android Keystore hardware, the plaintext key file is deleted with `let _`. If deletion fails (permissions, busy filesystem), the plaintext key remains alongside the wrapped key. The migration reports success. The key now exists in two places — one unprotected by hardware.
**Fix:** Treat failed plaintext-key deletion as a hard error. Do not return `Ok` if cleanup failed.

### RS5 — `destroy()` is non-atomic — partial deletion leaves inconsistent state
**File:** `backend/auth/persistence.rs:834-848`
**Verified at:** `destroy()` calls `self.destroy_keyfile()?` then `std::fs::remove_file(self.data_path())?` in sequence with no tombstone or rollback.
**Scenario:** Step 1 destroys the hardware keystore entry. Step 2 fails to remove the data file. The identity is now in an irrecoverable state: the key is gone so the data cannot be decrypted, but the data file looks valid to the next launch, which tries to open it, fails to unwrap the key, and produces a confusing error.
**Fix:** Write a tombstone marker as the first step. Any state with a tombstone but no valid key is treated as "destroyed" regardless of what other files remain.

---

## PROTOCOL

### P1 — Tor bootstrap never called — Tor transport permanently unavailable
**File:** `backend/transport/tor.rs:204, 468-469`, `backend/service/settings.rs:20-24`
**Verified at:** `TorTransport::new()` returns `client: None`; `is_available()` returns `self.client.is_some()` (always false); `set_enable_tor()` only calls `self.transport_manager.set_tor_enabled(value)` with no bootstrap trigger; `bootstrap()` is defined at line 239 but never called anywhere in the codebase.
**Scenario:** Users who enable Tor alongside clearnet silently send all traffic over clearnet, believing they have Tor protection. Users who enable Tor and disable clearnet get `NoAvailableTransport` on every send. No error distinguishes "Tor failed to start" from "Tor is working".
**Fix:** Call `bootstrap()` when the user enables Tor. Surface bootstrap success/failure to the UI. Do not route any message as Tor-protected until `is_available()` returns true.

### P2 — Nonce counter wrapping causes keystream reuse after ~65K messages
**File:** `backend/crypto/message_crypto.rs:1192-1206`
**Verified at:** line 1197 uses `wrapping_add(1)` on 8-byte counter; lines 1202-1205 append 4 random bytes. In-code comment claims "2^32 random bytes means ~2^-32 collision chance even if the counter wraps" — this is incorrect.
**Scenario:** The 32-bit random component means the birthday collision probability reaches ~50% after approximately 2^16 = 65,536 messages sharing the same counter value. ChaCha20-Poly1305 nonce reuse allows full plaintext recovery: `C1 XOR C2 = P1 XOR P2`. A long-running node or server hits this within days.
**Fix:** Use a fully random 96-bit nonce per message (standard for single-key AEAD) or a counter that errors at max rather than wrapping. Never mix a wrapping counter with a short random component.

### P3 — Invalid pairing code silently generates a random peer ID
**File:** `backend/service/peers.rs:26`
**Verified at:** `peer_id_from_pairing_code(trimmed).unwrap_or_else(random_peer_id)` — parse failure silently substitutes a random identity.
**Scenario:** A malformed, expired, or wrong-version pairing code produces a random peer ID that is stored as a trusted peer. Two failed pairing attempts with the same legitimate peer create two different phantom identities in the peer store. A malicious peer can deliberately send bad codes to pollute the peer database.
**Fix:** Return an error on parse failure. Never silently substitute a random identity for a failed cryptographic verification.

### P4 — Trust level is monotonically non-decreasing — no downgrade or revocation path
**File:** `backend/auth/web_of_trust.rs:458-466`
**Verified at:** lines 461-465 use `max(existing_trust, attested_trust)` — trust can only increase. No downgrade path exists anywhere in the trust system.
**Scenario:** Once a peer's trust is raised, it can never be lowered by attestation. A single compromised trusted key can permanently elevate any peer it attests. There is no mechanism to revoke trust transitively after a trusted peer is discovered to be malicious.
**Fix:** Attestations must be able to carry negative endorsements. Trust level should be derived from the current full attestation set, not accumulated monotonically. Implement signed "distrust" attestations that override prior endorsements.

---

## MEDIUM

### M1 — `firstWhere()` throws and is caught silently
**Files:** `frontend/lib/features/messaging/screens/thread_screen.dart:48-55`, `frontend/lib/features/peers/peers_state.dart:54-60`
**Verified at:** both locations confirmed — `try { return list.firstWhere(...) } catch (_) { return fallback; }`.
**Scenario:** A deleted room or peer causes `firstWhere` to throw `StateError`, which the catch block silently replaces with `'Chat'` or `null`. A logic error is masked as a normal code path.
**Fix:** Use `.where(...).firstOrNull` with an explicit absent-case handler.

### M2 — Dropped/malformed events swallowed with no telemetry
**File:** `frontend/lib/backend/event_bus.dart:173-203`
**Verified at:** catch block at lines 198-203 discards all exceptions with no log.
**Scenario:** Any parse failure, type error, or unknown event type is silently discarded. In a security app, silent event loss means the user acts on stale state (wrong trust level, missing message, peer shown as online when offline).
**Fix:** Log discarded events to a debug buffer. Expose a drop counter in a diagnostics view during development.

### M3 — `nodeMode` integer not range-validated after deserialization
**File:** `frontend/lib/backend/models/settings_models.dart:33-34`
**Verified at:** `nodeMode: json['nodeMode'] as int? ?? 0` with no range check. `nodeModeLabel` handles 0/1/2 only, falls to `'Unknown'` for anything else.
**Scenario:** Backend emits `nodeMode: 999`. Stored without validation. UI shows "Unknown" but the integer 999 is live in state, potentially desyncing any backend logic dependent on the enum value.
**Fix:** Validate integer enums are within the expected range on deserialization. Treat out-of-range as a parse error.

### M4 — `pairingCode` null/empty-string distinction lost in deserialization
**File:** `frontend/lib/backend/models/settings_models.dart:42`
**Verified at:** `pairingCode: json['pairingCode'] as String? ?? ''` — `?? ''` collapses null and missing key to empty string.
**Scenario:** UI cannot distinguish "no pairing code configured" from "pairing code explicitly set to empty". Users may misread their pairing status.
**Fix:** Preserve `null` as `null`. Show distinct UI states ("Not configured" vs empty).

### M5 — Room ID injection (latent — not exploitable with current callers)
**File:** `backend/service/messaging.rs:287-320`
**Verified at:** `receive_message(peer_id, room_id: Option<&str>, text)` creates the room on-demand if it doesn't exist (lines 306-313). All current callers pass `room_id: None` (confirmed). No membership check if `room_id` is Some.
**Scenario:** Not exploitable today. If a future refactor passes a peer-controlled `room_id`, the sender can inject messages into arbitrary rooms including ones they are not a member of.
**Fix:** Remove the `room_id` parameter or add sender-membership validation before accepting a non-None value.

### M6 — mDNS peer discovery has no hard cap — high-frequency announcement causes memory growth
**File:** `backend/discovery/mdns.rs:87`, `backend/discovery/catalog.rs:31`
**Verified at:** `discovered_peers` HashMap has no size limit; `known_peers.extend(peers)` is unbounded. TTL eviction at 5 minutes provides partial mitigation but is not a substitute for a hard cap.
**Scenario:** A malicious mDNS responder announces 1 unique peer ID per second. After 5 minutes the first entries evict, but the attacker stays ahead by announcing faster. No enforcement prevents 1,000+ entries during a sustained attack.
**Fix:** Cap `discovered_peers` at a reasonable maximum. Drop new entries beyond the cap. Add per-source-IP rate limiting.

### M7 — `parse_peer_id_hex` fallback to all-zeros peer ID — collision across failed nodes
**File:** `backend/service/mod.rs:1017`
**Verified at:** line 1017 `parse_peer_id_hex(&state.settings.local_peer_id).unwrap_or([0u8; 32])`.
**Scenario:** If `local_peer_id` fails to parse (corrupt settings, version mismatch, empty string), the local peer ID silently becomes `[0u8; 32]`. DM room IDs derived from this collide across all nodes with the same failure mode, merging unrelated users' conversations.
**Fix:** Return an error rather than substituting all-zeros. Treat an unparseable local peer ID as a fatal configuration error requiring identity re-generation.

### M8 — No global cap on passive outbox — 200+ offline peers exhaust memory
**File:** `backend/service/mod.rs:1075-1080`
**Verified at:** line 350 `const MAX_PASSIVE_ENVELOPES_PER_PEER: usize = 64` — per-peer cap confirmed. `passive_outbox` HashMap has no total-entry or total-peer-count cap.
**Scenario:** 200 offline peers × 64 messages = 12,800 envelopes retained in memory. On mobile devices this can cause OOM pressure or app termination.
**Fix:** Add a global cap (e.g. 50 peer queues). Evict the least-recently-used queue when the cap is reached.

### M9 — Connection pool has no per-peer or total size limit — file descriptor exhaustion
**File:** `backend/transport/core_manager.rs:312-318`
**Verified at:** lines 312-318 `active_connections.entry(...).or_default().push(connection)` — no cap before insertion.
**Scenario:** A swarm of peers exhausts the process's file descriptor limit (Linux default `ulimit -n` 1024). All subsequent `connect()` calls fail.
**Fix:** Enforce a per-peer cap (e.g. 3) and a global total cap (e.g. 256). Close the oldest connection when either cap is reached.

### M10 — Concurrent `get_best_connection()` for same peer creates duplicate connections
**File:** `backend/transport/core_manager.rs:402-493`
**Verified at:** `get_best_connection()` has no per-peer mutex. Two concurrent callers both call `transport.connect()` and both call `track_connection()` — producing two live connections to the same peer.
**Scenario:** Doubled connections waste file descriptors (amplifying M9) and produce inconsistent quality measurements.
**Fix:** Take a per-peer mutex before the connect attempt, or check the pool for an existing live connection before dialing.

---

## FLUTTER UX / CORRECTNESS

### UF2 — `_finishProfiles()` ignores bridge return values — silent onboarding failure
**File:** `frontend/lib/onboarding/onboarding_screen.dart:352-390`
**Verified at:** lines 370-373 `setPublicProfile()` return value discarded; lines 377-380 `setPrivateProfile()` return value discarded; line 390 `widget.onComplete()` called unconditionally.
**Scenario:** If the backend rejects either profile call (name too long, backend unavailable), `onComplete()` fires and the user exits onboarding with an invalid profile. No error is shown.
**Fix:** Capture and check both return values. On failure, show an error and keep the user on the onboarding screen.

### UF4 — Message arrives before room is loaded — preview silently dropped
**File:** `frontend/lib/features/messaging/messaging_state.dart:481-489`
**Verified at:** `_updateRoomPreview()` iterates `_rooms`; if `roomId` not found, the list is recreated unchanged. `RoomUpdatedEvent` has a fallback that creates a missing room (lines 420-425); `MessageAddedEvent` does not.
**Scenario:** On cold start, a `MessageAddedEvent` fires before `loadRooms()` completes. The preview is silently discarded. The room appears stale until the next `loadRooms()` call.
**Fix:** In `_updateRoomPreview()`, if the room is not found, add a placeholder room entry so the preview is not lost.

### UF5 — Trust attestation silently skipped when `localPeerId` is empty
**File:** `frontend/lib/features/peers/screens/peer_detail_screen.dart:187-193`
**Verified at:** line 164 `localPeerId = settingsState.settings?.localPeerId ?? ''`; line 187 `if (localPeerId.isNotEmpty)` — guard blocks `attestTrust()` with no error feedback.
**Scenario:** If `localPeerId` is null or empty at the moment the user taps "Set Trust Level", the attestation is silently not sent. The sheet closes and the trust level appears updated in the UI but no change was sent to the backend.
**Fix:** Check `localPeerId` before opening the trust sheet. If empty, show an error dialog explaining the identity is not yet loaded. Do not show the option as available when it cannot succeed.

### UF6 — No guard against concurrent `loadRooms()` calls — double rebuild and data race
**File:** `frontend/lib/features/messaging/messaging_state.dart:199-222`
**Verified at:** `loadRooms()` has no `_loadingRooms` guard. `loadMessages()` (lines 240-249) uses a `_loadingMessages` flag for exactly this purpose — confirming the pattern is known and intentional for that method.
**Scenario:** Two rapid pull-to-refresh gestures trigger two concurrent calls. Both overwrite `_rooms` and `_activeRoomId`. Whichever finishes last wins; stale data from the earlier response may briefly appear.
**Fix:** Add `bool _loadingRooms = false`. Set it at the start of `loadRooms()`, clear it at the end. Return early if already loading — exactly as `loadMessages()` does.
