# Known Issues — Mesh Infinity

Independently verified findings only. Every item here was confirmed by a separate
verification agent reading the actual source lines, not just the description.
Unverified findings live in issues-unverified.md.
Last updated: 2026-03-27 (session 2)

## FIXED (v0.3 sprint)

- **C5** — WireGuard XOR → ChaCha20-Poly1305 AEAD
- **C6** — Independent session keys → X25519 DH shared secret
- **C4** — I2P 4GB OOM → 64KB frame cap
- **C1** — Unsafe `as` casts → `is` type checks (frontend)
- **C2** — Silent isolate death → auto-restart with rate limiting (frontend)
- **H14** — EncryptedPayload raw keys → actual ciphertext + key ID hash *(source file deleted in v0.3 rewrite)*
- **H19** — Backup serializes private key → BackupContents now holds contacts/rooms/messages only; identity keys never included (fixed 2026-03-27)
- **H1** — Poisoned mutex cascade → `.unwrap_or_else(|e| e.into_inner())`
- **H2** — RNG failure panics → `try_random_fill()` catch_unwind wrapper in ffi/lib.rs
- **H8** — Key file permissions race → `OpenOptions::mode(0o600)` *(source file deleted in v0.3 rewrite)*
- **H3** — Disposed ChangeNotifier → `_disposed` guard on all 5 state files (frontend)
- **H4** — Room deleted race → capture `_activeRoomId` into local before null-check
- **H5** — Network toggle desync → unconditional re-fetch (frontend)
- **H9** — TOCTOU key existence → try-load-first + O_CREAT|O_EXCL atomic create *(source file deleted in v0.3 rewrite)*
- **H10** — Non-atomic key+data write → write data before key *(source file deleted in v0.3 rewrite)*
- **H11** — Messages dropped on retry exhaust → passive outbox fallback *(source file deleted in v0.3 rewrite)*
- **H12** — Unvalidated routing claims → sequence + signature verification *(source file deleted in v0.3 rewrite)*
- **H13** — No Tor connect timeout → configurable 30s default *(source file deleted in v0.3 rewrite)*
- **H15** — Tor inbound unimplemented *(backend/transport/tor.rs deleted; transport layer rebuilt)*
- **H16** — Obfuscation TLS/XOR fallback *(backend/core/mesh/obfuscation.rs deleted; transport layer rebuilt)*
- **H17** — Traffic shaping wrong bucket sizes *(backend/core/mesh/obfuscation.rs deleted; transport layer rebuilt)*
- **H18** — Inner auth uses Ed25519 (non-deniable) → HMAC-SHA256 in message_encrypt.rs step1_authenticate
- **H20** — PreKeyBundles never published → preauth_x25519_public added to NetworkMapEntry; broadcast on pairing + pairing_hello; receive path updates contact's preauth_key
- **P5** — clearnet_fallback enforced at wrong layer → check transport_flags.clearnet before TCP delivery and outbox flush
- **M2** — Dropped events swallowed silently → _droppedEventCount counter + debugPrint logging
- **M3** — nodeMode not range-validated → clamp to 0 if not in [0,2]
- **M4** — pairingCode null/empty conflation → String? preserves null; UI guards with ?.isNotEmpty
- **M15** — Env-var overrides in prod → gated behind kDebugMode
- **M17** — Message has no auth_status field → MessageAuthStatus enum; Rust emits authStatus; ⚠ badge in MessageBubble
- **RS1** — Arc::from_raw double-free → N/A: mesh_destroy now uses Box::from_raw (v0.3 rewrite)
- **RS2** — slice::from_raw_parts unvalidated → N/A: source deleted in v0.3 rewrite
- **RS3** — Android keystore opaque errors → N/A: backend/auth/keystore.rs deleted in v0.3 rewrite
- **RS4** → already listed above
- **RS5** → already listed above
- **P2** — Nonce counter wrapping → hard limit at 2^48
- **P3** — Invalid pairing code → return error instead of random peer ID
- **P4** — Trust monotonic-increase → downgrades/revocation allowed
- **C7** — Signal sessions never active → X3DH auto-initiation wired into send path
- **C8** — Decryption failure shows raw bytes → fail-closed (error, never displayed)
- **C9** — Outbound returns plaintext on error → Signal-encrypts before routing
- **RS4** — Plaintext key left after migration → overwrite with random before delete *(source file deleted)*
- **RS5** — Non-atomic destroy → overwrite data with random before delete *(source file deleted)*
- **M12** — PFS keys not zeroized → `#[derive(Zeroize, ZeroizeOnDrop)]`
- **M13** — Identity keys in plain HashMap → `Drop` impl with zeroize
- **M1** — `firstWhere()` throws silently → safe `where(...).first` pattern
- **M5** — Room ID injection → `is_valid_room_id()` format validator
- **M6** — mDNS no hard cap → 1000 peer cap with oldest-eviction
- **M8** — No passive outbox cap → 10,000 global cap with drain
- **M9** — Connection pool unlimited → per-peer (3) and total (100) limits
- **M10** — Duplicate connections → `connecting_peers` in-flight tracking
- **M11** — Revocation never gossiped → `broadcast_revocation()` on revoke
- **M14** — Clearnet enabled by default → disabled (privacy-first)
- **M16** — Capability flags missing → added to PeerModel
- **UF2** — `_finishProfiles()` ignores errors → checks + shows SnackBar
- **UF4** — Message before room loaded → auto-create placeholder room
- **UF5** — Trust skipped on empty localPeerId → shows error SnackBar
- **UF6** — Concurrent loadRooms → `_loadingRooms` guard flag
- **C3** — Use-after-free: isolate polls freed context → cooperative stop flag (`calloc<Int32>` native flag, async `stop()` awaits isolate exit before `mesh_destroy`) (fixed 2026-03-27)
- **P1** — Tor bootstrap never called → N/A: `backend/transport/tor.rs` deleted in v0.3 rewrite
- **M7** — `parse_peer_id_hex` fallback to all-zeros → N/A: `backend/service/mod.rs` deleted in v0.3 rewrite

---

## OPEN ISSUES

All tracked findings have been resolved or marked N/A (source files deleted in v0.3 rewrite).
See the FIXED section above for full disposition of each finding.

New findings will be added here as they are discovered.
