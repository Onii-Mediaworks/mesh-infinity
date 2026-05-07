# Mesh Infinity — Implementation Plan

**Date:** 2026-05-07  
**Spec:** v1.5  
**Last commit:** `d759def` — all top-priority network-map security fixes landed.

This plan covers every remaining spec gap, unimplemented feature, and open
audit item, ranked by risk tier.  Each item references the relevant spec
section and the exact files that need work.

---

## Tier 1 — Security / Correctness Blockers

These are implementation gaps that directly affect security or protocol
correctness.  Nothing in Tier 2 or 3 should be started until Tier 1 is clear.

---

### T1-A  Key-clearing atomicity (`clear_identity_keys`, §3.6.4)

**Problem:** The spec requires a single idempotent `clear_identity_keys()`
function guarded by an `AtomicBool`, called by BOTH the screen-lock path and
the PIN-timeout path.  Two separate clearing calls without a mutex/once guard
create a TOCTOU window where both triggers fire concurrently and one clears
partially-zeroed state while the other re-derives.  No such function currently
exists.

**Files:**
- `backend/service/identity_ops.rs` — add `clear_identity_keys(&self)` with
  `AtomicBool` guard; call it from both `lock_screen()` and the timeout handler.
- `backend/service/runtime.rs` — add `identity_clear_in_progress: Arc<AtomicBool>` field.

**Acceptance criteria:**
- Single function, single `AtomicBool.compare_exchange`, zeroizes all key
  material in `SelfIdentity` and clears `self.identity`.
- Called by screen-lock and by the PIN-timeout path.
- Unit test: concurrent calls from two threads; verify keys cleared exactly
  once.

---

### T1-B  Onboarding: required security controls (§22.27, §3.6.4)

**Problem:** Onboarding PIN step is missing:
1. "Require PIN after phone lock" checkbox (default: **enabled**).
2. Timeout selector (e.g., 1 min / 5 min / 15 min / always).
3. Double-confirmation "Skip" path with explicit risk disclosure.

Without these controls, a user who completes onboarding has no screen-lock
protection on Layer 2/3 key material and is not told.

**Files:**
- `frontend/lib/onboarding/onboarding_screen.dart` — add PIN security step
  with lock-after checkbox, timeout dropdown, and risk-disclosure skip path.
- `backend/ffi/lib.rs` / `backend/service/identity_ops.rs` — confirm
  `set_security_config()` persists `requirePinAfterLock` and `lockTimeoutSecs`.

**Acceptance criteria:**
- `mi_set_security_config` called during onboarding with `requirePinAfterLock`
  and `lockTimeoutSecs` fields.
- "Skip" requires two deliberate taps; risk disclosure shown on first tap.
- `flutter analyze` passes with no issues.

---

### T1-C  Android Wi-Fi Direct: Rust-owned socket lifecycle (§5.8)

**Problem:** The Wi-Fi Direct session socket/listener lifecycle is owned by
Kotlin (`AndroidProximityBridge.kt`), not Rust.  The spec requires Rust to be
the security boundary.  Kotlin currently holds the `ParcelFileDescriptor`; the
fd-ownership handoff into Rust is incomplete.

**Files:**
- `backend/transport/wifi_direct.rs` — complete `WifiDirectSession` with full
  Rust-owned read/write/close lifecycle over the adopted fd.
- `backend/service/android_proximity_ops.rs` — replace Kotlin-delegated I/O
  with Rust-driven `adopt_fd_socket()` calls.
- `platforms/android/.../AndroidProximityBridge.kt` — Kotlin role reduced to:
  platform lifecycle events (group started/stopped, peer connected) + raw fd
  handoff via `nativeAdoptWifiDirectFd()`.  No session I/O remains in Kotlin.

**Acceptance criteria:**
- `WifiDirectSession::send()` and `recv()` operate on the Rust-owned fd.
- Kotlin unit test verifies fd is handed off and closed by Rust.

---

### T1-D  Android NFC: fully backend-driven loop (§5.9)

**Problem:** NFC outbound and inbound data loop is queue-handoff only.  Kotlin
owns the NDEF read/write cycle; Rust does not drive the transport lifecycle.

**Files:**
- `backend/transport/nfc.rs` — add `NfcTransport::run_rw_cycle()` driven
  entirely from Rust; Kotlin calls `nativeNfcBytesReceived()` on inbound and
  polls `nativeNfcRequestSend()` for queued outbound bytes.
- `platforms/android/.../AndroidProximityBridge.kt` — limit NFC role to
  platform callbacks; remove Kotlin-side message framing.

**Acceptance criteria:**
- Integration test: Rust encodes a pairing payload, Kotlin simulates NDEF read
  event, Rust completes the pairing flow without Kotlin framing.
- Repeat-cycle test added to `backend/tests/simulation/`.

---

### T1-E  App Connector selector enforcement (§17.5)

**Problem:** `domain_pattern`, `ip_range`, and `port` selector rules are stored
but not enforced against routed packets.  `RouteViaMesh` decisions are computed
but the packet is never forwarded into the mesh data plane.

**Files:**
- `backend/vpn/app_connector.rs` — complete `evaluate_packet()` to enforce
  `domain_pattern` (hostname suffix match), `ip_range` (CIDR), and `port`
  selectors; return `RouteDecision`.
- `backend/service/transport_ops.rs` — wire `evaluate_packet()` into the VPN
  tun packet loop so `RouteViaMesh` packets are forwarded.
- `platforms/android/.../AndroidAppConnectorVpnService.kt` — pass raw IP
  packets from `ParcelFileDescriptor` through `nativeEvaluatePacket()`.

**Acceptance criteria:**
- Unit tests for each selector type (domain, CIDR, port, combined).
- `fuzz_ffi_json_inputs` extended with App Connector selector payloads.

---

## Tier 2 — Protocol Completeness

These gaps mean the product does not yet deliver full spec-defined behaviour,
but do not expose immediate security holes.

---

### T2-A  Deniable carrier ladder (§5.26, §5.27)

**Problem:** Current obfuscation (`backend/transport/obfuscation.rs`) is
`Scramble` (XOR) and `Pad` (fixed sizes) — trivially identified by DPI.  The
spec requires a full deniable carrier ladder when `ThreatContext >= Elevated`.

| Ladder rung | Protocol | Status |
|---|---|---|
| Primary | QUIC masquerading as HTTP/3 | MISSING |
| Fallback 1 | XMPP (chat traffic camouflage) | MISSING |
| Fallback 2 | DNS (covert subdomain encoding) | MISSING |
| Fallback 3 | Email (SMTP/IMAP header steganography) | MISSING |
| Fallback 4 | Steganographic media | MISSING |
| Passive assist | Relay-only, no active sends | MISSING |

**Files:**
- `backend/transport/obfuscation.rs` — add `CarrierLadder` struct; implement
  `QuicHttp3Carrier`, `XmppCarrier`, `DnsCarrier` as the first three rungs.
- `backend/transport/solver.rs` — wire `ThreatContext::Elevated` → carrier
  selection via `CarrierLadder::select()`.
- `backend/transport/passive_assist.rs` (new) — relay-only mode: node
  participates in routing but sends no traffic from its own address.

**Acceptance criteria:**
- `ThreatContext::Elevated` routes outbound through `QuicHttp3Carrier`.
- Test capture shows QUIC/UDP traffic only (no plaintext TCP).
- Carrier fallback ladder exercised by integration test.

---

### T2-B  Offline transport bundle (§5.28)

**Problem:** `PhysicalTransferHeader` (for QR-code / USB / SD-card offline
bundles) not implemented.

**Files:**
- New `backend/transport/offline_bundle.rs` — `OfflineBundle` struct with
  `PhysicalTransferHeader`, encrypt-for-recipient, and decode paths.
- `backend/ffi/lib.rs` — expose `mi_create_offline_bundle()` and
  `mi_import_offline_bundle()`.

**Acceptance criteria:**
- Round-trip test: encode bundle for a recipient, decode and verify message
  contents intact.
- Fuzz target `fuzz_offline_bundle_decode` added.

---

### T2-C  Bootstrap source diversity / anti-eclipse (§4.1, §4.3)

**Problem:** New node bootstrap queries a single directory source.  The §4.1
multi-source requirement is enforced at *insert* time (already fixed), but the
*query* layer does not yet enforce "query ≥3 independent directory sources".

**Files:**
- `backend/network/gossip.rs` — `bootstrap()` must query at least 3
  independent directory nodes when the map has ≥100 entries.
- `backend/service/transport_ops.rs` — feed bootstrap responses through
  `insert_gossiped()` with respective source peer IDs.

**Acceptance criteria:**
- Integration test: fresh node, 3 bootstrap directory responses, verify all
  3 source IDs registered in `pending_multi_source` before any promotion.

---

### T2-D  Overlay client parity — Tailscale / ZeroTier (§5.5)

**Problem:** Auth-completion and data-plane forwarding are incomplete for both
Tailscale/Headscale and ZeroTier.

**Files:**
- `backend/transport/tailscale.rs` — complete auth-key exchange and data-plane
  receive loop.
- `backend/transport/zerotier.rs` — complete join-network and data-plane
  receive loop.
- `backend/service/transport_ops.rs` — wire both into `TransportManager`.

**Acceptance criteria:**
- Headscale integration test: node joins, receives ping, event emitted.
- ZeroTier integration test: node joins, packet forwarded.

---

### T2-E  Plugin runtime — remove legacy `invoke_hook()` (§18)

**Problem:** `invoke_hook()` in `backend/services/plugin.rs` is metadata-only
(no WASM execution).  The sandboxed path is functional.  The legacy path should
not exist.

**Files:**
- `backend/services/plugin.rs` — remove `invoke_hook()`; route all callers to
  `invoke_hook_sandboxed()`.
- `backend/ffi/lib.rs` — update any call sites.

**Acceptance criteria:**
- Zero references to `invoke_hook(` (non-sandboxed) remain after the change.
- `cargo check` clean.

---

### T2-F  Duress PIN: 60–120 s mesh-identity wind-down (§3.9.2)

**Problem:** `duress_erase()` wipes identity immediately.  The spec requires a
60–120 s gradual wind-down: the node continues routing Layer 1 traffic under
the old identity to provide plausible deniability, then performs final wipe.

**Files:**
- `backend/identity/killswitch.rs` — add `DuressWindDown` state; continue
  forwarding Layer 1 traffic for 60–120 s before `complete_wipe()`.
- `backend/service/identity_ops.rs` — wire `duress_erase()` into the
  wind-down path.

**Acceptance criteria:**
- Test: after `duress_erase()`, node emits Layer 1 frames for ≥60 s, then all
  key material is zeroed and `identity` is `None`.

---

### T2-G  Remote killswitch: Level 8 trust gate (§3.9.3)

**Problem:** Remote killswitch handling does not verify the requesting peer is
`TrustLevel::InnerCircle` (Level 8) before wiping.

**Files:**
- `backend/service/identity_ops.rs` — add trust-level check before executing
  remote killswitch; return `Err` for anything below `InnerCircle`.

**Acceptance criteria:**
- Test: killswitch command from Level 5 peer → rejected.
- Test: killswitch command from Level 8 peer → accepted.

---

### T2-H  Cloud backup passphrase minimum length (§3.7.4)

**Problem:** `create_backup()` does not enforce the spec-required minimum
16-character passphrase.

**Files:**
- `backend/crypto/backup.rs` — reject passphrases shorter than 16 characters.
- `backend/ffi/lib.rs` — propagate error to Flutter with a clear message.

**Acceptance criteria:**
- Unit test: 15-char passphrase → `Err`; 16-char passphrase → `Ok`.

---

## Tier 3 — Testing / Infrastructure

These gaps do not block production correctness but violate the testing
methodology and prevent confident refactoring.

---

### T3-A  Stateful simulator: missing scenarios

**Problem (codex audit `2026-03-31`):** `SimulatorAction::DisavowPeer` maps
to `partition_primary_link()` instead of the real trust-revocation state
machine.  Kill-switch action has no post-wipe invariant assertions.

**Files:**
- `backend/testing/sim.rs` — fix `DisavowPeer` to call `revoke_trust()`; add
  invariant assertions to kill-switch action.
- `backend/tests/simulation/` — add scenario files:
  - `store_and_forward_delivery.rs`
  - `trust_disavow_propagation.rs`
  - `kill_switch_wipe.rs`
  - `transport_toggle_under_load.rs`
  - `restart_reload_vault.rs`

**Acceptance criteria:**
- All new scenarios run under `cargo test`.
- `fuzz_network_sim_actions` exercises the new action variants.

---

### T3-B  Missing fuzz targets (TESTING_METHODOLOGY.md)

Three external-byte-boundary paths have no fuzz coverage:

| Target | Path | Priority |
|---|---|---|
| `fuzz_gossip_entry` | `map.rs::insert_gossiped` | HIGH |
| `fuzz_sphinx_packet` | `transport/mixnet.rs` Sphinx parse | HIGH |
| `fuzz_store_forward` | `routing/store_forward.rs` deposit/release | MEDIUM |

**Files:**
- `fuzz/fuzz_targets/fuzz_gossip_entry.rs`
- `fuzz/fuzz_targets/fuzz_sphinx_packet.rs`
- `fuzz/fuzz_targets/fuzz_store_forward.rs`
- `fuzz/targets.toml` — register all three.
- `fuzz/Cargo.toml` — add harness entries.
- `.github/workflows/nightly-quality.yml` — add all three to nightly campaign.

**Acceptance criteria:**
- `cargo check --manifest-path fuzz/Cargo.toml` clean.
- All three run for at least 30 s in CI smoke.

---

### T3-C  Nightly tooling: coverage, Miri, Loom, Kani

**Problem (compliance-status.md §7.4):** Coverage reporting, Miri, Loom, and
Kani are absent from the nightly workflow.

**Files:**
- `.github/workflows/nightly-quality.yml` — add steps:
  - `cargo llvm-cov` for coverage report (artifact upload).
  - `cargo miri test` for unsafe sections in `backend/crypto/` and `vault.rs`.
  - `cargo +nightly loom` for concurrency in `runtime.rs`.

**Acceptance criteria:**
- Coverage report produced and uploaded on every nightly run.
- Miri clean on `backend/crypto/` and `backend/storage/vault.rs`.

---

### T3-D  OpenRouter-unverified audit triage (10 findings)

**Problem:** 10 findings in `.audits/openrouter-unverified/` from 2026-03-30
remain untriaged.  Each must be verified against current code and either
closed or promoted to a concrete Tier 1/2 item.

**Process:** For each finding:
1. Read the current code at the claimed location.
2. Verify whether the concern still applies.
3. If resolved: move to `.audits/resolved/` with explanation.
4. If a real gap: open a dated audit finding and add it to this plan.

**Priority order:** `missing-network-address-sanitization` → `missing-transport-parameter-validation` → `missing-concurrent-key-derivation-validation` → remainder.

---

## Tier 4 — Infrastructure / Clientless

Lower priority but explicitly tracked in `implementation-checklist.md §5`.

---

### T4-A  Clientless node packaging

**Files:**
- `src/bin/clientless/` — complete install/package artifacts for routers, SBCs.
- `Makefile` — add `linux-clientless-release` target producing a deployable
  binary + config template.

### T4-B  Layer 1 startup gap reconciliation

**Files:**
- `backend/service/android_startup_ops.rs` — finish true native startup before
  Flutter exists (§2.1 in implementation-checklist.md).
- `platforms/android/.../AndroidManifest.xml` — verify
  `RECEIVE_BOOT_COMPLETED` and `LOCKED_BOOT_COMPLETED` receivers are wired.

---

## Status Table

| ID | Description | Tier | Status |
|---|---|---|---|
| T1-A | Key-clearing atomicity (§3.6.4) | 1 | OPEN |
| T1-B | Onboarding security controls (§22.27) | 1 | OPEN |
| T1-C | Android Wi-Fi Direct Rust ownership (§5.8) | 1 | OPEN |
| T1-D | Android NFC backend loop (§5.9) | 1 | OPEN |
| T1-E | App Connector selector enforcement (§17.5) | 1 | OPEN |
| T2-A | Deniable carrier ladder (§5.26–5.27) | 2 | OPEN |
| T2-B | Offline transport bundle (§5.28) | 2 | OPEN |
| T2-C | Bootstrap source diversity (§4.1, §4.3) | 2 | OPEN |
| T2-D | Overlay client parity (§5.5) | 2 | OPEN |
| T2-E | Plugin legacy invoke_hook removal (§18) | 2 | OPEN |
| T2-F | Duress PIN wind-down (§3.9.2) | 2 | OPEN |
| T2-G | Remote killswitch trust gate (§3.9.3) | 2 | OPEN |
| T2-H | Cloud backup passphrase length (§3.7.4) | 2 | OPEN |
| T3-A | Stateful simulator scenarios | 3 | OPEN |
| T3-B | Missing fuzz targets | 3 | OPEN |
| T3-C | Nightly tooling (coverage / Miri / Loom) | 3 | OPEN |
| T3-D | OpenRouter-unverified audit triage | 3 | OPEN |
| T4-A | Clientless packaging | 4 | OPEN |
| T4-B | Layer 1 startup gap reconciliation | 4 | OPEN |

---

## Already fixed (this session — 2026-05-07)

| What | Commit |
|---|---|
| Gossip endpoint injection — per-transport format validation (§4.2, S-CRITICAL) | `35f72dd` |
| bluetooth.rs stub replaced — `BluetoothTransport` struct, no unwrap() (AGENTS.md Std 1) | `35f72dd` |
| Map scale-validation Sybil defense — multi-source staging (§4.1, S-HIGH) | `35f72dd` |
| avatar_hash length check — exactly 32 bytes (§4.2, S-MEDIUM) | `35f72dd` |
| poll.rs raw pointer soundness — Drop invariant documented | `35f72dd` |
| Map lower-bound timestamp — 30-day replay window (§4.2) | `d759def` |
| Map unbounded staging DoS — `MAX_STAGED_PEERS` + `MAX_STAGED_SOURCES_PER_PEER` caps | `d759def` |
| Map Mixnet/GNUnet endpoint hardening — alphanumeric only, 128 bytes | `d759def` |
| Map per-peer update rate limiting — `MIN_UPDATE_INTERVAL_SECS` | `d759def` |
| Map prev_hash limitation documented | `d759def` |
