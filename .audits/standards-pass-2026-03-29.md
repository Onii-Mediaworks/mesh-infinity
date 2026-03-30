# Standards Pass — 2026-03-29 (v2, post-reboot)

**Auditor:** Claude (claude-sonnet-4-6)
**Date:** 2026-03-29
**Status:** UNRESOLVED (see individual finding files for tracking)
**Codebase revision:** af39aa9 (HEAD at time of audit)

---

## Executive Summary

This audit covers the full Rust backend of Mesh Infinity v0.3 against the 11 minimum
standards in AGENTS.md, SPEC.md §3/4/5/6/7/17, and all ten vulnerability-assessment
categories from the audit task.

**Build state:** `cargo clippy` reports 107 errors and 4 warnings. The build does NOT
pass. All 107 errors are the single lint `clippy::not_unsafe_ptr_arg_deref` on public
`extern "C"` FFI functions that dereference raw pointers without being marked `unsafe`.
This is Standard 1 non-compliance (treating errors as errors). The functions themselves
have null-checks and SAFETY comments, but Clippy is correct that the functions must be
marked `unsafe` to document the raw pointer contract.

**Critical findings:** 3
**High findings:** 5
**Medium findings:** 5
**Low findings:** 4

---

## Critical Findings (severity: CRITICAL)

### CRIT-1: LAN Broadcast Exposes Full Identity Keys — §4.9.5 Violation

**File:** `backend/ffi/lib.rs:1244–1255`
**Severity:** CRITICAL

**Description:**
The LAN presence announcement packet (broadcast to 255.255.255.255:7235 every 5 seconds)
includes the following fields:

```json
{
  "v": 1,
  "type": "mi_presence",
  "peer_id": "<64-char hex>",
  "ed25519_pub": "<64-char hex>",
  "x25519_pub": "<64-char hex>",
  "preauth_x25519_pub": "<64-char hex>",
  "preauth_sig": "<128-char hex>",
  "display_name": "<user display name>",
  "clearnet_port": 7234,
  "ts": 1234567890
}
```

SPEC.md §4.9.5 (line 1925) states explicitly:

> All LAN discovery mechanisms advertise the **mesh identity WireGuard public key**
> (Layer 1) only. **Mask-level keys and peer IDs are never included.**

The broadcast is broadcasting `ed25519_pub`, `x25519_pub`, `peer_id`, and `display_name`
— all Layer 2 (mask-level) identity material. This violates the core privacy architecture.
Any device on the local network — including rogue access points, corporate network monitors,
and any entity doing passive Wi-Fi capture — can:
1. Link all IP activity on the LAN to a specific Mesh Infinity user (`peer_id`)
2. Build a persistent cross-session identity via the stable `ed25519_pub`
3. Learn the user's display name in plaintext
4. Obtain the user's X25519 public key, enabling key substitution attacks before pairing

The document also notes (spec line 1889): "It reveals only that a Mesh Infinity node is
on this network segment, not who the user is." The current code violates this property.

**Proposed fix:**
1. Remove `peer_id`, `ed25519_pub`, `x25519_pub`, `preauth_x25519_pub`, `preauth_sig`,
   and `display_name` from the LAN broadcast packet.
2. The broadcast should contain only: `{"v":1,"type":"mi_presence","wg_pub":"<hex>","clearnet_port":N,"ts":N}`
   where `wg_pub` is the mesh identity WireGuard public key (Layer 1).
3. After pairing over an out-of-band channel (QR code, etc.), mask-level key exchange
   happens inside an authenticated WireGuard tunnel — not over LAN broadcast.
4. Update `handle_lan_presence_packet` (line 1267) to only update endpoint/port,
   not to update preauth keys from the broadcast.

---

### CRIT-2: Double Ratchet Header Exposed Outside Recipient Encryption — Traffic Correlation

**File:** `backend/ffi/lib.rs:5499–5510`
**Severity:** CRITICAL

**Description:**
When a message is sent over the wire, the JSON envelope is:

```json
{
  "v": 1,
  "type": "msg",
  "sender": "<peer_id_hex>",
  "room": "<room_id>",
  "msg_id": "<id>",
  "ts": <unix_ts>,
  "ratchet_pub": "<64-char hex>",
  "prev_chain_len": <N>,
  "msg_num": <N>,
  "ciphertext": "<encrypted blob>"
}
```

The fields `ratchet_pub`, `prev_chain_len`, and `msg_num` are the Double Ratchet header.
They are in the plaintext outer JSON envelope, NOT inside the Step 4 recipient encryption.

A passive observer monitoring clearnet TCP connections can:
1. Track `ratchet_pub` changes to map message epochs (DH ratchet steps signal topic/session
   changes and are correlated with conversation rhythm).
2. Use `msg_num` to count messages per session and `prev_chain_len` to map session boundaries.
3. Correlate `ratchet_pub` changes between two observed endpoints to confirm they are
   communicating with each other (relationship correlation attack).

SPEC.md §7.2 (line 4721) as written places `dr_header` outside Step 4 encryption
(`payload = dr_header || trust_encrypted`), meaning the spec itself specifies this
plaintext placement. However, the spec comment on Step 4 (line 4758) says:
"Relay nodes see only the outer encrypted blob and destination address — nothing inside
is visible to them." The dr_header is visible to relay nodes, which is an inconsistency
in the spec.

**Proposed fixes:**
Option A (preferred): Move dr_header inside Step 4 encryption. Change Step 4 to encrypt
`dr_header || double_signed` instead of `double_signed`. This fully protects all ratchet
metadata. Requires a spec update to §7.2.

Option B: Encrypt or obfuscate `ratchet_pub` at the outer layer using a shared secret
between the two peers (derived from the static DH channel key), so relay nodes cannot
link successive ratchet keys to the same session.

Option C: Replace the JSON plaintext envelope with a binary framing where all message
metadata is inside the Step 4 AEAD. The outer frame only carries destination address
and payload length (but NOT the ratchet header).

See also: Signal Protocol's sealed sender design for comparison.

---

### CRIT-3: AOS Ring Signatures — Claimed But Not Implemented (Standard 2 Violation)

**File:** `backend/crypto/lib.rs:10`, `backend/groups/group.rs:184`
**Severity:** CRITICAL

**Description:**
The module docstring in `backend/crypto/lib.rs` explicitly lists "AOS ring signatures
(§3.5.2)" as an implemented feature. The `NetworkType::uses_ring_signatures()` function
(group.rs:184) returns `true` for Private and Closed groups, and tests at lines 564–567
assert this is the case.

However, there is NO implementation of AOS ring signatures anywhere in the codebase.
A full text search for `ring_sign`, `ring_verify`, `lsag`, `aos_ring`, `ring_sig` returns
zero results in any non-comment, non-comment-only context.

This means:
1. Private and Closed groups claim to use ring signatures for membership deniability, but
   they do NOT. This is a false security guarantee.
2. Group messages from Private/Closed groups are sent without the membership-deniability
   property the spec requires, exposing member identities to routing nodes.
3. The tests at group.rs:564–567 test only the `uses_ring_signatures()` flag, not any
   actual ring signature operation. They test nothing meaningful.
4. This violates Standard 2 (tests must represent the threat model) and Standard 6
   (spec-required features must be implemented — no stubs or placeholders per AGENTS.md).

SPEC.md §3.5.2 specifies AOS (Abe-Okamoto-Suzuki) Linkable Ring Signatures for group
message deniability. This is unimplemented.

**Proposed fix:**
Implement LSAG (Linkable Spontaneous Anonymous Group) signatures as the AOS variant.
Reference implementation: the Monero codebase contains a well-audited LSAG in C++.
A Rust crate (`ring-signature` on crates.io) exists but is not audited; a custom
implementation against the LSAG paper is preferred. Until implemented, `uses_ring_signatures()`
must return `false` and the module docstring must not list it as implemented. Fuzz the
sign/verify round-trip and cross-key-confusion properties.

---

## High Findings (severity: HIGH)

### HIGH-1: 107 FFI Functions Not Marked `unsafe` — Clippy Build Failure

**File:** `backend/ffi/lib.rs` (throughout)
**Severity:** HIGH (build-blocking; Standard 1)

**Description:**
All 107 public `extern "C"` functions that dereference raw `*const c_char` or
`*mut MeshContext` pointers are flagged by `clippy::not_unsafe_ptr_arg_deref` because
they are not marked `unsafe`. Clippy treats this as an error, causing the build to fail
with "could not compile `mesh-infinity` due to 107 previous errors."

Standard 1 states: "warnings and errors need to be treated as valid and fixed without
being hidden." The 107 errors are all of the same type: public `extern "C"` functions
that perform pointer dereference without being marked `unsafe`. The SAFETY comments
are present and the null-checks exist, but the function signature itself must be
`unsafe extern "C"` to communicate the contract to callers.

This is a real correctness issue: the Dart FFI caller must use `@Native` or
`lookupFunction` with `unsafe` annotations appropriate to the ABI; not marking these
functions `unsafe` creates a false API contract.

**Proposed fix:**
Change all 107 public FFI functions from `pub extern "C" fn` to
`pub unsafe extern "C" fn`. Update the Dart FFI declarations to match.
This is a mechanical change (sed-replaceable). No logic changes required.

---

### HIGH-2: Null Pointer Dereference — `peer_id_hex` and `call_id_hex` Without Null Checks

**Files:**
- `backend/ffi/lib.rs:9726` (`mi_call_offer`) — `peer_id_hex` not null-checked before `CStr::from_ptr`
- `backend/ffi/lib.rs:9797` (`mi_call_answer`) — `call_id_hex` not null-checked before `CStr::from_ptr`
- `backend/ffi/lib.rs:9854` (`mi_call_hangup`) — `call_id_hex` not null-checked before `CStr::from_ptr`
**Severity:** HIGH

**Description:**
Three FFI functions check `ctx.is_null()` but do not check their string pointer arguments
for null before calling `CStr::from_ptr(...)`. A null pointer passed from Dart for
`peer_id_hex` (in `mi_call_offer`) or `call_id_hex` (in `mi_call_answer`/`mi_call_hangup`)
will cause a null dereference inside `CStr::from_ptr`, which is undefined behaviour
and will abort the process. On iOS and Android, this terminates the app.

The "stupidest user" scenario: a UI bug passes `null` for a call ID string after a call
clears, triggering a crash report loop.

**Proposed fix:**
Add null checks at the top of each function:
```rust
if ctx.is_null() || peer_id_hex.is_null() { return ptr::null(); }
```
Pattern already used correctly elsewhere (e.g., `mi_tor_connect` at line 6027 checks
all three pointers before use).

---

### HIGH-3: Store-and-Forward Expiry Signature Verified Against Request's Own Destination Key

**File:** `backend/routing/store_forward.rs:433–448`
**Severity:** HIGH

**Description:**
The S&F expiry signature verification code (lines 433–448) verifies `expiry_sig` using
`request.destination.0` as the public key — the key from the deposit REQUEST itself.

```rust
if !signing::verify(
    &request.destination.0,     // <-- key from the INCOMING REQUEST
    signing::DOMAIN_SF_EXPIRY,
    &msg,
    &request.expiry_sig,
) {
    return DepositResult::InvalidExpirySig;
}
```

The comment (lines 422–431) explains this is intentional: "The expiry_sig is signed by
the RECIPIENT's key over destination || expiry." The design allows the S&F node to verify
without knowing the sender identity. However, an attacker who fabricates a
`StoreAndForwardRequest` can:
1. Set `destination` to any peer's address.
2. Sign `expiry_sig` with their OWN Ed25519 key.
3. Also set `destination.0` to their own key.

This results in a self-signed expiry that is accepted by the relay — the attacker can
deposit messages for any destination they fabricate a request for. The relay cannot
distinguish a legitimate deposit from a fabricated one because the relay trusts whatever
key is presented in the `destination` field.

This is specifically the "relay deposit expiry verified against key in the relay request
rather than a stored contact key" concern from the audit task.

**Impact:** An attacker can flood a relay's S&F queue for any destination address by
generating a key pair, setting destination to their new key, and depositing messages
until quota limits are hit. However, the destination will never decrypt these messages
(they have no matching private key). More critically, an attacker who knows a target's
real `destination.0` (which equals their peer_id, a public value) CANNOT self-sign since
they don't have the target's private key — so the attack is limited to self-targeted fake
destinations. The real risk is DoS against the relay's aggregate storage cap.

**Proposed fix:**
The design is acceptable for preventing relay-storage-extension attacks, but should be
documented with an explicit threat model note. Additionally, add a check that
`destination.0` matches a known contact's key when the depositing peer is authenticated
(trusted context), or enforce stricter rate limits per tunnel for unauthenticated deposits.

---

### HIGH-4: Missing Message Deduplication — No Replay Protection for Delivered Messages

**File:** `backend/messaging/delivery.rs`, `backend/routing/store_forward.rs`
**Severity:** HIGH

**Description:**
The `delivery.rs` module implements a delivery state machine (Pending → Sending → Sent →
Delivered → Read), but there is no message ID deduplication mechanism that prevents a
previously delivered `msg_id` from being re-accepted and re-delivered.

In `process_inbound_frame` (`backend/ffi/lib.rs:1918`), incoming messages are decrypted
and pushed to the message store. The code checks for `type == "pairing_hello"` and other
special frames but does NOT check whether `msg_id` has already been seen/delivered.

**Attack scenario:** An attacker or misbehaving relay node replays a captured clearnet
TCP frame. The recipient's node will decrypt (the Double Ratchet will reject duplicate
ciphertext because the ratchet state has advanced), but if the DR session has been
reloaded from a stale snapshot, the same `msg_id` could be re-delivered and added to
the message store a second time.

The `DeduplicationCache` in `backend/routing/loop_prevention.rs` is for routing packet
deduplication (announcement IDs), not message content IDs.

**Proposed fix:**
Maintain a per-room seen-message-ID set (bloom filter or bounded LRU cache keyed by
`msg_id`) that persists in the vault. Reject and drop any message whose `msg_id` is
already in the delivered set. The Double Ratchet DuplicateMessage error in
`double_ratchet.rs:72` already exists but is only triggered if the same ratchet state
processes the same message twice — it does not protect against replays to a freshly
loaded session.

---

### HIGH-5: KEM Public Key Not Independently Signed by Ed25519 Identity Key

**File:** `backend/identity/self_identity.rs:109–111`, `backend/crypto/x3dh.rs:124–132`
**Severity:** HIGH

**Description:**
The ML-KEM-768 encapsulation key (`kem_encapsulation_key`) is derived deterministically
from `master_key` via HKDF in `derive_kem_keypair()` (self_identity.rs:109). It is
advertised in pairing payloads and LAN presence packets (`network/map.rs:83`).

Unlike the preauth X25519 key (which has a `preauth_sig` signed by the Ed25519 identity
key — see `PreauthBundle.preauth_sig` and PREAUTH_SIG_DOMAIN), the KEM encapsulation key
has NO Ed25519 signature binding it to the identity key.

In the `PreauthBundle` struct (`x3dh.rs:116–132`), `preauth_kem_pub` is `Option<Vec<u8>>`
with no accompanying signature field. The `x3dh_initiate()` function (line 203) verifies
`preauth_sig` for the X25519 preauth key but does NOT verify any KEM key binding.

**Attack scenario:** An active network attacker (on-path MITM) strips the
`kem_encapsulation_key` from a gossip entry or substitutes their own KEM key. Alice
then uses the attacker's KEM key for encapsulation. The attacker decapsulates, recovers
`pq_ss`, and mixes it into the master_secret. If Bob's classical X25519 component is
uncompromised, this does NOT break the classical security — the IKM still contains
DH1 || DH2 || DH3 from the X25519 path. However:
- If the X25519 path is later compromised (via classical break), the PQ protection is
  already gone.
- The protocol claims post-quantum security but it can be silently downgraded if
  the KEM key is stripped (resulting in classical-only HKDF output).

The existing preauth key signing (`PREAUTH_SIG_DOMAIN`) demonstrates the pattern to
use. The KEM key needs the same treatment.

**Proposed fix:**
Add a `kem_sig` field to `PreauthBundle` (alongside `preauth_sig`) containing an Ed25519
signature over `"MeshInfinity_PQXDH_kem_pub_v1" || kem_encapsulation_key_bytes`.
Verify it in `x3dh_initiate()` the same way `preauth_sig` is verified at lines 203–219.
Generate and publish the `kem_sig` alongside the encapsulation key in
`self_identity.rs` and the gossip map entry.

---

## Medium Findings (severity: MEDIUM)

### MED-1: `lock().unwrap()` — Mutex Panic Risk in Spawned Thread Paths

**Files:**
- `backend/transport/cjdns.rs:173, 183`
- `backend/transport/wifi_direct.rs:519, 585, 594, 729, 813`
- `backend/transport/can_bus.rs:317, 391, 402`
- `backend/transport/kcp.rs:692, 695, 720, 732, 747, 756`
- `backend/transport/layer2.rs:388, 518`
- `backend/transport/yggdrasil.rs:316, 337`
**Severity:** MEDIUM (Standard 7 concern)

**Description:**
Many transport modules use bare `.lock().unwrap()` on mutexes that are accessed from
spawned worker threads (e.g., the cjdns, WiFi Direct, CAN bus, KCP, and Yggdrasil
transports all spawn background threads). If a thread panics while holding a Mutex,
all subsequent `.lock().unwrap()` calls on that mutex from other threads will see
a poisoned mutex and panic themselves — cascading failure.

The FFI layer itself uses `.lock().unwrap_or_else(|e| e.into_inner())` consistently
(correct), but these transport-level background threads do not.

**Proposed fix:**
Replace `.lock().unwrap()` with `.lock().unwrap_or_else(|e| e.into_inner())` in all
transport background threads, consistent with the FFI layer pattern. Alternatively,
design transports to not share mutexes across thread boundaries (message-passing instead).

---

### MED-2: `send_msg_num` and `recv_msg_num` Will Overflow at u32::MAX

**File:** `backend/crypto/double_ratchet.rs:298, 384`
**Severity:** MEDIUM

**Description:**
`send_msg_num` and `recv_msg_num` are `u32` fields incremented with `+= 1` (lines 298,
384, 470, 541). At u32::MAX (4,294,967,295 messages in a single ratchet chain), the
increment wraps around to 0 due to Rust integer overflow behaviour in release mode.
This would reuse message numbers, causing the DH ratchet step to be triggered spuriously
(the receiver would see `header.msg_num = 0` with an unchanged `ratchet_pub`).

In practice, a DH ratchet step occurs after every received message, resetting msg_num
to 0, so this requires 4 billion messages in one chain — not reachable in practice.
However, a malicious peer sending manipulated `msg_num` values could trigger the
`skip_message_keys` function (line 393) to be called with `until = 0xFFFFFFFF` and
`from = current`, attempting to cache up to `MAX_SKIP - existing` = ~1000 keys, which
is bounded. The actual overflow risk at the arithmetic level is controlled by `MAX_SKIP`.

**Proposed fix:**
Add a check in `encrypt()` and `recv_msg_key()` that returns `EncryptionFailed` /
`DecryptionFailed` if `send_msg_num == u32::MAX` or `header.msg_num == u32::MAX`
before incrementing, forcing a DH ratchet step. Document this in the ratchet spec.

---

### MED-3: Governance Vote Validation — `proposed_by` Not Verified Against Admin List

**File:** `backend/trust/governance.rs:144–162`
**Severity:** MEDIUM

**Description:**
`GovernanceVote::new()` accepts a `proposed_by: PeerId` parameter with no validation
that the proposer is actually an admin (for actions that `requires_admin()`). The
`requires_admin()` function (line 84) correctly marks all governance actions as admin-
required, but the calling code is responsible for enforcing this. If a non-admin peer
fabricates a `GovernanceVote` with `proposed_by` set to themselves and distributes it
over the network, nodes that don't check the proposer against their admin list will
process it as a valid proposal.

The vote structure has no signature over `proposed_by` — it is a trust-on-presentation
field. There is no `propose_sig: Vec<u8>` field binding the proposal to an authenticated admin.

**Proposed fix:**
Add `propose_sig: Vec<u8>` to `GovernanceVote` signed by the proposer's Ed25519 key
over `DOMAIN_TRUST_PROMOTION || action_bytes || proposed_by || eligible_voters_hash ||
timestamp`. Verify this signature before processing any governance proposal. Alternatively,
wrap `GovernanceVote` in a `SignedGovernanceVote` that includes proposer key + signature.

---

### MED-4: `mi_configure_module` — `service_id` and `config_json` Only Null-Checked Via Guard

**File:** `backend/ffi/lib.rs:9469–9479`
**Severity:** MEDIUM

**Description:**
`mi_configure_module` (line 9468) checks `ctx.is_null() || service_id.is_null() || config_json.is_null()`
at line 9470 — this is correct. However, after the null check, the code does NOT use the
safe `c_str_to_str()` wrapper (which double-checks null); instead it calls `CStr::from_ptr`
directly at lines 9479 and 9483. While the null check above does guard against null
dereferences, the `CStr::from_ptr` calls are then not marked as `unsafe` expressions
explicitly justifying the safety invariant. This is a code clarity issue that, combined
with the HIGH-1 finding (all FFI functions not marked `unsafe`), creates unsafe code
paths that are not clearly demarcated.

**Proposed fix:**
Replace the direct `CStr::from_ptr` calls with the `c_str_to_string()` safe wrapper
already defined at line 4816. This wraps the null check into the extraction function
and is consistent with the rest of the codebase.

---

### MED-5: Sender Key Not Rotated on Group Member Removal

**File:** `backend/crypto/sender_keys.rs`, `backend/groups/rekey.rs`
**Severity:** MEDIUM

**Description:**
`Group::needs_rekey()` (group.rs:433) triggers only on a time interval
(`DEFAULT_REKEY_INTERVAL_SECS = 7 days`). There is no event-driven rekey trigger for
member removal events. In the Signal sender key protocol, removing a member from a
group MUST trigger an immediate sender key rotation for all remaining members to
maintain forward secrecy: the removed member retains knowledge of the current sender
chain key and can decrypt all future messages until a new key is distributed.

The spec §15.2 (Ratchet Rotation Policy) and §8.7 (Trusted Groups) imply rotation on
membership change, but the implementation has no code path linking `Group::members.remove()`
to a rekeying event. The `ForceRekey` governance action exists but requires a manual
admin trigger.

**Proposed fix:**
Add an explicit `rekey_on_member_removal: bool` flag (default true) and trigger
`last_rekey_at = 0` (forcing `needs_rekey()` to return true on next message) when a
member is removed. The rekeying should be initiated automatically by admins without
requiring a separate governance vote.

---

## Low Findings (severity: LOW)

### LOW-1: Clippy Warnings — `needless_borrows_for_generic_args` and `explicit_auto_deref`

**Files:**
- `backend/transport/mixnet.rs:244, 307`
- `backend/ffi/lib.rs:4718, 4724`
**Severity:** LOW (Standard 1)

**Description:**
Four clippy warnings exist (non-blocking but present under `--deny warnings`):
- `mixnet.rs:244, 307`: `&layer_key` passed where `layer_key` suffices (auto-deref)
- `ffi/lib.rs:4718, 4724`: `&*master` used where `&master` suffices

These are cosmetic but violate Standard 1 (no warnings suppressed or tolerated).

**Proposed fix:** Apply the suggestions: `layer_key` → `layer_key`, `&*master` → `&master`.

---

### LOW-2: Comment Overstates Security — LAN Announce `sig` Field Noted as Future

**File:** `backend/ffi/lib.rs:1177–1179`
**Severity:** LOW

**Description:**
The comment at line 1177 reads:
```
/// Signed announcements (future): the `sig` field will carry an Ed25519
/// signature over the canonical JSON. For now omitted — LAN trust is
/// confirmed at pairing; the announce is only used to learn the endpoint.
```

Given that CRIT-1 (LAN broadcast exposes full identity keys) is filed as a critical
finding, this comment understates the real situation. The broadcast is not "only used
to learn the endpoint" — it exposes full mask identity. The comment could mislead
future contributors into thinking this is a minor, known gap.

**Proposed fix:** After CRIT-1 is fixed, update this comment to accurately describe
that WireGuard public key is the only broadcast field and signatures are validated
during pairing.

---

### LOW-3: `SessionSnapshot` — `skipped_keys` Contains Raw Key Material With No Zeroize

**File:** `backend/crypto/double_ratchet.rs:625–651`
**Severity:** LOW

**Description:**
`SessionSnapshot` is a serializable struct containing raw key material: `root_key: [u8; 32]`,
`my_ratchet_secret_bytes: [u8; 32]`, `send_chain_key: Option<[u8; 32]>`,
`recv_chain_key: Option<[u8; 32]>`, and `skipped_keys: Vec<([u8; 32], u32, [u8; 32])>`.

The struct derives `Serialize, Deserialize` but does NOT implement `Zeroize` or `Drop`.
The live `DoubleRatchetSession` struct has a `Drop` impl (line 197) that zeroizes all
key material, but the `SessionSnapshot` created by `to_snapshot()` (line 568) does not.
The snapshot lives in memory (potentially for the duration of vault serialization) with
no guarantee of zeroization.

**Proposed fix:**
Add `#[derive(Zeroize, ZeroizeOnDrop)]` to `SessionSnapshot` or implement `Drop` manually
the same way the main session struct does. Alternatively, mark the snapshot struct as
`#[cfg(not(feature = "production"))]` and only expose it for testing, doing all vault
persistence inside the session struct itself.

---

### LOW-4: `step1_authenticate` Uses `expect()` on HMAC Construction

**File:** `backend/crypto/message_encrypt.rs:108–109`
**Severity:** LOW

**Description:**
```rust
let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(msg_key)
    .expect("HMAC-SHA256 accepts 32-byte key");
```

`step1_authenticate` is called from the FFI send path. While the HMAC-SHA256
construction with a 32-byte key cannot fail in practice (HMAC accepts any key length
and 32 bytes is valid), `expect()` will panic if somehow invoked with a zero-length
key. This path is reachable from FFI (via `encrypt_message` → `step1_authenticate`).
Panics in FFI paths are UB on stable Rust (before any panic-abort guarantee is set).

The same issue appears at `compute_kem_binding` (x3dh.rs:513):
```rust
let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(eph_dh_shared)
    .expect("HMAC-SHA256 accepts any key length");
```

**Proposed fix:**
Propagate the error instead of panicking:
```rust
let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(msg_key)
    .map_err(|_| MessageCryptoError::EncryptFailed)?;
```

---

## Clippy Output Summary

Running `cargo clippy 2>&1` (as of HEAD af39aa9):

- **107 errors:** All are `clippy::not_unsafe_ptr_arg_deref` on public `extern "C"`
  functions in `backend/ffi/lib.rs` that dereference raw pointers without the function
  being marked `unsafe`. This is a build-blocking error level.

- **4 warnings:**
  - `backend/transport/mixnet.rs:244` — `needless_borrows_for_generic_args`
  - `backend/transport/mixnet.rs:307` — `needless_borrows_for_generic_args`
  - `backend/ffi/lib.rs:4718` — `explicit_auto_deref`
  - `backend/ffi/lib.rs:4724` — `explicit_auto_deref`

**Build result:** DOES NOT COMPILE under `cargo clippy`.

---

## Suppressed Warnings Check

Running `grep -rn '#\[allow(' backend/ src/` returns no results. No warnings are
suppressed via `#[allow]` attributes. This is consistent with Standard 1.

---

## Commit History Issues

```
af39aa9 fix(security): resolve critical standards violations from audit pass
e781e8f docs(readme): merge contributor standards into README, update project structure
8060be8 fix(tests): update integration test to use current runtime API
...
```

No commits reference Claude, Codex, ChatGPT, OpenAI, or other LLMs in any form.
Standard 4 is satisfied.

---

## Recommended Fix Order

Priority 1 — CRITICAL (user privacy and data security):
1. **CRIT-1** (LAN broadcast identity leak): Fix immediately. This actively leaks
   user identity to all devices on the local network on every poll cycle.
2. **CRIT-3** (Ring signatures unimplemented): Document accurate security guarantees;
   remove false claims from module docstring; implement or explicitly scope.
3. **HIGH-1** (107 Clippy errors): Run `cargo clippy --fix` then manually fix remaining.
   Build must pass before shipping.

Priority 2 — HIGH (exploitable with attacker access):
4. **HIGH-2** (null pointer dereference in call FFI functions): 3-line fix per function.
5. **CRIT-2** (DR header in plaintext): Spec update + implementation change.
6. **HIGH-5** (KEM key not signed): Add `kem_sig` field and verification.
7. **HIGH-4** (no message replay deduplication): Implement msg_id seen-set in vault.

Priority 3 — HIGH (trust/governance integrity):
8. **HIGH-3** (S&F expiry design): Document threat model; add rate-limit hardening.

Priority 4 — MEDIUM:
9. **MED-1** (mutex unwrap in threads): Mechanical replacement.
10. **MED-5** (sender key not rotated on removal): Implement event-driven rekey trigger.
11. **MED-3** (governance vote no signature): Add `propose_sig` field.
12. **MED-2** (u32 msg_num overflow): Add guard at chain extremity.
13. **MED-4** (code clarity): Replace direct `CStr::from_ptr` with safe wrapper.

Priority 5 — LOW:
14. **LOW-1** through **LOW-4**: Address in any subsequent cleanup pass.
