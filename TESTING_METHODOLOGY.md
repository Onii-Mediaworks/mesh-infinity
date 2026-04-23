# Testing Methodology

Mesh Infinity is safety-critical privacy and communications software. The
project is still in initial development. That is not permission to weaken the
testing methodology. It is the reason to make the methodology stricter.

The core rule is:

> A security-sensitive feature is not considered implemented until its safety
> tests, fuzzing surface, and invariants are implemented too.

And the non-negotiable warning is:

> Do not add fake passing tests. Do not claim compliance just because the
> implementation is incomplete. Track incomplete safety surfaces explicitly,
> and make it impossible for future implementation work to land without
> activating the matching tests.

## Initial Development Methodology

Pre-1.0 development may contain incomplete targets, incomplete harnesses, and
blocked test surfaces. That state is allowed only if it is explicit.

Explicit means:

- the surface is tracked in `fuzz/targets.toml`
- the owning module is named
- the threat is named
- the status is one of the approved registry states
- the unblock condition is written
- the mismatch is visible in review and CI

Implicit incompleteness is forbidden. A dangerous parser or state machine may
not appear in the repository without its fuzzability and testability being
tracked at the same time.

## External Byte Boundary Rule

Any function, type, or module that accepts untrusted bytes from:

- network traffic
- FFI
- QR / NFC / BLE / acoustic / media carriers
- storage files
- imported bundles or backups
- helper or middleware payloads

must satisfy all of the following:

1. no panic path on attacker-controlled input
2. no `unwrap()` / `expect()` on attacker-controlled input paths
3. length / version / type validation before semantic use
4. typed errors rather than stringly-typed silent failure
5. corpus replay test coverage
6. an active fuzz target, or a registry entry explaining why fuzzing is not
   yet active

If fuzzing is not active yet, the registry entry must make the gap explicit.

## Fuzz Target Registry

`fuzz/targets.toml` is the machine-readable source of truth for fuzz coverage.

Allowed states:

- `active`
- `blocked-unimplemented`
- `blocked-design-pending`
- `not-applicable`

Rules:

- `active` means the target exists under `fuzz/fuzz_targets/`, has a committed
  seed corpus, and must run in fuzz CI.
- `blocked-unimplemented` is allowed only while the owning parser or byte
  boundary does not exist in the codebase.
- once the owning parser exists, `blocked-unimplemented` is a methodology
  violation
- `blocked-design-pending` is allowed when the parser exists but the dedicated
  fuzz harness or stateful driver is not yet landed; this is still a tracked
  safety gap
- `not-applicable` requires a written reason
- missing registry entries for externally-originating byte processors are
  methodology violations

## Shared Testing Layer

Shared testing helpers live under `backend/testing/`.

This layer exists so future dangerous code is born testable rather than
retrofit later. The shared layer is where common invariants, deterministic
arbitrary-data decoding, corpus helpers, and simulator action models live.

Key modules:

- `backend/testing/invariants.rs`
- `backend/testing/arbitrary.rs`
- `backend/testing/corpus.rs`
- `backend/testing/sim.rs`

These helpers do not prove safety. They make consistent safety checks easy to
reuse.

## Required Security Invariants

Tests, fuzz harnesses, simulator scenarios, and regression checks must enforce
these invariants where applicable:

- invalid input never escalates trust
- failed authentication never mutates trusted state
- malformed input never panics
- replayed messages are rejected or deduplicated
- kill switch / disavow state always revokes capabilities
- private keys, seeds, plaintext, and internal crypto state never appear in
  FFI JSON, diagnostics, logs, or public events
- decrypt never succeeds unless authentication succeeds
- diagnostic reports never contain message content, private keys, contact
  names, phone numbers, emails, IPs, or hostnames

## Stateful Simulator / Property-Fuzz Methodology

Byte fuzzing alone is not enough for stateful protocols. Mesh Infinity must
also support action-sequence fuzzing over the simulator.

The future canonical target is `fuzz_network_sim_actions`.

It decodes arbitrary bytes into bounded action sequences such as:

- create node
- pair nodes
- send message
- drop packet
- duplicate packet
- delay packet
- partition link
- restore link
- advance time
- rotate key
- disavow peer
- trigger kill switch
- restart node
- reload vault
- toggle transport

After every action, shared simulator invariants are checked.

## Feature Landing Checklist

Security-sensitive features are not considered landed unless this checklist is
complete:

- [ ] Threat boundary identified.
- [ ] External byte inputs listed.
- [ ] Parser rejects malformed inputs with typed errors.
- [ ] No panic path from FFI/network/storage/untrusted input.
- [ ] Unit tests include valid, invalid, boundary, replay, wrong-key, and corrupted-input cases where applicable.
- [ ] Fuzz target exists, or registry explains why not applicable yet.
- [ ] Seed corpus added.
- [ ] Regression corpus replay passes.
- [ ] Shared invariants added or reused.
- [ ] Simulator action added if the feature affects network, trust, routing, message, transport, or identity state.
- [ ] CI enforces the relevant checks.

## Crash / Bug Corpus Policy

Any fuzz crash, parser weirdness, trust escalation, panic, replay bug,
sanitizer finding, or simulator invariant failure must become:

- a minimized corpus entry
- a regression test
- a short finding note
- a release blocker until fixed if security-relevant

Committed fixed artifacts live under:

- `fuzz/artifacts/fixed/YYYY-MM-DD-short-bug-name/`

Each fixed artifact directory must contain:

- the minimized reproducer bytes
- a `README.md` explaining the bug class and the fix

## CI Methodology

Per PR:

- formatting
- linting with warnings denied
- unit tests
- integration tests where available
- corpus replay
- 30–60 second fuzz smoke for active targets
- fuzz registry consistency check
- Flutter analyze/test when required by existing policy

Nightly:

- long fuzzing of all active targets
- simulator/property tests
- coverage
- dependency audit
- sanitizer / Miri / Loom / Kani checks where applicable

Release:

- tagged commit passes all PR checks
- long fuzzing has run on the release commit
- no open fuzz crashers
- crash reproducers committed as regression corpus
- coverage exceptions documented
- spec version and implementation version agree

## Current Repo State

Current active cargo-fuzz targets are tracked in `fuzz/targets.toml`.
Additional spec-required byte boundaries are also tracked there, but some are
still blocked pending dedicated harnesses.

That is not claimed as compliance. It is explicit gap tracking.

Known methodology mismatches resolved or tracked by this document:

- `fuzz/Cargo.toml` must identify itself explicitly as a cargo-fuzz manifest
- CI must validate the fuzz registry
- fuzz smoke must cover active targets in normal CI, not just drift silently
- nightly long fuzzing and simulator/property campaigns remain required even
  where automation is still being tightened

## Recommended Open-Source Tooling

- `cargo-fuzz` / libFuzzer
- `cargo-afl` / AFL++
- `proptest`
- `arbitrary`
- `cargo-llvm-cov`
- `Miri`
- `Loom`
- `Kani`
- sanitizers
- `cargo audit`
- future public continuous fuzzing via ClusterFuzzLite or OSS-Fuzz

Fuzzing is mandatory but not sufficient. It complements human review, protocol
review, simulation testing, typed-error discipline, and release gating.
