# Backend Organization Plan

## Objective

Reorganize [`backend/`](backend) so every folder and file has one dedicated purpose, with no duplicate-purpose files.

## Organization Rules

1. One file owns one behavior or one data model concern.
2. One folder owns one bounded domain.
3. Orchestration code must not contain domain logic.
4. Cross-domain shared helpers live in explicit shared utility files.
5. Public API boundaries are narrow and documented.

## Complete Current Map of [`backend/`](backend)

### Root

- [`backend/lib.rs`](backend/lib.rs): backend crate public re-export surface.
- [`backend/service.rs`](backend/service.rs): high-level backend service orchestration and user-facing backend operations.
- [`backend/auth/`](backend/auth): authentication and trust domain.
- [`backend/core/`](backend/core): core networking, routing, policy, and mesh internals.
- [`backend/crypto/`](backend/crypto): cryptographic primitives and key lifecycle utilities.
- [`backend/discovery/`](backend/discovery): peer discovery services.
- [`backend/ffi/`](backend/ffi): C/FFI bridge for frontend/runtime integration.
- [`backend/transport/`](backend/transport): transport implementations and transport selection managers.

### Auth Domain

- [`backend/auth/lib.rs`](backend/auth/lib.rs): auth module exports.
- [`backend/auth/identity.rs`](backend/auth/identity.rs): local identity keypair and DH key management.
- [`backend/auth/storage.rs`](backend/auth/storage.rs): trust graph persistence and revocation certificate persistence model.
- [`backend/auth/web_of_trust.rs`](backend/auth/web_of_trust.rs): trust graph, attestations, revocations, trust evaluation logic.

### Core Domain Root

- [`backend/core/lib.rs`](backend/core/lib.rs): core module exports.
- [`backend/core/core.rs`](backend/core/core.rs): shared core types and system configuration models.
- [`backend/core/error.rs`](backend/core/error.rs): global backend error types.
- [`backend/core/service.rs`](backend/core/service.rs): core mesh service orchestrator lifecycle.

### Core Application Gateway

- [`backend/core/application_gateway/mod.rs`](backend/core/application_gateway/mod.rs): module wiring.
- [`backend/core/application_gateway/app_registry.rs`](backend/core/application_gateway/app_registry.rs): app registration/lookup.
- [`backend/core/application_gateway/protocol_handlers.rs`](backend/core/application_gateway/protocol_handlers.rs): protocol dispatch/handling.

### Core Exit Node

- [`backend/core/exit_node/mod.rs`](backend/core/exit_node/mod.rs): module wiring.
- [`backend/core/exit_node/bandwidth_manager.rs`](backend/core/exit_node/bandwidth_manager.rs): bandwidth control and limits.
- [`backend/core/exit_node/traffic_router.rs`](backend/core/exit_node/traffic_router.rs): exit-node route decisions.

### Core File Transfer

- [`backend/core/file_transfer/mod.rs`](backend/core/file_transfer/mod.rs): module wiring.
- [`backend/core/file_transfer/chunk_manager.rs`](backend/core/file_transfer/chunk_manager.rs): chunk slicing/assembly.
- [`backend/core/file_transfer/transfer_manager.rs`](backend/core/file_transfer/transfer_manager.rs): transfer state orchestration.
- [`backend/core/file_transfer/transfer_queue.rs`](backend/core/file_transfer/transfer_queue.rs): transfer queue policies.

### Core Mesh

- [`backend/core/mesh/mod.rs`](backend/core/mesh/mod.rs): module wiring.
- [`backend/core/mesh/connection.rs`](backend/core/mesh/connection.rs): peer connection state and lifecycle.
- [`backend/core/mesh/obfuscation.rs`](backend/core/mesh/obfuscation.rs): payload/traffic obfuscation logic.
- [`backend/core/mesh/peer.rs`](backend/core/mesh/peer.rs): peer model and peer-level helpers.
- [`backend/core/mesh/routing.rs`](backend/core/mesh/routing.rs): message routing logic.
- [`backend/core/mesh/wireguard.rs`](backend/core/mesh/wireguard.rs): WireGuard mesh/session behavior.

### Core Network Stack

- [`backend/core/network_stack/mod.rs`](backend/core/network_stack/mod.rs): module wiring.
- [`backend/core/network_stack/dns_resolver.rs`](backend/core/network_stack/dns_resolver.rs): DNS resolution paths.
- [`backend/core/network_stack/hop_router.rs`](backend/core/network_stack/hop_router.rs): hop-by-hop route propagation.
- [`backend/core/network_stack/mesh_address.rs`](backend/core/network_stack/mesh_address.rs): mesh addressing model.
- [`backend/core/network_stack/mesh_packet_router.rs`](backend/core/network_stack/mesh_packet_router.rs): packet-level router.
- [`backend/core/network_stack/nat_traversal.rs`](backend/core/network_stack/nat_traversal.rs): NAT traversal logic.
- [`backend/core/network_stack/policy_router.rs`](backend/core/network_stack/policy_router.rs): route/policy matching.
- [`backend/core/network_stack/virtual_interface.rs`](backend/core/network_stack/virtual_interface.rs): virtual interface handling.
- [`backend/core/network_stack/vpn_service.rs`](backend/core/network_stack/vpn_service.rs): VPN service behavior.

### Core Security

- [`backend/core/security/mod.rs`](backend/core/security/mod.rs): module wiring.
- [`backend/core/security/policy_engine.rs`](backend/core/security/policy_engine.rs): policy checks.
- [`backend/core/security/sandbox.rs`](backend/core/security/sandbox.rs): sandbox and resource constraints.

### Crypto Domain

- [`backend/crypto/lib.rs`](backend/crypto/lib.rs): crypto module exports.
- [`backend/crypto/backup.rs`](backend/crypto/backup.rs): encrypted backup/restore primitives.
- [`backend/crypto/deniable.rs`](backend/crypto/deniable.rs): deniable signature operations.
- [`backend/crypto/message_crypto.rs`](backend/crypto/message_crypto.rs): message/session encryption primitives.
- [`backend/crypto/pfs.rs`](backend/crypto/pfs.rs): perfect forward secrecy/session key rotation helpers.
- [`backend/crypto/secmem.rs`](backend/crypto/secmem.rs): secure memory management helpers.
- [`backend/crypto/vault.rs`](backend/crypto/vault.rs): key vault storage and retrieval.

### Discovery Domain

- [`backend/discovery/lib.rs`](backend/discovery/lib.rs): discovery module exports.
- [`backend/discovery/catalog.rs`](backend/discovery/catalog.rs): discovered peer catalog/index.
- [`backend/discovery/mdns.rs`](backend/discovery/mdns.rs): mDNS discovery implementation.
- [`backend/discovery/service.rs`](backend/discovery/service.rs): discovery service orchestration.

### FFI Domain

- [`backend/ffi/lib.rs`](backend/ffi/lib.rs): FFI API surface, event bridging, and runtime control glue.

### Transport Domain

- [`backend/transport/lib.rs`](backend/transport/lib.rs): transport module exports.
- [`backend/transport/traits.rs`](backend/transport/traits.rs): transport abstraction traits.
- [`backend/transport/core_manager.rs`](backend/transport/core_manager.rs): connection quality selection and transport manager internals.
- [`backend/transport/manager.rs`](backend/transport/manager.rs): runtime transport enable/ordering policy wrapper layer.
- [`backend/transport/clearnet.rs`](backend/transport/clearnet.rs): clearnet transport implementation.
- [`backend/transport/tor.rs`](backend/transport/tor.rs): Tor-style transport implementation.
- [`backend/transport/i2p.rs`](backend/transport/i2p.rs): I2P-style transport implementation.
- [`backend/transport/bluetooth.rs`](backend/transport/bluetooth.rs): Bluetooth transport implementation.
- [`backend/transport/rf.rs`](backend/transport/rf.rs): RF transport foundation and meshtastic feature gate.

## Duplicate-Purpose Risk Areas

1. Service orchestration overlap between [`backend/service.rs`](backend/service.rs) and [`backend/core/service.rs`](backend/core/service.rs).
2. Transport policy split between [`backend/transport/core_manager.rs`](backend/transport/core_manager.rs) and [`backend/transport/manager.rs`](backend/transport/manager.rs).
3. Discovery orchestration split between [`backend/discovery/service.rs`](backend/discovery/service.rs) and service-layer glue in [`backend/service.rs`](backend/service.rs).
4. Trust domain operations split between [`backend/auth/web_of_trust.rs`](backend/auth/web_of_trust.rs) and trust-facing call paths embedded in [`backend/service.rs`](backend/service.rs).

## Target Reorganization Blueprint

### 1) Backend Root

- Keep [`backend/lib.rs`](backend/lib.rs) as the only backend public export boundary.
- Replace monolithic [`backend/service.rs`](backend/service.rs) with `backend/service/` package:
  - `backend/service/mod.rs`: surface and wiring only.
  - `backend/service/lifecycle.rs`: startup/shutdown/run-state only.
  - `backend/service/settings.rs`: settings mutation/query only.
  - `backend/service/messaging.rs`: rooms/messages only.
  - `backend/service/trust.rs`: trust and identity operations only.
  - `backend/service/hosted_services.rs`: hosted-service config/access policy only.
  - `backend/service/reconnect.rs`: passive fallback and reconnect sync only.
  - `backend/service/metrics.rs`: stats/reporting only.

### 2) Core Domain

- Keep [`backend/core/core.rs`](backend/core/core.rs) as pure shared models and constants.
- Keep [`backend/core/service.rs`](backend/core/service.rs) as lower-level mesh runtime orchestrator only.
- Disallow user-facing backend API logic inside [`backend/core/service.rs`](backend/core/service.rs).

### 3) Transport Domain

- Keep file-per-transport implementation model.
- Merge policy ownership to one manager authority:
  - [`backend/transport/core_manager.rs`](backend/transport/core_manager.rs): scoring/selection internals only.
  - [`backend/transport/manager.rs`](backend/transport/manager.rs): runtime toggles and ordered policy only.
- Forbid duplicated routing/selection logic in individual transport files.

### 4) Auth Domain

- Keep existing split and tighten single-purpose boundaries:
  - [`backend/auth/identity.rs`](backend/auth/identity.rs): local identity keys and signatures.
  - [`backend/auth/web_of_trust.rs`](backend/auth/web_of_trust.rs): trust graph and evaluation engine.
  - [`backend/auth/storage.rs`](backend/auth/storage.rs): persistence models and disk I/O only.

### 5) Discovery Domain

- [`backend/discovery/service.rs`](backend/discovery/service.rs): orchestration only.
- [`backend/discovery/catalog.rs`](backend/discovery/catalog.rs): storage/index only.
- [`backend/discovery/mdns.rs`](backend/discovery/mdns.rs): protocol adapter only.

### 6) FFI Domain

- Keep [`backend/ffi/lib.rs`](backend/ffi/lib.rs) as boundary translation only.
- Move non-FFI business logic out into service/domain files.

## Comment Verbosity Standard

1. Every module gets a top-level doc comment with:
   - intent
   - invariants
   - security constraints
   - ownership boundaries
2. Every public type and function documents:
   - input expectations
   - side effects
   - failure cases
3. Inline comments explain rationale and policy decisions, not obvious syntax.
4. Security-sensitive code blocks include explicit threat/risk note comments.
5. Keep comments accurate during moves; stale comments fail review.

## Migration Phases

1. Create new `backend/service/` structure and move code from [`backend/service.rs`](backend/service.rs) behavior-preserving only.
2. Reduce duplicate orchestrator responsibilities between [`backend/service/`](backend/service.rs) and [`backend/core/service.rs`](backend/core/service.rs).
3. Normalize transport manager boundaries between [`backend/transport/manager.rs`](backend/transport/manager.rs) and [`backend/transport/core_manager.rs`](backend/transport/core_manager.rs).
4. Perform comment verbosity pass for all touched files, then full backend pass.
5. Remove temporary re-export compatibility glue after imports are migrated.

## Validation Gates Per Phase

1. Build: `cargo check --all-targets`
2. Formatting: `cargo fmt --all -- --check`
3. Lint: `cargo clippy --all-targets --all-features -- -D warnings`
4. Tests: `cargo test --all-targets`
5. Structural check: no duplicate-purpose file ownership in moved domains.

