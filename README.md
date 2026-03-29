# Mesh Infinity

Decentralized, metadata-resistant mesh communications. Multi-transport, end-to-end encrypted, no central authority.

**Architecture**: Rust application with an embedded Flutter UI. The Rust crate is the primary artifact — Flutter is compiled to a native library and embedded, not the other way around.

## Building

### Prerequisites

| Tool | Version |
|---|---|
| Rust (stable) | `rustup toolchain install stable` |
| Flutter | 3.41+ |

| Platform | Additional tools |
|---|---|
| macOS | Xcode + Command Line Tools |
| Android | Android SDK + NDK; `cargo install cargo-ndk` |
| iOS | Xcode; `rustup target add aarch64-apple-ios` |
| Linux | `clang cmake ninja-build pkg-config libgtk-3-dev` |
| Windows | MSVC build tools; NSIS (for installer) |

### Make targets

```bash
make macos-debug        make macos-release
make android-debug      make android-release
make ios-debug          make ios-release
make linux-debug        make linux-release
make windows-debug      make windows-release
```

Artifacts land in `build/output/<platform>/<profile>/`.

## Project layout

```
backend/          Rust — all business logic, crypto, transport, FFI
  crypto/         X3DH, Double Ratchet, ring signatures, Sphinx mixnet, KEM
  identity/       Self-identity, peer IDs, masks, kill switch
  trust/          Web-of-trust levels, governance, ACL
  pairing/        Contact exchange and cryptographic handshake
  messaging/      Rooms, messages, delivery, reactions
  groups/         Membership, Sender Key distribution, garden
  network/        Gossip, federation, relay deposits, threat context
  routing/        Path selection, store-and-forward, tunnel gossip
  transport/      Tor, I2P, WireGuard, BLE, Wi-Fi Direct, RF, NFC, …
  mesh/           Mesh coordinator and packet forwarder
  files/          File transfer and hosted storage
  calls/          Voice/video call signalling
  vpn/            Exit-node VPN routing
  services/       Module system, plugin registry, port policy
  storage/        Encrypted vault
  ffi/            C FFI boundary (Dart ↔ Rust)

frontend/         Flutter UI — single codebase, all platforms
  lib/backend/    FFI bridge, event bus, data models
  lib/features/   messaging / files / peers / network / settings / calls
  lib/shell/      Responsive shell (mobile / tablet / desktop)

platforms/        Native host projects
  android/        Gradle — embeds Flutter AAR + Rust .so
  apple/          Xcode — Runner (macOS) + RunnerIOS (iOS)
  linux/          CMake + GTK runner
  windows/        MSVC runner + NSIS installer

src/              Rust crate entry point (lib.rs, runtime.rs)
Makefile          Canonical cross-platform build entry point
```

## Architecture

```
┌──────────────────────────────────────┐
│  Native host  (Xcode / Gradle / CMake)│  ← primary application
├──────────────────────────────────────┤
│  Rust backend  (mesh-infinity)        │  ← all logic, crypto, transport
│  cdylib / staticlib / rlib            │
├──────────────────────────────────────┤
│  Flutter UI  (embedded native lib)    │  ← UI only, no business logic
│  XCFramework / AAR / .so             │
└──────────────────────────────────────┘
```

FFI bridge: `frontend/lib/backend/backend_bridge.dart` ↔ `backend/ffi/lib.rs`

## Contributing

### Adding a feature

1. Implement in `backend/{module}/`
2. Expose via `backend/ffi/lib.rs` and mirror in `frontend/lib/backend/backend_bridge.dart`
3. Add UI under `frontend/lib/features/{feature}/`

### Cargo feature flags

| Flag | Description |
|---|---|
| `transport-bluetooth-native` | BLE via `btleplug` |
| `transport-rf-meshtastic` | LoRa/RF via Meshtastic protocol |
| `vpn-routing` | Full-tunnel VPN (requires root / CAP_NET_ADMIN) |

### The 11 standards

Every committed file must pass all of these. Violation of any standard requires a fix before merge, not a waiver.

1. Are any warnings or errors being suppressed? They must be fixed, not hidden.
2. Does every function do what it claims? Stubs, `todo!()`, and no-op bodies are not permitted.
3. Does every test cover adversarial inputs — malformed data, replay, boundary conditions — not just the happy path?
4. Does every implementation match the specification? Deviations must be commented and filed as findings.
5. Is there duplicate code, unused typedefs, or unnecessary imports? Reuse existing code.
6. Are errors on security-critical paths propagated or explicitly handled? Silent discards are not permitted.
7. Can any code path panic through the FFI boundary? `.unwrap()` / `.expect()` are not permitted in FFI-reachable or concurrent paths.
8. Does the code follow project conventions? This project uses `snake_case` throughout.
9. Are errors typed and propagated with `?`? Swallowed errors are not compliant.
10. Is the implementation simple and readable without external context?
11. Does every line of code have ~2 lines of comments explaining intent and reasoning?

**Compliant code** passes all 11 standards, adheres to the spec, and passes human accuracy review. All three are required.

### Commit format

`type(scope): description` — [Conventional Commits](https://www.conventionalcommits.org/)

The only permitted AI reference in a commit message is crediting a specific finding:
> `finding surfaced by review from (model name)`

## CI

GitHub Actions builds all platforms on every push. Release builds publish as GitHub prereleases with native artifacts attached.

## License

GNU General Public License v3.0 (GPLv3). See LICENSE.
