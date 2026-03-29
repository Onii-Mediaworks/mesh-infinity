# Mesh Infinity

A decentralized mesh networking application with multi-transport support, web-of-trust authentication, and secure peer-to-peer messaging and file transfer.

**Architecture**: Rust application with an embedded Flutter UI. The Rust crate is the primary artifact on every platform — Flutter is compiled to a native library and embedded into the host project, not the other way around.

## Features

- **Multi-Transport**: Tor, I2P, WireGuard, Clearnet, Bluetooth (BLE), Wi-Fi Direct, RF/SDR, NFC, and more
- **Web of Trust**: Decentralized peer authentication with attestation and governance
- **Mixnet / Onion Routing**: Sphinx-based onion routing over the mesh
- **End-to-End Encryption**: X3DH + Double Ratchet with header encryption; ring signatures for group privacy
- **Peer-to-Peer File Transfer**: Direct file sharing with contacts, outside of conversations
- **File Hosting Services**: Serve files to trusted peers via configurable service endpoints
- **Local Discovery**: mDNS/Bonjour for zero-config LAN peers
- **VPN Routing**: Full-tunnel VPN via exit nodes (requires root/CAP_NET_ADMIN)
- **Cross-Platform**: macOS, Android, iOS, Linux, Windows

## Quick Start

### Prerequisites

| Requirement | Version |
|---|---|
| Rust (stable) | `rustup toolchain install stable` |
| Flutter | 3.41+ |

Platform-specific requirements:

| Platform | Additional requirements |
|---|---|
| **macOS** | Xcode with Command Line Tools |
| **Android** | Android SDK + NDK; `cargo install cargo-ndk` |
| **iOS** | Xcode; `rustup target add aarch64-apple-ios` |
| **Linux** | `clang`, `cmake`, `ninja-build`, `pkg-config`, `libgtk-3-dev` |

### Building

```bash
make macos-debug      # or macos-release
make android-debug    # or android-release
make ios-debug        # or ios-release
make linux-debug      # or linux-release
```

Output artifacts land in `build/output/<os>/<profile>/`.

## Project Structure

```
mesh-infinity/
├── src/                        # Rust crate entry point
│   ├── lib.rs                 # Re-exports all backend modules
│   └── runtime.rs             # Runtime lifecycle / config
├── backend/                   # Rust backend — all business logic
│   ├── crypto/               # X3DH, Double Ratchet, ring sigs, Sphinx, KEM
│   ├── identity/             # Self-identity, peer IDs, masks, kill switch
│   ├── trust/                # Web-of-trust levels, governance, ACL
│   ├── pairing/              # Contact exchange and handshake
│   ├── messaging/            # Rooms, messages, delivery
│   ├── groups/               # Group membership, garden, sender keys
│   ├── network/              # Gossip, relay deposit, federation, threat context
│   ├── routing/              # Path selection, store-and-forward, tunnel gossip
│   ├── transport/            # All transport backends (Tor, I2P, WG, BLE, …)
│   ├── mesh/                 # Mesh coordinator and forwarder
│   ├── files/                # File transfer and hosted storage
│   ├── calls/                # Voice/video call signalling
│   ├── vpn/                  # Exit-node VPN routing
│   ├── services/             # Module system, plugin registry, port policy
│   ├── notifications/        # Notification delivery
│   ├── storage/              # Encrypted vault
│   └── ffi/                  # C FFI bindings (Dart ↔ Rust)
├── frontend/                  # Flutter UI — single codebase, all platforms
│   └── lib/
│       ├── backend/          # FFI bridge, event bus, data models
│       ├── features/         # messaging / files / peers / network / settings / calls
│       └── shell/            # Responsive shell (mobile/tablet/desktop)
├── platforms/                 # Native host projects
│   ├── android/              # Gradle project — embeds Flutter AAR + Rust .so
│   ├── apple/                # Xcode project (Runner = macOS, RunnerIOS = iOS)
│   ├── linux/                # CMake + GTK runner
│   └── windows/              # Windows runner + NSIS installer
├── Makefile                   # Canonical cross-platform build entry point
└── build/                     # All artifacts (gitignored)
    ├── intermediates/        # Per-platform build intermediates
    └── output/               # Final packaged artifacts
```

## Architecture

```
┌─────────────────────────────────┐
│  Native host (Xcode / Gradle)   │  ← primary application
├─────────────────────────────────┤
│  Rust backend (mesh-infinity)   │  ← business logic, transports, crypto
│  cdylib / staticlib / rlib      │
├─────────────────────────────────┤
│  Flutter UI (embedded)          │  ← UI only, no business logic
│  XCFramework / AAR / .so        │
└─────────────────────────────────┘
```

The FFI bridge in `frontend/lib/backend/backend_bridge.dart` is the only contact point between Dart and Rust.

## Development

### Adding a Feature

1. **Backend**: Implement in the appropriate `backend/{module}/` directory
2. **FFI**: Expose via `backend/ffi/lib.rs` and mirror in `frontend/lib/backend/backend_bridge.dart`
3. **UI**: Add screen/state under `frontend/lib/features/{feature}/`

### Cargo Features

| Feature | Description |
|---|---|
| `transport-bluetooth-native` | BLE transport via `btleplug` |
| `transport-rf-meshtastic` | RF transport via Meshtastic |
| `vpn-routing` | Full-tunnel VPN routing |

## Contributor Standards

Every committed file must meet all of the following before merging. These are the minimum requirements — all three pillars (standards compliance, spec compliance, and human accuracy review) are required for code to be considered complete.

### The 11 Standards

1. **No suppressed warnings or errors.** Compiler warnings and lints are valid feedback. Fix them. `#[allow(...)]`, `@SuppressWarnings`, and equivalent suppression annotations are not permitted.

2. **No stub implementations.** Every committed function must do what it claims. `todo!()`, `unimplemented!()`, hardcoded placeholder return values, and no-op bodies are not permitted.

3. **Adversarial test coverage.** Tests must cover attacker-controlled inputs, malformed data, replay attacks, and boundary conditions — not only the happy path.

4. **Spec compliance.** Code must implement what the specification says. Deviations must be explicitly noted in comments and raised as findings.

5. **No duplicate implementations.** Reuse and improve existing code. Multiple implementations of the same concept, unused typedefs, and unnecessary imports are not permitted.

6. **No silent failures.** Errors on security-critical paths must be propagated or explicitly handled. `let _ =` discards and `.ok()` on write/save/crypto operations are not permitted.

7. **Panic safety.** Production code must not panic through the FFI boundary. `.unwrap()` and `.expect()` are not permitted in paths reachable from FFI or concurrent contexts. Use `?`, `unwrap_or_else`, or explicit error handling.

8. **Project conventions.** This project uses `snake_case` throughout Rust and Dart.

9. **Proper error handling.** Errors must be typed, propagated with `?`, and handled at the appropriate boundary.

10. **Readable implementation.** Code must be simple and direct. If a block requires external context to understand, it needs refactoring or comments.

11. **Sufficient comments.** On average, every line of code should have two lines of comments. Explain intent, context, and reasoning — not what the code literally does.

### Commit messages

Format: `type(scope): description` (Conventional Commits)

The only permitted LLM reference in a commit message is crediting a specific discovery:
> finding surfaced by review from (LLM name)

Commit messages describe the code change. The developer is the author.

## CI / Releases

GitHub Actions builds all platforms on every push to `main`. Successful release builds are published as GitHub prereleases with native artifacts attached.

## License

To be determined.
