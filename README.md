# Mesh Infinity

A decentralized mesh networking application with multi-transport support, web-of-trust authentication, and secure peer-to-peer file transfer.

**Architecture**: Rust application with an embedded Flutter UI. The Rust crate is the primary artifact on every platform — Flutter is compiled to a native library and embedded into the host project, not the other way around.

## Features

- **Multi-Transport**: Tor, I2P, Clearnet, Bluetooth (BLE), RF/Meshtastic
- **Web of Trust**: Decentralized peer authentication with attestation
- **WireGuard Integration**: Mesh-wide VPN routing via exit nodes
- **Peer-to-Peer File Transfer**: Direct file sharing with contacts, outside of conversations
- **File Hosting Services**: Serve files to trusted peers via configurable service endpoints
- **Encrypted Messaging**: End-to-end encrypted conversations over the mesh
- **Local Discovery**: mDNS/Bonjour for zero-config LAN peers
- **Cross-Platform**: macOS, Android, iOS (in progress), Linux (in progress), Windows (planned)

## Quick Start

### Prerequisites

| Requirement | Version |
|---|---|
| Rust (stable) | `rustup toolchain install stable` |
| Flutter | 3.41+ (stable channel) |

Platform-specific requirements:

| Platform | Additional requirements |
|---|---|
| **macOS** | Xcode with Command Line Tools |
| **Android** | Android SDK + NDK; `cargo install cargo-ndk` |
| **iOS** | Xcode; `rustup target add aarch64-apple-ios` |
| **Linux** | `clang`, `cmake`, `ninja-build`, `pkg-config`, `libgtk-3-dev` |

### Building

```bash
# macOS
make macos-debug
make macos-release

# Android
make android-debug
make android-release
```

Output artifacts land in `build/output/<os>/<profile>/`:
- macOS → `meshinfinity-0.2.0-<profile>.dmg`
- Android → `meshinfinity-0.2.0-<profile>.apk`

## Project Structure

```
mesh-infinity/
├── src/                    # Rust crate entry point
│   ├── lib.rs             # Re-exports all backend modules
│   └── runtime.rs         # Runtime configuration
├── backend/               # Rust backend modules (single crate)
│   ├── auth/             # Web-of-trust authentication
│   ├── core/             # Mesh networking primitives
│   ├── crypto/           # Cryptographic operations
│   ├── discovery/        # Peer discovery (mDNS, DHT)
│   ├── ffi/              # C FFI bindings (Dart ↔ Rust)
│   ├── service/          # Backend service implementation
│   └── transport/        # Transports (Tor, I2P, Clearnet, BLE, RF)
├── frontend/              # Flutter UI — single codebase for all platforms
│   └── lib/
│       ├── backend/      # FFI bridge + event bus + data models
│       ├── features/     # chat / files / peers / network / settings
│       └── shell/        # Responsive app shell (mobile/tablet/desktop)
├── platforms/             # Native host projects
│   ├── android/          # Gradle project — embeds Flutter AAR + Rust .so
│   ├── apple/            # Single Xcode project (Runner = macOS, RunnerIOS = iOS)
│   ├── linux/            # CMake + GTK runner
│   └── windows/          # Windows runner
├── Makefile               # Canonical cross-platform build entrypoint
└── build/                 # All build artifacts (gitignored)
    ├── intermediates/    # Per-platform build intermediates
    └── output/           # Final packaged artifacts
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

The FFI bridge in `frontend/lib/backend/backend_bridge.dart` is the only point of contact between the Dart layer and the Rust library.

## Development

### Adding a Feature

1. **Backend**: Implement in the appropriate `backend/{module}/` directory
2. **FFI**: Add a C binding in `backend/ffi/lib.rs` + `BackendBridge` in `frontend/lib/backend/backend_bridge.dart`
3. **UI**: Implement screen/state in `frontend/lib/features/{feature}/`

### Cargo Features

| Feature | Description |
|---|---|
| `transport-bluetooth-native` | BLE transport via `btleplug` |
| `transport-rf-meshtastic` | RF transport via Meshtastic |
| `vpn-routing` | Full-tunnel VPN routing (requires root/CAP_NET_ADMIN) |

## CI / Releases

GitHub Actions builds all platforms on every push. On pushes to `main`, successful builds are published as a GitHub prerelease with the native artifacts attached (`.dmg`, `.apk`).

## Current Version

**0.2.0**

## License

To be determined.
