# Mesh Infinity

A decentralized mesh networking platform with multi-transport support, web-of-trust authentication, and cross-platform client applications.

## Features

- **Multi-Transport**: Tor, I2P, Clearnet, Bluetooth (planned)
- **Web of Trust**: Decentralized peer authentication
- **WireGuard Integration**: Secure mesh networking
- **Cross-Platform**: iOS, Android, macOS, Linux, Windows
- **Exit Nodes**: VPN-style routing through the mesh
- **File Transfer**: Peer-to-peer file sharing
- **Local Discovery**: mDNS/Bonjour for LAN peers

## Quick Start

### Prerequisites
- Rust toolchain (latest stable)
- Flutter SDK (3.30+)
- Platform-specific build tools (Xcode for macOS/iOS, Android SDK, etc.)

### Building

```bash
# Canonical build entrypoint
make build-debug OS=linux
make build-release OS=macos UNSIGNED=1
make build-both OS=macos,ios UNSIGNED=1

# Convenience wrapper (delegates to Makefile)
./scripts/build.sh --os ios --profile debug --unsigned
```

See [build/README.md](build/README.md) for detailed build instructions and options.

### Running

```bash
# After building, run the platform-specific executable
# macOS
open build/output/<timestamp>/macos/meshinfinity-*.app

# Linux
./build/output/<timestamp>/linux/meshinfinity-*/mesh_infinity_frontend

# Or use Flutter directly
cd frontend && flutter run
```

## Project Structure

See [STRUCTURE.md](STRUCTURE.md) for a detailed explanation of the project organization.

**Key directories:**
- `backend/` - Rust backend modules (mesh, crypto, auth, transport, etc.)
- `frontend/` - Flutter UI (single codebase for all platforms)
- `platforms/` - Platform-specific host projects (Android, Apple, Linux, Windows)
- `Makefile` - Canonical cross-platform build entrypoint
- `scripts/` - Helper/convenience scripts
- `build/` - All build artifacts (gitignored)

## Architecture

Mesh Infinity uses a **unified architecture**:
- Single Rust crate for all backend code
- Single Flutter app for all platforms
- FFI bridge connecting Rust ↔ Dart
- No platform separation - platform-specific code only where required

## Development

### Adding a Feature

1. **Backend**: Implement in `backend/{module}/`
2. **FFI**: Add C bindings in `backend/ffi/lib.rs`
3. **Dart Bridge**: Add Dart bindings in `frontend/lib/backend/backend_bridge.dart`
4. **UI**: Implement in `frontend/lib/`

### Code Organization

- Rust code is organized as internal modules under `backend/`
- All modules compile into one `mesh-infinity` crate (cdylib + rlib)
- Flutter code follows standard Flutter project structure
- Platform integrations in `platforms/{android,apple,linux,windows}/`

## Implementation Status

**Current version**: 0.1.1

## License

[To be determined]

## Contributing

[Contribution guidelines to be added]
