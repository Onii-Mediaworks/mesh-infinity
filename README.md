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

All platforms require:
- **Rust** stable toolchain (`rustup`)
- **Flutter** SDK 3.30+

| Platform | Additional requirements |
|---|---|
| **Linux** | `clang`, `cmake`, `ninja-build`, `pkg-config`, `libgtk-3-dev` (and other GTK/X11 libs — see CI workflow for the full list) |
| **Linux packages** | `fpm` (`gem install fpm`) · `rpm` system package (for `.rpm`) · `appimagetool` + `libfuse2` (for `.AppImage`) |
| **Windows** | Flutter Windows desktop toolchain; Visual Studio 2022 Build Tools with MSVC (required by Rust) |
| **macOS** | Xcode with Command Line Tools |
| **iOS** | Xcode; `rustup target add aarch64-apple-ios x86_64-apple-ios` |
| **Android** | Android SDK/NDK; `cargo install cargo-ndk --locked`; `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` |

> **Windows self-contained?** Yes. The output directory contains the Flutter engine, Dart code, all assets, and `mesh_infinity.dll` (the Rust backend). End users need only the Visual C++ Redistributable, which is pre-installed on Windows 10/11. Note: TUN/VPN functionality is not available on Windows (POSIX-only); all other backend features compile and run normally.

### Building

```bash
# Canonical build entrypoint
make build-debug OS=linux
make build-release OS=macos UNSIGNED=1
make build-both OS=macos,ios UNSIGNED=1

# Convenience wrapper (delegates to Makefile)
./scripts/build.sh --os ios --profile debug --unsigned
```

Linux builds produce four artifacts: `.tar.gz`, `.deb`, `.rpm`, and `.AppImage`.

### Running

```bash
# After building, run the platform-specific executable
# macOS
open build/output/<timestamp>/macos/meshinfinity-*.app

# Linux (tarball)
tar -xzf build/output/<timestamp>/linux/meshinfinity-*-debug.tar.gz -C /tmp/mi
/tmp/mi/meshinfinity

# Linux (AppImage)
chmod +x build/output/<timestamp>/linux/meshinfinity-*.AppImage
./build/output/<timestamp>/linux/meshinfinity-*.AppImage

# Or use Flutter directly for development
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
