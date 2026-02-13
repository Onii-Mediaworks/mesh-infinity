# Project Structure

Mesh Infinity is organized as a unified codebase with platform-specific integrations.

## Directory Layout

```
mesh-infinity/
├── src/                    # Rust library entry point
│   ├── lib.rs             # Main module (re-exports backend modules)
│   └── runtime.rs         # Runtime configuration
├── backend/               # Rust backend modules (organized as internal modules)
│   ├── core/             # Core mesh networking primitives
│   ├── auth/             # Authentication and web of trust
│   ├── crypto/           # Cryptographic operations
│   ├── mesh/             # Mesh routing and topology
│   ├── transport/        # Transport layer (Tor, I2P, Clearnet)
│   ├── discovery/        # Peer discovery (mDNS, DHT)
│   ├── ffi/              # C FFI bindings for Flutter
│   └── src/              # Backend service implementation
├── frontend/             # Flutter UI (multi-platform)
│   ├── lib/             # Dart source code
│   ├── android/         # Android platform integration
│   ├── ios/             # iOS platform integration
│   ├── macos/           # macOS platform integration
│   ├── linux/           # Linux platform integration
│   └── windows/         # Windows platform integration
├── build/               # Build artifacts (gitignored)
│   ├── output/         # Final packaged applications
│   ├── intermediates/  # Build intermediates
│   └── logs/           # Build logs
├── scripts/            # Build and deployment scripts
│   ├── build.sh       # Organized build script
│   └── build_unified.sh # Original build script (compat)
├── plans/             # Implementation plans and roadmap
└── assets/            # Shared assets
```

## Architecture

### Single Rust Crate
All Rust code compiles into a single `mesh-infinity` crate that produces:
- **cdylib**: Dynamic library for Flutter FFI integration
- **staticlib**: Static library for embedding
- **rlib**: Rust library for tooling

### Flutter Multi-Platform
The Flutter frontend is a single codebase with platform-specific runners:
- Android and iOS use the same Dart code with platform channels
- Desktop platforms (macOS, Linux, Windows) share the same implementation
- All platforms use the same Rust backend via FFI

### No Platform Separation
Platform-specific code lives in `frontend/{platform}/` directories as standard Flutter platform integration, not as separate projects. This ensures:
- Single source of truth for UI
- Shared business logic
- Consistent user experience
- Easier maintenance

## Build Process

The build system is organized to keep all artifacts in the `build/` directory:

1. **Rust Backend** → `build/intermediates/{profile}/libmesh_infinity.{so,dylib,dll}`
2. **Flutter Frontend** → Platform-specific bundles
3. **Final Package** → `build/output/{platform}/meshinfinity-{version}-{profile}.{tar.gz,dmg,zip}`

See [build/README.md](build/README.md) for detailed build documentation.

## Development Workflow

### Building
```bash
# Build for current platform
./scripts/build.sh --profile debug

# Build all profiles (CI/CD)
./scripts/build.sh --all --clean
```

### Platform Development
- **Rust changes**: Edit files in `backend/` or `src/`
- **UI changes**: Edit files in `frontend/lib/`
- **Platform integration**: Edit platform-specific files in `frontend/{platform}/`

### Adding Features
1. Implement backend logic in appropriate `backend/` module
2. Add FFI bindings in `backend/ffi/src/lib.rs`
3. Add Dart bindings in `frontend/lib/backend/backend_bridge.dart`
4. Implement UI in `frontend/lib/`

## Module Organization

### Rust Library Structure
The `src/` directory is the Rust library entry point (required by Cargo):
- `src/lib.rs` - Main library module that re-exports all backend modules
- `src/runtime.rs` - Runtime configuration and initialization

### Backend Modules
Each directory under `backend/` is an internal module with `src/lib.rs`:
- Pulled into main crate via `#[path = "../backend/{module}/src/lib.rs"]` in `src/lib.rs`
- Not separate crates (no individual Cargo.toml files)
- Organized for logical separation, compiled as one unit
- All accessible through the main `mesh_infinity` library

**Why use path attributes?**
- Keeps related code organized in `backend/` subdirectories
- Allows each module to have its own internal structure
- Still compiles as a single crate for FFI simplicity
- Standard Cargo project structure with `src/lib.rs` as entry point

### Why This Structure?
- **Simpler dependencies**: No workspace complexity
- **Unified versioning**: One version number for entire backend
- **Easier FFI**: All backend code available in one library
- **Fast compilation**: Better optimization across modules
- **Logical organization**: Backend code separated by concern while remaining one crate
