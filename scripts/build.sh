#!/usr/bin/env bash
# Build script following build-configuration.md plan
set -euo pipefail

# Disable output buffering for better real-time feedback
export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend"

# Build directories as per build-configuration.md
BUILD_DIR="$ROOT_DIR/build"
OUTPUT_DIR="$BUILD_DIR/output"
INTERMEDIATES_DIR="$BUILD_DIR/intermediates"
RUST_INTERMEDIATE_DIR="$INTERMEDIATES_DIR/rust"
FLUTTER_INTERMEDIATE_DIR="$INTERMEDIATES_DIR/flutter"
LOGS_DIR="$BUILD_DIR/logs"

# Default build configuration
PROFILE="release"
VERSION=""
BUILD_OS=""

usage() {
  cat <<EOF
Usage: build.sh [OPTIONS]

Build Mesh Infinity following organized directory structure.

OPTIONS:
  --profile <debug|release>  Build profile (default: release)
  --os <linux|macos|windows|ios> Target OS (default: current OS)
  --unsigned                 Skip code signing on all platforms
  --clean                    Clean build directories before building
  --all                      Build all profiles (debug + release) for current OS
  -h, --help                 Show this help message

EXAMPLES:
  ./build.sh --profile release --os macos
  ./build.sh --profile debug --os ios --unsigned
  ./build.sh --clean --profile debug
  ./build.sh --all                        # Build both debug and release
  ./build.sh --all --unsigned             # Build all, skip signing

DIRECTORY STRUCTURE:
  build/
  ├── output/               Final packaged artifacts
  │   ├── linux/
  │   ├── macos/
  │   ├── ios/
  │   └── windows/
  ├── intermediates/        Build intermediates (Rust artifacts)
  │   ├── debug/
  │   └── release/
  └── logs/                 Build logs
EOF
}

log() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  # Ensure logs directory exists
  mkdir -p "$LOGS_DIR" 2>/dev/null || true
  echo "[$timestamp] $*" | tee -a "$LOGS_DIR/build.log"
}

detect_os() {
  case "$(uname -s)" in
    Darwin*) echo "macos" ;;
    Linux*) echo "linux" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

get_version() {
  grep -E '^version\s*=\s*"' "$ROOT_DIR/Cargo.toml" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/'
}

clean_build_dir() {
  log "Cleaning build directory..."
  rm -rf "$OUTPUT_DIR"
  rm -rf "$INTERMEDIATES_DIR"
  mkdir -p "$OUTPUT_DIR"/{linux,macos,ios,windows}
  mkdir -p "$RUST_INTERMEDIATE_DIR"/{backend,ffi}
  mkdir -p "$FLUTTER_INTERMEDIATE_DIR"
  mkdir -p "$LOGS_DIR"
  log "Build directory cleaned"
}

setup_build_dirs() {
  log "Setting up build directories..."
  mkdir -p "$OUTPUT_DIR"/{linux,macos,ios,windows}
  mkdir -p "$RUST_INTERMEDIATE_DIR"/{backend,ffi}
  mkdir -p "$FLUTTER_INTERMEDIATE_DIR"
  mkdir -p "$LOGS_DIR"
  log "Build directories ready"
}

build_rust_backend() {
  log "Building Rust backend..."
  local cargo_flags=""
  if [[ "$PROFILE" == "release" ]]; then
    cargo_flags="--release"
  fi

  # Build mesh-infinity package (includes FFI as cdylib)
  cd "$ROOT_DIR"
  log "Building mesh-infinity package (includes FFI)..."
  if ! CARGO_TARGET_DIR="$RUST_INTERMEDIATE_DIR" \
    cargo build -p mesh-infinity $cargo_flags 2>&1 | tee -a "$LOGS_DIR/rust-build.log"; then
    log "ERROR: Rust build failed. Check $LOGS_DIR/rust-build.log"
    exit 1
  fi

  log "Rust backend build complete"
}

build_rust_ios() {
  log "Building Rust static library for iOS..."
  local cargo_flags=""
  if [[ "$PROFILE" == "release" ]]; then
    cargo_flags="--release"
  fi

  cd "$ROOT_DIR"

  # Build for device (arm64)
  log "Building for aarch64-apple-ios..."
  if ! CARGO_TARGET_DIR="$RUST_INTERMEDIATE_DIR" \
    cargo build -p mesh-infinity --target aarch64-apple-ios $cargo_flags 2>&1 | tee -a "$LOGS_DIR/rust-ios-build.log"; then
    log "ERROR: iOS arm64 Rust build failed. Check $LOGS_DIR/rust-ios-build.log"
    exit 1
  fi

  # Build for simulator (x86_64) - useful for testing
  log "Building for x86_64-apple-ios (simulator)..."
  if ! CARGO_TARGET_DIR="$RUST_INTERMEDIATE_DIR" \
    cargo build -p mesh-infinity --target x86_64-apple-ios $cargo_flags 2>&1 | tee -a "$LOGS_DIR/rust-ios-build.log"; then
    log "WARNING: iOS x86_64 simulator build failed (non-fatal)"
  fi

  log "Rust iOS build complete"
}

build_flutter_frontend() {
  log "Building Flutter frontend for $BUILD_OS..."
  local flutter_flags=""
  if [[ "$PROFILE" == "release" ]]; then
    flutter_flags="--release"
  else
    flutter_flags="--debug"
  fi

  cd "$FRONTEND_DIR"

  # Export MESH_UNSIGNED so Xcode build phases can skip signing
  if [[ "$UNSIGNED" == "true" ]]; then
    export MESH_UNSIGNED=1
  fi

  local build_result=0
  case "$BUILD_OS" in
    macos)
      if ! flutter build macos $flutter_flags 2>&1 | tee -a "$LOGS_DIR/flutter-macos.log"; then
        log "ERROR: Flutter macOS build failed. Check $LOGS_DIR/flutter-macos.log"
        exit 1
      fi
      ;;
    linux)
      if ! flutter build linux $flutter_flags 2>&1 | tee -a "$LOGS_DIR/flutter-linux.log"; then
        log "ERROR: Flutter Linux build failed. Check $LOGS_DIR/flutter-linux.log"
        exit 1
      fi
      ;;
    windows)
      if ! flutter build windows $flutter_flags 2>&1 | tee -a "$LOGS_DIR/flutter-windows.log"; then
        log "ERROR: Flutter Windows build failed. Check $LOGS_DIR/flutter-windows.log"
        exit 1
      fi
      ;;
    ios)
      if ! flutter build ios $flutter_flags --no-codesign 2>&1 | tee -a "$LOGS_DIR/flutter-ios.log"; then
        log "ERROR: Flutter iOS build failed. Check $LOGS_DIR/flutter-ios.log"
        exit 1
      fi
      ;;
    *)
      log "ERROR: Unsupported OS: $BUILD_OS"
      exit 1
      ;;
  esac

  log "Flutter frontend build complete"
}

package_macos() {
  log "Packaging macOS application..."

  local build_config="Release"
  if [[ "$PROFILE" == "debug" ]]; then
    build_config="Debug"
  fi

  # Get product name from Flutter config
  local macos_product_name
  macos_product_name="$(grep -E '^PRODUCT_NAME\s*=' "$FRONTEND_DIR/macos/Runner/Configs/AppInfo.xcconfig" | head -n1 | cut -d '=' -f2- | xargs || echo "Runner")"

  local flutter_app="$FRONTEND_DIR/build/macos/Build/Products/$build_config/${macos_product_name}.app"
  local output_app="$OUTPUT_DIR/macos/meshinfinity-${VERSION}-${PROFILE}.app"

  # Check if Flutter app exists
  if [[ ! -d "$flutter_app" ]]; then
    log "ERROR: Flutter app not found at $flutter_app"
    log "Flutter build may have failed or produced output in unexpected location"
    exit 1
  fi

  # Copy Flutter app
  log "Copying Flutter app from $flutter_app"
  rm -rf "$output_app"
  cp -R "$flutter_app" "$output_app"

  # Copy Rust dylib from build
  local dylib_path="$RUST_INTERMEDIATE_DIR/$PROFILE/libmesh_infinity.dylib"
  if [[ ! -f "$dylib_path" ]]; then
    # Try alternate location (target-specific subdirectory)
    dylib_path="$RUST_INTERMEDIATE_DIR/aarch64-apple-darwin/$PROFILE/libmesh_infinity.dylib"
  fi
  if [[ ! -f "$dylib_path" ]]; then
    # Try x86_64 location
    dylib_path="$RUST_INTERMEDIATE_DIR/x86_64-apple-darwin/$PROFILE/libmesh_infinity.dylib"
  fi

  if [[ -f "$dylib_path" ]]; then
    mkdir -p "$output_app/Contents/Frameworks"
    mkdir -p "$output_app/Contents/MacOS"
    cp -f "$dylib_path" "$output_app/Contents/Frameworks/"
    cp -f "$dylib_path" "$output_app/Contents/MacOS/"
    log "Copied Rust dylib to app bundle"
  else
    log "WARNING: Could not find Rust dylib at $dylib_path"
  fi

  # Create DMG
  local dmg_output="$OUTPUT_DIR/macos/meshinfinity-${VERSION}-${PROFILE}.dmg"
  if command -v hdiutil >/dev/null 2>&1; then
    rm -f "$dmg_output"
    hdiutil create -volname "Mesh Infinity $VERSION" -srcfolder "$output_app" -ov -format UDZO "$dmg_output" 2>&1 | tee -a "$LOGS_DIR/package-macos.log"
    log "Created DMG: $dmg_output"
  fi

  log "macOS packaging complete"
}

package_ios() {
  log "Packaging iOS application..."

  local flutter_app="$FRONTEND_DIR/build/ios/iphoneos/Runner.app"
  local output_app="$OUTPUT_DIR/ios/meshinfinity-${VERSION}-${PROFILE}.app"

  # Check if Flutter app exists
  if [[ ! -d "$flutter_app" ]]; then
    log "ERROR: Flutter iOS app not found at $flutter_app"
    log "Flutter build may have failed or produced output in unexpected location"
    exit 1
  fi

  # Copy Flutter app
  log "Copying iOS app from $flutter_app"
  rm -rf "$output_app"
  cp -R "$flutter_app" "$output_app"

  # For iOS, the static library should be linked during the Flutter build.
  # Verify it was linked by checking the binary.
  local static_lib="$RUST_INTERMEDIATE_DIR/aarch64-apple-ios/$PROFILE/libmesh_infinity.a"
  if [[ -f "$static_lib" ]]; then
    log "Rust static library found at $static_lib"
  else
    log "WARNING: Rust static library not found at $static_lib"
  fi

  # Create an xcarchive-style output for later IPA generation
  local archive_dir="$OUTPUT_DIR/ios/meshinfinity-${VERSION}-${PROFILE}.xcarchive"
  mkdir -p "$archive_dir/Products/Applications"
  cp -R "$output_app" "$archive_dir/Products/Applications/meshinfinity.app"

  # Generate IPA if possible (requires valid code signing)
  local ipa_output="$OUTPUT_DIR/ios/meshinfinity-${VERSION}-${PROFILE}.ipa"
  local payload_dir
  payload_dir=$(mktemp -d)
  mkdir -p "$payload_dir/Payload"
  cp -R "$output_app" "$payload_dir/Payload/meshinfinity.app"
  cd "$payload_dir"
  if zip -r "$ipa_output" Payload 2>&1 | tee -a "$LOGS_DIR/package-ios.log"; then
    log "Created IPA: $ipa_output"
  else
    log "WARNING: IPA creation failed"
  fi
  rm -rf "$payload_dir"

  log "iOS packaging complete"
}

package_linux() {
  log "Packaging Linux application..."

  local flutter_bundle="$FRONTEND_DIR/build/linux/x64/$PROFILE/bundle"
  local output_bundle="$OUTPUT_DIR/linux/meshinfinity-${VERSION}-${PROFILE}"

  # Check if Flutter bundle exists
  if [[ ! -d "$flutter_bundle" ]]; then
    log "ERROR: Flutter bundle not found at $flutter_bundle"
    log "Flutter build may have failed or produced output in unexpected location"
    exit 1
  fi

  # Copy Flutter bundle
  log "Copying Flutter bundle from $flutter_bundle"
  rm -rf "$output_bundle"
  cp -R "$flutter_bundle" "$output_bundle"

  # Copy Rust .so from build
  local so_path="$RUST_INTERMEDIATE_DIR/$PROFILE/libmesh_infinity.so"
  if [[ ! -f "$so_path" ]]; then
    # Try alternate location (target-specific subdirectory)
    so_path="$RUST_INTERMEDIATE_DIR/x86_64-unknown-linux-gnu/$PROFILE/libmesh_infinity.so"
  fi
  if [[ ! -f "$so_path" ]]; then
    # Try aarch64 location
    so_path="$RUST_INTERMEDIATE_DIR/aarch64-unknown-linux-gnu/$PROFILE/libmesh_infinity.so"
  fi

  if [[ -f "$so_path" ]]; then
    cp -f "$so_path" "$output_bundle/lib/"
    log "Copied Rust .so to bundle"
  else
    log "WARNING: Could not find Rust .so at $so_path"
  fi

  # Create tar.gz
  local tarball="$OUTPUT_DIR/linux/meshinfinity-${VERSION}-${PROFILE}.tar.gz"
  cd "$OUTPUT_DIR/linux"
  tar -czf "$tarball" "meshinfinity-${VERSION}-${PROFILE}" 2>&1 | tee -a "$LOGS_DIR/package-linux.log"
  log "Created tarball: $tarball"

  log "Linux packaging complete"
}

package_windows() {
  log "Packaging Windows application..."

  local build_config="Release"
  if [[ "$PROFILE" == "debug" ]]; then
    build_config="Debug"
  fi

  local flutter_bundle="$FRONTEND_DIR/build/windows/x64/runner/$build_config"
  local output_bundle="$OUTPUT_DIR/windows/meshinfinity-${VERSION}-${PROFILE}"

  # Check if Flutter bundle exists
  if [[ ! -d "$flutter_bundle" ]]; then
    log "ERROR: Flutter bundle not found at $flutter_bundle"
    log "Flutter build may have failed or produced output in unexpected location"
    exit 1
  fi

  # Copy Flutter bundle
  log "Copying Flutter bundle from $flutter_bundle"
  rm -rf "$output_bundle"
  cp -R "$flutter_bundle" "$output_bundle"

  # Copy Rust DLL from build
  local dll_path="$RUST_INTERMEDIATE_DIR/$PROFILE/mesh_infinity.dll"
  if [[ ! -f "$dll_path" ]]; then
    # Try alternate location (target-specific subdirectory)
    dll_path="$RUST_INTERMEDIATE_DIR/x86_64-pc-windows-msvc/$PROFILE/mesh_infinity.dll"
  fi
  if [[ ! -f "$dll_path" ]]; then
    # Try aarch64 location
    dll_path="$RUST_INTERMEDIATE_DIR/aarch64-pc-windows-msvc/$PROFILE/mesh_infinity.dll"
  fi

  if [[ -f "$dll_path" ]]; then
    cp -f "$dll_path" "$output_bundle/"
    log "Copied Rust DLL to bundle"
  else
    log "WARNING: Could not find Rust DLL at $dll_path"
  fi

  # Create zip
  if command -v zip >/dev/null 2>&1; then
    local zip_output="$OUTPUT_DIR/windows/meshinfinity-${VERSION}-${PROFILE}.zip"
    cd "$OUTPUT_DIR/windows"
    zip -r "$zip_output" "meshinfinity-${VERSION}-${PROFILE}" 2>&1 | tee -a "$LOGS_DIR/package-windows.log"
    log "Created ZIP: $zip_output"
  fi

  log "Windows packaging complete"
}

validate_build() {
  log "Validating build artifacts..."

  local output_path="$OUTPUT_DIR/$BUILD_OS"
  local expected_files=0
  local found_files=0

  case "$BUILD_OS" in
    macos)
      [[ -d "$output_path/meshinfinity-${VERSION}-${PROFILE}.app" ]] && ((found_files++))
      [[ -f "$output_path/meshinfinity-${VERSION}-${PROFILE}.dmg" ]] && ((found_files++))
      expected_files=2
      ;;
    ios)
      [[ -d "$output_path/meshinfinity-${VERSION}-${PROFILE}.app" ]] && ((found_files++))
      [[ -f "$output_path/meshinfinity-${VERSION}-${PROFILE}.ipa" ]] && ((found_files++))
      expected_files=2
      ;;
    linux)
      [[ -d "$output_path/meshinfinity-${VERSION}-${PROFILE}" ]] && ((found_files++))
      [[ -f "$output_path/meshinfinity-${VERSION}-${PROFILE}.tar.gz" ]] && ((found_files++))
      expected_files=2
      ;;
    windows)
      [[ -d "$output_path/meshinfinity-${VERSION}-${PROFILE}" ]] && ((found_files++))
      [[ -f "$output_path/meshinfinity-${VERSION}-${PROFILE}.zip" ]] && ((found_files++))
      expected_files=2
      ;;
  esac

  log "Found $found_files of $expected_files expected artifacts"

  if [[ $found_files -eq $expected_files ]]; then
    log "✓ Build validation passed"
    return 0
  else
    log "✗ Build validation failed: missing artifacts"
    return 1
  fi
}

# Parse command line arguments
CLEAN_BUILD=false
BUILD_ALL=false
UNSIGNED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --os)
      BUILD_OS="$2"
      shift 2
      ;;
    --unsigned)
      UNSIGNED=true
      shift
      ;;
    --clean)
      CLEAN_BUILD=true
      shift
      ;;
    --all)
      BUILD_ALL=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

# Handle --all flag (build all profiles for current platform)
if [[ "$BUILD_ALL" == "true" ]]; then
  VERSION=$(get_version)
  if [[ -z "$VERSION" ]]; then
    echo "ERROR: Failed to read version from Cargo.toml"
    exit 1
  fi

  CURRENT_OS=$(detect_os)
  log "========================================"
  log "Building ALL profiles for $CURRENT_OS"
  log "Version: $VERSION"
  log "========================================"

  # Setup build directories once
  if [[ "$CLEAN_BUILD" == "true" ]]; then
    clean_build_dir
  else
    setup_build_dirs
  fi

  # Build both profiles
  for profile in debug release; do
    log ""
    log "========================================"
    log "Building $profile profile..."
    log "========================================"

    PROFILE="$profile"
    BUILD_OS="$CURRENT_OS"

    # Build process
    if [[ "$BUILD_OS" == "ios" ]]; then
      build_rust_ios
    else
      build_rust_backend
    fi
    build_flutter_frontend

    # Package for target OS
    case "$BUILD_OS" in
      macos)
        package_macos
        ;;
      ios)
        package_ios
        ;;
      linux)
        package_linux
        ;;
      windows)
        package_windows
        ;;
      *)
        log "ERROR: Unsupported OS: $BUILD_OS"
        exit 1
        ;;
    esac

    # Validate build
    if ! validate_build; then
      log "WARNING: Build validation failed for $profile"
    fi
  done

  log ""
  log "========================================"
  log "All builds completed!"
  log "Output directory: $OUTPUT_DIR/$CURRENT_OS"
  log "========================================"
  exit 0
fi

# Validate profile
if [[ "$PROFILE" != "debug" && "$PROFILE" != "release" ]]; then
  echo "ERROR: Invalid profile '$PROFILE'. Must be 'debug' or 'release'."
  exit 1
fi

# Detect OS if not specified
if [[ -z "$BUILD_OS" ]]; then
  BUILD_OS=$(detect_os)
  log "Detected OS: $BUILD_OS"
fi

# Get version
VERSION=$(get_version)
if [[ -z "$VERSION" ]]; then
  echo "ERROR: Failed to read version from Cargo.toml"
  exit 1
fi

log "========================================"
log "Mesh Infinity Build"
log "Version: $VERSION"
log "Profile: $PROFILE"
log "Target OS: $BUILD_OS"
log "========================================"

# Setup or clean build directories
if [[ "$CLEAN_BUILD" == "true" ]]; then
  clean_build_dir
else
  setup_build_dirs
fi

# Build process
if [[ "$BUILD_OS" == "ios" ]]; then
  build_rust_ios
else
  build_rust_backend
fi
build_flutter_frontend

# Package for target OS
case "$BUILD_OS" in
  macos)
    package_macos
    ;;
  ios)
    package_ios
    ;;
  linux)
    package_linux
    ;;
  windows)
    package_windows
    ;;
  *)
    log "ERROR: Unsupported OS: $BUILD_OS"
    exit 1
    ;;
esac

# Validate build
if validate_build; then
  log "========================================"
  log "Build completed successfully!"
  log "Output directory: $OUTPUT_DIR/$BUILD_OS"
  log "========================================"
  exit 0
else
  log "========================================"
  log "Build completed with warnings"
  log "Output directory: $OUTPUT_DIR/$BUILD_OS"
  log "========================================"
  exit 1
fi
