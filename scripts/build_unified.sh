#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend"

profile="debug"
platforms=("macos" "android" "ios" "linux" "windows")

usage() {
  echo "Usage: build_unified.sh [--profile <debug|release>] [--platforms <comma-separated>]"
  echo "Android ABIs: set ANDROID_ABIS=arm64-v8a,x86_64,armeabi-v7a to build universal APKs."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      profile="$2"
      shift 2
      ;;
    --platforms)
      IFS="," read -r -a platforms <<< "$2"
      shift 2
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

if [[ "$profile" != "debug" && "$profile" != "release" ]]; then
  echo "Unsupported profile: $profile"
  usage
  exit 1
fi

version=$(cd "$ROOT_DIR" && grep -E '^version\s*=\s*"' Cargo.toml | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
if [[ -z "$version" ]]; then
  echo "Failed to read version from Cargo.toml"
  exit 1
fi

cargo_profile_flag=""
flutter_profile_flag="--debug"
build_config="Debug"
target_dir="$ROOT_DIR/target/$profile"
if [[ "$profile" == "release" ]]; then
  cargo_profile_flag="--release"
  flutter_profile_flag="--release"
  build_config="Release"
  target_dir="$ROOT_DIR/target/release"
fi

echo "Building Mesh Infinity $version ($profile)"

host_platform() {
  case "$(uname -s)" in
    Darwin*) echo "macos" ;;
    Linux*) echo "linux" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

supports_platform() {
  local platform="$1"
  local host
  host="$(host_platform)"
  case "$platform" in
    macos|ios)
      [[ "$host" == "macos" ]]
      ;;
    linux)
      [[ "$host" == "linux" ]]
      ;;
    windows)
      [[ "$host" == "windows" ]]
      ;;
    android)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

list_codesign_identities() {
  security find-identity -v -p codesigning | sed -nE 's/.*"([^"]+)".*/\1/p'
}

pick_codesign_identity() {
  local label="$1"
  local prefer_pattern="$2"
  local fallback_pattern="$3"
  local override="$4"

  if [[ -n "$override" ]]; then
    echo "$override"
    return 0
  fi

  local identities
  identities="$(list_codesign_identities)"
  if [[ -z "$identities" ]]; then
    echo "No code signing identities found for $label."
    exit 1
  fi

  local pick=""
  if [[ -n "$prefer_pattern" ]]; then
    pick="$(echo "$identities" | grep -m1 -E "$prefer_pattern" || true)"
  fi
  if [[ -z "$pick" && -n "$fallback_pattern" ]]; then
    pick="$(echo "$identities" | grep -m1 -E "$fallback_pattern" || true)"
  fi
  if [[ -z "$pick" ]]; then
    pick="$(echo "$identities" | head -n1)"
  fi
  if [[ -z "$pick" ]]; then
    echo "No usable code signing identity found for $label."
    exit 1
  fi
  echo "$pick"
}

macos_sign() {
  local app_path="$1"
  local identity="${MACOS_CODESIGN_IDENTITY:-}"
  identity="$(pick_codesign_identity "macOS" "Developer ID Application" "Apple Development|Mac Developer|iPhone Developer" "$identity")"
  echo "Using macOS codesign identity: $identity"
  /usr/bin/codesign --force --deep --sign "$identity" "$app_path"
}

ios_sign() {
  local app_path="$1"
  local identity="${IOS_CODESIGN_IDENTITY:-}"
  identity="$(pick_codesign_identity "iOS" "Apple Development|iPhone Developer" "Apple Distribution|iPhone Distribution|Developer ID Application" "$identity")"
  echo "Using iOS codesign identity: $identity"
  /usr/bin/codesign --force --deep --sign "$identity" "$app_path"
}

build_macos() {
  (cd "$ROOT_DIR" && cargo build -p mesh-infinity $cargo_profile_flag)
  (cd "$FRONTEND_DIR" && flutter build macos $flutter_profile_flag)
  local macos_product_name
  macos_product_name="$(grep -E '^PRODUCT_NAME\s*=' "$FRONTEND_DIR/macos/Runner/Configs/AppInfo.xcconfig" | head -n1 | cut -d '=' -f2- | xargs)"
  if [[ -z "$macos_product_name" ]]; then
    macos_product_name="Runner"
  fi
  local app_src="$FRONTEND_DIR/build/macos/Build/Products/$build_config/${macos_product_name}.app"
  local app_out="$ROOT_DIR/build/macos/meshinfinity-${version}-${profile}.app"
  mkdir -p "$ROOT_DIR/build/macos"
  rm -rf "$app_out"
  cp -R "$app_src" "$app_out"
  local dylib_src="$target_dir/libmesh_infinity.dylib"
  local frameworks_dir="$app_out/Contents/Frameworks"
  local macos_dir="$app_out/Contents/MacOS"
  if [[ -f "$dylib_src" ]]; then
    mkdir -p "$frameworks_dir" "$macos_dir"
    cp -f "$dylib_src" "$frameworks_dir/"
    cp -f "$dylib_src" "$macos_dir/"
  else
    echo "Expected Rust dylib missing at $dylib_src"
    exit 1
  fi
  macos_sign "$app_out"
}

build_linux() {
  (cd "$ROOT_DIR" && cargo build -p mesh-infinity $cargo_profile_flag)
  (cd "$FRONTEND_DIR" && flutter build linux $flutter_profile_flag)
  local bundle_src="$FRONTEND_DIR/build/linux/x64/$profile/bundle"
  local bundle_out="$ROOT_DIR/build/linux/meshinfinity-${version}-${profile}"
  mkdir -p "$ROOT_DIR/build/linux"
  rm -rf "$bundle_out"
  cp -R "$bundle_src" "$bundle_out"
  local so_src="$target_dir/libmesh_infinity.so"
  if [[ -f "$so_src" ]]; then
    cp -f "$so_src" "$bundle_out/"
  else
    echo "Expected Rust shared library missing at $so_src"
    exit 1
  fi
}

build_windows() {
  (cd "$ROOT_DIR" && cargo build -p mesh-infinity $cargo_profile_flag)
  (cd "$FRONTEND_DIR" && flutter build windows $flutter_profile_flag)
  local bundle_src="$FRONTEND_DIR/build/windows/x64/runner/$build_config"
  local bundle_out="$ROOT_DIR/build/windows/meshinfinity-${version}-${profile}"
  mkdir -p "$ROOT_DIR/build/windows"
  rm -rf "$bundle_out"
  cp -R "$bundle_src" "$bundle_out"
  local dll_src="$target_dir/mesh_infinity.dll"
  if [[ -f "$dll_src" ]]; then
    cp -f "$dll_src" "$bundle_out/"
  else
    echo "Expected Rust DLL missing at $dll_src"
    exit 1
  fi
}

build_android() {
  if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "cargo-ndk is required for Android builds. Install with: cargo install cargo-ndk"
    exit 1
  fi
  if [[ -z "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" ]]; then
    echo "ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) must be set for Android builds."
    exit 1
  fi
  local android_abis=("arm64-v8a")
  if [[ -n "${ANDROID_ABIS:-}" ]]; then
    IFS="," read -r -a android_abis <<< "$ANDROID_ABIS"
  fi
  local cargo_ndk_args=()
  local target_platforms=()
  for abi in "${android_abis[@]}"; do
    case "$abi" in
      arm64-v8a)
        target_platforms+=("android-arm64")
        ;;
      armeabi-v7a)
        target_platforms+=("android-arm")
        ;;
      x86_64)
        target_platforms+=("android-x64")
        ;;
      x86)
        target_platforms+=("android-x86")
        ;;
      *)
        echo "Unsupported Android ABI: $abi"
        exit 1
        ;;
    esac
    cargo_ndk_args+=("-t" "$abi")
  done
  (cd "$ROOT_DIR" && cargo ndk \
    "${cargo_ndk_args[@]}" \
    -o "$ROOT_DIR/frontend/android/app/src/main/jniLibs" \
    build -p mesh-infinity $cargo_profile_flag)
  if [[ ! -f "$FRONTEND_DIR/android/key.properties" ]]; then
    cat <<'EOF'
Android signing is not configured.

Run scripts/setup_android_keystore.sh to generate a keystore and key.properties.

Create a keystore:
  keytool -genkey -v -keystore "$ROOT_DIR/frontend/android/meshinfinity-release.jks" \
    -keyalg RSA -keysize 2048 -validity 10000 -alias meshinfinity

Then create key.properties:
  storePassword=YOUR_STORE_PASSWORD
  keyPassword=YOUR_KEY_PASSWORD
  keyAlias=meshinfinity
  storeFile=meshinfinity-release.jks
EOF
    exit 1
  fi
  local flutter_target_platforms
  flutter_target_platforms=$(IFS=","; echo "${target_platforms[*]}")
  (cd "$FRONTEND_DIR" && flutter build apk $flutter_profile_flag --target-platform="$flutter_target_platforms")
  local apk_src="$FRONTEND_DIR/build/app/outputs/flutter-apk/app-${profile}.apk"
  if [[ ! -f "$apk_src" ]]; then
    apk_src="$FRONTEND_DIR/build/app/outputs/flutter-apk/app-release.apk"
  fi
  if [[ ! -f "$apk_src" ]]; then
    apk_src="$FRONTEND_DIR/build/app/outputs/flutter-apk/app-debug.apk"
  fi
  local apk_out="$ROOT_DIR/build/android/meshinfinity-${version}-${profile}.apk"
  mkdir -p "$ROOT_DIR/build/android"
  cp -f "$apk_src" "$apk_out"
}

build_ios() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "iOS builds require macOS."
    exit 1
  fi
  for target in aarch64-apple-ios x86_64-apple-ios; do
    (cd "$ROOT_DIR" && cargo build -p mesh-infinity --target "$target" $cargo_profile_flag)
  done
  (cd "$FRONTEND_DIR" && flutter build ios $flutter_profile_flag --no-codesign)
  local app_src="$FRONTEND_DIR/build/ios/iphoneos/Runner.app"
  local app_out="$ROOT_DIR/build/ios/meshinfinity-${version}-${profile}.app"
  mkdir -p "$ROOT_DIR/build/ios"
  rm -rf "$app_out"
  cp -R "$app_src" "$app_out"
  ios_sign "$app_out"
}

for platform in "${platforms[@]}"; do
  if ! supports_platform "$platform"; then
    echo "Skipping $platform build on $(host_platform)."
    continue
  fi
  case "$platform" in
    macos) build_macos ;;
    linux) build_linux ;;
    windows) build_windows ;;
    android) build_android ;;
    ios) build_ios ;;
    *)
      echo "Unsupported platform: $platform"
      exit 1
      ;;
  esac
done

echo "Unified builds are available under $ROOT_DIR/build"
