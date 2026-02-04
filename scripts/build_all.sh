#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

platform=""
profile="debug"

usage() {
  echo "Usage: build_all.sh --platform <macos|linux|windows|android|ios> [--profile <debug|release>]"
}

host_platform() {
  case "$(uname -s)" in
    Darwin*) echo "macos" ;;
    Linux*) echo "linux" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      platform="$2"
      shift 2
      ;;
    --profile)
      profile="$2"
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

if [[ -z "$platform" ]]; then
  platform="$(host_platform)"
fi

if [[ "$profile" != "debug" && "$profile" != "release" ]]; then
  echo "Unsupported profile: $profile"
  usage
  exit 1
fi

cargo_profile_flag=""
flutter_profile_flag="--debug"
build_config="Debug"
if [[ "$profile" == "release" ]]; then
  cargo_profile_flag="--release"
  flutter_profile_flag="--release"
  build_config="Release"
fi

case "$platform" in
  macos|linux|windows)
    if [[ -n "$cargo_profile_flag" ]]; then
      (cd "$ROOT_DIR" && cargo build -p mesh-infinity "$cargo_profile_flag")
    else
      (cd "$ROOT_DIR" && cargo build -p mesh-infinity)
    fi
    (cd "$ROOT_DIR/frontend" && flutter build "$platform" "$flutter_profile_flag")

    target_dir="$ROOT_DIR/target/$profile"
    case "$platform" in
      macos)
        bundle_dir="$ROOT_DIR/frontend/build/macos/Build/Products/$build_config/mesh_infinity_frontend.app/Contents/MacOS"
        mkdir -p "$bundle_dir"
        cp -f "$target_dir/libmesh_infinity.dylib" "$bundle_dir/"
        ;;
      linux)
        bundle_dir="$ROOT_DIR/frontend/build/linux/x64/$profile/bundle"
        mkdir -p "$bundle_dir"
        cp -f "$target_dir/libmesh_infinity.so" "$bundle_dir/"
        ;;
      windows)
        bundle_dir="$ROOT_DIR/frontend/build/windows/x64/runner/$build_config"
        mkdir -p "$bundle_dir"
        cp -f "$target_dir/mesh_infinity.dll" "$bundle_dir/"
        ;;
    esac
    ;;
  android)
    if ! command -v cargo-ndk >/dev/null 2>&1; then
      echo "cargo-ndk is required for Android builds. Install with: cargo install cargo-ndk"
      exit 1
    fi
    if [[ -z "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" ]]; then
      echo "ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) must be set for Android builds."
      exit 1
    fi
    if [[ -n "$cargo_profile_flag" ]]; then
      cargo_profile_args=("$cargo_profile_flag")
    else
      cargo_profile_args=()
    fi
    (cd "$ROOT_DIR" && cargo ndk \
      -t armeabi-v7a \
      -t arm64-v8a \
      -t x86_64 \
      -o "$ROOT_DIR/frontend/android/app/src/main/jniLibs" \
      build -p mesh-infinity "${cargo_profile_args[@]}")
    (cd "$ROOT_DIR/frontend" && flutter build apk "$flutter_profile_flag")
    ;;
  ios)
    if [[ "$(host_platform)" != "macos" ]]; then
      echo "iOS builds require macOS."
      exit 1
    fi
    for target in aarch64-apple-ios x86_64-apple-ios; do
      if [[ -n "$cargo_profile_flag" ]]; then
        (cd "$ROOT_DIR" && cargo build -p mesh-infinity --target "$target" "$cargo_profile_flag")
      else
        (cd "$ROOT_DIR" && cargo build -p mesh-infinity --target "$target")
      fi
    done
    (cd "$ROOT_DIR/frontend" && flutter build ios "$flutter_profile_flag" --no-codesign)
    ;;
  *)
    echo "Unsupported platform: $platform"
    usage
    exit 1
    ;;
esac
