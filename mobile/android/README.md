# Android Flutter Shell

Planned integration steps:
- Build the Rust core as a `cdylib` for Android (via `cargo ndk`).
- Place the shared object in `android/app/src/main/jniLibs/<abi>/`.
- Load the library from Dart via `dart:ffi` (see `frontend/lib/backend/backend_bridge.dart`).

The current `android/` project remains a temporary shell; the canonical app lives in `frontend/android`.
