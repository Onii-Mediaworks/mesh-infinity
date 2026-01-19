# Android Slint Shell

Planned integration steps:
- Build the Rust UI as a `cdylib` for Android (via `cargo ndk`).
- Place the shared object in `android/app/src/main/jniLibs/<abi>/`.
- Add a JNI bridge that calls `netinfinity_run()` to start the UI.

The current `android/` project remains as a temporary shell until the Slint UI is fully wired.
