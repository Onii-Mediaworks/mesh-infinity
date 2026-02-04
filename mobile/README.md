# Flutter Mobile Scaffold

This directory tracks the Flutter mobile integration work. The shared UI lives in `frontend/` and is
embedded in platform shells via Flutter.

Goals
- Use the Flutter UI on all platforms.
- Keep the SwiftUI codebase as a reference only during migration.
- Ship a single app per platform that can run Client, Server, or Dual modes.

Entry Points
- The Flutter entrypoint is in `frontend/lib/main.dart`.
- The Rust core is exposed via the `backend/ffi` C ABI and loaded by Dart FFI.
