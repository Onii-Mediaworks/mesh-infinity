# Mesh Infinity Agent Guidelines

## Source of Truth
- `SPEC.md` is the authoritative specification.
- `README.md` files are for end users only and must not override `SPEC.md`.

## UI Direction
- The Flutter UI (`frontend/`) is the canonical UI across platforms.
- The Slint UI is deprecated and should only be referenced for parity checks.
- The SwiftUI app (`MeshInfinity/`) is deprecated and should only be referenced for parity checks.

## Platform Scope
- All platforms are in scope for this phase.
- Android is the primary focus; iOS is incidental (do not prioritize iOS-specific work).

## Implementation Principles
- Keep platform-specific code minimal; prefer shared Rust + Flutter logic.
- Align behavior with `SPEC.md` even if existing code or docs diverge.
- Cloud services are prohibited for all platforms (no Google Play services, Apple cloud services, or Microsoft cloud services).
