## Resolution Status: RESOLVED
# Headless / Server Mode Requires GTK Display

**Date:** 2026-03-29
**Auditor:** claude
**Status:** UNRESOLVED
**Severity:** Medium

## Issue

The Linux binary (`mesh_infinity_frontend`) requires a GTK display to start. Running
it on a headless server (no `$DISPLAY`) fails immediately:

```
Gtk-WARNING: cannot open display:
```

Per the spec and user requirements, Mesh Infinity should support a server/daemon mode
configured via a web UI — not via Flutter/GTK at all. The Rust backend is fully
capable of running without a display; the GTK requirement comes purely from Flutter's
Linux runner.

## Proposed solutions

**Option A — Rust-only daemon binary (correct fix):**
Add a second binary target in Cargo.toml (`[[bin]] name = "mesh-infinityd"`) that
starts the Rust backend directly with a built-in HTTP server (axum/warp) serving
a web UI. The Flutter frontend would connect to this daemon over the FFI or a local
socket. This matches the stated architecture (Rust is primary; Flutter is UI).

**Option B — `--headless` flag in the Flutter runner:**
Patch `platforms/linux/runner/main.cc` to detect a `--headless` flag and skip GTK
initialisation. Flutter's engine can still run in "headless" mode. The backend would
expose its web UI through the Rust layer.

**Option C — Environment-variable gate (minimal fix):**
If `DISPLAY` is unset and `MESH_HEADLESS=1` is set, the runner skips GTK init and
falls through to backend-only mode. Quick to implement but fragile.

## Resolution

*(Fill in when resolved)*
