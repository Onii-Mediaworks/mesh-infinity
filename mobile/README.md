# Slint Mobile Scaffold

This directory tracks the Slint mobile integration work. The shared UI lives in `ui/main.slint` and is
exported through `ui/src/lib.rs` for embedding in platform shells.

Goals
- Use the Slint UI on all platforms.
- Keep the SwiftUI codebase as a reference only during migration.
- Ship a single app per platform that can run Client, Server, or Dual modes.

Entry Points
- `net_infinity_ui::run_app()` runs the Slint UI for desktop.
- `netinfinity_run()` is the exported C entrypoint for mobile shells.
