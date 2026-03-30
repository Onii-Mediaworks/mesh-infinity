//! Hosted Services (§12)
//!
//! Service hosting, registration, tunneling, and access control.
//!
//! - **ports** — the mesh port space and service addressing
//! - **tunnel** — TCP/UDP tunneling through the mesh
//! - **registry** — service registration and discovery
//! - **health** — service health monitoring and mirroring

// Sub-module: ports — see module-level docs for details.
pub mod ports;
// Sub-module: tunnel — see module-level docs for details.
pub mod tunnel;
// Sub-module: registry — see module-level docs for details.
pub mod registry;
// Sub-module: health — see module-level docs for details.
pub mod health;
// Sub-module: module_system — see module-level docs for details.
pub mod module_system;
// Sub-module: plugin — see module-level docs for details.
pub mod plugin;
pub mod mesh_protocols;
