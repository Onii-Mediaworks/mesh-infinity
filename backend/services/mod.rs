//! Hosted Services (§12)
//!
//! Service hosting, registration, tunneling, and access control.
//!
//! - **ports** — the mesh port space and service addressing
//! - **tunnel** — TCP/UDP tunneling through the mesh
//! - **registry** — service registration and discovery
//! - **health** — service health monitoring and mirroring

pub mod ports;
pub mod tunnel;
pub mod registry;
pub mod health;
pub mod module_system;
pub mod plugin;
pub mod mesh_protocols;
