//! Core backend subsystem root.
//!
//! Re-exports foundational modules used by higher-level backend services:
//! networking, mesh routing, file transfer, security policy, and node runtime.

pub mod application_gateway;
#[allow(clippy::module_inception)]
pub mod core;
pub mod error;
pub mod exit_node;
pub mod file_transfer;
pub mod mesh;
pub mod network_stack;
pub mod security;
pub mod service;

pub use application_gateway::*;
pub use core::*;
pub use error::*;
pub use exit_node::*;
pub use file_transfer::*;
pub use mesh::*;
pub use network_stack::*;
pub use security::*;
pub use service::*;
