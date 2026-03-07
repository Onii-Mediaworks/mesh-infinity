//! Application-gateway subsystem.
//!
//! Hosts protocol-handler registration and application endpoint lookup used by
//! higher layers that route mesh payloads into app-specific handlers.
pub mod app_registry;
pub mod protocol_handlers;

pub use app_registry::*;
pub use protocol_handlers::*;
