//! Exit-node routing subsystem.
//!
//! Exposes policy-aware traffic routing and bandwidth controls used when the
//! node is acting as a gateway for non-mesh egress traffic.
pub mod bandwidth_manager;
pub mod traffic_router;

pub use bandwidth_manager::*;
pub use traffic_router::*;
