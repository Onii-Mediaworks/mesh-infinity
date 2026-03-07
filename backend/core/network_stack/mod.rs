//! Network-stack subsystem exports.
//!
//! Re-exports packet routing, addressing, DNS/NAT helpers, policy routing, and
//! virtual interface / VPN integration modules.
//!
//! All modules compile on every supported platform.  Platform-specific TUN
//! backends (tun-tap on Unix, wintun on Windows) are selected inside
//! `virtual_interface` at compile time; the rest of the stack is agnostic.
pub mod dns_resolver;
pub mod hop_router;
pub mod mesh_address;
pub mod mesh_packet_router;
pub mod nat_traversal;
pub mod policy_router;
pub mod virtual_interface;
pub mod vpn_service;

pub use dns_resolver::*;
pub use hop_router::*;
pub use mesh_address::*;
pub use mesh_packet_router::*;
pub use nat_traversal::*;
pub use policy_router::*;
pub use virtual_interface::*;
pub use vpn_service::*;
