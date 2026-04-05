//! Routing Layer (§6)
//!
//! # What is the Routing Layer?
//!
//! The routing layer determines HOW packets find their way through the mesh.
//! It sits ABOVE the transport layer (which decides how each hop is carried)
//! and BELOW the application layer (which decides what to send).
//!
//! # Key Distinction: Routing vs Transport
//!
//! The routing layer selects which MESH NODES are on the path.
//! The transport solver (§5.10) selects HOW each hop is carried (internet,
//! BLE, Tor, etc.). These are entirely separate decisions made by
//! different subsystems.
//!
//! # Module Layout
//!
//! - **table** — the routing table itself, with four routing planes:
//!   public, group-scoped, local/private, and BLE ephemeral
//! - **announcement** — reachability announcements that nodes share with
//!   neighbours to populate routing tables
//! - **path_selection** — the trust-weighted scoring function that picks
//!   the best path among multiple candidates
//! - **loop_prevention** — packet ID deduplication and hop count bounding
//!   to prevent routing loops
//! - **store_forward** — deferred delivery for offline recipients, with
//!   signed expiry and per-destination quotas
//! - **relay** — mesh relay (DERP-style NAT traversal without IP disclosure)
//! - **losec** — low-security high-bandwidth transport mode configuration
//! - **isolation** — network isolation mode (darknet mode) for maximum
//!   privacy, restricting connections to pre-configured peers only

pub mod announcement;
pub mod fast_routing;
pub mod isolation;
pub mod loop_prevention;
pub mod losec;
pub mod path_selection;
pub mod relay;
pub mod store_forward;
pub mod table;
pub mod tunnel_gossip;
