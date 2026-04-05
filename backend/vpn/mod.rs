//! VPN and Exit Nodes (§13)
//!
//! Traffic routing through the mesh: exit node capabilities,
//! traffic routing modes, kill switch, Infinet virtual networks,
//! and the app connector.
//!
//! - **exit_node** — exit node advertisements and capabilities
//! - **routing_mode** — VPN traffic routing modes
//! - **infinet** — virtual private network namespaces
//! - **app_connector** — per-app routing rules

pub mod app_connector;
pub mod exit_node;
pub mod funnel;
pub mod infinet;
pub mod routing_mode;
