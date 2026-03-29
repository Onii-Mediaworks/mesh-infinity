//! Network Model (§4)
//!
//! Network map, gossip, transport hints, reachability.
//! The network map is a public-only structure containing peer addresses,
//! public keys, transport hints, and service advertisements.

pub mod map;
pub mod transport_hint;
pub mod threat_context;
pub mod gossip;
pub mod relay_deposit;
pub mod proximity;
pub mod dns;
pub mod kcp;
pub mod security_policy;
pub mod federation;
