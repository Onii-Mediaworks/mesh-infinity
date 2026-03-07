//! Discovery subsystem exports.
//!
//! Contains local-network discovery, cache/index sources, and optional
//! DHT-like/jumpstart peer-sharing helpers.
pub mod catalog;
pub mod dht;
pub mod jumpstart;
pub mod mdns;
pub mod peer_codec;
pub mod service;

pub use catalog::*;
pub use dht::*;
pub use jumpstart::*;
pub use mdns::*;
pub use peer_codec::*;
pub use service::*;
