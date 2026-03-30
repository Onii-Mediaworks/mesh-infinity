//! Network Model (§4)
//!
//! Network map, gossip, transport hints, reachability.
//! The network map is a public-only structure containing peer addresses,
//! public keys, transport hints, and service advertisements.

// Sub-module: map — see module-level docs for details.
// map sub-module — see its own module-level docs.
pub mod map;
// Sub-module: transport_hint — see module-level docs for details.
// transport_hint sub-module — see its own module-level docs.
pub mod transport_hint;
// Sub-module: threat_context — see module-level docs for details.
// threat_context sub-module — see its own module-level docs.
pub mod threat_context;
// Sub-module: gossip — see module-level docs for details.
// gossip sub-module — see its own module-level docs.
pub mod gossip;
// Sub-module: relay_deposit — see module-level docs for details.
// relay_deposit sub-module — see its own module-level docs.
pub mod relay_deposit;
// Sub-module: proximity — see module-level docs for details.
pub mod proximity;
// Sub-module: dns — see module-level docs for details.
pub mod dns;
// Sub-module: kcp — see module-level docs for details.
pub mod kcp;
// Sub-module: security_policy — see module-level docs for details.
pub mod security_policy;
// Sub-module: federation — see module-level docs for details.
pub mod federation;
