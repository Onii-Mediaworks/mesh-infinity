//! Mesh Routing Coordinator (§6)
//!
//! # What is the Mesh Coordinator?
//!
//! The mesh coordinator bridges the routing table (§6.1) with the transport
//! layer (§5). When the application wants to send a packet to a peer, it asks
//! the coordinator to route it. The coordinator:
//!
//! 1. Looks up the destination in the four-plane routing table (§6.1).
//! 2. Selects the best transport for the next hop (§5.10).
//! 3. Wraps the payload in a `MeshPacket` envelope.
//! 4. Forwards the packet via the chosen transport.
//!
//! For packets that are NOT addressed to this node (multi-hop forwarding),
//! the coordinator decrements the TTL, selects the next hop, and re-sends.
//!
//! # Multi-hop forwarding (§6.5)
//!
//! Unlike IP routing, Mesh Infinity does not assume global reachability.
//! Packets may travel through several intermediate nodes (each running
//! this coordinator) before reaching the destination. The routing table
//! gives us the **next hop** — a directly-connected peer that is closer to
//! the destination. We encrypt the payload again for that next hop (onion
//! style — the intermediate node decrypts only the outer layer to learn the
//! next hop address, not the payload contents).
//!
//! # Deduplication (§6.6)
//!
//! The `DeduplicationCache` prevents forwarding loops. Each `MeshPacket`
//! carries a unique `packet_id`; if we see the same ID twice we discard it.

pub mod coordinator;
pub mod packet;
pub mod forwarder;

pub use coordinator::MeshCoordinator;
pub use packet::{MeshPacket, PacketKind};
pub use forwarder::ForwardDecision;
