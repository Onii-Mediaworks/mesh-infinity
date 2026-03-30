//! libp2p Integration (§5.24)
//!
//! libp2p is a modular networking stack underlying IPFS, Ethereum, and many
//! other decentralised projects.  Mesh Infinity uses it as an implementation
//! accelerator for specific capabilities:
//!
//! ## What we use
//!
//! | Component | Purpose |
//! |-----------|---------|
//! | **GossipSub** | Network map propagation (candidate for §6 gossip) |
//! | **Rendezvous protocol** | Bootstrap peer discovery at known rendezvous points |
//! | **AutoNAT** | NAT detection (not hole-punching — we use mesh relay instead) |
//! | **TCP transport** | Reliable byte streams for long-lived connections |
//!
//! ## What we explicitly do NOT use
//!
//! | Component | Reason |
//! |-----------|--------|
//! | **Identify** | Leaks all listen addresses + protocols on connect (metadata) |
//! | **Kademlia DHT** | Reveals peer interest patterns (§4.8) |
//! | **Circuit Relay** | Our wrapper node model handles this |
//! | **QUIC** | WireGuard already provides encrypted multiplexed transport |
//!
//! ## Privacy model
//!
//! libp2p is an **implementation accelerator**, not an architectural
//! dependency.  All libp2p channels are untrusted transport.  Our encryption
//! and validation layers sit on top of any libp2p stream.
//!
//! ## GossipSub topic
//!
//! The mesh network map is propagated on the topic:
//! `"/meshinfinity/network-map/1.0.0"`
//!
//! Messages on this topic are signed Gossip map entries (same format as the
//! native gossip protocol).  Nodes subscribing to this topic receive map
//! updates from any peer who has them.

use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// ────────────────────────────────────────────────────────────────────────────
// Topic and protocol IDs
// ────────────────────────────────────────────────────────────────────────────

/// GossipSub topic for Mesh Infinity network map propagation.
/// The version suffix (1.0.0) allows future incompatible map formats
/// to use a different topic without interference from old nodes.
/// GossipSub's flood/mesh hybrid propagation ensures high-reliability
/// delivery without requiring every node to maintain a direct connection
/// to every other node.
pub const GOSSIPSUB_NETWORK_MAP_TOPIC: &str = "/meshinfinity/network-map/1.0.0";

/// GossipSub topic for Mesh Infinity peer announcements.
/// Separated from network-map because announcements are higher-frequency
/// (peers come and go) and nodes may want to subscribe to maps without
/// receiving every peer churn event.
pub const GOSSIPSUB_PEER_ANNOUNCE_TOPIC: &str = "/meshinfinity/peer-announce/1.0.0";

/// Rendezvous namespace for Mesh Infinity peer discovery.
/// Rendezvous protocol (libp2p RFC 0062) allows nodes to register at
/// well-known rendezvous points and discover peers by namespace — this
/// provides bootstrap discovery without relying on a DHT, which would
/// leak interest patterns (§4.8 privacy concern).
pub const RENDEZVOUS_NAMESPACE: &str = "meshinfinity";

/// Default libp2p TCP port.  4001 is the standard IPFS/libp2p port;
/// we reuse it for familiarity and firewall rule reuse.
pub const LIBP2P_TCP_PORT: u16 = 4001;

// ────────────────────────────────────────────────────────────────────────────
// libp2p types and abstractions
// ────────────────────────────────────────────────────────────────────────────

use libp2p::{
    gossipsub::{self, IdentTopic, TopicHash},
    rendezvous,
    autonat,
    noise,
    tcp,
    yamux,
    identity::Keypair,
    Multiaddr,
    PeerId,
    SwarmBuilder,
};

/// Events emitted by the libp2p transport.
#[derive(Debug)]
pub enum Libp2pEvent {
    /// A GossipSub message was received.
    GossipMessage {
        topic: TopicHash,
        data: Vec<u8>,
        source: Option<PeerId>,
    },
    /// A peer was discovered via rendezvous.
    PeerDiscovered {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    },
    /// AutoNAT determined our NAT status.
    NatStatus(NatStatus),
    /// A connection to a peer was established.
    Connected(PeerId),
    /// A peer disconnected.
    Disconnected(PeerId),
}

/// Our NAT traversal status as determined by AutoNAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatStatus {
    /// Not yet determined.
    Unknown,
    /// We are directly reachable (public IP or port mapping).
    Public,
    /// We are behind NAT — outbound connections only.
    Private,
}

// ────────────────────────────────────────────────────────────────────────────
// Libp2pTransport
// ────────────────────────────────────────────────────────────────────────────

/// Configuration for the libp2p transport.
#[derive(Debug, Clone)]
pub struct Libp2pConfig {
    /// Local TCP listen port.
    pub tcp_port: u16,
    /// Rendezvous server addresses (multiaddrs).
    pub rendezvous_servers: Vec<String>,
    /// Additional bootstrap peers.
    pub bootstrap_peers: Vec<String>,
    /// GossipSub mesh parameters.
    pub gossipsub_fanout: usize,
}

impl Default for Libp2pConfig {
    fn default() -> Self {
        Libp2pConfig {
            tcp_port: LIBP2P_TCP_PORT,
            rendezvous_servers: Vec::new(),
            bootstrap_peers: Vec::new(),
            gossipsub_fanout: 6,
        }
    }
}

/// Outbound message queue item: (gossipsub topic, payload).
type OutboundQueue = Arc<Mutex<Vec<(IdentTopic, Vec<u8>)>>>;

/// A libp2p-based transport for Mesh Infinity.
///
/// Manages the libp2p swarm lifecycle and exposes a simple message-passing
/// interface.  The swarm runs in a dedicated tokio task.
pub struct Libp2pTransport {
    /// Our libp2p PeerId (derived from our Ed25519 key).
    pub peer_id: PeerId,
    /// Outbound message queue: (topic, data) pairs to publish on GossipSub.
    outbound: OutboundQueue,
    /// Inbound events from the swarm.
    inbound: Arc<Mutex<Vec<Libp2pEvent>>>,
    /// Connected peers with their last-known addresses.
    peers: Arc<Mutex<HashMap<PeerId, Vec<Multiaddr>>>>,
    /// Our current NAT status.
    pub nat_status: Arc<Mutex<NatStatus>>,
}

impl Libp2pTransport {
    /// Create a new transport from the raw Ed25519 keypair bytes.
    ///
    /// `ed25519_keypair_bytes` — 64-byte Ed25519 keypair (secret + public).
    pub fn new(ed25519_keypair_bytes: &[u8; 64]) -> Result<Self, Box<dyn std::error::Error>> {
        let keypair = Keypair::ed25519_from_bytes(ed25519_keypair_bytes.to_vec())?;
        let peer_id = PeerId::from(keypair.public());

        Ok(Libp2pTransport {
            peer_id,
            outbound: Arc::new(Mutex::new(Vec::new())),
            inbound: Arc::new(Mutex::new(Vec::new())),
            peers: Arc::new(Mutex::new(HashMap::new())),
            nat_status: Arc::new(Mutex::new(NatStatus::Unknown)),
        })
    }

    /// Create a transport with a freshly generated keypair.
    pub fn new_random() -> Self {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        Libp2pTransport {
            peer_id,
            outbound: Arc::new(Mutex::new(Vec::new())),
            inbound: Arc::new(Mutex::new(Vec::new())),
            peers: Arc::new(Mutex::new(HashMap::new())),
            nat_status: Arc::new(Mutex::new(NatStatus::Unknown)),
        }
    }

    /// Publish `data` to a GossipSub topic.
    pub fn publish(&self, topic: &str, data: Vec<u8>) {
        let t = IdentTopic::new(topic);
        // Mutex recovery: outbound queue is valid after poison.
        self.outbound.lock().unwrap_or_else(|e| e.into_inner()).push((t, data));
    }

    /// Publish a network map update.
    pub fn publish_network_map(&self, map_entry: Vec<u8>) {
        self.publish(GOSSIPSUB_NETWORK_MAP_TOPIC, map_entry);
    }

    /// Publish a peer announcement.
    pub fn publish_peer_announce(&self, announcement: Vec<u8>) {
        self.publish(GOSSIPSUB_PEER_ANNOUNCE_TOPIC, announcement);
    }

    /// Drain all inbound events since the last call.
    pub fn drain_events(&self) -> Vec<Libp2pEvent> {
        // Mutex recovery: drain is safe even after a poisoned lock.
        std::mem::take(&mut *self.inbound.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Drain all GossipSub messages for a specific topic.
    pub fn drain_topic(&self, topic: &str) -> Vec<Vec<u8>> {
        let topic_hash = TopicHash::from_raw(topic);
        // Mutex recovery: event queue is valid after poison.
        let mut events = self.inbound.lock().unwrap_or_else(|e| e.into_inner());
        let mut matching = Vec::new();
        events.retain(|e| {
            if let Libp2pEvent::GossipMessage { topic: t, data, .. } = e {
                if *t == topic_hash {
                    matching.push(data.clone());
                    return false;
                }
            }
            true
        });
        matching
    }

    /// Number of currently connected peers.
    pub fn connected_peer_count(&self) -> usize {
        // Mutex recovery: peer set is valid after poison.
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Current NAT status.
    pub fn nat_status(&self) -> NatStatus {
        // Mutex recovery: NAT status is valid after poison.
        *self.nat_status.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the libp2p transport is operational on this platform.
    pub fn is_available() -> bool {
        true // libp2p works on all platforms
    }

    /// Build a GossipSub configuration for Mesh Infinity.
    ///
    /// Note: Identify protocol is explicitly disabled (§5.24 — metadata leak).
    pub fn gossipsub_config(fanout: usize) -> gossipsub::Config {
        gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .mesh_n(fanout)
            .mesh_n_low(fanout / 2)
            .mesh_n_high(fanout * 2)
            .gossip_lazy(6)
            .history_length(5)
            .history_gossip(3)
            .validate_messages()
            .build()
            .expect("valid gossipsub config")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Swarm builder helper
// ────────────────────────────────────────────────────────────────────────────

/// Build a Swarm with GossipSub + Rendezvous client + AutoNAT.
///
/// The Identify protocol is explicitly **not** included.
///
/// Returns the swarm and the GossipSub topic handles for the two mesh topics.
pub async fn build_swarm(
    keypair: Keypair,
    config: &Libp2pConfig,
) -> Result<
    (
        libp2p::Swarm<MeshBehaviour>,
        IdentTopic,
        IdentTopic,
    ),
    Box<dyn std::error::Error>,
> {
    let network_map_topic = IdentTopic::new(GOSSIPSUB_NETWORK_MAP_TOPIC);
    let peer_announce_topic = IdentTopic::new(GOSSIPSUB_PEER_ANNOUNCE_TOPIC);
    let fanout = config.gossipsub_fanout;

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            // GossipSub — mesh map propagation.
            let gs_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(std::time::Duration::from_secs(10))
                .mesh_n(fanout)
                .mesh_n_low(fanout / 2)
                .mesh_n_high(fanout * 2)
                .validate_messages()
                .build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gs_config,
            )
            .map_err(std::io::Error::other)?;

            // Rendezvous client — lightweight bootstrap.
            let rendezvous = rendezvous::client::Behaviour::new(key.clone());

            // AutoNAT — detect our reachability.
            let autonat = autonat::Behaviour::new(
                PeerId::from(key.public()),
                autonat::Config::default(),
            );

            Ok(MeshBehaviour {
                gossipsub,
                rendezvous,
                autonat,
            })
        })?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(std::time::Duration::from_secs(60))
        })
        .build();

    Ok((swarm, network_map_topic, peer_announce_topic))
}

/// Combined libp2p behaviour for Mesh Infinity.
///
/// Deliberately excludes Identify, Kademlia, and Circuit Relay.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct MeshBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub rendezvous: rendezvous::client::Behaviour,
    pub autonat: autonat::Behaviour,
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_new_random_peer_id() {
        let t1 = Libp2pTransport::new_random();
        let t2 = Libp2pTransport::new_random();
        assert_ne!(t1.peer_id, t2.peer_id, "random transports must have different peer IDs");
    }

    #[test]
    fn gossipsub_config_fanout() {
        let cfg = Libp2pTransport::gossipsub_config(6);
        // Just verify it builds without panic.
        let _ = cfg;
    }

    #[test]
    fn publish_queues_message() {
        let t = Libp2pTransport::new_random();
        t.publish(GOSSIPSUB_NETWORK_MAP_TOPIC, b"map entry".to_vec());
        let outbound = t.outbound.lock().unwrap();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].1, b"map entry");
    }

    #[test]
    fn drain_topic_filters_correctly() {
        let t = Libp2pTransport::new_random();
        let topic_hash_nm = TopicHash::from_raw(GOSSIPSUB_NETWORK_MAP_TOPIC);
        let topic_hash_pa = TopicHash::from_raw(GOSSIPSUB_PEER_ANNOUNCE_TOPIC);

        {
            let mut events = t.inbound.lock().unwrap();
            events.push(Libp2pEvent::GossipMessage {
                topic: topic_hash_nm.clone(),
                data: b"map data".to_vec(),
                source: None,
            });
            events.push(Libp2pEvent::GossipMessage {
                topic: topic_hash_pa.clone(),
                data: b"peer announce".to_vec(),
                source: None,
            });
        }

        let map_msgs = t.drain_topic(GOSSIPSUB_NETWORK_MAP_TOPIC);
        assert_eq!(map_msgs.len(), 1);
        assert_eq!(map_msgs[0], b"map data");

        // The peer announce message should still be in the queue.
        let remaining: Vec<_> = t.inbound.lock().unwrap().drain(..).collect();
        assert_eq!(remaining.len(), 1);
    }

    #[test]
    fn nat_status_default_unknown() {
        let t = Libp2pTransport::new_random();
        assert_eq!(t.nat_status(), NatStatus::Unknown);
    }

    #[test]
    fn is_available_true() {
        assert!(Libp2pTransport::is_available());
    }

    #[test]
    fn topic_constants_correct() {
        assert!(GOSSIPSUB_NETWORK_MAP_TOPIC.contains("network-map"));
        assert!(GOSSIPSUB_PEER_ANNOUNCE_TOPIC.contains("peer-announce"));
    }
}
