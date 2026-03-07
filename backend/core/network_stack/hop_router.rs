// Hop-by-Hop Router - Decentralized routing based on network topology
//
// Routing Model:
// - Each node only makes local decisions about the next hop
// - No predetermined paths - routing is dynamic based on current topology
// - Links kept open until data delivered (no ACK/retransmit)
// - Discovery-driven: routing tables built from network discovery
//
// Each node maintains:
// - Direct neighbors (peers we have direct connections to)
// - Known topology (which neighbors can reach which destinations)
// - Distance metrics (hop count, latency, trust-weighted distance)

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::mesh_address::{ConversationId, DeviceAddress, MeshAddress};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::{PeerId, TransportType, TrustLevel};

/// Information about a direct neighbor
#[derive(Debug, Clone)]
pub struct NeighborInfo {
    /// Peer ID of the neighbor
    pub peer_id: PeerId,
    /// Their device address
    pub device_address: DeviceAddress,
    /// Available transports to reach them
    pub transports: Vec<TransportType>,
    /// Trust level
    pub trust_level: TrustLevel,
    /// Latency to this neighbor (measured)
    pub latency: Duration,
    /// Last time we heard from them
    pub last_seen: Instant,
    /// Is the connection currently active
    pub is_active: bool,
}

/// Reachability information shared between nodes
/// "I can reach X through Y in N hops"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityAnnouncement {
    /// The destination that can be reached
    pub destination: DeviceAddress,
    /// Number of hops to reach it
    pub hop_count: u8,
    /// Cumulative latency estimate (ms)
    pub latency_estimate_ms: u32,
    /// Minimum trust level along the path
    pub path_trust: TrustLevel,
    /// Timestamp of this announcement
    pub timestamp_ms: u64,
    /// Sequence number for freshness
    pub sequence: u64,
}

/// Local routing table entry
#[derive(Debug, Clone)]
pub struct RoutingEntry {
    /// Destination device address
    pub destination: DeviceAddress,
    /// Next hop to reach this destination
    pub next_hop: PeerId,
    /// Total hops to destination
    pub hop_count: u8,
    /// Estimated latency
    pub latency_estimate: Duration,
    /// Path trust (minimum trust along the path)
    pub path_trust: TrustLevel,
    /// When this entry was last updated
    pub last_updated: Instant,
    /// Sequence number from the announcement
    pub sequence: u64,
}

/// Active link for an ongoing transmission
#[derive(Debug, Clone)]
pub struct ActiveLink {
    /// Source address (full, with conversation ID)
    pub source: MeshAddress,
    /// Destination address (full, with conversation ID)
    pub destination: MeshAddress,
    /// The next hop we're forwarding to
    pub next_hop: PeerId,
    /// When this link was established
    pub established: Instant,
    /// Last activity on this link
    pub last_activity: Instant,
    /// Bytes forwarded
    pub bytes_forwarded: u64,
}

/// Hop-by-hop router based on network topology discovery
pub struct HopRouter {
    /// Our own device address
    our_address: DeviceAddress,

    /// Direct neighbors we can communicate with
    neighbors: Arc<RwLock<HashMap<PeerId, NeighborInfo>>>,

    /// Routing table: destination -> how to get there
    routing_table: Arc<RwLock<HashMap<DeviceAddress, Vec<RoutingEntry>>>>,

    /// Active links for ongoing transmissions
    active_links: Arc<RwLock<HashMap<ConversationId, ActiveLink>>>,

    /// Configuration
    config: HopRouterConfig,
}

/// Configuration for the hop router
#[derive(Debug, Clone)]
pub struct HopRouterConfig {
    /// Maximum hops to accept in routing
    pub max_hops: u8,
    /// How long before a route is considered stale
    pub route_timeout: Duration,
    /// How long to keep an active link without activity
    pub link_timeout: Duration,
    /// Maximum number of routes per destination to keep
    pub max_routes_per_dest: usize,
    /// Minimum trust level to route through
    pub min_path_trust: TrustLevel,
}

impl Default for HopRouterConfig {
    /// Provide conservative defaults for hop routing behavior.
    fn default() -> Self {
        Self {
            max_hops: 8,
            route_timeout: Duration::from_secs(300),
            link_timeout: Duration::from_secs(60),
            max_routes_per_dest: 3,
            min_path_trust: TrustLevel::Caution,
        }
    }
}

impl HopRouter {
    /// Create a new hop router
    pub fn new(our_address: DeviceAddress, _our_peer_id: PeerId) -> Self {
        Self {
            our_address,
            neighbors: Arc::new(RwLock::new(HashMap::new())),
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            active_links: Arc::new(RwLock::new(HashMap::new())),
            config: HopRouterConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        our_address: DeviceAddress,
        _our_peer_id: PeerId,
        config: HopRouterConfig,
    ) -> Self {
        Self {
            our_address,
            neighbors: Arc::new(RwLock::new(HashMap::new())),
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            active_links: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Register a direct neighbor
    pub fn add_neighbor(&self, info: NeighborInfo) {
        let peer_id = info.peer_id;
        let device_addr = info.device_address;

        self.neighbors.write().unwrap().insert(peer_id, info);

        // Direct neighbors are always reachable in 1 hop
        let entry = RoutingEntry {
            destination: device_addr,
            next_hop: peer_id,
            hop_count: 1,
            latency_estimate: Duration::from_millis(0), // Will be updated
            path_trust: TrustLevel::HighlyTrusted,      // Direct connection
            last_updated: Instant::now(),
            sequence: 0,
        };

        self.routing_table
            .write()
            .unwrap()
            .entry(device_addr)
            .or_default()
            .push(entry);
    }

    /// Remove a neighbor (they disconnected)
    pub fn remove_neighbor(&self, peer_id: &PeerId) {
        self.neighbors.write().unwrap().remove(peer_id);

        // Remove routes that use this peer as next hop
        let mut table = self.routing_table.write().unwrap();
        for routes in table.values_mut() {
            routes.retain(|r| r.next_hop != *peer_id);
        }
        // Remove empty entries
        table.retain(|_, routes| !routes.is_empty());
    }

    /// Update neighbor status (heartbeat received)
    pub fn update_neighbor(&self, peer_id: &PeerId, latency: Duration) {
        if let Some(neighbor) = self.neighbors.write().unwrap().get_mut(peer_id) {
            neighbor.last_seen = Instant::now();
            neighbor.latency = latency;
            neighbor.is_active = true;
        }
    }

    /// Process a reachability announcement from a neighbor
    pub fn process_announcement(
        &self,
        from_peer: PeerId,
        announcement: ReachabilityAnnouncement,
    ) -> bool {
        // Ignore if hop count exceeds maximum
        if announcement.hop_count >= self.config.max_hops {
            return false;
        }

        // Ignore if trust is too low
        if announcement.path_trust < self.config.min_path_trust {
            return false;
        }

        // Ignore if it's about us
        if announcement.destination == self.our_address {
            return false;
        }

        // Get the neighbor info to calculate our path metrics
        let neighbor = {
            let neighbors = self.neighbors.read().unwrap();
            neighbors.get(&from_peer).cloned()
        };

        let neighbor = match neighbor {
            Some(n) => n,
            None => return false, // Unknown peer
        };

        // Calculate our metrics for this route
        let our_hop_count = announcement.hop_count + 1;
        let our_latency =
            Duration::from_millis(announcement.latency_estimate_ms as u64) + neighbor.latency;
        let our_trust = std::cmp::min(announcement.path_trust, neighbor.trust_level);

        let entry = RoutingEntry {
            destination: announcement.destination,
            next_hop: from_peer,
            hop_count: our_hop_count,
            latency_estimate: our_latency,
            path_trust: our_trust,
            last_updated: Instant::now(),
            sequence: announcement.sequence,
        };

        // Update routing table
        let mut table = self.routing_table.write().unwrap();
        let routes = table.entry(announcement.destination).or_default();

        // Check if we already have a route through this next hop
        if let Some(existing) = routes.iter_mut().find(|r| r.next_hop == from_peer) {
            // Update if this is newer
            if announcement.sequence > existing.sequence {
                *existing = entry;
                return true;
            }
            return false;
        }

        // Add new route if we have room
        if routes.len() < self.config.max_routes_per_dest {
            routes.push(entry);
            // Sort by quality (hop count, then latency)
            routes.sort_by(|a, b| {
                a.hop_count
                    .cmp(&b.hop_count)
                    .then(a.latency_estimate.cmp(&b.latency_estimate))
            });
            return true;
        }

        // Replace worst route if new one is better
        if let Some(worst) = routes.last() {
            if our_hop_count < worst.hop_count
                || (our_hop_count == worst.hop_count && our_latency < worst.latency_estimate)
            {
                routes.pop();
                routes.push(entry);
                routes.sort_by(|a, b| {
                    a.hop_count
                        .cmp(&b.hop_count)
                        .then(a.latency_estimate.cmp(&b.latency_estimate))
                });
                return true;
            }
        }

        false
    }

    /// Generate announcements about our reachable destinations
    /// Should be called periodically to share routing info with neighbors
    pub fn generate_announcements(&self) -> Vec<ReachabilityAnnouncement> {
        self.generate_announcements_for_neighbor(None)
    }

    /// Generate announcements scoped for a specific neighbor.
    ///
    /// Applies split-horizon behavior when `for_neighbor` is set:
    /// routes learned from that neighbor are not re-announced back to it.
    /// This reduces unnecessary topology disclosure and route churn.
    pub fn generate_announcements_for_neighbor(
        &self,
        for_neighbor: Option<PeerId>,
    ) -> Vec<ReachabilityAnnouncement> {
        let table = self.routing_table.read().unwrap();
        let mut announcements = Vec::new();
        let now = current_time_ms();

        // Announce ourselves (reachable in 0 hops from us)
        announcements.push(ReachabilityAnnouncement {
            destination: self.our_address,
            hop_count: 0,
            latency_estimate_ms: 0,
            path_trust: TrustLevel::HighlyTrusted,
            timestamp_ms: now,
            sequence: now, // Use time as sequence
        });

        // Announce all destinations we can reach
        for (dest, routes) in table.iter() {
            // Split-horizon: do not advertise back to the same next hop
            let best = routes.iter().find(|route| {
                for_neighbor
                    .map(|neighbor_peer| route.next_hop != neighbor_peer)
                    .unwrap_or(true)
            });

            if let Some(best) = best {
                announcements.push(ReachabilityAnnouncement {
                    destination: *dest,
                    hop_count: best.hop_count,
                    latency_estimate_ms: best.latency_estimate.as_millis() as u32,
                    path_trust: best.path_trust,
                    timestamp_ms: now,
                    sequence: best.sequence,
                });
            }
        }

        announcements
    }

    /// Determine the next hop for a destination
    /// Returns the peer ID to forward to, or None if unreachable
    pub fn next_hop_for(&self, destination: &DeviceAddress) -> Option<NextHopDecision> {
        // Check if destination is a direct neighbor
        {
            let neighbors = self.neighbors.read().unwrap();
            for (peer_id, neighbor) in neighbors.iter() {
                if neighbor.device_address == *destination && neighbor.is_active {
                    return Some(NextHopDecision {
                        next_hop: *peer_id,
                        hop_count: 1,
                        latency_estimate: neighbor.latency,
                        transport: neighbor.transports.first().copied(),
                    });
                }
            }
        }

        // Look up in routing table
        let table = self.routing_table.read().unwrap();
        if let Some(routes) = table.get(destination) {
            // Filter to active routes with valid next hops
            let neighbors = self.neighbors.read().unwrap();
            for route in routes {
                if let Some(neighbor) = neighbors.get(&route.next_hop) {
                    if neighbor.is_active {
                        return Some(NextHopDecision {
                            next_hop: route.next_hop,
                            hop_count: route.hop_count,
                            latency_estimate: route.latency_estimate,
                            transport: neighbor.transports.first().copied(),
                        });
                    }
                }
            }
        }

        None
    }

    /// Route a packet - determines next hop and establishes/updates active link
    pub fn route_packet(
        &self,
        source: MeshAddress,
        destination: MeshAddress,
        _packet_size: usize,
    ) -> Result<RoutingResult> {
        let dest_device = destination.device_address();
        let conv_id = source.conversation_id();

        // Check if we already have an active link for this conversation
        {
            let links = self.active_links.read().unwrap();
            if let Some(link) = links.get(&conv_id) {
                // Verify the link is still valid (next hop is still reachable)
                let neighbors = self.neighbors.read().unwrap();
                if neighbors
                    .get(&link.next_hop)
                    .map(|n| n.is_active)
                    .unwrap_or(false)
                {
                    return Ok(RoutingResult {
                        next_hop: link.next_hop,
                        is_final: dest_device == self.our_address,
                        new_link: false,
                    });
                }
                // Link is stale, will be replaced below
            }
        }

        // Find next hop for this destination
        let decision = self.next_hop_for(&dest_device).ok_or_else(|| {
            MeshInfinityError::NetworkError(format!("No route to destination {:?}", dest_device))
        })?;

        // Create/update active link
        let link = ActiveLink {
            source,
            destination,
            next_hop: decision.next_hop,
            established: Instant::now(),
            last_activity: Instant::now(),
            bytes_forwarded: 0,
        };

        self.active_links.write().unwrap().insert(conv_id, link);

        Ok(RoutingResult {
            next_hop: decision.next_hop,
            is_final: dest_device == self.our_address,
            new_link: true,
        })
    }

    /// Update activity on a link (packet forwarded)
    pub fn update_link_activity(&self, conv_id: &ConversationId, bytes: u64) {
        if let Some(link) = self.active_links.write().unwrap().get_mut(conv_id) {
            link.last_activity = Instant::now();
            link.bytes_forwarded += bytes;
        }
    }

    /// Close a link (transmission complete)
    pub fn close_link(&self, conv_id: &ConversationId) {
        self.active_links.write().unwrap().remove(conv_id);
    }

    /// Cleanup stale routes and links
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Clean stale routes
        {
            let mut table = self.routing_table.write().unwrap();
            for routes in table.values_mut() {
                routes.retain(|r| now.duration_since(r.last_updated) < self.config.route_timeout);
            }
            table.retain(|_, routes| !routes.is_empty());
        }

        // Clean inactive links
        {
            let mut links = self.active_links.write().unwrap();
            links.retain(|_, link| {
                now.duration_since(link.last_activity) < self.config.link_timeout
            });
        }

        // Clean stale neighbors
        {
            let mut neighbors = self.neighbors.write().unwrap();
            for neighbor in neighbors.values_mut() {
                if now.duration_since(neighbor.last_seen) > self.config.route_timeout {
                    neighbor.is_active = false;
                }
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> HopRouterStats {
        let neighbors = self.neighbors.read().unwrap();
        let active_neighbors = neighbors.values().filter(|n| n.is_active).count();

        HopRouterStats {
            total_neighbors: neighbors.len(),
            active_neighbors,
            routing_entries: self.routing_table.read().unwrap().len(),
            active_links: self.active_links.read().unwrap().len(),
        }
    }

    /// Get all known reachable destinations
    pub fn reachable_destinations(&self) -> Vec<DeviceAddress> {
        self.routing_table.read().unwrap().keys().copied().collect()
    }

    /// Check if a destination is reachable
    pub fn is_reachable(&self, destination: &DeviceAddress) -> bool {
        self.next_hop_for(destination).is_some()
    }
}

/// Result of a next-hop decision
#[derive(Debug, Clone)]
pub struct NextHopDecision {
    pub next_hop: PeerId,
    pub hop_count: u8,
    pub latency_estimate: Duration,
    pub transport: Option<TransportType>,
}

/// Result of routing a packet
#[derive(Debug, Clone)]
pub struct RoutingResult {
    /// The peer to forward to
    pub next_hop: PeerId,
    /// Is this the final destination (us)?
    pub is_final: bool,
    /// Did we create a new link?
    pub new_link: bool,
}

/// Router statistics
#[derive(Debug, Clone)]
pub struct HopRouterStats {
    pub total_neighbors: usize,
    pub active_neighbors: usize,
    pub routing_entries: usize,
    pub active_links: usize,
}

/// Get current time in milliseconds
fn current_time_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build deterministic device address for tests.
    fn make_device_addr(seed: u8) -> DeviceAddress {
        let mut bytes = [0u8; 20];
        bytes[0] = seed;
        DeviceAddress::new(bytes)
    }

    /// Build deterministic peer id for tests.
    fn make_peer_id(seed: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes
    }

    /// Adding a neighbor should immediately create a direct 1-hop route.
    #[test]
    fn test_add_neighbor() {
        let our_addr = make_device_addr(1);
        let our_peer = make_peer_id(1);
        let router = HopRouter::new(our_addr, our_peer);

        let neighbor = NeighborInfo {
            peer_id: make_peer_id(2),
            device_address: make_device_addr(2),
            transports: vec![TransportType::Clearnet],
            trust_level: TrustLevel::Trusted,
            latency: Duration::from_millis(50),
            last_seen: Instant::now(),
            is_active: true,
        };

        router.add_neighbor(neighbor.clone());

        let decision = router.next_hop_for(&make_device_addr(2));
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().next_hop, make_peer_id(2));
    }

    /// Valid reachability announcement should install a multi-hop route.
    #[test]
    fn test_process_announcement() {
        let our_addr = make_device_addr(1);
        let our_peer = make_peer_id(1);
        let router = HopRouter::new(our_addr, our_peer);

        // Add a direct neighbor
        let neighbor = NeighborInfo {
            peer_id: make_peer_id(2),
            device_address: make_device_addr(2),
            transports: vec![TransportType::Clearnet],
            trust_level: TrustLevel::Trusted,
            latency: Duration::from_millis(50),
            last_seen: Instant::now(),
            is_active: true,
        };
        router.add_neighbor(neighbor);

        // Neighbor announces they can reach peer 3
        let announcement = ReachabilityAnnouncement {
            destination: make_device_addr(3),
            hop_count: 1,
            latency_estimate_ms: 30,
            path_trust: TrustLevel::Trusted,
            timestamp_ms: current_time_ms(),
            sequence: 1,
        };

        let accepted = router.process_announcement(make_peer_id(2), announcement);
        assert!(accepted);

        // Should now be able to reach peer 3 through peer 2
        let decision = router.next_hop_for(&make_device_addr(3));
        assert!(decision.is_some());
        let decision = decision.unwrap();
        assert_eq!(&decision.next_hop, &make_peer_id(2));
        assert_eq!(decision.hop_count, 2);
    }

    /// Routing to direct neighbor should return expected next hop decision.
    #[test]
    fn test_route_packet() {
        let our_addr = make_device_addr(1);
        let our_peer = make_peer_id(1);
        let router = HopRouter::new(our_addr, our_peer);

        let neighbor = NeighborInfo {
            peer_id: make_peer_id(2),
            device_address: make_device_addr(2),
            transports: vec![TransportType::Clearnet],
            trust_level: TrustLevel::Trusted,
            latency: Duration::from_millis(50),
            last_seen: Instant::now(),
            is_active: true,
        };
        router.add_neighbor(neighbor);

        let conv_id = ConversationId::random();
        let source = our_addr.with_conversation(conv_id);
        let dest = make_device_addr(2).with_conversation(conv_id);

        let result = router.route_packet(source, dest, 100);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.next_hop, make_peer_id(2));
        assert!(result.new_link);
    }

    /// Subsequent packets in same conversation should reuse active link.
    #[test]
    fn test_link_reuse() {
        let our_addr = make_device_addr(1);
        let our_peer = make_peer_id(1);
        let router = HopRouter::new(our_addr, our_peer);

        let neighbor = NeighborInfo {
            peer_id: make_peer_id(2),
            device_address: make_device_addr(2),
            transports: vec![TransportType::Clearnet],
            trust_level: TrustLevel::Trusted,
            latency: Duration::from_millis(50),
            last_seen: Instant::now(),
            is_active: true,
        };
        router.add_neighbor(neighbor);

        let conv_id = ConversationId::random();
        let source = our_addr.with_conversation(conv_id);
        let dest = make_device_addr(2).with_conversation(conv_id);

        // First packet creates link
        let result1 = router.route_packet(source, dest, 100).unwrap();
        assert!(result1.new_link);

        // Second packet reuses link
        let result2 = router.route_packet(source, dest, 100).unwrap();
        assert!(!result2.new_link);
    }

    /// Split horizon must avoid re-announcing neighbor-learned routes back.
    #[test]
    fn test_generate_announcements_uses_split_horizon() {
        let our_addr = make_device_addr(1);
        let our_peer = make_peer_id(1);
        let router = HopRouter::new(our_addr, our_peer);

        let neighbor_peer = make_peer_id(2);
        let neighbor_addr = make_device_addr(2);

        let neighbor = NeighborInfo {
            peer_id: neighbor_peer,
            device_address: neighbor_addr,
            transports: vec![TransportType::Tor],
            trust_level: TrustLevel::Trusted,
            latency: Duration::from_millis(30),
            last_seen: Instant::now(),
            is_active: true,
        };
        router.add_neighbor(neighbor);

        // Learned through that same neighbor.
        let learned_dest = make_device_addr(9);
        let accepted = router.process_announcement(
            neighbor_peer,
            ReachabilityAnnouncement {
                destination: learned_dest,
                hop_count: 1,
                latency_estimate_ms: 20,
                path_trust: TrustLevel::Trusted,
                timestamp_ms: current_time_ms(),
                sequence: 1,
            },
        );
        assert!(accepted);

        // Generic announcements include that destination.
        let all = router.generate_announcements();
        assert!(all.iter().any(|a| a.destination == learned_dest));

        // Scoped announcements for that neighbor should withhold it.
        let scoped = router.generate_announcements_for_neighbor(Some(neighbor_peer));
        assert!(!scoped.iter().any(|a| a.destination == learned_dest));
        // Still announces ourselves.
        assert!(scoped.iter().any(|a| a.destination == our_addr));
    }

    /// Reachability announcements must not leak next-hop identity metadata.
    #[test]
    fn test_reachability_announcement_has_no_next_hop_identity_fields() {
        let announcement = ReachabilityAnnouncement {
            destination: make_device_addr(7),
            hop_count: 2,
            latency_estimate_ms: 42,
            path_trust: TrustLevel::Caution,
            timestamp_ms: current_time_ms(),
            sequence: 55,
        };

        let json = serde_json::to_string(&announcement).expect("serialize announcement");
        assert!(!json.contains("next_hop"));
        assert!(!json.contains("peer_id"));
    }
}
