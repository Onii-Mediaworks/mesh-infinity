// Mesh routing implementation
use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

use crate::core::{PeerId, TransportQuality};
use crate::core::error::{Result, MeshInfinityError};
use crate::core::transport::TransportManager;

pub struct MessageRouter {
    routing_table: Arc<RwLock<RoutingTable>>,
    transport_manager: Arc<TransportManager>,
    outbound_queue: Arc<Mutex<PriorityQueue<OutboundMessage>>>,
    ack_tracker: Arc<AckTracker>,
    retry_policy: RetryPolicy,
}

pub struct RoutingTable {
    routes: HashMap<PeerId, RouteInfo>,
    path_cache: HashMap<(PeerId, PeerId), Vec<PeerId>>,
    /// Network topology graph: peer -> (neighbor, cost)
    graph: HashMap<PeerId, Vec<(PeerId, f32)>>,
}

#[derive(Clone)]
pub struct RouteInfo {
    pub primary_path: PathInfo,
    pub backup_paths: Vec<PathInfo>,
    pub last_updated: SystemTime,
    pub quality_score: f32,
}

#[derive(Clone)]
pub struct PathInfo {
    pub transport: crate::core::TransportType,
    pub endpoint: Endpoint,
    pub latency: Option<Duration>,
    pub reliability: f32,
    pub bandwidth: Option<u64>,
    pub cost: f32,
}

#[derive(Clone)]
pub struct Endpoint {
    pub peer_id: PeerId,
    pub address: String,
}

pub struct OutboundMessage {
    pub payload: EncryptedPayload,
    pub target: PeerId,
    pub priority: MessagePriority,
    pub preferred_paths: Vec<PathInfo>,
    pub ttl: u8,
    pub max_retries: u8,
    pub current_retry: u8,
}

pub struct EncryptedPayload {
    pub data: Vec<u8>,
    pub encryption_key_id: [u8; 32],
    pub mac: [u8; 32],
}

pub enum MessagePriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Multi-hop mesh packet with routing information
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MeshPacket {
    /// Ordered list of peer IDs forming the complete path
    pub hops: Vec<PeerId>,
    /// Current position in the hop list
    pub current_hop: usize,
    /// Encrypted payload for final destination
    pub payload: Vec<u8>,
    /// Time-to-live to prevent routing loops
    pub ttl: u8,
}

/// Node state for Dijkstra's algorithm
#[derive(Clone)]
struct DijkstraNode {
    peer_id: PeerId,
    cost: f32,
}

impl Eq for DijkstraNode {}

impl PartialEq for DijkstraNode {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost && self.peer_id == other.peer_id
    }
}

impl Ord for DijkstraNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap
        other.cost.partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
            .then_with(|| self.peer_id.cmp(&other.peer_id))
    }
}

impl PartialOrd for DijkstraNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct AckTracker {
    pending: Mutex<HashMap<PeerId, SystemTime>>,
}

pub struct RetryPolicy {
    max_retries: u8,
    backoff: Duration,
}

pub struct PriorityQueue<T> {
    items: Vec<T>,
}

impl MessageRouter {
    pub fn new(transport_manager: Arc<TransportManager>) -> Self {
        Self {
            routing_table: Arc::new(RwLock::new(RoutingTable::new())),
            transport_manager,
            outbound_queue: Arc::new(Mutex::new(PriorityQueue::new())),
            ack_tracker: Arc::new(AckTracker::new()),
            retry_policy: RetryPolicy::default(),
        }
    }
    
    pub fn route_message(&self, message: OutboundMessage) -> Result<()> {
        // Add to outbound queue
        let mut message = message;

        if message.preferred_paths.is_empty() {
            if let Some(route) = self.routing_table.read().unwrap().get_best_route(&message.target) {
                let mut paths = Vec::with_capacity(1 + route.backup_paths.len());
                paths.push(route.primary_path);
                paths.extend(route.backup_paths);
                message.preferred_paths = paths;
            }
        }

        self.outbound_queue.lock().unwrap().push(message);
        Ok(())
    }
    
    pub fn process_queue(&self) -> Result<()> {
        // Process messages in the queue
        let mut queue = self.outbound_queue.lock().unwrap();
        while let Some(message) = queue.pop() {
            self.send_message(message)?;
        }
        Ok(())
    }
    
    fn send_message(&self, message: OutboundMessage) -> Result<()> {
        // Try each path in order
        for path in &message.preferred_paths {
            if let Ok(mut connection) = self.transport_manager
                .get_transport(&path.transport)
                .unwrap()
                .connect(&crate::core::PeerInfo {
                    peer_id: message.target,
                    public_key: [0; 32], // Would be proper public key
                    trust_level: crate::core::TrustLevel::Untrusted,
                    available_transports: vec![path.transport],
                    last_seen: None,
                    endpoint: None,
                }) {
                // Send the message
                connection.send(&message.payload.data)?;
                self.transport_manager
                    .track_connection(&peer_label(&message.target), connection);
                self.ack_tracker.track_pending(message.target);
                return Ok(());
            }
        }
        
        // If all paths failed, handle retry
        self.handle_retry(message)
    }
    
    fn handle_retry(&self, mut message: OutboundMessage) -> Result<()> {
        if self.retry_policy.should_retry(message.current_retry, message.max_retries) {
            message.current_retry += 1;
            // Add back to queue with delay
            self.outbound_queue.lock().unwrap().push(message);
        } else {
            self.ack_tracker.clear_pending(&message.target);
        }

        Err(crate::core::error::MeshInfinityError::TransportError(
            "All paths failed".to_string()
        ))
    }

    /// Forward a multi-hop mesh packet
    pub fn forward_packet(&self, mut packet: MeshPacket) -> Result<()> {
        // Check TTL to prevent routing loops
        if packet.ttl == 0 {
            return Err(crate::core::error::MeshInfinityError::NetworkError(
                "Packet TTL expired".to_string()
            ));
        }
        packet.ttl -= 1;

        // Check if we're the destination
        if packet.current_hop >= packet.hops.len() {
            // This packet is for us - deliver locally
            return self.deliver_local(&packet);
        }

        // Get next hop
        let next_hop = packet.hops[packet.current_hop];
        packet.current_hop += 1;

        // Serialize packet
        let packet_bytes = serde_json::to_vec(&packet)
            .map_err(|e| crate::core::error::MeshInfinityError::SerializationError(e.to_string()))?;

        // Forward to next hop (would use WireGuard mesh in real implementation)
        // For now, create a simple outbound message
        let outbound = OutboundMessage {
            payload: EncryptedPayload {
                data: packet_bytes,
                encryption_key_id: [0; 32],
                mac: [0; 32],
            },
            target: next_hop,
            priority: MessagePriority::Normal,
            preferred_paths: Vec::new(),
            ttl: packet.ttl,
            max_retries: 3,
            current_retry: 0,
        };

        self.route_message(outbound)
    }

    /// Deliver packet to local application
    fn deliver_local(&self, packet: &MeshPacket) -> Result<()> {
        // TODO: Implement local delivery to application layer
        // For now, just log that we received it
        Ok(())
    }
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            path_cache: HashMap::new(),
            graph: HashMap::new(),
        }
    }
    
    pub fn get_best_route(&self, target: &PeerId) -> Option<RouteInfo> {
        self.routes.get(target).cloned()
    }
    
    /// Calculate shortest path using Dijkstra's algorithm
    pub fn calculate_shortest_path(&mut self, source: &PeerId, target: &PeerId) -> Vec<PeerId> {
        let cache_key = (*source, *target);
        if let Some(path) = self.path_cache.get(&cache_key) {
            return path.clone();
        }

        // Dijkstra's algorithm
        let mut distances: HashMap<PeerId, f32> = HashMap::new();
        let mut previous: HashMap<PeerId, PeerId> = HashMap::new();
        let mut heap = BinaryHeap::new();
        let mut visited = HashSet::new();

        distances.insert(*source, 0.0);
        heap.push(DijkstraNode {
            peer_id: *source,
            cost: 0.0,
        });

        while let Some(DijkstraNode { peer_id: current, cost }) = heap.pop() {
            // Skip if already visited
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            // Found target
            if current == *target {
                break;
            }

            // Skip if we found a better path already
            if cost > *distances.get(&current).unwrap_or(&f32::MAX) {
                continue;
            }

            // Update neighbors
            if let Some(neighbors) = self.graph.get(&current) {
                for &(neighbor, edge_cost) in neighbors {
                    let new_cost = cost + edge_cost;
                    let current_best = *distances.get(&neighbor).unwrap_or(&f32::MAX);

                    if new_cost < current_best {
                        distances.insert(neighbor, new_cost);
                        previous.insert(neighbor, current);
                        heap.push(DijkstraNode {
                            peer_id: neighbor,
                            cost: new_cost,
                        });
                    }
                }
            }
        }

        // Reconstruct path
        let mut path = Vec::new();
        if previous.contains_key(target) {
            let mut current = *target;
            while current != *source {
                path.push(current);
                if let Some(&prev) = previous.get(&current) {
                    current = prev;
                } else {
                    break;
                }
            }
            path.reverse();
        }

        // Cache result if we found a path
        if !path.is_empty() {
            self.path_cache.insert(cache_key, path.clone());
        }

        path
    }

    /// Update network topology graph
    pub fn update_graph(&mut self, peer: PeerId, neighbors: Vec<(PeerId, TransportQuality)>) {
        let edges = neighbors
            .into_iter()
            .map(|(n, q)| (n, Self::quality_to_cost(&q)))
            .collect();
        self.graph.insert(peer, edges);

        // Invalidate cache when topology changes
        self.path_cache.clear();
    }

    /// Convert transport quality metrics to path cost (lower is better)
    fn quality_to_cost(quality: &TransportQuality) -> f32 {
        let latency_score = quality.latency.as_millis() as f32 / 1000.0;
        let reliability_score = (1.0 - quality.reliability) * 10.0;
        let cost_score = quality.cost * 5.0;
        latency_score + reliability_score + cost_score
    }

    pub fn calculate_paths(
        &mut self,
        source: &PeerId,
        target: &PeerId,
        available_transports: &[crate::core::TransportType],
    ) -> Vec<PathInfo> {
        // Use Dijkstra to find shortest path
        let peer_path = self.calculate_shortest_path(source, target);

        let mut paths = Vec::new();

        if let Some(route) = self.get_best_route(target) {
            paths.push(route.primary_path);
            paths.extend(route.backup_paths);
        }

        if !available_transports.is_empty() {
            paths.retain(|path| available_transports.contains(&path.transport));
        }

        paths
    }
}

impl PriorityQueue<OutboundMessage> {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }
    
    pub fn push(&mut self, message: OutboundMessage) {
        self.items.push(message);
    }
    
    pub fn pop(&mut self) -> Option<OutboundMessage> {
        self.items.pop()
    }
}

impl AckTracker {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn track_pending(&self, target: PeerId) {
        self.pending.lock().unwrap().insert(target, SystemTime::now());
    }

    pub fn clear_pending(&self, target: &PeerId) {
        self.pending.lock().unwrap().remove(target);
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff: Duration::from_millis(250),
        }
    }
}

impl RetryPolicy {
    pub fn should_retry(&self, current_retry: u8, message_max: u8) -> bool {
        let limit = self.max_retries.min(message_max);
        current_retry < limit
    }

    pub fn backoff_delay(&self, attempt: u8) -> Duration {
        self.backoff.saturating_mul(u32::from(attempt.max(1)))
    }
}

fn peer_label(peer_id: &PeerId) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(peer_id.len() * 2);
    for &byte in peer_id {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}
