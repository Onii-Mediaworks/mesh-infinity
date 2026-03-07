//! Mesh routing and relay-forwarding logic.
//!
//! This module owns outbound message queuing, path selection, retry behavior,
//! and hop-by-hop packet forwarding semantics. It is the bridge between higher
//! level service messaging and transport-level connection attempts.
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::WireGuardMesh;
use crate::core::error::Result;
use crate::core::{PeerId, TransportQuality};
use crate::transport::TransportManager;

pub struct MessageRouter {
    local_peer_id: PeerId,
    routing_table: Arc<RwLock<RoutingTable>>,
    transport_manager: Arc<TransportManager>,
    wireguard_mesh: Arc<RwLock<Option<Arc<RwLock<WireGuardMesh>>>>>,
    outbound_queue: Arc<Mutex<PriorityQueue<OutboundMessage>>>,
    ack_tracker: Arc<AckTracker>,
    retry_policy: RetryPolicy,
    local_inbox: Arc<Mutex<Vec<Vec<u8>>>>,
}

pub struct RoutingTable {
    routes: HashMap<PeerId, RouteInfo>,
    path_cache: HashMap<(PeerId, PeerId), Vec<PeerId>>,
    /// Network topology graph: peer -> (neighbor, cost)
    graph: HashMap<PeerId, Vec<(PeerId, f32)>>,
}

impl Default for RoutingTable {
    /// Create an empty routing table with no cached paths.
    fn default() -> Self {
        Self::new()
    }
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

#[derive(Clone, Copy)]
pub enum MessagePriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Multi-hop mesh packet with routing information
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MeshPacket {
    /// Immediate next hop only (previous/future hops are not exposed)
    pub next_hop: PeerId,
    /// Final destination peer
    pub destination: PeerId,
    /// Relay metadata epoch
    pub relay_epoch: u64,
    /// Per-hop relay tag; rotated each hop to reduce metadata linkability
    pub relay_tag: [u8; 16],
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
    /// Node equality is defined by both route cost and peer identity.
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost && self.peer_id == other.peer_id
    }
}

impl Ord for DijkstraNode {
    /// Reverse ordering so [`BinaryHeap`] behaves like a min-heap by cost.
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap
        other
            .cost
            .partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
            .then_with(|| self.peer_id.cmp(&other.peer_id))
    }
}

impl PartialOrd for DijkstraNode {
    /// Delegate partial ordering to total ordering implementation.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct AckTracker {
    pending: Mutex<HashMap<PeerId, SystemTime>>,
    delivered: Mutex<u64>,
    failed: Mutex<u64>,
}

impl Default for AckTracker {
    /// Create ack tracker with empty pending set and zero counters.
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct RouterMetrics {
    pub pending: usize,
    pub delivered: u64,
    pub failed: u64,
}

pub struct RetryPolicy {
    max_retries: u8,
    backoff: Duration,
}

pub struct PriorityQueue<T> {
    items: BinaryHeap<QueuedMessage<T>>,
    sequence: u64,
}

impl<T> Default for PriorityQueue<T> {
    /// Create empty priority queue with initial sequence counter.
    fn default() -> Self {
        Self {
            items: BinaryHeap::new(),
            sequence: 0,
        }
    }
}

struct QueuedMessage<T> {
    priority: u8,
    sequence: u64,
    item: T,
}

impl<T> Eq for QueuedMessage<T> {}

impl<T> PartialEq for QueuedMessage<T> {
    /// Queue entries are equal when priority and insertion order match.
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl<T> Ord for QueuedMessage<T> {
    /// Higher priority wins; ties are FIFO by sequence number.
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl<T> PartialOrd for QueuedMessage<T> {
    /// Delegate partial ordering to total ordering implementation.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl MessageRouter {
    /// Construct a router bound to local peer identity and transport manager.
    pub fn new(transport_manager: Arc<TransportManager>, local_peer_id: PeerId) -> Self {
        Self {
            local_peer_id,
            routing_table: Arc::new(RwLock::new(RoutingTable::new())),
            transport_manager,
            wireguard_mesh: Arc::new(RwLock::new(None)),
            outbound_queue: Arc::new(Mutex::new(PriorityQueue::new())),
            ack_tracker: Arc::new(AckTracker::new()),
            retry_policy: RetryPolicy::default(),
            local_inbox: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Attach the active WireGuard mesh instance used for tunnel-first sends.
    pub fn set_wireguard_mesh(&self, wireguard_mesh: Arc<RwLock<WireGuardMesh>>) {
        if let Ok(mut slot) = self.wireguard_mesh.write() {
            *slot = Some(wireguard_mesh);
        }
    }

    /// Enqueue a message for delivery, lazily filling preferred paths if missing.
    pub fn route_message(&self, message: OutboundMessage) -> Result<()> {
        // Add to outbound queue
        let mut message = message;

        if message.preferred_paths.is_empty() {
            if let Some(route) = self
                .routing_table
                .read()
                .unwrap()
                .get_best_route(&message.target)
            {
                let mut paths = Vec::with_capacity(1 + route.backup_paths.len());
                paths.push(route.primary_path);
                paths.extend(route.backup_paths);
                message.preferred_paths = paths;
            }
        }

        self.outbound_queue.lock().unwrap().push(message);
        Ok(())
    }

    /// Drain and process outbound queue until empty.
    pub fn process_queue(&self) -> Result<()> {
        // Process messages in the queue
        let mut queue = self.outbound_queue.lock().unwrap();
        while let Some(message) = queue.pop() {
            self.send_message(message)?;
        }
        Ok(())
    }

    /// Attempt to deliver one outbound message using tunnel-first policy.
    ///
    /// Strategy:
    /// 1) validate TTL and path data,
    /// 2) try active WireGuard tunnel first,
    /// 3) fall back to direct underlay path attempts,
    /// 4) queue retry or mark failure.
    fn send_message(&self, message: OutboundMessage) -> Result<()> {
        if message.ttl == 0 {
            self.ack_tracker.record_failed(&message.target);
            return Err(crate::core::error::MeshInfinityError::NetworkError(
                "Message TTL expired".to_string(),
            ));
        }

        if message.preferred_paths.is_empty() {
            self.ack_tracker.record_failed(&message.target);
            return Err(crate::core::error::MeshInfinityError::NoAvailableTransport);
        }

        // Active tunnel-first path: always attempt WireGuard before underlay-direct sends.
        if let Ok(wg_slot) = self.wireguard_mesh.read() {
            if let Some(wg_mesh) = wg_slot.as_ref() {
                if let Ok(wg) = wg_mesh.read() {
                    if wg
                        .send_message(&message.target, &message.payload.data)
                        .is_ok()
                    {
                        self.ack_tracker.track_pending(message.target);
                        self.ack_tracker.record_delivered(&message.target);
                        return Ok(());
                    }
                }
            }
        }

        // Try each path in order
        //
        // Security policy:
        // - Clearnet underlay must not carry direct plaintext-or-app-layer sends.
        // - Clearnet is only allowed as a WireGuard-enveloped path (attempted
        //   above in the tunnel-first branch).
        for path in &message.preferred_paths {
            if path.transport == crate::core::TransportType::Clearnet {
                continue;
            }

            let Some(transport) = self.transport_manager.get_transport(&path.transport) else {
                continue;
            };

            if let Ok(mut connection) = transport.connect(&crate::core::PeerInfo {
                peer_id: message.target,
                public_key: [0; 32],
                trust_level: crate::core::TrustLevel::Untrusted,
                available_transports: vec![path.transport],
                last_seen: None,
                endpoint: None,
                transport_endpoints: std::collections::HashMap::new(),
            }) {
                // Send the message
                connection.send(&message.payload.data)?;
                self.transport_manager
                    .track_connection(&peer_label(&message.target), connection);
                self.ack_tracker.track_pending(message.target);
                self.ack_tracker.record_delivered(&message.target);
                return Ok(());
            }
        }

        // If all paths failed, handle retry
        self.handle_retry(message)
    }

    /// Apply retry policy and requeue message when budget remains.
    fn handle_retry(&self, mut message: OutboundMessage) -> Result<()> {
        if self
            .retry_policy
            .should_retry(message.current_retry, message.max_retries)
        {
            message.current_retry += 1;
            message.ttl = message.ttl.saturating_sub(1);
            std::thread::sleep(self.retry_policy.backoff_delay(message.current_retry));
            // Add back to queue with delay
            self.outbound_queue.lock().unwrap().push(message);
        } else {
            self.ack_tracker.record_failed(&message.target);
        }

        Err(crate::core::error::MeshInfinityError::TransportError(
            "All paths failed".to_string(),
        ))
    }

    /// Forward a multi-hop mesh packet
    pub fn forward_packet(&self, mut packet: MeshPacket) -> Result<()> {
        // Check TTL to prevent routing loops
        if packet.ttl == 0 {
            return Err(crate::core::error::MeshInfinityError::NetworkError(
                "Packet TTL expired".to_string(),
            ));
        }
        packet.ttl -= 1;

        // Enforce hop-by-hop forwarding invariant: only intended next hop may process.
        if packet.next_hop != self.local_peer_id {
            return Err(crate::core::error::MeshInfinityError::SecurityError(
                "packet received by non-designated relay hop".to_string(),
            ));
        }

        // Destination reached at this hop if next_hop is destination.
        // Only immediate-hop metadata is visible to each relay.
        if self.local_peer_id == packet.destination {
            // This packet is for us - deliver locally
            return self.deliver_local(&packet);
        }

        // Determine next hop toward destination using current routing state.
        let next_hop = packet.next_hop;
        let subsequent_hop = self
            .routing_table
            .read()
            .unwrap()
            .get_best_route(&packet.destination)
            .map(|r| r.primary_path.endpoint.peer_id)
            .unwrap_or(packet.destination);

        packet.relay_epoch = packet.relay_epoch.saturating_add(1);
        packet.relay_tag = derive_relay_tag(&packet.relay_tag, &subsequent_hop, packet.relay_epoch);
        packet.next_hop = subsequent_hop;

        // Serialize packet
        let packet_bytes = serde_json::to_vec(&packet).map_err(|e| {
            crate::core::error::MeshInfinityError::SerializationError(e.to_string())
        })?;

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

    /// Deliver packet payload to local consumers on this node.
    ///
    /// Placeholder: wired for success currently, to be integrated with the
    /// application/event dispatch layer.
    fn deliver_local(&self, _packet: &MeshPacket) -> Result<()> {
        self.local_inbox
            .lock()
            .unwrap()
            .push(_packet.payload.clone());
        Ok(())
    }

    /// Drain locally-delivered packet payloads for application consumers.
    pub fn drain_local_inbox(&self) -> Vec<Vec<u8>> {
        let mut inbox = self.local_inbox.lock().unwrap();
        std::mem::take(&mut *inbox)
    }

    /// Return aggregate router delivery counters.
    pub fn metrics(&self) -> RouterMetrics {
        self.ack_tracker.metrics()
    }
}

impl RoutingTable {
    /// Create an empty routing table and shortest-path cache.
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            path_cache: HashMap::new(),
            graph: HashMap::new(),
        }
    }

    /// Fetch best known route to target peer, if present.
    pub fn get_best_route(&self, target: &PeerId) -> Option<RouteInfo> {
        self.routes.get(target).cloned()
    }

    /// Calculate and cache shortest peer path with Dijkstra's algorithm.
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

        while let Some(DijkstraNode {
            peer_id: current,
            cost,
        }) = heap.pop()
        {
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

    /// Update adjacency list from fresh neighbor quality observations.
    pub fn update_graph(&mut self, peer: PeerId, neighbors: Vec<(PeerId, TransportQuality)>) {
        let edges = neighbors
            .into_iter()
            .map(|(n, q)| (n, Self::quality_to_cost(&q)))
            .collect();
        self.graph.insert(peer, edges);

        // Invalidate cache when topology changes
        self.path_cache.clear();
    }

    /// Convert transport quality metrics to additive path cost (lower is better).
    fn quality_to_cost(quality: &TransportQuality) -> f32 {
        let latency_score = quality.latency.as_millis() as f32 / 1000.0;
        let reliability_score = (1.0 - quality.reliability) * 10.0;
        let cost_score = quality.cost * 5.0;
        latency_score + reliability_score + cost_score
    }

    /// Build candidate path list for a source-target pair.
    ///
    /// Uses cached route metadata and filters candidates by currently allowed
    /// transports.
    pub fn calculate_paths(
        &mut self,
        source: &PeerId,
        target: &PeerId,
        available_transports: &[crate::core::TransportType],
    ) -> Vec<PathInfo> {
        // Use Dijkstra to find shortest path
        let _peer_path = self.calculate_shortest_path(source, target);

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
    /// Create an empty outbound priority queue.
    pub fn new() -> Self {
        Self {
            items: BinaryHeap::new(),
            sequence: 0,
        }
    }

    /// Push outbound message with stable insertion sequence for tie-breaking.
    pub fn push(&mut self, message: OutboundMessage) {
        self.sequence = self.sequence.wrapping_add(1);
        self.items.push(QueuedMessage {
            priority: priority_rank(message.priority),
            sequence: self.sequence,
            item: message,
        });
    }

    /// Pop highest-priority queued message, if any.
    pub fn pop(&mut self) -> Option<OutboundMessage> {
        self.items.pop().map(|queued| queued.item)
    }
}

impl AckTracker {
    /// Create tracker with empty pending map and zeroed counters.
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            delivered: Mutex::new(0),
            failed: Mutex::new(0),
        }
    }

    /// Mark target peer as awaiting delivery confirmation.
    pub fn track_pending(&self, target: PeerId) {
        self.pending
            .lock()
            .unwrap()
            .insert(target, SystemTime::now());
    }

    /// Remove target from pending set.
    pub fn clear_pending(&self, target: &PeerId) {
        self.pending.lock().unwrap().remove(target);
    }

    /// Mark target as delivered and increment delivered counter.
    pub fn record_delivered(&self, target: &PeerId) {
        self.clear_pending(target);
        if let Ok(mut delivered) = self.delivered.lock() {
            *delivered = delivered.saturating_add(1);
        }
    }

    /// Mark target as failed and increment failure counter.
    pub fn record_failed(&self, target: &PeerId) {
        self.clear_pending(target);
        if let Ok(mut failed) = self.failed.lock() {
            *failed = failed.saturating_add(1);
        }
    }

    /// Snapshot current ack-tracker metrics.
    pub fn metrics(&self) -> RouterMetrics {
        let pending = self.pending.lock().map(|p| p.len()).unwrap_or(0);
        let delivered = self.delivered.lock().map(|v| *v).unwrap_or(0);
        let failed = self.failed.lock().map(|v| *v).unwrap_or(0);
        RouterMetrics {
            pending,
            delivered,
            failed,
        }
    }
}

impl Default for RetryPolicy {
    /// Default retry policy tuned for short, bounded retry windows.
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff: Duration::from_millis(250),
        }
    }
}

impl RetryPolicy {
    /// Determine whether another retry is permitted for this message.
    pub fn should_retry(&self, current_retry: u8, message_max: u8) -> bool {
        let limit = self.max_retries.min(message_max);
        current_retry < limit
    }

    /// Compute linear backoff delay for `attempt` (minimum 1x base backoff).
    pub fn backoff_delay(&self, attempt: u8) -> Duration {
        self.backoff.saturating_mul(u32::from(attempt.max(1)))
    }
}

/// Convert binary peer id into fixed uppercase hex label for logging/keys.
fn peer_label(peer_id: &PeerId) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(peer_id.len() * 2);
    for &byte in peer_id {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Map message priority enum to queue rank used by [`PriorityQueue`].
fn priority_rank(priority: MessagePriority) -> u8 {
    match priority {
        MessagePriority::Low => 0,
        MessagePriority::Normal => 1,
        MessagePriority::High => 2,
        MessagePriority::Critical => 3,
    }
}

/// Derive a per-hop relay tag that rotates across hop/epoch/time context.
fn derive_relay_tag(previous_tag: &[u8; 16], next_hop: &PeerId, relay_epoch: u64) -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut input = Vec::with_capacity(16 + 32 + 8 + 16);
    input.extend_from_slice(previous_tag);
    input.extend_from_slice(next_hop);
    input.extend_from_slice(&relay_epoch.to_be_bytes());
    input.extend_from_slice(&nanos.to_be_bytes());

    let hash = digest(&SHA256, &input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_ref()[..16]);
    out
}

#[cfg(test)]
mod routing_security_tests {
    use super::*;
    use crate::core::error::MeshInfinityError;
    use serde_json::Value;

    /// Relay tag must change as epoch changes, preventing static correlation.
    #[test]
    fn relay_tag_rotates_per_hop_epoch() {
        let seed = [1u8; 16];
        let hop = [2u8; 32];
        let a = derive_relay_tag(&seed, &hop, 1);
        let b = derive_relay_tag(&seed, &hop, 2);
        assert_ne!(a, b);
    }

    /// Router must reject packets not addressed to the local relay hop.
    #[test]
    fn forward_packet_rejects_non_designated_hop() {
        let router = MessageRouter::new(Arc::new(TransportManager::new()), [9u8; 32]);

        let packet = MeshPacket {
            next_hop: [1u8; 32],
            destination: [2u8; 32],
            relay_epoch: 1,
            relay_tag: [0u8; 16],
            payload: vec![7, 7, 7],
            ttl: 2,
        };

        let err = router.forward_packet(packet).unwrap_err();
        assert!(matches!(err, MeshInfinityError::SecurityError(_)));
    }

    /// Missing paths should fail fast without attempting undefined sends.
    #[test]
    fn send_message_without_paths_fails_fast() {
        let router = MessageRouter::new(Arc::new(TransportManager::new()), [3u8; 32]);
        let msg = OutboundMessage {
            payload: EncryptedPayload {
                data: vec![1, 2, 3],
                encryption_key_id: [0u8; 32],
                mac: [0u8; 32],
            },
            target: [4u8; 32],
            priority: MessagePriority::Normal,
            preferred_paths: Vec::new(),
            ttl: 2,
            max_retries: 3,
            current_retry: 0,
        };

        let err = router.send_message(msg).unwrap_err();
        assert!(matches!(err, MeshInfinityError::NoAvailableTransport));
    }

    /// Serialized relay packet must avoid source/origin lineage exposure.
    #[test]
    fn relay_packet_metadata_excludes_origin_linkage_fields() {
        let packet = MeshPacket {
            next_hop: [0x11; 32],
            destination: [0x22; 32],
            relay_epoch: 4,
            relay_tag: [0x33; 16],
            payload: vec![1, 2, 3, 4],
            ttl: 7,
        };

        let encoded = serde_json::to_vec(&packet).expect("serialize packet");
        let json: Value = serde_json::from_slice(&encoded).expect("parse packet json");
        let object = json.as_object().expect("mesh packet object");

        // Relay-visible packet must not expose full-route or origin lineage fields.
        assert!(!object.contains_key("source"));
        assert!(!object.contains_key("origin"));
        assert!(!object.contains_key("hops"));
        assert!(!object.contains_key("current_hop"));

        // Only immediate routing metadata should be visible.
        assert!(object.contains_key("next_hop"));
        assert!(object.contains_key("destination"));
        assert!(object.contains_key("relay_tag"));
    }

    /// Local-destination packets should be delivered to local inbox.
    #[test]
    fn forward_packet_delivers_to_local_inbox() {
        let router = MessageRouter::new(Arc::new(TransportManager::new()), [7u8; 32]);

        let packet = MeshPacket {
            next_hop: [7u8; 32],
            destination: [7u8; 32],
            relay_epoch: 1,
            relay_tag: [1u8; 16],
            payload: b"local delivery payload".to_vec(),
            ttl: 4,
        };

        router.forward_packet(packet).expect("forward local packet");
        let inbox = router.drain_local_inbox();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0], b"local delivery payload".to_vec());
    }
}
