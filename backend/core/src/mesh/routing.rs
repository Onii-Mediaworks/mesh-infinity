// Mesh routing implementation
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use crate::core::PeerId;
use crate::core::error::Result;
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
    path_cache: HashMap<(PeerId, PeerId), Vec<PathInfo>>,
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
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            path_cache: HashMap::new(),
        }
    }
    
    pub fn get_best_route(&self, target: &PeerId) -> Option<RouteInfo> {
        self.routes.get(target).cloned()
    }
    
    pub fn calculate_paths(
        &mut self,
        source: &PeerId,
        target: &PeerId,
        available_transports: &[crate::core::TransportType],
    ) -> Vec<PathInfo> {
        let cache_key = (*source, *target);
        if let Some(paths) = self.path_cache.get(&cache_key) {
            return paths.clone();
        }

        // Simple implementation - would use Dijkstra's algorithm in real version
        let mut paths = Vec::new();
        
        if let Some(route) = self.get_best_route(target) {
            paths.push(route.primary_path);
            paths.extend(route.backup_paths);
        }

        if !available_transports.is_empty() {
            paths.retain(|path| available_transports.contains(&path.transport));
        }

        if !paths.is_empty() {
            self.path_cache.insert(cache_key, paths.clone());
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
