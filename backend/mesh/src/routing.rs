// Mesh routing implementation
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use crate::core::core::PeerId;
use crate::core::error::Result;
use std::time::{SystemTime, Duration};

pub struct RoutingTable {
    routes: Arc<RwLock<HashMap<PeerId, RouteInfo>>>,
    path_cache: Arc<RwLock<HashMap<(PeerId, PeerId), Vec<PathInfo>>>>,
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
    pub transport: crate::core::core::TransportType,
    pub endpoint: Endpoint,
    pub latency: Option<Duration>,
    pub reliability: f32,
    pub bandwidth: Option<u64>,
    pub cost: f32,
}

#[derive(Clone)]
pub struct Endpoint {
    pub peer_id: PeerId,
    pub address: String, // Could be IP:port, Tor address, etc.
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            path_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub fn get_best_route(&self, target: &PeerId) -> Option<RouteInfo> {
        let routes = self.routes.read().unwrap();
        routes.get(target).cloned()
    }
    
    pub fn calculate_paths(
        &self,
        source: &PeerId,
        target: &PeerId,
        available_transports: &[crate::core::core::TransportType],
    ) -> Vec<PathInfo> {
        let cache_key = (*source, *target);
        if let Some(paths) = self.path_cache.read().unwrap().get(&cache_key) {
            return paths.clone();
        }

        // Simple implementation - would use Dijkstra's algorithm in real version
        let mut paths = Vec::new();

        // Check for direct connection
        if let Some(route) = self.get_best_route(target) {
            paths.push(route.primary_path);
            paths.extend(route.backup_paths);
        }

        if !available_transports.is_empty() {
            paths.retain(|path| available_transports.contains(&path.transport));
        }

        if !paths.is_empty() {
            self.path_cache.write().unwrap().insert(cache_key, paths.clone());
        }

        paths
    }
    
    pub fn add_route(&self, peer_id: PeerId, route: RouteInfo) {
        let mut routes = self.routes.write().unwrap();
        routes.insert(peer_id, route);
    }
    
    pub fn update_route_quality(&self, peer_id: &PeerId, quality: f32) -> Result<()> {
        let mut routes = self.routes.write().unwrap();
        if let Some(route) = routes.get_mut(peer_id) {
            route.quality_score = quality;
            route.last_updated = SystemTime::now();
            Ok(())
        } else {
            Err(crate::core::error::NetInfinityError::PeerNotFound(
                format!("{:?}", peer_id)
            ))
        }
    }
}
