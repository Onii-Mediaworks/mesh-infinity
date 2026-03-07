//! Exit-node traffic routing with trust and bandwidth policy enforcement.
//!
//! This router resolves destination IP traffic to explicit routes or a default
//! gateway, then enforces gateway trust thresholds and optional rate limits
//! before allowing forwarding.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use crate::core::core::PeerId;
use crate::core::error::{MeshInfinityError, Result};
use crate::core::TrustLevel;

use super::bandwidth_manager::BandwidthManager;

#[derive(Clone)]
pub struct Route {
    pub gateway: PeerId,
    pub metric: u32,
}

pub struct TrafficRouter {
    routing_table: Arc<RwLock<HashMap<IpAddr, Route>>>,
    default_gateway: Arc<RwLock<Option<PeerId>>>,
    gateway_trust: Arc<RwLock<HashMap<PeerId, TrustLevel>>>,
    min_exit_trust: Arc<RwLock<TrustLevel>>,
    bandwidth_manager: Arc<RwLock<Option<Arc<BandwidthManager>>>>,
}

impl TrafficRouter {
    /// Construct a new empty traffic router.
    pub fn new() -> Self {
        Self {
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            default_gateway: Arc::new(RwLock::new(None)),
            gateway_trust: Arc::new(RwLock::new(HashMap::new())),
            min_exit_trust: Arc::new(RwLock::new(TrustLevel::Caution)),
            bandwidth_manager: Arc::new(RwLock::new(None)),
        }
    }

    /// Set minimum trust level required for a gateway to be used as exit.
    pub fn set_min_exit_trust(&self, level: TrustLevel) -> Result<()> {
        let mut min = self
            .min_exit_trust
            .write()
            .map_err(|e| MeshInfinityError::LockError(format!("Min trust lock poisoned: {}", e)))?;
        *min = level;
        Ok(())
    }

    /// Register or update trust level for a candidate gateway peer.
    pub fn register_gateway_trust(&self, gateway: PeerId, trust: TrustLevel) -> Result<()> {
        let mut trust_map = self.gateway_trust.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Gateway trust lock poisoned: {}", e))
        })?;
        trust_map.insert(gateway, trust);
        Ok(())
    }

    /// Attach optional bandwidth limiter used during route checks.
    pub fn set_bandwidth_manager(&self, manager: Option<Arc<BandwidthManager>>) -> Result<()> {
        let mut slot = self
            .bandwidth_manager
            .write()
            .map_err(|e| MeshInfinityError::LockError(format!("Bandwidth lock poisoned: {}", e)))?;
        *slot = manager;
        Ok(())
    }

    /// Add/replace route for destination when metric is better than existing.
    pub fn add_route(&self, destination: IpAddr, gateway: PeerId, metric: u32) -> Result<()> {
        let mut table = self.routing_table.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Routing table lock poisoned: {}", e))
        })?;

        // Keep the best (lowest-metric) route for each destination.
        match table.get(&destination) {
            Some(existing) if existing.metric <= metric => {}
            _ => {
                table.insert(destination, Route { gateway, metric });
            }
        }
        Ok(())
    }

    /// Remove explicit route entry for destination.
    pub fn remove_route(&self, destination: &IpAddr) -> Result<()> {
        let mut table = self.routing_table.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Routing table lock poisoned: {}", e))
        })?;
        table.remove(destination);
        Ok(())
    }

    /// Set or clear default gateway used when no specific route exists.
    pub fn set_default_gateway(&self, gateway: Option<PeerId>) -> Result<()> {
        let mut gw = self.default_gateway.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Default gateway lock poisoned: {}", e))
        })?;
        *gw = gateway;
        Ok(())
    }

    /// Return currently configured default gateway, if any.
    pub fn get_default_gateway(&self) -> Result<Option<PeerId>> {
        let gw = self.default_gateway.read().map_err(|e| {
            MeshInfinityError::LockError(format!("Default gateway lock poisoned: {}", e))
        })?;
        Ok(*gw)
    }

    /// Validate and route payload to destination via explicit/default gateway.
    ///
    /// This function currently performs policy validation and route selection;
    /// actual packet forwarding is left to higher integration layers.
    pub fn route(&self, destination: IpAddr, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Err(MeshInfinityError::InvalidInput("Empty payload".to_string()));
        }

        let table = self.routing_table.read().map_err(|e| {
            MeshInfinityError::LockError(format!("Routing table lock poisoned: {}", e))
        })?;

        // Look up specific route
        if let Some(route) = table.get(&destination) {
            self.enforce_gateway_policy(&route.gateway, payload.len() as u64)?;
            // Route found - in a real implementation, this would forward the packet
            // For now, we just validate that routing is configured
            return Ok(());
        }

        // Check for default gateway
        let gw = self.default_gateway.read().map_err(|e| {
            MeshInfinityError::LockError(format!("Default gateway lock poisoned: {}", e))
        })?;

        if let Some(default_gateway) = *gw {
            self.enforce_gateway_policy(&default_gateway, payload.len() as u64)?;
            // Default gateway exists - would forward there
            return Ok(());
        }

        Err(MeshInfinityError::NetworkError(format!(
            "No route to destination: {}",
            destination
        )))
    }

    /// Return specific route for destination, if present.
    pub fn get_route(&self, destination: &IpAddr) -> Result<Option<Route>> {
        let table = self.routing_table.read().map_err(|e| {
            MeshInfinityError::LockError(format!("Routing table lock poisoned: {}", e))
        })?;
        Ok(table.get(destination).cloned())
    }

    /// Enforce trust threshold and bandwidth reservation for chosen gateway.
    fn enforce_gateway_policy(&self, gateway: &PeerId, payload_bytes: u64) -> Result<()> {
        let min_trust = *self
            .min_exit_trust
            .read()
            .map_err(|e| MeshInfinityError::LockError(format!("Min trust lock poisoned: {}", e)))?;

        let gateway_trust = self
            .gateway_trust
            .read()
            .map_err(|e| {
                MeshInfinityError::LockError(format!("Gateway trust lock poisoned: {}", e))
            })?
            .get(gateway)
            .copied()
            .unwrap_or(TrustLevel::Untrusted);

        if gateway_trust < min_trust {
            return Err(MeshInfinityError::InsufficientTrust);
        }

        if let Some(bandwidth) = self
            .bandwidth_manager
            .read()
            .map_err(|e| MeshInfinityError::LockError(format!("Bandwidth lock poisoned: {}", e)))?
            .clone()
        {
            bandwidth.reserve(payload_bytes)?;
        }

        Ok(())
    }
}

impl Default for TrafficRouter {
    /// Provide default empty router configuration.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Build deterministic test peer id with first byte as seed.
    fn peer(seed: u8) -> PeerId {
        let mut out = [0u8; 32];
        out[0] = seed;
        out
    }

    /// Default gateway use must fail when gateway trust is below policy minimum.
    #[test]
    fn route_rejects_default_gateway_when_below_min_trust() {
        let router = TrafficRouter::new();
        let gateway = peer(9);

        router
            .set_min_exit_trust(TrustLevel::Trusted)
            .expect("set min trust");
        router
            .register_gateway_trust(gateway, TrustLevel::Caution)
            .expect("register trust");
        router
            .set_default_gateway(Some(gateway))
            .expect("set default gateway");

        let dest = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let err = router
            .route(dest, b"hello")
            .expect_err("must fail trust-gate");
        assert!(matches!(err, MeshInfinityError::InsufficientTrust));
    }

    /// Default gateway use succeeds when trust meets/exceeds configured minimum.
    #[test]
    fn route_accepts_default_gateway_when_trust_meets_policy() {
        let router = TrafficRouter::new();
        let gateway = peer(7);

        router
            .set_min_exit_trust(TrustLevel::Caution)
            .expect("set min trust");
        router
            .register_gateway_trust(gateway, TrustLevel::HighlyTrusted)
            .expect("register trust");
        router
            .set_default_gateway(Some(gateway))
            .expect("set default gateway");

        let dest = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        router
            .route(dest, b"hello world")
            .expect("trusted route ok");
    }

    /// Routing must fail when bandwidth limiter denies reservation.
    #[test]
    fn route_enforces_bandwidth_limits() {
        let router = TrafficRouter::new();
        let gateway = peer(5);

        router
            .register_gateway_trust(gateway, TrustLevel::Trusted)
            .expect("register trust");
        router
            .set_default_gateway(Some(gateway))
            .expect("set default gateway");
        router
            .set_bandwidth_manager(Some(Arc::new(BandwidthManager::new(1))))
            .expect("set bandwidth manager");

        // 300 bytes ~= 2.3 Kbps in a 1s window, exceeds 1 Kbps limit.
        let payload = vec![0xAA; 300];
        let dest = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        let err = router
            .route(dest, &payload)
            .expect_err("must fail bandwidth reserve");
        assert!(matches!(err, MeshInfinityError::ResourceUnavailable));
    }

    /// Route table must keep best (lowest metric) path for a destination.
    #[test]
    fn add_route_keeps_lower_metric_path() {
        let router = TrafficRouter::new();
        let dest = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let gateway_a = peer(1);
        let gateway_b = peer(2);

        router
            .add_route(dest, gateway_a, 50)
            .expect("insert initial route");
        router
            .add_route(dest, gateway_b, 90)
            .expect("worse route should be ignored");

        let route = router
            .get_route(&dest)
            .expect("get route")
            .expect("route exists");
        assert_eq!(route.gateway, gateway_a);
        assert_eq!(route.metric, 50);

        router
            .add_route(dest, gateway_b, 10)
            .expect("better route should replace");

        let route = router
            .get_route(&dest)
            .expect("get route")
            .expect("route exists");
        assert_eq!(route.gateway, gateway_b);
        assert_eq!(route.metric, 10);
    }
}
