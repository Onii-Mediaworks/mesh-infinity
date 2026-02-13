use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use crate::core::error::{MeshInfinityError, Result};
use crate::core::core::PeerId;

#[derive(Clone)]
pub struct Route {
    pub gateway: PeerId,
    pub metric: u32,
}

pub struct TrafficRouter {
    routing_table: Arc<RwLock<HashMap<IpAddr, Route>>>,
    default_gateway: Arc<RwLock<Option<PeerId>>>,
}

impl TrafficRouter {
    pub fn new() -> Self {
        Self {
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            default_gateway: Arc::new(RwLock::new(None)),
        }
    }

    pub fn add_route(&self, destination: IpAddr, gateway: PeerId, metric: u32) -> Result<()> {
        let mut table = self.routing_table.write()
            .map_err(|e| MeshInfinityError::LockError(format!("Routing table lock poisoned: {}", e)))?;
        table.insert(destination, Route { gateway, metric });
        Ok(())
    }

    pub fn remove_route(&self, destination: &IpAddr) -> Result<()> {
        let mut table = self.routing_table.write()
            .map_err(|e| MeshInfinityError::LockError(format!("Routing table lock poisoned: {}", e)))?;
        table.remove(destination);
        Ok(())
    }

    pub fn set_default_gateway(&self, gateway: Option<PeerId>) -> Result<()> {
        let mut gw = self.default_gateway.write()
            .map_err(|e| MeshInfinityError::LockError(format!("Default gateway lock poisoned: {}", e)))?;
        *gw = gateway;
        Ok(())
    }

    pub fn route(&self, destination: IpAddr, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Err(MeshInfinityError::InvalidInput("Empty payload".to_string()));
        }

        let table = self.routing_table.read()
            .map_err(|e| MeshInfinityError::LockError(format!("Routing table lock poisoned: {}", e)))?;

        // Look up specific route
        if let Some(_route) = table.get(&destination) {
            // Route found - in a real implementation, this would forward the packet
            // For now, we just validate that routing is configured
            return Ok(());
        }

        // Check for default gateway
        let gw = self.default_gateway.read()
            .map_err(|e| MeshInfinityError::LockError(format!("Default gateway lock poisoned: {}", e)))?;

        if gw.is_some() {
            // Default gateway exists - would forward there
            return Ok(());
        }

        Err(MeshInfinityError::NetworkError(format!(
            "No route to destination: {}",
            destination
        )))
    }

    pub fn get_route(&self, destination: &IpAddr) -> Result<Option<Route>> {
        let table = self.routing_table.read()
            .map_err(|e| MeshInfinityError::LockError(format!("Routing table lock poisoned: {}", e)))?;
        Ok(table.get(destination).cloned())
    }
}

impl Default for TrafficRouter {
    fn default() -> Self {
        Self::new()
    }
}
