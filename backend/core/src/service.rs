// MeshService - Main orchestrator for Mesh Infinity
// Coordinates all subsystems: discovery, transport, mesh, routing, trust

use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::core::error::{MeshInfinityError, Result};
use crate::core::{PeerId, TrustLevel};
use crate::core::transport::TransportManager;
use crate::core::mesh::{WireGuardMesh, ConnectionManager, MessageRouter, ObfuscationMode};
use crate::core::auth::{WebOfTrust, TrustStorage};
use crate::core::discovery::MdnsDiscovery;
use crate::core::network_stack::vpn_service::VpnService;

/// Main service that orchestrates all mesh components
pub struct MeshService {
    // Identity
    local_peer_id: PeerId,

    // Discovery
    mdns: Arc<MdnsDiscovery>,

    // Transport
    transport_manager: Arc<TransportManager>,

    // Mesh
    wg_mesh: Arc<RwLock<WireGuardMesh>>,
    connection_manager: Arc<ConnectionManager>,

    // Routing
    message_router: Arc<MessageRouter>,

    // Network
    vpn_service: Option<Arc<VpnService>>,

    // Trust
    web_of_trust: Arc<RwLock<WebOfTrust>>,
    trust_storage: Arc<TrustStorage>,

    // State
    running: Arc<RwLock<bool>>,
}

impl MeshService {
    /// Create a new MeshService
    pub fn new(
        local_peer_id: PeerId,
        wg_mesh: Arc<RwLock<WireGuardMesh>>,
        transport_manager: Arc<TransportManager>,
        web_of_trust: Arc<RwLock<WebOfTrust>>,
        mdns: Arc<MdnsDiscovery>,
        message_router: Arc<MessageRouter>,
        trust_storage_path: &str,
    ) -> Result<Self> {
        let trust_storage = Arc::new(TrustStorage::new(trust_storage_path)?);

        let connection_manager = Arc::new(ConnectionManager::new(
            local_peer_id,
            wg_mesh.clone(),
            web_of_trust.clone(),
            transport_manager.clone(),
        ));

        Ok(Self {
            local_peer_id,
            mdns,
            transport_manager,
            wg_mesh,
            connection_manager,
            message_router,
            vpn_service: None,
            web_of_trust,
            trust_storage,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Set VPN service (optional)
    pub fn set_vpn_service(&mut self, vpn_service: Arc<VpnService>) {
        vpn_service.set_wireguard_mesh(self.wg_mesh.clone());
        self.vpn_service = Some(vpn_service);
    }

    /// Enable traffic obfuscation
    pub fn enable_obfuscation(&self, mode: ObfuscationMode) -> Result<()> {
        let wg = self.wg_mesh.read()
            .map_err(|e| MeshInfinityError::LockError(format!("WG lock: {}", e)))?;
        wg.set_obfuscation(mode)?;
        Ok(())
    }

    /// Start the mesh service
    pub async fn start(&self) -> Result<()> {
        {
            let mut running = self.running.write()
                .map_err(|e| MeshInfinityError::LockError(format!("Running lock: {}", e)))?;
            if *running {
                return Err(MeshInfinityError::NetworkError(
                    "Service already running".to_string()
                ));
            }
            *running = true;
        }

        // 1. Load trust graph from disk (if exists)
        if self.trust_storage.exists() {
            match self.trust_storage.load() {
                Ok(exported) => {
                    let imported_trust = WebOfTrust::import(exported);
                    *self.web_of_trust.write()
                        .map_err(|e| MeshInfinityError::LockError(format!("Trust lock: {}", e)))? = imported_trust;
                }
                Err(e) => {
                    // Log warning but continue - not fatal
                    eprintln!("Warning: Failed to load trust graph: {:?}", e);
                }
            }
        }

        // 2. Initialize transports (clearnet, Tor if available)
        // Transport manager should already be initialized

        // 3. Start mDNS discovery
        self.mdns.start()?;

        // 4. Start VPN packet loop (if VPN service is configured)
        if let Some(vpn) = &self.vpn_service {
            vpn.start()?;
        }

        // 5. Auto-connect to discovered trusted peers
        self.connect_to_discovered_peers().await?;

        // 6. Start periodic tasks
        self.start_periodic_tasks().await?;

        Ok(())
    }

    /// Stop the mesh service
    pub fn stop(&self) -> Result<()> {
        let mut running = self.running.write()
            .map_err(|e| MeshInfinityError::LockError(format!("Running lock: {}", e)))?;

        if !*running {
            return Err(MeshInfinityError::NetworkError(
                "Service not running".to_string()
            ));
        }

        // Stop VPN service
        if let Some(vpn) = &self.vpn_service {
            vpn.stop()?;
        }

        // Save trust graph before stopping
        let trust = self.web_of_trust.read()
            .map_err(|e| MeshInfinityError::LockError(format!("Trust lock: {}", e)))?;
        let exported = trust.export();
        self.trust_storage.save(&exported)?;

        *running = false;
        Ok(())
    }

    /// Check if service is running
    pub fn is_running(&self) -> bool {
        self.running.read().map(|r| *r).unwrap_or(false)
    }

    /// Connect to discovered trusted peers
    async fn connect_to_discovered_peers(&self) -> Result<()> {
        let peers = self.mdns.discovered_peers()?;

        for peer in peers {
            // Check if peer is trusted
            let is_trusted = {
                let trust = self.web_of_trust.read()
                    .map_err(|e| MeshInfinityError::LockError(format!("Trust lock: {}", e)))?;

                match trust.get_trust_level(&peer.peer_id) {
                    Some(level) => matches!(level, TrustLevel::Trusted | TrustLevel::HighlyTrusted),
                    None => false,
                }
            };

            if is_trusted {
                // Attempt to establish connection
                match self.connection_manager.establish_connection(&peer).await {
                    Ok(_) => {
                        // Connection successful
                    }
                    Err(e) => {
                        // Log error but continue with other peers
                        eprintln!("Failed to connect to peer {:?}: {:?}", peer.peer_id, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Start periodic background tasks
    async fn start_periodic_tasks(&self) -> Result<()> {
        // Task 1: Periodic routing table updates
        let router = self.message_router.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            loop {
                let is_running = running.read().map(|r| *r).unwrap_or(false);
                if !is_running {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
                // Router would update routes here
                // router.update_routes().await;
            }
        });

        // Task 2: Trust temporal decay (hourly)
        let trust = self.web_of_trust.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            loop {
                let is_running = running.read().map(|r| *r).unwrap_or(false);
                if !is_running {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(3600)).await;
                if let Ok(mut trust_lock) = trust.write() {
                    trust_lock.apply_temporal_decay();
                }
            }
        });

        // Task 3: Trust persistence (every 5 minutes)
        let trust = self.web_of_trust.clone();
        let storage = self.trust_storage.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            loop {
                let is_running = running.read().map(|r| *r).unwrap_or(false);
                if !is_running {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(300)).await;
                if let Ok(trust_lock) = trust.read() {
                    let exported = trust_lock.export();
                    let _ = storage.save(&exported);
                }
            }
        });

        // Task 4: Periodic peer discovery refresh
        let _mdns = self.mdns.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            loop {
                let is_running = running.read().map(|r| *r).unwrap_or(false);
                if !is_running {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
                // Refresh discovery
                // MdnsDiscovery automatically refreshes, no manual refresh needed
            }
        });

        Ok(())
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Get connection manager
    pub fn connection_manager(&self) -> Arc<ConnectionManager> {
        self.connection_manager.clone()
    }

    /// Get message router
    pub fn message_router(&self) -> Arc<MessageRouter> {
        self.message_router.clone()
    }

    /// Get web of trust
    pub fn web_of_trust(&self) -> Arc<RwLock<WebOfTrust>> {
        self.web_of_trust.clone()
    }

    /// Get WireGuard mesh
    pub fn wireguard_mesh(&self) -> Arc<RwLock<WireGuardMesh>> {
        self.wg_mesh.clone()
    }

    /// Get VPN service
    pub fn vpn_service(&self) -> Option<Arc<VpnService>> {
        self.vpn_service.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_creation() {
        // This is a basic structural test
        // Full integration tests would require more setup
    }
}
