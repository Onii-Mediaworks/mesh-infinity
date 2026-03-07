//! Core mesh-service orchestrator.
//!
//! This service wires together discovery, trust, routing, WireGuard mesh state,
//! and optional VPN integration. It owns lifecycle transitions (`start`/`stop`)
//! and background maintenance tasks (trust decay, persistence, refresh loops).

use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::auth::{TrustStorage, WebOfTrust};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::mesh::{ConnectionManager, MessageRouter, ObfuscationMode, WireGuardMesh};
use crate::core::network_stack::vpn_service::VpnService;
use crate::core::{PeerId, TrustLevel};
use crate::discovery::MdnsDiscovery;
use crate::transport::TransportManager;

/// Main service that orchestrates all mesh components
pub struct MeshService {
    // Identity
    local_peer_id: PeerId,

    // Discovery
    mdns: Arc<MdnsDiscovery>,

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
    /// Build a fully wired mesh service instance.
    ///
    /// The constructor does not start background tasks or open network loops;
    /// callers must invoke [`MeshService::start`] for that.
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

        // Enforce active-tunnel-first behavior at router layer by wiring WG mesh.
        message_router.set_wireguard_mesh(wg_mesh.clone());

        Ok(Self {
            local_peer_id,
            mdns,
            wg_mesh,
            connection_manager,
            message_router,
            vpn_service: None,
            web_of_trust,
            trust_storage,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Attach optional VPN service and bind it to the active WireGuard mesh.
    pub fn set_vpn_service(&mut self, vpn_service: Arc<VpnService>) {
        vpn_service.set_wireguard_mesh(self.wg_mesh.clone());
        self.vpn_service = Some(vpn_service);
    }

    /// Enable or switch WireGuard payload obfuscation mode.
    pub fn enable_obfuscation(&self, mode: ObfuscationMode) -> Result<()> {
        let wg = self
            .wg_mesh
            .read()
            .map_err(|e| MeshInfinityError::LockError(format!("WG lock: {}", e)))?;
        wg.set_obfuscation(mode)?;
        Ok(())
    }

    /// Transition service into running state and start operational loops.
    ///
    /// Startup sequence:
    /// 1) restore trust graph from disk,
    /// 2) start mDNS discovery,
    /// 3) start optional VPN packet loop,
    /// 4) attempt trusted-peer auto-connect,
    /// 5) launch periodic maintenance tasks.
    pub async fn start(&self) -> Result<()> {
        {
            let mut running = self
                .running
                .write()
                .map_err(|e| MeshInfinityError::LockError(format!("Running lock: {}", e)))?;
            if *running {
                return Err(MeshInfinityError::NetworkError(
                    "Service already running".to_string(),
                ));
            }
            *running = true;
        }

        // 1. Load trust graph from disk (if exists)
        if self.trust_storage.exists() {
            match self.trust_storage.load() {
                Ok(exported) => {
                    let imported_trust = WebOfTrust::import(exported);
                    *self.web_of_trust.write().map_err(|e| {
                        MeshInfinityError::LockError(format!("Trust lock: {}", e))
                    })? = imported_trust;
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

    /// Stop service loops and persist trust state for next startup.
    pub fn stop(&self) -> Result<()> {
        let mut running = self
            .running
            .write()
            .map_err(|e| MeshInfinityError::LockError(format!("Running lock: {}", e)))?;

        if !*running {
            return Err(MeshInfinityError::NetworkError(
                "Service not running".to_string(),
            ));
        }

        // Stop VPN service
        if let Some(vpn) = &self.vpn_service {
            vpn.stop()?;
        }

        // Save trust graph before stopping
        let trust = self
            .web_of_trust
            .read()
            .map_err(|e| MeshInfinityError::LockError(format!("Trust lock: {}", e)))?;
        let exported = trust.export();
        self.trust_storage.save(&exported)?;

        *running = false;
        Ok(())
    }

    /// Return whether the service has been marked as running.
    pub fn is_running(&self) -> bool {
        self.running.read().map(|r| *r).unwrap_or(false)
    }

    /// Attempt connections to currently discovered peers that meet trust policy.
    async fn connect_to_discovered_peers(&self) -> Result<()> {
        let peers = self.mdns.discovered_peers()?;

        for peer in peers {
            // Check if peer is trusted
            let is_trusted = {
                let trust = self
                    .web_of_trust
                    .read()
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

    /// Spawn periodic maintenance tasks while service is running.
    ///
    /// Current tasks include route refresh placeholders, trust decay, trust
    /// persistence, and discovery refresh pacing.
    async fn start_periodic_tasks(&self) -> Result<()> {
        // Task 1: Periodic routing table updates
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
                if let Ok(trust_lock) = trust.write() {
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

    /// Return local peer id served by this mesh instance.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Return shared connection manager handle.
    pub fn connection_manager(&self) -> Arc<ConnectionManager> {
        self.connection_manager.clone()
    }

    /// Return shared message router handle.
    pub fn message_router(&self) -> Arc<MessageRouter> {
        self.message_router.clone()
    }

    /// Return shared web-of-trust state handle.
    pub fn web_of_trust(&self) -> Arc<RwLock<WebOfTrust>> {
        self.web_of_trust.clone()
    }

    /// Return shared WireGuard mesh handle.
    pub fn wireguard_mesh(&self) -> Arc<RwLock<WireGuardMesh>> {
        self.wg_mesh.clone()
    }

    /// Return optional VPN service handle if configured.
    pub fn vpn_service(&self) -> Option<Arc<VpnService>> {
        self.vpn_service.clone()
    }
}

#[cfg(test)]
mod tests {
    /// Placeholder smoke-test slot for service construction coverage.
    #[test]
    fn test_service_creation() {
        // This is a basic structural test
        // Full integration tests would require more setup
    }
}
