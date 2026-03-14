//! mDNS-based local-network peer discovery.
//!
//! Advertises local node presence and listens for peer service announcements on
//! LAN, producing `PeerInfo` candidates for the higher discovery coordinator.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::core::error::{MeshInfinityError, Result};
use crate::core::{PeerId, PeerInfo, TransportType, TrustLevel};
use crate::discovery::peer_codec::{hex_to_peer_id, peer_id_to_hex};

const SERVICE_TYPE: &str = "_mesh-infinity._udp.local.";
const PEER_TTL_SECONDS: u64 = 300; // 5 minutes

#[derive(Clone)]
struct DiscoveredPeer {
    peer_info: PeerInfo,
    last_seen: SystemTime,
}

pub struct MdnsDiscovery {
    daemon: Arc<ServiceDaemon>,
    discovered_peers: Arc<RwLock<HashMap<PeerId, DiscoveredPeer>>>,
    local_peer_id: PeerId,
    local_port: u16,
    running: Arc<RwLock<bool>>,
}

impl MdnsDiscovery {
    /// Create a new mDNS discovery service
    pub fn new(local_peer_id: PeerId, local_port: u16) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to create mDNS daemon: {}", e))
        })?;

        Ok(Self {
            daemon: Arc::new(daemon),
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            local_peer_id,
            local_port,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start broadcasting and listening for peers
    pub fn start(&self) -> Result<()> {
        // Set running flag
        {
            let mut running = self.running.write().map_err(|e| {
                MeshInfinityError::LockError(format!("Running lock poisoned: {}", e))
            })?;
            if *running {
                return Err(MeshInfinityError::InvalidInput(
                    "mDNS discovery already running".to_string(),
                ));
            }
            *running = true;
        }

        // Register our service
        self.register_service()?;

        // Start browsing for other peers
        self.browse_services()?;

        Ok(())
    }

    /// Stop broadcasting and listening
    pub fn stop(&self) -> Result<()> {
        let mut running = self
            .running
            .write()
            .map_err(|e| MeshInfinityError::LockError(format!("Running lock poisoned: {}", e)))?;
        *running = false;

        // Shutdown the daemon
        self.daemon.shutdown().map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to shutdown mDNS: {}", e))
        })?;

        Ok(())
    }

    /// Check if the service is running
    pub fn is_running(&self) -> bool {
        self.running.read().map(|r| *r).unwrap_or(false)
    }

    /// Get all discovered peers (excludes stale peers)
    pub fn discovered_peers(&self) -> Result<Vec<PeerInfo>> {
        self.cleanup_stale_peers()?;

        let peers = self.discovered_peers.read().map_err(|e| {
            MeshInfinityError::LockError(format!("Discovered peers lock poisoned: {}", e))
        })?;

        Ok(peers.values().map(|p| p.peer_info.clone()).collect())
    }

    /// Register our service on the network
    fn register_service(&self) -> Result<()> {
        let instance_name = peer_id_to_hex(&self.local_peer_id);

        // Create properties with peer information
        let mut properties = HashMap::new();
        properties.insert("peer_id".to_string(), peer_id_to_hex(&self.local_peer_id));
        properties.insert("version".to_string(), "0.5.0".to_string());

        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &format!("{}.local.", instance_name),
            (),
            self.local_port,
            Some(properties),
        )
        .map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to create service info: {}", e))
        })?;

        self.daemon.register(service_info).map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to register mDNS service: {}", e))
        })?;

        Ok(())
    }

    /// Start browsing for peer services
    fn browse_services(&self) -> Result<()> {
        let receiver = self.daemon.browse(SERVICE_TYPE).map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to browse mDNS: {}", e))
        })?;

        let discovered_peers = Arc::clone(&self.discovered_peers);
        let local_peer_id = self.local_peer_id;
        let running = Arc::clone(&self.running);

        // Spawn a thread to handle service events
        thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                // Check if we should stop
                if let Ok(is_running) = running.read() {
                    if !*is_running {
                        break;
                    }
                }

                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        if let Err(e) =
                            Self::handle_service_resolved(info, &discovered_peers, &local_peer_id)
                        {
                            eprintln!("mDNS error handling resolved service: {}", e);
                        }
                    }
                    ServiceEvent::ServiceRemoved(_, full_name) => {
                        if let Err(e) = Self::handle_service_removed(&full_name, &discovered_peers)
                        {
                            eprintln!("mDNS error handling removed service: {}", e);
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(())
    }

    /// Handle a newly resolved service
    fn handle_service_resolved(
        info: Box<ResolvedService>,
        discovered_peers: &Arc<RwLock<HashMap<PeerId, DiscoveredPeer>>>,
        local_peer_id: &PeerId,
    ) -> Result<()> {
        // Extract peer ID from properties
        let properties = info.get_properties();
        let peer_id_str = properties
            .get("peer_id")
            .map(|v| v.val_str())
            .ok_or_else(|| {
                MeshInfinityError::InvalidInput("No peer_id in mDNS service".to_string())
            })?;

        let peer_id = hex_to_peer_id(peer_id_str)?;

        // Don't add ourselves
        if peer_id == *local_peer_id {
            return Ok(());
        }

        // Get IP addresses
        let addresses: Vec<IpAddr> = info.get_addresses().iter().copied().collect();
        if addresses.is_empty() {
            return Err(MeshInfinityError::InvalidInput(
                "No addresses in mDNS service".to_string(),
            ));
        }

        // Use first available address and create SocketAddr
        use std::net::SocketAddr;
        let endpoint_address = SocketAddr::new(addresses[0], info.get_port());

        // Create PeerInfo
        let peer_info = PeerInfo {
            peer_id,
            public_key: [0u8; 32], // Will be exchanged during handshake
            trust_level: TrustLevel::Untrusted,
            available_transports: vec![TransportType::Clearnet],
            last_seen: Some(SystemTime::now()),
            endpoint: Some(endpoint_address),
            transport_endpoints: std::collections::HashMap::new(),
        };

        // Add to discovered peers
        let mut peers = discovered_peers.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Discovered peers lock poisoned: {}", e))
        })?;

        peers.insert(
            peer_id,
            DiscoveredPeer {
                peer_info,
                last_seen: SystemTime::now(),
            },
        );

        Ok(())
    }

    /// Handle a removed service
    fn handle_service_removed(
        full_name: &str,
        discovered_peers: &Arc<RwLock<HashMap<PeerId, DiscoveredPeer>>>,
    ) -> Result<()> {
        // Extract instance name from full name (format: "instance._service._protocol.local.")
        let instance_name = full_name
            .split('.')
            .next()
            .ok_or_else(|| MeshInfinityError::InvalidInput("Invalid service name".to_string()))?;

        let peer_id = hex_to_peer_id(instance_name)?;

        let mut peers = discovered_peers.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Discovered peers lock poisoned: {}", e))
        })?;

        peers.remove(&peer_id);

        Ok(())
    }

    /// Remove peers that haven't been seen recently
    fn cleanup_stale_peers(&self) -> Result<()> {
        let now = SystemTime::now();
        let ttl = Duration::from_secs(PEER_TTL_SECONDS);

        let mut peers = self.discovered_peers.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Discovered peers lock poisoned: {}", e))
        })?;

        peers.retain(|_, discovered| {
            now.duration_since(discovered.last_seen)
                .map(|elapsed| elapsed < ttl)
                .unwrap_or(false)
        });

        Ok(())
    }
}

impl Drop for MdnsDiscovery {
    /// Best-effort shutdown when discovery instance is dropped.
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Peer-id hex conversion should round-trip losslessly.
    fn test_peer_id_hex_conversion() {
        let peer_id = [0x42u8; 32];
        let hex = peer_id_to_hex(&peer_id);
        assert_eq!(hex.len(), 64);

        let converted = hex_to_peer_id(&hex).unwrap();
        assert_eq!(peer_id, converted);
    }

    #[test]
    /// Invalid hex or length must be rejected by parser.
    fn test_invalid_hex() {
        assert!(hex_to_peer_id("invalid").is_err());
        assert!(hex_to_peer_id("00").is_err()); // Too short
    }
}
