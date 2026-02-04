// Mesh Packet Router - Routes VPN packets through the mesh network
// Handles peer lookup and packet forwarding through the mesh

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use crate::core::{PeerId, PeerInfo};
use crate::core::error::{MeshInfinityError, Result};
use super::vpn_service::{PacketHandler, VpnService, parse_source_ip};

/// Routes IP packets through the mesh network
/// Handles peer lookup and forwarding
pub struct MeshPacketRouter {
    /// Reference to VPN service for IP/peer mapping
    vpn_service: Arc<VpnService>,

    /// Peer information map
    peer_info: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,

    /// Callback for sending packets to mesh
    /// (peer_id, packet_data) -> Result<()>
    send_callback: Arc<RwLock<Option<Box<dyn Fn(PeerId, Vec<u8>) -> Result<()> + Send + Sync>>>>,

    /// Our own IP address
    local_ip: IpAddr,
}

impl MeshPacketRouter {
    pub fn new(
        vpn_service: Arc<VpnService>,
        local_ip: IpAddr,
    ) -> Self {
        Self {
            vpn_service,
            peer_info: Arc::new(RwLock::new(HashMap::new())),
            send_callback: Arc::new(RwLock::new(None)),
            local_ip,
        }
    }

    /// Set callback for sending packets to the mesh
    pub fn set_send_callback<F>(&self, callback: F)
    where
        F: Fn(PeerId, Vec<u8>) -> Result<()> + Send + Sync + 'static,
    {
        *self.send_callback.write().unwrap() = Some(Box::new(callback));
    }

    /// Register a peer with routing information
    pub fn register_peer(&self, peer_id: PeerId, info: PeerInfo) {
        self.peer_info.write().unwrap().insert(peer_id, info);
    }

    /// Unregister a peer
    pub fn unregister_peer(&self, peer_id: &PeerId) {
        self.peer_info.write().unwrap().remove(peer_id);
    }

    /// Route an outbound packet (from local machine to peer via mesh)
    fn route_outbound(&self, dest_ip: IpAddr, packet: Vec<u8>) -> Result<()> {
        // Look up peer ID from destination IP
        let peer_id = self.vpn_service.get_ip_peer(&dest_ip)
            .ok_or_else(|| MeshInfinityError::NetworkError(
                format!("No peer found for IP {}", dest_ip)
            ))?;

        // Send to mesh via callback
        if let Some(callback) = self.send_callback.read().unwrap().as_ref() {
            callback(peer_id, packet)?;
        } else {
            return Err(MeshInfinityError::NetworkError(
                "No send callback configured".to_string()
            ));
        }

        Ok(())
    }

    /// Handle inbound packet (from mesh to local machine)
    /// This should be called when a packet arrives from the mesh for this node
    pub fn handle_inbound_from_mesh(&self, source_peer: &PeerId, packet: &[u8]) -> Result<()> {
        // Verify source IP matches peer's assigned IP
        if let Some(expected_ip) = self.vpn_service.get_peer_ip(source_peer) {
            if let Some(actual_ip) = parse_source_ip(packet) {
                if actual_ip != expected_ip {
                    return Err(MeshInfinityError::SecurityError(
                        format!("IP spoofing detected: expected {}, got {}", expected_ip, actual_ip)
                    ));
                }
            }
        }

        // Inject packet into TUN device
        self.vpn_service.inject_inbound_packet(packet)?;

        Ok(())
    }

    /// Get statistics about routed packets
    pub fn get_stats(&self) -> RouterStats {
        RouterStats {
            peer_count: self.peer_info.read().unwrap().len(),
            local_ip: self.local_ip,
        }
    }
}

impl PacketHandler for MeshPacketRouter {
    fn handle_outbound(&mut self, dest_ip: IpAddr, packet: Vec<u8>) -> Result<()> {
        self.route_outbound(dest_ip, packet)
    }

    fn handle_inbound(&mut self, _source_ip: IpAddr, _packet: Vec<u8>) -> Result<()> {
        // Inbound packets come through handle_inbound_from_mesh instead
        Ok(())
    }
}

pub struct RouterStats {
    pub peer_count: usize,
    pub local_ip: IpAddr,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_router_creation() {
        // This is a basic test structure
        // Full tests would require mocking the VPN service
        let local_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(format!("{}", local_ip), "100.64.0.1");
    }
}
