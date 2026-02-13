// VPN Service - System-wide proxy/VPN like Tailscale
// Provides virtual network interface for routing all traffic through the mesh

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use crate::core::{PeerId, PeerInfo};
use crate::core::error::{MeshInfinityError, Result};
use super::virtual_interface::VirtualInterface;
use super::dns_resolver::DnsResolver;
use crate::core::mesh::WireGuardMesh;

/// VPN Service provides system-wide network routing through the mesh
/// Modeled after Tailscale's architecture
pub struct VpnService {
    /// Virtual network interface (TUN device)
    interface: Arc<Mutex<VirtualInterface>>,

    /// Maps peer IDs to their virtual IP addresses
    peer_ip_map: Arc<RwLock<HashMap<PeerId, IpAddr>>>,

    /// Reverse map: IP to peer ID
    ip_peer_map: Arc<RwLock<HashMap<IpAddr, PeerId>>>,

    /// DNS resolver for mesh-internal names
    #[allow(dead_code)]
    dns_resolver: Arc<DnsResolver>,

    /// Packet handler callback
    packet_handler: Arc<Mutex<Option<Box<dyn PacketHandler + Send>>>>,

    /// WireGuard mesh for direct integration
    wg_mesh: Arc<RwLock<Option<Arc<RwLock<WireGuardMesh>>>>>,

    /// Running state
    running: Arc<Mutex<bool>>,

    /// Virtual network range (default: 100.64.0.0/10 like Tailscale)
    network_range: String,
}

/// Trait for handling packets routed through the VPN
pub trait PacketHandler: Send {
    /// Handle an outbound packet (from local machine to mesh)
    fn handle_outbound(&mut self, dest_ip: IpAddr, packet: Vec<u8>) -> Result<()>;

    /// Handle an inbound packet (from mesh to local machine)
    fn handle_inbound(&mut self, source_ip: IpAddr, packet: Vec<u8>) -> Result<()>;
}

impl VpnService {
    /// Create a new VPN service
    ///
    /// # Arguments
    /// * `interface_name` - Name for the virtual interface (e.g., "mi0")
    /// * `network_range` - CIDR range for virtual IPs (e.g., "100.64.0.0/10")
    pub fn new(interface_name: &str, network_range: &str) -> Result<Self> {
        let interface = VirtualInterface::new(interface_name, network_range)?;

        let dns_resolver = DnsResolver::new()?;

        Ok(Self {
            interface: Arc::new(Mutex::new(interface)),
            peer_ip_map: Arc::new(RwLock::new(HashMap::new())),
            ip_peer_map: Arc::new(RwLock::new(HashMap::new())),
            dns_resolver: Arc::new(dns_resolver),
            packet_handler: Arc::new(Mutex::new(None)),
            wg_mesh: Arc::new(RwLock::new(None)),
            running: Arc::new(Mutex::new(false)),
            network_range: network_range.to_string(),
        })
    }

    /// Start the VPN service
    /// Begins packet processing loop
    pub fn start(&self) -> Result<()> {
        let mut running = self.running.lock().unwrap();
        if *running {
            return Err(MeshInfinityError::NetworkError(
                "VPN service already running".to_string()
            ));
        }
        *running = true;
        drop(running);

        // Start packet processing thread
        let interface = self.interface.clone();
        let running_flag = self.running.clone();
        let packet_handler = self.packet_handler.clone();
        let ip_peer_map = self.ip_peer_map.clone();
        let wg_mesh = self.wg_mesh.clone();

        thread::spawn(move || {
            let mut buffer = vec![0u8; 65536]; // Max IP packet size

            while *running_flag.lock().unwrap() {
                // Read packet from TUN device
                let bytes_read = match interface.lock().unwrap().read_packet(&mut buffer) {
                    Ok(n) if n > 0 => n,
                    Ok(_) => continue, // Filtered packet
                    Err(_) => {
                        thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                };

                let packet = buffer[..bytes_read].to_vec();

                // Parse IP header to get destination
                if let Some(dest_ip) = parse_dest_ip(&packet) {
                    // Check if this is for a known peer
                    if let Some(peer_id) = ip_peer_map.read().unwrap().get(&dest_ip) {
                        // Try WireGuard mesh first (if available)
                        let mut sent_via_wg = false;
                        if let Some(wg) = wg_mesh.read().unwrap().as_ref() {
                            if let Ok(wg_lock) = wg.read() {
                                if wg_lock.send_message(peer_id, &packet).is_ok() {
                                    sent_via_wg = true;
                                }
                            }
                        }

                        // Fallback to packet handler if WireGuard didn't work
                        if !sent_via_wg {
                            if let Some(handler) = packet_handler.lock().unwrap().as_mut() {
                                let _ = handler.handle_outbound(dest_ip, packet);
                            }
                        }
                    } else {
                        // Regular internet traffic - could be handled differently
                        // For now, drop or forward to real gateway
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the VPN service
    pub fn stop(&self) -> Result<()> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        Ok(())
    }

    /// Register a peer with a virtual IP address
    /// This makes the peer reachable via the VPN
    pub fn register_peer(&self, peer_id: PeerId, _peer_info: &PeerInfo) -> Result<IpAddr> {
        // Allocate a new IP for this peer
        let ip = self.interface.lock().unwrap().allocate_ip()?;

        // Store bidirectional mapping
        self.peer_ip_map.write().unwrap().insert(peer_id, ip);
        self.ip_peer_map.write().unwrap().insert(ip, peer_id);

        // Add route for this peer
        let interface_name = self.interface.lock().unwrap().get_interface_name();
        self.interface
            .lock()
            .unwrap()
            .add_route(ip, None, &interface_name)?;

        Ok(ip)
    }

    /// Unregister a peer from the VPN
    pub fn unregister_peer(&self, peer_id: &PeerId) -> Result<()> {
        if let Some(ip) = self.peer_ip_map.write().unwrap().remove(peer_id) {
            self.ip_peer_map.write().unwrap().remove(&ip);
        }
        Ok(())
    }

    /// Get the virtual IP for a peer
    pub fn get_peer_ip(&self, peer_id: &PeerId) -> Option<IpAddr> {
        self.peer_ip_map.read().unwrap().get(peer_id).copied()
    }

    /// Get the peer ID for a virtual IP
    pub fn get_ip_peer(&self, ip: &IpAddr) -> Option<PeerId> {
        self.ip_peer_map.read().unwrap().get(ip).copied()
    }

    /// Inject an inbound packet from the mesh
    /// This sends a packet to the local machine through the TUN device
    pub fn inject_inbound_packet(&self, packet: &[u8]) -> Result<()> {
        self.interface.lock().unwrap().write_packet(packet)?;
        Ok(())
    }

    /// Set the packet handler for outbound traffic
    pub fn set_packet_handler<H: PacketHandler + 'static>(&self, handler: H) {
        *self.packet_handler.lock().unwrap() = Some(Box::new(handler));
    }

    /// Set the WireGuard mesh for direct packet routing
    pub fn set_wireguard_mesh(&self, wg_mesh: Arc<RwLock<WireGuardMesh>>) {
        *self.wg_mesh.write().unwrap() = Some(wg_mesh);
    }

    /// Route packet directly through WireGuard mesh (if available)
    fn route_through_wireguard(&self, dest_ip: IpAddr, packet: Vec<u8>) -> bool {
        if let Some(wg_mesh) = self.wg_mesh.read().unwrap().as_ref() {
            // Look up peer ID for destination IP
            if let Some(peer_id) = self.ip_peer_map.read().unwrap().get(&dest_ip) {
                // Send through WireGuard
                if let Ok(wg) = wg_mesh.read() {
                    return wg.send_message(peer_id, &packet).is_ok();
                }
            }
        }
        false
    }

    /// Get interface name
    pub fn get_interface_name(&self) -> String {
        self.interface.lock().unwrap().get_interface_name()
    }

    /// Get the network range
    pub fn get_network_range(&self) -> String {
        self.network_range.clone()
    }

    /// Allocate the next available IP (for ourselves)
    pub fn allocate_local_ip(&self) -> Result<IpAddr> {
        self.interface.lock().unwrap().allocate_ip()
    }
}

/// Parse destination IP from IP packet
/// Returns the destination IP address from the packet header
fn parse_dest_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        return None; // Too short for IP header
    }

    // Check IP version
    let version = (packet[0] >> 4) & 0x0F;

    match version {
        4 => {
            // IPv4: destination is bytes 16-19
            if packet.len() < 20 {
                return None;
            }
            let dest = Ipv4Addr::new(
                packet[16],
                packet[17],
                packet[18],
                packet[19],
            );
            Some(IpAddr::V4(dest))
        }
        6 => {
            // IPv6: destination is bytes 24-39
            if packet.len() < 40 {
                return None;
            }
            // For now, just return None for IPv6
            // Full implementation would parse IPv6 header
            None
        }
        _ => None,
    }
}

/// Parse source IP from IP packet
pub fn parse_source_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        return None;
    }

    let version = (packet[0] >> 4) & 0x0F;

    match version {
        4 => {
            // IPv4: source is bytes 12-15
            let src = Ipv4Addr::new(
                packet[12],
                packet[13],
                packet[14],
                packet[15],
            );
            Some(IpAddr::V4(src))
        }
        6 => None, // Not implemented yet
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_dest() {
        // Minimal IPv4 packet header
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, header length 5
        packet[16] = 192;
        packet[17] = 168;
        packet[18] = 1;
        packet[19] = 1;

        let dest = parse_dest_ip(&packet);
        assert_eq!(dest, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_parse_ipv4_source() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4
        packet[12] = 10;
        packet[13] = 0;
        packet[14] = 0;
        packet[15] = 1;

        let src = parse_source_ip(&packet);
        assert_eq!(src, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }
}
