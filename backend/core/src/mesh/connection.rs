// Connection management for mesh peers
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};

use crate::core::{PeerId, PeerInfo};
use crate::core::error::Result;
use crate::core::transport::TransportManager;
use crate::core::auth::web_of_trust::WebOfTrust;
use crate::core::discovery::MdnsDiscovery;
use super::wireguard::WireGuardMesh;

/// Connection handshake messages
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectionRequest {
    pub peer_id: PeerId,
    pub wg_public_key: [u8; 32],
    pub protocol_version: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectionAccept {
    pub peer_id: PeerId,
    pub wg_public_key: [u8; 32],
    pub assigned_ip: std::net::IpAddr,
    pub protocol_version: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectionReject {
    pub reason: RejectReason,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RejectReason {
    Untrusted,
    AtCapacity,
    ProtocolMismatch,
    InternalError,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ping {
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Pong {
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Disconnect {
    pub reason: String,
}

/// Manages peer connections and handshakes
pub struct ConnectionManager {
    local_peer_id: PeerId,
    wg_mesh: Arc<RwLock<WireGuardMesh>>,
    trust_system: Arc<RwLock<WebOfTrust>>,
    transport_manager: Arc<TransportManager>,
    discovery: Option<Arc<MdnsDiscovery>>,
}

impl ConnectionManager {
    pub fn new(
        local_peer_id: PeerId,
        wg_mesh: Arc<RwLock<WireGuardMesh>>,
        trust_system: Arc<RwLock<WebOfTrust>>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            local_peer_id,
            wg_mesh,
            trust_system,
            transport_manager,
            discovery: None,
        }
    }

    pub fn set_discovery(&mut self, discovery: Arc<MdnsDiscovery>) {
        self.discovery = Some(discovery);
    }

    /// Establish a connection with a peer
    pub async fn establish_connection(&self, peer: &PeerInfo) -> Result<()> {
        // 1. Check trust level
        let is_trusted = {
            let trust = self.trust_system.read()
                .map_err(|e| crate::core::error::MeshInfinityError::LockError(format!("Trust lock: {}", e)))?;

            // Check if we have a trust relationship with this peer
            match trust.get_trust_level(&peer.peer_id) {
                Some(level) => {
                    // Accept Trusted or HighlyTrusted
                    matches!(level, crate::core::TrustLevel::Trusted | crate::core::TrustLevel::HighlyTrusted)
                }
                None => false,
            }
        };

        if !is_trusted {
            return Err(crate::core::error::MeshInfinityError::UntrustedPeer);
        }

        // 2. Get WireGuard public key
        let wg_public_key = {
            let wg = self.wg_mesh.read()
                .map_err(|e| crate::core::error::MeshInfinityError::LockError(format!("WG lock: {}", e)))?;
            wg.public_key()
        };

        // 3. Create connection request
        let request = ConnectionRequest {
            peer_id: self.local_peer_id,
            wg_public_key,
            protocol_version: 1,
        };

        // 4. Send request over transport
        let mut connection = self.transport_manager
            .get_best_connection(peer, &peer.available_transports)
            .await?;

        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| crate::core::error::MeshInfinityError::SerializationError(e.to_string()))?;

        connection.send(&request_bytes)?;

        // 5. Receive response
        let mut response_buf = vec![0u8; 4096];
        let len = connection.receive(&mut response_buf)?;

        // Try to deserialize as ConnectionAccept
        let accept_result: std::result::Result<ConnectionAccept, _> = serde_json::from_slice(&response_buf[..len]);

        match accept_result {
            Ok(accept) => {
                // 6. Add peer to WireGuard mesh
                let mut wg = self.wg_mesh.write()
                    .map_err(|e| crate::core::error::MeshInfinityError::LockError(format!("WG lock: {}", e)))?;

                wg.add_peer(
                    peer.peer_id,
                    accept.wg_public_key,
                    vec![accept.assigned_ip],
                    peer.endpoint,
                    Some(25), // 25s keepalive
                )?;

                Ok(())
            }
            Err(e) => {
                // Try to deserialize as rejection
                if let Ok(reject) = serde_json::from_slice::<ConnectionReject>(&response_buf[..len]) {
                    Err(crate::core::error::MeshInfinityError::ConnectionRejected(
                        format!("{:?}", reject.reason)
                    ))
                } else {
                    Err(crate::core::error::MeshInfinityError::SerializationError(
                        format!("Failed to deserialize response: {}", e)
                    ))
                }
            }
        }
    }

    /// Handle incoming connection request
    pub async fn handle_connection_request(
        &self,
        request: ConnectionRequest,
        source_peer: &PeerInfo,
    ) -> Result<ConnectionAccept> {
        // 1. Verify trust
        let is_trusted = {
            let trust = self.trust_system.read()
                .map_err(|e| crate::core::error::MeshInfinityError::LockError(format!("Trust lock: {}", e)))?;

            // Check if we have a trust relationship with this peer
            match trust.get_trust_level(&request.peer_id) {
                Some(level) => {
                    matches!(level, crate::core::TrustLevel::Trusted | crate::core::TrustLevel::HighlyTrusted)
                }
                None => false,
            }
        };

        if !is_trusted {
            return Err(crate::core::error::MeshInfinityError::UntrustedPeer);
        }

        // 2. Check protocol version
        if request.protocol_version != 1 {
            return Err(crate::core::error::MeshInfinityError::ProtocolMismatch);
        }

        // 3. Allocate IP address for peer (TODO: implement proper IP allocation)
        let assigned_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 42, 0, 2));

        // 4. Add peer to WireGuard mesh
        let mut wg = self.wg_mesh.write()
            .map_err(|e| crate::core::error::MeshInfinityError::LockError(format!("WG lock: {}", e)))?;

        wg.add_peer(
            request.peer_id,
            request.wg_public_key,
            vec![assigned_ip],
            source_peer.endpoint,
            Some(25), // 25s keepalive
        )?;

        // 5. Create accept response
        let accept = ConnectionAccept {
            peer_id: self.local_peer_id,
            wg_public_key: wg.public_key(),
            assigned_ip,
            protocol_version: 1,
        };

        Ok(accept)
    }

    /// Send ping to peer
    pub async fn ping(&self, peer: &PeerInfo) -> Result<u64> {
        let start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ping = Ping { timestamp: start };
        let ping_bytes = serde_json::to_vec(&ping)
            .map_err(|e| crate::core::error::MeshInfinityError::SerializationError(e.to_string()))?;

        let mut connection = self.transport_manager
            .get_best_connection(peer, &peer.available_transports)
            .await?;

        connection.send(&ping_bytes)?;

        // Wait for pong
        let mut pong_buf = vec![0u8; 256];
        let len = connection.receive(&mut pong_buf)?;

        let _pong: Pong = serde_json::from_slice(&pong_buf[..len])
            .map_err(|e| crate::core::error::MeshInfinityError::SerializationError(e.to_string()))?;

        let end = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Ok(end - start)
    }

    /// Disconnect from peer
    pub fn disconnect(&self, peer_id: &PeerId, reason: String) -> Result<()> {
        let mut wg = self.wg_mesh.write()
            .map_err(|e| crate::core::error::MeshInfinityError::LockError(format!("WG lock: {}", e)))?;
        wg.remove_peer(peer_id)?;

        // TODO: Send disconnect message to peer

        Ok(())
    }
}
