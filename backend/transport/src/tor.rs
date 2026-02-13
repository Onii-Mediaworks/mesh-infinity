// Tor transport implementation using arti-client
use crate::core::core::{PeerInfo, TransportType, TransportQuality};
use crate::core::error::{Result, MeshInfinityError};
use crate::core::transport::traits::{Connection, Listener, Transport};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arti_client::{TorClient, TorClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct TorTransport {
    client: Arc<Option<TorClient<tor_rtcompat::PreferredRuntime>>>,
    onion_address: Arc<Mutex<Option<String>>>,
}

impl TorTransport {
    /// Create a new Tor transport (not initialized)
    pub fn new() -> Self {
        Self {
            client: Arc::new(None),
            onion_address: Arc::new(Mutex::new(None)),
        }
    }

    /// Initialize Tor client by bootstrapping
    /// This should be called once at startup
    pub async fn initialize() -> Result<Self> {
        let config = TorClientConfig::default();

        // Bootstrap Tor client with default runtime
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| MeshInfinityError::NetworkError(format!("Failed to bootstrap Tor: {:?}", e)))?;

        Ok(Self {
            client: Arc::new(Some(client)),
            onion_address: Arc::new(Mutex::new(None)),
        })
    }

    /// Get or extract .onion address from peer info
    fn extract_onion_address(peer_info: &PeerInfo) -> Result<String> {
        // Try to extract .onion address from peer endpoint
        if let Some(endpoint) = &peer_info.endpoint {
            let addr_str = endpoint.to_string();
            if addr_str.contains(".onion") {
                // Extract the .onion address
                let parts: Vec<&str> = addr_str.split(':').collect();
                if let Some(onion_part) = parts.first() {
                    return Ok(onion_part.to_string());
                }
            }
        }

        Err(MeshInfinityError::NetworkError(
            "No .onion address found for peer".to_string()
        ))
    }

    /// Check if Tor client is initialized
    pub fn is_initialized(&self) -> bool {
        self.client.is_some()
    }
}

impl Transport for TorTransport {
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        // Check if client is initialized
        if self.client.is_none() {
            return Err(MeshInfinityError::NetworkError(
                "Tor client not initialized".to_string()
            ));
        }

        // Extract .onion address
        let onion_addr = Self::extract_onion_address(peer_info)?;

        // Use a default port for WireGuard (51820)
        let port = 51820u16;

        // Connect via Tor using tokio runtime
        let client_arc = self.client.clone();
        let stream = tokio::runtime::Handle::current()
            .block_on(async move {
                if let Some(ref client_ref) = *client_arc {
                    client_ref
                        .connect((onion_addr.as_str(), port))
                        .await
                        .map_err(|e| MeshInfinityError::NetworkError(format!("Tor connect failed: {:?}", e)))
                } else {
                    Err(MeshInfinityError::NetworkError("Client disappeared".to_string()))
                }
            })?;

        Ok(Box::new(TorConnection {
            stream: Arc::new(Mutex::new(stream)),
            peer: peer_info.clone(),
        }))
    }

    fn listen(&self) -> Result<Box<dyn Listener>> {
        // Listening requires onion service creation
        // For now, return not supported - will implement in future
        // TODO: Implement onion service creation with arti when API is available
        Err(MeshInfinityError::OperationNotSupported)
    }

    fn priority(&self) -> u8 {
        2 // Lower priority than clearnet (higher latency)
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tor
    }

    fn is_available(&self) -> bool {
        // Check if Tor client is initialized
        self.is_initialized()
    }

    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        // Tor has higher latency but good anonymity
        Ok(TransportQuality {
            latency: Duration::from_millis(500), // ~500ms average for Tor
            bandwidth: 500000, // ~500 Kbps typical
            reliability: 0.90, // Slightly less reliable due to circuit changes
            cost: 0.2, // Higher cost due to latency
            congestion: 0.3,
        })
    }
}

pub struct TorConnection {
    stream: Arc<Mutex<arti_client::DataStream>>,
    peer: PeerInfo,
}

impl Connection for TorConnection {
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        let stream_arc = self.stream.clone();

        tokio::runtime::Handle::current()
            .block_on(async move {
                let mut stream = stream_arc.lock()
                    .map_err(|e| MeshInfinityError::NetworkError(format!("Lock error: {}", e)))?;

                stream.write_all(data)
                    .await
                    .map_err(|e| MeshInfinityError::NetworkError(format!("Tor send failed: {}", e)))?;

                Ok(data.len())
            })
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let stream_arc = self.stream.clone();

        tokio::runtime::Handle::current()
            .block_on(async move {
                let mut stream = stream_arc.lock()
                    .map_err(|e| MeshInfinityError::NetworkError(format!("Lock error: {}", e)))?;

                let len = stream.read(buffer)
                    .await
                    .map_err(|e| MeshInfinityError::NetworkError(format!("Tor receive failed: {}", e)))?;

                Ok(len)
            })
    }

    fn close(&mut self) -> Result<()> {
        // Drop the stream to close it
        Ok(())
    }

    fn remote_peer(&self) -> &PeerInfo {
        &self.peer
    }

    fn is_active(&self) -> bool {
        // Check if we can still acquire the lock (stream exists)
        self.stream.lock().is_ok()
    }
}

pub struct TorListener {
    // TODO: Implement when arti supports onion services
}

impl Listener for TorListener {
    fn accept(&mut self) -> Result<Box<dyn Connection>> {
        // Not yet implemented - onion service support needed
        Err(MeshInfinityError::OperationNotSupported)
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }

    fn local_addr(&self) -> String {
        "tor-listener".to_string()
    }
}
