//! Tor transport via arti-client.
//!
//! Routes all connections through the Tor anonymity network using the
//! embedded arti-client Tor implementation.  Supports both clearnet exits
//! (hostname:port through a Tor exit node) and v3 .onion hidden service
//! addresses.
//!
//! # Bootstrapping
//!
//! `TorTransport` must be constructed via [`TorTransport::bootstrap`], an
//! async fn that establishes Tor circuits before returning.  After that the
//! transport implements the synchronous [`Transport`] trait by bridging async
//! Tor I/O through `tokio::task::block_in_place`.
//!
//! # Inbound connections
//!
//! Inbound Tor connections require a v3 onion service with persistent key
//! storage.  `listen()` returns an error; hidden-service support is a future
//! work item.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use arti_client::{DataStream, TorClient, TorClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Handle;
use tor_rtcompat::PreferredRuntime;

use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::transport::traits::{Connection, Listener, Transport};

/// Tor transport backed by arti-client.
///
/// Construct via [`TorTransport::new`] (unbootstrapped) or
/// [`TorTransport::bootstrap`] (fully ready).  Until bootstrapped,
/// [`Transport::connect`] returns an error and [`Transport::is_available`]
/// returns `false`.  The transport manager creates it synchronously via
/// `new()`; the service layer bootstraps it asynchronously when the user
/// enables Tor.
pub struct TorTransport {
    client: Option<Arc<TorClient<PreferredRuntime>>>,
    handle: Option<Handle>,
}

impl Default for TorTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TorTransport {
    /// Create an unbootstrapped transport placeholder.
    ///
    /// `is_available()` returns `false` until [`bootstrap`] is called.
    pub fn new() -> Self {
        Self {
            client: None,
            handle: Handle::try_current().ok(),
        }
    }

    /// Bootstrap a Tor client in place, making the transport usable.
    ///
    /// Must be called from within a Tokio runtime.
    pub async fn bootstrap() -> Result<Self> {
        let config = TorClientConfig::default();
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| MeshInfinityError::TransportError(format!("Tor bootstrap failed: {e}")))?;
        Ok(Self {
            client: Some(Arc::new(client)),
            handle: Some(Handle::current()),
        })
    }

    /// Wrap an already-bootstrapped [`TorClient`].
    pub fn from_client(client: TorClient<PreferredRuntime>) -> Self {
        Self {
            client: Some(Arc::new(client)),
            handle: Some(Handle::current()),
        }
    }

    /// Resolve peer metadata into `(host, port)` for [`TorClient::connect`].
    ///
    /// Prefers the explicit `TransportType::Tor` endpoint string (supports
    /// `.onion` addresses), then falls back to the generic socket endpoint.
    fn resolve_target(peer_info: &PeerInfo) -> Result<(String, u16)> {
        let raw = peer_info
            .transport_endpoints
            .get(&TransportType::Tor)
            .cloned()
            .or_else(|| peer_info.endpoint.map(|a| a.to_string()))
            .ok_or_else(|| {
                MeshInfinityError::TransportError("no Tor endpoint in peer metadata".to_string())
            })?;

        let (host, port_str) = raw.rsplit_once(':').ok_or_else(|| {
            MeshInfinityError::TransportError(format!("invalid Tor endpoint format: {raw}"))
        })?;
        let port: u16 = port_str.parse().map_err(|_| {
            MeshInfinityError::TransportError(format!("invalid port in Tor endpoint: {raw}"))
        })?;
        Ok((host.to_string(), port))
    }
}

impl Transport for TorTransport {
    /// Open an anonymous stream to `peer_info` through the Tor network.
    ///
    /// The target address may be a clearnet host (routed through a Tor exit
    /// node) or a `.onion` v3 hidden service address.
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        let client = self.client.as_ref().ok_or_else(|| {
            MeshInfinityError::TransportError(
                "Tor transport not bootstrapped — call bootstrap() first".to_string(),
            )
        })?;
        let handle = self.handle.as_ref().ok_or_else(|| {
            MeshInfinityError::TransportError("Tor transport has no runtime handle".to_string())
        })?;

        let (host, port) = Self::resolve_target(peer_info)?;
        let client = Arc::clone(client);
        let handle_conn = handle.clone();
        let peer = peer_info.clone();

        let stream = tokio::task::block_in_place(|| {
            handle.block_on(async move {
                client
                    .connect((host.as_str(), port))
                    .await
                    .map_err(|e| {
                        MeshInfinityError::TransportError(format!(
                            "Tor connect to {host}:{port} failed: {e}"
                        ))
                    })
            })
        })?;

        Ok(Box::new(TorConnection::new(stream, peer, handle_conn)))
    }

    /// Inbound connections require a v3 onion service — not yet implemented.
    fn listen(&self) -> Result<Box<dyn Listener>> {
        Err(MeshInfinityError::TransportError(
            "Tor inbound listener requires onion service configuration (not yet implemented)"
                .to_string(),
        ))
    }

    fn priority(&self) -> u8 {
        2
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tor
    }

    fn is_available(&self) -> bool {
        self.client.is_some()
    }

    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(520),
            bandwidth: 400_000,
            reliability: 0.88,
            cost: 0.2,
            congestion: 0.35,
        })
    }
}

/// Live Tor stream connection wrapping an arti-client [`DataStream`].
///
/// The stream is held in a `Mutex<Option<DataStream>>` so the struct is
/// `Sync` even though [`DataStream`] is only `Send`.  `None` indicates the
/// stream has been shut down.
pub struct TorConnection {
    stream: Mutex<Option<DataStream>>,
    peer: PeerInfo,
    handle: Handle,
}

impl TorConnection {
    fn new(stream: DataStream, peer: PeerInfo, handle: Handle) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            peer,
            handle,
        }
    }
}

impl Connection for TorConnection {
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        let mut guard = self.stream.lock().map_err(|_| {
            MeshInfinityError::TransportError("Tor stream lock poisoned".to_string())
        })?;
        let stream = guard.as_mut().ok_or_else(|| {
            MeshInfinityError::NetworkError("Tor connection closed".to_string())
        })?;
        let handle = &self.handle;
        tokio::task::block_in_place(|| {
            handle.block_on(async { stream.write_all(data).await })
        })
        .map_err(|e| MeshInfinityError::TransportError(format!("Tor send failed: {e}")))?;
        Ok(data.len())
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let mut guard = self.stream.lock().map_err(|_| {
            MeshInfinityError::TransportError("Tor stream lock poisoned".to_string())
        })?;
        let stream = guard.as_mut().ok_or_else(|| {
            MeshInfinityError::NetworkError("Tor connection closed".to_string())
        })?;
        let handle = &self.handle;
        tokio::task::block_in_place(|| handle.block_on(async { stream.read(buffer).await }))
            .map_err(|e| MeshInfinityError::TransportError(format!("Tor receive failed: {e}")))
    }

    fn close(&mut self) -> Result<()> {
        let mut guard = self.stream.lock().map_err(|_| {
            MeshInfinityError::TransportError("Tor stream lock poisoned".to_string())
        })?;
        if let Some(mut stream) = guard.take() {
            let handle = &self.handle;
            tokio::task::block_in_place(|| {
                handle.block_on(async { stream.shutdown().await })
            })
            .map_err(|e| {
                MeshInfinityError::TransportError(format!("Tor shutdown failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn remote_peer(&self) -> &PeerInfo {
        &self.peer
    }

    fn is_active(&self) -> bool {
        self.stream.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}
