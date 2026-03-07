//! Core transport-orchestration manager.
//!
//! Tracks registered transports, initializes them from factories, evaluates
//! quality probes, and chooses the best available connection in anti-downgrade
//! order.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::core::error::Result;
use crate::core::{PeerInfo, TransportQuality, TransportType};

use super::traits::{Connection, Transport, TransportFactory};

type ActiveConnections = HashMap<String, Vec<Box<dyn Connection>>>;

pub struct TransportManager {
    transports: HashMap<TransportType, Arc<dyn Transport>>,
    factories: HashMap<TransportType, Box<dyn TransportFactory>>,
    active_connections: Arc<Mutex<ActiveConnections>>,
    min_reliability: f32,
    max_congestion: f32,
}

impl Default for TransportManager {
    /// Create transport manager with default quality thresholds.
    fn default() -> Self {
        Self::new()
    }
}

impl TransportManager {
    /// Construct empty manager with conservative reliability/congestion gates.
    pub fn new() -> Self {
        Self {
            transports: HashMap::new(),
            factories: HashMap::new(),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            min_reliability: 0.35,
            max_congestion: 0.90,
        }
    }

    /// Register a transport factory keyed by its transport type.
    pub fn register_transport_factory(&mut self, factory: Box<dyn TransportFactory>) {
        let transport_type = factory.transport_type();
        self.factories.insert(transport_type, factory);
    }

    /// Instantiate all registered transport factories into active transport map.
    pub fn initialize_transports(&mut self) -> Result<()> {
        for (transport_type, factory) in &self.factories {
            let transport = factory.create_transport();
            self.transports
                .insert(*transport_type, Arc::from(transport));
        }
        Ok(())
    }

    /// Track an active connection under peer id for bookkeeping/inspection.
    pub fn track_connection(&self, peer_id: &str, connection: Box<dyn Connection>) {
        let mut active = self.active_connections.lock().unwrap();
        active
            .entry(peer_id.to_string())
            .or_default()
            .push(connection);
    }

    /// Return number of tracked active connections for a peer.
    pub fn active_connection_count(&self, peer_id: &str) -> usize {
        let active = self.active_connections.lock().unwrap();
        active.get(peer_id).map(|list| list.len()).unwrap_or(0)
    }

    /// Select best available transport connection in caller-provided preference order.
    ///
    /// Pass 1 enforces quality thresholds; pass 2 fails open when probes are
    /// unavailable but transport connect still succeeds.
    pub async fn get_best_connection(
        &self,
        target: &PeerInfo,
        preferred: &[TransportType],
    ) -> Result<Box<dyn Connection>> {
        // Pass 1: honor anti-downgrade order and require minimum quality.
        for transport_type in preferred {
            if let Some(transport) = self.transports.get(transport_type) {
                if transport.is_available() {
                    let quality_ok = transport
                        .measure_quality(target)
                        .map(|q| {
                            q.reliability >= self.min_reliability
                                && q.congestion <= self.max_congestion
                        })
                        .unwrap_or(false);

                    if quality_ok {
                        if let Ok(conn) = transport.connect(target) {
                            return Ok(conn);
                        }
                    }
                }
            }
        }

        // Pass 2: fail-open fallback in same anti-downgrade order if probes are stale/unavailable.
        for transport_type in preferred {
            if let Some(transport) = self.transports.get(transport_type) {
                if transport.is_available() {
                    if let Ok(conn) = transport.connect(target) {
                        return Ok(conn);
                    }
                }
            }
        }

        Err(crate::core::error::MeshInfinityError::NoAvailableTransport)
    }

    /// Fetch a transport implementation by type.
    pub fn get_transport(&self, transport_type: &TransportType) -> Option<Arc<dyn Transport>> {
        self.transports.get(transport_type).cloned()
    }

    /// List transport types currently registered in manager.
    pub fn available_transports(&self) -> Vec<TransportType> {
        self.transports.keys().copied().collect()
    }

    /// Run transport-specific quality measurement against target peer.
    pub fn measure_quality(
        &self,
        target: &PeerInfo,
        transport_type: TransportType,
    ) -> Result<TransportQuality> {
        if let Some(transport) = self.transports.get(&transport_type) {
            transport.measure_quality(target)
        } else {
            Err(crate::core::error::MeshInfinityError::TransportError(
                format!("Transport type {:?} not available", transport_type),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::traits::Listener;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;

    struct TestConnection {
        peer: PeerInfo,
    }

    impl Connection for TestConnection {
        /// Test helper send: report all bytes accepted.
        fn send(&mut self, data: &[u8]) -> Result<usize> {
            Ok(data.len())
        }

        /// Test helper receive: no inbound data.
        fn receive(&mut self, _buffer: &mut [u8]) -> Result<usize> {
            Ok(0)
        }

        /// Test helper close: no-op.
        fn close(&mut self) -> Result<()> {
            Ok(())
        }

        /// Return bound test peer metadata.
        fn remote_peer(&self) -> &PeerInfo {
            &self.peer
        }

        /// Always active for test connection stub.
        fn is_active(&self) -> bool {
            true
        }
    }

    struct TestTransport {
        transport_type: TransportType,
        available: bool,
        quality: Option<TransportQuality>,
        probe_error: bool,
        connect_ok: bool,
        connect_calls: Arc<AtomicUsize>,
    }

    impl Transport for TestTransport {
        /// Simulate connect with configurable success/failure.
        fn connect(&self, _peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
            self.connect_calls.fetch_add(1, AtomicOrdering::Relaxed);
            if self.connect_ok {
                Ok(Box::new(TestConnection {
                    peer: _peer_info.clone(),
                }))
            } else {
                Err(crate::core::error::MeshInfinityError::TransportError(
                    "connect fail".to_string(),
                ))
            }
        }

        /// Listener path is unsupported in unit test transport.
        fn listen(&self) -> Result<Box<dyn Listener>> {
            Err(crate::core::error::MeshInfinityError::OperationNotSupported)
        }

        /// Return fixed priority used by test harness.
        fn priority(&self) -> u8 {
            1
        }

        /// Return transport type represented by this test instance.
        fn transport_type(&self) -> TransportType {
            self.transport_type
        }

        /// Return configured availability flag.
        fn is_available(&self) -> bool {
            self.available
        }

        /// Return configured quality or probe error for test cases.
        fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
            if self.probe_error {
                Err(crate::core::error::MeshInfinityError::TransportError(
                    "probe failed".to_string(),
                ))
            } else {
                self.quality.clone().ok_or_else(|| {
                    crate::core::error::MeshInfinityError::TransportError(
                        "no quality available".to_string(),
                    )
                })
            }
        }
    }

    /// Build deterministic peer fixture for transport-manager tests.
    fn test_peer() -> PeerInfo {
        PeerInfo {
            peer_id: [1u8; 32],
            public_key: [2u8; 32],
            trust_level: crate::core::TrustLevel::Caution,
            available_transports: vec![TransportType::Tor, TransportType::Clearnet],
            last_seen: None,
            endpoint: None,
            transport_endpoints: std::collections::HashMap::new(),
        }
    }

    /// Build quality fixture with caller-provided reliability/congestion values.
    fn quality(reliability: f32, congestion: f32) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(50),
            bandwidth: 1_000_000,
            reliability,
            cost: 0.2,
            congestion,
        })
    }

    #[tokio::test]
    /// Manager should skip low-quality preferred transport and fail over.
    async fn get_best_connection_skips_low_quality_and_fails_over() {
        let mut manager = TransportManager::new();
        let tor_calls = Arc::new(AtomicUsize::new(0));
        let clearnet_calls = Arc::new(AtomicUsize::new(0));

        manager.transports.insert(
            TransportType::Tor,
            Arc::new(TestTransport {
                transport_type: TransportType::Tor,
                available: true,
                quality: quality(0.10, 0.20).ok(),
                probe_error: false,
                connect_ok: true,
                connect_calls: Arc::clone(&tor_calls),
            }),
        );
        manager.transports.insert(
            TransportType::Clearnet,
            Arc::new(TestTransport {
                transport_type: TransportType::Clearnet,
                available: true,
                quality: quality(0.95, 0.10).ok(),
                probe_error: false,
                connect_ok: true,
                connect_calls: Arc::clone(&clearnet_calls),
            }),
        );

        let peer = test_peer();
        let _conn = manager
            .get_best_connection(&peer, &[TransportType::Tor, TransportType::Clearnet])
            .await
            .expect("must connect via fallback transport");

        assert_eq!(tor_calls.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(clearnet_calls.load(AtomicOrdering::Relaxed), 1);
    }

    #[tokio::test]
    /// Manager should fail open when quality probes error but connect works.
    async fn get_best_connection_fail_open_when_quality_probe_fails() {
        let mut manager = TransportManager::new();
        let tor_calls = Arc::new(AtomicUsize::new(0));

        manager.transports.insert(
            TransportType::Tor,
            Arc::new(TestTransport {
                transport_type: TransportType::Tor,
                available: true,
                quality: None,
                probe_error: true,
                connect_ok: true,
                connect_calls: Arc::clone(&tor_calls),
            }),
        );

        let peer = test_peer();
        let _conn = manager
            .get_best_connection(&peer, &[TransportType::Tor])
            .await
            .expect("should fail-open when probes unavailable");

        assert_eq!(tor_calls.load(AtomicOrdering::Relaxed), 1);
    }
}
