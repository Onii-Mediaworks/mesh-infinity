// Transport manager for handling multiple transport types
use crate::core::{PeerInfo, TransportType, TransportQuality};
use crate::error::Result;
use crate::transport::traits::{Transport, Connection, TransportFactory};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct TransportManager {
    transports: HashMap<TransportType, Arc<dyn Transport>>,
    factories: HashMap<TransportType, Box<dyn TransportFactory>>,
    active_connections: Arc<Mutex<HashMap<String, Vec<Box<dyn Connection>>>>>,
}

impl TransportManager {
    pub fn new() -> Self {
        Self {
            transports: HashMap::new(),
            factories: HashMap::new(),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    pub fn register_transport_factory(&mut self, factory: Box<dyn TransportFactory>) {
        let transport_type = factory.transport_type();
        self.factories.insert(transport_type, factory);
    }
    
    pub fn initialize_transports(&mut self) -> Result<()> {
        for (transport_type, factory) in &self.factories {
            let transport = factory.create_transport();
            self.transports
                .insert(*transport_type, Arc::from(transport));
        }
        Ok(())
    }

    pub fn track_connection(&self, peer_id: &str, connection: Box<dyn Connection>) {
        let mut active = self.active_connections.lock().unwrap();
        active
            .entry(peer_id.to_string())
            .or_default()
            .push(connection);
    }

    pub fn active_connection_count(&self, peer_id: &str) -> usize {
        let active = self.active_connections.lock().unwrap();
        active.get(peer_id).map(|list| list.len()).unwrap_or(0)
    }
    
    pub async fn get_best_connection(
        &self, 
        target: &PeerInfo, 
        preferred: &[TransportType]
    ) -> Result<Box<dyn Connection>> {
        // Try transports in priority order
        for transport_type in preferred {
            if let Some(transport) = self.transports.get(transport_type) {
                if transport.is_available() {
                    // Test connection quality
                    if let Ok(conn) = transport.connect(target) {
                        return Ok(conn);
                    }
                }
            }
        }
        Err(crate::error::NetInfinityError::NoAvailableTransport)
    }
    
    pub fn get_transport(&self, transport_type: &TransportType) -> Option<Arc<dyn Transport>> {
        self.transports.get(transport_type).cloned()
    }
    
    pub fn available_transports(&self) -> Vec<TransportType> {
        self.transports.keys().copied().collect()
    }
    
    pub fn measure_quality(&self, target: &PeerInfo, transport_type: TransportType) -> Result<TransportQuality> {
        if let Some(transport) = self.transports.get(&transport_type) {
            transport.measure_quality(target)
        } else {
            Err(crate::error::NetInfinityError::TransportError(
                format!("Transport type {:?} not available", transport_type)
            ))
        }
    }
}
