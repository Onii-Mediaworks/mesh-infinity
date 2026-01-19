// Transport manager implementation
use net-infinity_core::transport::{TransportManager, TransportFactory};
use net-infinity_core::core::TransportType;
use std::sync::Arc;

pub struct TransportManagerImpl {
    inner: TransportManager,
}

impl TransportManagerImpl {
    pub fn new() -> Self {
        let mut manager = TransportManager::new();
        
        // Register transport factories
        manager.register_transport_factory(Box::new(TorTransportFactory));
        manager.register_transport_factory(Box::new(ClearnetTransportFactory));
        
        // Initialize transports
        manager.initialize_transports().expect("Failed to initialize transports");
        
        Self { inner: manager }
    }
    
    pub fn get_manager(&self) -> &TransportManager {
        &self.inner
    }
}

pub struct TorTransportFactory;

impl TransportFactory for TorTransportFactory {
    fn create_transport(&self) -> Box<dyn net-infinity_core::transport::traits::Transport> {
        Box::new(TorTransport::new())
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::Tor
    }
}

pub struct ClearnetTransportFactory;

impl TransportFactory for ClearnetTransportFactory {
    fn create_transport(&self) -> Box<dyn net-infinity_core::transport::traits::Transport> {
        Box::new(ClearnetTransport::new())
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::Clearnet
    }
}