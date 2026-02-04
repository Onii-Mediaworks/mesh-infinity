// Transport manager implementation
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::transport::traits::{Connection, Listener, Transport, TransportFactory};
use crate::core::transport::TransportManager;

use super::{BluetoothTransport, ClearnetTransport, I2pTransport, TorTransport};

struct ConfigurableTransport {
    enabled: Arc<AtomicBool>,
    inner: Box<dyn Transport>,
}

impl ConfigurableTransport {
    fn new(enabled: Arc<AtomicBool>, inner: Box<dyn Transport>) -> Self {
        Self { enabled, inner }
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

impl Transport for ConfigurableTransport {
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        if !self.is_enabled() {
            return Err(MeshInfinityError::TransportError("Transport disabled".to_string()));
        }
        self.inner.connect(peer_info)
    }

    fn listen(&self) -> Result<Box<dyn Listener>> {
        if !self.is_enabled() {
            return Err(MeshInfinityError::TransportError("Transport disabled".to_string()));
        }
        self.inner.listen()
    }

    fn priority(&self) -> u8 {
        self.inner.priority()
    }

    fn transport_type(&self) -> TransportType {
        self.inner.transport_type()
    }

    fn is_available(&self) -> bool {
        self.is_enabled() && self.inner.is_available()
    }

    fn measure_quality(&self, target: &PeerInfo) -> Result<TransportQuality> {
        if !self.is_available() {
            return Err(MeshInfinityError::TransportError("Transport disabled".to_string()));
        }
        self.inner.measure_quality(target)
    }
}

pub struct TransportManagerImpl {
    inner: Arc<TransportManager>,
    tor_enabled: Arc<AtomicBool>,
    clearnet_enabled: Arc<AtomicBool>,
    i2p_enabled: Arc<AtomicBool>,
    bluetooth_enabled: Arc<AtomicBool>,
}

impl TransportManagerImpl {
    pub fn new() -> Self {
        let mut manager = TransportManager::new();
        let tor_enabled = Arc::new(AtomicBool::new(true));
        let clearnet_enabled = Arc::new(AtomicBool::new(true));
        let i2p_enabled = Arc::new(AtomicBool::new(false));
        let bluetooth_enabled = Arc::new(AtomicBool::new(false));
        
        // Register transport factories
        manager.register_transport_factory(Box::new(TorTransportFactory {
            enabled: Arc::clone(&tor_enabled),
        }));
        manager.register_transport_factory(Box::new(ClearnetTransportFactory {
            enabled: Arc::clone(&clearnet_enabled),
        }));
        manager.register_transport_factory(Box::new(I2pTransportFactory {
            enabled: Arc::clone(&i2p_enabled),
        }));
        manager.register_transport_factory(Box::new(BluetoothTransportFactory {
            enabled: Arc::clone(&bluetooth_enabled),
        }));
        
        // Initialize transports
        manager.initialize_transports().expect("Failed to initialize transports");
        
        Self {
            inner: Arc::new(manager),
            tor_enabled,
            clearnet_enabled,
            i2p_enabled,
            bluetooth_enabled,
        }
    }
    
    pub fn get_manager(&self) -> Arc<TransportManager> {
        Arc::clone(&self.inner)
    }

    pub fn set_tor_enabled(&self, enabled: bool) {
        self.tor_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_clearnet_enabled(&self, enabled: bool) {
        self.clearnet_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_i2p_enabled(&self, enabled: bool) {
        self.i2p_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_bluetooth_enabled(&self, enabled: bool) {
        self.bluetooth_enabled.store(enabled, Ordering::Relaxed);
    }
}

pub struct TorTransportFactory {
    enabled: Arc<AtomicBool>,
}

impl TransportFactory for TorTransportFactory {
    fn create_transport(&self) -> Box<dyn crate::core::transport::traits::Transport> {
        Box::new(ConfigurableTransport::new(
            Arc::clone(&self.enabled),
            Box::new(TorTransport::new()),
        ))
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::Tor
    }
}

pub struct ClearnetTransportFactory {
    enabled: Arc<AtomicBool>,
}

impl TransportFactory for ClearnetTransportFactory {
    fn create_transport(&self) -> Box<dyn crate::core::transport::traits::Transport> {
        Box::new(ConfigurableTransport::new(
            Arc::clone(&self.enabled),
            Box::new(ClearnetTransport::new()),
        ))
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::Clearnet
    }
}

pub struct I2pTransportFactory {
    enabled: Arc<AtomicBool>,
}

impl TransportFactory for I2pTransportFactory {
    fn create_transport(&self) -> Box<dyn crate::core::transport::traits::Transport> {
        Box::new(ConfigurableTransport::new(
            Arc::clone(&self.enabled),
            Box::new(I2pTransport::new()),
        ))
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::I2P
    }
}

pub struct BluetoothTransportFactory {
    enabled: Arc<AtomicBool>,
}

impl TransportFactory for BluetoothTransportFactory {
    fn create_transport(&self) -> Box<dyn crate::core::transport::traits::Transport> {
        Box::new(ConfigurableTransport::new(
            Arc::clone(&self.enabled),
            Box::new(BluetoothTransport::new()),
        ))
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::Bluetooth
    }
}
