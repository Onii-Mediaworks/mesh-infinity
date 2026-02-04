// I2P transport implementation
use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::Result;
use crate::core::transport::traits::{Connection, Listener, Transport};
use std::time::Duration;

pub struct I2pTransport;

impl I2pTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Transport for I2pTransport {
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        Ok(Box::new(I2pConnection {
            peer: peer_info.clone(),
        }))
    }

    fn listen(&self) -> Result<Box<dyn Listener>> {
        Ok(Box::new(I2pListener {}))
    }

    fn priority(&self) -> u8 {
        3
    }

    fn transport_type(&self) -> TransportType {
        TransportType::I2P
    }

    fn is_available(&self) -> bool {
        false
    }

    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(350),
            bandwidth: 500_000,
            reliability: 0.8,
            cost: 0.15,
            congestion: 0.3,
        })
    }
}

pub struct I2pConnection {
    peer: PeerInfo,
}

impl Connection for I2pConnection {
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        Ok(data.len())
    }

    fn receive(&mut self, _buffer: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }

    fn remote_peer(&self) -> &PeerInfo {
        &self.peer
    }

    fn is_active(&self) -> bool {
        true
    }
}

pub struct I2pListener;

impl Listener for I2pListener {
    fn accept(&mut self) -> Result<Box<dyn Connection>> {
        Err(crate::core::error::MeshInfinityError::OperationNotSupported)
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }

    fn local_addr(&self) -> String {
        "i2p-listener".to_string()
    }
}
