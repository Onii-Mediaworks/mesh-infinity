// Bluetooth transport implementation
use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::Result;
use crate::core::transport::traits::{Connection, Listener, Transport};
use std::time::Duration;

pub struct BluetoothTransport;

impl BluetoothTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Transport for BluetoothTransport {
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        Ok(Box::new(BluetoothConnection {
            peer: peer_info.clone(),
        }))
    }

    fn listen(&self) -> Result<Box<dyn Listener>> {
        Ok(Box::new(BluetoothListener {}))
    }

    fn priority(&self) -> u8 {
        6
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Bluetooth
    }

    fn is_available(&self) -> bool {
        false
    }

    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(80),
            bandwidth: 250_000,
            reliability: 0.7,
            cost: 0.05,
            congestion: 0.2,
        })
    }
}

pub struct BluetoothConnection {
    peer: PeerInfo,
}

impl Connection for BluetoothConnection {
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

pub struct BluetoothListener;

impl Listener for BluetoothListener {
    fn accept(&mut self) -> Result<Box<dyn Connection>> {
        Err(crate::core::error::NetInfinityError::OperationNotSupported)
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }

    fn local_addr(&self) -> String {
        "bluetooth-listener".to_string()
    }
}
