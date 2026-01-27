// Transport traits for modular transport implementations
use crate::core::{PeerInfo, TransportType, TransportQuality};
use crate::error::Result;

pub trait Transport: Send + Sync {
    /// Connect to a peer via this transport
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>>;
    
    /// Listen for incoming connections
    fn listen(&self) -> Result<Box<dyn Listener>>;
    
    /// Transport priority (lower = higher priority)
    fn priority(&self) -> u8;
    
    /// Transport type identifier
    fn transport_type(&self) -> TransportType;
    
    /// Check if transport is currently available
    fn is_available(&self) -> bool;
    
    /// Measure transport quality
    fn measure_quality(&self, target: &PeerInfo) -> Result<TransportQuality>;
}

pub trait Connection: Send + Sync {
    /// Send data over the connection
    fn send(&mut self, data: &[u8]) -> Result<usize>;
    
    /// Receive data from the connection
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize>;
    
    /// Close the connection
    fn close(&mut self) -> Result<()>;
    
    /// Get the remote peer information
    fn remote_peer(&self) -> &PeerInfo;
    
    /// Check if connection is still active
    fn is_active(&self) -> bool;
}

pub trait Listener: Send + Sync {
    /// Accept an incoming connection
    fn accept(&mut self) -> Result<Box<dyn Connection>>;
    
    /// Close the listener
    fn close(&mut self) -> Result<()>;
    
    /// Get the local address
    fn local_addr(&self) -> String;
}

pub trait TransportFactory: Send + Sync {
    /// Create a new transport instance
    fn create_transport(&self) -> Box<dyn Transport>;
    
    /// Get the transport type
    fn transport_type(&self) -> TransportType;
}
