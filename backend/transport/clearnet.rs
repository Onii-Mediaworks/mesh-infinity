//! Clearnet transport implementation.
//!
//! Clearnet is treated as an underlay and should carry WireGuard-enveloped
//! payloads only (router enforces tunnel-first semantics).

use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::transport::traits::{Connection, Listener, Transport};

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

/// Direct TCP transport used as a WireGuard underlay path.
pub struct ClearnetTransport;

impl Default for ClearnetTransport {
    /// Create default clearnet transport instance.
    fn default() -> Self {
        Self::new()
    }
}

impl ClearnetTransport {
    /// Construct a clearnet transport instance.
    pub fn new() -> Self {
        Self
    }
}

impl Transport for ClearnetTransport {
    /// Open TCP connection to peer endpoint for underlay traffic.
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        let endpoint = peer_info.endpoint.ok_or(MeshInfinityError::TransportError(
            "Peer has no endpoint".to_string(),
        ))?;

        let stream = TcpStream::connect(endpoint)?;
        stream.set_nodelay(true)?;

        Ok(Box::new(ClearnetConnection {
            stream,
            peer: peer_info.clone(),
            closed: false,
        }))
    }

    /// Bind an ephemeral local TCP listener for inbound sessions.
    fn listen(&self) -> Result<Box<dyn Listener>> {
        let listener = TcpListener::bind("0.0.0.0:0")?;
        listener.set_nonblocking(false)?;
        Ok(Box::new(ClearnetListener { listener }))
    }

    /// Return fallback priority for clearnet.
    fn priority(&self) -> u8 {
        10
    }

    /// Identify this transport as clearnet.
    fn transport_type(&self) -> TransportType {
        TransportType::Clearnet
    }

    /// Report host TCP availability.
    fn is_available(&self) -> bool {
        true
    }

    /// Return conservative quality estimate for internet TCP path.
    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(80),
            bandwidth: 5_000_000,
            reliability: 0.85,
            cost: 0.05,
            congestion: 0.25,
        })
    }
}

pub struct ClearnetConnection {
    stream: TcpStream,
    peer: PeerInfo,
    closed: bool,
}

impl Connection for ClearnetConnection {
    /// Write bytes to TCP stream.
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.closed {
            return Err(MeshInfinityError::NetworkError(
                "connection closed".to_string(),
            ));
        }
        Ok(self.stream.write(data)?)
    }

    /// Read bytes from TCP stream.
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if self.closed {
            return Ok(0);
        }
        Ok(self.stream.read(buffer)?)
    }

    /// Shutdown stream in both directions.
    fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.stream.shutdown(Shutdown::Both)?;
            self.closed = true;
        }
        Ok(())
    }

    /// Return remote peer metadata.
    fn remote_peer(&self) -> &PeerInfo {
        &self.peer
    }

    /// Return whether connection is still active.
    fn is_active(&self) -> bool {
        !self.closed
    }
}

pub struct ClearnetListener {
    listener: TcpListener,
}

impl Listener for ClearnetListener {
    /// Accept incoming TCP connection and wrap into transport connection.
    fn accept(&mut self) -> Result<Box<dyn Connection>> {
        let (stream, addr) = self.listener.accept()?;
        stream.set_nodelay(true)?;

        let peer_info = PeerInfo {
            peer_id: [0; 32],
            public_key: [0; 32],
            trust_level: crate::core::core::TrustLevel::Untrusted,
            available_transports: vec![TransportType::Clearnet],
            last_seen: None,
            endpoint: Some(addr),
            transport_endpoints: std::collections::HashMap::new(),
        };

        Ok(Box::new(ClearnetConnection {
            stream,
            peer: peer_info,
            closed: false,
        }))
    }

    /// Close listener socket via nonblocking toggle to unblock accept loops.
    fn close(&mut self) -> Result<()> {
        self.listener.set_nonblocking(true)?;
        Ok(())
    }

    /// Return bound local socket address.
    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "0.0.0.0:0".to_string())
    }
}
