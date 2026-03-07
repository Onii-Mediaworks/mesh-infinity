//! NAT traversal helper interface.
//!
//! Placeholder abstraction for future hole-punching and relay-assist logic used
//! when peers are behind NAT boundaries.

use std::net::SocketAddr;
use std::net::UdpSocket;

use crate::core::error::{MeshInfinityError, Result};

pub struct NatTraversal;

impl Default for NatTraversal {
    /// Create default NAT traversal helper.
    fn default() -> Self {
        Self::new()
    }
}

impl NatTraversal {
    /// Construct NAT traversal helper.
    pub fn new() -> Self {
        Self
    }

    /// Attempt UDP/TCP hole punch toward remote endpoint.
    pub fn punch_hole(&self, remote: SocketAddr) -> Result<()> {
        if remote.port() == 0 {
            return Err(MeshInfinityError::InvalidConfiguration(
                "remote endpoint must have non-zero port".to_string(),
            ));
        }

        let bind_addr = if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;

        // Send a minimal probe datagram to create NAT state at the boundary.
        // Errors are surfaced so caller can decide whether to retry/relay.
        socket
            .send_to(&[0u8], remote)
            .map(|_| ())
            .map_err(MeshInfinityError::from)
    }
}
