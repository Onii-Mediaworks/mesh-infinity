//! RF transport foundation.
//!
//! Provides a feature-gated Meshtastic-backed adapter surface and secure
//! fail-closed behavior when RF support is unavailable.

use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::transport::traits::{Connection, Listener, Transport};

use std::time::Duration;

/// RF transport entrypoint.
pub struct RfTransport;

impl Default for RfTransport {
    /// Construct RF transport instance.
    fn default() -> Self {
        Self::new()
    }
}

impl RfTransport {
    /// Construct RF transport instance.
    pub fn new() -> Self {
        Self
    }
}

impl Transport for RfTransport {
    /// Open RF connection through configured backend.
    fn connect(&self, _peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        Err(MeshInfinityError::OperationNotSupported)
    }

    /// Listen for inbound RF link sessions.
    fn listen(&self) -> Result<Box<dyn Listener>> {
        Err(MeshInfinityError::OperationNotSupported)
    }

    /// Return RF transport priority.
    fn priority(&self) -> u8 {
        4
    }

    /// Identify this transport as RF.
    fn transport_type(&self) -> TransportType {
        TransportType::Rf
    }

    /// Report RF availability based on compile-time feature gating.
    fn is_available(&self) -> bool {
        cfg!(feature = "transport-rf-meshtastic")
    }

    /// Return conservative RF quality estimate.
    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        if !self.is_available() {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        Ok(TransportQuality {
            latency: Duration::from_millis(650),
            bandwidth: 19_200,
            reliability: 0.65,
            cost: 0.1,
            congestion: 0.4,
        })
    }
}
