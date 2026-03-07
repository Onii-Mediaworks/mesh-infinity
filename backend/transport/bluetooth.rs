//! Native Bluetooth transport backend.
//!
//! Uses a feature-gated native implementation via `btleplug` and fails closed
//! when the native backend is not enabled or unavailable.

use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::transport::traits::{Connection, Listener, Transport};

use std::time::Duration;

#[cfg(feature = "transport-bluetooth-native")]
use btleplug::api::Manager as _;
#[cfg(feature = "transport-bluetooth-native")]
use btleplug::platform::Manager;

/// Bluetooth transport backend entrypoint.
pub struct BluetoothTransport;

impl Default for BluetoothTransport {
    /// Construct Bluetooth transport instance.
    fn default() -> Self {
        Self::new()
    }
}

impl BluetoothTransport {
    /// Construct Bluetooth transport instance.
    pub fn new() -> Self {
        Self
    }

    /// Probe native adapter availability.
    fn adapter_ready(&self) -> bool {
        #[cfg(feature = "transport-bluetooth-native")]
        {
            let result = tokio::runtime::Handle::current().block_on(async {
                let manager = Manager::new().await.ok()?;
                let adapters = manager.adapters().await.ok()?;
                if adapters.is_empty() {
                    None
                } else {
                    Some(())
                }
            });
            result.is_some()
        }

        #[cfg(not(feature = "transport-bluetooth-native"))]
        {
            false
        }
    }
}

impl Transport for BluetoothTransport {
    /// Open Bluetooth transport connection for a known peer endpoint.
    fn connect(&self, _peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        Err(MeshInfinityError::OperationNotSupported)
    }

    /// Start Bluetooth listener for inbound sessions.
    fn listen(&self) -> Result<Box<dyn Listener>> {
        Err(MeshInfinityError::OperationNotSupported)
    }

    /// Return Bluetooth transport priority.
    fn priority(&self) -> u8 {
        6
    }

    /// Identify transport type.
    fn transport_type(&self) -> TransportType {
        TransportType::Bluetooth
    }

    /// Report native backend readiness.
    fn is_available(&self) -> bool {
        self.adapter_ready()
    }

    /// Return baseline quality estimate for short-range encrypted links.
    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        if !self.is_available() {
            return Err(MeshInfinityError::OperationNotSupported);
        }

        Ok(TransportQuality {
            latency: Duration::from_millis(60),
            bandwidth: 1_000_000,
            reliability: 0.7,
            cost: 0.02,
            congestion: 0.25,
        })
    }
}
