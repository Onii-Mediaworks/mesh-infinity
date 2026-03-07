//! Transport policy façade and runtime toggle ownership.
//!
//! This module owns local transport-policy state (enabled/disabled flags and
//! anti-downgrade ordering) and delegates connection execution/quality probing to
//! [`TransportManager`](backend/transport/core_manager.rs).
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::core::TransportType;
use crate::transport::core_manager::TransportManager;
use crate::transport::traits::{Transport, TransportFactory};

use super::{BluetoothTransport, ClearnetTransport, I2pTransport, RfTransport, TorTransport};

pub struct TransportManagerImpl {
    /// Execution engine for connection attempts and quality probes.
    inner: Arc<TransportManager>,
    /// Local policy toggle: Tor transport allowed.
    tor_enabled: Arc<AtomicBool>,
    /// Local policy toggle: Clearnet transport allowed.
    clearnet_enabled: Arc<AtomicBool>,
    /// Local policy toggle: I2P transport allowed.
    i2p_enabled: Arc<AtomicBool>,
    /// Local policy toggle: Bluetooth transport allowed.
    bluetooth_enabled: Arc<AtomicBool>,
    /// Local policy toggle: RF transport allowed.
    rf_enabled: Arc<AtomicBool>,
}

impl Default for TransportManagerImpl {
    /// Create transport-manager implementation with default toggles.
    fn default() -> Self {
        Self::new()
    }
}

impl TransportManagerImpl {
    /// Construct manager, register transport factories, and initialize transports.
    pub fn new() -> Self {
        let mut manager = TransportManager::new();
        let tor_enabled = Arc::new(AtomicBool::new(true));
        let clearnet_enabled = Arc::new(AtomicBool::new(true));
        let i2p_enabled = Arc::new(AtomicBool::new(false));
        let bluetooth_enabled = Arc::new(AtomicBool::new(false));
        let rf_enabled = Arc::new(AtomicBool::new(false));

        // Register transport factories
        manager.register_transport_factory(Box::new(TorTransportFactory));
        manager.register_transport_factory(Box::new(ClearnetTransportFactory));
        manager.register_transport_factory(Box::new(I2pTransportFactory));
        manager.register_transport_factory(Box::new(BluetoothTransportFactory));
        manager.register_transport_factory(Box::new(RfTransportFactory));

        // Initialize transports
        manager
            .initialize_transports()
            .expect("Failed to initialize transports");

        Self {
            inner: Arc::new(manager),
            tor_enabled,
            clearnet_enabled,
            i2p_enabled,
            bluetooth_enabled,
            rf_enabled,
        }
    }

    /// Return shared handle to the underlying core transport manager.
    pub fn get_manager(&self) -> Arc<TransportManager> {
        Arc::clone(&self.inner)
    }

    /// Return whether a specific transport is currently enabled by local policy.
    pub fn is_transport_enabled(&self, transport: TransportType) -> bool {
        match transport {
            TransportType::Tor => self.tor_enabled.load(Ordering::Relaxed),
            TransportType::I2P => self.i2p_enabled.load(Ordering::Relaxed),
            TransportType::Bluetooth => self.bluetooth_enabled.load(Ordering::Relaxed),
            TransportType::Rf => self.rf_enabled.load(Ordering::Relaxed),
            TransportType::Clearnet => self.clearnet_enabled.load(Ordering::Relaxed),
        }
    }

    /// Enable/disable Tor transport.
    pub fn set_tor_enabled(&self, enabled: bool) {
        self.tor_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Enable/disable clearnet transport.
    pub fn set_clearnet_enabled(&self, enabled: bool) {
        self.clearnet_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Enable/disable I2P transport.
    pub fn set_i2p_enabled(&self, enabled: bool) {
        self.i2p_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Enable/disable Bluetooth transport.
    pub fn set_bluetooth_enabled(&self, enabled: bool) {
        self.bluetooth_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Enable/disable RF transport.
    pub fn set_rf_enabled(&self, enabled: bool) {
        self.rf_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Returns enabled transports in anti-downgrade order.
    /// Privacy-preserving transports are always preferred over clearnet.
    pub fn enabled_transport_order(&self) -> Vec<TransportType> {
        let mut ordered = Vec::with_capacity(5);

        if self.tor_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::Tor);
        }
        if self.i2p_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::I2P);
        }
        if self.bluetooth_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::Bluetooth);
        }
        if self.rf_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::Rf);
        }
        if self.clearnet_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::Clearnet);
        }

        ordered
    }

    /// Returns enabled transports filtered by peer-advertised support.
    pub fn enabled_transport_order_for_available(
        &self,
        available: &[TransportType],
    ) -> Vec<TransportType> {
        self.enabled_transport_order()
            .into_iter()
            .filter(|t| available.contains(t))
            .collect()
    }
}

pub struct TorTransportFactory;

impl TransportFactory for TorTransportFactory {
    /// Build a Tor transport wrapped in runtime enabled gating.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(TorTransport::new())
    }

    /// Identify this factory as producing Tor transports.
    fn transport_type(&self) -> TransportType {
        TransportType::Tor
    }
}

pub struct ClearnetTransportFactory;

impl TransportFactory for ClearnetTransportFactory {
    /// Build a clearnet transport wrapped in runtime enabled gating.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(ClearnetTransport::new())
    }

    /// Identify this factory as producing clearnet transports.
    fn transport_type(&self) -> TransportType {
        TransportType::Clearnet
    }
}

pub struct I2pTransportFactory;

impl TransportFactory for I2pTransportFactory {
    /// Build an I2P transport wrapped in runtime enabled gating.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(I2pTransport::new())
    }

    /// Identify this factory as producing I2P transports.
    fn transport_type(&self) -> TransportType {
        TransportType::I2P
    }
}

pub struct BluetoothTransportFactory;

impl TransportFactory for BluetoothTransportFactory {
    /// Build a Bluetooth transport wrapped in runtime enabled gating.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(BluetoothTransport::new())
    }

    /// Identify this factory as producing Bluetooth transports.
    fn transport_type(&self) -> TransportType {
        TransportType::Bluetooth
    }
}

pub struct RfTransportFactory;

impl TransportFactory for RfTransportFactory {
    /// Build an RF transport wrapped in runtime enabled gating.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(RfTransport::new())
    }

    /// Identify this factory as producing RF transports.
    fn transport_type(&self) -> TransportType {
        TransportType::Rf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Enabled-order list should always place privacy transports before clearnet.
    fn enabled_transport_order_prefers_privacy_transports() {
        let manager = TransportManagerImpl::new();
        manager.set_tor_enabled(true);
        manager.set_i2p_enabled(true);
        manager.set_bluetooth_enabled(true);
        manager.set_rf_enabled(true);
        manager.set_clearnet_enabled(true);

        let order = manager.enabled_transport_order();
        assert_eq!(
            order,
            vec![
                TransportType::Tor,
                TransportType::I2P,
                TransportType::Bluetooth,
                TransportType::Rf,
                TransportType::Clearnet,
            ]
        );
    }

    #[test]
    /// Availability filtering must preserve anti-downgrade relative ordering.
    fn enabled_transport_order_for_available_filters_without_downgrade() {
        let manager = TransportManagerImpl::new();
        manager.set_tor_enabled(true);
        manager.set_i2p_enabled(true);
        manager.set_bluetooth_enabled(false);
        manager.set_clearnet_enabled(true);

        let available = vec![TransportType::Clearnet, TransportType::Tor];
        let order = manager.enabled_transport_order_for_available(&available);

        assert_eq!(order, vec![TransportType::Tor, TransportType::Clearnet]);
    }
}
