//! Transport Manager (§5.0)
//!
//! # What is the Transport Manager?
//!
//! The transport manager is the coordinator for all active transports.
//! It owns the transport instances (WireGuard sessions, Tor circuits,
//! BLE connections, etc.) and provides a unified interface for sending
//! and receiving packets regardless of the underlying transport.
//!
//! # Responsibilities
//!
//! 1. **Lifecycle management:** start/stop individual transports
//! 2. **Health monitoring:** track transport health via keepalives
//! 3. **Transport migration:** seamlessly switch between transports
//!    when a better one becomes available (§5.2 migration protocol)
//! 4. **Diversity enforcement:** ensure the node maintains connections
//!    over at least 3 transport types (§5.10.5)
//! 5. **Cover traffic:** generate synthetic packets to maintain constant
//!    traffic flow (§15.4)

use std::collections::HashMap;

use crate::identity::peer_id::PeerId;
use crate::network::transport_hint::TransportType;
use super::health::{HealthState, TransportStatus};

// ---------------------------------------------------------------------------
// Transport Manager
// ---------------------------------------------------------------------------

/// The transport manager — owns and coordinates all active transports.
///
/// In a full implementation, this would hold actual WireGuard sessions,
/// Tor circuits, BLE connections, etc. For now, it manages the health
/// and status tracking that the solver needs.
pub struct TransportManager {
    /// Status of each transport type on this device.
    /// Key: transport type, Value: current status.
    transports: HashMap<TransportType, TransportStatus>,

    /// Active peer connections.
    /// Key: peer ID, Value: which transport(s) we're connected to them on.
    peer_connections: HashMap<PeerId, Vec<TransportType>>,
}

impl TransportManager {
    /// Create a new transport manager.
    ///
    /// All transports start as unavailable (`hardware_available: false`).
    /// Callers must explicitly enable each transport after confirming hardware
    /// capability or user configuration (via `set_available` / `sync_availability`).
    /// This prevents the routing solver from using transports that have not
    /// been verified as present on this device.
    pub fn new() -> Self {
        let mut transports = HashMap::new();

        // Register all supported transport types as unavailable.
        // The startup sequence (or capability probe) must call set_available()
        // before any transport is used for routing.
        for transport_type in [
            TransportType::Clearnet,
            TransportType::Tor,
            TransportType::BLE,
        ] {
            transports.insert(
                transport_type.clone(),
                TransportStatus::new(transport_type, false),
            );
        }

        Self {
            transports,
            peer_connections: HashMap::new(),
        }
    }

    /// Get the current status of all transports.
    ///
    /// Used by the solver to know what's available for routing decisions.
    pub fn all_statuses(&self) -> Vec<TransportStatus> {
        self.transports.values().cloned().collect()
    }

    /// Get the status of a specific transport.
    pub fn status(&self, transport: &TransportType) -> Option<&TransportStatus> {
        self.transports.get(transport)
    }

    /// Update a transport's health state.
    ///
    /// Called by the health monitoring subsystem when keepalives
    /// succeed/fail or when errors are detected.
    pub fn set_health(&mut self, transport: &TransportType, health: HealthState) {
        if let Some(status) = self.transports.get_mut(transport) {
            status.health = health;
        }
    }

    /// Update a transport's latency measurement.
    ///
    /// Called when a keepalive probe round-trip time is measured.
    pub fn update_latency(&mut self, transport: &TransportType, rtt_ms: f32) {
        if let Some(status) = self.transports.get_mut(transport) {
            status.update_latency(rtt_ms);
        }
    }

    /// Register a transport as available (hardware detected).
    pub fn set_available(&mut self, transport: TransportType, available: bool) {
        let entry = self
            .transports
            .entry(transport.clone())
            .or_insert_with(|| TransportStatus::new(transport, available));
        entry.hardware_available = available;
        if available && entry.health == HealthState::Dead {
            entry.health = HealthState::Live;
        }
    }

    /// Record that we have an active connection to a peer on a transport.
    pub fn add_peer_connection(&mut self, peer: PeerId, transport: TransportType) {
        self.peer_connections
            .entry(peer)
            .or_default()
            .push(transport);
    }

    /// Remove a peer connection.
    pub fn remove_peer_connection(&mut self, peer: &PeerId, transport: &TransportType) {
        if let Some(transports) = self.peer_connections.get_mut(peer) {
            transports.retain(|t| t != transport);
            if transports.is_empty() {
                self.peer_connections.remove(peer);
            }
        }
    }

    /// Update transport availability from a configuration/flag source.
    ///
    /// Called whenever the user enables or disables transports (e.g., via
    /// `mi_set_transport_flags`).  Each entry is `(TransportType, available)`.
    /// Transports not in the list are left unchanged.
    ///
    /// When a transport is enabled its health is set to `Live` (pending a real
    /// health probe); when disabled it is set to `Dead` so the coordinator
    /// will not route through it.
    pub fn sync_availability(&mut self, updates: &[(TransportType, bool)]) {
        for (transport, available) in updates {
            let entry = self
                .transports
                .entry(transport.clone())
                .or_insert_with(|| TransportStatus::new(transport.clone(), *available));
            entry.hardware_available = *available;
            entry.health = if *available {
                // Only upgrade to Live; do not downgrade an already-degraded
                // transport that happens to be re-enabled.
                if entry.health == HealthState::Dead {
                    HealthState::Live
                } else {
                    entry.health
                }
            } else {
                HealthState::Dead
            };
        }
    }

    /// Returns the transport types that are currently available for routing.
    ///
    /// A transport is considered available when both:
    /// - `hardware_available` is true (enabled in config / detected)
    /// - `health` is `Live` or `Degraded` (not `Dead`)
    pub fn available_types(&self) -> Vec<TransportType> {
        self.transports
            .iter()
            .filter(|(_, s)| s.hardware_available && s.health != HealthState::Dead)
            .map(|(t, _)| t.clone())
            .collect()
    }

    /// Get the number of distinct active transport types.
    ///
    /// Used by the solver for diversity scoring (§5.10.5).
    /// The target is 3 — below that, the solver applies pressure
    /// to diversify.
    pub fn active_transport_type_count(&self) -> usize {
        self.available_types().len()
    }

    /// Get the transports a specific peer is connected on.
    pub fn peer_transports(&self, peer: &PeerId) -> Vec<TransportType> {
        self.peer_connections
            .get(peer)
            .cloned()
            .unwrap_or_default()
    }

    /// Get the number of active peer connections.
    pub fn connected_peer_count(&self) -> usize {
        self.peer_connections.len()
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_manager() {
        let mgr = TransportManager::new();
        // Should have some default transports registered
        assert!(!mgr.transports.is_empty());
    }

    #[test]
    fn test_set_available() {
        let mut mgr = TransportManager::new();
        mgr.set_available(TransportType::Tor, true);
        let status = mgr.status(&TransportType::Tor).unwrap();
        assert!(status.hardware_available);
        assert_eq!(status.health, HealthState::Live);
    }

    #[test]
    fn test_health_update() {
        let mut mgr = TransportManager::new();
        mgr.set_health(&TransportType::Clearnet, HealthState::Degraded);
        assert_eq!(
            mgr.status(&TransportType::Clearnet).unwrap().health,
            HealthState::Degraded
        );
    }

    #[test]
    fn test_latency_tracking() {
        let mut mgr = TransportManager::new();
        mgr.update_latency(&TransportType::Clearnet, 50.0);
        assert!(mgr
            .status(&TransportType::Clearnet)
            .unwrap()
            .latency_ema
            .is_some());
    }

    #[test]
    fn test_peer_connections() {
        let mut mgr = TransportManager::new();
        let peer = PeerId([0x01; 32]);

        mgr.add_peer_connection(peer, TransportType::Clearnet);
        mgr.add_peer_connection(peer, TransportType::Tor);

        assert_eq!(mgr.peer_transports(&peer).len(), 2);
        assert_eq!(mgr.connected_peer_count(), 1);

        mgr.remove_peer_connection(&peer, &TransportType::Clearnet);
        assert_eq!(mgr.peer_transports(&peer).len(), 1);
    }

    #[test]
    fn test_active_transport_count() {
        let mut mgr = TransportManager::new();
        // All transports start unavailable — no phantom defaults.
        assert_eq!(mgr.active_transport_type_count(), 0);

        // Enable clearnet explicitly, as the startup sequence does.
        mgr.set_available(TransportType::Clearnet, true);
        assert_eq!(mgr.active_transport_type_count(), 1);

        // Enable Tor — count increases.
        mgr.set_available(TransportType::Tor, true);
        assert_eq!(mgr.active_transport_type_count(), 2);
    }

    #[test]
    fn test_sync_availability_enables_transport() {
        let mut mgr = TransportManager::new();

        // Tor starts as unavailable.
        assert!(!mgr.available_types().contains(&TransportType::Tor));

        // Sync with flags that enable Tor.
        mgr.sync_availability(&[(TransportType::Tor, true)]);

        assert!(
            mgr.available_types().contains(&TransportType::Tor),
            "Tor must be available after sync_availability(true)"
        );
    }

    #[test]
    fn test_sync_availability_disables_transport() {
        let mut mgr = TransportManager::new();

        // Enable clearnet first, then disable it via sync.
        mgr.set_available(TransportType::Clearnet, true);
        assert!(mgr.available_types().contains(&TransportType::Clearnet));

        // Disable it.
        mgr.sync_availability(&[(TransportType::Clearnet, false)]);

        assert!(
            !mgr.available_types().contains(&TransportType::Clearnet),
            "Clearnet must not be available after sync_availability(false)"
        );
    }

    #[test]
    fn test_sync_availability_multiple_at_once() {
        let mut mgr = TransportManager::new();

        mgr.sync_availability(&[
            (TransportType::Tor, true),
            (TransportType::BLE, true),
            (TransportType::Clearnet, false),
        ]);

        let avail = mgr.available_types();
        assert!(avail.contains(&TransportType::Tor));
        assert!(avail.contains(&TransportType::BLE));
        assert!(!avail.contains(&TransportType::Clearnet));
    }

    #[test]
    fn test_available_types_excludes_dead_transports() {
        let mut mgr = TransportManager::new();
        // Enable clearnet first.
        mgr.set_available(TransportType::Clearnet, true);
        assert!(mgr.available_types().contains(&TransportType::Clearnet));

        // Kill it manually — must drop out of available_types.
        mgr.set_health(&TransportType::Clearnet, HealthState::Dead);
        assert!(
            !mgr.available_types().contains(&TransportType::Clearnet),
            "Dead transport must not appear in available_types"
        );
    }

    #[test]
    fn test_sync_does_not_revive_degraded_transport() {
        let mut mgr = TransportManager::new();

        // Degrade clearnet.
        mgr.set_health(&TransportType::Clearnet, HealthState::Degraded);

        // Sync with enabled=true — should not reset health to Live.
        mgr.sync_availability(&[(TransportType::Clearnet, true)]);

        // Should still be Degraded, not promoted back to Live.
        assert_eq!(
            mgr.status(&TransportType::Clearnet).unwrap().health,
            HealthState::Degraded,
            "sync_availability must not promote Degraded to Live"
        );

        // But degraded is still available (not Dead).
        assert!(mgr.available_types().contains(&TransportType::Clearnet));
    }
}
