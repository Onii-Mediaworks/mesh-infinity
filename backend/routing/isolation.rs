//! Network Isolation Mode (§6.12)
//!
//! # What is Network Isolation Mode?
//!
//! Network isolation mode is a persistent security posture that
//! disables all automatic peer discovery, restricting connectivity
//! to a pre-configured set of trusted peers. Think of it as
//! "darknet mode" — the node only talks to peers it already knows.
//!
//! # What It Disables
//!
//! When network isolation is active, the following are disabled:
//!
//! - **DHT participation** — the node does not publish or query the
//!   distributed hash table, preventing discovery through DHT.
//! - **mDNS/SSDP local discovery** — no broadcasting on the local
//!   network. The node is invisible to LAN scans.
//! - **Bootstrap node contact** — the node does not contact any
//!   bootstrap nodes (hardcoded or configured).
//! - **Reachability announcements to unknown peers** — only peers
//!   on the allowlist receive routing information.
//! - **Automatic connection to new peers** — no new peer connections
//!   are established unless the peer is on the allowlist.
//!
//! # What It Preserves
//!
//! Isolation mode does NOT disable:
//!
//! - **Connectivity to explicitly configured peers** — the allowlist
//!   is the lifeline. These peers are connected as normal.
//! - **Store-and-forward delivery** — if enabled in the config,
//!   S&F delivery through the allowed peers works normally.
//! - **Mesh routing through the allowed peer graph** — still
//!   hop-by-hop, still encrypted. The routing table just has
//!   fewer entries (only paths through allowed peers).
//! - **All application-layer functions** — messaging, file transfer,
//!   etc. all work within the restricted peer graph.
//!
//! # Interaction with ThreatContext
//!
//! `ThreatContext::Critical` automatically enables network isolation
//! with `allow_lan: false`. This is the nuclear option — maximum
//! privacy at the cost of discoverability.
//!
//! # Configuration
//!
//! The isolation config specifies:
//! - `enabled`: master toggle
//! - `allowed_peers`: list of device addresses that may connect
//! - `allow_lan`: whether to permit LAN connections (mDNS, etc.)
//!   even in isolation mode
//! - `allow_s_and_f`: whether store-and-forward is permitted
//!   through allowed peers

use serde::{Deserialize, Serialize};

use super::table::DeviceAddress;

// ---------------------------------------------------------------------------
// Network Isolation Configuration
// ---------------------------------------------------------------------------

/// Network isolation mode configuration (§6.12).
///
/// Controls whether the node operates in isolation mode and what
/// exceptions are allowed. This is a persistent setting that
/// survives restarts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkIsolationConfig {
    /// Master toggle for network isolation mode.
    /// When true, all automatic discovery is disabled and only
    /// connections to allowed_peers are established.
    pub enabled: bool,

    /// List of device addresses that are allowed to connect.
    /// These peers are the only ones the node will communicate with
    /// in isolation mode. Empty list = truly isolated (no connections).
    pub allowed_peers: Vec<DeviceAddress>,

    /// Whether to allow LAN connections (mDNS/SSDP discovery)
    /// even in isolation mode.
    ///
    /// Set to true for "work from home" scenarios where you want
    /// to restrict internet-facing connections but still allow
    /// devices on your local network.
    ///
    /// Set to false for maximum isolation (ThreatContext::Critical
    /// forces this to false).
    pub allow_lan: bool,

    /// Whether store-and-forward delivery is permitted.
    ///
    /// When true, allowed peers can relay stored messages for us.
    /// When false, only live connections deliver messages.
    ///
    /// Set to false if you don't want any node holding messages
    /// on your behalf (even encrypted ones).
    pub allow_s_and_f: bool,
}

impl Default for NetworkIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_peers: Vec::new(),
            allow_lan: true,
            allow_s_and_f: true,
        }
    }
}

impl NetworkIsolationConfig {
    /// Create a configuration for ThreatContext::Critical.
    ///
    /// Critical threat context forces isolation with no LAN and
    /// no S&F. Only pre-configured peers are reachable.
    pub fn critical_mode(allowed_peers: Vec<DeviceAddress>) -> Self {
        Self {
            enabled: true,
            allowed_peers,
            allow_lan: false,   // Forced off in Critical.
            allow_s_and_f: false,
        }
    }

    /// Check if a peer is allowed to connect.
    ///
    /// In isolation mode, only explicitly allowed peers may connect.
    /// When isolation is disabled, all peers are allowed.
    pub fn is_peer_allowed(&self, peer: &DeviceAddress) -> bool {
        // If isolation is not enabled, everyone is allowed.
        if !self.enabled {
            return true;
        }

        // In isolation mode, check the allowlist.
        self.allowed_peers.contains(peer)
    }

    /// Check if DHT participation is allowed.
    ///
    /// Disabled in isolation mode — the node does not publish to
    /// or query the DHT.
    pub fn allows_dht(&self) -> bool {
        !self.enabled
    }

    /// Check if mDNS/SSDP local discovery is allowed.
    ///
    /// Disabled in isolation mode unless allow_lan is true.
    pub fn allows_mdns(&self) -> bool {
        if !self.enabled {
            return true;
        }
        self.allow_lan
    }

    /// Check if bootstrap node contact is allowed.
    ///
    /// Always disabled in isolation mode — bootstrap nodes are
    /// unknown peers by definition.
    pub fn allows_bootstrap(&self) -> bool {
        !self.enabled
    }

    /// Check if store-and-forward is allowed.
    ///
    /// Configurable in isolation mode via the allow_s_and_f flag.
    /// Always allowed when isolation is disabled.
    pub fn allows_store_and_forward(&self) -> bool {
        if !self.enabled {
            return true;
        }
        self.allow_s_and_f
    }

    /// Check if reachability announcements should be sent to a peer.
    ///
    /// In isolation mode, announcements are only sent to allowed peers.
    /// When isolation is disabled, announcements go to all peers.
    pub fn allows_announcement_to(&self, peer: &DeviceAddress) -> bool {
        self.is_peer_allowed(peer)
    }

    /// Add a peer to the allowlist.
    ///
    /// Idempotent — adding a peer that's already allowed is a no-op.
    pub fn add_allowed_peer(&mut self, peer: DeviceAddress) {
        if !self.allowed_peers.contains(&peer) {
            self.allowed_peers.push(peer);
        }
    }

    /// Remove a peer from the allowlist.
    pub fn remove_allowed_peer(&mut self, peer: &DeviceAddress) {
        self.allowed_peers.retain(|p| p != peer);
    }

    /// Number of allowed peers.
    pub fn allowed_peer_count(&self) -> usize {
        self.allowed_peers.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a DeviceAddress from a single byte.
    fn addr(b: u8) -> DeviceAddress {
        DeviceAddress([b; 32])
    }

    #[test]
    fn test_default_not_isolated() {
        let config = NetworkIsolationConfig::default();

        assert!(!config.enabled);
        assert!(config.is_peer_allowed(&addr(0x01)));
        assert!(config.allows_dht());
        assert!(config.allows_mdns());
        assert!(config.allows_bootstrap());
        assert!(config.allows_store_and_forward());
    }

    #[test]
    fn test_isolation_enabled() {
        let mut config = NetworkIsolationConfig {
            enabled: true,
            allowed_peers: vec![addr(0xAA), addr(0xBB)],
            allow_lan: false,
            allow_s_and_f: true,
        };

        // Allowed peers: OK.
        assert!(config.is_peer_allowed(&addr(0xAA)));
        assert!(config.is_peer_allowed(&addr(0xBB)));

        // Unknown peer: blocked.
        assert!(!config.is_peer_allowed(&addr(0xCC)));

        // Discovery disabled.
        assert!(!config.allows_dht());
        assert!(!config.allows_mdns());
        assert!(!config.allows_bootstrap());

        // S&F allowed (config says so).
        assert!(config.allows_store_and_forward());

        // Announcements only to allowed peers.
        assert!(config.allows_announcement_to(&addr(0xAA)));
        assert!(!config.allows_announcement_to(&addr(0xCC)));

        // Add a new peer.
        config.add_allowed_peer(addr(0xCC));
        assert!(config.is_peer_allowed(&addr(0xCC)));
        assert_eq!(config.allowed_peer_count(), 3);

        // Remove a peer.
        config.remove_allowed_peer(&addr(0xBB));
        assert!(!config.is_peer_allowed(&addr(0xBB)));
        assert_eq!(config.allowed_peer_count(), 2);
    }

    #[test]
    fn test_critical_mode() {
        let config = NetworkIsolationConfig::critical_mode(vec![addr(0x01)]);

        assert!(config.enabled);
        assert!(!config.allow_lan);
        assert!(!config.allow_s_and_f);
        assert!(config.is_peer_allowed(&addr(0x01)));
        assert!(!config.is_peer_allowed(&addr(0x02)));
        assert!(!config.allows_dht());
        assert!(!config.allows_mdns());
        assert!(!config.allows_bootstrap());
        assert!(!config.allows_store_and_forward());
    }

    #[test]
    fn test_isolation_with_lan() {
        let config = NetworkIsolationConfig {
            enabled: true,
            allowed_peers: vec![],
            allow_lan: true, // LAN allowed even in isolation.
            allow_s_and_f: false,
        };

        // mDNS allowed because allow_lan is true.
        assert!(config.allows_mdns());

        // But DHT and bootstrap still disabled.
        assert!(!config.allows_dht());
        assert!(!config.allows_bootstrap());
    }

    #[test]
    fn test_add_allowed_peer_idempotent() {
        let mut config = NetworkIsolationConfig::default();
        config.enabled = true;

        config.add_allowed_peer(addr(0xAA));
        config.add_allowed_peer(addr(0xAA)); // Duplicate — should be ignored.

        assert_eq!(config.allowed_peer_count(), 1);
    }
}
