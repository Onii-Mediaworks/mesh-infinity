//! Tailscale / Headscale Transport (§5.23)
//!
//! Tailscale is a managed WireGuard overlay network.  Nodes authenticate via
//! Tailscale's coordination server (or a self-hosted **Headscale** instance)
//! and receive stable addresses in the `100.64.0.0/10` CGNAT range.
//!
//! ## First-class native client (§5.23.1)
//!
//! Mesh Infinity implements the Tailscale control protocol directly — no
//! dependency on the `tailscale` CLI or daemon.  On mobile this is mandatory
//! (single VPN slot); on desktop Mesh Infinity manages its own interface
//! independently of any installed Tailscale service.
//!
//! ## Double-layer encryption
//!
//! The outer Tailscale WireGuard session provides the overlay network path;
//! the inner Mesh Infinity WireGuard session provides mesh-level encryption
//! and identity.  Both layers use WireGuard for different roles:
//! - Outer: transport / path establishment
//! - Inner: identity, authentication, mesh routing
//!
//! ## Control protocol
//!
//! Tailscale's control protocol is HTTPS-based:
//! 1. POST `/machine/register` with our public key → receive machine config
//! 2. POST `/machine/map` (long-poll) → receive peer list + DERP map updates
//! 3. POST `/machine/key` → rotate machine key
//!
//! Headscale implements the same protocol at a configurable base URL.
//!
//! ## DERP relay
//!
//! When direct WireGuard paths are not available (NAT, firewalls), traffic is
//! relayed via DERP (Designated Encrypted Relay for Packets) servers.  DERP
//! is a WebSocket-based relay that encrypts payloads end-to-end.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────────────
// Tailscale addressing
// ────────────────────────────────────────────────────────────────────────────

/// Tailscale CGNAT address range: 100.64.0.0/10.
pub const TS_IP_RANGE_START: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
/// Prefix length for the Tailscale address space.
pub const TS_PREFIX_LEN: u8 = 10;

/// Default Tailscale coordination server URL.
pub const TS_CONTROL_URL: &str = "https://controlplane.tailscale.com";

/// DERP server port (WebSocket).
pub const DERP_PORT: u16 = 443;

// ────────────────────────────────────────────────────────────────────────────
// Tailscale control protocol messages
// ────────────────────────────────────────────────────────────────────────────

/// Machine registration request to the coordination server.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Base64-encoded Curve25519 public key (for WireGuard).
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    /// Base64-encoded old key (empty for first registration).
    #[serde(rename = "OldNodeKey", default)]
    pub old_node_key: String,
    /// Auth key (pre-auth key or OAuth token).
    #[serde(rename = "Auth", default)]
    pub auth: String,
    /// Hostname for this node.
    #[serde(rename = "Hostname")]
    pub hostname: String,
    /// OS name.
    #[serde(rename = "OS", default)]
    pub os: String,
    /// Client capabilities (version string).
    #[serde(rename = "Version", default)]
    pub version: String,
}

/// Machine registration response from the coordination server.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Whether the node needs to authenticate via browser.
    #[serde(rename = "AuthURL", default)]
    pub auth_url: Option<String>,
    /// Whether the node is now authorized.
    #[serde(rename = "NodeAuthorized", default)]
    pub node_authorized: bool,
    /// Assigned IP addresses (typically one IPv4 + one IPv6).
    #[serde(rename = "IPAddresses", default)]
    pub ip_addresses: Vec<String>,
    /// Machine name on the tailnet.
    #[serde(rename = "MachineName", default)]
    pub machine_name: String,
}

/// A Tailscale peer on the tailnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscalePeer {
    /// WireGuard public key (base64).
    #[serde(rename = "Key")]
    pub key: String,
    /// Assigned Tailscale IP addresses.
    #[serde(rename = "Addresses", default)]
    pub addresses: Vec<String>,
    /// Hostname.
    #[serde(rename = "Name", default)]
    pub name: String,
    /// Whether this peer is currently online.
    #[serde(rename = "Online", default)]
    pub online: bool,
    /// Whether this peer can act as an exit node.
    #[serde(rename = "ExitNodeOption", default)]
    pub exit_node_option: bool,
    /// Allowed DERP relay region IDs.
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Vec<String>,
    /// Direct UDP endpoint (if known).
    #[serde(rename = "Endpoint", default)]
    pub endpoint: Option<String>,
}

/// Network map response (peers + DERP map).
#[derive(Debug, Serialize, Deserialize)]
pub struct MapResponse {
    /// Our assigned IP.
    #[serde(rename = "Self", default)]
    pub self_node: Option<TailscalePeer>,
    /// All peers on the tailnet.
    #[serde(rename = "Peers", default)]
    pub peers: Vec<TailscalePeer>,
    /// DERP server regions.
    #[serde(rename = "DERPMap", default)]
    pub derp_map: Option<DerpMap>,
    /// Key expiry time (Unix timestamp, 0 = no expiry).
    #[serde(rename = "KeyExpiry", default)]
    pub key_expiry: u64,
}

/// DERP relay server map.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DerpMap {
    #[serde(rename = "Regions", default)]
    pub regions: HashMap<u32, DerpRegion>,
}

/// A DERP relay region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: u32,
    #[serde(rename = "RegionCode", default)]
    pub region_code: String,
    #[serde(rename = "Nodes", default)]
    pub nodes: Vec<DerpNode>,
}

/// A DERP relay node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpNode {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "HostName")]
    pub hostname: String,
    #[serde(rename = "DERPPort", default)]
    pub derp_port: u16,
    #[serde(rename = "IPv4", default)]
    pub ipv4: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// Tailscale control client
// ────────────────────────────────────────────────────────────────────────────

/// Authentication method for the coordination server.
#[derive(Debug, Clone)]
pub enum TailscaleAuth {
    /// Pre-auth key (from the admin panel or headless enrollment).
    AuthKey(String),
    /// OAuth device flow (browser-based).
    AuthUrl(String),
}

/// Tailscale / Headscale control protocol client.
pub struct TailscaleClient {
    /// Coordination server base URL.
    pub control_url: String,
    /// Our WireGuard public key (Curve25519, 32 bytes).
    pub wg_pubkey: [u8; 32],
    /// Hostname advertised to the tailnet.
    pub hostname: String,
    /// HTTP client.
    client: reqwest::Client,
    /// Current state.
    pub state: Mutex<TailscaleState>,
}

/// Current Tailscale connection state.
#[derive(Debug, Default)]
pub struct TailscaleState {
    /// Assigned Tailscale IPs.
    pub assigned_ips: Vec<IpAddr>,
    /// Machine name on the tailnet.
    pub machine_name: String,
    /// Current peer list.
    pub peers: Vec<TailscalePeer>,
    /// DERP map.
    pub derp_map: Option<DerpMap>,
    /// Authentication URL if pending.
    pub auth_url: Option<String>,
    /// Whether we are fully authorized.
    pub authorized: bool,
    /// Key expiry (Unix ms, 0 = no expiry).
    pub key_expiry_ms: u64,
}

impl TailscaleClient {
    /// Create a new client for Tailscale Central.
    pub fn new_central(wg_pubkey: [u8; 32], hostname: &str) -> Self {
        TailscaleClient {
            control_url: TS_CONTROL_URL.to_owned(),
            wg_pubkey,
            hostname: hostname.to_owned(),
            client: reqwest::Client::new(),
            state: Mutex::new(TailscaleState::default()),
        }
    }

    /// Create a new client for a self-hosted Headscale instance.
    pub fn new_headscale(base_url: &str, wg_pubkey: [u8; 32], hostname: &str) -> Self {
        TailscaleClient {
            control_url: base_url.trim_end_matches('/').to_owned(),
            wg_pubkey,
            hostname: hostname.to_owned(),
            client: reqwest::Client::new(),
            state: Mutex::new(TailscaleState::default()),
        }
    }

    /// Register this machine with the coordination server.
    ///
    /// Returns `RegisterResponse` which may contain an `auth_url` if the user
    /// needs to complete browser-based authentication.
    pub async fn register(
        &self,
        auth: TailscaleAuth,
    ) -> Result<RegisterResponse, reqwest::Error> {
        let auth_str = match auth {
            TailscaleAuth::AuthKey(k) => k,
            TailscaleAuth::AuthUrl(_) => String::new(),
        };

        let req = RegisterRequest {
            node_key: base64::engine::general_purpose::STANDARD.encode(self.wg_pubkey),
            old_node_key: String::new(),
            auth: auth_str,
            hostname: self.hostname.clone(),
            os: std::env::consts::OS.to_owned(),
            version: "mesh-infinity/0.3".to_owned(),
        };

        let url = format!("{}/machine/register", self.control_url);
        let resp: RegisterResponse = self
            .client
            .post(&url)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        // Update state.
        let mut state = self.state.lock().unwrap();
        state.authorized = resp.node_authorized;
        state.machine_name = resp.machine_name.clone();
        state.auth_url = resp.auth_url.clone();
        state.assigned_ips = resp
            .ip_addresses
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        Ok(resp)
    }

    /// Poll the coordination server for peer updates (long-poll).
    ///
    /// This call blocks until the server sends an update.  Run in a dedicated
    /// task/thread.
    pub async fn poll_map(&self) -> Result<MapResponse, reqwest::Error> {
        let url = format!("{}/machine/map", self.control_url);
        let map: MapResponse = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "NodeKey": base64::engine::general_purpose::STANDARD.encode(self.wg_pubkey),
                "DiscoKey": "",
                "IncludeIPv6": true,
                "Stream": true,
            }))
            .send()
            .await?
            .json()
            .await?;

        let mut state = self.state.lock().unwrap();
        state.peers = map.peers.clone();
        state.derp_map = map.derp_map.clone();
        if let Some(ref s) = map.self_node {
            state.assigned_ips = s
                .addresses
                .iter()
                .filter_map(|a| a.parse().ok())
                .collect();
        }
        state.key_expiry_ms = map.key_expiry;

        Ok(map)
    }

    /// Get the best DERP relay for our region (for fallback when direct
    /// WireGuard fails).
    pub fn best_derp_relay(&self) -> Option<SocketAddr> {
        let state = self.state.lock().unwrap();
        let derp = state.derp_map.as_ref()?;
        // Pick the first region with any node (prefer lower region IDs = closer).
        let mut region_ids: Vec<u32> = derp.regions.keys().copied().collect();
        region_ids.sort_unstable();
        for rid in region_ids {
            let region = derp.regions.get(&rid)?;
            for node in &region.nodes {
                if let Some(ref ip) = node.ipv4 {
                    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                        let port = if node.derp_port > 0 { node.derp_port } else { DERP_PORT };
                        return Some(SocketAddr::new(IpAddr::V4(addr), port));
                    }
                }
            }
        }
        None
    }

    /// Return all currently known peers.
    pub fn peers(&self) -> Vec<TailscalePeer> {
        self.state.lock().unwrap().peers.clone()
    }

    /// Return all peers that have advertised exit-node capability.
    pub fn exit_nodes(&self) -> Vec<TailscalePeer> {
        self.state
            .lock()
            .unwrap()
            .peers
            .iter()
            .filter(|p| p.exit_node_option)
            .cloned()
            .collect()
    }

    /// Our current Tailscale IP (first assigned IPv4, if any).
    pub fn our_ip(&self) -> Option<Ipv4Addr> {
        self.state
            .lock()
            .unwrap()
            .assigned_ips
            .iter()
            .find_map(|ip| {
                if let IpAddr::V4(v4) = ip {
                    let o = v4.octets();
                    // Must be in 100.64.0.0/10.
                    if o[0] == 100 && (o[1] & 0xC0) == 64 {
                        return Some(*v4);
                    }
                }
                None
            })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 0xAB;
        k[31] = 0xCD;
        k
    }

    #[test]
    fn client_central_url() {
        let c = TailscaleClient::new_central(test_key(), "test-node");
        assert_eq!(c.control_url, TS_CONTROL_URL);
        assert_eq!(c.hostname, "test-node");
    }

    #[test]
    fn client_headscale_url() {
        let c = TailscaleClient::new_headscale(
            "https://headscale.example.com/",
            test_key(),
            "my-node",
        );
        // Trailing slash should be stripped.
        assert_eq!(c.control_url, "https://headscale.example.com");
    }

    #[test]
    fn ts_ip_range_correct() {
        let ip = TS_IP_RANGE_START;
        let octets = ip.octets();
        assert_eq!(octets[0], 100);
        assert_eq!(octets[1], 64);
    }

    #[test]
    fn our_ip_in_cgnat_range() {
        let c = TailscaleClient::new_central(test_key(), "test");
        {
            let mut state = c.state.lock().unwrap();
            state.assigned_ips.push("100.90.1.5".parse().unwrap());
        }
        let ip = c.our_ip().expect("should find a Tailscale IP");
        let o = ip.octets();
        assert_eq!(o[0], 100);
        assert!((o[1] & 0xC0) == 64, "IP should be in 100.64.0.0/10");
    }

    #[test]
    fn our_ip_non_cgnat_ignored() {
        let c = TailscaleClient::new_central(test_key(), "test");
        {
            let mut state = c.state.lock().unwrap();
            state.assigned_ips.push("192.168.1.1".parse().unwrap()); // not in TS range
        }
        assert!(c.our_ip().is_none());
    }

    #[test]
    fn exit_nodes_filter() {
        let c = TailscaleClient::new_central(test_key(), "test");
        {
            let mut state = c.state.lock().unwrap();
            state.peers.push(TailscalePeer {
                key: "keyA".into(),
                addresses: vec!["100.90.1.1".into()],
                name: "exit-node".into(),
                online: true,
                exit_node_option: true,
                allowed_ips: vec![],
                endpoint: None,
            });
            state.peers.push(TailscalePeer {
                key: "keyB".into(),
                addresses: vec!["100.90.1.2".into()],
                name: "regular-node".into(),
                online: true,
                exit_node_option: false,
                allowed_ips: vec![],
                endpoint: None,
            });
        }
        let exits = c.exit_nodes();
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "exit-node");
    }

    #[test]
    fn best_derp_selects_lowest_region() {
        let c = TailscaleClient::new_central(test_key(), "test");
        {
            let mut state = c.state.lock().unwrap();
            let mut regions = HashMap::new();
            regions.insert(
                5u32,
                DerpRegion {
                    region_id: 5,
                    region_code: "nyc".into(),
                    nodes: vec![DerpNode {
                        name: "nyc1".into(),
                        hostname: "derp5.tailscale.com".into(),
                        derp_port: 443,
                        ipv4: Some("1.2.3.4".into()),
                    }],
                },
            );
            regions.insert(
                1u32,
                DerpRegion {
                    region_id: 1,
                    region_code: "nyc".into(),
                    nodes: vec![DerpNode {
                        name: "nyc1".into(),
                        hostname: "derp1.tailscale.com".into(),
                        derp_port: 443,
                        ipv4: Some("5.6.7.8".into()),
                    }],
                },
            );
            state.derp_map = Some(DerpMap { regions });
        }
        let relay = c.best_derp_relay().expect("should find a DERP relay");
        // Region 1 should be preferred over region 5.
        assert_eq!(relay.ip(), IpAddr::V4("5.6.7.8".parse().unwrap()));
    }
}
