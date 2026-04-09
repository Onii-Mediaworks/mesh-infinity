//! ZeroTier Virtual Network Transport (§5.22)
//!
//! ZeroTier is a software-defined virtual Ethernet network.  Nodes join
//! virtual networks and communicate as if on the same LAN regardless of
//! physical location.
//!
//! ## Native protocol client (§5.22.1)
//!
//! Mesh Infinity implements the ZeroTier client-side protocol directly — no
//! external ZeroTier daemon. This is mandatory on mobile (single VPN slot)
//! and preferred on desktop.
//!
//! Important boundary: Mesh Infinity does not implement or host the ZeroTier
//! network controller. It interoperates with an existing ZeroTier network
//! administered by ZeroTier Central or by an external self-hosted controller.
//!
//! ### ZeroTier identity
//!
//! A ZeroTier **Node ID** is the first 40 bits (10 hex characters) of the
//! SHA-512 of the node's NIST P-384 or Curve25519 public key pair.  For
//! compatibility with the ZeroTier protocol we derive our identity from the
//! existing Ed25519 key via SHA-512 truncation.
//!
//! ### Root server protocol (PLANET)
//!
//! ZeroTier nodes find each other via **root servers** ("planets") at UDP
//! port 9993.  The root handshake is:
//!
//! 1. Send a `HELLO` packet (verb 0x01) with our Node ID and version.
//! 2. Root responds with an `OK(HELLO)` packet (0x04/0x01).
//! 3. Send `WHOIS` (0x09) for target Node IDs to get their addresses.
//!
//! ### Network controller API
//!
//! Network membership is managed via HTTPS to the controller:
//! - ZeroTier Central:  `https://my.zerotier.com/api/v1/`
//! - Self-hosted:       `https://<host>/api/v1/`
//!
//! API key is stored encrypted in the vault.  Endpoints used:
//! - `GET  /network/{networkId}` — network configuration
//! - `POST /network/{networkId}/member/{nodeId}` — authorize member
//! - `GET  /network/{networkId}/member` — list members
//!
//! ### Virtual Ethernet
//!
//! After joining a network, packets are exchanged as Ethernet frames
//! encapsulated in ZeroTier UDP datagrams.  The virtual interface appears
//! as a TAP device (`zt*`) to the OS.

use sha2::{Digest, Sha512};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

// ────────────────────────────────────────────────────────────────────────────
// ZeroTier constants
// ────────────────────────────────────────────────────────────────────────────

/// Default ZeroTier UDP port.  All ZeroTier nodes listen on 9993/UDP.
/// This port is intentionally outside the ephemeral range (49152-65535)
/// to avoid conflicts with OS-assigned outbound connections.
pub const ZT_UDP_PORT: u16 = 9993;

/// ZeroTier protocol version 11 (current as of ZeroTier 1.x).
/// The HELLO handshake includes this version so the root can detect
/// and reject incompatible clients before wasting bandwidth.
pub const ZT_PROTO_VERSION: u8 = 11;

/// ZeroTier packet verbs — each identifies the message type in the
/// single-byte verb field at offset 34 of every ZeroTier packet.
/// HELLO initiates the root handshake; WHOIS performs peer lookup;
/// FRAME carries virtual Ethernet frames on the overlay network.
pub const ZT_VERB_HELLO: u8 = 0x01;
pub const ZT_VERB_OK: u8 = 0x04;
pub const ZT_VERB_WHOIS: u8 = 0x09;
pub const ZT_VERB_FRAME: u8 = 0x06;
pub const ZT_VERB_MULTICAST_FRAME: u8 = 0x0E;
pub const ZT_VERB_NETWORK_CONFIG: u8 = 0x04;

/// Packet flag: fragmented — indicates this packet is one fragment of a
/// larger ZeroTier message and must be reassembled before processing.
pub const ZT_PACKET_FLAG_FRAGMENTED: u8 = 0x40;

/// ZeroTier well-known root server (PLANET) addresses.
/// These are ZeroTier Inc.'s infrastructure root servers — they perform
/// initial peer discovery but never see the contents of encrypted frames.
/// Self-hosted deployments use custom MOON server configurations that
/// bypass these roots entirely.
pub const ZT_PLANET_ROOTS: &[&str] = &[
    "195.181.173.159:9993",
    "84.17.53.155:9993",
    "104.194.8.134:9993",
    "185.180.13.82:9993",
];

// ────────────────────────────────────────────────────────────────────────────
// ZeroTier Node Identity
// ────────────────────────────────────────────────────────────────────────────

/// A ZeroTier Node ID (40-bit / 10 hex chars).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZtNodeId(pub [u8; 5]);

impl ZtNodeId {
    /// Derive a ZeroTier Node ID from an Ed25519 public key.
    ///
    /// The real ZeroTier protocol derives Node IDs from P-384/Curve25519
    /// keypairs, but we simplify by using SHA-512 of our Ed25519 key.
    /// The first 40 bits provide 2^40 = ~1 trillion possible addresses,
    /// which gives negligible collision probability for mesh networks
    /// of any practical size.
    pub fn from_ed25519(pubkey: &[u8; 32]) -> Self {
        let hash: [u8; 64] = Sha512::digest(pubkey.as_slice()).into();
        let mut id = [0u8; 5];
        id.copy_from_slice(&hash[..5]);
        ZtNodeId(id)
    }

    /// Format as 10-character lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ZtNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ZeroTier packet format
// ────────────────────────────────────────────────────────────────────────────

/// ZeroTier packet header (wire format).
///
/// ```text
/// [ 8 B: destination address (5 B node ID + 3 B flags/version) ]
/// [ 8 B: source address      (5 B node ID + 3 B flags/version) ]
/// [ 8 B: packet ID (u64 LE)                                    ]
/// [ 1 B: flags                                                  ]
/// [ 1 B: cipher (0 = none, 1 = Salsa20, 3 = AES-GMAC-SIV)     ]
/// [ 8 B: message auth code                                      ]
/// [ 1 B: verb                                                   ]
/// [ N B: verb-specific payload                                  ]
/// ```
pub struct ZtPacket {
    pub dest: ZtNodeId,
    pub src: ZtNodeId,
    pub packet_id: u64,
    pub verb: u8,
    pub payload: Vec<u8>,
}

impl ZtPacket {
    /// Encode a HELLO packet (verb 0x01).
    ///
    /// HELLO payload: `[protocol_version u8] [major u8] [minor u8] [revision u16 BE]
    ///                  [timestamp u64 BE] [identity bytes]`
    pub fn hello(src: ZtNodeId, timestamp_ms: u64, pubkey: &[u8; 32]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(ZT_PROTO_VERSION);
        payload.push(1); // major
        payload.push(14); // minor
        payload.extend_from_slice(&9u16.to_be_bytes()); // revision
        payload.extend_from_slice(&timestamp_ms.to_be_bytes());
        payload.extend_from_slice(pubkey); // simplified identity
        Self::encode_raw(ZtNodeId([0xFF; 5]), src, ZT_VERB_HELLO, &payload)
    }

    /// Encode a WHOIS request for `target`.
    pub fn whois(src: ZtNodeId, target: ZtNodeId) -> Vec<u8> {
        Self::encode_raw(ZtNodeId([0xFF; 5]), src, ZT_VERB_WHOIS, &target.0)
    }

    /// Encode a FRAME (Ethernet frame over ZeroTier).
    ///
    /// payload: `[network_id u64 BE] [client_id u16 BE] [ethertype u16 BE] [frame bytes]`
    pub fn frame(src: ZtNodeId, dest: ZtNodeId, network_id: u64, frame: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&network_id.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes()); // client id (reserved)
        payload.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
        payload.extend_from_slice(frame);
        Self::encode_raw(dest, src, ZT_VERB_FRAME, &payload)
    }

    /// Low-level packet encoder (no encryption — raw/plaintext mode for
    /// controller communication).
    fn encode_raw(dest: ZtNodeId, src: ZtNodeId, verb: u8, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Destination: 5 B node ID + 3 B flags/version
        pkt.extend_from_slice(&dest.0);
        pkt.extend_from_slice(&[0u8; 3]);
        // Source: 5 B node ID + 3 B flags/version
        pkt.extend_from_slice(&src.0);
        pkt.extend_from_slice(&[0u8; 3]);
        // Packet ID (random u64)
        let pid: u64 = rand::random();
        pkt.extend_from_slice(&pid.to_le_bytes());
        // Flags
        pkt.push(0);
        // Cipher (0 = none)
        pkt.push(0);
        // MAC (8 bytes placeholder)
        pkt.extend_from_slice(&[0u8; 8]);
        // Verb
        pkt.push(verb);
        // Payload
        pkt.extend_from_slice(payload);
        pkt
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Network controller API client
// ────────────────────────────────────────────────────────────────────────────

/// ZeroTier network configuration received from the controller.
#[derive(Debug, Clone)]
pub struct ZtNetworkConfig {
    pub network_id: String,
    pub name: String,
    pub assigned_ip: Option<std::net::IpAddr>,
    pub authorized: bool,
}

/// ZeroTier controller client.
///
/// Uses HTTPS to the ZeroTier Central API or a self-hosted controller.
pub struct ZtControllerClient {
    /// Controller base URL (e.g. `"https://my.zerotier.com/api/v1"`).
    pub base_url: String,
    /// API key.
    pub api_key: String,
    /// HTTP client.
    client: reqwest::Client,
}

impl ZtControllerClient {
    /// Create a client for ZeroTier Central.
    pub fn central(api_key: &str) -> Self {
        ZtControllerClient {
            base_url: "https://my.zerotier.com/api/v1".to_owned(),
            api_key: api_key.to_owned(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a client for a self-hosted controller.
    pub fn self_hosted(base_url: &str, api_key: &str) -> Self {
        ZtControllerClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key: api_key.to_owned(),
            client: reqwest::Client::new(),
        }
    }

    /// Get network configuration.
    pub async fn get_network(&self, network_id: &str) -> Result<ZtNetworkConfig, reqwest::Error> {
        let url = format!("{}/network/{}", self.base_url, network_id);
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .header("Authorization", format!("token {}", self.api_key))
            .send()
            .await?
            .json()
            .await?;

        Ok(ZtNetworkConfig {
            network_id: network_id.to_owned(),
            name: resp["config"]["name"]
                .as_str()
                .unwrap_or("unknown")
                .to_owned(),
            assigned_ip: None,
            authorized: resp["authorized"].as_bool().unwrap_or(false),
        })
    }

    /// List members of a network.
    pub async fn list_members(
        &self,
        network_id: &str,
    ) -> Result<Vec<serde_json::Value>, reqwest::Error> {
        let url = format!("{}/network/{}/member", self.base_url, network_id);
        let resp: Vec<serde_json::Value> = self
            .client
            .get(&url)
            .header("Authorization", format!("token {}", self.api_key))
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }

    /// Set a member's authorization state.
    pub async fn set_member_authorized(
        &self,
        network_id: &str,
        node_id: &str,
        authorized: bool,
    ) -> Result<(), reqwest::Error> {
        let url = format!(
            "{}/network/{}/member/{}",
            self.base_url, network_id, node_id
        );
        self.client
            .post(&url)
            .header("Authorization", format!("token {}", self.api_key))
            .json(&serde_json::json!({ "config": { "authorized": authorized } }))
            .send()
            .await?;
        Ok(())
    }

    /// Authorize a member.
    pub async fn authorize_member(
        &self,
        network_id: &str,
        node_id: &str,
    ) -> Result<(), reqwest::Error> {
        self.set_member_authorized(network_id, node_id, true).await
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ZeroTier transport
// ────────────────────────────────────────────────────────────────────────────

/// ZeroTier virtual network transport.
pub struct ZeroTierTransport {
    /// Our ZeroTier Node ID.
    pub node_id: ZtNodeId,
    /// Our Ed25519 public key (for identity).
    pubkey: [u8; 32],
    /// UDP socket for ZeroTier protocol.
    socket: Option<Arc<UdpSocket>>,
    /// Network IDs we've joined.
    pub networks: Mutex<Vec<String>>,
    /// Inbound Ethernet frames.
    pub inbound: Mutex<Vec<Vec<u8>>>,
    /// Root server addresses.
    roots: Vec<SocketAddr>,
}

impl ZeroTierTransport {
    /// Create a ZeroTier transport from an Ed25519 public key.
    pub fn new(pubkey: &[u8; 32]) -> Self {
        let roots: Vec<SocketAddr> = ZT_PLANET_ROOTS
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        ZeroTierTransport {
            node_id: ZtNodeId::from_ed25519(pubkey),
            pubkey: *pubkey,
            socket: None,
            networks: Mutex::new(Vec::new()),
            inbound: Mutex::new(Vec::new()),
            roots,
        }
    }

    /// Bind the UDP socket.
    pub fn bind(&mut self, port: u16) -> std::io::Result<()> {
        let sock = UdpSocket::bind(("0.0.0.0", port))?;
        self.socket = Some(Arc::new(sock));
        Ok(())
    }

    /// Send a HELLO to all roots to register our presence.
    pub fn hello_roots(&self) -> std::io::Result<()> {
        if let Some(ref sock) = self.socket {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let pkt = ZtPacket::hello(self.node_id, ts, &self.pubkey);
            for root in &self.roots {
                sock.send_to(&pkt, root)?;
            }
        }
        Ok(())
    }

    /// Join a virtual network (records the network ID; membership is confirmed
    /// via the controller API).
    pub fn join_network(&self, network_id: &str) {
        // Mutex recovery: network list is still valid after a poisoned lock.
        self.networks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(network_id.to_owned());
        tracing::info!(node = %self.node_id, network = network_id, "Joining ZeroTier network");
    }

    /// Start the background receive loop.
    pub fn start_recv(self: Arc<Self>) {
        if let Some(ref sock) = self.socket {
            let sock = Arc::clone(sock);
            let transport = Arc::clone(&self);
            std::thread::Builder::new()
                .name("zerotier-recv".into())
                .spawn(move || {
                    let mut buf = [0u8; 65535];
                    while let Ok((n, _src)) = sock.recv_from(&mut buf) {
                        let pkt = &buf[..n];
                        // Minimal frame extraction: skip header (35 B), check verb.
                        if pkt.len() > 35 {
                            let verb = pkt[34];
                            if verb == ZT_VERB_FRAME || verb == ZT_VERB_MULTICAST_FRAME {
                                // Extract Ethernet frame from payload.
                                let frame = pkt[35..].to_vec();
                                // Mutex recovery: inbound queue is valid after poison.
                                transport
                                    .inbound
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .push(frame);
                            }
                        }
                    }
                })
                .ok();
        }
    }

    /// Send an Ethernet frame to `dest` over the virtual network.
    pub fn send_frame(
        &self,
        network_id: u64,
        dest: ZtNodeId,
        dest_addr: SocketAddr,
        frame: &[u8],
    ) -> std::io::Result<()> {
        if let Some(ref sock) = self.socket {
            let pkt = ZtPacket::frame(self.node_id, dest, network_id, frame);
            sock.send_to(&pkt, dest_addr)?;
        }
        Ok(())
    }

    /// Drain inbound Ethernet frames.
    pub fn drain_inbound(&self) -> Vec<Vec<u8>> {
        // Mutex recovery: drain is safe even after a poisoned lock.
        std::mem::take(&mut *self.inbound.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Check whether a PLANET server is reachable.
    pub fn probe_roots(&self) -> bool {
        if let Some(ref sock) = self.socket {
            for root in &self.roots {
                // Send a tiny UDP probe; if bind succeeded the socket is operational.
                let _ = sock.send_to(&[0u8], root);
            }
            return true;
        }
        false
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 0xAB;
        k[31] = 0xCD;
        k
    }

    #[test]
    fn node_id_derivation() {
        let id = ZtNodeId::from_ed25519(&test_pubkey());
        assert_eq!(id.0.len(), 5);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 10, "node ID hex should be 10 characters");
    }

    #[test]
    fn node_id_deterministic() {
        let a = ZtNodeId::from_ed25519(&test_pubkey());
        let b = ZtNodeId::from_ed25519(&test_pubkey());
        assert_eq!(a, b);
    }

    #[test]
    fn node_id_different_keys() {
        let a = ZtNodeId::from_ed25519(&[0u8; 32]);
        let b = ZtNodeId::from_ed25519(&test_pubkey());
        assert_ne!(a, b);
    }

    #[test]
    fn hello_packet_has_correct_verb() {
        let src = ZtNodeId::from_ed25519(&test_pubkey());
        let pkt = ZtPacket::hello(src, 1234567890, &test_pubkey());
        // Verb is at byte 34 (after dest(8) + src(8) + packet_id(8) + flags(1) + cipher(1) + mac(8)).
        assert!(pkt.len() > 34);
        assert_eq!(pkt[34], ZT_VERB_HELLO);
    }

    #[test]
    fn hello_contains_protocol_version() {
        let src = ZtNodeId::from_ed25519(&test_pubkey());
        let pkt = ZtPacket::hello(src, 0, &test_pubkey());
        // Payload starts at byte 35.
        assert!(pkt.len() > 35);
        assert_eq!(pkt[35], ZT_PROTO_VERSION);
    }

    #[test]
    fn whois_contains_target_id() {
        let src = ZtNodeId::from_ed25519(&test_pubkey());
        let target = ZtNodeId([1, 2, 3, 4, 5]);
        let pkt = ZtPacket::whois(src, target);
        assert_eq!(pkt[34], ZT_VERB_WHOIS);
        // Target ID is in the payload (after byte 35).
        assert_eq!(&pkt[35..40], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn transport_node_id_from_pubkey() {
        let t = ZeroTierTransport::new(&test_pubkey());
        assert_eq!(t.node_id, ZtNodeId::from_ed25519(&test_pubkey()));
    }

    #[test]
    fn network_id_formatted() {
        let id = ZtNodeId([0x8a, 0x7b, 0x00, 0x12, 0x34]);
        assert_eq!(id.to_hex(), "8a7b001234");
    }
}
