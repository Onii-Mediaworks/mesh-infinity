# PMWAN Architecture - Private Mesh Wide Area Network

## Overview

Mesh Infinity implements a **PMWAN (Private Mesh Wide Area Network)** - a system-wide VPN/proxy that routes all device traffic through the mesh network. It provides transparent networking across the mesh with discovery-driven, hop-by-hop routing and multi-layer message security.

## Core Concept

```
┌─────────────────────────────────────────────────────┐
│  Applications (Web, SSH, etc.)                      │
│  Connect via mesh addresses (256-bit)               │
└────────────────────┬────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────┐
│  Operating System Network Stack                     │
│  ┌─────────────────────────────────────────────┐   │
│  │ Virtual Interface (TUN): mi0                │   │
│  │ Mesh address space (256-bit)                │   │
│  └───────────────────┬─────────────────────────┘   │
└────────────────────────┼────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│  Mesh Infinity VPN Service                            │
│  • Captures traffic to mesh destinations            │
│  • Mesh address resolution                          │
│  • Traffic shaping & QoS                            │
└───────────────────┬─────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────┐
│  Hop-by-Hop Router                                  │
│  ┌──────────────────────────────────────────────┐  │
│  │ • Next-hop decisions only (no full paths)   │  │
│  │ • Discovery-driven routing tables           │  │
│  │ • Links open until delivery (no ACK)        │  │
│  │ • Trust-weighted path selection             │  │
│  └──────────────────────────────────────────────┘  │
└───────────────────┬─────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────┐
│  Message Crypto Layer                               │
│  • Sign → Trust Encrypt → Re-sign → Final Encrypt  │
│  • Session key derivation for connections          │
└───────────────────┬─────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────┐
│  Transport Layer (Multi-path)                       │
│  • Tor (censorship resistance)                      │
│  • I2P (fallback)                                   │
│  • WireGuard mesh (direct)                          │
│  • Clearnet (optional)                              │
└─────────────────────────────────────────────────────┘
```

## Mesh Addressing Scheme

### 256-bit Address Format

Mesh Infinity uses a custom 256-bit addressing scheme displayed as 8 groups of 8 hexadecimal characters:

```
a1b2c3d4:e5f6a7b8:12345678:90abcdef:01234567:89abcdef:fedcba98:76543210
└────────────── device address (20 bytes) ──────────────┘└── conversation ID (12 bytes) ──┘
```

### Address Structure

```rust
/// Size constants for address structure
pub const DEVICE_PORTION_SIZE: usize = 20;       // 5 groups, 160 bits
pub const CONVERSATION_PORTION_SIZE: usize = 12; // 3 groups, 96 bits
pub const TOTAL_ADDRESS_SIZE: usize = 32;        // 8 groups, 256 bits

/// 256-bit mesh network address
/// Structure: [device_address: 20 bytes][conversation_id: 12 bytes]
pub struct MeshAddress([u8; TOTAL_ADDRESS_SIZE]);

/// Device portion of an address (first 20 bytes)
pub struct DeviceAddress([u8; DEVICE_PORTION_SIZE]);

/// Conversation identifier (last 12 bytes of address)
pub struct ConversationId([u8; CONVERSATION_PORTION_SIZE]);
```

### Address Types

| Type | Derivation | Purpose | Sharing |
|------|------------|---------|---------|
| **Primary** | `SHA256("meshinfinity-primary-addr-v1" \| public_key)` | Public identity | Shared with anyone |
| **Trusted Channel** | `SHA256("meshinfinity-trusted-channel-v1" \| sorted(key_a, key_b))` | Per-peer private address | Never shared publicly |
| **Ephemeral** | Random | Temporary sessions | Disposable after use |

### Conversation Identification

Conversations are uniquely identified by the tuple:

```rust
pub struct ConversationTuple {
    pub source: MeshAddress,       // Full source address (device + conversation)
    pub destination: MeshAddress,  // Full destination address
    pub conversation_id: ConversationId,
}
```

This enables:
- Multiple concurrent conversations to the same peer
- Privacy: primary address for untrusted, trusted channel for trusted peers
- Session isolation without revealing identity

### Device Address Registry

Each device maintains a registry of its addresses:

```rust
pub struct DeviceAddressRegistry {
    /// Our public key
    our_key: [u8; 32],
    /// Primary address (shared publicly)
    primary: DeviceAddress,
    /// Trusted channel addresses per peer (never shared)
    trusted_channels: HashMap<PeerId, DeviceAddress>,
    /// Active ephemeral addresses
    ephemeral: Vec<DeviceAddress>,
}
```

## Hop-by-Hop Routing

### Routing Philosophy

Mesh Infinity uses **decentralized, discovery-driven routing** where:

1. **Local decisions only**: Each node only decides the next hop, not the full path
2. **No predetermined paths**: Routes emerge from network topology
3. **Links stay open**: Connections maintained until delivery completes (no ACK/retransmit)
4. **Trust-weighted**: Routing prefers paths through trusted peers

### Routing Table Structure

```rust
pub struct HopRouter {
    /// Our own device address
    our_address: DeviceAddress,

    /// Direct neighbors we can communicate with
    neighbors: HashMap<PeerId, NeighborInfo>,

    /// Routing table: destination → how to get there
    routing_table: HashMap<DeviceAddress, Vec<RoutingEntry>>,

    /// Active links for ongoing transmissions
    active_links: HashMap<ConversationId, ActiveLink>,
}

pub struct RoutingEntry {
    pub destination: DeviceAddress,
    pub next_hop: PeerId,          // The neighbor to forward to
    pub hop_count: u8,             // Total hops to destination
    pub latency_estimate: Duration,
    pub path_trust: TrustLevel,    // Minimum trust along path
}
```

### Reachability Announcements

Nodes share routing information via announcements:

```rust
pub struct ReachabilityAnnouncement {
    /// The destination that can be reached
    pub destination: DeviceAddress,
    /// Number of hops to reach it
    pub hop_count: u8,
    /// Cumulative latency estimate (ms)
    pub latency_estimate_ms: u32,
    /// Minimum trust level along the path
    pub path_trust: TrustLevel,
    /// Sequence number for freshness
    pub sequence: u64,
}
```

When a node receives an announcement:
1. Verify the announcing peer is a known neighbor
2. Add 1 to hop count, add neighbor's latency
3. Take minimum of path trust and neighbor trust
4. Update routing table if this is a better/newer route
5. Propagate to other neighbors

### Active Links

Links are established per-conversation and maintained until complete:

```rust
pub struct ActiveLink {
    pub source: MeshAddress,
    pub destination: MeshAddress,
    pub next_hop: PeerId,
    pub established: Instant,
    pub last_activity: Instant,
    pub bytes_forwarded: u64,
}
```

**No acknowledgment or retransmission** - if delivery fails, the application layer handles retry.

## Message Encryption Scheme

### Multi-Layer Security

All messages use a 4-step signing and encryption process:

```
┌─────────────────────────────────────────────────────────────┐
│  STEP 1: Sign with sender's private key                     │
│  ────────────────────────────────────────                   │
│  • Proves sender authenticity                               │
│  • signature = Ed25519_Sign(sender_private, message)        │
│  • signed_message = message || signature                    │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  STEP 2: Encrypt with trust-pair key (if trusted)           │
│  ────────────────────────────────────────                   │
│  • Only if sender and recipient mutually trust each other   │
│  • trust_key = HKDF(ECDH(our_key, their_key), "trust")      │
│  • trust_encrypted = AES256_GCM(trust_key, signed_message)  │
│  • If not trusted: trust_encrypted = signed_message         │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  STEP 3: Re-sign the encrypted content                      │
│  ────────────────────────────────────────                   │
│  • Proves authenticity of the encrypted blob                │
│  • outer_sig = Ed25519_Sign(sender_private, trust_encrypted)│
│  • double_signed = trust_encrypted || outer_sig             │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  STEP 4: Encrypt with recipient's global public key         │
│  ────────────────────────────────────────                   │
│  • Hides sender identity from observers                     │
│  • ephemeral_key = X25519_Generate()                        │
│  • final = X25519_Box(recipient_public, ephemeral, double)  │
└─────────────────────────────────────────────────────────────┘
```

### Implementation

```rust
pub struct MessageCrypto {
    our_private_key: Ed25519PrivateKey,
    our_public_key: Ed25519PublicKey,
    trust_keys: HashMap<PeerId, [u8; 32]>,  // Pre-derived trust keys
}

impl MessageCrypto {
    pub fn encrypt_message(
        &self,
        message: &[u8],
        recipient_public_key: &[u8; 32],
        is_trusted: bool,
    ) -> Result<Vec<u8>> {
        // Step 1: Sign with our private key
        let signature = self.our_private_key.sign(message);
        let mut signed = message.to_vec();
        signed.extend_from_slice(&signature);

        // Step 2: Trust-pair encryption (if trusted)
        let trust_encrypted = if is_trusted {
            let trust_key = self.get_trust_key(recipient_public_key)?;
            aes256_gcm_encrypt(&trust_key, &signed)?
        } else {
            signed
        };

        // Step 3: Re-sign
        let outer_signature = self.our_private_key.sign(&trust_encrypted);
        let mut double_signed = trust_encrypted;
        double_signed.extend_from_slice(&outer_signature);

        // Step 4: Encrypt with recipient's public key
        let (ephemeral_public, ciphertext) = x25519_box_seal(
            recipient_public_key,
            &double_signed,
        )?;

        // Package: ephemeral_public || ciphertext
        let mut final_message = ephemeral_public.to_vec();
        final_message.extend(ciphertext);

        Ok(final_message)
    }
}
```

### For Network Connections

Ongoing network connections (file transfers, streams) use the full encryption scheme for the **handshake only**, then derive a session key:

```rust
// Handshake establishes session
let handshake_request = MessageCrypto::encrypt_message(
    &session_proposal,
    recipient_public_key,
    is_trusted,
)?;

// After handshake, derive session key
let session_key = hkdf_derive(
    shared_secret,
    "session-key",
    session_id,
);

// Subsequent data uses efficient session encryption
let encrypted_data = aes256_gcm_encrypt(&session_key, &data)?;
```

### Security Properties

| Property | How Achieved |
|----------|--------------|
| **Message authenticity** | Inner signature (Step 1) |
| **Trust verification** | Trust-pair encryption (Step 2) - only trusted peers can decrypt |
| **Forwarding authenticity** | Outer signature (Step 3) - proves sender even after encryption |
| **Sender privacy** | Final encryption (Step 4) - sender identity hidden from all except recipient |
| **Forward secrecy** | Ephemeral keys in Step 4 |
| **Replay protection** | Nonces in AES-GCM, sequence numbers |

## On-Device Routing (Tailscale-like)

Mesh Infinity provides system-wide VPN/proxy functionality similar to Tailscale, allowing users to route device traffic through the mesh network.

### Routing Modes

Users can choose how their device traffic is handled:

| Mode | Mesh Traffic | Non-Mesh Traffic | Use Case |
|------|--------------|------------------|----------|
| **Direct** | Through mesh | Normal internet | Default - mesh peers only |
| **Exit Node** | Through mesh | Via exit node peer | Privacy / geo-spoofing |
| **Split Tunnel** | Through mesh | Normal internet | Selective mesh access |

### Traffic Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Device Applications                                         │
│  (browsers, apps, services)                                  │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  Mesh Infinity TUN Device (mi0)                                │
│  Captures all outbound traffic                               │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  Traffic Classification                                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Is destination a mesh address?                      │    │
│  │   YES → Route through mesh (hop-by-hop)             │    │
│  │   NO  → Check user routing preference               │    │
│  │         • "Use exit node" → Route to exit node      │    │
│  │         • "Direct internet" → Bypass, normal route  │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Configuration

```rust
pub enum DeviceRoutingMode {
    /// Only mesh traffic uses the mesh; internet goes direct
    MeshOnly,

    /// All traffic routes through a selected exit node
    AllTrafficViaExitNode {
        exit_node: DeviceAddress,
        transport: Option<TransportType>,
    },

    /// User-defined rules for selective routing
    PolicyBased {
        rules: Vec<RoutingPolicy>,
        default_action: DefaultRouteAction,
    },
}

pub enum DefaultRouteAction {
    /// Non-mesh traffic goes through normal internet
    DirectInternet,
    /// Non-mesh traffic routes through an exit node
    ExitNode(DeviceAddress),
    /// Non-mesh traffic is blocked
    Block,
}
```

### Exit Node Selection

When routing through exit nodes, users can:

1. **Auto-select**: Choose the best available exit node based on:
   - Trust level (prefer highly trusted peers)
   - Latency (prefer low-latency connections)
   - Bandwidth availability
   - Geographic location

2. **Manual select**: Choose a specific trusted peer as exit node

3. **Policy-based**: Route specific traffic through specific exit nodes
   - Work traffic → Work exit node
   - Streaming → Low-latency exit node
   - Privacy-sensitive → Tor-capable exit node

### Privacy Considerations

- **Mesh traffic**: Always encrypted end-to-end, sender identity protected
- **Exit node traffic**: Exit node can see destination (but not TLS content)
- **Direct internet**: Bypasses mesh entirely, uses normal network path

## Mesh Routing Modes

### 1. Direct Peer Routing

**Use Case**: Peer-to-peer communication within the mesh

```
Application → 100.64.0.5:22
  ↓
TUN capture
  ↓
Lookup peer from IP (100.64.0.5 → peer_abc123)
  ↓
Encrypt with PFS
  ↓
Send through mesh (Tor/I2P/WireGuard)
  ↓
Peer receives → injects into their TUN → SSH server sees connection
```

### 2. Exit Node Routing

**Use Case**: Access internet through another mesh peer's connection

Any peer can volunteer as an exit node, allowing others to route internet traffic through them.

```rust
pub struct ExitNodeConfig {
    /// Whether this node offers exit services
    pub enabled: bool,

    /// Which traffic to allow
    pub allowed_destinations: DestinationPolicy,

    /// Bandwidth limits
    pub bandwidth_limit: Option<u64>,

    /// Only allow from trusted peers
    pub trust_requirement: TrustLevel,
}

pub enum DestinationPolicy {
    /// Allow all internet traffic
    AllTraffic,

    /// Only specific domains/IPs
    Whitelist(Vec<String>),

    /// Block specific domains/IPs
    Blacklist(Vec<String>),

    /// Only allow specific protocols
    ProtocolFilter(Vec<Protocol>),
}
```

**Exit Node Selection**:
```
Application → 1.1.1.1:443 (Cloudflare DNS)
  ↓
TUN captures non-mesh IP
  ↓
Check routing rules: "route all traffic through exit node peer_xyz"
  ↓
Encapsulate: [IP packet to 1.1.1.1] → encrypted mesh packet
  ↓
Send to exit node peer_xyz
  ↓
Exit node decrypts, extracts original packet
  ↓
Exit node forwards to real internet (1.1.1.1)
  ↓
Response: 1.1.1.1 → exit node → encrypted → your node → injected into TUN
  ↓
Application receives response from 1.1.1.1
```

### 3. Selective Transport Routing

**Use Case**: Route specific traffic through specific transports

```rust
pub struct RoutingPolicy {
    /// Match criteria
    pub matcher: TrafficMatcher,

    /// Routing action
    pub action: RoutingAction,
}

pub enum TrafficMatcher {
    /// Match by destination IP/port
    Destination { ip: Option<IpAddr>, port: Option<u16> },

    /// Match by protocol
    Protocol(Protocol),

    /// Match by peer ID
    Peer(PeerId),

    /// Match by application (process name/path)
    Application(String),

    /// Combine multiple matchers
    And(Vec<TrafficMatcher>),
    Or(Vec<TrafficMatcher>),
}

pub enum RoutingAction {
    /// Route through specific transport
    UseTransport(TransportType),

    /// Route through specific exit node
    UseExitNode(PeerId),

    /// Route through external VPN
    UseExternalVPN(VpnConfig),

    /// Block traffic
    Block,

    /// Allow with no special routing
    Direct,
}
```

**Examples**:

```rust
// Route all BitTorrent traffic through Tor
RoutingPolicy {
    matcher: TrafficMatcher::Protocol(Protocol::BitTorrent),
    action: RoutingAction::UseTransport(TransportType::Tor),
}

// Route work traffic through specific exit node
RoutingPolicy {
    matcher: TrafficMatcher::Destination {
        ip: Some("192.0.2.0/24".parse().unwrap()),
        port: None
    },
    action: RoutingAction::UseExitNode(work_exit_node_id),
}

// Route Zoom through clearnet (low latency)
RoutingPolicy {
    matcher: TrafficMatcher::Application("zoom.us".to_string()),
    action: RoutingAction::UseTransport(TransportType::Clearnet),
}
```

### 4. External VPN Chaining

**Use Case**: Chain Mesh Infinity with existing VPN providers

```rust
pub struct VpnConfig {
    /// VPN provider/type
    pub provider: VpnProvider,

    /// Connection credentials
    pub credentials: VpnCredentials,

    /// VPN endpoint
    pub endpoint: String,
}

pub enum VpnProvider {
    WireGuard { private_key: [u8; 32], peer_public_key: [u8; 32] },
    OpenVPN { config_file: PathBuf },
    IPSec { psk: String, gateway: String },
    Custom { command: String },
}
```

**Chaining Architecture**:

```
Application Traffic
  ↓
Mesh Infinity TUN (mi0)
  ↓
Routing policy: "use external VPN"
  ↓
Encapsulate in mesh packet
  ↓
Send through external VPN tunnel (wg0)
  ↓
VPN provider → internet
```

This allows:
- **Geographic spoofing**: Appear to be in a different country
- **ISP bypass**: Hide Mesh Infinity usage from ISP
- **Commercial VPN integration**: Use paid VPN services as exit nodes

## Multi-Transport Routing

### Transport Selection Algorithm

```rust
pub struct TransportSelector {
    /// Available transports, ordered by preference
    transports: Vec<TransportInfo>,

    /// Quality metrics
    quality_tracker: QualityTracker,
}

impl TransportSelector {
    pub fn select_for_traffic(
        &self,
        destination: &PeerId,
        traffic_type: TrafficType,
        policies: &[RoutingPolicy],
    ) -> TransportType {
        // 1. Check routing policies first
        for policy in policies {
            if policy.matcher.matches(destination, traffic_type) {
                if let Some(transport) = policy.action.transport() {
                    return transport;
                }
            }
        }

        // 2. Fall back to quality-based selection
        let available = self.transports
            .iter()
            .filter(|t| t.is_available() && t.supports(traffic_type))
            .collect::<Vec<_>>();

        // 3. Score each transport
        let best = available
            .iter()
            .max_by_key(|t| self.score_transport(t, destination, traffic_type))
            .unwrap();

        best.transport_type
    }

    fn score_transport(
        &self,
        transport: &TransportInfo,
        destination: &PeerId,
        traffic_type: TrafficType,
    ) -> u32 {
        let quality = self.quality_tracker.get_quality(transport.transport_type, destination);

        // Scoring factors:
        let mut score = 0u32;

        // Latency (higher is better, inverse scale)
        score += (1000 / (quality.latency.as_millis() + 1)) as u32;

        // Bandwidth
        score += (quality.bandwidth / 1_000_000) as u32;

        // Reliability (0.0-1.0)
        score += (quality.reliability * 100.0) as u32;

        // Priority bonus
        score += transport.priority as u32 * 10;

        // Traffic type suitability
        score += match (traffic_type, transport.transport_type) {
            // Tor: good for anonymity, bad for latency-sensitive
            (TrafficType::Web, TransportType::Tor) => 20,
            (TrafficType::Streaming, TransportType::Tor) => 0,
            (TrafficType::VoIP, TransportType::Tor) => 0,

            // WireGuard: excellent for everything
            (_, TransportType::WireGuard) => 30,

            // Clearnet: fast but not censorship-resistant
            (TrafficType::VoIP, TransportType::Clearnet) => 40,
            (_, TransportType::Clearnet) => 10,

            _ => 5,
        };

        score
    }
}
```

### Quality Monitoring

```rust
pub struct QualityTracker {
    measurements: Arc<RwLock<HashMap<(TransportType, PeerId), TransportQuality>>>,
}

pub struct TransportQuality {
    pub latency: Duration,
    pub bandwidth: u64,          // bytes per second
    pub reliability: f32,        // 0.0 - 1.0
    pub last_measured: SystemTime,
    pub packet_loss: f32,
}

impl QualityTracker {
    /// Continuously monitor transport quality
    pub fn start_monitoring(&self) {
        tokio::spawn(async move {
            loop {
                // Ping each transport/peer combination
                for (transport, peer) in active_routes {
                    let quality = measure_quality(transport, peer).await;
                    self.update_quality(transport, peer, quality);
                }

                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    async fn measure_quality(
        &self,
        transport: TransportType,
        peer: &PeerId,
    ) -> TransportQuality {
        // Send probe packets
        let start = Instant::now();
        let result = send_probe(transport, peer).await;
        let latency = start.elapsed();

        // Measure bandwidth with larger payload
        let bandwidth = measure_bandwidth(transport, peer).await;

        TransportQuality {
            latency,
            bandwidth,
            reliability: if result.is_ok() { 0.99 } else { 0.0 },
            last_measured: SystemTime::now(),
            packet_loss: 0.01,
        }
    }
}
```

## Security Considerations

### IP Spoofing Prevention

All inbound packets are verified:

```rust
pub fn handle_inbound_from_mesh(&self, source_peer: &PeerId, packet: &[u8]) -> Result<()> {
    // Parse source IP from packet header
    let packet_source_ip = parse_source_ip(packet)?;

    // Look up expected IP for this peer
    let expected_ip = self.vpn_service.get_peer_ip(source_peer)
        .ok_or(Error::UnknownPeer)?;

    // Verify they match
    if packet_source_ip != expected_ip {
        return Err(Error::SecurityViolation(format!(
            "IP spoofing: peer {:?} sent packet with source {} but should be {}",
            source_peer, packet_source_ip, expected_ip
        )));
    }

    // Packet verified, inject into TUN
    self.vpn_service.inject_inbound_packet(packet)
}
```

### Exit Node Trust

Exit nodes have access to unencrypted traffic after decapsulation. Trust is enforced:

```rust
pub fn select_exit_node(&self, trust_requirement: TrustLevel) -> Option<PeerId> {
    let available_exits = self.get_available_exit_nodes();

    available_exits
        .into_iter()
        .filter(|peer_id| {
            let trust = self.web_of_trust.get_trust_level(peer_id);
            trust >= trust_requirement
        })
        .max_by_key(|peer_id| {
            // Prefer peers with:
            // 1. Higher trust
            // 2. Better bandwidth
            // 3. Lower latency
            let trust_score = self.web_of_trust.get_trust_level(peer_id) as u32 * 1000;
            let quality_score = self.quality_tracker.score(peer_id);
            trust_score + quality_score
        })
}
```

### Encryption Layers

When using exit nodes, traffic has multiple encryption layers:

```
┌─────────────────────────────────────────────┐
│ Original packet (e.g., HTTPS to example.com)│  ← TLS encryption
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ Mesh packet encryption (PFS)                │  ← Mesh Infinity encryption
│ [ Encrypted: original packet ]              │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ Transport encryption (Tor/WireGuard)        │  ← Transport layer encryption
│ [ Encrypted: mesh packet ]                  │
└─────────────────────────────────────────────┘
```

Exit nodes can only see:
- That traffic came from a mesh peer
- The original IP packet (destination, protocol)
- Content if not TLS (HTTP, unencrypted protocols)

Exit nodes **cannot** see:
- Your real IP address (hidden by mesh)
- Your identity (if using Tor transport)
- TLS-encrypted content

## Platform Integration

### macOS / iOS

**Network Extension Framework**:

```swift
// NEPacketTunnelProvider implementation
class MeshInfinityVPNProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String : NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        // Initialize Mesh Infinity Rust backend
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "100.64.0.1")
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["100.64.0.1"],
            subnetMasks: ["255.192.0.0"]  // /10
        )

        // Route all mesh IPs through our tunnel
        settings.ipv4Settings?.includedRoutes = [
            NEIPv4Route(destinationAddress: "100.64.0.0",
                       subnetMask: "255.192.0.0")
        ]

        setTunnelNetworkSettings(settings) { error in
            // Start packet processing
            self.packetFlow.readPackets { packets, protocols in
                // Send to Rust backend
                meshinfinity_handle_packets(packets)
            }
            completionHandler(error)
        }
    }
}
```

### Android

**VPN Service**:

```kotlin
class MeshInfinityVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val builder = Builder()
            .setSession("Mesh Infinity")
            .addAddress("100.64.0.1", 10)
            .addRoute("100.64.0.0", 10)
            .setMtu(1400)

        val vpnInterface = builder.establish()

        // Start packet processing thread
        thread {
            val packet = ByteArray(32767)
            while (running) {
                val length = vpnInterface.read(packet)
                // Send to Rust backend
                MeshInfinity.handlePacket(packet, length)
            }
        }

        return START_STICKY
    }
}
```

### Linux

**TUN device with routing**:

```bash
# Mesh Infinity automatically creates and configures:
sudo ip tuntap add mode tun name mi0
sudo ip addr add 100.64.0.1/10 dev mi0
sudo ip link set mi0 up
sudo ip route add 100.64.0.0/10 dev mi0

# Optional: Route all traffic through exit node
sudo ip route add default via 100.64.0.1 dev mi0 table 100
sudo ip rule add fwmark 0x1 table 100
```

### Windows

**WinTun driver**:

```rust
use wintun::Adapter;

pub fn create_windows_interface() -> Result<Adapter> {
    let adapter = Adapter::create("Mesh Infinity", "Mesh Infinity", None)?;

    // Configure IP
    adapter.set_ip_address("100.64.0.1", "255.192.0.0")?;

    // Start packet processing
    let session = adapter.start_session(wintun::MAX_RING_CAPACITY)?;

    Ok(adapter)
}
```

## Performance Optimizations

### Zero-Copy Packet Processing

```rust
// Use io_uring on Linux for zero-copy TUN I/O
#[cfg(target_os = "linux")]
pub struct IoUringTunDevice {
    ring: IoUring,
    buffers: Vec<Box<[u8]>>,
}

impl IoUringTunDevice {
    pub async fn read_packet(&mut self) -> Result<&[u8]> {
        // Submit read operation
        unsafe {
            self.ring.submission()
                .push(&opcode::Read::new(
                    types::Fd(self.tun_fd),
                    self.buffers[0].as_mut_ptr(),
                    self.buffers[0].len() as u32,
                ).build())?;
        }

        // Wait for completion (zero-copy)
        let cqe = self.ring.completion().next().await?;
        Ok(&self.buffers[0][..cqe.result() as usize])
    }
}
```

### Batch Processing

```rust
pub struct BatchProcessor {
    pending: Vec<Packet>,
    batch_size: usize,
}

impl BatchProcessor {
    pub fn process_packets(&mut self) {
        while let Some(packet) = self.read_from_tun() {
            self.pending.push(packet);

            if self.pending.len() >= self.batch_size {
                self.flush();
            }
        }
    }

    fn flush(&mut self) {
        // Process entire batch in one go
        let destinations = self.pending
            .iter()
            .map(|p| self.route_packet(p))
            .collect::<Vec<_>>();

        // Group by destination peer
        let mut by_peer = HashMap::new();
        for (packet, peer) in self.pending.drain(..).zip(destinations) {
            by_peer.entry(peer).or_insert_with(Vec::new).push(packet);
        }

        // Send batched to each peer
        for (peer, packets) in by_peer {
            self.send_batch(peer, packets);
        }
    }
}
```

## Configuration Example

```toml
[vpn]
enabled = true
interface_name = "mi0"
network_range = "100.64.0.0/10"
mtu = 1400

[vpn.routing]
default_action = "direct"  # or "exit_node"
default_exit_node = "peer_abc123"

[[vpn.routing.policies]]
name = "Route work traffic through VPN"
matcher = { destination = "192.0.2.0/24" }
action = { use_exit_node = "work_exit" }

[[vpn.routing.policies]]
name = "Route Tor Browser through Tor"
matcher = { application = "firefox" }
action = { use_transport = "tor" }

[[vpn.routing.policies]]
name = "Block ads"
matcher = { destination = ["ads.example.com", "tracker.example.com"] }
action = "block"

[vpn.exit_node]
enabled = true
allowed_destinations = "all"
bandwidth_limit = 10_000_000  # 10 Mbps
trust_requirement = "trusted"

[[vpn.external_vpns]]
name = "work_vpn"
provider = { wireguard = { config = "/etc/wireguard/work.conf" } }

[[vpn.external_vpns]]
name = "mullvad"
provider = { wireguard = { config = "/etc/wireguard/mullvad.conf" } }
```

## Monitoring & Control

### Real-time Statistics

```rust
pub struct VpnStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub active_connections: usize,
    pub routing_latency: Duration,
}

pub struct PeerStats {
    pub peer_id: PeerId,
    pub ip_address: IpAddr,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency: Duration,
    pub transport: TransportType,
}

// FFI for Flutter UI
#[no_mangle]
pub extern "C" fn mi_vpn_get_stats() -> *const VpnStats {
    // Return current statistics
}

#[no_mangle]
pub extern "C" fn mi_vpn_get_peer_stats(count: *mut usize) -> *const PeerStats {
    // Return per-peer statistics
}
```

### UI Control Panel

```dart
class VpnControlPanel extends StatefulWidget {
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // VPN Status
        VpnStatusCard(),

        // Exit Node Selection
        ExitNodeSelector(),

        // Routing Policies
        RoutingPoliciesList(),

        // Per-Peer Statistics
        PeerStatsList(),

        // Traffic Graph
        TrafficGraph(),
      ],
    );
  }
}
```

## Use Cases

### 1. **Censorship Circumvention**
Route all traffic through Tor transport to resist censorship, while using exit nodes in uncensored countries.

### 2. **Privacy-Preserving Remote Work**
Access company resources through trusted exit nodes without exposing your location or using company VPN.

### 3. **Geo-Distributed Services**
Deploy services across the mesh and use exit nodes to make them appear local to different regions.

### 4. **Secure IoT Networking**
Connect IoT devices to mesh with unique IPs, route all their traffic through controlled exit nodes.

### 5. **Anonymous Publishing**
Run services accessible via mesh IPs while routing through Tor, providing deniability and censorship resistance.

### 6. **Multi-Path Reliability**
Automatically fail over between transports (Tor → I2P → WireGuard) based on availability and quality.

---

This PMWAN architecture transforms Mesh Infinity from a messaging app into a complete networking platform, providing Tailscale-like convenience with the security and censorship-resistance of Tor/I2P.
