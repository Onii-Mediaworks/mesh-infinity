// Policy Router - Flexible routing based on traffic policies
// Replaces IP-based routing with policy-based decisions
//
// Routing is determined by:
// - Traffic matchers (protocol, port, destination patterns)
// - Routing actions (transport selection, exit node, direct peer)
// - Conversation state (existing connections maintain their routing)

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Serialize, Deserialize};

use crate::core::{PeerId, TransportType, Protocol, TrustLevel};
use crate::core::error::{MeshInfinityError, Result};
use super::mesh_address::{MeshAddress, DeviceAddress, ConversationId, ConversationTuple};

/// Traffic matching criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrafficMatcher {
    /// Match all traffic
    Any,

    /// Match by destination IP/CIDR
    DestinationIp {
        ip: IpAddr,
        prefix_len: Option<u8>,
    },

    /// Match by destination port
    DestinationPort(u16),

    /// Match by port range
    PortRange { start: u16, end: u16 },

    /// Match by protocol
    Protocol(Protocol),

    /// Match by domain pattern (for DNS-aware routing)
    DomainPattern(String),

    /// Match by mesh address prefix
    MeshPrefix {
        device_prefix: Vec<u8>,
    },

    /// Match by conversation (existing connection)
    Conversation(ConversationTuple),

    /// Match by peer trust level (route based on who we're talking to)
    TrustLevel(TrustLevel),

    /// Compound matcher: all conditions must match
    All(Vec<TrafficMatcher>),

    /// Compound matcher: any condition must match
    AnyOf(Vec<TrafficMatcher>),

    /// Negation
    Not(Box<TrafficMatcher>),
}

/// What action to take when traffic matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingAction {
    /// Route directly to a mesh peer
    DirectPeer {
        destination: DeviceAddress,
    },

    /// Route through a specific transport
    UseTransport {
        transport: TransportType,
        /// Optional peer to route through
        via_peer: Option<DeviceAddress>,
    },

    /// Route through an exit node (for internet traffic)
    ExitNode {
        /// Specific exit node, or None for auto-select
        node: Option<DeviceAddress>,
        /// Preferred transport to the exit node
        transport: Option<TransportType>,
    },

    /// Route through external VPN
    ExternalVpn {
        config_id: String,
    },

    /// Multi-hop routing through specific peers
    MultiHop {
        hops: Vec<DeviceAddress>,
        final_transport: TransportType,
    },

    /// Block this traffic
    Block {
        reason: String,
    },

    /// Allow traffic to pass through to real network (bypass mesh)
    Bypass,

    /// Defer to next matching rule
    Continue,
}

/// A routing policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Unique rule identifier
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Priority (lower = higher priority, evaluated first)
    pub priority: u32,

    /// Traffic matcher
    pub matcher: TrafficMatcher,

    /// Action to take
    pub action: RoutingAction,

    /// Is this rule enabled?
    pub enabled: bool,

    /// Optional expiration time (for temporary rules)
    #[serde(skip)]
    pub expires_at: Option<Instant>,
}

/// Routing decision result
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// The rule that matched
    pub rule_id: String,

    /// The action to take
    pub action: RoutingAction,

    /// Source address to use
    pub source_addr: MeshAddress,

    /// Destination address
    pub destination_addr: MeshAddress,

    /// Conversation ID for this flow
    pub conversation_id: ConversationId,
}

/// Active conversation tracking
#[derive(Debug, Clone)]
pub struct ActiveConversation {
    pub tuple: ConversationTuple,
    pub routing_decision: RoutingDecision,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Policy Router - makes routing decisions based on policies
pub struct PolicyRouter {
    /// Routing rules, sorted by priority
    rules: Arc<RwLock<Vec<RoutingRule>>>,

    /// Active conversations (keyed by source-side tuple)
    active_conversations: Arc<RwLock<HashMap<ConversationTuple, ActiveConversation>>>,

    /// Mapping of peer IDs to their known device addresses
    peer_addresses: Arc<RwLock<HashMap<PeerId, Vec<DeviceAddress>>>>,

    /// Our device address registry (which addresses belong to us)
    our_addresses: Arc<RwLock<Vec<DeviceAddress>>>,

    /// Exit node pool
    available_exit_nodes: Arc<RwLock<Vec<ExitNodeInfo>>>,

    /// Conversation timeout for cleanup
    conversation_timeout: Duration,
}

/// Information about an available exit node
#[derive(Debug, Clone)]
pub struct ExitNodeInfo {
    pub device_address: DeviceAddress,
    pub peer_id: PeerId,
    pub trust_level: TrustLevel,
    pub available_transports: Vec<TransportType>,
    pub bandwidth_available: u64,
    pub latency_ms: u32,
    pub last_seen: Instant,
}

impl PolicyRouter {
    /// Create a new policy router
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            active_conversations: Arc::new(RwLock::new(HashMap::new())),
            peer_addresses: Arc::new(RwLock::new(HashMap::new())),
            our_addresses: Arc::new(RwLock::new(Vec::new())),
            available_exit_nodes: Arc::new(RwLock::new(Vec::new())),
            conversation_timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Add a routing rule
    pub fn add_rule(&self, rule: RoutingRule) {
        let mut rules = self.rules.write().unwrap();
        rules.push(rule);
        // Keep sorted by priority
        rules.sort_by_key(|r| r.priority);
    }

    /// Remove a rule by ID
    pub fn remove_rule(&self, rule_id: &str) -> bool {
        let mut rules = self.rules.write().unwrap();
        let initial_len = rules.len();
        rules.retain(|r| r.id != rule_id);
        rules.len() < initial_len
    }

    /// Register our device address
    pub fn register_our_address(&self, addr: DeviceAddress) {
        self.our_addresses.write().unwrap().push(addr);
    }

    /// Register a peer's device address
    pub fn register_peer_address(&self, peer_id: PeerId, addr: DeviceAddress) {
        let mut addresses = self.peer_addresses.write().unwrap();
        addresses.entry(peer_id).or_default().push(addr);
    }

    /// Register an available exit node
    pub fn register_exit_node(&self, info: ExitNodeInfo) {
        let mut nodes = self.available_exit_nodes.write().unwrap();
        // Update existing or add new
        if let Some(existing) = nodes.iter_mut().find(|n| n.device_address == info.device_address) {
            *existing = info;
        } else {
            nodes.push(info);
        }
    }

    /// Make a routing decision for outbound traffic
    pub fn route_outbound(
        &self,
        packet: &PacketInfo,
        our_source_addr: DeviceAddress,
    ) -> Result<RoutingDecision> {
        // Check for existing conversation
        let conv_id = ConversationId::from_session(&packet.flow_id());

        // Check if we have an active conversation for this flow
        {
            let conversations = self.active_conversations.read().unwrap();
            // Build a probe tuple to search
            let probe = self.build_conversation_probe(packet, &our_source_addr, &conv_id);
            if let Some(conv) = conversations.get(&probe) {
                // Return existing decision for this conversation
                return Ok(conv.routing_decision.clone());
            }
        }

        // No existing conversation, evaluate rules
        let rules = self.rules.read().unwrap();

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // Check expiration
            if let Some(expires) = rule.expires_at {
                if Instant::now() > expires {
                    continue;
                }
            }

            if self.matches(&rule.matcher, packet) {
                match &rule.action {
                    RoutingAction::Continue => continue,
                    RoutingAction::Block { reason } => {
                        return Err(MeshInfinityError::NetworkError(
                            format!("Traffic blocked: {}", reason)
                        ));
                    }
                    action => {
                        let decision = self.build_decision(
                            &rule.id,
                            action.clone(),
                            our_source_addr,
                            packet,
                            conv_id,
                        )?;

                        // Store as active conversation
                        self.record_conversation(&decision);

                        return Ok(decision);
                    }
                }
            }
        }

        // No rule matched - default action depends on destination
        if self.is_mesh_traffic(packet) {
            // Mesh traffic without explicit rule - try direct routing
            Err(MeshInfinityError::NetworkError(
                "No routing rule matched for mesh traffic".to_string()
            ))
        } else {
            // Internet traffic - default to blocking unless exit node configured
            Err(MeshInfinityError::NetworkError(
                "No exit node configured for internet traffic".to_string()
            ))
        }
    }

    /// Route inbound traffic (from mesh to local)
    pub fn route_inbound(
        &self,
        source_addr: &MeshAddress,
        our_addr: &MeshAddress,
        packet_data: &[u8],
    ) -> Result<InboundDecision> {
        // Verify destination is one of our addresses
        let our_device = our_addr.device_address();
        let is_ours = self.our_addresses.read().unwrap().contains(&our_device);

        if !is_ours {
            return Err(MeshInfinityError::NetworkError(
                "Inbound packet addressed to unknown local address".to_string()
            ));
        }

        // Update conversation tracking
        let conv_id = our_addr.conversation_id();
        let tuple = ConversationTuple {
            source: *source_addr,
            destination: *our_addr,
            conversation_id: conv_id,
        };

        // Update activity timestamp
        {
            let mut conversations = self.active_conversations.write().unwrap();
            if let Some(conv) = conversations.get_mut(&tuple.reverse()) {
                conv.last_activity = Instant::now();
                conv.packets_received += 1;
                conv.bytes_received += packet_data.len() as u64;
            }
        }

        Ok(InboundDecision {
            accept: true,
            source_addr: *source_addr,
            conversation_id: conv_id,
        })
    }

    /// Check if traffic matches a matcher
    fn matches(&self, matcher: &TrafficMatcher, packet: &PacketInfo) -> bool {
        match matcher {
            TrafficMatcher::Any => true,

            TrafficMatcher::DestinationIp { ip, prefix_len } => {
                if let Some(dest) = &packet.dest_ip {
                    if let Some(prefix) = prefix_len {
                        self.ip_matches_prefix(dest, ip, *prefix)
                    } else {
                        dest == ip
                    }
                } else {
                    false
                }
            }

            TrafficMatcher::DestinationPort(port) => {
                packet.dest_port == Some(*port)
            }

            TrafficMatcher::PortRange { start, end } => {
                if let Some(port) = packet.dest_port {
                    port >= *start && port <= *end
                } else {
                    false
                }
            }

            TrafficMatcher::Protocol(proto) => {
                packet.protocol == *proto
            }

            TrafficMatcher::DomainPattern(pattern) => {
                if let Some(domain) = &packet.resolved_domain {
                    self.domain_matches(domain, pattern)
                } else {
                    false
                }
            }

            TrafficMatcher::MeshPrefix { device_prefix } => {
                if let Some(mesh_addr) = &packet.mesh_destination {
                    let device_addr = mesh_addr.device_address();
                    device_addr.as_bytes().starts_with(device_prefix)
                } else {
                    false
                }
            }

            TrafficMatcher::Conversation(tuple) => {
                // Check if this packet belongs to the specified conversation
                if let Some(mesh_dest) = &packet.mesh_destination {
                    tuple.destination.same_device(mesh_dest)
                } else {
                    false
                }
            }

            TrafficMatcher::TrustLevel(required_level) => {
                if let Some(level) = &packet.peer_trust_level {
                    level >= required_level
                } else {
                    false
                }
            }

            TrafficMatcher::All(matchers) => {
                matchers.iter().all(|m| self.matches(m, packet))
            }

            TrafficMatcher::AnyOf(matchers) => {
                matchers.iter().any(|m| self.matches(m, packet))
            }

            TrafficMatcher::Not(inner) => {
                !self.matches(inner, packet)
            }
        }
    }

    /// Build a routing decision from an action
    fn build_decision(
        &self,
        rule_id: &str,
        action: RoutingAction,
        our_source: DeviceAddress,
        packet: &PacketInfo,
        conv_id: ConversationId,
    ) -> Result<RoutingDecision> {
        let source_addr = our_source.with_conversation(conv_id);

        // Determine destination address
        let destination_addr = match &action {
            RoutingAction::DirectPeer { destination } => {
                destination.with_conversation(conv_id)
            }
            RoutingAction::ExitNode { node, .. } => {
                if let Some(exit_addr) = node {
                    exit_addr.with_conversation(conv_id)
                } else {
                    // Auto-select exit node
                    self.select_best_exit_node()?
                        .device_address
                        .with_conversation(conv_id)
                }
            }
            RoutingAction::UseTransport { via_peer, .. } => {
                if let Some(peer) = via_peer {
                    peer.with_conversation(conv_id)
                } else if let Some(mesh_dest) = &packet.mesh_destination {
                    *mesh_dest
                } else {
                    return Err(MeshInfinityError::NetworkError(
                        "No destination for transport routing".to_string()
                    ));
                }
            }
            RoutingAction::MultiHop { hops, .. } => {
                // First hop is the immediate destination
                if let Some(first) = hops.first() {
                    first.with_conversation(conv_id)
                } else {
                    return Err(MeshInfinityError::NetworkError(
                        "Empty hop list for multi-hop routing".to_string()
                    ));
                }
            }
            _ => {
                // For other actions, use mesh destination if available
                packet.mesh_destination.unwrap_or_else(MeshAddress::zero)
            }
        };

        Ok(RoutingDecision {
            rule_id: rule_id.to_string(),
            action,
            source_addr,
            destination_addr,
            conversation_id: conv_id,
        })
    }

    /// Record a new conversation
    fn record_conversation(&self, decision: &RoutingDecision) {
        let tuple = ConversationTuple::new(
            decision.source_addr,
            decision.destination_addr,
        );

        let conv = ActiveConversation {
            tuple: tuple.clone(),
            routing_decision: decision.clone(),
            created_at: Instant::now(),
            last_activity: Instant::now(),
            packets_sent: 1,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };

        self.active_conversations.write().unwrap().insert(tuple, conv);
    }

    /// Build a probe tuple for conversation lookup
    fn build_conversation_probe(
        &self,
        packet: &PacketInfo,
        source: &DeviceAddress,
        conv_id: &ConversationId,
    ) -> ConversationTuple {
        let source_addr = source.with_conversation(*conv_id);
        let dest_addr = packet.mesh_destination.unwrap_or_else(MeshAddress::zero);

        ConversationTuple {
            source: source_addr,
            destination: dest_addr,
            conversation_id: *conv_id,
        }
    }

    /// Check if traffic is destined for the mesh
    fn is_mesh_traffic(&self, packet: &PacketInfo) -> bool {
        packet.mesh_destination.is_some()
    }

    /// Check if IP matches a prefix
    fn ip_matches_prefix(&self, ip: &IpAddr, prefix_ip: &IpAddr, prefix_len: u8) -> bool {
        match (ip, prefix_ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                if prefix_len > 32 {
                    return false;
                }
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                (u32::from(*a) & mask) == (u32::from(*b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                if prefix_len > 128 {
                    return false;
                }
                let a_bytes = a.octets();
                let b_bytes = b.octets();
                let full_bytes = (prefix_len / 8) as usize;
                let remaining_bits = prefix_len % 8;

                if a_bytes[..full_bytes] != b_bytes[..full_bytes] {
                    return false;
                }

                if remaining_bits > 0 && full_bytes < 16 {
                    let mask = 0xFF << (8 - remaining_bits);
                    (a_bytes[full_bytes] & mask) == (b_bytes[full_bytes] & mask)
                } else {
                    true
                }
            }
            _ => false, // Mismatched IP versions
        }
    }

    /// Check if domain matches a pattern (supports wildcards)
    fn domain_matches(&self, domain: &str, pattern: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // Keep the dot
            domain.ends_with(suffix) || domain == &pattern[2..]
        } else {
            domain == pattern
        }
    }

    /// Select the best available exit node
    fn select_best_exit_node(&self) -> Result<ExitNodeInfo> {
        let nodes = self.available_exit_nodes.read().unwrap();

        if nodes.is_empty() {
            return Err(MeshInfinityError::NetworkError(
                "No exit nodes available".to_string()
            ));
        }

        // Score based on: trust level, latency, bandwidth
        let now = Instant::now();
        let best = nodes.iter()
            .filter(|n| now.duration_since(n.last_seen) < Duration::from_secs(60))
            .max_by(|a, b| {
                let score_a = self.exit_node_score(a);
                let score_b = self.exit_node_score(b);
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            });

        best.cloned()
            .ok_or_else(|| MeshInfinityError::NetworkError(
                "No suitable exit node found".to_string()
            ))
    }

    /// Calculate score for exit node selection
    fn exit_node_score(&self, node: &ExitNodeInfo) -> f64 {
        let trust_score = match node.trust_level {
            TrustLevel::HighlyTrusted => 1.0,
            TrustLevel::Trusted => 0.75,
            TrustLevel::Caution => 0.5,
            TrustLevel::Untrusted => 0.25,
        };

        let latency_score = 1.0 / (1.0 + (node.latency_ms as f64 / 100.0));
        let bandwidth_score = (node.bandwidth_available as f64).log10() / 10.0;

        trust_score * 0.5 + latency_score * 0.3 + bandwidth_score * 0.2
    }

    /// Clean up expired conversations
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut conversations = self.active_conversations.write().unwrap();

        conversations.retain(|_, conv| {
            now.duration_since(conv.last_activity) < self.conversation_timeout
        });

        // Also clean up expired rules
        let mut rules = self.rules.write().unwrap();
        rules.retain(|rule| {
            rule.expires_at.map(|exp| now < exp).unwrap_or(true)
        });
    }

    /// Get statistics
    pub fn stats(&self) -> PolicyRouterStats {
        PolicyRouterStats {
            active_rules: self.rules.read().unwrap().len(),
            active_conversations: self.active_conversations.read().unwrap().len(),
            known_peers: self.peer_addresses.read().unwrap().len(),
            available_exit_nodes: self.available_exit_nodes.read().unwrap().len(),
        }
    }
}

impl Default for PolicyRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Packet information for routing decisions
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// Source IP (for IP-based traffic)
    pub source_ip: Option<IpAddr>,
    /// Destination IP (for IP-based traffic)
    pub dest_ip: Option<IpAddr>,
    /// Source port
    pub source_port: Option<u16>,
    /// Destination port
    pub dest_port: Option<u16>,
    /// Protocol
    pub protocol: Protocol,
    /// Resolved domain name (from DNS tracking)
    pub resolved_domain: Option<String>,
    /// Mesh destination address (for mesh-addressed traffic)
    pub mesh_destination: Option<MeshAddress>,
    /// Trust level of the peer we're communicating with
    pub peer_trust_level: Option<TrustLevel>,
    /// Raw packet data
    pub data: Vec<u8>,
}

impl PacketInfo {
    /// Generate a flow ID for conversation tracking
    pub fn flow_id(&self) -> Vec<u8> {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();

        if let Some(src) = &self.source_ip {
            hasher.update(format!("{}", src).as_bytes());
        }
        if let Some(dst) = &self.dest_ip {
            hasher.update(format!("{}", dst).as_bytes());
        }
        if let Some(port) = self.source_port {
            hasher.update(&port.to_be_bytes());
        }
        if let Some(port) = self.dest_port {
            hasher.update(&port.to_be_bytes());
        }
        hasher.update(&[self.protocol.to_u8()]);

        hasher.finalize().to_vec()
    }

    /// Parse from raw IP packet
    pub fn from_ip_packet(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }

        let version = (packet[0] >> 4) & 0x0F;

        if version == 4 {
            Self::parse_ipv4(packet)
        } else if version == 6 {
            Self::parse_ipv6(packet)
        } else {
            None
        }
    }

    fn parse_ipv4(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }

        let ihl = (packet[0] & 0x0F) as usize * 4;
        let protocol_num = packet[9];

        let source_ip = IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15]
        ));
        let dest_ip = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19]
        ));

        let protocol = match protocol_num {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            _ => Protocol::Custom(protocol_num),
        };

        let (source_port, dest_port) = if packet.len() >= ihl + 4 {
            match protocol {
                Protocol::TCP | Protocol::UDP => {
                    let sp = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                    let dp = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                    (Some(sp), Some(dp))
                }
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        Some(Self {
            source_ip: Some(source_ip),
            dest_ip: Some(dest_ip),
            source_port,
            dest_port,
            protocol,
            resolved_domain: None,
            mesh_destination: None,
            peer_trust_level: None,
            data: packet.to_vec(),
        })
    }

    fn parse_ipv6(packet: &[u8]) -> Option<Self> {
        if packet.len() < 40 {
            return None;
        }

        let protocol_num = packet[6]; // Next header

        let protocol = match protocol_num {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            58 => Protocol::ICMP, // ICMPv6
            _ => Protocol::Custom(protocol_num),
        };

        // For simplicity, just extract the basic info
        // Full IPv6 parsing would handle extension headers
        let (source_port, dest_port) = if packet.len() >= 44 {
            match protocol {
                Protocol::TCP | Protocol::UDP => {
                    let sp = u16::from_be_bytes([packet[40], packet[41]]);
                    let dp = u16::from_be_bytes([packet[42], packet[43]]);
                    (Some(sp), Some(dp))
                }
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        Some(Self {
            source_ip: None, // Would need full IPv6 address parsing
            dest_ip: None,
            source_port,
            dest_port,
            protocol,
            resolved_domain: None,
            mesh_destination: None,
            peer_trust_level: None,
            data: packet.to_vec(),
        })
    }
}

impl Protocol {
    fn to_u8(&self) -> u8 {
        match self {
            Protocol::TCP => 6,
            Protocol::UDP => 17,
            Protocol::ICMP => 1,
            Protocol::Custom(n) => *n,
        }
    }
}

/// Inbound traffic decision
#[derive(Debug, Clone)]
pub struct InboundDecision {
    pub accept: bool,
    pub source_addr: MeshAddress,
    pub conversation_id: ConversationId,
}

/// Router statistics
#[derive(Debug, Clone)]
pub struct PolicyRouterStats {
    pub active_rules: usize,
    pub active_conversations: usize,
    pub known_peers: usize,
    pub available_exit_nodes: usize,
}

/// Convenience builders for common rules
impl RoutingRule {
    /// Create a rule to route all traffic through an exit node
    pub fn default_exit_node(exit_node: DeviceAddress) -> Self {
        Self {
            id: "default-exit".to_string(),
            name: "Default Exit Node".to_string(),
            priority: 1000, // Low priority (high number = evaluated later)
            matcher: TrafficMatcher::Any,
            action: RoutingAction::ExitNode {
                node: Some(exit_node),
                transport: None,
            },
            enabled: true,
            expires_at: None,
        }
    }

    /// Create a rule to route specific domain through specific transport
    pub fn domain_transport(domain: &str, transport: TransportType) -> Self {
        Self {
            id: format!("domain-{}", domain.replace('.', "-")),
            name: format!("Route {} via {:?}", domain, transport),
            priority: 100,
            matcher: TrafficMatcher::DomainPattern(domain.to_string()),
            action: RoutingAction::UseTransport {
                transport,
                via_peer: None,
            },
            enabled: true,
            expires_at: None,
        }
    }

    /// Create a rule to route to a specific peer
    pub fn peer_direct(peer_addr: DeviceAddress) -> Self {
        let bytes = peer_addr.as_bytes();
        let id_suffix: String = bytes[..8].iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        Self {
            id: format!("peer-{}", id_suffix),
            name: "Direct peer routing".to_string(),
            priority: 50,
            matcher: TrafficMatcher::MeshPrefix {
                device_prefix: peer_addr.as_bytes()[..8].to_vec(),
            },
            action: RoutingAction::DirectPeer {
                destination: peer_addr,
            },
            enabled: true,
            expires_at: None,
        }
    }

    /// Create a rule to block traffic to specific IPs
    pub fn block_ip(ip: IpAddr, reason: &str) -> Self {
        Self {
            id: format!("block-{}", ip),
            name: format!("Block {}", ip),
            priority: 10, // High priority
            matcher: TrafficMatcher::DestinationIp { ip, prefix_len: None },
            action: RoutingAction::Block { reason: reason.to_string() },
            enabled: true,
            expires_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_any() {
        let router = PolicyRouter::new();
        let packet = PacketInfo {
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            source_port: Some(12345),
            dest_port: Some(443),
            protocol: Protocol::TCP,
            resolved_domain: None,
            mesh_destination: None,
            peer_trust_level: None,
            data: vec![],
        };

        assert!(router.matches(&TrafficMatcher::Any, &packet));
    }

    #[test]
    fn test_matcher_port() {
        let router = PolicyRouter::new();
        let packet = PacketInfo {
            source_ip: None,
            dest_ip: None,
            source_port: Some(12345),
            dest_port: Some(443),
            protocol: Protocol::TCP,
            resolved_domain: None,
            mesh_destination: None,
            peer_trust_level: None,
            data: vec![],
        };

        assert!(router.matches(&TrafficMatcher::DestinationPort(443), &packet));
        assert!(!router.matches(&TrafficMatcher::DestinationPort(80), &packet));
    }

    #[test]
    fn test_matcher_compound() {
        let router = PolicyRouter::new();
        let packet = PacketInfo {
            source_ip: None,
            dest_ip: None,
            source_port: Some(12345),
            dest_port: Some(443),
            protocol: Protocol::TCP,
            resolved_domain: None,
            mesh_destination: None,
            peer_trust_level: None,
            data: vec![],
        };

        let matcher = TrafficMatcher::All(vec![
            TrafficMatcher::DestinationPort(443),
            TrafficMatcher::Protocol(Protocol::TCP),
        ]);

        assert!(router.matches(&matcher, &packet));

        let non_matching = TrafficMatcher::All(vec![
            TrafficMatcher::DestinationPort(80),
            TrafficMatcher::Protocol(Protocol::TCP),
        ]);

        assert!(!router.matches(&non_matching, &packet));
    }

    #[test]
    fn test_domain_matching() {
        let router = PolicyRouter::new();

        assert!(router.domain_matches("example.com", "example.com"));
        assert!(router.domain_matches("sub.example.com", "*.example.com"));
        assert!(router.domain_matches("example.com", "*.example.com"));
        assert!(!router.domain_matches("other.com", "*.example.com"));
    }

    #[test]
    fn test_ip_prefix_matching() {
        let router = PolicyRouter::new();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let prefix = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));

        assert!(router.ip_matches_prefix(&ip, &prefix, 24));
        assert!(!router.ip_matches_prefix(&ip, &prefix, 32));
    }
}
