// =============================================================================
// network_models.dart
//
// Typed Dart models for network-layer statistics and local peer discovery.
//
// WHAT THESE MODELS REPRESENT
// The Rust backend continuously measures mesh network activity.  The Network
// feature screen (NetworkState → StatusScreen, NodesScreen, TransportsScreen)
// reads these models to display live stats to the user.
//
// HOW DATA FLOWS HERE
// NetworkState periodically calls BackendBridge.getNetworkStats() which calls
// mi_get_network_stats() in Rust.  The returned JSON is decoded into a
// NetworkStatsModel.  Similarly, mDNS-discovered peers on the local LAN are
// fetched via BackendBridge.getDiscoveredPeers() and decoded into a list of
// DiscoveredPeerModel.
//
// DESERIALIZATION PATTERN
// All fromJson() factories use `?? 0` / `?? ''` fallbacks so that a missing
// field in the JSON does not crash the app — it simply shows zero or empty.
// JSON numbers are handled via `(json['x'] as num?)?.toInt()` because the
// Rust serialiser may emit them as either int or float depending on the value.
// =============================================================================

/// A snapshot of real-time mesh network statistics.
///
/// Returned by [BackendBridge.getNetworkStats] and decoded into this class by
/// [NetworkStatsModel.fromJson].  All counts are cumulative since node startup
/// unless otherwise noted.
class NetworkStatsModel {
  const NetworkStatsModel({
    this.bytesSent = 0,
    this.bytesReceived = 0,
    this.activeConnections = 0,
    this.pendingRoutes = 0,
    this.deliveredRoutes = 0,
    this.failedRoutes = 0,
    this.packetsLost = 0,
    this.avgLatencyMs = 0,
    this.bandwidthKbps = 0,
    this.routingEntries = 0,
    this.gossipMapSize = 0,
    this.wireGuardSessions = 0,
    this.sfPendingMessages = 0,
    this.clearnetConnections = 0,
  });

  /// Total bytes transmitted to other peers across all transports since startup.
  final int bytesSent;

  /// Total bytes received from other peers across all transports since startup.
  final int bytesReceived;

  /// Number of peers with an active transport session right now.
  final int activeConnections;

  /// Route computation requests that have been queued but not yet resolved.
  final int pendingRoutes;

  /// Routes that were successfully computed and packets forwarded.
  final int deliveredRoutes;

  /// Route computation attempts that failed (no path to destination found).
  final int failedRoutes;

  /// Cumulative count of packets declared lost (no ACK received within timeout).
  final int packetsLost;

  /// Exponentially weighted moving average of round-trip latency in milliseconds
  /// across all active connections.  0 if no connections are active.
  final int avgLatencyMs;

  /// Estimated current outbound bandwidth in kilobits per second.
  final int bandwidthKbps;

  /// Total entries across all four routing planes (§6.1).
  ///
  /// The four planes are: direct, relay, store-and-forward, and overlay.
  /// A high value here means the node has learned many routes — expected on
  /// well-connected relay nodes.
  final int routingEntries;

  /// Number of entries in the gossip network map (§4.1).
  ///
  /// The gossip map tracks which peers have been announced by other peers via
  /// the gossip protocol.  It grows as the node discovers more of the mesh
  /// topology.  A very large value (>1000) may indicate a gossip amplification
  /// event.
  final int gossipMapSize;

  /// Active WireGuard link-layer sessions (§5.2).
  ///
  /// Each entry represents a completed WireGuard handshake with a peer.
  /// WireGuard sessions provide authenticated, encrypted point-to-point links
  /// on top of which mesh traffic runs.
  final int wireGuardSessions;

  /// Messages buffered in the store-and-forward server (§6.8).
  ///
  /// When a destination peer is offline, messages are queued here until they
  /// reconnect.  A high value means many offline peers have undelivered messages.
  final int sfPendingMessages;

  /// Currently identified clearnet TCP connections.
  ///
  /// "Clearnet" means plain internet (not Tor, not I2P).  Each entry is a
  /// direct TCP connection to another peer using their public IP address.
  final int clearnetConnections;

  /// Deserialise from the JSON object returned by mi_get_network_stats().
  factory NetworkStatsModel.fromJson(Map<String, dynamic> json) => NetworkStatsModel(
    bytesSent: (json['bytesSent'] as num?)?.toInt() ?? 0,
    bytesReceived: (json['bytesReceived'] as num?)?.toInt() ?? 0,
    activeConnections: (json['activeConnections'] as num?)?.toInt() ?? 0,
    pendingRoutes: (json['pendingRoutes'] as num?)?.toInt() ?? 0,
    deliveredRoutes: (json['deliveredRoutes'] as num?)?.toInt() ?? 0,
    failedRoutes: (json['failedRoutes'] as num?)?.toInt() ?? 0,
    packetsLost: (json['packetsLost'] as num?)?.toInt() ?? 0,
    avgLatencyMs: (json['avgLatencyMs'] as num?)?.toInt() ?? 0,
    bandwidthKbps: (json['bandwidthKbps'] as num?)?.toInt() ?? 0,
    routingEntries: (json['routingEntries'] as num?)?.toInt() ?? 0,
    gossipMapSize: (json['gossipMapSize'] as num?)?.toInt() ?? 0,
    wireGuardSessions: (json['wireGuardSessions'] as num?)?.toInt() ?? 0,
    sfPendingMessages: (json['sfPendingMessages'] as num?)?.toInt() ?? 0,
    clearnetConnections: (json['clearnetConnections'] as num?)?.toInt() ?? 0,
  );
}

/// A peer discovered on the local network via mDNS (Multicast DNS).
///
/// mDNS lets devices on the same LAN announce themselves without a central
/// server — the same technology as Apple's Bonjour / `.local` hostnames.
/// The backend listens for mDNS announcements on UDP and collects them here.
///
/// Discovered peers are shown in the Network → Nodes screen.  The user can
/// tap one to initiate pairing if [canPair] is true.
class DiscoveredPeerModel {
  const DiscoveredPeerModel({
    required this.id,
    required this.address,
    this.displayName = '',
    this.ed25519Pub = '',
    this.x25519Pub = '',
  });

  /// The peer's hex-encoded node ID, as announced via mDNS.
  final String id;

  /// The network address where this peer is reachable (e.g. "192.168.1.42:7234").
  final String address;

  /// Human-readable display name, if the peer chose to advertise one.
  /// Empty string if the peer did not include a name in its announcement.
  final String displayName;

  /// Ed25519 public key hex — needed to construct a pairing payload.
  ///
  /// Ed25519 is the signing key — used to verify that messages really came
  /// from this peer and to establish a shared secret via X25519 DH.
  final String ed25519Pub;

  /// X25519 public key hex — needed to construct a pairing payload.
  ///
  /// X25519 is the Diffie-Hellman key agreement key — used to derive the
  /// shared session key for the WireGuard link and the Double Ratchet.
  final String x25519Pub;

  /// True if this entry has enough key material to attempt direct pairing.
  ///
  /// Both public keys must be present for pairing — without them we cannot
  /// establish a cryptographically authenticated session with this peer.
  bool get canPair => ed25519Pub.isNotEmpty && x25519Pub.isNotEmpty;

  /// Deserialise from the JSON object in the mi_mdns_get_discovered_peers() list.
  factory DiscoveredPeerModel.fromJson(Map<String, dynamic> json) =>
      DiscoveredPeerModel(
        id: json['id'] as String? ?? '',
        address: json['address'] as String? ?? '',
        displayName: json['displayName'] as String? ?? '',
        ed25519Pub: json['ed25519Pub'] as String? ?? '',
        x25519Pub: json['x25519Pub'] as String? ?? '',
      );
}
