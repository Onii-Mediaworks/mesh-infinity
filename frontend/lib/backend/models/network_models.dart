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

  final int bytesSent;
  final int bytesReceived;
  final int activeConnections;
  final int pendingRoutes;
  final int deliveredRoutes;
  final int failedRoutes;
  final int packetsLost;
  final int avgLatencyMs;
  final int bandwidthKbps;

  /// Total entries across all four routing planes (§6.1).
  final int routingEntries;

  /// Number of entries in the gossip network map (§4.1).
  final int gossipMapSize;

  /// Active WireGuard link-layer sessions (§5.2).
  final int wireGuardSessions;

  /// Messages buffered in the store-and-forward server (§6.8).
  final int sfPendingMessages;

  /// Currently identified clearnet TCP connections.
  final int clearnetConnections;

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

class DiscoveredPeerModel {
  const DiscoveredPeerModel({
    required this.id,
    required this.address,
    this.displayName = '',
    this.ed25519Pub = '',
    this.x25519Pub = '',
  });

  final String id;
  final String address;
  final String displayName;

  /// Ed25519 public key hex — needed to construct a pairing payload.
  final String ed25519Pub;

  /// X25519 public key hex — needed to construct a pairing payload.
  final String x25519Pub;

  /// True if this entry has enough data to attempt direct pairing.
  bool get canPair => ed25519Pub.isNotEmpty && x25519Pub.isNotEmpty;

  factory DiscoveredPeerModel.fromJson(Map<String, dynamic> json) =>
      DiscoveredPeerModel(
        id: json['id'] as String? ?? '',
        address: json['address'] as String? ?? '',
        displayName: json['displayName'] as String? ?? '',
        ed25519Pub: json['ed25519Pub'] as String? ?? '',
        x25519Pub: json['x25519Pub'] as String? ?? '',
      );
}
