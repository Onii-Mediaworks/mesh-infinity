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
  );
}

class DiscoveredPeerModel {
  const DiscoveredPeerModel({required this.id, required this.address});

  final String id;
  final String address;

  factory DiscoveredPeerModel.fromJson(Map<String, dynamic> json) =>
      DiscoveredPeerModel(
        id: json['id'] as String? ?? '',
        address: json['address'] as String? ?? '',
      );
}
