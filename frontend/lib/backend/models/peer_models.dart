enum TrustLevel {
  untrusted(0),
  caution(1),
  trusted(2),
  highlyTrusted(3);

  const TrustLevel(this.value);
  final int value;

  static TrustLevel fromInt(int v) =>
      TrustLevel.values.firstWhere((e) => e.value == v, orElse: () => TrustLevel.untrusted);

  String get label => switch (this) {
    TrustLevel.untrusted => 'Untrusted',
    TrustLevel.caution => 'Caution',
    TrustLevel.trusted => 'Trusted',
    TrustLevel.highlyTrusted => 'Highly Trusted',
  };
}

class PeerModel {
  const PeerModel({
    required this.id,
    required this.name,
    this.trustLevel = TrustLevel.untrusted,
    this.status = 'offline',
    this.canBeExitNode = false,
    this.canBeWrapperNode = false,
    this.canBeStoreForward = false,
    this.canEndorsePeers = false,
    this.latencyMs,
  });

  final String id;
  final String name;
  final TrustLevel trustLevel;
  final String status;

  /// Whether this peer advertises itself as an available exit node.
  final bool canBeExitNode;

  /// Whether this peer advertises itself as an available wrapper node.
  final bool canBeWrapperNode;

  /// Whether this peer advertises store-and-forward capability.
  final bool canBeStoreForward;

  /// Whether this peer can endorse other peers in the web of trust.
  final bool canEndorsePeers;

  /// Round-trip latency to this peer in milliseconds, if known.
  final int? latencyMs;

  bool get isOnline => status == 'online';
  bool get isIdle => status == 'idle';

  factory PeerModel.fromJson(Map<String, dynamic> json) => PeerModel(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    trustLevel: TrustLevel.fromInt(json['trustLevel'] as int? ?? 0),
    status: json['status'] as String? ?? 'offline',
    canBeExitNode: json['canBeExitNode'] as bool? ?? false,
    canBeWrapperNode: json['canBeWrapperNode'] as bool? ?? false,
    canBeStoreForward: json['canBeStoreForward'] as bool? ?? false,
    canEndorsePeers: json['canEndorsePeers'] as bool? ?? false,
    latencyMs: json['latencyMs'] as int?,
  );

  PeerModel copyWith({
    String? id,
    String? name,
    TrustLevel? trustLevel,
    String? status,
    bool? canBeExitNode,
    bool? canBeWrapperNode,
    bool? canBeStoreForward,
    bool? canEndorsePeers,
    int? latencyMs,
  }) => PeerModel(
    id: id ?? this.id,
    name: name ?? this.name,
    trustLevel: trustLevel ?? this.trustLevel,
    status: status ?? this.status,
    canBeExitNode: canBeExitNode ?? this.canBeExitNode,
    canBeWrapperNode: canBeWrapperNode ?? this.canBeWrapperNode,
    canBeStoreForward: canBeStoreForward ?? this.canBeStoreForward,
    canEndorsePeers: canEndorsePeers ?? this.canEndorsePeers,
    latencyMs: latencyMs ?? this.latencyMs,
  );
}
