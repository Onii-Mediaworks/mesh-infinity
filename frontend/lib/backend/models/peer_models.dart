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
  });

  final String id;
  final String name;
  final TrustLevel trustLevel;
  final String status;

  bool get isOnline => status == 'online';
  bool get isIdle => status == 'idle';

  factory PeerModel.fromJson(Map<String, dynamic> json) => PeerModel(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    trustLevel: TrustLevel.fromInt(json['trustLevel'] as int? ?? 0),
    status: json['status'] as String? ?? 'offline',
  );

  PeerModel copyWith({
    String? id,
    String? name,
    TrustLevel? trustLevel,
    String? status,
  }) => PeerModel(
    id: id ?? this.id,
    name: name ?? this.name,
    trustLevel: trustLevel ?? this.trustLevel,
    status: status ?? this.status,
  );
}
