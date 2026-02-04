class PeerInfoModel {
  const PeerInfoModel({
    required this.id,
    required this.name,
    required this.trustLevel,
    required this.status,
  });

  final String id;
  final String name;
  final int trustLevel;
  final String status;

  factory PeerInfoModel.fromJson(Map<String, dynamic> json) {
    return PeerInfoModel(
      id: json['id'] as String? ?? '',
      name: json['name'] as String? ?? '',
      trustLevel: json['trustLevel'] as int? ?? 0,
      status: json['status'] as String? ?? '',
    );
  }
}
