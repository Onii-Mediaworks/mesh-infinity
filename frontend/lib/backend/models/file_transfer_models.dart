enum TransferStatus {
  pending,
  active,
  paused,
  completed,
  failed;

  static TransferStatus fromString(String s) =>
      TransferStatus.values.firstWhere(
        (e) => e.name == s,
        orElse: () => TransferStatus.pending,
      );

  bool get isActive => this == TransferStatus.active;
  bool get isDone => this == TransferStatus.completed || this == TransferStatus.failed;
}

enum TransferDirection {
  send,
  receive;

  static TransferDirection fromString(String s) =>
      s == 'send' ? TransferDirection.send : TransferDirection.receive;
}

class FileTransferModel {
  const FileTransferModel({
    required this.id,
    required this.peerId,
    required this.name,
    required this.sizeBytes,
    required this.transferredBytes,
    required this.status,
    required this.direction,
  });

  final String id;
  final String peerId;
  final String name;
  final int sizeBytes;
  final int transferredBytes;
  final TransferStatus status;
  final TransferDirection direction;

  double get progress =>
      sizeBytes > 0 ? (transferredBytes / sizeBytes).clamp(0.0, 1.0) : 0.0;

  factory FileTransferModel.fromJson(Map<String, dynamic> json) => FileTransferModel(
    id: json['id'] as String? ?? '',
    peerId: json['peerId'] as String? ?? '',
    name: json['name'] as String? ?? '',
    sizeBytes: (json['sizeBytes'] as num?)?.toInt() ?? 0,
    transferredBytes: (json['transferredBytes'] as num?)?.toInt() ?? 0,
    status: TransferStatus.fromString(json['status'] as String? ?? 'pending'),
    direction: TransferDirection.fromString(json['direction'] as String? ?? 'receive'),
  );

  FileTransferModel copyWith({
    String? id,
    String? peerId,
    String? name,
    int? sizeBytes,
    int? transferredBytes,
    TransferStatus? status,
    TransferDirection? direction,
  }) => FileTransferModel(
    id: id ?? this.id,
    peerId: peerId ?? this.peerId,
    name: name ?? this.name,
    sizeBytes: sizeBytes ?? this.sizeBytes,
    transferredBytes: transferredBytes ?? this.transferredBytes,
    status: status ?? this.status,
    direction: direction ?? this.direction,
  );
}
