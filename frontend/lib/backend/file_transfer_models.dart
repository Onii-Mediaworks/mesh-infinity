class FileTransferItem {
  const FileTransferItem({
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
  final String status;
  final String direction;

  factory FileTransferItem.fromJson(Map<String, dynamic> json) {
    return FileTransferItem(
      id: json['id'] as String? ?? '',
      peerId: json['peerId'] as String? ?? '',
      name: json['name'] as String? ?? '',
      sizeBytes: json['sizeBytes'] as int? ?? 0,
      transferredBytes: json['transferredBytes'] as int? ?? 0,
      status: json['status'] as String? ?? '',
      direction: json['direction'] as String? ?? '',
    );
  }
}
