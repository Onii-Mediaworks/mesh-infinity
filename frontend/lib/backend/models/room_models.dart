class RoomSummary {
  const RoomSummary({
    required this.id,
    required this.name,
    this.lastMessage = '',
    this.unreadCount = 0,
    this.timestamp = '',
  });

  final String id;
  final String name;
  final String lastMessage;
  final int unreadCount;
  final String timestamp;

  factory RoomSummary.fromJson(Map<String, dynamic> json) => RoomSummary(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    lastMessage: json['lastMessage'] as String? ?? '',
    unreadCount: json['unreadCount'] as int? ?? 0,
    timestamp: json['timestamp'] as String? ?? '',
  );

  RoomSummary copyWith({
    String? id,
    String? name,
    String? lastMessage,
    int? unreadCount,
    String? timestamp,
  }) => RoomSummary(
    id: id ?? this.id,
    name: name ?? this.name,
    lastMessage: lastMessage ?? this.lastMessage,
    unreadCount: unreadCount ?? this.unreadCount,
    timestamp: timestamp ?? this.timestamp,
  );
}
