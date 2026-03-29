class RoomSummary {
  const RoomSummary({
    required this.id,
    required this.name,
    this.lastMessage = '',
    this.unreadCount = 0,
    this.timestamp = '',
    this.conversationType = 'dm',
    this.groupId,
    this.otherPeerId,
  });

  final String id;
  final String name;
  final String lastMessage;
  final int unreadCount;
  final String timestamp;
  /// "dm" or "group"
  final String conversationType;
  /// Non-null for group rooms; the hex group ID.
  final String? groupId;
  /// Non-null for DM rooms; the other party's peer ID hex.
  final String? otherPeerId;

  bool get isGroup => conversationType == 'group';

  factory RoomSummary.fromJson(Map<String, dynamic> json) => RoomSummary(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    lastMessage: json['lastMessage'] as String? ?? '',
    unreadCount: json['unreadCount'] as int? ?? 0,
    timestamp: json['timestamp'] as String? ?? '',
    conversationType: json['conversationType'] as String? ?? 'dm',
    groupId: json['groupId'] as String?,
    otherPeerId: json['otherPeerId'] as String?,
  );

  RoomSummary copyWith({
    String? id,
    String? name,
    String? lastMessage,
    int? unreadCount,
    String? timestamp,
    String? conversationType,
    String? groupId,
    String? otherPeerId,
  }) => RoomSummary(
    id: id ?? this.id,
    name: name ?? this.name,
    lastMessage: lastMessage ?? this.lastMessage,
    unreadCount: unreadCount ?? this.unreadCount,
    timestamp: timestamp ?? this.timestamp,
    conversationType: conversationType ?? this.conversationType,
    groupId: groupId ?? this.groupId,
    otherPeerId: otherPeerId ?? this.otherPeerId,
  );
}
