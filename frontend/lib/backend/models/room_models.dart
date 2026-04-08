// =============================================================================
// room_models.dart
//
// Typed Dart model for a conversation room summary.
//
// WHAT IS A ROOM?
// A "room" is the unit of conversation in Mesh Infinity.  It can be:
//
//   DM room  — a private conversation between exactly two peers.
//              [conversationType] == "dm", [otherPeerId] is non-null.
//
//   Group room — a conversation between three or more peers, managed by a
//              group object in the backend.
//              [conversationType] == "group", [groupId] is non-null.
//
// Each room has a stable [id] (hex string) that the backend uses as the
// primary key across all message storage, routing, and event tables.
//
// WHERE THIS COMES FROM
// BackendBridge.fetchRooms() calls mi_rooms_json() in Rust, which returns a
// JSON array of RoomSummary objects.  RoomUpdatedEvent and RoomDeletedEvent
// on the event bus deliver incremental changes.
//
// IMMUTABILITY PATTERN
// RoomSummary is immutable.  When a RoomUpdatedEvent arrives, MessagingState
// replaces the old RoomSummary with the new one rather than mutating in place.
// copyWith() makes it easy to update a single field (e.g. unreadCount) while
// preserving all others.
// =============================================================================

/// A lightweight summary of one conversation room, as returned by the backend.
///
/// This is a "summary" — it contains just enough data to render a row in the
/// conversation list (name, last message preview, unread badge) but not the
/// full message history.  The full history is fetched on demand when the user
/// opens the room via [BackendBridge.fetchMessages].
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

  /// Hex-encoded room ID — the backend's primary key for this conversation.
  final String id;

  /// Human-readable room name.
  /// For DMs: the display name of the other peer (may change if they rename).
  /// For groups: the group name chosen by the creator.
  final String name;

  /// Preview of the most recent message (first ~80 chars).
  /// Empty string if no messages have been sent yet.
  final String lastMessage;

  /// Count of messages received since the user last viewed this room.
  /// Zero when all messages have been read.
  final int unreadCount;

  /// ISO-8601 timestamp string of the most recent message.
  /// Empty string if no messages have been sent yet.
  final String timestamp;

  /// Conversation type discriminator: "dm" or "group".
  ///
  /// This drives the UI's layout decisions (e.g. group avatars vs. peer avatars)
  /// and the routing logic (group messages use a different Rust path).
  final String conversationType;

  /// Non-null for group rooms — the hex group ID managed by the backend (§8.7).
  ///
  /// Null for DM rooms.  UI code should use [isGroup] to check the type rather
  /// than null-checking this field directly, to avoid confusion if a future
  /// type is added.
  final String? groupId;

  /// Non-null for DM rooms — the hex peer ID of the other participant.
  ///
  /// Null for group rooms.  Used by PeerDetailScreen to look up the peer's
  /// full profile when the user taps the conversation avatar.
  final String? otherPeerId;

  /// True when this is a group conversation (three or more participants).
  bool get isGroup => conversationType == 'group';

  /// Deserialise from one element of the mi_rooms_json() JSON array.
  factory RoomSummary.fromJson(Map<String, dynamic> json) => RoomSummary(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    lastMessage: json['lastMessage'] as String? ?? '',
    unreadCount: json['unreadCount'] as int? ?? 0,
    timestamp: json['timestamp'] as String? ?? '',
    conversationType: json['conversationType'] as String? ?? 'dm',
    // groupId and otherPeerId are intentionally nullable — null is a valid
    // semantic value (means "this is not a group" / "this is not a DM").
    // We do NOT use ?? '' because an empty string would be indistinguishable
    // from a real empty-string ID, which could trigger incorrect UI branches.
    groupId: json['groupId'] as String?,
    otherPeerId: json['otherPeerId'] as String?,
  );

  /// Return a copy with selected fields replaced.
  ///
  /// Used by MessagingState to apply partial updates from [RoomUpdatedEvent]
  /// without constructing a full new object from scratch.
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
