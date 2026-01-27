class ThreadSummary {
  const ThreadSummary({
    required this.id,
    required this.title,
    required this.preview,
    required this.lastSeen,
    required this.unreadCount,
  });

  final String id;
  final String title;
  final String preview;
  final String lastSeen;
  final int unreadCount;
}

class MessageItem {
  const MessageItem({
    required this.id,
    required this.sender,
    required this.text,
    required this.timestamp,
    required this.isOutgoing,
  });

  final String id;
  final String sender;
  final String text;
  final String timestamp;
  final bool isOutgoing;
}
