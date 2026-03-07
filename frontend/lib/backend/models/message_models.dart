class MessageModel {
  const MessageModel({
    required this.id,
    required this.roomId,
    required this.sender,
    required this.text,
    required this.timestamp,
    this.isOutgoing = false,
  });

  final String id;
  final String roomId;
  final String sender;
  final String text;
  final String timestamp;
  final bool isOutgoing;

  factory MessageModel.fromJson(Map<String, dynamic> json) => MessageModel(
    id: json['id'] as String? ?? '',
    roomId: json['roomId'] as String? ?? '',
    sender: json['sender'] as String? ?? '',
    text: json['text'] as String? ?? '',
    timestamp: json['timestamp'] as String? ?? '',
    isOutgoing: json['isOutgoing'] as bool? ?? false,
  );
}
