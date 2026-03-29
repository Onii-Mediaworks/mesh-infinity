class ReactionModel {
  const ReactionModel({
    required this.emoji,
    required this.sender,
    required this.timestamp,
  });

  final String emoji;
  final String sender;
  final int timestamp;

  factory ReactionModel.fromJson(Map<String, dynamic> json) => ReactionModel(
    emoji: json['emoji'] as String? ?? '',
    sender: json['sender'] as String? ?? '',
    timestamp: json['timestamp'] as int? ?? 0,
  );
}

/// Authentication/decryption status for an inbound message (M17, §7.1).
///
/// - `authenticated`: HMAC verified and Double Ratchet decrypted successfully.
/// - `outgoing`: sent by us (no inbound verification needed).
/// - `decryptionFailed`: ciphertext could not be decrypted — show ⚠ in UI.
/// - `unauthenticated`: plaintext path (no session yet); treat with caution.
enum MessageAuthStatus { authenticated, outgoing, decryptionFailed, unauthenticated }

class MessageModel {
  const MessageModel({
    required this.id,
    required this.roomId,
    required this.sender,
    required this.text,
    required this.timestamp,
    this.isOutgoing = false,
    this.replyTo,
    this.reactions = const [],
    this.edited = false,
    this.expiresAt,
    this.contentType = 'text',
    this.deliveryStatus = 'sent',
    this.forwardedFrom,
    this.authStatus = MessageAuthStatus.unauthenticated,
  });

  final String id;
  final String roomId;
  final String sender;
  final String text;
  final String timestamp;
  final bool isOutgoing;
  final String? replyTo;
  final List<ReactionModel> reactions;
  final bool edited;
  final String? expiresAt;
  final String contentType;
  final String deliveryStatus;
  final String? forwardedFrom;
  /// Whether this message was cryptographically verified (M17, §7.1).
  final MessageAuthStatus authStatus;

  /// True when the message failed decryption — show ⚠ warning in the UI.
  bool get isDecryptionFailed => authStatus == MessageAuthStatus.decryptionFailed;

  static MessageAuthStatus _parseAuthStatus(String? s) => switch (s) {
    'authenticated' => MessageAuthStatus.authenticated,
    'outgoing' => MessageAuthStatus.outgoing,
    'decryptionFailed' => MessageAuthStatus.decryptionFailed,
    _ => MessageAuthStatus.unauthenticated,
  };

  factory MessageModel.fromJson(Map<String, dynamic> json) => MessageModel(
    id: json['id'] as String? ?? '',
    roomId: json['roomId'] as String? ?? '',
    sender: json['sender'] as String? ?? '',
    text: json['text'] as String? ?? '',
    timestamp: json['timestamp'] as String? ?? '',
    isOutgoing: json['isOutgoing'] as bool? ?? false,
    replyTo: json['replyTo'] as String?,
    reactions: (json['reactions'] as List<dynamic>?)
        ?.map((e) => ReactionModel.fromJson(e as Map<String, dynamic>))
        .toList() ?? const [],
    edited: json['edited'] as bool? ?? false,
    expiresAt: json['expiresAt'] as String?,
    contentType: json['contentType'] as String? ?? 'text',
    deliveryStatus: json['deliveryStatus'] as String? ?? 'sent',
    forwardedFrom: json['forwardedFrom'] as String?,
    authStatus: _parseAuthStatus(json['authStatus'] as String?),
  );

  MessageModel copyWith({
    String? id,
    String? roomId,
    String? sender,
    String? text,
    String? timestamp,
    bool? isOutgoing,
    String? replyTo,
    List<ReactionModel>? reactions,
    bool? edited,
    String? expiresAt,
    String? contentType,
    String? deliveryStatus,
    String? forwardedFrom,
    MessageAuthStatus? authStatus,
  }) => MessageModel(
    id: id ?? this.id,
    roomId: roomId ?? this.roomId,
    sender: sender ?? this.sender,
    text: text ?? this.text,
    timestamp: timestamp ?? this.timestamp,
    isOutgoing: isOutgoing ?? this.isOutgoing,
    replyTo: replyTo ?? this.replyTo,
    reactions: reactions ?? this.reactions,
    edited: edited ?? this.edited,
    expiresAt: expiresAt ?? this.expiresAt,
    contentType: contentType ?? this.contentType,
    deliveryStatus: deliveryStatus ?? this.deliveryStatus,
    forwardedFrom: forwardedFrom ?? this.forwardedFrom,
    authStatus: authStatus ?? this.authStatus,
  );
}
