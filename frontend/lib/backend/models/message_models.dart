// ---------------------------------------------------------------------------
// MessageRequest — pending inbound conversation from a low-trust peer (§22.5.4)
// ---------------------------------------------------------------------------
//
// WHAT IS A MESSAGE REQUEST?
// When a peer whose trust level is 0–5 (below "ally" threshold) sends us a
// first message, the Rust backend does NOT deliver it to the main room list.
// Instead it queues it here as a MessageRequest.  The UI then shows it in
// MessageRequestsScreen, where the user can Accept or Decline.
//
// WHY HOLD LOW-TRUST MESSAGES SEPARATELY?
// The main chat list is a curated, trusted space.  Delivering low-trust
// messages directly there would train users to treat unknown senders as
// implicitly safe.  The request inbox is the intentional friction point.
//
// RATE LIMITS (enforced in Rust, NOT in this model):
//   - Max 5 pending requests per unique sender (prevents request flooding).
//   - Total queue cap: 200 requests.
//   - Requests older than 30 days are automatically expired.
//
// RELATIONSHIP TO MessageModel
// MessageRequest is a lightweight summary, not the full message thread.
// [messagePreview] is the first ~100 characters of the first message — just
// enough for the user to decide whether to accept.  The full message is only
// accessible after accepting (at which point a real room + MessageModels are
// created in the backend).

/// A single pending inbound message request (§22.5.4).
///
/// Returned by [BackendBridge.fetchMessageRequests] and stored in
/// [MessagingState._requests].
class MessageRequest {
  const MessageRequest({
    required this.id,
    required this.peerId,
    required this.senderName,
    required this.trustLevel,
    required this.messagePreview,
    required this.timestamp,
  });

  /// Opaque backend identifier for this request.  Passed to
  /// [BackendBridge.acceptMessageRequest] / [declineMessageRequest].
  final String id;

  /// The peer ID of the sender — used to open their PeerDetailScreen
  /// so the user can evaluate who is making the request.
  final String peerId;

  /// Display name of the sender, or a hex-prefix of their peer ID if unnamed.
  final String senderName;

  /// Raw trust level integer (0–8).  Use [TrustLevel.fromInt(trustLevel)]
  /// to convert to the typed enum for display in [TrustBadge].
  final int trustLevel;

  /// First ~100 chars of the first message — shown in the request tile so
  /// the user can gauge intent without accepting the full conversation.
  final String messagePreview;

  /// ISO-8601 timestamp string of when the request arrived.
  /// Displayed in the tile's trust-context row.
  final String timestamp;

  /// Deserialise from the JSON returned by the Rust backend.
  ///
  /// Every field uses `?? ''` / `?? 0` fallbacks so that a missing or null
  /// JSON key never causes a runtime cast exception — the worst outcome is
  /// that a field shows as blank, which is recoverable by the user.
  factory MessageRequest.fromJson(Map<String, dynamic> json) => MessageRequest(
    id: json['id'] as String? ?? '',
    peerId: json['peerId'] as String? ?? '',
    senderName: json['senderName'] as String? ?? '',
    trustLevel: json['trustLevel'] as int? ?? 0,
    messagePreview: json['messagePreview'] as String? ?? '',
    timestamp: json['timestamp'] as String? ?? '',
  );
}

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
