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

/// A single emoji reaction attached to a message (§10.1.2).
///
/// Reactions are stored on the message itself ([MessageModel.reactions]).
/// They are updated by [ReactionAddedEvent] from the event bus.
class ReactionModel {
  const ReactionModel({
    required this.emoji,
    required this.sender,
    required this.timestamp,
  });

  /// The emoji character or sequence (e.g. "👍", "❤️").
  final String emoji;

  /// Hex-encoded peer ID of the peer who sent this reaction.
  /// May be the local peer's own ID for reactions sent by this device.
  final String sender;

  /// Unix epoch timestamp (seconds) when the reaction was added.
  /// Used to order reactions chronologically in the UI.
  final int timestamp;

  /// Deserialise from the JSON within a MessageModel's "reactions" array.
  factory ReactionModel.fromJson(Map<String, dynamic> json) => ReactionModel(
    emoji: json['emoji'] as String? ?? '',
    sender: json['sender'] as String? ?? '',
    timestamp: json['timestamp'] as int? ?? 0,
  );
}

/// The cryptographic authentication status of an inbound message (M17, §7.1).
///
/// The Rust backend verifies every inbound message against the Double Ratchet
/// session with the sender and sets this field accordingly.  The UI uses it to
/// show a verification badge or a decryption-failure warning.
///
/// - [authenticated]: HMAC verified and Double Ratchet decrypted successfully.
/// - [outgoing]: sent by us (no inbound verification needed).
/// - [decryptionFailed]: ciphertext could not be decrypted — show ⚠ in UI.
/// - [unauthenticated]: plaintext path (no session established yet); treat with caution.
enum MessageAuthStatus { authenticated, outgoing, decryptionFailed, unauthenticated }

/// A single chat message as stored and returned by the Rust backend.
///
/// This model represents one entry in a conversation thread.  It is fetched
/// in bulk via [BackendBridge.fetchMessages] and delivered incrementally via
/// [MessageAddedEvent].  Updates to an existing message (edit, delivery status,
/// new reactions) arrive via [MessageStatusUpdatedEvent] and [ReactionAddedEvent].
///
/// All fields are immutable; use [copyWith] to produce an updated copy.
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

  /// Opaque backend-assigned message ID (hex string).
  final String id;

  /// The room this message belongs to (hex room ID).
  final String roomId;

  /// Hex-encoded peer ID of the message author.
  /// For outgoing messages this is the local node's own peer ID.
  final String sender;

  /// The message body as a UTF-8 string.
  /// For non-text content types (e.g. "image"), this may be a URI or caption.
  final String text;

  /// ISO-8601 timestamp string of when the message was created.
  final String timestamp;

  /// True if this message was sent by the local user (not received from a peer).
  /// Controls bubble alignment and whether a delivery indicator is shown.
  final bool isOutgoing;

  /// The ID of the message this is a reply to, or null if it is a top-level message.
  /// When non-null, the UI renders a quoted-message preview above the bubble.
  final String? replyTo;

  /// Emoji reactions attached to this message.
  final List<ReactionModel> reactions;

  /// True if this message has been edited by its sender after initial delivery.
  /// The UI shows an "edited" label next to the timestamp when true.
  final bool edited;

  /// ISO-8601 expiry timestamp for disappearing messages (§10.1.4).
  /// Null means the message does not expire.  When non-null, the UI shows a
  /// countdown timer and the backend prunes the message after this time.
  final String? expiresAt;

  /// The MIME-like content type of the message body.
  /// Current values: "text" (default), "image", "file", "audio", "location".
  /// The UI uses this to choose the appropriate renderer for [text].
  final String contentType;

  /// Delivery state of an outgoing message, or acknowledgement state of
  /// an incoming message.  Known values: "sending", "sent", "delivered", "read".
  /// The UI maps these to delivery indicator icons (single/double ticks).
  final String deliveryStatus;

  /// The peer ID of the original sender if this message was forwarded by a
  /// third party.  Null for direct messages.  When non-null, the UI shows a
  /// "Forwarded from [name]" header above the bubble.
  final String? forwardedFrom;

  /// Whether this message was cryptographically verified (M17, §7.1).
  final MessageAuthStatus authStatus;

  /// True when the message failed decryption — show ⚠ warning in the UI.
  /// This is a convenience getter derived from [authStatus] to avoid repeated
  /// enum comparisons in widget code.
  bool get isDecryptionFailed => authStatus == MessageAuthStatus.decryptionFailed;

  /// Parse the string representation of [MessageAuthStatus] from JSON.
  ///
  /// Unknown strings default to [MessageAuthStatus.unauthenticated] — the most
  /// conservative interpretation (show no verification badge).
  static MessageAuthStatus _parseAuthStatus(String? s) => switch (s) {
    'authenticated' => MessageAuthStatus.authenticated,
    'outgoing' => MessageAuthStatus.outgoing,
    'decryptionFailed' => MessageAuthStatus.decryptionFailed,
    // Any unknown value (including null) → unauthenticated.
    // This is safe: the UI will not show a false "verified" badge for unknown values.
    _ => MessageAuthStatus.unauthenticated,
  };

  /// Deserialise from one element of the mi_messages_json() JSON array, or
  /// from the payload of a [MessageAddedEvent].
  factory MessageModel.fromJson(Map<String, dynamic> json) => MessageModel(
    id: json['id'] as String? ?? '',
    roomId: json['roomId'] as String? ?? '',
    sender: json['sender'] as String? ?? '',
    text: json['text'] as String? ?? '',
    timestamp: json['timestamp'] as String? ?? '',
    isOutgoing: json['isOutgoing'] as bool? ?? false,
    // replyTo is genuinely optional — null means "not a reply".
    replyTo: json['replyTo'] as String?,
    // Parse the reactions array, ignoring any element that is not a Map.
    reactions: (json['reactions'] as List<dynamic>?)
        ?.map((e) => ReactionModel.fromJson(e as Map<String, dynamic>))
        .toList() ?? const [],
    edited: json['edited'] as bool? ?? false,
    // expiresAt is null for non-disappearing messages.
    expiresAt: json['expiresAt'] as String?,
    contentType: json['contentType'] as String? ?? 'text',
    deliveryStatus: json['deliveryStatus'] as String? ?? 'sent',
    // forwardedFrom is null for direct (non-forwarded) messages.
    forwardedFrom: json['forwardedFrom'] as String?,
    authStatus: _parseAuthStatus(json['authStatus'] as String?),
  );

  /// Return a copy with selected fields replaced.
  ///
  /// Used by MessagingState to apply incremental updates:
  ///   - [deliveryStatus] update from [MessageStatusUpdatedEvent]
  ///   - [reactions] update from [ReactionAddedEvent]
  ///   - [text] + [edited] = true from an edit operation
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
