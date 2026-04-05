// =============================================================================
// event_models.dart
//
// Typed Dart representations of every real-time event that the Rust backend
// can emit.
//
// WHERE DO THESE EVENTS COME FROM?
// The Rust backend maintains an internal event queue.  Any time something
// significant happens — a new message arrives, a peer changes status, a file
// transfer progresses — Rust pushes an event object onto that queue.  The
// background isolate in event_bus.dart polls the queue via mi_poll_events()
// and delivers the raw JSON to this file's fromJson() factory, which converts
// it into one of the typed classes below.
//
// WHY SEALED CLASSES?
// In Dart, a `sealed` class (introduced in Dart 3) is a class that can only
// be subclassed within the same file.  This gives us two powerful guarantees:
//
//   1. EXHAUSTIVE PATTERN MATCHING — when you write a `switch` statement on a
//      BackendEvent, the Dart compiler knows every possible subtype.  If you
//      forget to handle one (e.g. you forgot the TrustUpdatedEvent case), the
//      compiler issues a compile-time warning.  This prevents bugs where new
//      event types are added but some handler doesn't know about them.
//
//   2. CONTROLLED HIERARCHY — external code cannot create new BackendEvent
//      subclasses.  The set of possible events is fixed and visible in a single
//      file, making the codebase easier to reason about.
//
// HOW TO USE THESE IN STATE OBJECTS
// Feature state classes subscribe to EventBus.instance.stream and pattern-
// match incoming events:
//
//   EventBus.instance.stream.listen((event) {
//     switch (event) {
//       case MessageAddedEvent(:final message):
//         // handle new message
//       case PeerUpdatedEvent(:final peer):
//         // handle peer status change
//       default:
//         break; // ignore events we don't care about
//     }
//   });
//
// THE JSON FORMAT
// Each event from Rust arrives as a JSON object with two keys:
//   { "type": "EventTypeName", "data": { ...event-specific fields... } }
//
// fromJson() reads the "type" string and dispatches to the appropriate
// constructor, passing the "data" object as its argument.
// =============================================================================

// Model imports — each event type wraps one of the typed model objects that
// the rest of the app already uses for display and state management.
import 'models/room_models.dart';
import 'models/message_models.dart';
import 'models/peer_models.dart';
import 'models/file_transfer_models.dart';
import 'models/settings_models.dart';

// =============================================================================
// BackendEvent — sealed base class
//
// All event types extend this class.  It acts as the common type so that
// `Stream<BackendEvent>` can carry any event type, and switch statements can
// exhaustively match all subtypes.
// =============================================================================

sealed class BackendEvent {
  // The `const` constructor means subclasses can be constant expressions if
  // all their fields are also constant.  This is a minor optimisation for
  // event objects that are created in large numbers.
  const BackendEvent();

  /// Parse a single event from its JSON representation.
  ///
  /// The [json] map must have the shape:
  ///   { "type": String, "data": dynamic }
  ///
  /// Returns the appropriate BackendEvent subclass on success, or null if:
  ///   - The "type" field is missing or unrecognised.
  ///   - The "data" field cannot be parsed into the expected model.
  ///   - Any unexpected exception occurs during parsing.
  ///
  /// Returning null (instead of throwing) means the poll loop can safely
  /// skip unknown event types introduced by a newer Rust version without
  /// crashing the older Flutter app.  This supports rolling upgrades where
  /// the backend and frontend may temporarily be at different versions.
  static BackendEvent? fromJson(Map<String, dynamic> json) {
    final type = json['type'] as String?; // The event type discriminator.
    final data = json['data'];            // The event payload (structure varies by type).

    // Safely cast `data` to a Map when the event type expects an object payload.
    // Returns null if `data` is not a Map, which will cause the corresponding
    // event arm to return null (skipping the event) rather than throwing.
    final dataMap = data is Map<String, dynamic> ? data : null;

    try {
      // Dart's `switch` expression (introduced in Dart 3) evaluates to a value.
      // Each arm matches the type string and constructs the right event object.
      return switch (type) {

        // -----------------------------------------------------------------------
        // 'MessageAdded'
        // Fired when a new chat message arrives (from a remote peer) or is
        // successfully sent (from the local user).  The UI should append this
        // message to the conversation thread.
        // -----------------------------------------------------------------------
        'MessageAdded' => dataMap != null
          ? MessageAddedEvent(MessageModel.fromJson(dataMap))
          : null,

        // -----------------------------------------------------------------------
        // 'RoomUpdated'
        // Fired when a room's metadata changes — its name changed, a new message
        // updated the preview snippet, or the unread count changed.
        // The UI should refresh that room's entry in the conversation list.
        // -----------------------------------------------------------------------
        'RoomUpdated' => dataMap != null
          ? RoomUpdatedEvent(RoomSummary.fromJson(dataMap))
          : null,

        // -----------------------------------------------------------------------
        // 'RoomDeleted'
        // Fired when a room is permanently deleted (by this user or by the last
        // remaining member leaving).  The UI should remove the room from the list
        // and close any open conversation thread for that room.
        // The data contains only the room ID string.
        // -----------------------------------------------------------------------
        'RoomDeleted' => dataMap != null && dataMap['roomId'] is String
          ? RoomDeletedEvent(dataMap['roomId'] as String)
          : null,

        // -----------------------------------------------------------------------
        // 'MessageDeleted'
        // Fired when a specific message is deleted.  Both the room ID and message
        // ID are provided so the UI can find and remove the exact message from
        // the displayed thread.
        // -----------------------------------------------------------------------
        'MessageDeleted' => dataMap != null
            && dataMap['roomId'] is String
            && dataMap['messageId'] is String
          ? MessageDeletedEvent(
              roomId: dataMap['roomId'] as String,
              messageId: dataMap['messageId'] as String,
            )
          : null,

        // -----------------------------------------------------------------------
        // 'PeerUpdated'
        // Fired whenever a peer's state changes — they came online, went offline,
        // their display name changed, or their trust level was updated.
        // The UI should refresh that peer's entry in the peer list.
        // -----------------------------------------------------------------------
        'PeerUpdated' => dataMap != null
          ? PeerUpdatedEvent(PeerModel.fromJson(dataMap))
          : null,

        // -----------------------------------------------------------------------
        // 'TransferUpdated'
        // Fired periodically while a file transfer is in progress (progress
        // updates), and also when a transfer completes, fails, or is cancelled.
        // The UI should update the transfer progress bar or status badge.
        // -----------------------------------------------------------------------
        'TransferUpdated' => dataMap != null
          ? TransferUpdatedEvent(FileTransferModel.fromJson(dataMap))
          : null,

        // -----------------------------------------------------------------------
        // 'SettingsUpdated'
        // Fired when any setting changes — transport flags, node mode, etc.
        // This can happen because the user changed a setting on this device, or
        // (in future) because a sync from another device updated them.
        // The UI should reload the settings screen.
        // -----------------------------------------------------------------------
        'SettingsUpdated' => dataMap != null
          ? SettingsUpdatedEvent(SettingsModel.fromJson(dataMap))
          : null,

        // -----------------------------------------------------------------------
        // 'AppConnectorConfigChanged'
        // Fired when the backend-owned App Connector configuration changes.
        // The payload is intentionally left as a generic map because this
        // configuration is still evolving and the UI only needs the current
        // backend-owned fields.
        // -----------------------------------------------------------------------
        'AppConnectorConfigChanged' => dataMap != null
          ? AppConnectorConfigChangedEvent(Map<String, dynamic>.from(dataMap))
          : null,

        // -----------------------------------------------------------------------
        // 'OverlayStatusChanged'
        // Fired when backend-owned Tailscale or ZeroTier state changes.
        // The UI still reloads the full backend snapshot rather than trusting
        // the event delta as canonical state.
        // -----------------------------------------------------------------------
        'OverlayStatusChanged' => dataMap != null
          ? OverlayStatusChangedEvent(Map<String, dynamic>.from(dataMap))
          : null,

        // -----------------------------------------------------------------------
        // 'ActiveRoomChanged'
        // Fired when the currently selected/active room changes.
        // The roomId may be null if no room is now selected (e.g. the user
        // closed all conversations).  The UI should highlight the correct room
        // in the sidebar and show the right conversation thread.
        // -----------------------------------------------------------------------
        'ActiveRoomChanged' => dataMap != null
          ? ActiveRoomChangedEvent(
              dataMap['roomId'] is String ? dataMap['roomId'] as String : null,
            )
          : null,

        // -----------------------------------------------------------------------
        // 'TrustUpdated'
        // Fired when the trust level for a peer changes — either because the
        // local user explicitly attested trust, or because the web-of-trust
        // engine recalculated transitive trust based on new attestations from
        // other peers.
        // The UI should update the trust badge shown next to the peer.
        // -----------------------------------------------------------------------
        'TrustUpdated' => dataMap != null
            && dataMap['peerId'] is String
            && dataMap['trustLevel'] is int
          ? TrustUpdatedEvent(
              peerId: dataMap['peerId'] as String,
              trustLevel: TrustLevel.fromInt(dataMap['trustLevel'] as int),
            )
          : null,

        // -----------------------------------------------------------------------
        // 'PeerAdded'
        // Fired when a new peer is added to the contact store (e.g. via pairing).
        // -----------------------------------------------------------------------
        'PeerAdded' => dataMap != null
          ? PeerAddedEvent(PeerModel.fromJson(dataMap))
          : null,

        // -----------------------------------------------------------------------
        // 'LoSecResponse'
        // Fired when a peer responds to a LoSec negotiation request.
        // -----------------------------------------------------------------------
        'LoSecResponse' => dataMap != null
            && dataMap['peerId'] is String
            && dataMap['sessionId'] is String
          ? LoSecResponseEvent(
              peerId: dataMap['peerId'] as String,
              sessionId: dataMap['sessionId'] as String,
              accepted: dataMap['accepted'] as bool? ?? false,
              rejectionReason: dataMap['rejectionReason'] as String?,
            )
          : null,

        // -----------------------------------------------------------------------
        // 'LoSecRequested'
        // Fired when a remote peer sends us a LoSec negotiation request.
        // -----------------------------------------------------------------------
        'LoSecRequested' => dataMap != null
            && dataMap['peerId'] is String
          ? LoSecRequestedEvent(
              peerId: dataMap['peerId'] as String,
              sessionId: dataMap['sessionId'] as String? ?? '',
              accepted: dataMap['accepted'] as bool? ?? false,
            )
          : null,

        // -----------------------------------------------------------------------
        // 'CallIncoming'
        // Fired when a remote peer initiates a call to us.  The UI should ring
        // and show an incoming-call screen with accept/decline buttons.
        // -----------------------------------------------------------------------
        'CallIncoming' => dataMap != null
            && dataMap['callId'] is String
            && dataMap['peerId'] is String
          ? CallIncomingEvent(
              callId: dataMap['callId'] as String,
              peerId: dataMap['peerId'] as String,
              isVideo: dataMap['isVideo'] as bool? ?? false,
            )
          : null,

        // -----------------------------------------------------------------------
        // 'CallAnswered'
        // Fired when the remote peer accepts our outgoing call offer.
        // The UI should transition from "ringing" to "in call".
        // -----------------------------------------------------------------------
        'CallAnswered' => dataMap != null && dataMap['callId'] is String
          ? CallAnsweredEvent(
              callId: dataMap['callId'] as String,
              audioCodec: dataMap['audioCodec'] as String? ?? 'Opus',
            )
          : null,

        // -----------------------------------------------------------------------
        // 'CallHungUp'
        // Fired when the remote peer ends or declines the call.
        // The UI should return to idle state.
        // -----------------------------------------------------------------------
        'CallHungUp' => dataMap != null && dataMap['callId'] is String
          ? CallHungUpEvent(
              callId: dataMap['callId'] as String,
              reason: dataMap['reason'] as String? ?? 'Normal',
            )
          : null,

        // -----------------------------------------------------------------------
        // 'MeshPacketDelivered'
        // Fired when a mesh-routed packet (non-message kind) is delivered to
        // this node after multi-hop forwarding.  Used by the Network screen to
        // display live mesh traffic stats.
        // -----------------------------------------------------------------------
        'MeshPacketDelivered' => dataMap != null
            && dataMap['source'] is String
          ? MeshPacketDeliveredEvent(
              source: dataMap['source'] as String,
              kind: dataMap['kind'] as String? ?? 'Unknown',
              size: (dataMap['size'] as num?)?.toInt() ?? 0,
            )
          : null,

        // -----------------------------------------------------------------------
        // 'MessageStatusUpdated'
        // Fired when a delivery receipt arrives from the recipient (§7.3).
        // The UI should update the message's delivery indicator from "sent"
        // to "delivered" (e.g. single-tick → double-tick).
        // -----------------------------------------------------------------------
        'MessageStatusUpdated' => dataMap != null
            && dataMap['msgId'] is String
            && dataMap['roomId'] is String
          ? MessageStatusUpdatedEvent(
              msgId: dataMap['msgId'] as String,
              roomId: dataMap['roomId'] as String,
              deliveryStatus: dataMap['deliveryStatus'] as String? ?? 'sent',
            )
          : null,

        // -----------------------------------------------------------------------
        // 'TypingIndicator'
        // Fired when a remote peer starts or stops typing in a shared room.
        // Also fired locally when the user starts/stops typing (peerId is null
        // in that case — the UI can use this to suppress echo).
        // -----------------------------------------------------------------------
        'TypingIndicator' => dataMap != null && dataMap['roomId'] is String
          ? TypingIndicatorEvent(
              roomId: dataMap['roomId'] as String,
              peerId: dataMap['peerId'] as String?,
              active: dataMap['active'] as bool? ?? false,
            )
          : null,

        // -----------------------------------------------------------------------
        // 'LocalNotification'
        // Fired when the notification dispatcher delivers a coalesced notification
        // (§14).  The UI should display a system notification or in-app banner.
        // -----------------------------------------------------------------------
        'LocalNotification' => dataMap != null && dataMap['title'] is String
          ? LocalNotificationEvent(
              title: dataMap['title'] as String,
              body: dataMap['body'] as String?,
              conversationId: dataMap['conversationId'] as String?,
              eventCount: (dataMap['eventCount'] as num?)?.toInt() ?? 1,
              priority: dataMap['priority'] as String? ?? 'Normal',
              tier: dataMap['tier'] as String? ?? 'MeshTunnel',
            )
          : null,

        // -----------------------------------------------------------------------
        // 'ReactionAdded'
        // Fired when a peer (or the local user) adds an emoji reaction to a
        // message (§10.1.2).  The UI should display the emoji on the message row.
        // [peerId] is null when the reaction is the local user's own action.
        // -----------------------------------------------------------------------
        'ReactionAdded' => dataMap != null
            && dataMap['roomId'] is String
            && dataMap['msgId'] is String
            && dataMap['emoji'] is String
          ? ReactionAddedEvent(
              roomId: dataMap['roomId'] as String,
              msgId: dataMap['msgId'] as String,
              peerId: dataMap['peerId'] as String?,
              emoji: dataMap['emoji'] as String,
            )
          : null,

        // -----------------------------------------------------------------------
        // Catch-all: any event type we don't recognise is silently dropped.
        // This makes the app forward-compatible with new event types added in
        // newer versions of the Rust backend.
        // -----------------------------------------------------------------------
        _ => null,
      };
    } catch (_) {
      // If parsing fails for any reason (wrong field type, missing key, etc.),
      // return null rather than propagating the exception.  The poll loop will
      // simply skip this event, and the UI remains consistent.
      return null;
    }
  }
}

// =============================================================================
// Concrete event types
//
// Each `final class` below is one specific event.  The `final` keyword means
// this class cannot itself be extended further — the hierarchy is exactly two
// levels: BackendEvent → concrete event type.
//
// Fields are `final` (immutable) because events are facts about the past —
// they should never change after being created.
// =============================================================================

/// A new chat message has been received or sent.
/// [message] is the complete message object including sender, text, timestamp.
final class MessageAddedEvent extends BackendEvent {
  const MessageAddedEvent(this.message);
  final MessageModel message;
}

/// A room's metadata (name, last message preview, unread count) has changed.
/// [room] is the updated room summary.
final class RoomUpdatedEvent extends BackendEvent {
  const RoomUpdatedEvent(this.room);
  final RoomSummary room;
}

/// A room has been permanently deleted.
/// [roomId] identifies which room to remove from the UI.
final class RoomDeletedEvent extends BackendEvent {
  const RoomDeletedEvent(this.roomId);
  final String roomId;
}

/// A specific message within a room has been deleted.
/// Both [roomId] and [messageId] are needed to find the message in the UI's
/// data structures.
final class MessageDeletedEvent extends BackendEvent {
  const MessageDeletedEvent({required this.roomId, required this.messageId});
  final String roomId;
  final String messageId;
}

/// A peer's status or metadata has changed.
/// [peer] is the complete updated peer record.
final class PeerUpdatedEvent extends BackendEvent {
  const PeerUpdatedEvent(this.peer);
  final PeerModel peer;
}

/// A file transfer's state has changed — new progress, completion, or failure.
/// [transfer] is the complete updated transfer record including bytes transferred.
final class TransferUpdatedEvent extends BackendEvent {
  const TransferUpdatedEvent(this.transfer);
  final FileTransferModel transfer;
}

/// The node's configuration settings have changed.
/// [settings] is the full updated settings object.
final class SettingsUpdatedEvent extends BackendEvent {
  const SettingsUpdatedEvent(this.settings);
  final SettingsModel settings;
}

/// The backend-owned App Connector configuration has changed.
/// [config] contains the latest mode and app list from Rust.
final class AppConnectorConfigChangedEvent extends BackendEvent {
  const AppConnectorConfigChangedEvent(this.config);
  final Map<String, dynamic> config;
}

/// Tailscale or ZeroTier state changed in the backend.
/// [status] contains a lightweight delta for the changed overlay.
final class OverlayStatusChangedEvent extends BackendEvent {
  const OverlayStatusChangedEvent(this.status);
  final Map<String, dynamic> status;
}

/// The currently active (selected) room has changed.
/// [roomId] is null if no room is currently selected.
final class ActiveRoomChangedEvent extends BackendEvent {
  const ActiveRoomChangedEvent(this.roomId);
  final String? roomId; // nullable — absence means "no room selected"
}

/// The trust level for a peer has been updated by the web-of-trust engine.
/// [peerId] identifies the peer.
/// [trustLevel] is the new computed trust level (see TrustLevel enum).
final class TrustUpdatedEvent extends BackendEvent {
  const TrustUpdatedEvent({required this.peerId, required this.trustLevel});
  final String peerId;
  final TrustLevel trustLevel;
}

/// A new peer has been added to the contact store (e.g. via QR pairing).
final class PeerAddedEvent extends BackendEvent {
  const PeerAddedEvent(this.peer);
  final PeerModel peer;
}

/// A peer responded to our LoSec negotiation request (§6.9.6).
/// [accepted] indicates whether they agreed to LoSec mode.
final class LoSecResponseEvent extends BackendEvent {
  const LoSecResponseEvent({
    required this.peerId,
    required this.sessionId,
    required this.accepted,
    this.rejectionReason,
  });
  final String peerId;
  final String sessionId;
  final bool accepted;
  final String? rejectionReason;
}

/// A remote peer has sent us a LoSec negotiation request (§6.9.6).
/// [accepted] indicates whether our local policy accepted it.
final class LoSecRequestedEvent extends BackendEvent {
  const LoSecRequestedEvent({
    required this.peerId,
    required this.sessionId,
    required this.accepted,
  });
  final String peerId;
  final String sessionId;
  final bool accepted;
}

/// A remote peer is calling us (§10.1.6).
/// [isVideo] — true if the offer includes a video track.
final class CallIncomingEvent extends BackendEvent {
  const CallIncomingEvent({
    required this.callId,
    required this.peerId,
    required this.isVideo,
  });
  final String callId;
  final String peerId;
  final bool isVideo;
}

/// The remote peer accepted our outgoing call offer (§10.1.6).
final class CallAnsweredEvent extends BackendEvent {
  const CallAnsweredEvent({required this.callId, required this.audioCodec});
  final String callId;
  final String audioCodec;
}

/// The call ended — either the remote peer hung up or declined (§10.1.6).
final class CallHungUpEvent extends BackendEvent {
  const CallHungUpEvent({required this.callId, required this.reason});
  final String callId;
  final String reason;
}

/// A non-message mesh packet was delivered to this node after multi-hop routing.
/// Used by the Network screen for live mesh traffic statistics.
/// [source] is the hex-encoded originating node address.
/// [kind] is the packet kind (Keepalive, Data, CallSignal, etc.).
/// [size] is the payload size in bytes.
final class MeshPacketDeliveredEvent extends BackendEvent {
  const MeshPacketDeliveredEvent({
    required this.source,
    required this.kind,
    required this.size,
  });
  final String source;
  final String kind;
  final int size;
}

/// A delivery receipt was received from the message recipient (§7.3).
/// [msgId] identifies the acknowledged message.
/// [roomId] identifies the room it belongs to.
/// [deliveryStatus] is the new status string — currently always "delivered".
final class MessageStatusUpdatedEvent extends BackendEvent {
  const MessageStatusUpdatedEvent({
    required this.msgId,
    required this.roomId,
    required this.deliveryStatus,
  });
  final String msgId;
  final String roomId;
  final String deliveryStatus;
}

/// A peer started or stopped typing in a shared room (§10.2.1).
/// [roomId] identifies the conversation room.
/// [peerId] is the hex-encoded peer ID of the typist, or null when this event
/// is fired for the local user's own typing state.
/// [active] is true while the peer is typing, false when they stop.
final class TypingIndicatorEvent extends BackendEvent {
  const TypingIndicatorEvent({
    required this.roomId,
    required this.peerId,
    required this.active,
  });
  final String roomId;
  final String? peerId;
  final bool active;
}

/// A coalesced notification was dispatched by the notification system (§14).
/// [title] is the notification heading.
/// [body] is the optional detail text (omitted for privacy on lower tiers).
/// [conversationId] is the hex room/group ID this notification relates to, or null.
/// [eventCount] is how many underlying events were coalesced into this notification.
/// [priority] and [tier] are the string representations of the backend enums.
final class LocalNotificationEvent extends BackendEvent {
  const LocalNotificationEvent({
    required this.title,
    required this.body,
    required this.conversationId,
    required this.eventCount,
    required this.priority,
    required this.tier,
  });
  final String title;
  final String? body;
  final String? conversationId;
  final int eventCount;
  final String priority;
  final String tier;
}

/// A peer (or the local user) added an emoji reaction to a message (§10.1.2).
/// [roomId] identifies the conversation room.
/// [msgId] identifies the message being reacted to.
/// [peerId] is the hex-encoded peer ID of the reactor, or null for the local user.
/// [emoji] is the emoji string (e.g. "👍").
final class ReactionAddedEvent extends BackendEvent {
  const ReactionAddedEvent({
    required this.roomId,
    required this.msgId,
    required this.peerId,
    required this.emoji,
  });
  final String roomId;
  final String msgId;
  final String? peerId;
  final String emoji;
}
