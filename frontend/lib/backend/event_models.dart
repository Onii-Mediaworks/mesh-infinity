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
        'MessageAdded' => MessageAddedEvent(
          MessageModel.fromJson(data as Map<String, dynamic>),
        ),

        // -----------------------------------------------------------------------
        // 'RoomUpdated'
        // Fired when a room's metadata changes — its name changed, a new message
        // updated the preview snippet, or the unread count changed.
        // The UI should refresh that room's entry in the conversation list.
        // -----------------------------------------------------------------------
        'RoomUpdated' => RoomUpdatedEvent(
          RoomSummary.fromJson(data as Map<String, dynamic>),
        ),

        // -----------------------------------------------------------------------
        // 'RoomDeleted'
        // Fired when a room is permanently deleted (by this user or by the last
        // remaining member leaving).  The UI should remove the room from the list
        // and close any open conversation thread for that room.
        // The data contains only the room ID string.
        // -----------------------------------------------------------------------
        'RoomDeleted' => RoomDeletedEvent(data['roomId'] as String),

        // -----------------------------------------------------------------------
        // 'MessageDeleted'
        // Fired when a specific message is deleted.  Both the room ID and message
        // ID are provided so the UI can find and remove the exact message from
        // the displayed thread.
        // -----------------------------------------------------------------------
        'MessageDeleted' => MessageDeletedEvent(
          roomId: data['roomId'] as String,
          messageId: data['messageId'] as String,
        ),

        // -----------------------------------------------------------------------
        // 'PeerUpdated'
        // Fired whenever a peer's state changes — they came online, went offline,
        // their display name changed, or their trust level was updated.
        // The UI should refresh that peer's entry in the peer list.
        // -----------------------------------------------------------------------
        'PeerUpdated' => PeerUpdatedEvent(
          PeerModel.fromJson(data as Map<String, dynamic>),
        ),

        // -----------------------------------------------------------------------
        // 'TransferUpdated'
        // Fired periodically while a file transfer is in progress (progress
        // updates), and also when a transfer completes, fails, or is cancelled.
        // The UI should update the transfer progress bar or status badge.
        // -----------------------------------------------------------------------
        'TransferUpdated' => TransferUpdatedEvent(
          FileTransferModel.fromJson(data as Map<String, dynamic>),
        ),

        // -----------------------------------------------------------------------
        // 'SettingsUpdated'
        // Fired when any setting changes — transport flags, node mode, etc.
        // This can happen because the user changed a setting on this device, or
        // (in future) because a sync from another device updated them.
        // The UI should reload the settings screen.
        // -----------------------------------------------------------------------
        'SettingsUpdated' => SettingsUpdatedEvent(
          SettingsModel.fromJson(data as Map<String, dynamic>),
        ),

        // -----------------------------------------------------------------------
        // 'ActiveRoomChanged'
        // Fired when the currently selected/active room changes.
        // The roomId may be null if no room is now selected (e.g. the user
        // closed all conversations).  The UI should highlight the correct room
        // in the sidebar and show the right conversation thread.
        // -----------------------------------------------------------------------
        'ActiveRoomChanged' => ActiveRoomChangedEvent(
          data['roomId'] as String?, // nullable — no room may be active
        ),

        // -----------------------------------------------------------------------
        // 'TrustUpdated'
        // Fired when the trust level for a peer changes — either because the
        // local user explicitly attested trust, or because the web-of-trust
        // engine recalculated transitive trust based on new attestations from
        // other peers.
        // The UI should update the trust badge shown next to the peer.
        // -----------------------------------------------------------------------
        'TrustUpdated' => TrustUpdatedEvent(
          peerId: data['peerId'] as String,
          trustLevel: TrustLevel.fromInt(data['trustLevel'] as int),
        ),

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
