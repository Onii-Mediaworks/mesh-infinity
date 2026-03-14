// messaging_state.dart
//
// This file implements MessagingState — the single class that owns all
// chat data visible in the messaging feature.
//
// WHAT problem does this class solve?
// ------------------------------------
// The messaging feature has multiple widgets that need the same data:
//   - ConversationListScreen needs the list of all rooms.
//   - ThreadScreen needs the messages for the currently open room.
//   - The app badge / unread count needs to know about new messages.
//
// If each of those widgets fetched data independently they would:
//   (a) Make duplicate calls to the backend.
//   (b) Easily drift out of sync (e.g. a new message appears in the list but
//       not the thread, or vice versa).
//
// MessagingState is the single source of truth.  All widgets read from it;
// only MessagingState writes to itself.  When the data changes, every widget
// watching MessagingState automatically rebuilds.
//
// HOW does the UI learn about changes?
// --------------------------------------
// Flutter's Provider pattern uses ChangeNotifier:
//   1. MessagingState extends ChangeNotifier.
//   2. Widgets call context.watch<MessagingState>() to subscribe.
//   3. Whenever MessagingState calls notifyListeners(), Flutter rebuilds
//      every widget that called context.watch<MessagingState>().
//
// WHY polling instead of true push events?
// -----------------------------------------
// The Rust backend runs in a separate native thread (or isolate).  True push
// would require a real-time cross-thread channel.  Instead we use the
// EventBus: a background Dart isolate polls the backend every ~200 ms for
// queued events and pushes them into a Stream.  MessagingState subscribes to
// that Stream and updates itself when events arrive.  From the UI's perspective
// this is indistinguishable from push — latency is at most 200 ms, which is
// imperceptible for a messaging app.

import 'dart:async';
// dart:async provides StreamSubscription — the handle to a stream listener
// so we can cancel it later to avoid memory leaks.
//
// A StreamSubscription<T> is returned by stream.listen(callback).  It is
// essentially a "receipt" for the subscription.  Calling sub.cancel() removes
// the callback from the stream so no further events are delivered.  Always
// cancel in dispose() to prevent the callback (which references `this`) from
// keeping the object alive in memory after it is logically destroyed.

import 'package:flutter/foundation.dart';
// flutter/foundation.dart provides ChangeNotifier.
// It is deliberately a "no-UI" import — no widgets, no painting code.
// This keeps the state class light and testable without a full Flutter runtime.

import '../../backend/backend_bridge.dart';
// BackendBridge wraps all FFI calls into Rust.
// Every call that touches actual data (rooms, messages) goes through here.
import '../../backend/event_bus.dart';
// EventBus is the background-isolate poller that converts backend events
// into a Dart Stream.  See event_bus.dart for a detailed explanation of
// how the background isolate works.
import '../../backend/event_models.dart';
// Typed event classes: MessageAddedEvent, RoomUpdatedEvent, etc.
// These are Dart sealed classes — exhaustive pattern matching is possible
// in switch statements (the compiler warns if a case is missing).
import '../../backend/models/message_models.dart';
// MessageModel — a typed Dart object representing one chat message.
// Fields: id, roomId, sender, text, timestamp, isOutgoing.
import '../../backend/models/room_models.dart';
// RoomSummary — a typed Dart object representing one room (conversation).
// Fields: id, name, lastMessage, unreadCount, timestamp.

// ---------------------------------------------------------------------------
// MessagingState
// ---------------------------------------------------------------------------

/// MessagingState holds all data for the messaging feature and notifies the
/// UI whenever that data changes.
///
/// LIFECYCLE
/// ---------
/// Created once (in app.dart via Provider) when the main shell mounts.
/// Disposed (via dispose()) when the app closes.
///
/// WHAT is a ChangeNotifier?
/// -------------------------
/// ChangeNotifier is a Flutter base class that provides:
///   - addListener()   — used by the Provider system to register rebuild callbacks.
///   - removeListener() — unregisters them (done automatically by Provider).
///   - notifyListeners() — fires all registered callbacks, triggering rebuilds.
///
/// We never call addListener/removeListener directly.  Provider does it for us
/// when widgets call context.watch<MessagingState>().
class MessagingState extends ChangeNotifier {
  /// [bridge] is the FFI gateway to the Rust backend.  It is passed in from
  /// outside (dependency injection) so that tests can provide a fake bridge.
  ///
  /// The constructor body runs immediately when MessagingState is created
  /// (which happens in app.dart when the Provider is set up).
  ///
  /// Dependency injection means: rather than creating BackendBridge ourselves
  /// inside this constructor, we receive it as a parameter.  The benefit is
  /// that in unit tests, a fake or mock BackendBridge can be injected instead
  /// of the real one, so the test can run without actual Rust FFI code.
  MessagingState(this._bridge) {
    // Subscribe to the event stream immediately.  _onEvent() will be called
    // for every BackendEvent that the background isolate emits.
    //
    // EventBus.instance is a singleton — there is exactly one EventBus for
    // the whole app.  .stream is a broadcast Stream that any number of
    // listeners can subscribe to simultaneously.  .listen(callback) registers
    // our callback and returns a StreamSubscription that we store in _sub.
    _sub = EventBus.instance.stream.listen(_onEvent);

    // Perform an initial data load so the UI has something to show right away,
    // rather than waiting for the first event to arrive.
    //
    // loadRooms() is an async method, but we do NOT await it here.  That's
    // intentional: the constructor cannot be async in Dart, so we fire the
    // load and let it complete in the background.  The UI starts with empty
    // lists and rebuilds when loadRooms() calls notifyListeners() after the
    // data arrives.
    loadRooms();
  }

  // -------------------------------------------------------------------------
  // Private fields — the actual data
  // -------------------------------------------------------------------------

  /// The FFI bridge — our path to Rust.
  final BackendBridge _bridge;

  /// The subscription handle returned when we listened to EventBus.instance.stream.
  /// We store it so we can cancel it in dispose() and stop receiving events
  /// after the state object is removed from memory.
  StreamSubscription<BackendEvent>? _sub;

  /// The list of all rooms (conversations) the local node is a member of.
  /// Displayed in ConversationListScreen.  Starts empty; populated by loadRooms().
  /// `const []` is an immutable empty list — safe as a default value.
  List<RoomSummary> _rooms = const [];

  /// The messages belonging to the currently open room.
  /// Empty when no room is selected or while loading.
  List<MessageModel> _messages = const [];

  /// The ID of the room the user is currently reading.
  /// Null means the user has not opened any conversation yet.
  /// Used to decide whether incoming messages should be appended to _messages
  /// (if they belong to this room) or just update the room's preview text.
  String? _activeRoomId;

  /// True between the moment we call fetchMessages() and the moment we receive
  /// results.  Used to show a loading indicator in ThreadScreen.
  bool _loadingMessages = false;

  // -------------------------------------------------------------------------
  // Public getters — read-only access for the UI
  // -------------------------------------------------------------------------
  // Dart getters behave like computed read-only properties.  External code
  // (widgets) can read these but cannot write to the underlying fields.
  // All mutations must go through the methods below so that notifyListeners()
  // is always called and the UI stays consistent.

  /// All rooms the user belongs to, in whatever order the backend returns them.
  List<RoomSummary> get rooms => _rooms;

  /// Messages for the currently open room, oldest first.
  List<MessageModel> get messages => _messages;

  /// The ID of the room currently displayed in ThreadScreen, or null.
  String? get activeRoomId => _activeRoomId;

  /// True while messages are being fetched from the backend.
  bool get loadingMessages => _loadingMessages;

  // -------------------------------------------------------------------------
  // Load / refresh operations
  // -------------------------------------------------------------------------
  //
  // All load methods follow this pattern:
  //   1. Call the bridge (synchronous FFI → Rust → JSON → Dart objects).
  //   2. Store results in private fields.
  //   3. Call notifyListeners() to trigger widget rebuilds.
  //
  // They return Future<void> so callers can await them if needed (e.g. a
  // pull-to-refresh handler can await loadRooms() and then hide the spinner).

  /// Fetches the room list from the backend and notifies listeners.
  ///
  /// Marked async even though the bridge calls are synchronous today, so that
  /// callers can await it and future implementations can make it truly async
  /// (e.g. if the backend gains a network-round-trip step).
  ///
  /// This is called:
  ///   - Once in the constructor (initial load on app start).
  ///   - After createRoom() or deleteRoom() to keep the list up-to-date.
  ///   - From ConversationListScreen's pull-to-refresh handler.
  Future<void> loadRooms() async {
    // fetchRooms() calls into Rust via FFI and returns a List<RoomSummary>
    // decoded from JSON.
    //
    // The call path looks like:
    //   Dart: _bridge.fetchRooms()
    //     → native: mi_fetch_rooms(ctx)     (C FFI boundary)
    //       → Rust: service.fetch_rooms()   (returns JSON bytes)
    //     → native: returns pointer to JSON string
    //   Dart: parses JSON → List<RoomSummary>
    final rooms = _bridge.fetchRooms();

    // activeRoomId() asks the backend which room is currently "focused"
    // (relevant after restoring state from disk on app restart).
    final activeId = _bridge.activeRoomId();

    _rooms = rooms;
    _activeRoomId = activeId;

    // Tell every watching widget to rebuild with the new data.
    // At this point _rooms has new content, so ConversationListScreen will
    // render the updated list on its next build() call.
    notifyListeners();
  }

  /// Fetches the messages for [roomId] and stores them in _messages.
  ///
  /// Sets _loadingMessages = true before the fetch and false after, so
  /// ThreadScreen can show a spinner while waiting.
  ///
  /// The two-step rebuild (spinner → messages) works because notifyListeners()
  /// schedules a rebuild asynchronously — it does NOT rebuild inline.  So:
  ///   1. We set _loadingMessages = true and call notifyListeners().
  ///      Flutter queues a rebuild.
  ///   2. We do the synchronous fetch (very fast in practice).
  ///   3. We set _loadingMessages = false and call notifyListeners() again.
  ///      Flutter queues another rebuild.
  ///   4. The two rebuilds happen in order on the next frame(s).
  ///
  /// In practice the fetch is so fast that the spinner may never be visible,
  /// but it is correct behaviour and important for future async implementations.
  Future<void> loadMessages(String roomId) async {
    _loadingMessages = true;
    notifyListeners(); // Rebuild now so the spinner appears immediately.

    final msgs = _bridge.fetchMessages(roomId);
    _messages = msgs;

    _loadingMessages = false;
    notifyListeners(); // Rebuild again to replace the spinner with actual messages.
  }

  // -------------------------------------------------------------------------
  // User-initiated actions
  // -------------------------------------------------------------------------

  /// Opens a room — tells the backend which room is active, then loads its
  /// messages so they appear in ThreadScreen.
  ///
  /// The two-step approach (notify backend + load messages) is intentional:
  ///   1. The backend needs to know the active room to mark messages as read.
  ///   2. We then pull the messages so the UI can display them.
  Future<void> selectRoom(String roomId) async {
    _bridge.selectRoom(roomId); // Tell Rust "this is the focused room".
    _activeRoomId = roomId;
    notifyListeners(); // Update ConversationListScreen's highlighted row.
    await loadMessages(roomId); // Load and display messages.
  }

  /// Creates a new named room.  Returns the new room's ID on success, or null
  /// on failure.
  ///
  /// After creation we reload the room list so the new room appears in
  /// ConversationListScreen without a manual refresh.
  Future<String?> createRoom(String name) async {
    final id = _bridge.createRoom(name);
    if (id != null) await loadRooms();
    return id;
  }

  /// Deletes a room by ID.  Returns true if the backend confirmed deletion.
  ///
  /// If the deleted room was the currently open one, we clear _activeRoomId
  /// and _messages so ThreadScreen is not left showing stale data from a room
  /// that no longer exists.
  Future<bool> deleteRoom(String roomId) async {
    final ok = _bridge.deleteRoom(roomId);
    if (ok) {
      if (_activeRoomId == roomId) {
        // The open room was deleted — reset the message view.
        _activeRoomId = null;
        _messages = const [];
      }
      await loadRooms(); // Refresh the room list.
    }
    return ok;
  }

  /// Sends [text] as a message in the currently active room.
  /// Returns false if no room is selected (guard against accidental calls).
  ///
  /// Note: we do NOT manually append the message here.  Instead we rely on
  /// the backend to emit a MessageAddedEvent, which _onEvent() will receive
  /// and use to update _messages.  This prevents duplicates and ensures the
  /// message ID and server-side timestamp come from Rust.
  ///
  /// "Event-driven confirmation" vs "optimistic append":
  /// ----------------------------------------------------
  /// An alternative design would be to immediately append the message to
  /// _messages ("optimistic update") for instant feedback, then let the
  /// backend confirm.  We chose NOT to do that because:
  ///   - The message ID must come from Rust (it encodes cryptographic info).
  ///   - The timestamp must come from Rust (consistent with other devices).
  ///   - Duplicates are hard to deduplicate if both optimistic and event
  ///     paths fire at the same time.
  /// The ~200 ms EventBus latency is acceptable for a messaging app.
  bool sendMessage(String text) {
    if (_activeRoomId == null) return false; // No room open — nothing to send.
    return _bridge.sendMessage(_activeRoomId, text);
  }

  /// Removes a message locally without waiting for a backend confirmation event.
  ///
  /// The UI updates immediately (optimistic update) by filtering the message
  /// out of _messages.  If the backend call fails in the background, a
  /// subsequent loadMessages() call will restore the correct state.
  ///
  /// WHY use an optimistic update here but NOT in sendMessage()?
  /// ------------------------------------------------------------
  /// Deletion is a UI-critical action: the user expects the message to vanish
  /// the instant they tap "Delete".  A 200 ms delay would feel like the app
  /// ignored the tap.  The rollback cost (showing the message again if the
  /// backend fails) is low and very rare.
  ///
  /// Sending is different: the message ID and timestamp are provided by Rust,
  /// so we cannot construct a complete MessageModel locally to append.
  bool deleteMessage(String messageId) {
    final ok = _bridge.deleteMessage(messageId);
    if (ok) {
      // Filter out the deleted message from the in-memory list.
      // `where` returns a lazy Iterable of elements that satisfy the predicate.
      // `.toList()` materialises it into a new List<MessageModel>.
      // We REPLACE _messages (new list object) rather than mutating it
      // in-place, so notifyListeners triggers a proper rebuild diff.
      _messages = _messages.where((m) => m.id != messageId).toList();
      notifyListeners();
    }
    return ok;
  }

  // -------------------------------------------------------------------------
  // Event handling — reacting to backend-pushed changes
  // -------------------------------------------------------------------------

  /// Processes events emitted by the background EventBus isolate.
  ///
  /// The EventBus polls the Rust backend ~5 times per second.  When the
  /// backend queues an event (e.g. "peer sent a message"), it appears here
  /// as a typed BackendEvent subclass.
  ///
  /// WHY use a stream and events instead of polling from the UI?
  /// -----------------------------------------------------------
  /// If widgets polled the backend directly they would each need their own
  /// timer, their own error handling, and their own notion of "what changed".
  /// The EventBus centralises that concern.  MessagingState is the single
  /// subscriber for messaging-related events, and it translates them into
  /// simple data mutations + notifyListeners() calls.
  void _onEvent(BackendEvent event) {
    // PATTERN MATCHING ON SEALED TYPES
    // ---------------------------------
    // BackendEvent is a Dart sealed class (defined in event_models.dart).
    // A sealed class is like a closed enum: a fixed set of subtypes, all
    // known at compile time.  Dart's switch can exhaustively match all
    // subtypes, and the compiler warns if a case is missing.
    //
    // The `case SomeEvent(:final field)` syntax is Dart 3's "destructuring
    // pattern".  It matches if the event IS a SomeEvent, AND simultaneously
    // extracts the named field into a local variable.  For example:
    //   case MessageAddedEvent(:final message)
    // is equivalent to:
    //   if (event is MessageAddedEvent) {
    //     final message = event.message;
    //     ...
    //   }
    switch (event) {
      // A new message arrived (from a peer or from ourselves on another
      // device via a relay).
      case MessageAddedEvent(:final message):
        if (message.roomId == _activeRoomId) {
          // The message belongs to the open room — append it to the thread.
          // We create a NEW list (spread operator `...`) rather than mutating
          // the existing one.  Dart's const lists are immutable; creating a
          // new list also makes diffing easier for the rendering layer.
          //
          // The spread operator `...` unpacks one list into another:
          //   [..._messages, message]
          // creates a new List that contains all elements of _messages
          // followed by the new message at the end.
          _messages = [..._messages, message];
          notifyListeners();
        }
        // Regardless of which room the message is for, update the room's
        // preview line in the conversation list (shows the last message snippet).
        // This handles the case where the message arrived in a background room
        // (not the currently open one) — we still want the list to show the
        // preview text updating.
        _updateRoomPreview(message.roomId, message.text);

      // Room metadata was updated (e.g. name change, unread count cleared).
      case RoomUpdatedEvent(:final room):
        // Replace the matching room in the list with the updated version.
        //
        // This uses a Dart "collection for" with an "if" inside it — a
        // compact way to build a new list where one element is conditionally
        // replaced.  It reads:
        //   "For each room r in _rooms, if r.id matches, use the new `room`;
        //   otherwise keep the old r."
        _rooms = [
          for (final r in _rooms)
            if (r.id == room.id) room else r, // Swap in the updated room.
        ];
        // Guard: if the backend sent an update for a room we don't have yet
        // (possible race condition on first launch), append it.
        // _rooms.any() returns true if any element satisfies the predicate.
        if (!_rooms.any((r) => r.id == room.id)) {
          _rooms = [..._rooms, room];
        }
        notifyListeners();

      // A room was deleted (by us or by a room admin on another device).
      case RoomDeletedEvent(:final roomId):
        // Remove the room from the list.
        _rooms = _rooms.where((r) => r.id != roomId).toList();
        if (_activeRoomId == roomId) {
          // The open room was deleted remotely — clear the thread view.
          // Setting _activeRoomId = null will cause the detail pane to show
          // the "Select a conversation" placeholder on the next rebuild.
          _activeRoomId = null;
          _messages = const [];
        }
        notifyListeners();

      // A specific message was deleted (e.g. user deleted from another device).
      case MessageDeletedEvent(:final roomId, :final messageId):
        if (roomId == _activeRoomId) {
          // Only update _messages if the deletion is in the currently open room.
          // Messages in other rooms are not in _messages anyway.
          _messages = _messages.where((m) => m.id != messageId).toList();
          notifyListeners();
        }

      // The backend changed its notion of which room is "active" (e.g. the
      // app was restored from a saved session).
      case ActiveRoomChangedEvent(:final roomId):
        _activeRoomId = roomId;
        // Load the messages for the newly active room.
        // `if (roomId != null)` is necessary because roomId is nullable —
        // a null value means "no active room", in which case we don't load.
        if (roomId != null) loadMessages(roomId); // Load the new room's messages.
        notifyListeners();

      // Ignore all other event types (peer changes, file transfers, etc.).
      // MessagingState only cares about messaging events; other ChangeNotifiers
      // (PeersState, FilesState, NetworkState) handle their own events.
      default:
        break;
    }
  }

  /// Updates the preview text (last-message snippet) for a room in _rooms.
  ///
  /// ConversationListScreen shows the first line of the latest message beneath
  /// each room name.  This helper finds the right room and replaces it with a
  /// copy that has the updated lastMessage field.
  ///
  /// WHY create a new list instead of mutating in-place?
  /// ----------------------------------------------------
  /// _rooms is typed as List<RoomSummary>.  Mutating a single element in-place
  /// would NOT trigger notifyListeners() to produce a meaningful diff — the
  /// reference to _rooms itself would be unchanged and some optimisations in
  /// the Flutter rebuild system could skip the update.  By replacing _rooms
  /// with a new list we guarantee that listeners see a change.
  void _updateRoomPreview(String roomId, String preview) {
    _rooms = [
      for (final r in _rooms)
        // copyWith() returns a new RoomSummary with only lastMessage changed;
        // all other fields (id, name, unreadCount, etc.) are preserved.
        if (r.id == roomId) r.copyWith(lastMessage: preview) else r,
    ];
    notifyListeners();
  }

  // -------------------------------------------------------------------------
  // Cleanup
  // -------------------------------------------------------------------------

  @override
  void dispose() {
    // Cancel the EventBus subscription so we stop receiving events after
    // this state object is removed from the tree.  Without this cancellation
    // the closure inside listen() would retain a reference to this object and
    // prevent garbage collection (a memory leak).
    _sub?.cancel();
    // The `?.` (null-safe call) means: only call cancel() if _sub is not null.

    super.dispose(); // Always call super.dispose() so ChangeNotifier can clean up.
  }
}
