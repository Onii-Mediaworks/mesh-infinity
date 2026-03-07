import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/message_models.dart';
import '../../backend/models/room_models.dart';

class MessagingState extends ChangeNotifier {
  MessagingState(this._bridge) {
    _sub = EventBus.instance.stream.listen(_onEvent);
    loadRooms();
  }

  final BackendBridge _bridge;
  StreamSubscription<BackendEvent>? _sub;

  List<RoomSummary> _rooms = const [];
  List<MessageModel> _messages = const [];
  String? _activeRoomId;
  bool _loadingMessages = false;

  List<RoomSummary> get rooms => _rooms;
  List<MessageModel> get messages => _messages;
  String? get activeRoomId => _activeRoomId;
  bool get loadingMessages => _loadingMessages;

  // ---------------------------------------------------------------------------
  // Load / refresh
  // ---------------------------------------------------------------------------

  Future<void> loadRooms() async {
    final rooms = _bridge.fetchRooms();
    final activeId = _bridge.activeRoomId();
    _rooms = rooms;
    _activeRoomId = activeId;
    notifyListeners();
  }

  Future<void> loadMessages(String roomId) async {
    _loadingMessages = true;
    notifyListeners();
    final msgs = _bridge.fetchMessages(roomId);
    _messages = msgs;
    _loadingMessages = false;
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  Future<void> selectRoom(String roomId) async {
    _bridge.selectRoom(roomId);
    _activeRoomId = roomId;
    notifyListeners();
    await loadMessages(roomId);
  }

  Future<String?> createRoom(String name) async {
    final id = _bridge.createRoom(name);
    if (id != null) await loadRooms();
    return id;
  }

  Future<bool> deleteRoom(String roomId) async {
    final ok = _bridge.deleteRoom(roomId);
    if (ok) {
      if (_activeRoomId == roomId) {
        _activeRoomId = null;
        _messages = const [];
      }
      await loadRooms();
    }
    return ok;
  }

  bool sendMessage(String text) {
    if (_activeRoomId == null) return false;
    return _bridge.sendMessage(_activeRoomId, text);
  }

  bool deleteMessage(String messageId) {
    final ok = _bridge.deleteMessage(messageId);
    if (ok) {
      _messages = _messages.where((m) => m.id != messageId).toList();
      notifyListeners();
    }
    return ok;
  }

  // ---------------------------------------------------------------------------
  // Event handling
  // ---------------------------------------------------------------------------

  void _onEvent(BackendEvent event) {
    switch (event) {
      case MessageAddedEvent(:final message):
        if (message.roomId == _activeRoomId) {
          _messages = [..._messages, message];
          notifyListeners();
        }
        // Update room preview
        _updateRoomPreview(message.roomId, message.text);

      case RoomUpdatedEvent(:final room):
        _rooms = [
          for (final r in _rooms)
            if (r.id == room.id) room else r,
        ];
        if (!_rooms.any((r) => r.id == room.id)) {
          _rooms = [..._rooms, room];
        }
        notifyListeners();

      case RoomDeletedEvent(:final roomId):
        _rooms = _rooms.where((r) => r.id != roomId).toList();
        if (_activeRoomId == roomId) {
          _activeRoomId = null;
          _messages = const [];
        }
        notifyListeners();

      case MessageDeletedEvent(:final roomId, :final messageId):
        if (roomId == _activeRoomId) {
          _messages = _messages.where((m) => m.id != messageId).toList();
          notifyListeners();
        }

      case ActiveRoomChangedEvent(:final roomId):
        _activeRoomId = roomId;
        if (roomId != null) loadMessages(roomId);
        notifyListeners();

      default:
        break;
    }
  }

  void _updateRoomPreview(String roomId, String preview) {
    _rooms = [
      for (final r in _rooms)
        if (r.id == roomId) r.copyWith(lastMessage: preview) else r,
    ];
    notifyListeners();
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }
}
