import 'dart:async';

import 'package:flutter/foundation.dart';

import '../models/thread_models.dart';
import 'backend_bridge.dart';

class ThreadStore extends ChangeNotifier {
  ThreadStore({BackendBridge? backend}) : _backend = backend ?? BackendBridge.open();

  final BackendBridge _backend;
  Timer? _poller;

  List<ThreadSummary> _threads = const [];
  List<MessageItem> _activeMessages = const [];
  String? _activeThreadId;
  bool _ready = false;

  List<ThreadSummary> get threads => _threads;
  List<MessageItem> get activeMessages => _activeMessages;
  String? get activeThreadId => _activeThreadId;
  bool get isReady => _ready;

  Future<void> initialize() async {
    _reloadAll();
    _ready = true;
    _poller?.cancel();
    _poller = Timer.periodic(const Duration(seconds: 1), (_) {
      if (_backend.pollEvents()) {
        _reloadAll();
      }
    });
  }

  void selectThread(String threadId) {
    _backend.selectRoom(threadId);
    _activeThreadId = threadId;
    _activeMessages = _backend.fetchMessages(threadId);
    _threads = _backend.fetchThreads();
    notifyListeners();
  }

  Future<void> createThread(String name) async {
    final roomId = _backend.createRoom(name);
    if (roomId == null || roomId.isEmpty) {
      return;
    }
    _activeThreadId = roomId;
    _threads = _backend.fetchThreads();
    _activeMessages = _backend.fetchMessages(roomId);
    notifyListeners();
  }

  void sendMessage(String text) {
    if (_activeThreadId == null) {
      return;
    }
    _backend.sendMessage(_activeThreadId, text);
    _activeMessages = _backend.fetchMessages(_activeThreadId);
    _threads = _backend.fetchThreads();
    notifyListeners();
  }

  void _reloadAll() {
    _threads = _backend.fetchThreads();
    final activeFromBackend = _backend.activeRoomId();
    if (activeFromBackend != null && activeFromBackend.isNotEmpty) {
      _activeThreadId = activeFromBackend;
    } else if (_threads.isNotEmpty) {
      _activeThreadId ??= _threads.first.id;
    } else {
      _activeThreadId = null;
    }

    if (_activeThreadId != null) {
      _activeMessages = _backend.fetchMessages(_activeThreadId);
    } else {
      _activeMessages = const [];
    }
    notifyListeners();
  }

  @override
  void dispose() {
    _poller?.cancel();
    _backend.dispose();
    super.dispose();
  }
}
