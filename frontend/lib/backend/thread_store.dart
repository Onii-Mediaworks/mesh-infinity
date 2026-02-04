import 'dart:async';

import 'package:flutter/foundation.dart';

import '../models/thread_models.dart';
import 'backend_bridge.dart';
import 'backend_models.dart';
import 'file_transfer_models.dart';
import 'peer_models.dart';

class ThreadStore extends ChangeNotifier {
  ThreadStore({BackendBridge? backend}) : _backend = backend ?? BackendBridge.open();

  final BackendBridge _backend;
  Timer? _poller;

  List<ThreadSummary> _threads = const [];
  List<MessageItem> _activeMessages = const [];
  String? _activeThreadId;
  bool _ready = false;
  BackendSettings? _settings;
  LocalIdentitySummary? _localIdentity;
  int? _lastVerifiedTrustLevel;
  String? _lastPairingCode;
  List<PeerInfoModel> _peers = const [];
  List<FileTransferItem> _transfers = const [];

  List<ThreadSummary> get threads => _threads;
  List<MessageItem> get activeMessages => _activeMessages;
  String? get activeThreadId => _activeThreadId;
  bool get isReady => _ready;
  BackendSettings? get settings => _settings;
  String? get pairingCode => _settings?.pairingCode ?? _lastPairingCode;
  LocalIdentitySummary? get localIdentity => _localIdentity;
  int? get lastVerifiedTrustLevel => _lastVerifiedTrustLevel;
  int get peerCount => _peers.length;
  List<PeerInfoModel> get peers => _peers;
  List<FileTransferItem> get transfers => _transfers;
  BackendBridge get backendBridge => _backend;

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
    _settings = _loadSettings();
    _localIdentity = _backend.fetchLocalIdentity();
    if (_settings?.pairingCode.isNotEmpty ?? false) {
      _lastPairingCode = _settings?.pairingCode;
    }
    _peers = _backend.fetchPeers().map(PeerInfoModel.fromJson).toList();
    _transfers = _backend.fetchFileTransfers().map(FileTransferItem.fromJson).toList();
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

  void refreshSettings() {
    _settings = _loadSettings();
    if (_settings?.pairingCode.isNotEmpty ?? false) {
      _lastPairingCode = _settings?.pairingCode;
    }
    _localIdentity = _backend.fetchLocalIdentity();
    notifyListeners();
  }

  bool attestTrust({
    required String targetPeerId,
    required int trustLevel,
    int verificationMethod = 2,
  }) {
    final localPeerId = _localIdentity?.peerId;
    if (localPeerId == null || localPeerId.isEmpty) {
      return false;
    }
    final success = _backend.trustAttest(
      endorserPeerId: localPeerId,
      targetPeerId: targetPeerId,
      trustLevel: trustLevel,
      verificationMethod: verificationMethod,
    );
    if (success) {
      _reloadAll();
    }
    return success;
  }

  int? verifyTrust(String targetPeerId, {List<Map<String, dynamic>> markers = const []}) {
    final result = _backend.trustVerify(targetPeerId: targetPeerId, markers: markers);
    if (result == null) {
      return null;
    }
    final trustLevel = result['trustLevel'] as int?;
    _lastVerifiedTrustLevel = trustLevel;
    notifyListeners();
    return trustLevel;
  }

  BackendSettings? _loadSettings() {
    final settingsJson = _backend.fetchSettings();
    if (settingsJson == null) {
      return null;
    }
    return BackendSettings.fromJson(settingsJson);
  }

  @override
  void dispose() {
    _poller?.cancel();
    _backend.dispose();
    super.dispose();
  }
}
