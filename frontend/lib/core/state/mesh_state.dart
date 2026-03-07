import 'package:flutter/material.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/backend_models.dart';
import '../../backend/file_transfer_models.dart';
import '../../backend/peer_models.dart';
import '../../models/thread_models.dart';

enum AuthenticationState { unknown, authenticated, notAuthenticated }

class Session {
  final String userId;
  final String displayName;
  final DateTime createdAt;

  const Session({
    required this.userId,
    required this.displayName,
    required this.createdAt,
  });
}

class AppError {
  final AppErrorType type;
  final String message;
  final dynamic error;

  AppError(this.type, this.message, [this.error]);

  String get title {
    switch (type) {
      case AppErrorType.authenticationFailed:
        return 'Authentication Failed';
      case AppErrorType.networkError:
        return 'Network Error';
      case AppErrorType.invalidSession:
        return 'Invalid Session';
      case AppErrorType.unknownError:
        return 'Error';
    }
  }
}

enum AppErrorType {
  authenticationFailed,
  networkError,
  invalidSession,
  unknownError,
}

class MeshState extends ChangeNotifier {
  // Dependencies
  final BackendBridge _backend;
  final bool _ownsBackend;

  // Authentication
  AuthenticationState _authenticationState = AuthenticationState.unknown;
  Session? _currentSession;

  // Theme & UI preferences
  ThemeMode _themeMode = ThemeMode.system;
  bool _isLoading = false;

  // App settings
  bool _autoSaveMedia = false;
  bool _readReceipts = true;
  bool _autoAcceptTransfers = false;
  bool _notifyOnTransferComplete = true;
  bool _preferLowLatencyRoutes = false;
  bool _showAdvancedStats = false;

  // Error handling
  AppError? _error;

  // Mesh data
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

  // Getters
  AuthenticationState get authenticationState => _authenticationState;
  Session? get currentSession => _currentSession;
  ThemeMode get themeMode => _themeMode;
  bool get isLoading => _isLoading;
  AppError? get error => _error;
  bool get autoSaveMedia => _autoSaveMedia;
  bool get readReceipts => _readReceipts;
  bool get autoAcceptTransfers => _autoAcceptTransfers;
  bool get notifyOnTransferComplete => _notifyOnTransferComplete;
  bool get preferLowLatencyRoutes => _preferLowLatencyRoutes;
  bool get showAdvancedStats => _showAdvancedStats;

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

  MeshState({BackendBridge? backend})
    : _backend = backend ?? BackendBridge.open(allowMissing: true),
      _ownsBackend = backend == null {
    // Initialize authentication state based on backend availability
    if (!_backend.isAvailable) {
      _error = AppError(
        AppErrorType.networkError,
        _backend.initError ??
            'Backend unavailable. Ensure the Rust service is running.',
      );
    }
  }

  Future<void> initialize() async {
    if (!_backend.isAvailable) {
      _error = AppError(
        AppErrorType.networkError,
        _backend.initError ?? 'Backend unavailable',
      );
      notifyListeners();
      return;
    }

    _reloadAll();
    _ready = true;

    notifyListeners();
  }

  void selectThread(String threadId) {
    if (!_backend.isAvailable) return;

    _backend.selectRoom(threadId);
    _activeThreadId = threadId;
    _activeMessages = _backend.fetchMessages(threadId);
    _threads = _backend.fetchThreads();
    notifyListeners();
  }

  Future<void> createThread(String name) async {
    if (!_backend.isAvailable) return;

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
    if (_activeThreadId == null) return;
    if (!_backend.isAvailable) return;

    _backend.sendMessage(_activeThreadId, text);
    _activeMessages = _backend.fetchMessages(_activeThreadId);
    _threads = _backend.fetchThreads();
    notifyListeners();
  }

  void _reloadAll() {
    if (!_backend.isAvailable) return;

    _threads = _backend.fetchThreads();
    _settings = _loadSettings();
    _localIdentity = _backend.fetchLocalIdentity();
    if (_settings?.pairingCode.isNotEmpty ?? false) {
      _lastPairingCode = _settings?.pairingCode;
    }
    _peers = _backend.fetchPeers().map(PeerInfoModel.fromJson).toList();
    _transfers = _backend
        .fetchFileTransfers()
        .map(FileTransferItem.fromJson)
        .toList();
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
  }

  void refreshSettings() {
    if (!_backend.isAvailable) return;

    _settings = _loadSettings();
    if (_settings?.pairingCode.isNotEmpty ?? false) {
      _lastPairingCode = _settings?.pairingCode;
    }
    _localIdentity = _backend.fetchLocalIdentity();
    notifyListeners();
  }

  void refreshData() {
    if (!_backend.isAvailable) return;
    _reloadAll();
    notifyListeners();
  }

  bool attestTrust({
    required String targetPeerId,
    required int trustLevel,
    int verificationMethod = 2,
  }) {
    if (!_backend.isAvailable) return false;

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

  int? verifyTrust(
    String targetPeerId, {
    List<Map<String, dynamic>> markers = const [],
  }) {
    if (!_backend.isAvailable) return null;

    final result = _backend.trustVerify(
      targetPeerId: targetPeerId,
      markers: markers,
    );
    if (result == null) {
      return null;
    }
    final trustLevel = result['trustLevel'] as int?;
    _lastVerifiedTrustLevel = trustLevel;
    notifyListeners();
    return trustLevel;
  }

  bool pairPeer(String pairingCode) {
    if (!_backend.isAvailable) return false;
    final trimmed = pairingCode.trim();
    if (trimmed.isEmpty) return false;
    final ok = _backend.pairPeer(trimmed);
    if (ok) {
      _reloadAll();
      notifyListeners();
    }
    return ok;
  }

  BackendSettings? _loadSettings() {
    if (!_backend.isAvailable) return null;
    final settingsJson = _backend.fetchSettings();
    if (settingsJson == null) {
      return null;
    }
    return BackendSettings.fromJson(settingsJson);
  }

  // Setters with notifyListeners
  void setAuthenticationState(AuthenticationState state) {
    _authenticationState = state;
    notifyListeners();
  }

  void setCurrentSession(Session? session) {
    _currentSession = session;
    notifyListeners();
  }

  void setThemeMode(ThemeMode mode) {
    _themeMode = mode;
    notifyListeners();
  }

  void setIsLoading(bool loading) {
    _isLoading = loading;
    notifyListeners();
  }

  void setError(AppError? error) {
    _error = error;
    notifyListeners();
  }

  void clearError() {
    _error = null;
    notifyListeners();
  }

  void setAutoSaveMedia(bool value) {
    _autoSaveMedia = value;
    notifyListeners();
  }

  void setReadReceipts(bool value) {
    _readReceipts = value;
    notifyListeners();
  }

  void setAutoAcceptTransfers(bool value) {
    _autoAcceptTransfers = value;
    notifyListeners();
  }

  void setNotifyOnTransferComplete(bool value) {
    _notifyOnTransferComplete = value;
    notifyListeners();
  }

  void setPreferLowLatencyRoutes(bool value) {
    _preferLowLatencyRoutes = value;
    notifyListeners();
  }

  void setShowAdvancedStats(bool value) {
    _showAdvancedStats = value;
    notifyListeners();
  }

  @override
  void dispose() {
    if (_ownsBackend) {
      _backend.dispose();
    }
    super.dispose();
  }
}
