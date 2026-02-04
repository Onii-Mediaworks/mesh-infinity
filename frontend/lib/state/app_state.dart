import 'package:flutter/material.dart';

enum AuthenticationState {
  unknown,
  authenticated,
  notAuthenticated,
}

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

class AppState extends ChangeNotifier {
  AuthenticationState _authenticationState = AuthenticationState.unknown;
  Session? _currentSession;
  ThemeMode _themeMode = ThemeMode.light;
  bool _isLoading = false;
  AppError? _error;
  bool _autoSaveMedia = false;
  bool _readReceipts = true;
  bool _autoAcceptTransfers = false;
  bool _notifyOnTransferComplete = true;
  bool _preferLowLatencyRoutes = false;

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
}
