import '../backend/backend_bridge.dart';
import '../models/thread_models.dart';
import 'service_interfaces.dart';

class DefaultAuthenticationService implements AuthenticationService {
  final BackendBridge _bridge;

  DefaultAuthenticationService(this._bridge);

  @override
  Future<bool> authenticate(String identifier) async {
    // Identity is currently provisioned by backend initialization.
    return isAuthenticated();
  }

  @override
  Future<void> logout() async {
    // No-op for now
  }

  @override
  Future<bool> isAuthenticated() async {
    if (!_bridge.isAvailable) {
      return false;
    }
    return _bridge.hasIdentity();
  }
}

class DefaultRoomService implements RoomService {
  final BackendBridge _bridge;

  DefaultRoomService(this._bridge);

  @override
  Future<List<ThreadSummary>> getRooms() async {
    return _bridge.fetchThreads();
  }

  @override
  Future<String> createRoom(String name) async {
    final roomId = _bridge.createRoom(name);
    return roomId ?? '';
  }

  @override
  Future<void> selectRoom(String roomId) async {
    _bridge.selectRoom(roomId);
  }

  @override
  Future<void> deleteRoom(String roomId) async {
    _bridge.deleteRoom(roomId);
  }
}

class DefaultMessageService implements MessageService {
  final BackendBridge _bridge;

  DefaultMessageService(this._bridge);

  @override
  Future<List<MessageItem>> getMessages(String roomId) async {
    return _bridge.fetchMessages(roomId);
  }

  @override
  Future<void> sendMessage(String roomId, String text) async {
    _bridge.sendMessage(roomId, text);
  }

  @override
  Future<void> deleteMessage(String messageId) async {
    _bridge.deleteMessage(messageId);
  }
}

class DefaultUserService implements UserService {
  @override
  Future<String> getCurrentUserId() async {
    return 'user-1';
  }

  @override
  Future<String> getCurrentUserName() async {
    return 'You';
  }

  @override
  Future<void> updateUserProfile(String name) async {
    // Not implemented yet
  }
}

class DefaultMediaService implements MediaService {
  @override
  Future<String> uploadMedia(String path) async {
    // Not implemented yet
    return '';
  }

  @override
  Future<void> downloadMedia(String mediaId, String path) async {
    // Not implemented yet
  }
}

class DefaultNotificationService implements NotificationService {
  @override
  Future<void> showNotification(String title, String body) async {
    // Not implemented yet
  }

  @override
  Future<void> requestPermissions() async {
    // Not implemented yet
  }
}

class DefaultAnalyticsService implements AnalyticsService {
  @override
  Future<void> logEvent(
    String eventName,
    Map<String, dynamic> parameters,
  ) async {
    // Not implemented yet - intentionally no-op for privacy
  }
}
