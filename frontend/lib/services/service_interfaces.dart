import '../models/thread_models.dart';

abstract class AuthenticationService {
  Future<bool> authenticate(String identifier);
  Future<void> logout();
  Future<bool> isAuthenticated();
}

abstract class RoomService {
  Future<List<ThreadSummary>> getRooms();
  Future<String> createRoom(String name);
  Future<void> selectRoom(String roomId);
  Future<void> deleteRoom(String roomId);
}

abstract class MessageService {
  Future<List<MessageItem>> getMessages(String roomId);
  Future<void> sendMessage(String roomId, String text);
  Future<void> deleteMessage(String messageId);
}

abstract class UserService {
  Future<String> getCurrentUserId();
  Future<String> getCurrentUserName();
  Future<void> updateUserProfile(String name);
}

abstract class MediaService {
  Future<String> uploadMedia(String path);
  Future<void> downloadMedia(String mediaId, String path);
}

abstract class NotificationService {
  Future<void> showNotification(String title, String body);
  Future<void> requestPermissions();
}

abstract class AnalyticsService {
  Future<void> logEvent(String eventName, Map<String, dynamic> parameters);
}
