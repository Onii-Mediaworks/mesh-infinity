import '../backend/backend_bridge.dart';
import 'implementations.dart';
import 'service_interfaces.dart';

abstract class DependencyContainer {
  AuthenticationService get authenticationService;
  RoomService get roomService;
  MessageService get messageService;
  UserService get userService;
  MediaService get mediaService;
  NotificationService get notificationService;
  AnalyticsService get analyticsService;
  BackendBridge get backendBridge;
}

class AppDependencyContainer implements DependencyContainer {
  late final BackendBridge _backendBridge;
  late final AuthenticationService _authenticationService;
  late final RoomService _roomService;
  late final MessageService _messageService;
  late final UserService _userService;
  late final MediaService _mediaService;
  late final NotificationService _notificationService;
  late final AnalyticsService _analyticsService;

  AppDependencyContainer({int nodeMode = 0}) {
    _backendBridge = BackendBridge.open(nodeMode: nodeMode, allowMissing: false);
    _authenticationService = DefaultAuthenticationService(_backendBridge);
    _roomService = DefaultRoomService(_backendBridge);
    _messageService = DefaultMessageService(_backendBridge);
    _userService = DefaultUserService();
    _mediaService = DefaultMediaService();
    _notificationService = DefaultNotificationService();
    _analyticsService = DefaultAnalyticsService();
  }

  @override
  AuthenticationService get authenticationService => _authenticationService;

  @override
  RoomService get roomService => _roomService;

  @override
  MessageService get messageService => _messageService;

  @override
  UserService get userService => _userService;

  @override
  MediaService get mediaService => _mediaService;

  @override
  NotificationService get notificationService => _notificationService;

  @override
  AnalyticsService get analyticsService => _analyticsService;

  @override
  BackendBridge get backendBridge => _backendBridge;

  void dispose() {
    _backendBridge.dispose();
  }
}
