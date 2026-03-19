import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/settings_models.dart';

class SettingsState extends ChangeNotifier {
  SettingsState(this._bridge) {
    _sub = EventBus.instance.stream.listen(_onEvent);
    loadAll();
  }

  final BackendBridge _bridge;
  StreamSubscription<BackendEvent>? _sub;
  bool _disposed = false;

  SettingsModel? _settings;
  LocalIdentitySummary? _identity;
  List<ServiceModel> _services = const [];

  SettingsModel? get settings => _settings;
  LocalIdentitySummary? get identity => _identity;
  List<ServiceModel> get services => _services;

  Future<void> loadAll() async {
    _settings = _bridge.fetchSettings();
    _identity = _bridge.fetchLocalIdentity();
    _services = _bridge.fetchServices();
    if (!_disposed) notifyListeners();
  }

  Future<bool> configureService(String serviceId, Map<String, dynamic> config) async {
    final ok = _bridge.configureService(serviceId, config);
    if (ok) await loadAll();
    return ok;
  }

  Future<bool> setVpnRoute(Map<String, dynamic> routeConfig) async {
    return _bridge.setVpnRoute(routeConfig);
  }

  Future<bool> setClearnetRoute(Map<String, dynamic> routeConfig) async {
    return _bridge.setClearnetRoute(routeConfig);
  }

  void _onEvent(BackendEvent event) {
    if (event is! SettingsUpdatedEvent) return;
    _settings = event.settings;
    _identity = _bridge.fetchLocalIdentity();
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _sub?.cancel();
    super.dispose();
  }
}
