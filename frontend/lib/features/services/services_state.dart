import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/settings_models.dart';

// ---------------------------------------------------------------------------
// ServiceHealth — derived health status for a service
// ---------------------------------------------------------------------------

enum ServiceHealth { healthy, degraded, offline }

extension ServiceModelExt on ServiceModel {
  // TODO: real health check when backend exposes per-service runtime status.
  // For now, enabled == healthy; disabled == offline.
  bool get isHealthy => enabled;
  ServiceHealth get health =>
      enabled ? ServiceHealth.healthy : ServiceHealth.offline;
}

// ---------------------------------------------------------------------------
// ServicesState — manages the list of mesh services
// ---------------------------------------------------------------------------

class ServicesState extends ChangeNotifier {
  ServicesState(this._bridge) {
    _sub = EventBus.instance.stream.listen(_onEvent);
    _load();
  }

  final BackendBridge _bridge;
  late final StreamSubscription<BackendEvent> _sub;

  List<ServiceModel> _services = [];

  List<ServiceModel> get services => List.unmodifiable(_services);

  int get runningCount => _services.where((s) => s.enabled).length;
  bool get anyDegraded => _services.any((s) => s.enabled && !s.isHealthy);

  @override
  void dispose() {
    _sub.cancel();
    super.dispose();
  }

  void _load() {
    _services = _bridge.fetchServices();
    notifyListeners();
  }

  void _onEvent(BackendEvent event) {
    // Re-fetch services on any settings change that might affect them
    if (event is SettingsUpdatedEvent) {
      _load();
    }
  }

  Future<void> refresh() async {
    _load();
  }

  Future<bool> setEnabled(String serviceId, bool enabled) async {
    final ok = _bridge.configureService(serviceId, {'enabled': enabled});
    if (ok) _load();
    return ok;
  }
}
