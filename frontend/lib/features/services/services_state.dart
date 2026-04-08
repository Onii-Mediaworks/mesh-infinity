// services_state.dart
//
// ServicesState — ChangeNotifier that owns the list of mesh services visible
// to this node.
//
// ARCHITECTURE:
// -------------
// ServicesState is the Provider-level owner of the services list.  It fetches
// the list on construction and re-fetches whenever a SettingsUpdatedEvent
// arrives on the EventBus — settings changes can affect which services are
// enabled or what addresses they use.
//
// The services list is exposed as an unmodifiable view so widgets can't mutate
// it directly; all writes go through setEnabled() or refresh().
//
// "Running" vs "enabled":
// -----------------------
// runningCount counts services where enabled == true.  anyDegraded is a
// future hook for services that are enabled but unhealthy — currently always
// false because health probing isn't implemented yet.
//
// Reached from: MyServicesScreen (via Provider).

import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/settings_models.dart';

/// Manages the list of mesh services (pinned / subscribed) for the Services
/// section.
///
/// Subscribes to the global [EventBus] and re-fetches on settings changes so
/// the UI always reflects the current backend state without polling.
class ServicesState extends ChangeNotifier {
  /// Constructs the state, wires the event subscription, and performs the
  /// initial service list load.
  ///
  /// [_bridge] is the FFI gateway to the Rust backend.
  ServicesState(this._bridge) {
    // Subscribe before loading so we never miss a SettingsUpdated event that
    // fires concurrently with the initial fetch.
    _sub = EventBus.instance.stream.listen(_onEvent);
    _load();
  }

  /// FFI gateway — used for all backend calls.
  final BackendBridge _bridge;

  /// EventBus subscription — cancelled in dispose() to avoid memory leaks.
  late final StreamSubscription<BackendEvent> _sub;

  /// Internal mutable list. Exposed as unmodifiable via the [services] getter.
  List<ServiceModel> _services = [];

  /// The current service list. Returns an unmodifiable view — callers must go
  /// through [setEnabled] or [refresh] to mutate.
  List<ServiceModel> get services => List.unmodifiable(_services);

  /// Number of services that are currently enabled (advertised to the mesh).
  int get runningCount => _services.where((s) => s.enabled).length;

  /// True if any enabled service is in a degraded / error state.
  ///
  /// Always false until backend health probing is implemented (placeholder for
  /// the badge state system which checks this to light the Services section
  /// ambient indicator).
  bool get anyDegraded => false;

  @override
  void dispose() {
    // Cancel the EventBus subscription so this object can be garbage-collected
    // after it leaves the Provider tree.
    _sub.cancel();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Data loading
  // ---------------------------------------------------------------------------

  /// Fetches the full service list from the backend and notifies listeners.
  void _load() {
    _services = _bridge.fetchServices();
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Event handling
  // ---------------------------------------------------------------------------

  /// Re-fetches the service list whenever settings change.
  ///
  /// Settings changes can enable/disable services, change their addresses, or
  /// alter trust requirements — any of these would make the current snapshot
  /// stale.
  void _onEvent(BackendEvent event) {
    if (event is SettingsUpdatedEvent) {
      _load();
    }
  }

  // ---------------------------------------------------------------------------
  // Public mutations
  // ---------------------------------------------------------------------------

  /// Forces a full re-fetch from the backend.
  ///
  /// Called by pull-to-refresh gestures on [MyServicesScreen].
  Future<void> refresh() async {
    _load();
  }

  /// Enables or disables [serviceId] and re-fetches the list on success.
  ///
  /// Returns true if the backend accepted the change. On failure the list
  /// stays unchanged and the caller should inform the user.
  Future<bool> setEnabled(String serviceId, bool enabled) async {
    final ok = _bridge.configureService(serviceId, {'enabled': enabled});
    // Only reload on success — a failed toggle leaves the state unchanged so
    // the Switch reverts to its previous position automatically.
    if (ok) _load();
    return ok;
  }
}
