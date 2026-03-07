import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/network_models.dart';
import '../../backend/models/settings_models.dart';

class NetworkState extends ChangeNotifier {
  NetworkState(this._bridge) {
    _sub = EventBus.instance.stream.listen(_onEvent);
    loadAll();
  }

  final BackendBridge _bridge;
  StreamSubscription<BackendEvent>? _sub;

  SettingsModel? _settings;
  NetworkStatsModel? _stats;
  bool _mdnsRunning = false;
  List<DiscoveredPeerModel> _discoveredPeers = const [];

  SettingsModel? get settings => _settings;
  NetworkStatsModel? get stats => _stats;
  bool get mdnsRunning => _mdnsRunning;
  List<DiscoveredPeerModel> get discoveredPeers => _discoveredPeers;

  Future<void> loadAll() async {
    final raw = _bridge.fetchSettings();
    _settings = raw;

    final statsRaw = _bridge.getNetworkStats();
    if (statsRaw != null) _stats = NetworkStatsModel.fromJson(statsRaw);

    _mdnsRunning = _bridge.isMdnsRunning();

    final rawPeers = _bridge.getDiscoveredPeers();
    _discoveredPeers = rawPeers
        .map(DiscoveredPeerModel.fromJson)
        .toList();

    notifyListeners();
  }

  Future<bool> toggleTransport(String name, bool enabled) async {
    final ok = _bridge.toggleTransport(name, enabled);
    if (ok) {
      final raw = _bridge.fetchSettings();
      _settings = raw;
      notifyListeners();
    }
    return ok;
  }

  Future<bool> setNodeMode(int mode) async {
    final ok = _bridge.setNodeMode(mode);
    if (ok) {
      final raw = _bridge.fetchSettings();
      _settings = raw;
      notifyListeners();
    }
    return ok;
  }

  Future<bool> enableMdns({int port = 51820}) async {
    final ok = _bridge.enableMdns(port: port);
    if (ok) {
      _mdnsRunning = true;
      notifyListeners();
    }
    return ok;
  }

  Future<bool> disableMdns() async {
    final ok = _bridge.disableMdns();
    if (ok) {
      _mdnsRunning = false;
      _discoveredPeers = const [];
      notifyListeners();
    }
    return ok;
  }

  void _onEvent(BackendEvent event) {
    if (event is! SettingsUpdatedEvent) return;
    _settings = event.settings;
    notifyListeners();
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }
}
