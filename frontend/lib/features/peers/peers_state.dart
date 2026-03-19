import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/peer_models.dart';

class PeersState extends ChangeNotifier {
  PeersState(this._bridge) {
    _sub = EventBus.instance.stream.listen(_onEvent);
    loadPeers();
  }

  final BackendBridge _bridge;
  StreamSubscription<BackendEvent>? _sub;
  bool _disposed = false;

  List<PeerModel> _peers = const [];
  bool _loading = false;

  List<PeerModel> get peers => _peers;
  bool get loading => _loading;

  Future<void> loadPeers() async {
    _loading = true;
    if (!_disposed) notifyListeners();
    _peers = _bridge.fetchPeers();
    _loading = false;
    if (!_disposed) notifyListeners();
  }

  Future<bool> pairPeer(String code) async {
    final ok = _bridge.pairPeer(code);
    if (ok) await loadPeers();
    return ok;
  }

  Future<bool> attestTrust({
    required String localPeerId,
    required String targetPeerId,
    required int trustLevel,
  }) async {
    final ok = _bridge.trustAttest(
      endorserPeerId: localPeerId,
      targetPeerId: targetPeerId,
      trustLevel: trustLevel,
      verificationMethod: 0,
    );
    if (ok) await loadPeers();
    return ok;
  }

  PeerModel? findPeer(String peerId) {
    try {
      return _peers.firstWhere((p) => p.id == peerId);
    } catch (_) {
      return null;
    }
  }

  void _onEvent(BackendEvent event) {
    switch (event) {
      case PeerUpdatedEvent(:final peer):
        _peers = [
          for (final p in _peers)
            if (p.id == peer.id) peer else p,
        ];
        if (!_peers.any((p) => p.id == peer.id)) {
          _peers = [..._peers, peer];
        }
        if (!_disposed) notifyListeners();

      case TrustUpdatedEvent(:final peerId, :final trustLevel):
        _peers = [
          for (final p in _peers)
            if (p.id == peerId) p.copyWith(trustLevel: trustLevel) else p,
        ];
        if (!_disposed) notifyListeners();

      default:
        break;
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _sub?.cancel();
    super.dispose();
  }
}
