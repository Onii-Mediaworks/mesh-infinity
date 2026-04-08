// peers_state.dart
//
// PeersState — ChangeNotifier that owns the in-memory peer list for the
// Contacts section.
//
// ARCHITECTURE:
// -------------
// PeersState sits between the BackendBridge (FFI boundary) and the UI layer.
// It performs three jobs:
//   1. Initial load: fetches all known peers from the backend on construction.
//   2. Real-time updates: listens to the EventBus stream and applies patch
//      events (PeerAdded, PeerUpdated, TrustUpdated) in-place without a full
//      reload, keeping the UI snappy.
//   3. Mutations: exposes pairPeer() and attestTrust() which write through to
//      the backend and then re-fetch so the list is always in sync.
//
// The peer list is immutable between updates — every modification creates a
// new list object. This makes it safe to hand the list to const widgets
// without defensive copies on each read.
//
// Reached from: ContactsScreen (via Provider).

import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/peer_models.dart';

/// Manages the live peer list for the Contacts feature.
///
/// Constructed once by the Provider tree and lives for the lifetime of the
/// app session. Subscribes to [EventBus] to receive real-time peer changes
/// from the backend without polling.
class PeersState extends ChangeNotifier {
  /// Creates the state, subscribes to the event bus, and triggers an initial
  /// peer load.
  ///
  /// [_bridge] is the FFI gateway to the Rust backend.
  PeersState(this._bridge) {
    // Start listening for peer-related events before the first load so we
    // never miss an event that fires between construction and load completing.
    _sub = EventBus.instance.stream.listen(_onEvent);
    loadPeers();
  }

  /// FFI gateway — used for all backend calls.
  final BackendBridge _bridge;

  /// EventBus subscription — cancelled in dispose() to prevent memory leaks.
  StreamSubscription<BackendEvent>? _sub;

  /// True once dispose() is called. Guards against calling notifyListeners()
  /// on a disposed ChangeNotifier, which would throw in debug mode.
  bool _disposed = false;

  /// Current snapshot of all known peers, newest-loaded state.
  /// Always an immutable list — never mutated in place.
  List<PeerModel> _peers = const [];

  /// True while a full peer fetch is in progress. Drives loading indicators.
  bool _loading = false;

  /// The current peer list. Returns the same list object between updates so
  /// that downstream widgets using == comparisons get the right answer.
  List<PeerModel> get peers => _peers;

  /// Whether a full reload is currently in flight.
  bool get loading => _loading;

  // ---------------------------------------------------------------------------
  // Data loading
  // ---------------------------------------------------------------------------

  /// Fetches the full peer list from the backend and notifies listeners.
  ///
  /// Called on construction and any time a mutation (pair, trust) succeeds.
  /// Callers can also invoke this directly (e.g. pull-to-refresh).
  Future<void> loadPeers() async {
    _loading = true;
    // Notify immediately so the UI shows the loading indicator before the
    // (potentially slow) FFI call starts.
    if (!_disposed) notifyListeners();

    _peers = _bridge.fetchPeers();

    _loading = false;
    if (!_disposed) notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------

  /// Pairs with a new peer using the provided invite/QR code.
  ///
  /// Returns true if the backend accepted the code and the peer was added.
  /// On success, re-fetches the peer list so the new peer appears immediately.
  Future<bool> pairPeer(String code) async {
    final ok = _bridge.pairPeer(code);
    // Only reload on success — a failed pair leaves the list unchanged.
    if (ok) await loadPeers();
    return ok;
  }

  /// Records a trust attestation for [targetPeerId], signed by [localPeerId].
  ///
  /// [trustLevel] is an integer in 0–8 matching the spec trust scale (§5.x).
  /// [verificationMethod] is always 0 (in-band) from the UI path — out-of-band
  /// verification is handled separately.
  ///
  /// Returns true on success. On success, re-fetches peers so trust badges
  /// update without waiting for a push event.
  Future<bool> attestTrust({
    required String localPeerId,
    required String targetPeerId,
    required int trustLevel,
  }) async {
    final ok = _bridge.trustAttest(
      endorserPeerId: localPeerId,
      targetPeerId: targetPeerId,
      trustLevel: trustLevel,
      // verificationMethod 0 = in-band (QR / code exchange).
      // Out-of-band (key ceremonies etc.) use a different flow.
      verificationMethod: 0,
    );
    if (ok) await loadPeers();
    return ok;
  }

  // ---------------------------------------------------------------------------
  // Lookup helpers
  // ---------------------------------------------------------------------------

  /// Returns the [PeerModel] with [peerId], or null if not in the current list.
  ///
  /// Returns null when the peer ID is unknown — callers must handle this case
  /// (e.g. when navigating to a detail screen before the list is loaded).
  PeerModel? findPeer(String peerId) {
    final match = _peers.where((p) => p.id == peerId);
    return match.isNotEmpty ? match.first : null;
  }

  // ---------------------------------------------------------------------------
  // Event handling
  // ---------------------------------------------------------------------------

  /// Handles real-time peer events from the EventBus.
  ///
  /// Each case produces a new list object rather than mutating the existing
  /// one — this is safe for const widgets and avoids missed rebuilds.
  void _onEvent(BackendEvent event) {
    switch (event) {
      case PeerUpdatedEvent(:final peer):
        // Replace the existing peer record in-place (same ID → new data).
        // If the peer isn't in the list yet, append it — this handles the race
        // where PeerUpdated fires before PeerAdded was processed.
        _peers = [
          for (final p in _peers)
            if (p.id == peer.id) peer else p,
        ];
        if (!_peers.any((p) => p.id == peer.id)) {
          _peers = [..._peers, peer];
        }
        if (!_disposed) notifyListeners();

      case PeerAddedEvent(:final peer):
        // Only append if not already present — the initial load may have raced
        // with the event, so deduplication here prevents duplicates.
        if (!_peers.any((p) => p.id == peer.id)) {
          _peers = [..._peers, peer];
          if (!_disposed) notifyListeners();
        }

      case TrustUpdatedEvent(:final peerId, :final trustLevel):
        // Patch only the trust level; all other fields stay unchanged.
        // This is more efficient than a full reload and avoids clearing
        // transient UI state (e.g. scroll position) on minor trust changes.
        _peers = [
          for (final p in _peers)
            if (p.id == peerId) p.copyWith(trustLevel: trustLevel) else p,
        ];
        if (!_disposed) notifyListeners();

      default:
        // Ignore events not relevant to the peer list (messages, files, etc.).
        break;
    }
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void dispose() {
    // Mark disposed first so any in-flight async work (loadPeers) that checks
    // this flag won't call notifyListeners on the dead notifier.
    _disposed = true;
    // Cancel the EventBus subscription to prevent the stream callback from
    // holding a reference to this object after disposal.
    _sub?.cancel();
    super.dispose();
  }
}
