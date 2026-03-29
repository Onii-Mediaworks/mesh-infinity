import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';

// ---------------------------------------------------------------------------
// Call phase enum
// ---------------------------------------------------------------------------

enum CallPhase {
  /// No call in progress.
  idle,
  /// We placed an outgoing call and are waiting for the remote to answer.
  outgoingRinging,
  /// The remote peer is calling us; awaiting our accept/decline.
  incomingRinging,
  /// Call is connected and active.
  connected,
}

// ---------------------------------------------------------------------------
// CallsState — ChangeNotifier
// ---------------------------------------------------------------------------

/// Manages voice/video call lifecycle (§10.1.6).
///
/// Reacts to three backend events:
///   CallIncoming  → phase = incomingRinging
///   CallAnswered  → phase = connected
///   CallHungUp    → phase = idle
///
/// Bridge methods:
///   callOffer()  → start outgoing call
///   callAnswer() → accept/decline incoming
///   callHangup() → end active call
class CallsState extends ChangeNotifier {
  CallsState(this._bridge) {
    _sub = EventBus.instance.stream.listen(_onEvent);
  }

  final BackendBridge _bridge;
  StreamSubscription<BackendEvent>? _sub;
  bool _disposed = false;

  // -------------------------------------------------------------------------
  // Public state
  // -------------------------------------------------------------------------

  CallPhase get phase => _phase;
  CallPhase _phase = CallPhase.idle;

  /// Hex call ID of the active / pending call.
  String? get activeCallId => _callId;
  String? _callId;

  /// Hex peer ID of the remote party.
  String? get remotePeerId => _peerId;
  String? _peerId;

  /// Whether the active or incoming call includes video.
  bool get isVideo => _isVideo;
  bool _isVideo = false;

  /// Elapsed seconds for a connected call (updated by [tick]).
  int get durationSecs => _durationSecs;
  int _durationSecs = 0;
  DateTime? _connectedAt;

  // -------------------------------------------------------------------------
  // Actions
  // -------------------------------------------------------------------------

  /// Start an outgoing call to [peerIdHex].
  void startCall(String peerIdHex, {bool video = false}) {
    if (_phase != CallPhase.idle) return;
    final resp = _bridge.callOffer(peerIdHex, isVideo: video);
    if (resp == null || resp['ok'] != true) return;
    _callId = resp['callId'] as String?;
    _peerId = peerIdHex;
    _isVideo = video;
    _phase = CallPhase.outgoingRinging;
    if (!_disposed) notifyListeners();
  }

  /// Accept an incoming call.
  void acceptCall() {
    if (_phase != CallPhase.incomingRinging || _callId == null) return;
    _bridge.callAnswer(_callId!, accept: true);
    _phase = CallPhase.connected;
    _connectedAt = DateTime.now();
    _durationSecs = 0;
    if (!_disposed) notifyListeners();
  }

  /// Decline an incoming call.
  void declineCall() {
    if (_callId == null) return;
    _bridge.callAnswer(_callId!, accept: false);
    _resetState();
  }

  /// Hang up an active or outgoing call.
  void hangUp() {
    if (_callId != null) _bridge.callHangup(_callId!);
    _resetState();
  }

  /// Called by the UI on a timer to update [durationSecs] while connected.
  void tick() {
    if (_phase != CallPhase.connected || _connectedAt == null) return;
    final secs = DateTime.now().difference(_connectedAt!).inSeconds;
    if (secs != _durationSecs) {
      _durationSecs = secs;
      if (!_disposed) notifyListeners();
    }
  }

  // -------------------------------------------------------------------------
  // Event handling
  // -------------------------------------------------------------------------

  void _onEvent(BackendEvent event) {
    switch (event) {
      case CallIncomingEvent(:final callId, :final peerId, :final isVideo):
        _callId = callId;
        _peerId = peerId;
        _isVideo = isVideo;
        _phase = CallPhase.incomingRinging;
        if (!_disposed) notifyListeners();

      case CallAnsweredEvent(:final callId):
        if (_callId == callId && _phase == CallPhase.outgoingRinging) {
          _phase = CallPhase.connected;
          _connectedAt = DateTime.now();
          _durationSecs = 0;
          if (!_disposed) notifyListeners();
        }

      case CallHungUpEvent(:final callId):
        if (_callId == callId) _resetState();

      default:
        break;
    }
  }

  void _resetState() {
    _phase = CallPhase.idle;
    _callId = null;
    _peerId = null;
    _isVideo = false;
    _durationSecs = 0;
    _connectedAt = null;
    if (!_disposed) notifyListeners();
  }

  // -------------------------------------------------------------------------
  // Cleanup
  // -------------------------------------------------------------------------

  @override
  void dispose() {
    _disposed = true;
    _sub?.cancel();
    super.dispose();
  }
}
