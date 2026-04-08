import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';

// ---------------------------------------------------------------------------
// Call phase enum
// ---------------------------------------------------------------------------

/// The lifecycle phase of a voice/video call (§10.1.6).
///
/// Transitions:
///   idle → outgoingRinging  (user places a call via startCall())
///   idle → incomingRinging  (backend fires CallIncomingEvent)
///   outgoingRinging → connected  (backend fires CallAnsweredEvent)
///   incomingRinging → connected  (user taps Accept)
///   incomingRinging → idle       (user taps Decline)
///   outgoingRinging → idle       (user taps Hang Up, or remote declines)
///   connected → idle             (either party hangs up)
enum CallPhase {
  /// No call in progress.  The call overlay is hidden in this state.
  idle,

  /// We placed an outgoing call and are waiting for the remote to answer.
  /// The overlay shows "Calling…" with a Hang Up button.
  outgoingRinging,

  /// The remote peer is calling us; awaiting our accept/decline.
  /// The overlay shows the peer's name with Accept / Decline buttons.
  incomingRinging,

  /// Call is connected and active.
  /// The overlay shows the peer name, elapsed duration, and a Hang Up button.
  connected,
}

// ---------------------------------------------------------------------------
// CallsState — ChangeNotifier
// ---------------------------------------------------------------------------

/// Manages voice/video call lifecycle (§10.1.6).
///
/// This is a [ChangeNotifier] registered in the Provider tree at the top of
/// the app.  Any widget that calls `context.watch<CallsState>()` will rebuild
/// whenever the call state changes.
///
/// Reacts to three backend events (received via [EventBus]):
///   [CallIncomingEvent]  → phase = incomingRinging
///   [CallAnsweredEvent]  → phase = connected  (only for our outgoing call)
///   [CallHungUpEvent]    → phase = idle        (for any active call ID)
///
/// Outward bridge methods (called to Rust):
///   callOffer()  → start an outgoing call
///   callAnswer() → accept or decline an incoming call
///   callHangup() → end an active or outgoing call
class CallsState extends ChangeNotifier {
  /// Creates [CallsState] and starts listening to backend events.
  ///
  /// [bridge] provides the FFI methods needed to initiate and control calls.
  CallsState(this._bridge) {
    // Subscribe to all backend events; _onEvent filters for call-related ones.
    _sub = EventBus.instance.stream.listen(_onEvent);
  }

  final BackendBridge _bridge;

  /// Stream subscription to the event bus.  Cancelled in dispose().
  StreamSubscription<BackendEvent>? _sub;

  /// Set to true in dispose() to prevent notifyListeners() from being called
  /// after the ChangeNotifier has been removed from the Provider tree.
  /// Without this guard, a Dart async callback (event or timer) firing after
  /// dispose() would assert-crash in debug mode.
  bool _disposed = false;

  // -------------------------------------------------------------------------
  // Public state
  // -------------------------------------------------------------------------

  CallPhase get phase => _phase;
  CallPhase _phase = CallPhase.idle;

  /// Hex call ID of the active / pending call.
  ///
  /// Null when no call is in progress ([phase] == idle).  The ID is assigned
  /// by the backend (outgoing) or received in the [CallIncomingEvent]
  /// (incoming) and is used to correlate subsequent events to the correct call.
  String? get activeCallId => _callId;
  String? _callId;

  /// Hex peer ID of the remote party.
  ///
  /// Null between calls.  Used by [CallOverlay] to look up the peer's display
  /// name in [PeersState] so the overlay can show a name rather than raw hex.
  String? get remotePeerId => _peerId;
  String? _peerId;

  /// Whether the active or incoming call includes video.
  ///
  /// Drives the status label ("Incoming video call" vs "Incoming call") and
  /// will later control whether the camera is activated.
  bool get isVideo => _isVideo;
  bool _isVideo = false;

  /// Elapsed seconds since [phase] became [CallPhase.connected].
  ///
  /// Updated on each call to [tick()].  Resets to 0 whenever a new call
  /// connects so the timer always starts at 00:00.
  int get durationSecs => _durationSecs;
  int _durationSecs = 0;

  /// The wall-clock timestamp when the call entered [CallPhase.connected].
  ///
  /// Null unless the call is currently connected.  Duration is computed as
  /// `DateTime.now().difference(_connectedAt).inSeconds` in [tick()].
  DateTime? _connectedAt;

  // -------------------------------------------------------------------------
  // Actions
  // -------------------------------------------------------------------------

  /// Start an outgoing call to [peerIdHex].
  ///
  /// Does nothing if a call is already in progress (guards against double-tap).
  /// On success, transitions phase to [CallPhase.outgoingRinging] and notifies
  /// listeners so [CallOverlay] appears immediately.
  void startCall(String peerIdHex, {bool video = false}) {
    // Prevent starting a second call while one is in progress.
    if (_phase != CallPhase.idle) return;

    // callOffer() calls Rust via FFI and returns a map with 'ok' and 'callId'.
    // Returns null if the bridge call itself fails (e.g. backend not running).
    final resp = _bridge.callOffer(peerIdHex, isVideo: video);
    if (resp == null || resp['ok'] != true) return;

    _callId = resp['callId'] as String?;
    _peerId = peerIdHex;
    _isVideo = video;
    _phase = CallPhase.outgoingRinging;
    if (!_disposed) notifyListeners();
  }

  /// Accept an incoming call.
  ///
  /// Must only be called when [phase] == [CallPhase.incomingRinging].
  /// Transitions to [CallPhase.connected] immediately (optimistic UI) and
  /// calls [BackendBridge.callAnswer] to inform the Rust backend.
  void acceptCall() {
    if (_phase != CallPhase.incomingRinging || _callId == null) return;
    _bridge.callAnswer(_callId!, accept: true);
    _phase = CallPhase.connected;
    // Record connection time so tick() can compute elapsed seconds.
    _connectedAt = DateTime.now();
    _durationSecs = 0;
    if (!_disposed) notifyListeners();
  }

  /// Decline an incoming call.
  ///
  /// Informs the backend and resets all call state to idle.
  void declineCall() {
    if (_callId == null) return;
    _bridge.callAnswer(_callId!, accept: false);
    _resetState();
  }

  /// Hang up an active or outgoing call.
  ///
  /// Safe to call in any non-idle phase — if [_callId] is null there is
  /// nothing to inform the backend about, so we just reset local state.
  void hangUp() {
    if (_callId != null) _bridge.callHangup(_callId!);
    _resetState();
  }

  /// Called by [CallOverlay]'s timer every second to update [durationSecs].
  ///
  /// Only mutates and notifies when the computed second count has actually
  /// changed — this avoids rebuilding the overlay 60× per second when Dart's
  /// event loop delivers the timer slightly early.
  void tick() {
    if (_phase != CallPhase.connected || _connectedAt == null) return;
    final secs = DateTime.now().difference(_connectedAt!).inSeconds;
    // Guard: only notify if the second count has advanced, to avoid spurious
    // rebuilds when the timer fires in the same second as the previous tick.
    if (secs != _durationSecs) {
      _durationSecs = secs;
      if (!_disposed) notifyListeners();
    }
  }

  // -------------------------------------------------------------------------
  // Event handling
  // -------------------------------------------------------------------------

  /// Handles backend events from [EventBus].
  ///
  /// Only [CallIncomingEvent], [CallAnsweredEvent], and [CallHungUpEvent] are
  /// acted on; all other event types are ignored via the default branch.
  void _onEvent(BackendEvent event) {
    switch (event) {
      case CallIncomingEvent(:final callId, :final peerId, :final isVideo):
        // A remote peer is calling us — surface the incoming-call overlay.
        _callId = callId;
        _peerId = peerId;
        _isVideo = isVideo;
        _phase = CallPhase.incomingRinging;
        if (!_disposed) notifyListeners();

      case CallAnsweredEvent(:final callId):
        // The remote peer accepted our outgoing call.
        // Guard against a stale event (e.g. from a previous call) by checking
        // both the call ID and the current phase.
        if (_callId == callId && _phase == CallPhase.outgoingRinging) {
          _phase = CallPhase.connected;
          _connectedAt = DateTime.now();
          _durationSecs = 0;
          if (!_disposed) notifyListeners();
        }

      case CallHungUpEvent(:final callId):
        // Either party ended the call — reset to idle if it is our active call.
        if (_callId == callId) _resetState();

      default:
        // All other event types are unrelated to call management.
        break;
    }
  }

  /// Resets all call state fields to their idle defaults and notifies listeners.
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
    // Set _disposed before cancelling the subscription so that any in-flight
    // event callbacks that arrive during tear-down skip notifyListeners().
    _disposed = true;
    _sub?.cancel();
    super.dispose();
  }
}
