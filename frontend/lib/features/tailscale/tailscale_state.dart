// tailscale_state.dart
//
// TailscaleState — the ChangeNotifier that owns all multi-instance Tailscale
// data and mediates every backend call related to Tailscale instances.
//
// ARCHITECTURE ROLE
// -----------------
// TailscaleState sits between the UI and the backend bridge:
//
//   UI widgets
//     ↓ context.read<TailscaleState>().someMethod()
//   TailscaleState   ← this file
//     ↓ bridge.tailscaleXxx()
//   BackendBridge (FFI → Rust)
//
// UI widgets NEVER call bridge methods directly for Tailscale operations.
// This keeps the FFI surface in one place, makes testing easier (mock
// TailscaleState, not the bridge), and allows us to add loading/error
// state uniformly without duplicating it across screens.
//
// WHY CHANGETNOTIFIER?
// --------------------
// Flutter's Provider package is built around ChangeNotifier.  When state
// changes, notifyListeners() is called and all widgets that called
// context.watch<TailscaleState>() are scheduled for rebuild.  This is
// deliberately simple — no streams, no Redux, no bloc.  The existing codebase
// (NetworkState, MessagingState, etc.) all follow this same pattern.
//
// LOADING GUARD PATTERN
// ---------------------
// _loading is set to true at the start of any async operation and false when
// it completes (in a finally block).  Buttons check _loading to prevent
// double-submission.  We call notifyListeners() immediately when _loading
// changes so the UI can show/hide spinners without waiting for the async
// result.
//
// PRIORITY INSTANCE
// -----------------
// When multiple tailnet instances are active, one is designated "priority".
// The priority instance's routing policy takes precedence when there is a
// conflict (e.g. both instances could route the same destination prefix).
// The backend enforces this; TailscaleState just tracks which instance the
// user has designated as priority and surfaces it to the UI.
//
// EVENT BUS SUBSCRIPTION
// ----------------------
// TailscaleState subscribes to EventBus for two event types:
//
//   TailscaleKeyExpiryWarningEvent — updates the warning badge count shown
//     in the nav drawer so the user knows to re-authenticate even when they
//     are not looking at the Tailscale hub screen.
//
//   OverlayStatusChangedEvent — triggers a reload so status changes pushed
//     by the Rust backend (e.g. "connected" after OAuth completes) are
//     reflected immediately without requiring a manual refresh.
//
// See §5.22 of the spec for the multi-instance overlay design.

import 'dart:async';
// dart:async: StreamSubscription — needed to hold and cancel the EventBus
// subscription when this ChangeNotifier is disposed.

import 'dart:convert';
// dart:convert: jsonDecode — parses the JSON string returned by the bridge
// into Dart Maps and Lists.

import 'package:flutter/foundation.dart';
// ChangeNotifier — the base class for Provider-pattern state objects.

import '../../backend/backend_bridge.dart';
// BackendBridge — the FFI gateway.  TailscaleState holds a reference to it
// and calls the tailscaleXxx() methods defined on it.

import '../../backend/event_bus.dart';
// EventBus — singleton background isolate that polls Rust for events and
// delivers them as a Dart Stream.

import '../../backend/event_models.dart';
// BackendEvent, TailscaleKeyExpiryWarningEvent, OverlayStatusChangedEvent —
// the typed event hierarchy produced by event_bus.dart.

import '../../features/network/network_state.dart';
// OverlayClientStatus — imported directly here so TailscaleState and all
// files that import only tailscale_state.dart can reference it without
// needing an additional import from network_state.dart.

import 'models/tailnet_instance.dart';
// TailnetInstance — the Dart model for one tailnet connection.

// ---------------------------------------------------------------------------
// TailscaleState
// ---------------------------------------------------------------------------

/// State object for the multi-instance Tailscale hub.
///
/// Provided at the app level via Provider (registered in app.dart alongside
/// NetworkState, MessagingState, etc.).  All screens and widgets in
/// `features/tailscale/` consume it via `context.watch<TailscaleState>()` or
/// `context.read<TailscaleState>()`.
///
/// Spec reference: §5.22 (multi-instance Tailscale overlay management)
class TailscaleState extends ChangeNotifier {
  // -------------------------------------------------------------------------
  // Constructor
  // -------------------------------------------------------------------------

  /// Creates a [TailscaleState] bound to the given [bridge].
  ///
  /// Immediately subscribes to the EventBus and performs an initial load so
  /// the hub screen is populated as soon as it is shown.
  TailscaleState(this._bridge) {
    // Subscribe to the shared EventBus stream.  We receive ALL backend events
    // here and filter for the ones we care about inside _onEvent().
    _eventSub = EventBus.instance.stream.listen(_onEvent);

    // Perform the first load.  This is async — the constructor returns before
    // it completes, but widgets will rebuild when notifyListeners() fires.
    loadAll();
  }

  // -------------------------------------------------------------------------
  // Private fields
  // -------------------------------------------------------------------------

  /// The FFI gateway — our only path to the Rust backend.
  final BackendBridge _bridge;

  /// Active EventBus subscription.  Cancelled in dispose() to prevent
  /// "setState called after dispose" exceptions.
  StreamSubscription<BackendEvent>? _eventSub;

  /// Guard: becomes true after dispose() to prevent notifyListeners() calls
  /// on a dead ChangeNotifier (asynchronous events can arrive after cancel()).
  bool _disposed = false;

  /// The list of currently known tailnet instances, ordered as returned by the
  /// backend (backend maintains insertion order).
  ///
  /// Empty list = no tailnets configured yet (show empty state in hub).
  List<TailnetInstance> _tailnets = [];

  /// The ID of the instance currently designated as "priority".
  ///
  /// Null means the backend has not set a priority (use [priorityInstance]
  /// getter which falls back to "first connected" then "first in list").
  String? _priorityTailnetId;

  /// True while an async bridge call is in flight.
  ///
  /// Checked by UI buttons to show spinners and prevent double-submission.
  bool _loading = false;

  /// The human-readable error from the most recent failed bridge call, or null.
  ///
  /// Shown inline in hub screens.  Cleared at the start of each new operation.
  String? _lastError;

  /// Count of instances with key expiry warnings currently active.
  ///
  /// Driven by TailscaleKeyExpiryWarningEvent from the event bus.
  /// Can be used by nav drawer badge logic.
  int _expiryWarningCount = 0;

  // -------------------------------------------------------------------------
  // Public read-only accessors
  // -------------------------------------------------------------------------

  /// The list of all managed tailnet instances.
  ///
  /// An empty list means no tailnets have been configured.  The hub screen
  /// shows an empty-state CTA when this is empty.
  List<TailnetInstance> get tailnets => List.unmodifiable(_tailnets);

  /// The ID of the priority instance, or null if none has been set explicitly.
  ///
  /// Use [priorityInstance] for a resolved (never-null-if-non-empty) version.
  String? get priorityTailnetId => _priorityTailnetId;

  /// True while any async bridge call is in flight.
  bool get loading => _loading;

  /// Human-readable error from the last failed operation, or null.
  String? get lastError => _lastError;

  /// Number of instances currently showing a key-expiry warning.
  int get expiryWarningCount => _expiryWarningCount;

  // -------------------------------------------------------------------------
  // Derived / computed accessors
  // -------------------------------------------------------------------------

  /// The priority instance — the one with highest routing precedence.
  ///
  /// Resolution order:
  ///   1. The instance whose id == [_priorityTailnetId], if set and present.
  ///   2. The first instance whose status == connected.
  ///   3. The first instance in the list.
  ///   4. Null if the list is empty.
  ///
  /// This fallback chain ensures the UI always has a "primary" instance to
  /// highlight even before the user has explicitly set a priority.
  TailnetInstance? get priorityInstance {
    if (_tailnets.isEmpty) return null;

    // 1. Explicit priority set by the user.
    if (_priorityTailnetId != null) {
      final explicit = instanceById(_priorityTailnetId!);
      if (explicit != null) return explicit;
    }

    // 2. First connected instance — a sensible auto-selection.
    final connected = _tailnets
        .where((t) => t.status == OverlayClientStatus.connected)
        .firstOrNull;
    if (connected != null) return connected;

    // 3. First in list as last resort.
    return _tailnets.first;
  }

  /// Look up an instance by its opaque id string.
  ///
  /// Returns null if no instance with that id is currently in the list.
  /// This can happen if the instance was removed between the time the UI
  /// captured the id and the time it tries to use it.
  TailnetInstance? instanceById(String id) {
    // firstWhereOrNull from collection package — safe alternative to
    // firstWhere with an orElse: () => null.
    for (final t in _tailnets) {
      if (t.id == id) return t;
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // loadAll — primary data refresh
  // -------------------------------------------------------------------------

  /// Refresh the full instance list from the backend.
  ///
  /// Called:
  ///   - On construction (initial population).
  ///   - After every mutating bridge call (addInstance, removeInstance, etc.)
  ///     so the UI always reflects the latest backend state.
  ///   - In response to OverlayStatusChangedEvent from the event bus.
  ///
  /// On success: updates [_tailnets] and [_priorityTailnetId], notifies
  ///             listeners so widgets rebuild.
  /// On failure: sets [_lastError], notifies listeners so error is shown.
  Future<void> loadAll() async {
    // Do not set _loading here — loadAll() is called frequently (including
    // from event handlers) and showing a spinner on every poll would be
    // distracting.  _loading is only set for user-initiated mutating calls.
    _lastError = null;

    try {
      // so no further changes are needed to this file once the bridge is ready.
      final raw = _bridge.tailscaleListInstances();

      if (raw == null || raw.isEmpty) {
        // Null or empty string means "no instances" — treat as empty list
        // rather than an error.  This is the initial state for a new install.
        _tailnets = [];
        _priorityTailnetId = null;
        _safeNotify();
        return;
      }

      // Parse the JSON array.
      // Expected top-level shape: { "instances": [...], "priorityId": "..." }
      // OR a bare array: [...]
      // We handle both to be robust against backend response format changes.
      final decoded = jsonDecode(raw);

      List<dynamic> instanceList;
      String? parsedPriorityId;

      if (decoded is Map<String, dynamic>) {
        // Object wrapper form — allows the backend to add top-level metadata.
        instanceList = (decoded['instances'] as List?) ?? [];
        parsedPriorityId = decoded['priorityId'] as String?;
      } else if (decoded is List) {
        // Bare array form — simpler but no priority metadata field.
        instanceList = decoded;
      } else {
        // Unexpected JSON structure — treat as empty and surface an error.
        throw FormatException(
          'tailscaleListInstances() returned unexpected JSON type: '
          '${decoded.runtimeType}',
        );
      }

      // Map each raw JSON element to a typed TailnetInstance.
      // Malformed elements are skipped (withType + cast) rather than crashing.
      _tailnets = instanceList
          .whereType<Map<String, dynamic>>()
          .map(TailnetInstance.fromJson)
          .toList();

      _priorityTailnetId = parsedPriorityId;

      // Recompute the expiry warning count from the freshly loaded instances.
      _expiryWarningCount =
          _tailnets.where((t) => t.isKeyExpiringSoon).length;
    } catch (e) {
      // Parsing failures and bridge null returns are both caught here.
      // We show the error inline rather than crashing — the previous list
      // state is preserved so the hub screen remains usable.
      _lastError = e.toString().replaceFirst('Exception: ', '');
    }

    _safeNotify();
  }

  // -------------------------------------------------------------------------
  // addInstance — enrol a new tailnet
  // -------------------------------------------------------------------------

  /// Enrol a new tailnet instance with the given [label] and [controlUrl].
  ///
  /// [label] — user-chosen name, e.g. "Work" or "Home".  Must not be empty.
  ///
  /// [controlUrl] — the control server URL.  Pass an empty string to use
  ///   Tailscale's vendor control plane (controlplane.tailscale.com).
  ///   Pass a Headscale URL for self-hosted setups.
  ///
  /// Returns the new instance's id on success, or null on failure (in which
  /// case [_lastError] is set and widgets should show it).
  ///
  /// NOTE: The caller (TailnetSetupSheet) is responsible for showing the
  /// [AdvancedWarningDialog] BEFORE calling this method when [tailnets.length]
  /// >= 1.  This state method does not show UI.
  Future<String?> addInstance(String label, String controlUrl) async {
    if (label.trim().isEmpty) {
      _lastError = 'Label is required';
      _safeNotify();
      return null;
    }

    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final raw = _bridge.tailscaleAddInstance(label.trim(), controlUrl.trim());

      if (raw == null || raw.isEmpty) {
        throw Exception(
          _bridge.getLastError() ?? 'Failed to add tailnet instance',
        );
      }

      // Parse the returned JSON to extract the new instance's id.
      final decoded = jsonDecode(raw) as Map<String, dynamic>?;
      final newId = decoded?['id'] as String?;

      if (newId == null || newId.isEmpty) {
        throw Exception('Backend returned invalid instance id');
      }

      // Reload the full list so the new instance appears immediately.
      await loadAll();
      return newId;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return null;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // removeInstance
  // -------------------------------------------------------------------------

  /// Remove the tailnet instance with the given [instanceId].
  ///
  /// This disconnects the WireGuard interface, deletes the stored credentials,
  /// and removes the row from the backend's instance table.  The operation is
  /// irreversible — the user must re-enrol to re-add the tailnet.
  ///
  /// Returns true on success, false on failure (lastError is set).
  Future<bool> removeInstance(String instanceId) async {
    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final ok = _bridge.tailscaleRemoveInstance(instanceId);

      if (!ok) {
        throw Exception(
          _bridge.getLastError() ?? 'Failed to remove tailnet instance',
        );
      }

      // Clear priority if we just removed the priority instance.
      if (_priorityTailnetId == instanceId) {
        _priorityTailnetId = null;
      }

      await loadAll();
      return true;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return false;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // setPriority
  // -------------------------------------------------------------------------

  /// Designate the instance with [instanceId] as the priority tailnet.
  ///
  /// The backend records this preference and uses it to resolve routing
  /// conflicts when two active instances both advertise routes to the same
  /// destination prefix.
  ///
  /// Returns true on success, false on failure (lastError is set).
  Future<bool> setPriority(String instanceId) async {
    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final ok = _bridge.tailscaleSetPriorityInstance(instanceId);

      if (!ok) {
        throw Exception(
          _bridge.getLastError() ?? 'Failed to set priority tailnet',
        );
      }

      _priorityTailnetId = instanceId;
      await loadAll();
      return true;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return false;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // connectAuthKey
  // -------------------------------------------------------------------------

  /// Enrol [instanceId] using a pre-authentication key.
  ///
  /// Pre-auth keys are generated in the Tailscale admin panel or Headscale
  /// CLI.  They allow headless enrollment without an interactive OAuth flow —
  /// useful for servers or CI nodes where a browser is not available.
  ///
  /// [authKey]    — the key string, typically "tskey-auth-..." format.
  /// [controlUrl] — empty for vendor Tailscale, Headscale URL otherwise.
  ///
  /// Returns true on success, false on failure (lastError is set).
  Future<bool> connectAuthKey(
    String instanceId,
    String authKey,
    String controlUrl,
  ) async {
    if (authKey.trim().isEmpty) {
      _lastError = 'Auth key is required';
      _safeNotify();
      return false;
    }

    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final ok = _bridge.tailscaleAuthKeyInstance(
        instanceId,
        authKey.trim(),
        controlUrl.trim(),
      );

      if (!ok) {
        throw Exception(
          _bridge.getLastError() ?? 'Auth key enrollment failed',
        );
      }

      await loadAll();
      return true;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return false;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // beginOAuth
  // -------------------------------------------------------------------------

  /// Start an interactive OAuth browser flow for [instanceId].
  ///
  /// This opens the control server's login page in the system browser.
  /// When the user completes authentication, the backend receives a callback
  /// and fires TailscaleOAuthCompleteEvent.  The UI should subscribe to that
  /// event (via event_bus.dart) to know when to dismiss any loading UI.
  ///
  /// [controlUrl] — empty for Tailscale.com, Headscale URL for self-hosted.
  ///
  /// Returns true if the browser was successfully opened, false on failure.
  Future<bool> beginOAuth(String instanceId, String controlUrl) async {
    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final ok = _bridge.tailscaleBeginOAuthInstance(instanceId, controlUrl.trim());

      if (!ok) {
        throw Exception(
          _bridge.getLastError() ?? 'Could not start OAuth flow',
        );
      }

      // The OAuth flow is asynchronous — we set loading false now and let
      // TailscaleOAuthCompleteEvent / OverlayStatusChangedEvent trigger a reload.
      return true;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return false;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // disconnect
  // -------------------------------------------------------------------------

  /// Disconnect [instanceId] without removing its credentials.
  ///
  /// The instance remains in the list in a "disconnected" state.  The user
  /// can reconnect later without re-enrolling.  This is useful for temporarily
  /// disabling a tailnet (e.g. while travelling) without losing the setup.
  ///
  /// Returns true on success, false on failure (lastError is set).
  Future<bool> disconnect(String instanceId) async {
    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final ok = _bridge.tailscaleDisconnectInstance(instanceId);

      if (!ok) {
        throw Exception(
          _bridge.getLastError() ?? 'Could not disconnect tailnet',
        );
      }

      await loadAll();
      return true;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return false;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // refresh
  // -------------------------------------------------------------------------

  /// Re-sync [instanceId] state from its control server.
  ///
  /// Useful after the tailnet admin has changed ACLs, added peers, or when
  /// recovering after a network outage.  Forces the backend to poll the
  /// control server's /map endpoint and update local state.
  ///
  /// Returns true on success, false on failure (lastError is set).
  Future<bool> refresh(String instanceId) async {
    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final ok = _bridge.tailscaleRefreshInstance(instanceId);

      if (!ok) {
        throw Exception(
          _bridge.getLastError() ?? 'Could not refresh tailnet',
        );
      }

      await loadAll();
      return true;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return false;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // setPreferMeshRelay
  // -------------------------------------------------------------------------

  /// Toggle the mesh-relay preference for [instanceId].
  ///
  /// When [enabled] is true, Mesh Infinity prefers its own relay nodes over
  /// Tailscale's DERP servers.  See TailnetInstance.preferMeshRelay for why
  /// this matters from a privacy perspective.
  ///
  /// Returns true on success, false on failure (lastError is set).
  Future<bool> setPreferMeshRelay(String instanceId, bool enabled) async {
    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final ok = _bridge.tailscaleSetPreferMeshRelayInstance(instanceId, enabled);

      if (!ok) {
        throw Exception(
          _bridge.getLastError() ?? 'Could not update relay preference',
        );
      }

      await loadAll();
      return true;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return false;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // setExitNode
  // -------------------------------------------------------------------------

  /// Set or clear the exit node for [instanceId].
  ///
  /// [peerName] — the name of the peer to use as exit node.
  ///   Pass an empty string to clear the exit node selection (no exit routing).
  ///
  /// When an exit node is active, internet-bound traffic from this device
  /// is routed through the named peer's outgoing connection.  Websites see
  /// the exit node's IP address instead of this device's real IP.
  ///
  /// Returns true on success, false on failure (lastError is set).
  Future<bool> setExitNode(String instanceId, String peerName) async {
    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final ok = _bridge.tailscaleSetExitNodeInstance(instanceId, peerName);

      if (!ok) {
        throw Exception(
          _bridge.getLastError() ?? 'Could not update exit node',
        );
      }

      await loadAll();
      return true;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return false;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // reauth
  // -------------------------------------------------------------------------

  /// Trigger re-authentication for [instanceId] whose key is expiring.
  ///
  /// Opens the appropriate browser flow for the instance's controller type.
  /// After re-auth, the backend issues a new WireGuard key with a fresh
  /// expiry timestamp, dismissing the [KeyExpiryBanner].
  ///
  /// Returns true if the re-auth browser flow was successfully opened.
  Future<bool> reauth(String instanceId) async {
    _loading = true;
    _lastError = null;
    _safeNotify();

    try {
      final ok = _bridge.tailscaleReauthInstance(instanceId);

      if (!ok) {
        throw Exception(
          _bridge.getLastError() ?? 'Could not start re-authentication',
        );
      }

      // Re-auth is async (browser flow) — reload will be triggered by
      // OverlayStatusChangedEvent once the new key is stored.
      return true;
    } catch (e) {
      _lastError = e.toString().replaceFirst('Exception: ', '');
      _safeNotify();
      return false;
    } finally {
      _loading = false;
      _safeNotify();
    }
  }

  // -------------------------------------------------------------------------
  // clearError
  // -------------------------------------------------------------------------

  /// Clear the current error message.
  ///
  /// Called by the UI when the user dismisses an error banner, preventing the
  /// same stale error from being shown after a subsequent successful operation.
  void clearError() {
    _lastError = null;
    _safeNotify();
  }

  // -------------------------------------------------------------------------
  // EventBus handler
  // -------------------------------------------------------------------------

  /// Handle incoming backend events from the EventBus stream.
  ///
  /// We only act on events that are relevant to Tailscale multi-instance
  /// state.  All other event types are silently ignored — this follows the
  /// same pattern as NetworkState._onEvent().
  void _onEvent(BackendEvent event) {
    switch (event) {
      // OverlayStatusChangedEvent — the backend reports that a Tailscale
      // instance changed status (e.g. "connecting" → "connected").
      // We reload the full list so the UI reflects the new state.
      case OverlayStatusChangedEvent():
        // Reload is async but we don't await it here because _onEvent is
        // a synchronous stream handler.  The rebuild will happen after
        // loadAll() completes and calls notifyListeners().
        loadAll();

      // TailscaleKeyExpiryWarningEvent — the backend found that a key is
      // expiring within 7 days and wants to notify the user.
      // We increment the warning count so the nav drawer can show a badge.
      case TailscaleKeyExpiryWarningEvent(:final daysRemaining):
        // Log the days remaining for diagnostics.
        debugPrint(
          '[TailscaleState] Key expiry warning: $daysRemaining days remaining',
        );
        // The authoritative count comes from loadAll() — increment here
        // only as a fast update for the badge before the next reload fires.
        _expiryWarningCount =
            (_tailnets.where((t) => t.isKeyExpiringSoon).length)
                .clamp(1, 999); // at minimum 1 if an event arrived
        _safeNotify();

      // All other event types: ignore.
      default:
        break;
    }
  }

  // -------------------------------------------------------------------------
  // dispose
  // -------------------------------------------------------------------------

  @override
  void dispose() {
    // Cancel the EventBus subscription so the stream listener is not called
    // after this ChangeNotifier has been disposed.  Without this cancel() call
    // a "setState after dispose" exception would occur on the next event.
    _disposed = true;
    _eventSub?.cancel();
    super.dispose();
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /// Call notifyListeners() only if the ChangeNotifier has not been disposed.
  ///
  /// This guard is necessary because async operations (bridge calls, loadAll)
  /// may complete after the object has been disposed.  Without this check,
  /// calling notifyListeners() after dispose() causes a Flutter framework
  /// assertion error.
  void _safeNotify() {
    if (!_disposed) notifyListeners();
  }
}

// OverlayClientStatus is imported above from network_state.dart.
// Files in features/tailscale/ that need OverlayClientStatus should import
// network_state.dart directly or import tailnet_instance.dart which also
// imports it.
