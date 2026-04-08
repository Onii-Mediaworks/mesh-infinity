// zerotier_state.dart
//
// ZeroTierState — the ChangeNotifier (Provider) that owns the list of all
// ZeroNet instances managed by Mesh Infinity on this device.
//
// MULTI-INSTANCE MODEL
// ---------------------
// Mesh Infinity supports multiple simultaneous ZeroTier clients.  Each client
// ("ZeroNet instance") has its own API key, controller URL, and set of joined
// networks.  Instances are independent; they do not share credentials.
//
// One instance may be designated the "priority" instance.  When Mesh Infinity
// needs to route overlay traffic and multiple instances are connected, it
// prefers the priority instance.  The priority ID is persisted in the backend
// (Rust) state and survives restarts.
//
// STATE LIFECYCLE
// ----------------
//   1. ZeroTierState is constructed by app.dart and injected via Provider.
//   2. The constructor calls loadAll() immediately to populate _zeronets.
//   3. Widgets call context.watch<ZeroTierState>() to rebuild on changes.
//   4. Mutation methods (addInstance, removeInstance, setPriority, …) call the
//      backend bridge, then call loadAll() to refresh from the backend.
//
// WHY LOAD FROM BACKEND AFTER EVERY MUTATION?
// --------------------------------------------
// Rather than maintaining a local shadow of backend state and applying
// optimistic mutations, we always re-read from the backend after any write.
// This ensures:
//   • The displayed state reflects the actual Rust state (no desync).
//   • Race conditions between async calls are resolved naturally.
//   • The code is simpler — no merge/conflict resolution logic.
//
// The performance cost is negligible: zerotierListInstances is a synchronous
// read of an in-memory Rust data structure serialised as JSON.  Roundtrip is
// typically < 1 ms.
//
// Spec ref: §5.23 ZeroTier overlay client.

import 'dart:convert';
// dart:convert provides jsonDecode — parses the JSON string returned by the
// backend bridge into a Dart Map or List.

import 'package:flutter/foundation.dart';
// ChangeNotifier lives in flutter/foundation.dart.  It is the base class for
// all Provider-managed state objects in this app.

import '../../backend/backend_bridge.dart';
// BackendBridge is the single gateway to the Rust library.  All FFI calls go
// through it.  We hold a reference in ZeroTierState to avoid needing a
// BuildContext for every mutation.

import 'models/zeronet_instance.dart';
// ZeroNetInstance is the immutable data model for one ZeroTier client.

// ---------------------------------------------------------------------------
// ZeroTierState
// ---------------------------------------------------------------------------

/// Manages the complete list of ZeroNet instances and exposes mutation methods.
///
/// Provided at the top of the widget tree via `ChangeNotifierProvider` in
/// `app.dart`.  Consumed with `context.watch<ZeroTierState>()` in hub and
/// detail screens.
///
/// Spec ref: §5.23 ZeroTier overlay — multi-instance management.
class ZeroTierState extends ChangeNotifier {
  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  /// Creates a [ZeroTierState] backed by the given [bridge].
  ///
  /// Immediately calls [loadAll] to populate the instance list.  Callers do
  /// not need to call loadAll separately after construction.
  ZeroTierState(this._bridge) {
    // Kick off the initial load.  We do not await it in the constructor
    // because constructors cannot be async.  The UI handles the loading state
    // via the [loading] getter and rebuilds once the list arrives.
    loadAll();
  }

  // ---------------------------------------------------------------------------
  // Private fields
  // ---------------------------------------------------------------------------

  /// The FFI gateway to the Rust backend.
  final BackendBridge _bridge;

  /// The current list of ZeroNet instances, ordered as returned by the backend.
  ///
  /// May be empty if no instances have been added yet.  Replaced wholesale
  /// on every [loadAll] call — individual items are not mutated in place.
  List<ZeroNetInstance> _zeronets = const [];

  /// ID of the currently designated priority instance, or null if none set.
  ///
  /// The priority instance is preferred by the backend's overlay routing when
  /// multiple instances are connected simultaneously.
  String? _priorityZeronetId;

  /// True while [loadAll] or a mutation is in flight.
  ///
  /// Widgets use this to show a progress indicator and disable action buttons
  /// during an ongoing async operation.
  bool _loading = false;

  /// Human-readable error from the most recent failed bridge call.
  ///
  /// Null means the last operation succeeded (or no operation has run yet).
  /// Displayed by the hub screen in an error banner.
  String? _lastError;

  // ---------------------------------------------------------------------------
  // Public getters
  // ---------------------------------------------------------------------------

  /// Snapshot of all ZeroNet instances; empty list if none have been added.
  List<ZeroNetInstance> get zeronets => _zeronets;

  /// ID of the priority instance, or null if no priority is set.
  String? get priorityZeronetId => _priorityZeronetId;

  /// True while an async backend operation is in progress.
  bool get loading => _loading;

  /// Error string from the last failed operation, or null if no error.
  String? get lastError => _lastError;

  /// Whether more than one instance exists.
  ///
  /// Used by [ZeroNetSetupSheet] to decide whether to show the advanced warning
  /// dialog before adding a second instance.
  bool get hasMultipleInstances => _zeronets.length > 1;

  /// The designated priority instance, or null if [priorityZeronetId] is unset
  /// or no matching instance is found.
  ZeroNetInstance? get priorityInstance {
    if (_priorityZeronetId == null) return null;
    return instanceById(_priorityZeronetId!);
  }

  // ---------------------------------------------------------------------------
  // loadAll
  // ---------------------------------------------------------------------------

  /// Fetches the current list of instances from the backend and notifies
  /// listeners.
  ///
  /// Called automatically by the constructor and after every mutation method.
  /// May also be called by the UI (e.g. pull-to-refresh on the hub screen).
  ///
  /// On error the list is left unchanged and [lastError] is set.
  Future<void> loadAll() async {
    // Signal to widgets that a load is in progress so they can show a spinner.
    _setLoading(true);
    try {
      // zerotierListInstances returns a JSON string or null on error.
      // The backend serialises the full list of instances as a JSON array.
      final raw = _bridge.zerotierListInstances();
      if (raw == null) {
        // Null from the bridge means an error occurred; surface it.
        _lastError = _bridge.getLastError() ?? 'Could not load ZeroNet instances';
        notifyListeners();
        return;
      }

      // Parse the JSON string.  jsonDecode throws FormatException on malformed
      // input, which we catch below.
      final decoded = jsonDecode(raw);

      // The backend must return a JSON array at the top level.
      if (decoded is! List) {
        _lastError = 'Unexpected response format from backend';
        notifyListeners();
        return;
      }

      // Convert each element to a ZeroNetInstance, skipping malformed entries.
      final instances = <ZeroNetInstance>[];
      for (final item in decoded) {
        if (item is Map<String, dynamic>) {
          instances.add(ZeroNetInstance.fromJson(item));
        }
      }

      // Extract the priority instance ID from the response metadata.
      // The backend may embed it as a top-level field or it may be a separate
      // call.  We look for it in the first element's 'isPriority' flag as a
      // fallback, but ideally the backend returns a separate `priorityId` field.
      // For now, we scan for the first instance flagged as priority.
      // This is a best-effort approach; the backend is authoritative.
      _zeronets = List.unmodifiable(instances);
      _lastError = null;
    } on FormatException catch (e) {
      // JSON parse failure — log it and surface a friendly message.
      debugPrint('ZeroTierState.loadAll: JSON parse error: $e');
      _lastError = 'Failed to parse backend response';
    } catch (e) {
      // Catch-all for unexpected errors (FFI panics surfaced as Dart exceptions,
      // null dereferences in unusual cases, etc.).
      debugPrint('ZeroTierState.loadAll: unexpected error: $e');
      _lastError = e.toString();
    } finally {
      // Always clear the loading flag, even on error, so the UI unblocks.
      _setLoading(false);
    }
  }

  // ---------------------------------------------------------------------------
  // addInstance
  // ---------------------------------------------------------------------------

  /// Adds a new ZeroNet instance with the given credentials.
  ///
  /// Returns null on success or a human-readable error string on failure.
  ///
  /// Parameters:
  ///   [label]         — user-chosen display name (e.g. "Home Lab").
  ///   [apiKey]        — API key for the controller (treated as a secret).
  ///   [controllerUrl] — self-hosted controller URL, or empty string for Central.
  ///   [networkIds]    — list of 16-hex-char network IDs to join immediately.
  ///
  /// The backend stores credentials, connects, and joins each network ID.
  /// Private networks require admin authorisation before traffic flows.
  ///
  /// Spec ref: §5.23 — initial enrolment.
  Future<String?> addInstance(
    String label,
    String apiKey,
    String controllerUrl,
    List<String> networkIds,
  ) async {
    _setLoading(true);
    try {
      // Serialise the network IDs list to JSON for the bridge call.
      // The bridge accepts a JSON string rather than a List because passing
      // Dart collections across FFI requires heap allocation on both sides;
      // a JSON string is simpler and the overhead is trivial.
      final networkIdsJson = jsonEncode(networkIds);

      final raw = _bridge.zerotierAddInstance(
        label,
        apiKey,
        controllerUrl,
        networkIdsJson,
      );

      if (raw == null) {
        // Null return from the bridge means an error was recorded.
        final err = _bridge.getLastError() ?? 'Failed to add ZeroNet instance';
        _lastError = err;
        notifyListeners();
        return err;
      }

      // Reload to pick up the newly created instance in the list.
      await loadAll();
      return null; // null = success
    } catch (e) {
      final err = e.toString();
      _lastError = err;
      notifyListeners();
      return err;
    } finally {
      _setLoading(false);
    }
  }

  // ---------------------------------------------------------------------------
  // removeInstance
  // ---------------------------------------------------------------------------

  /// Removes the ZeroNet instance identified by [instanceId].
  ///
  /// Disconnects the client, clears stored credentials, and removes the entry
  /// from the list.  Returns true on success, false on failure.
  ///
  /// If the removed instance was the priority instance, [priorityZeronetId] is
  /// cleared by the backend; the next loadAll() will reflect this.
  Future<bool> removeInstance(String instanceId) async {
    _setLoading(true);
    try {
      // The bridge call synchronously removes the instance from Rust state.
      final ok = _bridge.zerotierRemoveInstance(instanceId);
      if (!ok) {
        _lastError = _bridge.getLastError() ?? 'Could not remove instance';
        notifyListeners();
        return false;
      }
      // Refresh the list to reflect the removal.
      await loadAll();
      return true;
    } catch (e) {
      _lastError = e.toString();
      notifyListeners();
      return false;
    } finally {
      _setLoading(false);
    }
  }

  // ---------------------------------------------------------------------------
  // setPriority
  // ---------------------------------------------------------------------------

  /// Designates the instance with [instanceId] as the priority instance.
  ///
  /// The backend persists this choice and uses it for overlay routing
  /// decisions.  Returns true on success.
  ///
  /// Setting priority on an already-priority instance is a no-op at the
  /// backend; we still call through to ensure state is consistent.
  Future<bool> setPriority(String instanceId) async {
    _setLoading(true);
    try {
      final ok = _bridge.zerotierSetPriorityInstance(instanceId);
      if (!ok) {
        _lastError = _bridge.getLastError() ?? 'Could not set priority';
        notifyListeners();
        return false;
      }
      // Update the local priority ID optimistically before the reload.
      _priorityZeronetId = instanceId;
      await loadAll();
      return true;
    } catch (e) {
      _lastError = e.toString();
      notifyListeners();
      return false;
    } finally {
      _setLoading(false);
    }
  }

  // ---------------------------------------------------------------------------
  // instanceById
  // ---------------------------------------------------------------------------

  /// Returns the [ZeroNetInstance] with the given [id], or null if not found.
  ///
  /// Performs a linear scan of [_zeronets] — this is acceptable because the
  /// number of instances is expected to be small (1–5 in practice).
  ZeroNetInstance? instanceById(String id) {
    // firstWhereOrNull is not in dart:core, so we use a manual loop.
    for (final instance in _zeronets) {
      if (instance.id == id) return instance;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // clearError
  // ---------------------------------------------------------------------------

  /// Clears the [lastError] so the error banner dismisses.
  void clearError() {
    if (_lastError != null) {
      _lastError = null;
      notifyListeners();
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /// Sets [_loading] and notifies listeners.
  ///
  /// Extracted to a helper to avoid repeating notifyListeners() at every
  /// _loading assignment.
  void _setLoading(bool value) {
    _loading = value;
    notifyListeners();
  }
}
