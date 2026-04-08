// android_startup_sync.dart
//
// AndroidStartupSync — synchronises Android foreground service state with
// the Rust backend.
//
// WHAT THIS FILE DOES:
// --------------------
// The Rust backend needs to know whether the Android foreground service is
// running so it can make informed decisions about routing behaviour (e.g.
// whether to aggressively keep-alive connections or conserve resources).
//
// AndroidStartupSync.syncCurrentState() is the bridge between the two:
//
//   1. Call AndroidStartupBridge.ensureStartupService() to make sure the
//      foreground service is actually started.
//
//   2. Call AndroidStartupBridge.getStartupState() to get the current state
//      map from Kotlin.
//
//   3. If the state is non-empty, push it to Rust via
//      BackendBridge.updateAndroidStartupState().
//
//   4. Return the backend's view of the state so the caller has a consistent
//      snapshot without needing a second round-trip.
//
// CALLED FROM:
// ------------
// Typically called once during app resume (AppLifecycleState.resumed) and
// once during the initial startup sequence before the main shell renders.

import '../backend/backend_bridge.dart';
import 'android_startup_bridge.dart';

/// Synchronises Android foreground service state with the Rust backend.
///
/// All methods are static — this class is a stateless utility namespace.
class AndroidStartupSync {
  // Private constructor prevents instantiation.
  AndroidStartupSync._();

  /// Ensure the Android foreground service is running and push its state to Rust.
  ///
  /// Returns the backend's current view of the startup state Map.
  ///
  /// If the Kotlin side returns an empty map (non-Android, service unavailable,
  /// or Kotlin error), the state push is skipped and the backend's last-known
  /// state is returned unchanged.  This prevents overwriting a valid cached
  /// state with empty data on a transient Kotlin error.
  static Future<Map<String, dynamic>> syncCurrentState(
    BackendBridge bridge,
  ) async {
    // Start the foreground service if it isn't already running.  This is a
    // no-op on non-Android platforms (returns false safely).
    await AndroidStartupBridge.instance.ensureStartupService();

    // Fetch the current service state from Kotlin.
    final state = await AndroidStartupBridge.instance.getStartupState();

    if (state.isEmpty) {
      // Empty state means the Kotlin side had nothing to report (either
      // non-Android platform or the service hasn't started yet).
      // Return the backend's existing state rather than overwriting it.
      return bridge.getAndroidStartupState();
    }

    // Push the fresh state to Rust so it can update its cached ProximityState
    // (which drives routing behaviour decisions).
    bridge.updateAndroidStartupState(state);

    // Return the backend's updated view of the state.
    return bridge.getAndroidStartupState();
  }
}
