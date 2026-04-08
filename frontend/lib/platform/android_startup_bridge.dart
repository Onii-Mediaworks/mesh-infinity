// android_startup_bridge.dart
//
// AndroidStartupBridge — Flutter-side platform channel for Android foreground
// service startup and state queries.
//
// WHAT THIS IS FOR:
// -----------------
// On Android, background execution is tightly restricted.  If the user leaves
// Mesh Infinity and Android decides to kill it to reclaim memory, the mesh
// transport layer stops.  To maintain mesh connectivity even when the app is
// in the background (e.g. to continue routing for other nodes, or to receive
// messages while the screen is off), the app registers a Foreground Service.
//
// A Foreground Service is an Android component that:
//   - Shows a persistent notification (so the user knows the app is running).
//   - Is exempt from most background process restrictions.
//   - Survives system-initiated process death long enough to finish pending work.
//
// AndroidStartupBridge has two responsibilities:
//
//   ensureStartupService() — tells the Kotlin side to start the foreground
//                            service if it isn't already running.  Called on
//                            app resume and after backend initialisation.
//
//   getStartupState()      — retrieves the current service state from Kotlin
//                            as a flat Map.  The state is then pushed to the
//                            Rust backend via AndroidStartupSync so the backend
//                            can make routing decisions based on whether the
//                            foreground service is active.
//
// PLATFORM CHANNEL:
// -----------------
//   MethodChannel 'mesh_infinity/android_startup'
//   Kotlin handler: MeshStartupChannel (registered in MainActivity.kt)

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Platform channel bridge for Android foreground service lifecycle.
///
/// Access via [AndroidStartupBridge.instance].  Returns safe no-op values
/// on non-Android platforms.
class AndroidStartupBridge {
  // Private constructor — use [instance].
  AndroidStartupBridge._();

  /// Singleton.  One instance per app lifetime.
  static final AndroidStartupBridge instance = AndroidStartupBridge._();

  /// Channel name — must match the Kotlin registration exactly.
  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_startup',
  );

  /// True only on Android (non-web).
  ///
  /// On non-Android platforms all methods return safe empty/false values so
  /// callers don't need platform guards.
  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  // ---------------------------------------------------------------------------
  // State query
  // ---------------------------------------------------------------------------

  /// Return the current foreground service state as a flat string-keyed Map.
  ///
  /// The map contains fields such as:
  ///   'serviceRunning' (bool) — whether the foreground service is active.
  ///   'startedAt'     (int)  — epoch milliseconds when the service started.
  ///
  /// Returns an empty map on non-Android or if the Kotlin side returns null.
  Future<Map<String, dynamic>> getStartupState() async {
    if (!isSupported) {
      // Non-Android: no service state to report.
      return const {};
    }

    final raw = await _methodChannel.invokeMethod<Object?>('getStartupState');

    // The Kotlin side returns a Map<String, Object>.  Over the codec this
    // arrives as Map<Object?, Object?>.  We convert keys to strings here so
    // the rest of the app can use Map<String, dynamic> throughout.
    return raw is Map<Object?, Object?>
        ? raw.map(
            (key, value) => MapEntry(key.toString(), value),
          )
        : const {};
  }

  // ---------------------------------------------------------------------------
  // Service lifecycle
  // ---------------------------------------------------------------------------

  /// Start the Android foreground service if it is not already running.
  ///
  /// Returns true if the service was started or was already running.
  /// Returns false if Kotlin could not start the service (e.g. missing
  /// FOREGROUND_SERVICE permission, or the device is in battery saver mode
  /// and has blocked background services).
  ///
  /// On non-Android platforms, returns false (no service to start).
  Future<bool> ensureStartupService() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('ensureStartupService');
    return raw == true;
  }
}
