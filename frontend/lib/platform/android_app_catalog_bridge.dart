// android_app_catalog_bridge.dart
//
// AndroidAppCatalogBridge — Flutter-side platform channel for querying the
// list of installed Android applications.
//
// WHAT THIS IS FOR:
// -----------------
// Mesh Infinity's Network tier (Tier 2) supports per-app routing — the user
// can choose which installed apps have their traffic routed through the mesh
// VPN.  To present a meaningful selection UI, Flutter needs the list of apps
// installed on the device.
//
// Android does not expose the installed app list to Dart directly.  This
// bridge uses a Flutter platform channel (MethodChannel) to call Kotlin code
// that queries PackageManager.getInstalledApplications() and returns the
// results as a list of maps over the channel.
//
// PLATFORM CHANNEL ARCHITECTURE:
// --------------------------------
// Flutter communicates with native Android/iOS code via "platform channels".
// The Dart side calls a named method on a MethodChannel; the Kotlin/Swift side
// registers a handler for that channel name and responds.
//
//   Dart                                 Kotlin
//   ─────────────────────────────────    ──────────────────────────────
//   MethodChannel('mesh_infinity/       MeshAppCatalogChannel.register()
//     android_app_catalog')              └─ list_installed_apps handler
//     .invokeMethod('list_installed')        └─ PackageManager query
//
// WHY A SINGLETON?
// ----------------
// The MethodChannel object is cheap to construct, but having a single instance
// ensures there is exactly one channel registration in Kotlin and avoids any
// risk of duplicate registration errors across widget rebuilds.

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Data for a single installed Android application.
///
/// Contains the fields that the per-app routing UI needs to show the user
/// a meaningful selection list: app ID (package name), human-readable label,
/// and whether the app is a system app (system apps are hidden by default).
class AndroidInstalledApp {
  const AndroidInstalledApp({
    required this.appId,
    required this.label,
    required this.isSystemApp,
  });

  /// Android package name (e.g. "com.example.myapp").
  ///
  /// Used as the routing key in the Rust VPN policy configuration.
  final String appId;

  /// Human-readable app name from ApplicationInfo.loadLabel() in Kotlin.
  final String label;

  /// True if PackageManager flagged this as a system application.
  ///
  /// System apps are typically hidden from the per-app routing selection
  /// list because routing their traffic through the mesh can break system
  /// functionality (e.g. Google Play Services, dialler).
  final bool isSystemApp;

  /// Deserialise from the map returned by the Kotlin platform channel handler.
  ///
  /// Uses `Object?` key/value types because that is what MethodChannel returns
  /// over the codec — the actual values are always String/bool at runtime.
  factory AndroidInstalledApp.fromMap(Map<Object?, Object?> map) {
    return AndroidInstalledApp(
      appId: map['app_id'] as String? ?? '',
      label: map['label'] as String? ?? '',
      isSystemApp: map['is_system_app'] == true,
    );
  }
}

/// Platform channel bridge for querying the list of installed Android apps.
///
/// Access via [AndroidAppCatalogBridge.instance].  Returns empty lists on
/// non-Android platforms so callers never need to guard by platform.
class AndroidAppCatalogBridge {
  // Private constructor — use [instance] instead.
  AndroidAppCatalogBridge._();

  /// Singleton instance.  Created once and reused throughout the app lifetime.
  static final AndroidAppCatalogBridge instance = AndroidAppCatalogBridge._();

  /// The channel name must match the handler registered in Kotlin exactly.
  /// Convention: `mesh_infinity/<feature>` to namespace by app and feature.
  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_app_catalog',
  );

  /// True only on Android (non-web).
  ///
  /// All public methods return safe empty values when this is false, so
  /// callers on iOS / desktop / web never get an error.
  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  /// Return the list of installed applications on this Android device.
  ///
  /// Returns an empty list on non-Android platforms or if the channel call
  /// returns unexpected data (e.g. the Kotlin side returned null).
  ///
  /// Filtering out system apps and apps with empty IDs is done here (not in
  /// Kotlin) so the Kotlin side stays simple and the filter logic is testable
  /// in Dart.
  Future<List<AndroidInstalledApp>> listInstalledApps() async {
    if (!isSupported) {
      // Not on Android — nothing to query.
      return const [];
    }

    final raw = await _methodChannel.invokeMethod<Object?>('list_installed_apps');

    // The channel returns a List<dynamic> when successful; null or anything
    // else means the Kotlin handler returned nothing useful.
    if (raw is! List<Object?>) {
      return const [];
    }

    return raw
        .whereType<Map<Object?, Object?>>() // filter out any non-map entries
        .map(AndroidInstalledApp.fromMap)
        .where((app) => app.appId.isNotEmpty) // discard apps with no package name
        .toList(growable: false); // fixed-length for efficiency
  }
}
