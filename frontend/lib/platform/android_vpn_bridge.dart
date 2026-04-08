// android_vpn_bridge.dart
//
// AndroidVpnBridge — Flutter-side platform channel for the Android VpnService.
//
// WHAT THIS IS FOR:
// -----------------
// Android requires apps to use the VpnService API (android.net.VpnService) to
// intercept and route device traffic.  Flutter (Dart) cannot call the Android
// VpnService directly — it must go through a MethodChannel to Kotlin code that
// extends VpnService.
//
// This bridge has three responsibilities:
//
//   isPermissionGranted() — check whether the user has already granted VPN
//                           permission.  On Android, VPN permission is a
//                           one-time user consent dialog.  Granted permission
//                           persists until the user revokes it in system settings.
//
//   requestPermission()   — launch the VPN consent dialog.  Returns true when
//                           the user grants permission; false if they deny.
//
//   applyPolicy()         — push a routing policy (a flat Map) to the Kotlin
//                           VPN service.  The policy specifies which apps or
//                           destinations are routed through the mesh VPN.
//                           Encoded as JSON to avoid custom codec complexity.
//
//   getState()            — return the current VPN service state (connected,
//                           disconnected, bytes transferred, etc.).
//
// NON-ANDROID BEHAVIOUR:
// ----------------------
// On iOS, desktop, and web the VPN is managed differently (or not at all).
// All methods return "safe granted" values (true / null) so callers can
// proceed with normal logic without platform guards — the actual routing
// layer inside the backend handles the platform differences.
//
// PLATFORM CHANNEL:
// -----------------
//   MethodChannel 'mesh_infinity/android_vpn'
//   Kotlin handler: MeshVpnChannel (registered in MainActivity.kt)

import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Platform channel bridge for Android VpnService integration.
///
/// Access via [AndroidVpnBridge.instance].  Non-Android platforms return
/// safe permissive values so the VPN feature can be developed and tested
/// without conditional platform checks throughout the codebase.
class AndroidVpnBridge {
  // Private constructor — use [instance].
  AndroidVpnBridge._();

  /// Singleton.  One instance per app lifetime.
  static final AndroidVpnBridge instance = AndroidVpnBridge._();

  /// Channel name — must match the Kotlin handler registration exactly.
  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_vpn',
  );

  /// True only on Android (non-web).
  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  // ---------------------------------------------------------------------------
  // Permission
  // ---------------------------------------------------------------------------

  /// Check whether VPN permission has already been granted by the user.
  ///
  /// Returns true on non-Android (permission concept doesn't apply).
  /// Returns true on Android when VpnService.prepare() returns null (already
  /// granted); false when an Intent is returned (consent needed).
  Future<bool> isPermissionGranted() async {
    if (!isSupported) {
      // Non-Android: treat as granted so the feature can be exercised.
      return true;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'isPermissionGranted',
    );
    return raw == true;
  }

  /// Launch the Android VPN consent dialog.
  ///
  /// Returns true if the user grants permission; false if they deny or
  /// if the dialog could not be shown.  On non-Android returns true
  /// (no dialog needed).
  Future<bool> requestPermission() async {
    if (!isSupported) {
      return true;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('requestPermission');
    return raw == true;
  }

  // ---------------------------------------------------------------------------
  // Policy
  // ---------------------------------------------------------------------------

  /// Push a VPN routing policy to the Kotlin VPN service.
  ///
  /// [policy] is serialised to JSON before crossing the channel boundary.
  /// Using JSON avoids the need for a custom MethodChannel codec and keeps
  /// the policy format human-readable in logs.
  ///
  /// Returns true if the Kotlin side applied the policy successfully.
  /// Returns true on non-Android (no-op but not an error).
  ///
  /// A [PlatformException] from Kotlin (e.g. VpnService not yet started,
  /// or policy validation failed) is caught here and returns false — the
  /// caller sees a simple bool without needing to handle platform exceptions.
  Future<bool> applyPolicy(Map<String, dynamic> policy) async {
    if (!isSupported) {
      return true;
    }
    try {
      final raw = await _methodChannel.invokeMethod<Object?>('applyPolicy', {
        // JSON-encode the policy map so it crosses the MethodChannel codec as
        // a plain String rather than a nested Map (avoids codec edge cases).
        'policy_json': jsonEncode(policy),
      });
      return raw == true;
    } on PlatformException {
      // PlatformException can occur if the VPN service is not in a state that
      // can accept a policy (e.g. it was killed by the OS between the
      // permission grant and this call).  Return false so the caller can
      // retry or surface an error to the user — do not rethrow because this
      // is a recoverable condition.
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  /// Return the current VPN service state as a string-keyed Map, or null.
  ///
  /// The Map typically contains fields like:
  ///   'connected'        (bool)   — whether the VPN tunnel is up
  ///   'bytesSent'        (int)    — bytes transmitted through the tunnel
  ///   'bytesReceived'    (int)    — bytes received through the tunnel
  ///
  /// Returns null on non-Android or if the Kotlin side returns null.
  Future<Map<String, dynamic>?> getState() async {
    if (!isSupported) {
      return null;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('getState');
    // The channel returns Map<Object?, Object?> at runtime.
    // Map.from() converts it to Map<String, dynamic> for type safety.
    return raw is Map ? Map<String, dynamic>.from(raw) : null;
  }
}
