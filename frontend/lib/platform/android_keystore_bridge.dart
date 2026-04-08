// android_keystore_bridge.dart
//
// AndroidKeystoreBridge — Flutter-side platform channel for the Android
// Hardware-Backed Keystore (§3.10).
//
// WHAT IS THE ANDROID KEYSTORE?
// ------------------------------
// Android devices with a Trusted Execution Environment (TEE) or dedicated
// security chip (StrongBox) support hardware-backed cryptographic key storage.
// Keys stored in the Keystore live inside the secure hardware and can NEVER
// be extracted by software — not even by root or the OS kernel.
//
// Mesh Infinity uses the Keystore to wrap (encrypt) the Rust backend's
// master key material before writing it to disk.  The wrapped key is useless
// without the TEE to unwrap it, so physical access to the storage does not
// compromise the keys.
//
// HOW WRAP/UNWRAP WORKS:
// ----------------------
// "Wrapping" a key means encrypting it with an AES key that lives in the
// Keystore hardware.  Mesh Infinity does this when first generating its
// identity:
//
//   Rust generates master key
//       ↓
//   Flutter calls wrapKey(masterKey bytes)
//       ↓
//   Kotlin uses Keystore AES key to AES-GCM-encrypt the master key bytes
//       ↓
//   Returns the ciphertext (wrapped key)
//       ↓
//   Rust stores the wrapped key on disk
//
// On subsequent launches, the process runs in reverse (unwrapKey).
//
// PLATFORM CHANNEL:
// -----------------
// The Dart/Kotlin boundary is a MethodChannel named
// 'mesh_infinity/android_keystore'.  The Kotlin side registers handlers for
// isAvailable / wrapKey / unwrapKey / deleteKey.

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Platform channel bridge for the Android Hardware-Backed Keystore (§3.10).
///
/// Access via [AndroidKeystoreBridge.instance].  All methods return safe
/// fallback values on non-Android platforms so callers are platform-agnostic.
class AndroidKeystoreBridge {
  // Private constructor — use [instance].
  AndroidKeystoreBridge._();

  /// Singleton.  One instance per app lifetime.
  static final AndroidKeystoreBridge instance = AndroidKeystoreBridge._();

  /// Channel name — must match the Kotlin registration exactly.
  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_keystore',
  );

  /// True only on Android (non-web).
  ///
  /// On non-Android platforms, operations silently return safe no-op values
  /// (null / false) so callers never need conditional platform code.
  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  /// Returns true if a hardware-backed Keystore key is available.
  ///
  /// False when the device has no TEE (rare), when the Keystore key has been
  /// deleted, or on non-Android platforms.  Callers should fall back to
  /// software-only key storage if this returns false.
  Future<bool> isAvailable() async {
    if (!isSupported) {
      // Non-Android: hardware keystore does not exist.
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('isAvailable');
    // The Kotlin side returns a Java Boolean; over the codec this becomes a
    // Dart bool or null.  Comparing to true guards against null.
    return raw == true;
  }

  /// Wrap (encrypt) [input] using the hardware-backed Keystore AES key.
  ///
  /// Returns the AES-GCM ciphertext as a [Uint8List], or null if the wrapping
  /// fails (e.g. Keystore key not yet generated, user authentication required).
  ///
  /// The returned bytes should be stored on disk by the Rust backend.
  /// They are meaningless without the Keystore TEE to unwrap them.
  Future<Uint8List?> wrapKey(Uint8List input) async {
    if (!isSupported) {
      // Non-Android: cannot hardware-wrap; caller falls back to software path.
      return null;
    }
    final raw = await _methodChannel.invokeMethod<Uint8List?>('wrapKey', input);
    return raw;
  }

  /// Unwrap (decrypt) [input] that was previously produced by [wrapKey].
  ///
  /// Returns the original plaintext key bytes, or null if unwrapping fails.
  /// Failure reasons include: Keystore key deleted, user authentication
  /// required but not satisfied, or TEE hardware fault.
  Future<Uint8List?> unwrapKey(Uint8List input) async {
    if (!isSupported) {
      return null;
    }
    final raw = await _methodChannel.invokeMethod<Uint8List?>(
      'unwrapKey',
      input,
    );
    return raw;
  }

  /// Delete the Keystore AES key, permanently invalidating all wrapped blobs.
  ///
  /// Called during emergency erase (§22.10.11) to ensure that previously
  /// wrapped key material stored on disk can never be unwrapped again, even
  /// if the device storage is recovered after a wipe.
  ///
  /// Returns true if the deletion succeeded (or if there was no key to delete).
  Future<bool> deleteKey() async {
    if (!isSupported) {
      // Non-Android: nothing to delete; report success to avoid blocking the
      // emergency erase flow.
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('deleteKey');
    return raw == true;
  }
}
