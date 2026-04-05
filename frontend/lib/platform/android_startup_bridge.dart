import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

class AndroidStartupBridge {
  AndroidStartupBridge._();

  static final AndroidStartupBridge instance = AndroidStartupBridge._();

  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_startup',
  );

  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  Future<Map<String, dynamic>> getStartupState() async {
    if (!isSupported) {
      return const {};
    }
    final raw = await _methodChannel.invokeMethod<Object?>('getStartupState');
    return raw is Map<Object?, Object?>
        ? raw.map(
            (key, value) => MapEntry(key.toString(), value),
          )
        : const {};
  }

  Future<bool> ensureStartupService() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('ensureStartupService');
    return raw == true;
  }
}
