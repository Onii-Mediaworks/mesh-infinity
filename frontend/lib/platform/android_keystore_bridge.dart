import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

class AndroidKeystoreBridge {
  AndroidKeystoreBridge._();

  static final AndroidKeystoreBridge instance = AndroidKeystoreBridge._();

  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_keystore',
  );

  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  Future<bool> isAvailable() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('isAvailable');
    return raw == true;
  }

  Future<Uint8List?> wrapKey(Uint8List input) async {
    if (!isSupported) {
      return null;
    }
    final raw = await _methodChannel.invokeMethod<Uint8List?>('wrapKey', input);
    return raw;
  }

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

  Future<bool> deleteKey() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('deleteKey');
    return raw == true;
  }
}
