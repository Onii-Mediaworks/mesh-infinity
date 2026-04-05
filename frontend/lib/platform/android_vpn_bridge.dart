import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

class AndroidVpnBridge {
  AndroidVpnBridge._();

  static final AndroidVpnBridge instance = AndroidVpnBridge._();

  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_vpn',
  );

  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  Future<bool> isPermissionGranted() async {
    if (!isSupported) {
      return true;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'isPermissionGranted',
    );
    return raw == true;
  }

  Future<bool> requestPermission() async {
    if (!isSupported) {
      return true;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('requestPermission');
    return raw == true;
  }

  Future<bool> applyPolicy(Map<String, dynamic> policy) async {
    if (!isSupported) {
      return true;
    }
    try {
      final raw = await _methodChannel.invokeMethod<Object?>('applyPolicy', {
        'policy_json': jsonEncode(policy),
      });
      return raw == true;
    } on PlatformException {
      return false;
    }
  }

  Future<Map<String, dynamic>?> getState() async {
    if (!isSupported) {
      return null;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('getState');
    return raw is Map ? Map<String, dynamic>.from(raw) : null;
  }
}
