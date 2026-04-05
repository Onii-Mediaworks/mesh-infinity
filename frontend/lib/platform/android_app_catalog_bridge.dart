import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

class AndroidInstalledApp {
  const AndroidInstalledApp({
    required this.appId,
    required this.label,
    required this.isSystemApp,
  });

  final String appId;
  final String label;
  final bool isSystemApp;

  factory AndroidInstalledApp.fromMap(Map<Object?, Object?> map) {
    return AndroidInstalledApp(
      appId: map['app_id'] as String? ?? '',
      label: map['label'] as String? ?? '',
      isSystemApp: map['is_system_app'] == true,
    );
  }
}

class AndroidAppCatalogBridge {
  AndroidAppCatalogBridge._();

  static final AndroidAppCatalogBridge instance = AndroidAppCatalogBridge._();

  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_app_catalog',
  );

  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  Future<List<AndroidInstalledApp>> listInstalledApps() async {
    if (!isSupported) {
      return const [];
    }
    final raw = await _methodChannel.invokeMethod<Object?>('list_installed_apps');
    if (raw is! List<Object?>) {
      return const [];
    }
    return raw
        .whereType<Map<Object?, Object?>>()
        .map(AndroidInstalledApp.fromMap)
        .where((app) => app.appId.isNotEmpty)
        .toList(growable: false);
  }
}
