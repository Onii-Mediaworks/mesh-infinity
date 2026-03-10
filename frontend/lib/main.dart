import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'app/app.dart';
import 'backend/backend_bridge.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final appDir = await getApplicationSupportDirectory();
  final bridge = BackendBridge.open(configPath: appDir.path, allowMissing: true);
  runApp(MeshInfinityApp(bridge: bridge));
}
