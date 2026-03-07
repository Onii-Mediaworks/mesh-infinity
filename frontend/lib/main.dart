import 'package:flutter/material.dart';

import 'app/app.dart';
import 'backend/backend_bridge.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final bridge = BackendBridge.open(allowMissing: true);
  runApp(MeshInfinityApp(bridge: bridge));
}
