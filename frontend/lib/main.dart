import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'app/app.dart';
import 'app/app_theme.dart';
import 'backend/backend_bridge.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const _BootstrapApp());
}

/// Shown while [BackendBridge] initialises.  Displays immediately so the
/// window is never black — the user sees the brand background + spinner.
class _BootstrapApp extends StatefulWidget {
  const _BootstrapApp();

  @override
  State<_BootstrapApp> createState() => _BootstrapAppState();
}

class _BootstrapAppState extends State<_BootstrapApp> {
  BackendBridge? _bridge;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    // Resolve the app-support directory (fast platform-channel call).
    final appDir = await getApplicationSupportDirectory();

    // Yield so Flutter renders the loading frame before the synchronous FFI
    // call below blocks the event loop.
    await Future<void>.delayed(Duration.zero);

    // DynamicLibrary.open + mesh_init run here.  Both are fast in release
    // builds; in debug the dylib load takes ~200 ms on first open.
    final bridge = BackendBridge.open(
      configPath: appDir.path,
      allowMissing: true,
    );

    if (mounted) setState(() => _bridge = bridge);
  }

  @override
  Widget build(BuildContext context) {
    final bridge = _bridge;
    if (bridge != null) return MeshInfinityApp(bridge: bridge);

    // Loading screen — shown for the ~200 ms it takes to open the dylib.
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: MeshTheme.light(),
      darkTheme: MeshTheme.dark(),
      home: const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      ),
    );
  }
}
