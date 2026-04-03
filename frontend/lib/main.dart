import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'app/app.dart';
import 'app/app_theme.dart';
import 'app/debug_logger.dart';
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

    // §17.8.1 — initialise file logging before the backend opens so that
    // backend init failures are captured.  No-ops in release builds.
    await DebugLogger.init(appDir.path);

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

    if (bridge != null) {
      // Backend failed to load — show a blocking error screen so the user
      // knows something is wrong instead of seeing a silently empty app.
      if (!bridge.isAvailable) {
        return _FatalErrorApp(
          error: bridge.initError ?? 'Backend failed to load',
        );
      }
      return MeshInfinityApp(bridge: bridge);
    }

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

/// Shown when the Rust backend fails to load.  Blocks the app entirely so the
/// user cannot reach a silently-broken state, and surfaces the error message.
class _FatalErrorApp extends StatelessWidget {
  const _FatalErrorApp({required this.error});

  final String error;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: MeshTheme.light(),
      darkTheme: MeshTheme.dark(),
      home: Scaffold(
        body: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(Icons.error_outline, size: 64, color: Colors.red),
                const SizedBox(height: 24),
                const Text(
                  'Failed to start Mesh Infinity',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 16),
                const Text(
                  'The backend library could not be loaded. '
                  'Please reinstall the application.',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.grey.shade100,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: SelectableText(
                    error,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
