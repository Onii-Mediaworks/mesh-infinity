// main.dart
//
// Application entry point.
//
// STARTUP SEQUENCE:
// -----------------
// 1. WidgetsFlutterBinding.ensureInitialized() — must be called before any
//    platform channel call (path_provider, etc.).
//
// 2. _BootstrapApp shows immediately with a loading spinner so the window is
//    never blank while the backend initialises.
//
// 3. _BootstrapAppState._init() runs asynchronously:
//    a. Resolves the app support directory (fast platform-channel call).
//    b. Initialises DebugLogger (§17.8.1) — file log before backend opens so
//       that backend init failures are captured.  No-ops in release builds.
//    c. Yields one frame via Future.delayed(Duration.zero) so Flutter renders
//       the spinner before the synchronous FFI call blocks the event loop.
//    d. Opens the Rust backend via BackendBridge.open() — loads the native
//       library (DynamicLibrary.open) and calls mesh_init.
//
// 4. On success, setState replaces the spinner with MeshInfinityApp.
//    On failure (bridge.isAvailable == false), shows _FatalErrorApp.
//
// WHY A BOOTSTRAP WIDGET?
// -----------------------
// BackendBridge.open() is synchronous — it blocks the event loop for up to
// ~200 ms in debug builds while the native library loads.  Without the
// bootstrap pattern the user would see a black window during that gap.  With
// it, the spinner is already on screen before the blocking call runs.
//
// WHY allowMissing: true?
// ----------------------
// On desktop development builds the .so / .dylib / .dll may not be present
// if the developer hasn't run `make` yet.  allowMissing: true returns a bridge
// with isAvailable = false (showing _FatalErrorApp) rather than throwing an
// uncaught exception that crashes the Flutter engine entirely.

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'app/app.dart';
import 'app/app_theme.dart';
import 'app/debug_logger.dart';
import 'backend/backend_bridge.dart';

/// Flutter's required entry point.
///
/// ensureInitialized() must be called before getApplicationSupportDirectory()
/// (which uses a platform channel) and before any other Flutter binding API.
void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const _BootstrapApp());
}

// ---------------------------------------------------------------------------
// _BootstrapApp — shown while BackendBridge initialises
// ---------------------------------------------------------------------------

/// Splash-phase app wrapper shown while the Rust backend is loading.
///
/// Displays a brand-themed spinner immediately so the window is never black.
/// Transitions to [MeshInfinityApp] once the bridge is ready, or to
/// [_FatalErrorApp] if the backend fails to load.
class _BootstrapApp extends StatefulWidget {
  const _BootstrapApp();

  @override
  State<_BootstrapApp> createState() => _BootstrapAppState();
}

class _BootstrapAppState extends State<_BootstrapApp> {
  // Null until _init() completes.  null = still loading; non-null = done.
  // _bridge.isAvailable tells us whether the load succeeded or failed.
  BackendBridge? _bridge;

  @override
  void initState() {
    super.initState();
    _init();
  }

  /// Asynchronous backend initialisation sequence.
  ///
  /// Runs after the first frame so the loading spinner is visible before
  /// the blocking BackendBridge.open() call.
  Future<void> _init() async {
    // Resolve the app-support directory (fast platform-channel call).
    // This is where the Rust backend stores its database, keys, and config.
    final appDir = await getApplicationSupportDirectory();

    // §17.8.1 — initialise file logging before the backend opens so that
    // backend init failures are captured in the rolling log file.
    // DebugLogger.init is a no-op in release builds (profile-only feature).
    await DebugLogger.init(appDir.path);

    // Yield to the event loop so Flutter renders the loading spinner before
    // the synchronous FFI call below blocks the thread.
    // Duration.zero schedules the continuation as a microtask after the
    // current frame, giving Flutter exactly one frame to paint.
    await Future<void>.delayed(Duration.zero);

    // Load the native library and call mesh_init.
    // configPath tells the Rust backend where to find (or create) its files.
    // allowMissing: true returns an unavailable bridge instead of crashing
    // when the native library is absent (useful during development).
    final bridge = BackendBridge.open(
      configPath: appDir.path,
      allowMissing: true,
    );

    // Guard against the widget being disposed during the await above
    // (e.g. hot-restart during development).
    if (mounted) setState(() => _bridge = bridge);
  }

  @override
  Widget build(BuildContext context) {
    final bridge = _bridge;

    if (bridge != null) {
      // Backend loaded but reported an error — show the fatal error screen
      // so the user knows something is wrong instead of seeing a silently
      // empty or broken app.
      if (!bridge.isAvailable) {
        return _FatalErrorApp(
          error: bridge.initError ?? 'Backend failed to load',
        );
      }
      // Happy path — hand off to the real app.
      return MeshInfinityApp(bridge: bridge);
    }

    // Still loading — show a minimal themed loading screen.
    // Using MeshTheme here (rather than the default blue) means even the
    // splash spinner matches the app's brand.
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

// ---------------------------------------------------------------------------
// _FatalErrorApp — shown when the Rust backend fails to load
// ---------------------------------------------------------------------------

/// Full-screen error screen shown when [BackendBridge.isAvailable] is false.
///
/// Blocks the user from reaching the main app in a broken state.  Displays
/// the raw error string in a selectable monospace box so the user (or a
/// support engineer) can copy and share it.
class _FatalErrorApp extends StatelessWidget {
  const _FatalErrorApp({required this.error});

  /// The error string returned by [BackendBridge.initError].
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
                // Large error icon — immediately communicates "something is wrong".
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
                // Monospace error box — selectable so the user can copy and
                // paste the error when filing a bug report.
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
