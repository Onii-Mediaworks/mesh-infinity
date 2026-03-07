import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:provider/provider.dart';

import '../core/state/mesh_state.dart';
import '../navigation/navigation_manager.dart';
import '../screens/shell/signal_shell.dart';
import '../services/dependency_container.dart';
import 'app_theme.dart';

class MeshInfinityApp extends StatefulWidget {
  const MeshInfinityApp({super.key});

  @override
  State<MeshInfinityApp> createState() => _MeshInfinityAppState();
}

class _MeshInfinityAppState extends State<MeshInfinityApp> {
  AppDependencyContainer? _container;
  NavigationManager? _navigationManager;
  Object? _startupError;

  @override
  void initState() {
    super.initState();
    try {
      _container = AppDependencyContainer();
      _navigationManager = NavigationManager();
      _container!.meshState.initialize();
      _initializeAuth();
    } catch (error) {
      _startupError = error;
    }
  }

  Future<void> _initializeAuth() async {
    final container = _container;
    if (container == null) return;
    final isAuthenticated = await container.authenticationService
        .isAuthenticated();
    container.meshState.setAuthenticationState(
      isAuthenticated
          ? AuthenticationState.authenticated
          : AuthenticationState.notAuthenticated,
    );
  }

  @override
  void dispose() {
    _container?.dispose();
    _navigationManager?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_startupError != null ||
        _container == null ||
        _navigationManager == null) {
      return MaterialApp(
        title: 'Mesh Infinity',
        theme: MeshTheme.light(),
        darkTheme: MeshTheme.dark(),
        themeMode: ThemeMode.system,
        home: Scaffold(
          body: SafeArea(
            child: Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.shield_outlined, size: 40),
                    const SizedBox(height: 12),
                    const Text(
                      'Unable to start Mesh Infinity securely.',
                      textAlign: TextAlign.center,
                    ),
                    if (!kReleaseMode && _startupError != null) ...[
                      const SizedBox(height: 8),
                      Text(
                        _startupError.toString(),
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),
        ),
      );
    }

    return MultiProvider(
      providers: [
        ChangeNotifierProvider<MeshState>.value(value: _container!.meshState),
        ChangeNotifierProvider<NavigationManager>.value(
          value: _navigationManager!,
        ),
        Provider<DependencyContainer>.value(value: _container!),
      ],
      child: Consumer<MeshState>(
        builder: (context, meshState, _) {
          return MaterialApp(
            title: 'Mesh Infinity',
            theme: MeshTheme.light(),
            darkTheme: MeshTheme.dark(),
            themeMode: meshState.themeMode,
            home: const SignalShell(),
          );
        },
      ),
    );
  }
}
