import 'package:flutter/material.dart';
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
  late final AppDependencyContainer _container;
  late final NavigationManager _navigationManager;

  @override
  void initState() {
    super.initState();
    _container = AppDependencyContainer();
    _navigationManager = NavigationManager();
    _container.meshState.initialize();
    _initializeAuth();
  }

  Future<void> _initializeAuth() async {
    final isAuthenticated = await _container.authenticationService
        .isAuthenticated();
    _container.meshState.setAuthenticationState(
      isAuthenticated
          ? AuthenticationState.authenticated
          : AuthenticationState.notAuthenticated,
    );
  }

  @override
  void dispose() {
    _container.dispose();
    _navigationManager.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider<MeshState>.value(value: _container.meshState),
        ChangeNotifierProvider<NavigationManager>.value(
          value: _navigationManager,
        ),
        Provider<DependencyContainer>.value(value: _container),
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
