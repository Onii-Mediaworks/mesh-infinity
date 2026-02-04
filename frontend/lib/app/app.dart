import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../navigation/navigation_manager.dart';
import '../screens/shell/signal_shell.dart';
import '../services/dependency_container.dart';
import '../state/app_state.dart';
import 'app_theme.dart';

class MeshInfinityApp extends StatefulWidget {
  const MeshInfinityApp({super.key});

  @override
  State<MeshInfinityApp> createState() => _MeshInfinityAppState();
}

class _MeshInfinityAppState extends State<MeshInfinityApp> {
  late final AppDependencyContainer _container;
  late final AppState _appState;
  late final NavigationManager _navigationManager;

  @override
  void initState() {
    super.initState();
    _container = AppDependencyContainer();
    _appState = AppState();
    _navigationManager = NavigationManager();
    _initializeAuth();
  }

  Future<void> _initializeAuth() async {
    final isAuthenticated = await _container.authenticationService.isAuthenticated();
    _appState.setAuthenticationState(
      isAuthenticated ? AuthenticationState.authenticated : AuthenticationState.notAuthenticated,
    );
  }

  @override
  void dispose() {
    _container.dispose();
    _appState.dispose();
    _navigationManager.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider<AppState>.value(value: _appState),
        ChangeNotifierProvider<NavigationManager>.value(value: _navigationManager),
        Provider<DependencyContainer>.value(value: _container),
      ],
      child: Consumer<AppState>(
        builder: (context, appState, _) {
          return MaterialApp(
            title: 'Mesh Infinity',
            theme: MeshTheme.light(),
            darkTheme: MeshTheme.dark(),
            themeMode: appState.themeMode,
            home: const SignalShell(),
          );
        },
      ),
    );
  }
}
