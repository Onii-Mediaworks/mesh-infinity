import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../backend/backend_bridge.dart';
import '../backend/event_bus.dart';
import '../app/app_theme.dart';
import '../shell/shell_state.dart';
import '../shell/app_shell.dart';
import '../onboarding/onboarding_screen.dart';
import '../features/messaging/messaging_state.dart';
import '../features/peers/peers_state.dart';
import '../features/files/files_state.dart';
import '../features/network/network_state.dart';
import '../features/settings/settings_state.dart';

class MeshInfinityApp extends StatefulWidget {
  const MeshInfinityApp({super.key, required this.bridge});

  final BackendBridge bridge;

  @override
  State<MeshInfinityApp> createState() => _MeshInfinityAppState();
}

class _MeshInfinityAppState extends State<MeshInfinityApp> {
  late final bool _hasIdentity;
  bool _onboardingComplete = false;

  @override
  void initState() {
    super.initState();
    _hasIdentity = widget.bridge.hasIdentity();

    // Start the event bus only if the backend is available
    if (widget.bridge.isAvailable) {
      EventBus.instance.start(widget.bridge.contextAddress);
    }
  }

  @override
  void dispose() {
    EventBus.instance.stop();
    widget.bridge.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        Provider<BackendBridge>.value(value: widget.bridge),
        ChangeNotifierProvider(create: (_) => ShellState()),
        ChangeNotifierProvider(
          create: (_) => MessagingState(widget.bridge),
        ),
        ChangeNotifierProvider(
          create: (_) => PeersState(widget.bridge),
        ),
        ChangeNotifierProvider(
          create: (_) => FilesState(widget.bridge),
        ),
        ChangeNotifierProvider(
          create: (_) => NetworkState(widget.bridge),
        ),
        ChangeNotifierProvider(
          create: (_) => SettingsState(widget.bridge),
        ),
      ],
      child: MaterialApp(
        title: 'Mesh Infinity',
        theme: MeshTheme.light(),
        darkTheme: MeshTheme.dark(),
        debugShowCheckedModeBanner: false,
        home: _buildHome(),
      ),
    );
  }

  Widget _buildHome() {
    if (!_hasIdentity && !_onboardingComplete) {
      return OnboardingScreen(
        onComplete: () => setState(() => _onboardingComplete = true),
      );
    }
    return const AppShell();
  }
}
