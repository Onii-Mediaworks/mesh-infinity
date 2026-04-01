import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../backend/backend_bridge.dart';
import '../backend/event_bus.dart';
import '../app/app_theme.dart';
import '../shell/shell_state.dart';
import '../shell/badge_state.dart';
import '../shell/security_status_bar.dart';
import '../shell/app_shell.dart';
import '../onboarding/onboarding_screen.dart';
import '../features/messaging/messaging_state.dart';
import '../features/peers/peers_state.dart';
import '../features/files/files_state.dart';
import '../features/network/network_state.dart';
import '../features/settings/settings_state.dart';
import '../features/calls/calls_state.dart';
import '../features/calls/call_overlay.dart';
import '../features/services/services_state.dart';
import '../features/tidbits/tidbits.dart'; // Playful Tidbits init (§22.12)

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

    // Register all Playful Tidbits (§22.12) at startup.
    // This is a fast, synchronous operation — no I/O, no network.
    initTidbits();

    if (widget.bridge.isAvailable) {
      if (_hasIdentity) {
        final unlocked = widget.bridge.unlockIdentity();
        if (unlocked) {
          widget.bridge.startClearnetListener();
        }
      }
      EventBus.instance.start(widget.bridge.contextAddress);
    }
  }

  @override
  void dispose() {
    EventBus.instance.stop().then((_) => widget.bridge.dispose());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        Provider<BackendBridge>.value(value: widget.bridge),
        ChangeNotifierProvider(create: (_) => ShellState()),
        ChangeNotifierProvider(create: (_) => BadgeState()),
        ChangeNotifierProvider(create: (_) => MessagingState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => PeersState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => FilesState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => NetworkState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => SettingsState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => ServicesState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => CallsState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => SecurityState()),
      ],
      child: Consumer<SettingsState>(
        builder: (_, settings, _) => MaterialApp(
          title: 'Mesh Infinity',
          theme: MeshTheme.light(),
          darkTheme: MeshTheme.dark(),
          themeMode: settings.themeMode,
          debugShowCheckedModeBanner: false,
          home: _buildHome(),
        ),
      ),
    );
  }

  Widget _buildHome() {
    if (!_hasIdentity && !_onboardingComplete) {
      return OnboardingScreen(
        onComplete: () => setState(() => _onboardingComplete = true),
      );
    }
    // SnowfallLayer wraps the entire shell.  It self-deactivates outside
    // the winter window (Dec 1 – Jan 15) — zero overhead on other dates.
    return const SnowfallLayer(child: CallOverlay(child: AppShell()));
  }
}
