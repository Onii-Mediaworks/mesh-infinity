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
import '../features/settings/screens/pin_screen.dart';
import '../features/calls/calls_state.dart';
import '../features/calls/call_overlay.dart';
import '../features/services/services_state.dart';
import '../features/tidbits/tidbits.dart'; // Playful Tidbits init (§22.12)
import '../platform/android_keystore_bridge.dart';
import '../platform/android_startup_sync.dart';

class MeshInfinityApp extends StatefulWidget {
  const MeshInfinityApp({super.key, required this.bridge});
  final BackendBridge bridge;

  @override
  State<MeshInfinityApp> createState() => _MeshInfinityAppState();
}

class _MeshInfinityAppState extends State<MeshInfinityApp> {
  bool _hasIdentity = false;
  bool _identityUnlocked = false;
  bool _pinEnabled = false;
  bool? _androidKeystoreAvailable;
  bool _onboardingComplete = false;

  @override
  void initState() {
    super.initState();

    // Register all Playful Tidbits (§22.12) at startup.
    // This is a fast, synchronous operation — no I/O, no network.
    initTidbits();

    if (widget.bridge.isAvailable) {
      _refreshStartupState();
      _syncPlatformStartupState();
      EventBus.instance.start(widget.bridge.contextAddress);
    }
    _loadPlatformSecurityState();
  }

  Future<void> _syncPlatformStartupState() async {
    await AndroidStartupSync.syncCurrentState(widget.bridge);
    if (!mounted) {
      return;
    }
    setState(_refreshStartupState);
  }

  Future<void> _loadPlatformSecurityState() async {
    final available = await AndroidKeystoreBridge.instance.isAvailable();
    if (!mounted) {
      return;
    }
    setState(() {
      _androidKeystoreAvailable = available;
    });
  }

  void _refreshStartupState() {
    _hasIdentity = widget.bridge.hasIdentity();
    _identityUnlocked = widget.bridge.fetchLocalIdentity() != null;
    final security = widget.bridge.fetchSecurityConfig();
    _pinEnabled = security?['pinEnabled'] == true;
  }

  void _handleUnlockComplete() {
    setState(_refreshStartupState);
  }

  @override
  void dispose() {
    EventBus.instance.stop().then((_) => widget.bridge.dispose());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      key: ValueKey(
        '$_hasIdentity-$_identityUnlocked-$_pinEnabled-$_onboardingComplete',
      ),
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
        onComplete: () => setState(() {
          _onboardingComplete = true;
          _refreshStartupState();
        }),
      );
    }
    if (_hasIdentity && !_identityUnlocked) {
      if (_pinEnabled) {
        return PinScreen(
          mode: PinScreenMode.unlock,
          onUnlocked: _handleUnlockComplete,
        );
      }
      return _LockedStartupScreen(
        androidKeystoreAvailable: _androidKeystoreAvailable,
        onRetry: () => setState(_refreshStartupState),
      );
    }
    // SnowfallLayer wraps the entire shell.  It self-deactivates outside
    // the winter window (Dec 1 – Jan 15) — zero overhead on other dates.
    return const SnowfallLayer(child: CallOverlay(child: AppShell()));
  }
}

class _LockedStartupScreen extends StatelessWidget {
  const _LockedStartupScreen({
    required this.onRetry,
    required this.androidKeystoreAvailable,
  });

  final VoidCallback onRetry;
  final bool? androidKeystoreAvailable;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.lock_outline, size: 48),
                const SizedBox(height: 16),
                Text(
                  'Identity is still locked',
                  style: theme.textTheme.titleLarge,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 8),
                Text(
                  'The backend has not made your identity available yet. Retry startup to refresh backend state.',
                  style: theme.textTheme.bodyMedium,
                  textAlign: TextAlign.center,
                ),
                if (androidKeystoreAvailable == false) ...[
                  const SizedBox(height: 12),
                  Text(
                    'Android keystore access is unavailable on this device, so device-level key storage is not ready.',
                    style: theme.textTheme.bodySmall,
                    textAlign: TextAlign.center,
                  ),
                ],
                const SizedBox(height: 16),
                FilledButton(
                  onPressed: onRetry,
                  child: const Text('Retry'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
