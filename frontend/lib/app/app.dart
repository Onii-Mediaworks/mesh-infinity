// =============================================================================
// app.dart
//
// Root application widget for Mesh Infinity.  This is the entry point for the
// entire UI tree — `main.dart` calls `runApp(MeshInfinityApp(bridge: bridge))`
// which starts here.
//
// STARTUP SEQUENCE
// The app boot sequence has several phases that this widget orchestrates:
//
//   1. Identity check — `hasIdentity()` asks Rust whether a key pair has
//      previously been persisted to disk.  If not, the user sees onboarding.
//
//   2. Unlock check — `fetchLocalIdentity()` returns null if the identity key
//      is encrypted and has not yet been decrypted in this session.  The user
//      must enter a PIN (if configured) or tap Retry (waiting for the backend
//      to decrypt the key via OS keystore).
//
//   3. Pin check — `fetchSecurityConfig()` tells us whether the user has set
//      a PIN.  If so, the PinScreen is shown before the main shell.
//
//   4. Main shell — once identity is present and unlocked, the app renders
//      AppShell wrapped in seasonal decorations and the CallOverlay.
//
// PROVIDER TREE
// All feature state objects are created here and injected via the Provider
// package.  Putting them here (not in main.dart) ensures they are re-created
// if the identity changes — accomplished via the ValueKey on MultiProvider.
// =============================================================================

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
import '../features/tailscale/tailscale_state.dart';
import '../features/zerotier/zerotier_state.dart';
import '../platform/android_keystore_bridge.dart';
import '../platform/android_startup_sync.dart';

/// Root application widget.
///
/// Receives a [BackendBridge] instance constructed in main.dart and wires it
/// into every feature-level state object that needs to talk to the Rust backend.
///
/// This is a [StatefulWidget] because startup state (_hasIdentity, etc.) is
/// determined asynchronously at runtime and may change (e.g. after onboarding
/// completes the identity now exists).
class MeshInfinityApp extends StatefulWidget {
  const MeshInfinityApp({super.key, required this.bridge});

  /// The bridge to the Rust backend.  Passed down through the provider tree so
  /// every state object can issue FFI calls without needing a global reference.
  final BackendBridge bridge;

  @override
  State<MeshInfinityApp> createState() => _MeshInfinityAppState();
}

class _MeshInfinityAppState extends State<MeshInfinityApp> {
  // ---------------------------------------------------------------------------
  // Startup state flags
  //
  // These drive which screen the app shows.  All three start false and are
  // populated once _refreshStartupState() completes its synchronous FFI reads.
  // ---------------------------------------------------------------------------

  /// Whether the backend has a persisted identity key pair on disk.
  /// False → show OnboardingScreen.
  bool _hasIdentity = false;

  /// Whether the identity has been decrypted into memory for this session.
  /// False while the key is still encrypted (OS keystore not yet unlocked,
  /// or PIN not yet entered).
  bool _identityUnlocked = false;

  /// Whether the user has configured a numeric PIN to lock the app.
  /// If true and the identity is locked, we show PinScreen rather than the
  /// generic _LockedStartupScreen.
  bool _pinEnabled = false;

  /// Whether the Android hardware keystore is available on this device.
  /// Null while the async check is in flight; false means it was explicitly
  /// reported unavailable (shown as a warning on _LockedStartupScreen).
  bool? _androidKeystoreAvailable;

  /// Set to true after the user completes onboarding (creates an identity).
  /// Causes _buildHome() to skip the onboarding gate on the next rebuild even
  /// before the backend's own identity files are fully flushed to disk.
  bool _onboardingComplete = false;

  // ---------------------------------------------------------------------------
  // initState
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();

    // Register all Playful Tidbits (§22.12) at startup.
    // This is a fast, synchronous operation — no I/O, no network.
    initTidbits();

    // isAvailable is true only when the native library loaded successfully and
    // mesh_create() returned a non-null context pointer.  If either failed,
    // every bridge method silently returns empty/null — a failure mode that
    // produces a blank app with no error and no way to detect the root cause.
    // Assert here so that failure is immediate and obvious in debug builds.
    assert(widget.bridge.isAvailable, 'BackendBridge has no live context.');

    // Read initial identity/security state from the Rust backend.
    _refreshStartupState();

    // On Android, the platform layer may have cached startup signals
    // (BLE availability, NFC state, keystore status) via intent extras.
    // Sync these into the backend so Rust sees the full picture before
    // the event bus starts firing events.
    _syncPlatformStartupState();

    // Start the background polling isolate that delivers BackendEvents to the
    // broadcast stream.  Must come after _refreshStartupState() so that the
    // context address is valid when the isolate tries to call mi_poll_events().
    EventBus.instance.start(widget.bridge.contextAddress);

    // Query whether the Android hardware keystore is available.  This is an
    // async platform-channel call and must be separate from the FFI calls above.
    _loadPlatformSecurityState();
  }

  // ---------------------------------------------------------------------------
  // _syncPlatformStartupState
  //
  // Calls AndroidStartupSync which reads intent extras passed by the Android
  // launcher activity (keystore availability, system-level NFC state, etc.)
  // and forwards them to the Rust backend via FFI.  After the sync completes,
  // we re-read startup state because the sync may have unlocked the identity
  // (e.g. keystore was available and Rust could decrypt the key on its own).
  // ---------------------------------------------------------------------------
  Future<void> _syncPlatformStartupState() async {
    await AndroidStartupSync.syncCurrentState(widget.bridge);

    // Guard: if the widget was disposed while awaiting (app closed during startup),
    // do not call setState — that would throw a "setState called on dead widget" error.
    if (!mounted) {
      return;
    }

    // Re-read startup state because the sync may have changed identity lock status.
    setState(_refreshStartupState);
  }

  // ---------------------------------------------------------------------------
  // _loadPlatformSecurityState
  //
  // Queries the Android keystore bridge (a Flutter platform channel) to check
  // whether the device's hardware-backed keystore module is accessible.  This
  // is used only for the UI warning on _LockedStartupScreen; the actual
  // cryptographic operations are performed by the Rust backend, not here.
  // ---------------------------------------------------------------------------
  Future<void> _loadPlatformSecurityState() async {
    final available = await AndroidKeystoreBridge.instance.isAvailable();

    // Guard against widget disposal during the async gap.
    if (!mounted) {
      return;
    }

    setState(() {
      _androidKeystoreAvailable = available;
    });
  }

  // ---------------------------------------------------------------------------
  // _refreshStartupState
  //
  // Reads all startup-relevant state synchronously from the Rust backend.
  // This is fast (pure FFI reads, no I/O) and safe to call from setState().
  //
  // Called:
  //   - At initState (first boot, before any UI renders)
  //   - After Android startup sync completes
  //   - After onboarding completes (identity now exists)
  //   - After PIN unlock succeeds
  // ---------------------------------------------------------------------------
  void _refreshStartupState() {
    // Returns true if Rust has a persisted identity key file on disk.
    _hasIdentity = widget.bridge.hasIdentity();

    // Returns null if the identity is still encrypted/locked.
    // A non-null value means Rust has successfully decrypted the key into
    // in-memory state and can sign/verify messages.
    _identityUnlocked = widget.bridge.fetchLocalIdentity() != null;

    // Reads the security configuration (PIN enabled/disabled, etc.).
    // Returns null only if the identity has not yet been created (first run
    // before onboarding), not because the backend is absent.
    final security = widget.bridge.fetchSecurityConfig();
    _pinEnabled = security?['pinEnabled'] == true;
  }

  // ---------------------------------------------------------------------------
  // _handleUnlockComplete
  //
  // Called by PinScreen after the user enters the correct PIN.
  // Re-reads startup state so _identityUnlocked becomes true and the main
  // shell replaces the PIN screen on the next build.
  // ---------------------------------------------------------------------------
  void _handleUnlockComplete() {
    setState(_refreshStartupState);
  }

  // ---------------------------------------------------------------------------
  // dispose
  //
  // Shutdown order matters here because the background polling isolate calls
  // mi_poll_events() continuously.  If we called widget.bridge.dispose() first
  // (which frees the Rust context), the isolate might attempt a FFI call into
  // freed memory, causing a crash or undefined behaviour.
  //
  // The correct order is:
  //   1. Stop the event bus isolate and wait for it to exit cleanly (the
  //      cooperative stop flag ensures it exits between FFI calls).
  //   2. THEN call mesh_destroy() to free the Rust context.
  //
  // `.then()` chains the bridge.dispose() after stop() resolves its Future.
  // ---------------------------------------------------------------------------
  @override
  void dispose() {
    EventBus.instance.stop().then((_) => widget.bridge.dispose());
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      // The ValueKey encodes the four startup-state booleans.  Whenever any of
      // them changes (e.g. onboarding completes, identity unlocks), Flutter
      // disposes the old provider subtree and creates a new one.  This ensures
      // that all state objects are recreated with fresh data — preventing stale
      // snapshots from a pre-unlock session leaking into the post-unlock UI.
      key: ValueKey(
        '$_hasIdentity-$_identityUnlocked-$_pinEnabled-$_onboardingComplete',
      ),
      providers: [
        // The bridge is provided as a plain (non-listenable) value because it
        // never changes after construction — it is safe to cache references to it.
        Provider<BackendBridge>.value(value: widget.bridge),

        // ChangeNotifierProviders: these are listenable — they call notifyListeners()
        // when their data changes, causing dependent widgets to rebuild.
        ChangeNotifierProvider(create: (_) => ShellState()),
        ChangeNotifierProvider(create: (_) => BadgeState()),
        ChangeNotifierProvider(create: (_) => MessagingState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => PeersState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => FilesState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => NetworkState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => SettingsState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => ServicesState(widget.bridge)),
        ChangeNotifierProvider(create: (_) => CallsState(widget.bridge)),

        // TailscaleState manages all configured tailnet instances (§5.22).
        // Provided at the root level so the nav drawer and TailscaleHubScreen
        // both see the same list — changes (add/remove/priority) propagate
        // immediately to the nav drawer's dynamic entry visibility.
        ChangeNotifierProvider(create: (_) => TailscaleState(widget.bridge)),

        // ZeroTierState manages all configured zeronet instances (§5.23).
        // Same rationale as TailscaleState — root-level placement ensures
        // the nav drawer reacts when the user configures a first zeronet.
        ChangeNotifierProvider(create: (_) => ZeroTierState(widget.bridge)),

        // SecurityState manages the PIN/lock UI and has no direct backend dependency.
        ChangeNotifierProvider(create: (_) => SecurityState()),
      ],
      // Consumer<SettingsState> re-renders only when SettingsState notifies,
      // which is how the theme mode (light/dark/system) stays in sync with the
      // user's choice stored in the backend.
      child: Consumer<SettingsState>(
        builder: (_, settings, _) => MaterialApp(
          title: 'Mesh Infinity',
          theme: MeshTheme.light(),
          darkTheme: MeshTheme.dark(),
          // themeMode comes from SettingsState, which reads the backend setting.
          themeMode: settings.themeMode,
          // Never show the "DEBUG" banner in the top-right corner; it obscures UI
          // elements during testing and is unhelpful to end users.
          debugShowCheckedModeBanner: false,
          home: _buildHome(),
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // _buildHome
  //
  // Chooses which screen to show based on startup state (steps 1–4 from the
  // startup sequence above).  The gates are checked in priority order:
  //
  //   1. No identity + not completed onboarding → OnboardingScreen
  //   2. Identity exists but is locked + PIN configured → PinScreen
  //   3. Identity exists but is locked + no PIN → _LockedStartupScreen (retry)
  //   4. Identity is present and unlocked → main shell
  //
  // The onboarding completion gate checks _onboardingComplete (an optimistic
  // local flag) in addition to _hasIdentity because there is a brief window
  // after onboarding where the backend may not yet have flushed the new
  // identity to disk — we want to proceed to the shell immediately.
  // ---------------------------------------------------------------------------
  Widget _buildHome() {
    if (!_hasIdentity && !_onboardingComplete) {
      return OnboardingScreen(
        onComplete: () => setState(() {
          // Mark onboarding done locally so we don't flash back to it while
          // _refreshStartupState() reads the newly persisted identity.
          _onboardingComplete = true;
          _refreshStartupState();
        }),
      );
    }

    if (_hasIdentity && !_identityUnlocked) {
      // Identity key is on disk but still encrypted.  How we handle this
      // depends on whether a PIN was configured.
      if (_pinEnabled) {
        // The user set a PIN — show the PIN entry screen.
        return PinScreen(
          mode: PinScreenMode.unlock,
          onUnlocked: _handleUnlockComplete,
        );
      }

      // No PIN — probably waiting for Android keystore or some other async
      // unlock mechanism.  Show a screen with diagnostic info and a Retry button.
      return _LockedStartupScreen(
        androidKeystoreAvailable: _androidKeystoreAvailable,
        onRetry: () => setState(_refreshStartupState),
      );
    }

    // Identity is present and unlocked — render the full application shell.
    //
    // SnowfallLayer wraps the entire shell.  It self-deactivates outside
    // the winter window (Dec 1 – Jan 15) — zero overhead on other dates.
    // CallOverlay sits inside SnowfallLayer and renders floating call UI
    // above all other content when a call is active.
    return const SnowfallLayer(child: CallOverlay(child: AppShell()));
  }
}

// =============================================================================
// _LockedStartupScreen
//
// Shown when the identity key exists on disk but is still encrypted and the
// user has not set a PIN (so PinScreen is not appropriate).
//
// Typical cause on Android: the hardware keystore was not available at boot
// (device still booting, work profile locked, etc.) so Rust could not
// auto-decrypt the key.  The user taps Retry after the OS is ready.
// =============================================================================

/// Fallback screen shown when the identity is locked and no PIN has been set.
///
/// Provides a Retry button that re-reads startup state from the backend.
/// Also shows a diagnostic note when the Android keystore is reported unavailable,
/// explaining why the auto-unlock did not happen.
class _LockedStartupScreen extends StatelessWidget {
  const _LockedStartupScreen({
    required this.onRetry,
    required this.androidKeystoreAvailable,
  });

  /// Callback invoked when the user taps the Retry button.
  final VoidCallback onRetry;

  /// Tristate: null = still checking, true = available, false = unavailable.
  /// When false, an extra warning line explains the Android keystore situation.
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
                // Only show the keystore warning when we have a definitive false
                // value — not while the async check is still in flight (null).
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
