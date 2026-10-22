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

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../backend/backend_bridge.dart';
import '../backend/event_bus.dart';
import '../app/app_theme.dart';
import '../shell/shell_state.dart';
import '../shell/input_map.dart';
import '../shell/badge_state.dart';
import '../shell/security_status_bar.dart';
import '../shell/app_shell.dart';
import '../onboarding/onboarding_screen.dart';
import '../features/contacts/screens/pair_contact_screen.dart';
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

/// The screen the app opens with, chosen by [resolve_startup_screen].
enum StartupScreen {
  /// No identity on disk: run onboarding from the Welcome step.
  onboarding,

  /// Identity present and unlocked, but onboarding never reached Done:
  /// resume onboarding at the identity step (§22.42).
  resume,

  /// Identity present but locked, and a PIN is configured: PinScreen.
  pin,

  /// Identity present but locked with no PIN: wait for the OS keystore.
  locked,

  /// Identity present, unlocked and onboarded: the main shell.
  shell,
}

/// Pick the startup screen from the four facts the backend reports.
///
/// Pure so the gate order is testable without a native library.  The order
/// matters: the unlock gates come before the onboarding flag because the flag
/// lives in the encrypted settings vault and reads false until unlock — a
/// locked identity must reach PinScreen, not a resumed onboarding that would
/// then fail every backend write.
StartupScreen resolve_startup_screen({
  required bool has_identity,
  required bool unlocked,
  required bool pin_enabled,
  required bool onboarding_complete,
}) {
  // Nothing on disk: first run.
  if (!has_identity) return StartupScreen.onboarding;
  // Locked: unlock first, then re-evaluate.
  if (!unlocked) return pin_enabled ? StartupScreen.pin : StartupScreen.locked;
  // Unlocked but setup was interrupted after identity creation (§22.42):
  // the mandatory disclosures and PIN offer were never shown.
  if (!onboarding_complete) return StartupScreen.resume;
  return StartupScreen.shell;
}

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

  /// Whether the backend's persisted `onboarding_complete` flag is set
  /// (§22.42).  Read from the settings vault, so it is only meaningful once
  /// the identity is unlocked.  An unlocked identity without it means setup
  /// was interrupted and onboarding resumes at the identity step.
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

    // Reads the persisted onboarding flag (§22.42).  False until the Done
    // step has run setOnboardingComplete() — and false while locked, which
    // is why resolve_startup_screen() checks the unlock gates first.
    _onboardingComplete = widget.bridge.isOnboardingComplete();
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
  // _handle_onboarding_complete
  //
  // Called by the Done step (§22.42.7) after the backend has persisted the
  // onboarding_complete flag.  Re-reading startup state swaps the home widget
  // for the shell; because the MultiProvider key changes, the whole provider
  // subtree — MaterialApp and its Navigator included — is rebuilt on the
  // next frame.  "Add a contact" therefore pushes PairContactScreen through
  // the navigator key *after* that frame, so it lands on top of the new
  // shell rather than on a Navigator that is about to be disposed.
  // "Go to Chat" needs nothing more: a fresh ShellState opens on Chat.
  // ---------------------------------------------------------------------------
  void _handle_onboarding_complete(OnboardingExit exit) {
    setState(_refreshStartupState);
    if (exit != OnboardingExit.addContact) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // currentState is null only if the app was torn down meanwhile.
      _navigator_key.currentState?.push(
        MaterialPageRoute<void>(builder: (_) => const PairContactScreen()),
      );
    });
  }

  /// Key of the MaterialApp's Navigator, so the Done step's "Add a contact"
  /// can push on whichever Navigator instance exists after the rebuild.
  final GlobalKey<NavigatorState> _navigator_key = GlobalKey<NavigatorState>();

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
          // See _handle_onboarding_complete for why the Navigator is keyed.
          navigatorKey: _navigator_key,
          title: 'Mesh Infinity',
          theme: MeshTheme.light(),
          darkTheme: MeshTheme.dark(),
          // themeMode comes from SettingsState, which reads the backend setting.
          themeMode: settings.themeMode,
          // Never show the "DEBUG" banner in the top-right corner; it obscures UI
          // elements during testing and is unhelpful to end users.
          debugShowCheckedModeBanner: false,
          builder: (context, child) {
            // ShellInputScope installs the one §22.36 key/button → intent
            // table above the Navigator, so pushed routes, sheets and
            // dialogs all share it with the shell (see input_map.dart).
            final body = ShellInputScope(
              child: child ?? const SizedBox.shrink(),
            );
            final nodeLabel = kDebugMode
                ? Platform.environment['MESH_NODE_LABEL']?.trim()
                : null;
            if (nodeLabel == null || nodeLabel.isEmpty) {
              return body;
            }
            return Stack(
              children: [
                body,
                Positioned(
                  top: 8,
                  right: 8,
                  child: IgnorePointer(
                    child: Material(
                      color: Colors.deepOrange,
                      borderRadius: BorderRadius.circular(6),
                      elevation: 4,
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 10,
                          vertical: 5,
                        ),
                        child: Text(
                          nodeLabel,
                          style: const TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            );
          },
          home: _buildHome(),
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // _buildHome
  //
  // Chooses which screen to show based on startup state (steps 1–4 from the
  // startup sequence above).  The gate order lives in
  // resolve_startup_screen():
  //
  //   1. No identity → OnboardingScreen from Welcome
  //   2. Identity exists but is locked + PIN configured → PinScreen
  //   3. Identity exists but is locked + no PIN → _LockedStartupScreen (retry)
  //   4. Identity unlocked but onboarding_complete unset → OnboardingScreen
  //      resumed at the identity step (§22.42: an interrupted first run must
  //      still show the mandatory disclosures and the PIN offer)
  //   5. Identity unlocked and onboarded → main shell
  //
  // The Done step persists the flag through the backend before calling
  // onComplete, so re-reading startup state afterwards lands on the shell
  // without any optimistic local flag.
  // ---------------------------------------------------------------------------
  Widget _buildHome() {
    final screen = resolve_startup_screen(
      has_identity: _hasIdentity,
      unlocked: _identityUnlocked,
      pin_enabled: _pinEnabled,
      onboarding_complete: _onboardingComplete,
    );
    switch (screen) {
      case StartupScreen.onboarding:
      case StartupScreen.resume:
        return OnboardingScreen(
          // A resumed run skips Welcome/Import: the identity already exists,
          // so creating or importing another one is exactly what must not
          // happen.  The identity step pre-fills the stored name.
          initial_step: screen == StartupScreen.resume
              ? OnboardingStep.identity
              : OnboardingStep.welcome,
          // The flag is already persisted when this fires; re-reading the
          // startup state is what moves the app to the shell, and the exit
          // decides whether PairContactScreen is pushed on top of it.
          onComplete: _handle_onboarding_complete,
        );

      case StartupScreen.pin:
        // The user set a PIN — show the PIN entry screen.
        return PinScreen(
          mode: PinScreenMode.unlock,
          onUnlocked: _handleUnlockComplete,
        );

      case StartupScreen.locked:
        // No PIN — probably waiting for Android keystore or some other async
        // unlock mechanism.  Show diagnostic info and a Retry button.
        return _LockedStartupScreen(
          androidKeystoreAvailable: _androidKeystoreAvailable,
          onRetry: () => setState(_refreshStartupState),
        );

      case StartupScreen.shell:
        // Identity is present, unlocked and onboarded — render the shell.
        //
        // SnowfallLayer wraps the entire shell.  It self-deactivates outside
        // the winter window (Dec 1 – Jan 15) — zero overhead on other dates.
        // CallOverlay sits inside SnowfallLayer and renders floating call UI
        // above all other content when a call is active.
        return const SnowfallLayer(child: CallOverlay(child: AppShell()));
    }
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
                FilledButton(onPressed: onRetry, child: const Text('Retry')),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
