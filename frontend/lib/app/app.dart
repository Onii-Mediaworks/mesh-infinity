// =============================================================================
// app.dart
//
// The root widget of the entire Mesh Infinity Flutter application.
//
// WHAT IS A WIDGET?
// In Flutter, everything on screen is a Widget — buttons, text, images,
// layouts, even invisible things like state managers.  Widgets are
// lightweight, immutable descriptions of part of the UI.  Flutter rebuilds
// widgets frequently; the real work happens in State objects (for StatefulWidgets)
// which persist across rebuilds.
//
// THIS FILE'S RESPONSIBILITIES
//   1. Receive the BackendBridge (the FFI gateway to Rust) as a constructor
//      argument and make it available to every widget in the tree.
//   2. Start the EventBus background polling isolate if the backend is live.
//   3. Create all feature-level state objects and inject them via Provider so
//      any widget anywhere in the tree can access them without manual passing.
//   4. Decide whether to show the Onboarding screen (first run, no identity)
//      or the main AppShell (returning user with identity).
//   5. Shut everything down cleanly when the widget is disposed.
// =============================================================================

import 'package:flutter/material.dart';  // Flutter's Material Design widgets
import 'package:provider/provider.dart'; // State management via Providers

import '../backend/backend_bridge.dart';           // FFI bridge to Rust
import '../backend/event_bus.dart';                // Background event polling
import '../app/app_theme.dart';                    // Brand colours and Material theme
import '../shell/shell_state.dart';                // Which section of the app is visible
import '../shell/app_shell.dart';                  // The main navigation shell widget
import '../onboarding/onboarding_screen.dart';     // First-run identity setup screen
import '../features/messaging/messaging_state.dart'; // Chat room & message state
import '../features/peers/peers_state.dart';       // Connected peer state
import '../features/files/files_state.dart';       // File transfer state
import '../features/network/network_state.dart';   // Network/transport state
import '../features/settings/settings_state.dart'; // Settings and identity state

// =============================================================================
// MeshInfinityApp — StatefulWidget
//
// WHAT IS A StatefulWidget?
// A StatefulWidget is a widget that has mutable state that can change over time.
// It is split into two classes:
//   - MeshInfinityApp (the widget) — immutable, holds constructor parameters
//   - _MeshInfinityAppState (the state) — mutable, lives across rebuilds
//
// The widget is thrown away and recreated constantly; the State object persists
// and is where we store data that should survive rebuilds.
// =============================================================================

class MeshInfinityApp extends StatefulWidget {
  /// [bridge] is the fully-initialised FFI gateway created in main.dart.
  /// Passing it in (rather than creating it here) makes the class testable
  /// and separates library-loading concerns from widget concerns.
  const MeshInfinityApp({super.key, required this.bridge});

  final BackendBridge bridge;

  @override
  State<MeshInfinityApp> createState() => _MeshInfinityAppState();
}

// =============================================================================
// _MeshInfinityAppState — the mutable state for MeshInfinityApp
//
// Flutter calls initState() once when this widget first appears in the tree,
// dispose() once when it is permanently removed, and build() every time the
// state changes.
// =============================================================================

class _MeshInfinityAppState extends State<MeshInfinityApp> {
  // Whether the Rust backend already has a saved key pair for this device.
  // Checked once at startup; it determines whether we show onboarding.
  // `late final` means it will be assigned exactly once (in initState) and
  // never changed afterwards — the compiler enforces this.
  late final bool _hasIdentity;

  // Whether the user has completed the onboarding flow in THIS session.
  // Starts false; set to true when the user taps "Get Started" or equivalent.
  // Once true, _buildHome() shows the main AppShell instead of OnboardingScreen.
  bool _onboardingComplete = false;

  // ---------------------------------------------------------------------------
  // initState()
  //
  // Flutter calls this exactly once, when the State object is first inserted
  // into the widget tree.  It is the right place for one-time setup that needs
  // access to `widget` (our parent widget's properties).
  //
  // DO NOT call setState() here (it's not needed; the widget hasn't been built
  // yet) and DO NOT do anything async here (use addPostFrameCallback or other
  // patterns for that).
  // ---------------------------------------------------------------------------
  @override
  void initState() {
    super.initState(); // Always call super first in Flutter lifecycle methods.

    // Ask Rust whether a key pair exists on disk.  This is a synchronous FFI
    // call — it reads a file from disk or checks an in-memory flag.
    _hasIdentity = widget.bridge.hasIdentity();

    // Start the background event polling loop, but ONLY if the Rust backend
    // actually loaded.  On developer machines where the .so is not built,
    // bridge.isAvailable is false and we skip this to avoid a crash.
    if (widget.bridge.isAvailable) {
      // contextAddress is the raw memory address of the Rust context pointer,
      // passed as an integer so it can cross the isolate boundary safely.
      // See event_bus.dart for a detailed explanation of why this works.
      EventBus.instance.start(widget.bridge.contextAddress);
    }
  }

  // ---------------------------------------------------------------------------
  // dispose()
  //
  // Flutter calls this when the widget is permanently removed from the tree
  // (i.e. the app is closing).  This is where we clean up resources to prevent
  // memory leaks and ensure a clean shutdown.
  // ---------------------------------------------------------------------------
  @override
  void dispose() {
    // Kill the background polling isolate and close the message port.
    EventBus.instance.stop();
    // Call mesh_destroy() in Rust to flush state, close sockets, free memory.
    widget.bridge.dispose();
    super.dispose(); // Always call super last in dispose().
  }

  // ---------------------------------------------------------------------------
  // build()
  //
  // Flutter calls this whenever the widget needs to be drawn.  It should be a
  // pure function of the current state — no side effects.  It returns a widget
  // tree description; Flutter does the actual rendering.
  // ---------------------------------------------------------------------------
  @override
  Widget build(BuildContext context) {
    // -------------------------------------------------------------------------
    // MultiProvider
    //
    // WHAT IS A PROVIDER?
    // Provider is a Flutter state management pattern.  It allows you to make
    // an object available to ANY widget that is a descendant in the widget tree,
    // without manually passing it down through every layer of constructors.
    //
    // Think of it like a dependency injection container that is built into the
    // widget tree.  Any widget can call `context.watch<SomeState>()` or
    // `context.read<SomeState>()` to get the instance.
    //
    // WHY NOT JUST USE GLOBAL VARIABLES?
    // Providers participate in Flutter's lifecycle:
    //   - They are created when the widget appears and disposed when it disappears.
    //   - ChangeNotifierProvider automatically rebuilds listener widgets when
    //     the state object calls notifyListeners().
    //   - Testing is easier: you can swap in a fake Provider in tests.
    //
    // WHAT IS ChangeNotifierProvider?
    // ChangeNotifier is a Dart mixin/class that provides an addListener/
    // notifyListeners mechanism.  ChangeNotifierProvider wraps it and wires
    // up Flutter's rebuild system: when the notifier calls notifyListeners(),
    // any widget that used context.watch<T>() is automatically rebuilt.
    //
    // WHAT IS MultiProvider?
    // MultiProvider is just syntactic sugar for nesting multiple Providers.
    // Without it we'd have deeply nested code like:
    //   Provider(child: Provider(child: Provider(child: ...)))
    // -------------------------------------------------------------------------
    return MultiProvider(
      providers: [
        // Plain Provider (not Change Notifier) — BackendBridge never changes
        // after startup, so we don't need rebuild notifications for it.
        // Widgets access it with: context.read<BackendBridge>()
        Provider<BackendBridge>.value(value: widget.bridge),

        // ShellState tracks which section of the app (Chat/Files/Peers/Network/
        // Settings) is currently visible, and which item is selected within it.
        ChangeNotifierProvider(create: (_) => ShellState()),

        // MessagingState manages the list of rooms and their messages.
        // It subscribes to the EventBus stream to receive real-time message events.
        ChangeNotifierProvider(
          create: (_) => MessagingState(widget.bridge),
        ),

        // PeersState manages the list of known peers and their online/trust status.
        ChangeNotifierProvider(
          create: (_) => PeersState(widget.bridge),
        ),

        // FilesState manages active and recent file transfers.
        ChangeNotifierProvider(
          create: (_) => FilesState(widget.bridge),
        ),

        // NetworkState manages transport toggles, mDNS state, and network stats.
        ChangeNotifierProvider(
          create: (_) => NetworkState(widget.bridge),
        ),

        // SettingsState manages user preferences and the local identity.
        ChangeNotifierProvider(
          create: (_) => SettingsState(widget.bridge),
        ),
      ],
      // -----------------------------------------------------------------------
      // MaterialApp
      //
      // MaterialApp is Flutter's top-level widget for Material Design apps.
      // It provides:
      //   - Navigation (routing between screens)
      //   - Theme (colours, typography, component styles)
      //   - Localisation (language support)
      //   - MediaQuery (screen size information to all descendants)
      //   - Various global overlays (Snackbar, Dialog, BottomSheet hosts)
      //
      // All providers above are ancestors of MaterialApp, so every widget
      // inside it can access them via BuildContext.
      // -----------------------------------------------------------------------
      child: MaterialApp(
        title: 'Mesh Infinity', // Shown in the OS task switcher.
        theme: MeshTheme.light(),     // Light mode theme with brand colours.
        darkTheme: MeshTheme.dark(),  // Dark mode theme — Flutter picks based on OS.
        debugShowCheckedModeBanner: false, // Hide the red "DEBUG" ribbon in dev builds.
        home: _buildHome(), // The first screen shown when the app opens.
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // _buildHome()
  //
  // Decides which screen to show as the app's home screen.
  //
  // ONBOARDING LOGIC:
  //   - If the Rust backend has NO saved identity (first ever launch on this
  //     device) AND the user hasn't completed onboarding yet in this session,
  //     show the OnboardingScreen so they can create or import an identity.
  //   - Once they complete onboarding (the callback fires, we call setState
  //     to set _onboardingComplete = true), we rebuild and now show AppShell.
  //   - On subsequent launches where an identity already exists, we skip
  //     onboarding entirely and go straight to AppShell.
  //
  // WHY setState()?
  // setState() tells Flutter "my state has changed, please call build() again".
  // The closure passed to setState() performs the mutation; Flutter then
  // schedules a rebuild.  This is the fundamental Flutter pattern for updating
  // the UI in response to user actions.
  // ---------------------------------------------------------------------------
  Widget _buildHome() {
    if (!_hasIdentity && !_onboardingComplete) {
      // First run: show the onboarding screen.
      // The `onComplete` callback is called by OnboardingScreen when the user
      // finishes setting up their identity.  We use setState to flip the flag
      // and trigger a rebuild, which will then fall through to AppShell.
      return OnboardingScreen(
        onComplete: () => setState(() => _onboardingComplete = true),
      );
    }
    // Returning user (or just-completed onboarding): show the full app shell
    // with navigation, all features, and the complete UI.
    return const AppShell();
  }
}
