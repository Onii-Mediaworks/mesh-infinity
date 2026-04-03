// onboarding_screen.dart
//
// WHY does onboarding exist?
// --------------------------
// Mesh Infinity is a peer-to-peer encrypted messaging app.  Every node in
// the network is identified by a *cryptographic identity* — a public/private
// key pair generated on-device.  Without this identity the app cannot:
//   • Prove to other peers who it is.
//   • Encrypt or decrypt any message.
//   • Participate in the mesh network at all.
//
// On the very first launch there is no identity stored on disk.  The app
// detects this (in app.dart) and routes the user here before showing the
// main shell.  Onboarding walks the user through either:
//   (a) Creating a brand new identity (generates a fresh key pair), or
//   (b) Restoring an existing identity from an encrypted backup.
//
// After the key pair exists the user is given the chance to set up two
// profiles:
//   Public profile  — a display name that *might* be visible to unknown peers.
//   Private profile — personal notes stored only on this device.
//
// Once both profile steps are completed, widget.onComplete() is called,
// which dismisses the onboarding screen and shows the main app shell.
//
// WHAT is a public/private key pair?
// ------------------------------------
// Public-key cryptography (also called asymmetric cryptography) works by
// generating two mathematically linked numbers:
//
//   Private key — kept secret, never shared.  Used to SIGN outgoing messages
//                 and DECRYPT incoming ones.
//
//   Public key  — shareable freely (like a username or address).  Others use
//                 it to VERIFY your signatures and ENCRYPT messages only you
//                 can read.
//
// The pair is generated on the device (in Rust, via the backend) using a
// cryptographically secure random number generator.  No server is involved —
// the user's identity exists only on their device.
//
// WHY must identity creation happen before anything else?
// -------------------------------------------------------
// Every action in the app is tied to an identity:
//   - Sending a message requires signing it with the private key.
//   - Joining a room requires proving identity to other members.
//   - The peer ID (shown in QR codes) is derived from the public key.
//
// Without an identity the app literally has nothing to identify the local
// node as, so the backend refuses to do anything meaningful.
//
// WIZARD PATTERN
// --------------
// This screen uses the "wizard" (also called "stepper") pattern: a linear
// sequence of screens where each screen gathers one piece of information and
// the user can only proceed forward (or back) through the sequence.  This is
// simpler for the user than a single large form with many fields because:
//   - One decision at a time reduces cognitive load.
//   - Each step can be validated independently.
//   - Error messages appear close to the relevant input.
//
// The steps are driven by the _Step enum and _buildStep() method below.

import 'package:flutter/material.dart';
// material.dart is Flutter's Material Design widget library.
// It provides Scaffold, TextField, FilledButton, Column, AnimatedSwitcher, etc.

import 'package:provider/provider.dart';
// provider.dart lets us reach BackendBridge (the Rust FFI layer) from any
// widget without passing it through every constructor manually.

import '../backend/backend_bridge.dart';
// BackendBridge wraps all calls to the Rust backend via FFI (Foreign Function
// Interface).  It is the only place where the Flutter side talks to Rust.

// ---------------------------------------------------------------------------
// _Step — the onboarding wizard's internal page sequence
// ---------------------------------------------------------------------------

/// Private enum that names each screen in the onboarding wizard.
/// Being private (leading underscore) means it cannot be used outside this file.
///
/// The sequence is:
///   choice        — "Create new" vs "Import backup"
///   importBackup  — paste passphrase + backup JSON (only reached via Import)
///   identity      — set your private identity name; this is your primary mask
///                   and the "self" shown to trusted contacts
///   publicProfile — optional: set a public display name; toggle discoverability
enum _Step { choice, importBackup, identity, publicProfile }

// ---------------------------------------------------------------------------
// OnboardingScreen — the top-level StatefulWidget
// ---------------------------------------------------------------------------

/// The full-screen wizard shown on first launch.
///
/// What is a StatefulWidget?
/// -------------------------
/// Flutter widgets come in two flavours:
///   StatelessWidget — has no mutable internal data; just maps inputs → UI.
///   StatefulWidget  — has a companion State object that can mutate over time.
///                     When the state changes and setState() is called, Flutter
///                     rebuilds only the affected subtree.
///
/// We need StatefulWidget here because the wizard tracks:
///   - Which step is currently visible (_step).
///   - Whether an async operation is in flight (_busy).
///   - Error messages from the backend (_error).
///   - Text typed into name/bio/passphrase fields (via TextEditingControllers).
///
/// [onComplete] is a callback provided by the parent (app.dart).  When we
/// call it, the parent knows onboarding finished and switches to the main app.
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key, required this.onComplete});

  /// Called once, after the user taps "Get Started" at the end of the wizard.
  /// The parent (app.dart) uses this to hide OnboardingScreen and show the
  /// main AppShell.
  final VoidCallback onComplete;
  // VoidCallback is Dart shorthand for `void Function()` — a function that
  // takes no arguments and returns nothing.

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

// ---------------------------------------------------------------------------
// _OnboardingScreenState — the mutable half of OnboardingScreen
// ---------------------------------------------------------------------------

/// Holds all mutable state for the onboarding wizard.
///
/// The State object lives as long as OnboardingScreen is in the widget tree.
/// setState() is the mechanism that tells Flutter "my data changed, please
/// rebuild the widgets."
class _OnboardingScreenState extends State<OnboardingScreen> {
  /// Which step (page) of the wizard is currently shown.
  /// Starts at choice — the very first screen.
  _Step _step = _Step.choice;

  /// True while an async backend call (createIdentity, importIdentity) is
  /// running.  Used to disable buttons and show a loading spinner so the user
  /// knows work is happening and can't accidentally trigger a second request.
  bool _busy = false;

  /// An error message from the last backend call, or null if there was no
  /// error.  Shown as a red banner above the action buttons.
  String? _error;

  // -------------------------------------------------------------------------
  // TextEditingControllers — bridges between TextField widgets and our code
  // -------------------------------------------------------------------------
  // A TextEditingController is a Flutter object that lets code read (and
  // optionally write) the text currently in a TextField.  We create one
  // controller per input field and dispose them in dispose() to free memory.

  /// Display name for the public profile (what other peers might see).
  final _pubName = TextEditingController();

  /// Whether the user's identity is discoverable by strangers.
  /// Starts false ("don't show my identity publicly" is pre-checked by default)
  /// because privacy-first is the safer default for an encrypted mesh app.
  bool _identityPublic = false;

  /// Name for the primary private identity — shown to trusted contacts.
  /// This is the user's "self" on Mesh Infinity (the primary mask from a
  /// crypto perspective, but simply "your name" from a UX perspective).
  final _nameController = TextEditingController();

  /// Bio / personal notes for the private identity (device-only).
  final _privBio = TextEditingController();

  /// Multi-line field for the import wizard: line 1 = passphrase, rest = JSON.
  final _phrase = TextEditingController();

  // -------------------------------------------------------------------------
  // Lifecycle — dispose() cleans up controllers to prevent memory leaks
  // -------------------------------------------------------------------------

  @override
  void dispose() {
    // TextEditingControllers hold references to native text-editing resources.
    // Calling dispose() releases them when this State object is removed from
    // the tree.  Forgetting this would cause a memory leak.
    _pubName.dispose();
    _nameController.dispose();
    _privBio.dispose();
    _phrase.dispose();
    super.dispose(); // Always call super.dispose() last.
  }

  // -------------------------------------------------------------------------
  // Backend actions
  // -------------------------------------------------------------------------
  //
  // Each action follows the same async pattern:
  //   1. Read the bridge from the Provider (context.read — no rebuild needed).
  //   2. Set _busy = true via setState so the UI shows a spinner.
  //   3. Call the synchronous bridge method (Rust via FFI — fast in practice).
  //   4. Check `mounted` to guard against the widget being disposed mid-flight.
  //   5. Set _busy = false and either advance the wizard or show _error.
  //
  // WHY are these marked `async` if the bridge calls are synchronous?
  // -----------------------------------------------------------------
  // In Dart, `async` functions return a Future, which allows callers to `await`
  // them and allows the method body to use `await` for any future work.  Even
  // if the body doesn't currently have any `await` expressions, marking the
  // function `async` is a forward-compatibility choice: if the backend later
  // needs a real asynchronous operation (e.g. a network handshake), the
  // signature stays the same and callers don't need updating.
  //
  // Also note: these functions are called with `onCreateNew: _createIdentity`
  // (a function reference, not a call).  The caller type is VoidCallback
  // (void Function()) not Future<void> Function(), but Dart allows assigning
  // an async function to a VoidCallback — the Future is simply not awaited by
  // the callback handler, which is fine here because errors are handled
  // internally via _error state.

  /// Ask the Rust backend to generate a new cryptographic identity (key pair).
  ///
  /// This is an async function (marked with `async`) because in principle the
  /// key generation could take time.  In practice it is fast, but we still
  /// show a spinner so the UI never appears frozen.
  ///
  /// On success:  advance to the publicProfile step.
  /// On failure:  show the error returned by the backend.
  Future<void> _createIdentity() async {
    // context.read<T>() fetches a Provider-supplied object without subscribing
    // to changes (we just need it once here, not ongoing).
    //
    // We use read (not watch) here because:
    //   - We only need the bridge once — we are not building UI based on it.
    //   - Using watch inside an event handler (rather than build()) can cause
    //     spurious rebuilds or assertion failures in some Provider versions.
    final bridge = context.read<BackendBridge>();

    // setState() is the Flutter mechanism to update State-owned variables and
    // trigger a rebuild.  Everything inside the lambda runs synchronously;
    // after the lambda returns, Flutter schedules a rebuild of this widget.
    // We set _busy = true so the button disables and a spinner appears.
    setState(() {
      _busy = true;
      _error = null; // Clear any previous error.
    });

    // Call through to Rust via FFI.  Returns true on success.
    // Even though it is declared as synchronous (bool, not Future<bool>),
    // the Dart await-able nature of this async function means other microtasks
    // can run between the setState above and the code below if there were any
    // explicit await expressions — but there are none here, so execution is
    // actually continuous.
    final ok = bridge.createIdentity();

    // After an async gap, the widget might have been removed from the tree
    // (e.g. the user rotated the screen and Flutter rebuilt).  Checking
    // `mounted` prevents setState() calls on a dead State object, which
    // would throw an exception.
    //
    // `mounted` is a property on the State base class.  It is true while the
    // State object is attached to the widget tree and false after dispose().
    if (!mounted) return;

    if (ok) {
      // Start accepting incoming clearnet connections now that the identity
      // is live.  Pairing requires the listener to be running so the other
      // side can reach us after scanning our QR code.
      bridge.startClearnetListener();
      setState(() {
        _busy = false;
        _step = _Step.identity; // Advance to "Your Identity" step.
      });
    } else {
      setState(() {
        _busy = false;
        // getLastError() retrieves the most recent error string from the
        // Rust backend.  If it's null (shouldn't happen) we fall back to a
        // generic message.
        //
        // The `??` operator is Dart's "if-null" operator:
        //   a ?? b  means  a != null ? a : b
        // So this reads: "use the error from the backend; if that's null,
        // use the fallback string instead."
        _error = bridge.getLastError() ?? 'Failed to create identity.';
      });
    }
  }

  /// Parse the multi-line import field and send the backup to Rust for decryption.
  ///
  /// The field format is:
  ///   Line 1:      the user's passphrase (used to decrypt the backup)
  ///   Remaining:   the backup JSON payload (the EncryptedBackup struct)
  ///
  /// This two-in-one field avoids having two separate inputs, which reduces
  /// confusion for users doing a manual recovery process.
  Future<void> _importBackup() async {
    final text = _phrase.text.trim(); // Remove leading/trailing whitespace.

    // Guard: the field must not be empty.
    if (text.isEmpty) {
      setState(() => _error = 'Please enter your passphrase and backup data.');
      return;
    }

    // Split on the first newline.  Everything before it is the passphrase;
    // everything after is the JSON backup blob.
    final newlineIdx = text.indexOf('\n');

    // If there is no newline, the user only typed a passphrase with no JSON.
    final passphrase =
        newlineIdx >= 0 ? text.substring(0, newlineIdx).trim() : text;
    final backupJson =
        newlineIdx >= 0 ? text.substring(newlineIdx + 1).trim() : '';

    // Guard: the JSON portion must not be empty.
    if (backupJson.isEmpty) {
      setState(() => _error =
          'Paste your passphrase on the first line and the backup JSON below it.');
      return;
    }

    final bridge = context.read<BackendBridge>();
    setState(() {
      _busy = true;
      _error = null;
    });

    // Hand both pieces to the Rust backend, which will decrypt the backup
    // and store the recovered key pair on disk.
    final ok = bridge.importIdentity(backupJson: backupJson, passphrase: passphrase);
    if (!mounted) return;

    if (ok) {
      bridge.startClearnetListener();
      setState(() {
        _busy = false;
        _step = _Step.identity; // Advance to "Your Identity" step.
      });
    } else {
      setState(() {
        _busy = false;
        _error = bridge.getLastError() ??
            'Import failed. Check your passphrase and backup data.';
      });
    }
  }

  /// Save both profile payloads to the backend and call [onComplete] to
  /// dismiss onboarding.
  ///
  /// This is called from the final wizard step ("Get Started" button).
  /// It writes the public and private profiles synchronously (they are just
  /// JSON writes in Rust — no network round-trip), then invokes the parent's
  /// callback which swaps the UI from OnboardingScreen → AppShell.
  ///
  /// NOTE: This method is NOT async because both bridge calls are synchronous
  /// (simple disk writes) and there is no need to show a spinner — they are
  /// fast enough that the user will not notice any delay before onComplete()
  /// removes the onboarding screen.
  void _finishProfiles() {
    final bridge = context.read<BackendBridge>();

    // Read the text fields.  trim() removes accidental leading/trailing spaces.
    // controller.text is the current string in the TextField controlled by
    // that TextEditingController.
    final pubName  = _pubName.text.trim();
    final privName = _nameController.text.trim();
    final bio      = _privBio.text.trim();

    // Write the public profile.  Empty strings become null so the backend
    // knows "the user left this field blank" rather than "their name is ''".
    //
    // The ternary `pubName.isEmpty ? null : pubName` reads:
    //   "If pubName is an empty string, pass null; otherwise pass pubName."
    // This lets the Rust backend distinguish between "field was left blank"
    // and "field was filled with a value" — an important semantic difference
    // when merging profiles later.
    final pubOk = bridge.setPublicProfile(
      displayName: pubName.isEmpty ? null : pubName,
      isPublic: _identityPublic,
    );

    // Write the private profile (device-only, never sent over the network).
    // Same null-for-blank convention as the public profile above.
    final privOk = bridge.setPrivateProfile(
      displayName: privName.isEmpty ? null : privName,
      bio: bio.isEmpty ? null : bio,
    );

    if (!pubOk || !privOk) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Failed to save profile. Please try again.'),
          ),
        );
      }
      return;
    }

    // Tell the parent that onboarding is finished.  The parent (app.dart)
    // will remove OnboardingScreen from the tree and show the main AppShell.
    //
    // `widget` is how a State object accesses the fields of its associated
    // StatefulWidget.  In Flutter, the State class has a built-in `widget`
    // getter that returns the StatefulWidget it belongs to.  So
    // `widget.onComplete` is the VoidCallback that was passed to the
    // OnboardingScreen constructor.
    widget.onComplete();
  }

  // -------------------------------------------------------------------------
  // Widget build — the UI
  // -------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      // Scaffold provides the white (or themed) background surface.
      body: SafeArea(
        // SafeArea adds padding to avoid overlapping the status bar, notch,
        // or home indicator on phones so content is always visible.
        child: Center(
          // Center positions its child at the middle of the screen.
          child: SingleChildScrollView(
            // SingleChildScrollView allows the content to scroll if the
            // soft keyboard pushes the layout off-screen on small phones.
            padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 24),
            child: ConstrainedBox(
              // ConstrainedBox caps the width at 420 px so on wide screens
              // the form doesn't stretch to an unreadable 1000-pixel width.
              // This is a common pattern for centred form-based screens.
              constraints: const BoxConstraints(maxWidth: 420),
              child: AnimatedSwitcher(
                // AnimatedSwitcher cross-fades between its child widgets.
                // When _step changes, _buildStep() returns a different child
                // and AnimatedSwitcher fades from the old one to the new one
                // over 250 ms, giving a smooth page transition.
                duration: const Duration(milliseconds: 250),
                transitionBuilder: (child, anim) => FadeTransition(
                  // FadeTransition ties a widget's opacity to an Animation<double>.
                  // anim goes from 0.0 → 1.0 as the new child appears.
                  opacity: anim,
                  child: child,
                ),
                // _buildStep() returns the widget for the current wizard step.
                child: _buildStep(),
              ),
            ),
          ),
        ),
      ),
    );
  }

  /// Maps the current _step value to the correct step widget.
  ///
  /// Each step widget is a separate private class defined below.  We pass
  /// callbacks into them so they can trigger state transitions without knowing
  /// about the parent State.  This keeps each step widget simple and focused.
  ///
  /// PATTERN: callback-based communication between parent State and child widgets
  /// -----------------------------------------------------------------------------
  /// Because each step (_ChoiceStep, _ImportStep, etc.) is a StatelessWidget,
  /// it cannot directly call setState() on the parent.  Instead, the parent
  /// passes closures (anonymous functions) as arguments.  When the child
  /// needs to advance the wizard, it calls the closure, which runs in the
  /// parent's context and can call setState().
  ///
  /// This is sometimes called "lifting state up" or the "callback pattern" and
  /// is the standard Flutter way to let child widgets communicate with parents
  /// without tight coupling between the two.
  Widget _buildStep() {
    switch (_step) {
      case _Step.choice:
        return _ChoiceStep(
          // ValueKey is required by AnimatedSwitcher to tell which child is
          // "old" and which is "new" when animating.  Without a key it might
          // fail to detect that the child changed.
          //
          // Keys in Flutter are identifiers attached to widgets.  When Flutter
          // rebuilds a widget tree, it uses keys to match old widgets to new
          // widgets.  AnimatedSwitcher specifically requires that its children
          // have different keys so it can detect when the child changes and
          // trigger the transition animation.  ValueKey(x) creates a key from
          // any value — here we use the enum value itself as the key.
          key: const ValueKey(_Step.choice),
          busy: _busy,
          error: _error,
          onCreateNew: _createIdentity,
          // onImport just transitions to the importBackup step; the actual
          // import is triggered from within _ImportStep.
          onImport: () => setState(() {
            _step = _Step.importBackup;
            _error = null; // Clear error when switching steps.
          }),
        );

      case _Step.importBackup:
        return _ImportStep(
          key: const ValueKey(_Step.importBackup),
          controller: _phrase, // The shared TextEditingController for the paste field.
          busy: _busy,
          error: _error,
          onImport: _importBackup,
          onBack: () => setState(() {
            _step = _Step.choice;
            _error = null;
          }),
        );

      case _Step.identity:
        return _IdentityStep(
          key: const ValueKey(_Step.identity),
          nameController: _nameController,
          bioController: _privBio,
          onNext: () => setState(() => _step = _Step.publicProfile),
        );

      case _Step.publicProfile:
        return _PublicProfileStep(
          key: const ValueKey(_Step.publicProfile),
          controller: _pubName,
          isPublic: _identityPublic,
          // onPublicChanged toggles the _identityPublic flag; the setState
          // triggers a rebuild so the checkbox re-renders with the new value.
          onPublicChanged: (v) => setState(() => _identityPublic = v),
          onNext: _finishProfiles,  // "Get Started" — save and leave onboarding.
          onSkip: _finishProfiles,  // "Skip" — save with public profile blank.
          onBack: () => setState(() => _step = _Step.identity),
        );
    }
  }
}

// ---------------------------------------------------------------------------
// Shared header widget
// ---------------------------------------------------------------------------

/// Displays the app logo, the "Mesh Infinity" name, a step title, and an
/// optional subtitle.  Reused at the top of every wizard step for visual
/// consistency.
class _Header extends StatelessWidget {
  const _Header({required this.title, this.subtitle});

  /// Short step title shown below the app name (e.g. "Welcome", "Import Backup").
  final String title;

  /// Optional explanatory sentence shown below the title in smaller text.
  /// The `?` means this can be null (omitted when not needed).
  final String? subtitle;

  @override
  Widget build(BuildContext context) {
    // Theme.of(context).colorScheme gives access to the app's colour palette
    // (primary, surface, outline, etc.) as defined in app_theme.dart.
    final cs = Theme.of(context).colorScheme;
    return Column(
      children: [
        const SizedBox(height: 16), // Breathing room at the top.
        const _Logo(size: 64),      // App icon — 64×64 logical pixels.
        const SizedBox(height: 16),
        Text(
          'Mesh Infinity',
          // textTheme provides pre-defined text styles scaled to the device's
          // accessibility font size setting.
          style: Theme.of(context).textTheme.headlineMedium?.copyWith(
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 8),
        Text(title, style: Theme.of(context).textTheme.titleMedium),
        // The `if (condition) ...[widgets]` syntax is Dart's collection-if:
        // the subtitle widgets are only added to the Column's children list
        // when subtitle is not null.
        if (subtitle != null) ...[
          const SizedBox(height: 4),
          Text(
            subtitle!,
            // The `!` (bang) asserts non-null — safe here because we checked
            // `subtitle != null` in the if condition above.
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: cs.onSurfaceVariant, // Muted colour for secondary text.
            ),
          ),
        ],
        const SizedBox(height: 32), // Space between header and form fields.
      ],
    );
  }
}

/// Loads the app logo from assets, falling back to an icon if the image file
/// is missing (e.g. on a development build that doesn't yet have the asset).
class _Logo extends StatelessWidget {
  const _Logo({required this.size});

  /// Width and height in logical pixels (device-independent).
  final double size;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Image.asset(
      '../assets/logo.png',
      width: size,
      height: size,
      // errorBuilder is called if the image cannot be loaded.  The fallback
      // is a hub icon in the primary brand colour — good enough for dev builds.
      errorBuilder: (context, error, stackTrace) =>
          Icon(Icons.hub_rounded, size: size, color: cs.primary),
    );
  }
}

// ---------------------------------------------------------------------------
// Step 1: choice — "Create New Identity" or "Import Backup"
// ---------------------------------------------------------------------------

/// The first screen the user sees.  Explains the app in one line and offers
/// two mutually exclusive paths through the wizard.
class _ChoiceStep extends StatelessWidget {
  const _ChoiceStep({
    super.key,
    required this.busy,
    required this.error,
    required this.onCreateNew,
    required this.onImport,
  });

  /// True while the identity creation call to Rust is in-flight.
  /// Disables both buttons to prevent double-taps.
  final bool busy;

  /// Error string from the last attempt, or null.
  final String? error;

  /// Called when the user taps "Create New Identity".
  final VoidCallback onCreateNew;

  /// Called when the user taps "Import Backup" — just transitions the wizard
  /// to the import step; no async work happens here.
  final VoidCallback onImport;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min, // Don't expand to fill height unnecessarily.
      children: [
        const _Header(
          title: 'Welcome',
          subtitle: 'Decentralised, encrypted peer-to-peer messaging.',
        ),

        // Show the error banner only if there is an error to display.
        if (error != null) ...[
          _ErrorBanner(error!),
          const SizedBox(height: 16),
        ],

        // FilledButton is the high-emphasis Material 3 button (solid colour).
        // Used for the primary action — "Create New Identity".
        FilledButton.icon(
          // Passing null to onPressed disables the button.  When busy == true
          // the button is greyed out and ignores taps.
          onPressed: busy ? null : onCreateNew,
          // Show a spinner inside the button while work is in progress.
          icon: busy
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.person_add_rounded),
          label: const Text('Create New Identity'),
          style: FilledButton.styleFrom(
            // double.infinity makes the button stretch to fill the column width.
            minimumSize: const Size(double.infinity, 52),
          ),
        ),

        const SizedBox(height: 12),

        // OutlinedButton is the medium-emphasis Material 3 button (border only).
        // Used for the secondary action — "Import Backup".
        OutlinedButton.icon(
          onPressed: busy ? null : onImport,
          icon: const Icon(Icons.download_rounded),
          label: const Text('Import Backup'),
          style: OutlinedButton.styleFrom(
            minimumSize: const Size(double.infinity, 52),
          ),
        ),

        const SizedBox(height: 8),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Step 2 (optional): import backup
// ---------------------------------------------------------------------------

/// Shown only if the user chose "Import Backup" on the choice screen.
/// Accepts a multi-line text blob: passphrase on line 1, backup JSON below.
class _ImportStep extends StatelessWidget {
  const _ImportStep({
    super.key,
    required this.controller,
    required this.busy,
    required this.error,
    required this.onImport,
    required this.onBack,
  });

  /// Shared controller — reading controller.text gives the pasted content.
  final TextEditingController controller;

  /// True while the import call is running.
  final bool busy;

  /// Error string, or null.
  final String? error;

  /// Called when the user taps "Import" — triggers _importBackup() in the parent.
  final VoidCallback onImport;

  /// Called when the user taps "Back" — returns to the choice screen.
  final VoidCallback onBack;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch, // Buttons fill the full width.
      children: [
        const _Header(
          title: 'Import Backup',
          subtitle:
              'Paste your passphrase on the first line, then your backup JSON below it.',
        ),

        if (error != null) ...[
          _ErrorBanner(error!),
          const SizedBox(height: 16),
        ],

        // Multi-line text field for the combined passphrase + JSON input.
        // minLines/maxLines create a field tall enough to show a few lines
        // of JSON without becoming unwieldy.
        TextField(
          controller: controller,
          enabled: !busy, // Disable typing while import is running.
          minLines: 3,
          maxLines: 6,
          decoration: const InputDecoration(
            labelText: 'Backup phrase',
            hintText: 'passphrase\n{"version":1,"salt":...}',
            border: OutlineInputBorder(),
          ),
        ),

        const SizedBox(height: 20),

        FilledButton(
          onPressed: busy ? null : onImport,
          style: FilledButton.styleFrom(minimumSize: const Size(double.infinity, 52)),
          // Show a spinner inside the button while the import runs.
          child: busy
              ? const SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Import'),
        ),

        const SizedBox(height: 12),

        // TextButton is the low-emphasis Material 3 button (text only).
        // Used for "Back" — it's a secondary action and shouldn't compete
        // visually with the primary "Import" button.
        TextButton(
          onPressed: busy ? null : onBack,
          child: const Text('Back'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Step 3: public profile
// ---------------------------------------------------------------------------

/// Lets the user optionally set a public display name and choose whether
/// their peer ID is advertised on the network.
///
/// This is the final onboarding step and is skippable — tapping "Skip"
/// leaves the public profile blank (identity_is_public = false) and
/// completes onboarding.  Tapping "Get Started" saves whatever the user
/// entered and also completes onboarding.
///
/// WHY have a public profile at all?
/// ----------------------------------
/// In a mesh network, other nodes can discover your device.  By default we
/// keep the identity private (only share with contacts you add).  This step
/// makes that choice explicit and lets users opt into discoverability.
class _PublicProfileStep extends StatelessWidget {
  const _PublicProfileStep({
    super.key,
    required this.controller,
    required this.isPublic,
    required this.onPublicChanged,
    required this.onNext,
    required this.onSkip,
    required this.onBack,
  });

  /// Controller for the public display name text field.
  final TextEditingController controller;

  /// Whether the user's identity is currently set to public.
  final bool isPublic;

  /// Called when the user toggles the "show publicly" checkbox.
  final ValueChanged<bool> onPublicChanged;

  /// Called when the user taps "Get Started" — saves and exits onboarding.
  final VoidCallback onNext;

  /// Called when the user taps "Skip" — saves with blank public profile.
  final VoidCallback onSkip;

  /// Returns to the identity step.
  final VoidCallback onBack;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const _Header(
          title: 'Public Profile',
          subtitle:
              'Optional — let the network know you\'re here.\n'
              'Leave blank to stay private.',
        ),

        // Optional public display name — shown to other peers if discoverable.
        TextField(
          controller: controller,
          decoration: const InputDecoration(
            labelText: 'Public display name (optional)',
            hintText: 'e.g. Alice',
            border: OutlineInputBorder(),
          ),
        ),

        const SizedBox(height: 8),

        Card(
          margin: EdgeInsets.zero,
          child: CheckboxListTile(
            // The checkbox tracks "show publicly" directly.
            value: isPublic,
            onChanged: (v) => onPublicChanged(v ?? false),
            title: const Text('Show my identity publicly'),
            subtitle: Text(
              'Other nodes on the mesh can discover and contact you.',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
              ),
            ),
            controlAffinity: ListTileControlAffinity.leading,
            contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          ),
        ),

        const SizedBox(height: 24),

        FilledButton.icon(
          onPressed: onNext,
          icon: const Icon(Icons.arrow_forward_rounded),
          label: const Text('Get Started'),
          style: FilledButton.styleFrom(minimumSize: const Size(double.infinity, 52)),
        ),

        const SizedBox(height: 12),

        // "Skip" saves with an empty public profile and goes straight to the app.
        TextButton(
          onPressed: onSkip,
          child: const Text('Skip'),
        ),

        TextButton(
          onPressed: onBack,
          child: const Text('Back'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Step 3: identity — primary private identity ("Your Identity")
// ---------------------------------------------------------------------------

/// Collects the user's private identity name and an optional bio.
///
/// This is the user's primary mask — the "self" they present to trusted
/// contacts.  From a UX perspective this IS the user; from a crypto
/// perspective it is the primary mask derived from the root key pair.
///
/// The name and bio are stored device-only and shared only with contacts
/// the user explicitly trusts.  They are never transmitted publicly.
class _IdentityStep extends StatelessWidget {
  const _IdentityStep({
    super.key,
    required this.nameController,
    required this.bioController,
    required this.onNext,
  });

  /// Controller for the private identity name field.
  final TextEditingController nameController;

  /// Controller for the optional bio / personal notes field.
  final TextEditingController bioController;

  /// Advances to the optional public profile step.
  final VoidCallback onNext;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const _Header(
          title: 'Your identity',
          subtitle:
              'This is you on Mesh Infinity — the private identity\n'
              'you share with people you trust.',
        ),

        // The user's chosen name for trusted contacts.
        TextField(
          controller: nameController,
          decoration: const InputDecoration(
            labelText: 'Your name',
            hintText: 'What trusted contacts will call you',
            border: OutlineInputBorder(),
          ),
        ),

        const SizedBox(height: 16),

        // Optional bio — personal notes that never leave the device.
        TextField(
          controller: bioController,
          minLines: 3,
          maxLines: 6,
          decoration: const InputDecoration(
            labelText: 'About me (optional)',
            hintText: 'Notes for yourself…',
            border: OutlineInputBorder(),
          ),
        ),

        const SizedBox(height: 8),

        Text(
          'You can update this at any time in Settings.',
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
            color: cs.onSurfaceVariant,
          ),
        ),

        const SizedBox(height: 24),

        FilledButton(
          onPressed: onNext,
          style: FilledButton.styleFrom(minimumSize: const Size(double.infinity, 52)),
          child: const Text('Next'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Shared error banner
// ---------------------------------------------------------------------------

/// A styled red box that displays a warning icon and an error message.
/// Shown above the action buttons on any step where a backend call failed.
///
/// WHY use a dedicated widget instead of a plain Text?
/// ----------------------------------------------------
/// Error messages need to stand out clearly.  A plain Text in the normal
/// body colour is easy to miss.  The coloured container with a warning icon
/// is instantly recognisable as an error, matching user expectations from
/// native mobile apps.
class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner(this.message);

  /// The human-readable error text, typically from bridge.getLastError().
  final String message;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        // errorContainer is the Material 3 semantic colour for error
        // backgrounds — typically a light red that pairs with onErrorContainer.
        color: cs.errorContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          // Warning icon in the error foreground colour.
          Icon(Icons.warning_amber_rounded, color: cs.onErrorContainer, size: 20),
          const SizedBox(width: 8),
          // Expanded fills remaining row width so long messages wrap correctly
          // instead of overflowing off-screen.
          Expanded(
            child: Text(
              message,
              style: TextStyle(color: cs.onErrorContainer),
            ),
          ),
        ],
      ),
    );
  }
}
