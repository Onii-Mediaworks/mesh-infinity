// onboarding_screen.dart
//
// OVERVIEW — WHY THIS FILE EXISTS
// --------------------------------
// Mesh Infinity is a peer-to-peer encrypted mesh network app.  Every node is
// identified by a cryptographic identity — a public/private key pair generated
// on this device.  On the very first launch no identity exists, so app.dart
// detects that and routes here before showing the main shell.
//
// This wizard is also the mandatory point at which the user receives all
// "ambient state" disclosures required by §22.23: things that are always true
// about the system (relay participation, cover traffic, key storage location,
// etc.) that must be communicated before any message can be sent.
//
// THE 7-STEP ONBOARDING FLOW (§22.42, §22.23, §22.27)
// -------------------------------------------------------
// Step 0 — Welcome (_Step.welcome)
//   App name, brand logo, tagline.  Offers "Create new identity" and
//   "Import from backup."  This is the entry gate — the user hasn't touched
//   any cryptographic material yet.
//
// Step 1 — Create or Import (_Step.importBackup for import path)
//   "Create new identity" generates a fresh keypair via bridge.createIdentity()
//   and proceeds to step 2.  "Import" shows the import UI (passphrase + JSON).
//
// Step 2 — Your Identity (_Step.identity)
//   Sets the private identity name (the primary mask).  This is what trusted
//   contacts will see.  The backend receives the name as part of setPrivateProfile().
//   Do not use the word "mask" on this screen (§22.42.3 note).
//
// Step 3 — Public Presence (_Step.publicProfile)
//   Optionally set a public display name.  Entirely skippable — privacy-first.
//   If left blank, setPublicProfile() is called with displayName: null,
//   isPublic: false (§9.1 default).
//
// Step 4 — Ambient Disclosures (_Step.disclosures)
//   Mandatory.  Presents the §22.23 ambient state disclosures in clear,
//   non-scary language.  The "I understand" button is DISABLED until the user
//   scrolls to the bottom of the list — this prevents click-through without
//   reading, which is the entire point of mandatory disclosure.  This step
//   CANNOT be skipped.
//
// Step 5 — PIN Setup (_Step.pinSetup)
//   Strongly encouraged (§22.27.2) but skippable with an explicit warning.
//   Shows the benefit of a PIN ("prevents anyone who unlocks your phone from
//   reading your messages").  Offers inline PIN entry (not a push to PinScreen,
//   which is a separate full-screen flow) so the user stays in the onboarding
//   context.  A skip path shows an inline warning before allowing bypass.
//
// Step 6 — Done (_Step.done)
//   "You're set up. Your node is now part of the mesh."  Calls widget.onComplete()
//   which dismisses onboarding and shows AppShell.
//
// WHAT IS A KEYPAIR?
// -------------------
// Public-key cryptography generates two mathematically linked numbers:
//   Private key — kept secret; signs outgoing messages, decrypts incoming ones.
//   Public key  — shareable; others verify signatures and encrypt messages to you.
// The pair is generated entirely on-device (in Rust via secure RNG).  No server
// is involved — the identity exists only on this phone.
//
// WIZARD PATTERN
// ---------------
// Each step is a private _build* method.  A simple integer index (_stepIndex)
// drives which step is currently shown.  AnimatedSwitcher provides a 250ms
// cross-fade between steps.  No PageView is needed because the back button is
// disabled on some steps (Step 0, Step 4, Step 5) to prevent bypass.
//
// Back navigation is disabled on:
//   - Step 0 (Welcome) — nothing to go back to.
//   - Step 4 (Disclosures) — must not be bypassable by going back-then-forward.
//   - Step 5 (PIN Setup) — must not be bypassable by going back-then-forward.
//
// FFI CALL GAPS DOCUMENTED BELOW:
//   - bridge.setThreatContext() does NOT exist as a named bridge method for
//     threat level selection during onboarding; instead bridge.setThreatContext(int)
//     IS available (confirmed in backend_bridge.dart line 899).
//   - bridge.createIdentity(name: ...) passes the name as part of creation (line 665).
//   - Timeout/lock settings after PIN are written via bridge.setSecurityConfig().

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../app/app_theme.dart';
import '../backend/backend_bridge.dart';
import '../widgets/mask_avatar.dart';

// ---------------------------------------------------------------------------
// _Step — the wizard's named step sequence
// ---------------------------------------------------------------------------

/// Names each screen in the onboarding wizard.  Private (underscore prefix)
/// means it cannot be referenced outside this file.
///
/// The sequence is strictly linear.  Back navigation between some steps is
/// disabled (see file-level comment).
enum _Step {
  // Step 0 — App name, tagline, Create / Import choice.
  welcome,
  // Step 1 — Passphrase + backup JSON for import path (only reached via Import).
  importBackup,
  // Step 2 — Private identity name and avatar colour.
  identity,
  // Step 3 — Optional public display name.
  publicProfile,
  // Step 4 — Mandatory §22.23 ambient state disclosures.
  disclosures,
  // Step 5 — §22.27 PIN setup offer.
  pinSetup,
  // Step 6 — Done screen before calling onComplete().
  done,
}

// ---------------------------------------------------------------------------
// OnboardingScreen — top-level StatefulWidget
// ---------------------------------------------------------------------------

/// Full-screen wizard shown on first launch.
///
/// [onComplete] is called exactly once at the end of the flow.  The parent
/// (app.dart) uses it to replace this screen with AppShell.
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key, required this.onComplete});

  /// Invoked when the user taps "Get Started" at the end of step 6.
  final VoidCallback onComplete;

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

// ---------------------------------------------------------------------------
// _OnboardingScreenState — mutable state for the wizard
// ---------------------------------------------------------------------------

class _OnboardingScreenState extends State<OnboardingScreen> {
  // -------------------------------------------------------------------------
  // Step tracking
  // -------------------------------------------------------------------------

  /// The current wizard step.  Drives which _buildStep* method renders.
  _Step _step = _Step.welcome;

  // -------------------------------------------------------------------------
  // General async state
  // -------------------------------------------------------------------------

  /// True while a backend call is in progress — disables buttons, shows spinner.
  bool _busy = false;

  /// Most recent backend error, or null.  Shown as a red banner above buttons.
  String? _error;

  // -------------------------------------------------------------------------
  // Step 1 — Import backup
  // -------------------------------------------------------------------------

  /// Multi-line import field: line 1 = passphrase, lines 2+ = backup JSON.
  final _phraseController = TextEditingController();

  // -------------------------------------------------------------------------
  // Step 2 — Identity
  // -------------------------------------------------------------------------

  /// Private identity name — shown to trusted contacts only.
  final _nameController = TextEditingController();

  /// Selected avatar colour index into kMaskAvatarColors.  Defaults to 0
  /// (brand blue) — users can change it by tapping a colour swatch.
  int _selectedColorIndex = 0;

  // -------------------------------------------------------------------------
  // Step 3 — Public profile
  // -------------------------------------------------------------------------

  /// Optional public display name.  If empty on "Next", no public profile
  /// is set (isPublic: false, displayName: null — §9.1 default).
  final _publicNameController = TextEditingController();

  // -------------------------------------------------------------------------
  // Step 4 — Disclosures scroll gate
  // -------------------------------------------------------------------------

  /// Controls the disclosures scroll view.  We listen to this to track whether
  /// the user has scrolled far enough to enable the "I understand" button.
  late final ScrollController _disclosuresScrollCtrl = ScrollController()
    ..addListener(_onDisclosuresScroll);

  /// True once the user has scrolled to the bottom of the disclosures list.
  /// Only when true does the "I understand" button become active.
  bool _disclosuresRead = false;

  /// Called by the ScrollController whenever the scroll position changes.
  ///
  /// We consider "bottom reached" when the user is within 32 pixels of the
  /// maximum scroll extent.  A small tolerance (32px) accounts for rounding
  /// in the scroll physics and prevents the button from never enabling on
  /// devices where content fits exactly.
  void _onDisclosuresScroll() {
    if (_disclosuresRead) return; // already unlocked, no need to keep checking
    final pos = _disclosuresScrollCtrl.position;
    // Compare current offset to the maximum scrollable distance.
    // extentAfter is how many pixels remain below the current viewport edge.
    if (pos.extentAfter <= 32.0) {
      setState(() => _disclosuresRead = true);
    }
  }

  // -------------------------------------------------------------------------
  // Step 5 — PIN Setup
  // -------------------------------------------------------------------------

  /// PIN entry field (first entry — the one the user types initially).
  final _pinController = TextEditingController();

  /// PIN confirmation field (re-entry to confirm no typo).
  final _pinConfirmController = TextEditingController();

  /// True when the user tapped "Skip for now" — shows the inline warning
  /// container before allowing bypass.
  bool _showSkipWarning = false;

  /// True when the user tapped "Set a PIN" on the PIN step — shows the
  /// inline PIN entry form.
  bool _showPinForm = false;

  /// True when the two PIN fields don't match (shown as error text on confirm).
  bool _pinMismatch = false;

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  @override
  void dispose() {
    // Always dispose TextEditingControllers to free native text-editing resources.
    _phraseController.dispose();
    _nameController.dispose();
    _publicNameController.dispose();
    _pinController.dispose();
    _pinConfirmController.dispose();
    // Remove the listener before disposing to prevent use-after-free.
    _disclosuresScrollCtrl.removeListener(_onDisclosuresScroll);
    _disclosuresScrollCtrl.dispose();
    super.dispose();
  }

  // -------------------------------------------------------------------------
  // Step advance / back helpers
  // -------------------------------------------------------------------------

  /// Move forward one step.  The calling _buildStep* method is responsible for
  /// validating its own inputs before calling this.
  void _goTo(_Step target) {
    setState(() {
      _step = target;
      _error = null; // Clear any lingering error when changing steps.
    });
  }

  // -------------------------------------------------------------------------
  // Backend actions
  // -------------------------------------------------------------------------

  /// Create a fresh cryptographic identity via the Rust backend.
  ///
  /// Called when the user taps "Create new identity" on the Welcome screen.
  /// On success advances to _Step.identity.  On failure shows an error banner.
  ///
  /// The name is intentionally NOT passed here — the name is collected in the
  /// identity step and written later via setPrivateProfile().  Passing null
  /// creates an anonymous identity that the identity step then names.
  Future<void> _createIdentity() async {
    final bridge = context.read<BackendBridge>();
    setState(() {
      _busy = true;
      _error = null;
    });

    // createIdentity() is a synchronous FFI call that generates the keypair
    // and writes it to disk.  Fast in practice (< 100 ms).
    final ok = bridge.createIdentity();
    if (!mounted) return;

    if (ok) {
      setState(() {
        _busy = false;
        _step = _Step.identity;
      });
    } else {
      setState(() {
        _busy = false;
        _error = bridge.getLastError() ?? 'Failed to create identity.';
      });
    }
  }

  /// Import a backup using the passphrase + JSON from the import text field.
  ///
  /// The field format is: line 1 = passphrase, lines 2+ = backup JSON blob.
  /// On success advances to _Step.identity.
  Future<void> _doImport() async {
    final text = _phraseController.text.trim();
    if (text.isEmpty) {
      setState(() => _error = 'Please enter your passphrase and backup data.');
      return;
    }

    final newlineIdx = text.indexOf('\n');
    final passphrase =
        newlineIdx >= 0 ? text.substring(0, newlineIdx).trim() : text;
    final backupJson =
        newlineIdx >= 0 ? text.substring(newlineIdx + 1).trim() : '';

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

    final ok = bridge.importIdentity(
      backupJson: backupJson,
      passphrase: passphrase,
    );
    if (!mounted) return;

    if (ok) {
      setState(() {
        _busy = false;
        _step = _Step.identity;
      });
    } else {
      setState(() {
        _busy = false;
        _error = bridge.getLastError() ??
            'Import failed. Check your passphrase and backup data.';
      });
    }
  }

  /// Save private and public profiles at the end of the public-profile step.
  ///
  /// Writes both profiles to disk, then advances to the disclosures step.
  void _saveProfiles() {
    final bridge = context.read<BackendBridge>();

    final privName = _nameController.text.trim();
    final pubName = _publicNameController.text.trim();

    // Write private profile — the name the user set in step 2.
    final privOk = bridge.setPrivateProfile(
      displayName: privName.isEmpty ? null : privName,
    );

    // Write public profile — empty public name means stay anonymous (§9.1).
    final pubOk = bridge.setPublicProfile(
      displayName: pubName.isEmpty ? null : pubName,
      isPublic: pubName.isNotEmpty,
    );

    if (!privOk || !pubOk) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Failed to save profile. Please try again.'),
          ),
        );
      }
      return;
    }

    _goTo(_Step.disclosures);
  }

  /// Set the PIN via bridge.setPin() after confirming the two fields match.
  ///
  /// On success hides the PIN form and advances to _Step.done.
  void _confirmPin() {
    final pin = _pinController.text;
    final confirm = _pinConfirmController.text;

    // Validate minimum length (4 digits).
    if (pin.length < 4) {
      setState(() => _pinMismatch = false);
      return;
    }

    // Validate that the confirmation matches.
    if (pin != confirm) {
      setState(() => _pinMismatch = true);
      // Vibrate to give tactile feedback that something is wrong.
      HapticFeedback.vibrate();
      return;
    }

    final bridge = context.read<BackendBridge>();
    final ok = bridge.setPin(pin);
    if (!ok) {
      setState(() => _error = bridge.getLastError() ?? 'Failed to set PIN.');
      return;
    }

    // PIN set successfully — proceed to Done.
    _goTo(_Step.done);
  }

  // -------------------------------------------------------------------------
  // Build — top-level scaffold
  // -------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // Scaffold provides the background surface.  No AppBar — onboarding is
    // an immersive full-screen experience.
    return Scaffold(
      body: SafeArea(
        // SafeArea keeps content away from the notch, status bar, and home
        // indicator on modern phones.
        child: Center(
          child: SingleChildScrollView(
            // SingleChildScrollView allows content to scroll when the soft
            // keyboard pushes the layout off-screen on small devices.
            padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 24),
            child: ConstrainedBox(
              // Cap width at 420px so the form doesn't stretch to an
              // unreadable line length on tablets and large desktops.
              constraints: const BoxConstraints(maxWidth: 420),
              child: AnimatedSwitcher(
                // AnimatedSwitcher cross-fades between its children when the
                // key changes.  Each step widget has a ValueKey(_step) so
                // Flutter detects the change and plays the transition.
                duration: const Duration(milliseconds: 250),
                transitionBuilder: (child, anim) =>
                    FadeTransition(opacity: anim, child: child),
                child: _buildCurrentStep(),
              ),
            ),
          ),
        ),
      ),
    );
  }

  /// Routes to the correct step builder based on [_step].
  Widget _buildCurrentStep() {
    return switch (_step) {
      _Step.welcome => _buildWelcome(),
      _Step.importBackup => _buildImportBackup(),
      _Step.identity => _buildIdentity(),
      _Step.publicProfile => _buildPublicProfile(),
      _Step.disclosures => _buildDisclosures(),
      _Step.pinSetup => _buildPinSetup(),
      _Step.done => _buildDone(),
    };
  }

  // =========================================================================
  // Step 0 — Welcome
  // =========================================================================

  /// Builds the Welcome screen (§22.42.1).
  ///
  /// Shows the app logo, name, and tagline.  Offers two primary actions:
  /// "Create new identity" (calls _createIdentity, then advances to identity
  /// step) and "Import from backup" (navigates to importBackup step).
  ///
  /// The back button is disabled implicitly because this is the first step
  /// in the wizard and there is no previous screen to go back to.
  Widget _buildWelcome() {
    return Column(
      key: const ValueKey(_Step.welcome),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 48),

        // Brand logo.  Falls back to an icon if the asset does not exist.
        // The logo communicates "this is Mesh Infinity" before any text is read.
        const _BrandLogo(size: 80),

        const SizedBox(height: 20),

        // App name in the largest display style.
        Text(
          'Mesh Infinity',
          style: Theme.of(context).textTheme.displaySmall?.copyWith(
                fontWeight: FontWeight.w700,
              ),
        ),

        const SizedBox(height: 8),

        // Tagline — one sentence describing what the app is.
        Text(
          'Encrypted mesh networking for everyone.',
          style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
          textAlign: TextAlign.center,
        ),

        const SizedBox(height: 48),

        // Show any backend error (e.g. key generation failure) as a red banner.
        if (_error != null) ...[
          _ErrorBanner(message: _error!),
          const SizedBox(height: 16),
        ],

        // Primary action — create a new identity.
        // Shows a loading indicator while _createIdentity() is in progress.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton.icon(
            onPressed: _busy ? null : _createIdentity,
            icon: _busy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2.5,
                      valueColor:
                          AlwaysStoppedAnimation<Color>(Colors.white),
                    ),
                  )
                : const Icon(Icons.person_add_rounded),
            label: const Text('Create new identity'),
          ),
        ),

        const SizedBox(height: 12),

        // Secondary action — import from backup.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: OutlinedButton.icon(
            onPressed: _busy
                ? null
                : () => _goTo(_Step.importBackup),
            icon: const Icon(Icons.download_rounded),
            label: const Text('Import from backup'),
          ),
        ),

        const SizedBox(height: 32),
      ],
    );
  }

  // =========================================================================
  // Step 1 — Import Backup
  // =========================================================================

  /// Builds the Import Backup screen (§22.42.2).
  ///
  /// Shown when the user tapped "Import from backup" on the Welcome screen.
  /// The user pastes their passphrase on line 1 and the backup JSON below it.
  /// On success, _doImport() calls bridge.importIdentity() and advances to the
  /// identity step so the user can confirm the recovered name.
  ///
  /// The "Back" button returns to Welcome so the user can choose Create instead.
  Widget _buildImportBackup() {
    return Column(
      key: const ValueKey(_Step.importBackup),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 24),

        const _StepHeader(
          title: 'Import Backup',
          subtitle: 'Restore your identity from a previous backup.',
        ),

        if (_error != null) ...[
          const SizedBox(height: 16),
          _ErrorBanner(message: _error!),
        ],

        const SizedBox(height: 16),

        // Instructions — plain language.
        Text(
          'Line 1: your passphrase\nLines 2 and below: your backup JSON',
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
        ),

        const SizedBox(height: 16),

        // Combined passphrase + backup JSON field.
        TextField(
          controller: _phraseController,
          enabled: !_busy,
          minLines: 4,
          maxLines: 8,
          decoration: const InputDecoration(
            labelText: 'Passphrase + backup data',
            hintText: 'my-passphrase\n{"version":1,"salt":"..."}',
            alignLabelWithHint: true,
          ),
        ),

        const SizedBox(height: 20),

        // Import action — disabled while in progress.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: _busy ? null : _doImport,
            child: _busy
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Text('Import'),
          ),
        ),

        const SizedBox(height: 12),

        // Back to Welcome.
        TextButton(
          onPressed: _busy
              ? null
              : () => _goTo(_Step.welcome),
          child: const Text('Back'),
        ),

        const SizedBox(height: 16),
      ],
    );
  }

  // =========================================================================
  // Step 2 — Your Identity
  // =========================================================================

  /// Builds the Your Identity screen (§22.42.3).
  ///
  /// The user sets their private identity name — the name that trusted contacts
  /// will see when they pair with this node.  They also pick an avatar colour
  /// from the 8-colour palette defined in kMaskAvatarColors.
  ///
  /// This is the primary private mask from a crypto standpoint (§3.1.3), but
  /// the spec explicitly says NOT to use the word "mask" on this screen —
  /// from the user's standpoint this IS them, not a persona layer.
  ///
  /// The "Next" button is disabled until the name field contains at least one
  /// non-whitespace character.  This prevents advancing with no name.
  Widget _buildIdentity() {
    // Read the name text to drive button enable/disable state.  We use a
    // ValueListenableBuilder so the button re-renders on every keystroke
    // without calling setState() on the full State object.
    return Column(
      key: const ValueKey(_Step.identity),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 24),

        const _StepHeader(
          title: 'Your identity',
          subtitle:
              'This is you on Mesh Infinity — the identity\nyou share with people you trust.',
        ),

        const SizedBox(height: 24),

        // Name field — this is what trusted contacts see.
        // textCapitalization.words auto-capitalises the first letter of each
        // word, reducing friction for entering a real name.
        TextField(
          controller: _nameController,
          autofocus: true,
          textCapitalization: TextCapitalization.words,
          decoration: const InputDecoration(
            labelText: 'Your name',
            hintText: 'What trusted contacts will call you',
          ),
          // Rebuild whenever the text changes so the Next button reflects the
          // current state without a full setState().
          onChanged: (_) => setState(() {}),
        ),

        const SizedBox(height: 20),

        // Avatar colour picker — 8 colour swatches in a wrap row.
        Align(
          alignment: Alignment.centerLeft,
          child: Text(
            'Avatar color',
            style: Theme.of(context).textTheme.labelMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
          ),
        ),

        const SizedBox(height: 10),

        // Wrap allows swatches to flow to the next line on very narrow screens.
        Wrap(
          spacing: 12,
          runSpacing: 10,
          children: List.generate(kMaskAvatarColors.length, (i) {
            final selected = i == _selectedColorIndex;
            return GestureDetector(
              onTap: () => setState(() => _selectedColorIndex = i),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 150),
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  color: kMaskAvatarColors[i],
                  shape: BoxShape.circle,
                  // A 3px border on the selected swatch makes it obvious
                  // which colour is active without requiring an overlay icon.
                  border: selected
                      ? Border.all(
                          color:
                              Theme.of(context).colorScheme.onSurface,
                          width: 3,
                        )
                      : null,
                ),
                // Checkmark confirms the selection for colour-blind users.
                child: selected
                    ? const Icon(Icons.check, size: 18, color: Colors.white)
                    : null,
              ),
            );
          }),
        ),

        const SizedBox(height: 16),

        // Clarifying note — keeps the "private" concept clear.
        Text(
          'Shared only with contacts you explicitly trust.',
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
        ),

        const SizedBox(height: 28),

        // Next button — disabled until a name is entered.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: _nameController.text.trim().isEmpty
                ? null
                : () => _goTo(_Step.publicProfile),
            child: const Text('Next'),
          ),
        ),

        const SizedBox(height: 16),
      ],
    );
  }

  // =========================================================================
  // Step 3 — Public Presence
  // =========================================================================

  /// Builds the Public Presence screen (§22.42.3b).
  ///
  /// This step is entirely optional.  The user can type a public display name
  /// that strangers on the mesh will see, or leave it blank to stay anonymous.
  ///
  /// When the user taps Next or Skip, _saveProfiles() is called to write both
  /// the private and public profiles, then the wizard moves to the disclosures
  /// step.
  ///
  /// "Skip" and "Next" both call the same handler — the difference is only
  /// visual ("Skip" is a TextButton, "Next" is a FilledButton).
  Widget _buildPublicProfile() {
    return Column(
      key: const ValueKey(_Step.publicProfile),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 24),

        const _StepHeader(
          title: 'Public presence',
          subtitle:
              'Should people be able to find you by name?\nThis is optional — you can skip it entirely.',
        ),

        const SizedBox(height: 20),

        // Public name field — empty means anonymous.
        TextField(
          controller: _publicNameController,
          textCapitalization: TextCapitalization.words,
          decoration: const InputDecoration(
            labelText: 'Public name (optional)',
            hintText: 'Visible to anyone on the mesh',
          ),
        ),

        const SizedBox(height: 10),

        // Reminder that anonymity is valid and changes can be made later.
        Text(
          'Leave blank to stay anonymous. You can change this anytime in Settings.',
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
        ),

        const SizedBox(height: 28),

        // Next — saves profile then advances to disclosures.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: _saveProfiles,
            child: const Text('Next'),
          ),
        ),

        const SizedBox(height: 8),

        // Skip — also saves (with empty public name) and advances.
        TextButton(
          onPressed: _saveProfiles,
          child: const Text('Skip'),
        ),

        const SizedBox(height: 16),
      ],
    );
  }

  // =========================================================================
  // Step 4 — Ambient Disclosures
  // =========================================================================

  /// Builds the Ambient Disclosures screen (§22.23, §22.27.1).
  ///
  /// This step is MANDATORY — it cannot be skipped.  The §22.23 ambient state
  /// disclosures must be communicated to the user before they can send any
  /// message.
  ///
  /// The "I understand" button is intentionally DISABLED until the user scrolls
  /// to the bottom of the disclosure list.  This is not a legal trick — it is
  /// a UX mechanism to prevent the very common behaviour of tapping "OK" on a
  /// wall of text without reading any of it.  Each disclosure is short,
  /// non-scary, and written in plain language (§22.27 "must not use fear-based
  /// language").
  ///
  /// The back button is DISABLED on this step.  Allowing back navigation would
  /// allow the user to re-enter this step from a later step and bypass it by
  /// arriving via a different path.  Holding this step firm is the correct
  /// approach.
  Widget _buildDisclosures() {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Column(
      key: const ValueKey(_Step.disclosures),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 24),

        // Header — inviting tone, not a legal notice.
        const _StepHeader(
          title: 'How Mesh Infinity works',
          subtitle:
              'A few honest things worth knowing before you dive in.',
        ),

        const SizedBox(height: 20),

        // ---------------------------------------------------------------------------
        // Disclosure list in a scrollable container.
        //
        // WHY a fixed-height container with its own scroll controller?
        // ----------------------------------------------------------------
        // The outer SingleChildScrollView on the Scaffold body scrolls the
        // entire page.  We need a SEPARATE scroll controller so we can
        // detect when the user has specifically scrolled through the
        // disclosure items, not just scrolled past the section.
        //
        // The container height is capped so the disclosures don't expand to
        // fill the whole screen (which would make the button invisible until
        // the user scrolls the outer view) — instead, the inner list is
        // scrollable within a contained area, making the "scroll to read"
        // behaviour obvious.
        // ---------------------------------------------------------------------------
        Container(
          height: 300,
          decoration: BoxDecoration(
            color: cs.surfaceContainerHighest.withValues(alpha: 0.5),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Scrollbar(
            // The Scrollbar widget overlays a visible drag handle on the right
            // edge of the scroll container, making it obvious the list scrolls.
            controller: _disclosuresScrollCtrl,
            thumbVisibility: true,
            child: ListView(
              // This is the scroll controller we listen to for "reached bottom".
              controller: _disclosuresScrollCtrl,
              padding: const EdgeInsets.all(16),
              children: [
                const _DisclosureItem(
                  icon: Icons.lock_outline_rounded,
                  iconColor: MeshTheme.brand,
                  title: 'Your messages are end-to-end encrypted.',
                  body:
                      'Nobody — not even us — can read your messages. '
                      'Your identity key is generated on this device and '
                      'never leaves it.',
                ),
                const SizedBox(height: 16),
                const _DisclosureItem(
                  icon: Icons.hub_outlined,
                  iconColor: MeshTheme.secGreen,
                  title: 'Your device helps route others\' messages.',
                  body:
                      'Your device may relay encrypted messages for other '
                      'users on the mesh. You cannot read them, and '
                      'neither can anyone else. You can disable this in '
                      'Settings if needed.',
                ),
                const SizedBox(height: 16),
                const _DisclosureItem(
                  icon: Icons.visibility_off_outlined,
                  iconColor: MeshTheme.secAmber,
                  title: 'Extra data keeps everyone\'s traffic private.',
                  body:
                      'The app sends a small amount of cover traffic to '
                      'prevent traffic analysis. This uses some battery '
                      'and data.',
                ),
                const SizedBox(height: 16),
                const _DisclosureItem(
                  icon: Icons.storage_outlined,
                  iconColor: MeshTheme.brand,
                  title: 'Messages wait on trusted nodes for offline contacts.',
                  body:
                      'If a contact is offline, their messages are '
                      'temporarily stored on trusted mesh nodes until '
                      'they reconnect.',
                ),
                const SizedBox(height: 16),
                const _DisclosureItem(
                  icon: Icons.dns_outlined,
                  iconColor: MeshTheme.secGreen,
                  title: 'There are no central servers.',
                  body:
                      'Mesh Infinity has no central servers. Your messages '
                      'travel through the network itself. You control who '
                      'can contact you and what they can see.',
                ),
                // Extra padding at the bottom so the last item doesn't sit
                // right at the scroll edge — users need to clearly reach it.
                const SizedBox(height: 8),
              ],
            ),
          ),
        ),

        const SizedBox(height: 12),

        // Hint text tells users what to do — shown until button activates.
        AnimatedOpacity(
          opacity: _disclosuresRead ? 0.0 : 1.0,
          duration: const Duration(milliseconds: 200),
          child: Text(
            'Scroll to read all',
            style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          ),
        ),

        const SizedBox(height: 12),

        // "I understand" button — disabled until scroll reaches the bottom.
        //
        // This is the core of the scroll-gate pattern.  The button is
        // non-interactive (_disclosuresRead == false) when the user has not
        // yet scrolled through the list.  Once they reach the bottom, the
        // button becomes tappable.  This is the minimal friction that prevents
        // a "click through without reading" pattern while not being hostile
        // (the user just has to scroll, not tick boxes or pass a quiz).
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: _disclosuresRead
                ? () => _goTo(_Step.pinSetup)
                : null,
            child: const Text('I understand'),
          ),
        ),

        const SizedBox(height: 16),
      ],
    );
  }

  // =========================================================================
  // Step 5 — PIN Setup
  // =========================================================================

  /// Builds the PIN Setup screen (§22.42.5, §22.27.2).
  ///
  /// PIN setup is "strongly encouraged" but skippable with acknowledgment.
  /// This step CANNOT be reached by pressing Back from a later step — the
  /// back button is suppressed here to prevent bypass of the disclosure step
  /// (step 4) by going back from done (step 6) and re-entering from PIN.
  ///
  /// Three sub-states exist within this step:
  ///   1. Default: icon + explanation + "Set a PIN" / "Skip for now" buttons.
  ///   2. PIN form: inline PIN entry and confirm fields + checkboxes.
  ///   3. Skip warning: inline amber warning before allowing bypass.
  ///
  /// All three sub-states are shown in the same step — no push navigation —
  /// so the user stays in the onboarding flow context throughout.
  Widget _buildPinSetup() {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Column(
      key: const ValueKey(_Step.pinSetup),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 32),

        // Brand icon for the PIN concept.
        const Icon(Icons.pin_outlined, size: 48, color: MeshTheme.brand),

        const SizedBox(height: 16),

        // Headline — benefit-first, not threat-first (§22.27 "no fear language").
        Text(
          'Protect your messages',
          style: tt.titleLarge,
          textAlign: TextAlign.center,
        ),

        const SizedBox(height: 8),

        // One-sentence explanation of what a PIN does for the user.
        Text(
          'A PIN locks your identity behind a second factor. '
          'You can set one now or later in Settings.',
          style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
          textAlign: TextAlign.center,
        ),

        const SizedBox(height: 32),

        if (_error != null) ...[
          _ErrorBanner(message: _error!),
          const SizedBox(height: 16),
        ],

        // Show different content depending on sub-state.
        if (!_showPinForm && !_showSkipWarning) ...[
          // Default sub-state: offer the two primary choices.
          _buildPinSetupDefault(cs),
        ] else if (_showPinForm) ...[
          // PIN form sub-state: inline entry fields.
          _buildPinForm(cs, tt),
        ] else ...[
          // Skip warning sub-state: amber disclosure before bypass.
          _buildSkipWarning(cs, tt),
        ],

        const SizedBox(height: 16),
      ],
    );
  }

  /// Default sub-state for the PIN setup step.
  ///
  /// Shows the two top-level actions: "Set a PIN" and "Skip for now".
  Widget _buildPinSetupDefault(ColorScheme cs) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        // Primary CTA — show PIN form.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton.icon(
            onPressed: () => setState(() {
              _showPinForm = true;
              _showSkipWarning = false;
            }),
            icon: const Icon(Icons.lock_outlined),
            label: const Text('Set a PIN'),
          ),
        ),

        const SizedBox(height: 12),

        // Secondary CTA — show skip warning before allowing bypass.
        TextButton(
          onPressed: () => setState(() {
            _showSkipWarning = true;
            _showPinForm = false;
          }),
          child: const Text('Skip for now'),
        ),
      ],
    );
  }

  /// PIN form sub-state.
  ///
  /// Inline PIN entry and confirmation.  Minimum 4 digits (§22.27 / §22.42.5).
  /// "Set PIN" button is disabled until both fields are non-empty and at least
  /// 4 characters long.  Mismatch is shown as error text on the confirm field.
  Widget _buildPinForm(ColorScheme cs, TextTheme tt) {
    final pinLen = _pinController.text.length;
    final confirmLen = _pinConfirmController.text.length;

    // Enable the Set PIN button only when both fields have at least 4 digits.
    final pinReady = pinLen >= 4 && confirmLen >= 4;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text('Choose a PIN', style: tt.titleSmall),

        const SizedBox(height: 12),

        // First PIN entry — obscured for security, numeric keyboard on mobile.
        TextField(
          controller: _pinController,
          keyboardType: const TextInputType.numberWithOptions(
            signed: false,
            decimal: false,
          ),
          obscureText: true,
          maxLength: 16,
          autofocus: true,
          onChanged: (_) => setState(() => _pinMismatch = false),
          decoration: const InputDecoration(
            labelText: 'PIN',
            counterText: '', // hides the "N/16" character counter
          ),
        ),

        const SizedBox(height: 12),

        // Confirmation field — shows error text on mismatch.
        TextField(
          controller: _pinConfirmController,
          keyboardType: const TextInputType.numberWithOptions(
            signed: false,
            decimal: false,
          ),
          obscureText: true,
          maxLength: 16,
          onChanged: (_) => setState(() => _pinMismatch = false),
          decoration: InputDecoration(
            labelText: 'Confirm PIN',
            counterText: '',
            // Show error text only if the user has attempted a confirmation
            // and the values don't match.
            errorText: _pinMismatch ? 'PINs do not match' : null,
          ),
        ),

        const SizedBox(height: 20),

        // Set PIN — disabled until both fields meet minimum length.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: pinReady ? _confirmPin : null,
            child: const Text('Set PIN'),
          ),
        ),

        const SizedBox(height: 10),

        // Allow going back to the default sub-state.
        TextButton(
          onPressed: () => setState(() {
            _showPinForm = false;
            _pinController.clear();
            _pinConfirmController.clear();
            _pinMismatch = false;
          }),
          child: const Text('Cancel'),
        ),
      ],
    );
  }

  /// Skip warning sub-state.
  ///
  /// Shown when the user taps "Skip for now".  An inline amber container
  /// explains the risk in plain language.  Two buttons let the user either
  /// change their mind and set a PIN, or explicitly confirm they want to
  /// continue without one.  This is §22.42.5's "skip confirmation" pattern —
  /// inline, not a dialog, so the user stays in the flow.
  Widget _buildSkipWarning(ColorScheme cs, TextTheme tt) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: cs.errorContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Warning message — single sentence, plain language.
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(
                Icons.warning_amber_outlined,
                size: 18,
                color: cs.onErrorContainer,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Without a PIN, anyone who unlocks your phone can '
                  'read your messages.',
                  style: tt.bodySmall?.copyWith(
                    color: cs.onErrorContainer,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ),
            ],
          ),

          const SizedBox(height: 12),

          // Two-button row: change mind vs confirm bypass.
          Row(
            children: [
              // Go back to the default PIN setup buttons.
              Expanded(
                child: OutlinedButton(
                  onPressed: () => setState(() {
                    _showSkipWarning = false;
                  }),
                  child: const Text('Set a PIN'),
                ),
              ),
              const SizedBox(width: 12),
              // Confirm the user knows they are skipping — then proceed to Done.
              Expanded(
                child: TextButton(
                  style: TextButton.styleFrom(
                    foregroundColor: cs.error,
                  ),
                  onPressed: () => _goTo(_Step.done),
                  child: const Text('Continue without PIN'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // =========================================================================
  // Step 6 — Done
  // =========================================================================

  /// Builds the Done screen (final step of §22.42).
  ///
  /// Confirms that setup is complete and the node is now participating in the
  /// mesh.  "Get Started" calls widget.onComplete(), which dismisses the
  /// onboarding screen and shows AppShell.
  Widget _buildDone() {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Column(
      key: const ValueKey(_Step.done),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 48),

        // Success icon.
        Container(
          width: 72,
          height: 72,
          decoration: BoxDecoration(
            color: MeshTheme.secGreen.withValues(alpha: 0.12),
            shape: BoxShape.circle,
          ),
          child: const Icon(
            Icons.check_rounded,
            size: 40,
            color: MeshTheme.secGreen,
          ),
        ),

        const SizedBox(height: 24),

        Text(
          'You\'re set up.',
          style: tt.headlineMedium?.copyWith(fontWeight: FontWeight.w700),
          textAlign: TextAlign.center,
        ),

        const SizedBox(height: 12),

        Text(
          'Your node is now part of the mesh.\n'
          'You can start messaging and connecting with people.',
          style: tt.bodyLarge?.copyWith(color: cs.onSurfaceVariant),
          textAlign: TextAlign.center,
        ),

        const SizedBox(height: 48),

        // Final CTA — calls the parent callback to remove onboarding.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton.icon(
            onPressed: widget.onComplete,
            icon: const Icon(Icons.arrow_forward_rounded),
            label: const Text('Get Started'),
          ),
        ),

        const SizedBox(height: 32),
      ],
    );
  }
}

// =============================================================================
// Private helper widgets
// =============================================================================

// ---------------------------------------------------------------------------
// _BrandLogo
// ---------------------------------------------------------------------------

/// Renders the brand logo.
///
/// Tries to load the asset image first.  If it fails (e.g. asset not bundled
/// yet during development), falls back to the hub icon in brand colour.
/// This prevents hard crashes when running the onboarding screen in isolation.
class _BrandLogo extends StatelessWidget {
  const _BrandLogo({required this.size});

  final double size;

  @override
  Widget build(BuildContext context) {
    return Image.asset(
      'assets/logo.png',
      width: size,
      height: size,
      errorBuilder: (context, error, _) => Icon(
        Icons.hub_rounded,
        size: size,
        color: MeshTheme.brand,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _StepHeader
// ---------------------------------------------------------------------------

/// Consistent step header: logo (56px) + "Mesh Infinity" label + step title.
///
/// Used on all steps except Welcome (which has its own layout) so each step
/// has a visual anchor reminding the user which app they are setting up.
class _StepHeader extends StatelessWidget {
  const _StepHeader({required this.title, this.subtitle});

  final String title;
  final String? subtitle;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        // Compact logo for interior steps — smaller than the Welcome logo.
        Image.asset(
          'assets/logo.png',
          width: 56,
          height: 56,
          errorBuilder: (context, error, _) => const Icon(
            Icons.hub_rounded,
            size: 56,
            color: MeshTheme.brand,
          ),
        ),

        const SizedBox(height: 8),

        Text(
          'Mesh Infinity',
          style: tt.labelLarge?.copyWith(color: cs.onSurfaceVariant),
        ),

        const SizedBox(height: 12),

        Text(
          title,
          style: tt.headlineSmall?.copyWith(fontWeight: FontWeight.w700),
          textAlign: TextAlign.center,
        ),

        if (subtitle != null) ...[
          const SizedBox(height: 6),
          Text(
            subtitle!,
            style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
            textAlign: TextAlign.center,
          ),
        ],
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// _ErrorBanner
// ---------------------------------------------------------------------------

/// Red error banner shown above action buttons when a backend call fails.
///
/// Uses the theme's errorContainer / onErrorContainer colours so it adapts
/// correctly to both light and dark themes without hard-coded colours.
class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: cs.errorContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(Icons.error_outline_rounded, size: 18, color: cs.onErrorContainer),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              message,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: cs.onErrorContainer,
                  ),
            ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _DisclosureItem
// ---------------------------------------------------------------------------

/// A single disclosure row in the §22.23 disclosures step.
///
/// Layout: coloured icon in a rounded container on the left; title and body
/// text on the right.  This is the _FactRow layout from §22.42.4.
/// Reused here for the mandatory disclosures so the visual language is
/// consistent between the disclosure step and any other explainer screens.
class _DisclosureItem extends StatelessWidget {
  const _DisclosureItem({
    required this.icon,
    required this.iconColor,
    required this.title,
    required this.body,
  });

  final IconData icon;
  final Color iconColor;
  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Icon container — coloured background at 12% opacity keeps the
        // brand colours readable without overpowering the text.
        Container(
          width: 44,
          height: 44,
          decoration: BoxDecoration(
            color: iconColor.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, size: 22, color: iconColor),
        ),

        const SizedBox(width: 14),

        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 2),
              Text(title, style: tt.titleSmall),
              const SizedBox(height: 4),
              Text(
                body,
                style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
