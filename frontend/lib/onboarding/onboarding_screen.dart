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
// THE ONBOARDING FLOW (§22.42, §22.23, §22.27)
// ----------------------------------------------
// The §22.42 step list *is* the pipeline: [OnboardingStep] lists exactly
// these eight screens, in this order, and nothing else in the app has its
// own idea of what the steps are.  There is no "N of M" counter — the Import
// branch would make the total move mid-flow — so progress is conveyed by the
// back stack and each screen's title only.
//
// 1. Welcome (OnboardingStep.welcome)
//    App name, brand logo, tagline.  Offers "Create new identity" and
//    "Import from backup."  This is the entry gate — the user hasn't touched
//    any cryptographic material yet.
//
// 2. Import backup (OnboardingStep.importBackup)
//    Branch, only when the user chose Import: passphrase + backup JSON.
//    "Create new identity" instead generates a fresh keypair via
//    bridge.createIdentity() and goes straight to step 3.
//
// 3. Your identity (OnboardingStep.identity)
//    Sets the private identity name (the primary mask).  This is what trusted
//    contacts will see; it is written through setPrivateProfile() at the end
//    of step 4.  Do not use the word "mask" on this screen (§22.42.3 note).
//    Next stays disabled until a name exists, and a helper line says so.
//
// 4. Public presence (OnboardingStep.publicProfile)
//    Optionally set a public display name.  One forward button whose label is
//    "Skip" while the field is empty and "Next" once it has text (§22.42.3b).
//    If left blank, setPublicProfile() is called with displayName: null,
//    isPublic: false (§9.1 default).
//
// 5. How Mesh Infinity works (OnboardingStep.disclosures)
//    Mandatory.  Presents the §22.23 ambient state disclosures in clear,
//    non-scary language.  The "I understand" button is DISABLED until the user
//    has seen the whole list — this prevents click-through without reading,
//    which is the entire point of mandatory disclosure.  Cannot be skipped.
//
// 6. Privacy style (OnboardingStep.privacyStyle)
//    The §22.27 item 3 preset choice: Everyday / More private / Lockdown,
//    written through bridge.setThreatContext().  Placed right after the
//    disclosures so the user has just read what the presets change.
//
// 7. PIN (OnboardingStep.pinSetup)
//    Strongly encouraged (§22.27.2) but skippable with an explicit,
//    double-confirmed warning.  Offers inline PIN entry (not a push to
//    PinScreen, which is a separate full-screen flow) so the user stays in
//    the onboarding context.  "4 to 16 digits" is always visible so the
//    disabled Set PIN button is never the only signal.
//
// 8. Done (OnboardingStep.done)
//    "What next": primary "Add a contact" (→ PairContactScreen on top of the
//    shell, §22.8.3) and secondary "Go to Chat".  Both run
//    _finish_onboarding(), which persists the backend `onboarding_complete`
//    flag and only then calls widget.onComplete() with the chosen exit.
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
// Each step is a private _build* method.  The OnboardingStep enum value
// _step drives which step is currently shown.  AnimatedSwitcher provides a
// 250ms cross-fade between steps (zero under reduced motion, §22.1.7).  No
// PageView is needed: a PopScope maps the
// system Back gesture onto _go_back(), which steps backwards inside the flow
// instead of leaving the app (§22.42 "progress is conveyed by the back
// stack").
//
// Back navigation:
//   - Welcome — lets the system pop (there is nothing before it).
//   - Import → Welcome; Public presence → Identity; Disclosures → Public
//     presence; Privacy style → Disclosures; PIN → Privacy style (after
//     closing an open PIN sub-form).
//   - Identity and Done stay put: once an identity exists, Welcome's
//     "Create new identity" must not be reachable, and Done has nothing
//     left to undo.
//   Going back never skips the disclosures gate: the only way forward from
//   Public presence is through the disclosures step again.
//
// RESUME (§22.42)
// ----------------
// The backend persists an `onboarding_complete` flag only when the Done step
// runs _finish_onboarding().  app.dart passes initial_step: identity when an
// unlocked identity exists without that flag, so a first run that was killed
// mid-setup lands back on "Your identity" (name pre-filled from the stored
// profile) and still has to pass the disclosures and the PIN offer.
//
// BACKEND CALLS USED HERE
// -----------------------
//   - bridge.createIdentity() / importIdentity() — steps 1-2.
//   - bridge.setPrivateProfile() / setPublicProfile() — end of step 4.
//   - bridge.setThreatContext(int) — step 6; the backend persists the level
//     in its settings vault, so no extra flag is needed.
//   - bridge.setPin() + setSecurityConfig() — step 7.
//   - bridge.setOnboardingComplete() — step 8.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../app/app_theme.dart';
import '../app/debug_logger.dart';
import '../app/motion.dart';
import '../backend/backend_bridge.dart';
import '../widgets/mask_avatar.dart';

// ---------------------------------------------------------------------------
// OnboardingStep — the wizard's named step sequence
// ---------------------------------------------------------------------------

/// Names each screen in the onboarding wizard — the §22.42 step list, in
/// the spec's order.  This enum is the single list of steps; the order of
/// its values is the order of the screens.
///
/// Public so app.dart can resume an interrupted run at [identity] and tests
/// can pump a single step.  The sequence is strictly linear; see the
/// file-level comment for how Back moves inside it.
enum OnboardingStep {
  // 1 — App name, tagline, Create / Import choice.
  welcome,
  // 2 — Passphrase + backup JSON (branch, only reached via Import).
  importBackup,
  // 3 — Private identity name and avatar colour.
  identity,
  // 4 — Optional public display name.
  publicProfile,
  // 5 — Mandatory §22.23 ambient state disclosures ("How Mesh Infinity works").
  disclosures,
  // 6 — §22.27 item 3 privacy preset (Everyday / More private / Lockdown).
  privacyStyle,
  // 7 — §22.27 PIN setup offer.
  pinSetup,
  // 8 — Done: "what next" before calling onComplete().
  done,
}

/// Which "what next" action the user chose on the Done step (§22.42.7).
///
/// app.dart receives it through [OnboardingScreen.onComplete] after the
/// `onboarding_complete` flag is persisted, and either pushes
/// `PairContactScreen` on top of the freshly built shell or simply lands on
/// the Chat section.
enum OnboardingExit {
  /// Primary action "Add a contact" → `PairContactScreen` (§22.8.3).
  addContact,

  /// Secondary action "Go to Chat" → Chat section with its empty state.
  chat,
}

// ---------------------------------------------------------------------------
// OnboardingScreen — top-level StatefulWidget
// ---------------------------------------------------------------------------

/// Full-screen wizard shown on first launch.
///
/// [onComplete] is called exactly once at the end of the flow, after the
/// backend has persisted the `onboarding_complete` flag.  The parent
/// (app.dart) uses it to re-read startup state and show AppShell, and the
/// [OnboardingExit] argument tells it which "what next" button was pressed.
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({
    super.key,
    required this.onComplete,
    this.initial_step = OnboardingStep.welcome,
  });

  /// Invoked once the Done step has persisted the onboarding flag, with the
  /// exit the user chose there (§22.42.7).
  final void Function(OnboardingExit exit) onComplete;

  /// Step to open on.  [OnboardingStep.welcome] on a first run;
  /// [OnboardingStep.identity] when app.dart resumes an interrupted run
  /// (§22.42: identity present, `onboarding_complete` unset).
  final OnboardingStep initial_step;

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
  /// Seeded from widget.initial_step in initState.
  OnboardingStep _step = OnboardingStep.welcome;

  // -------------------------------------------------------------------------
  // General async state
  // -------------------------------------------------------------------------

  /// True while a backend call is in progress — disables buttons, shows spinner.
  bool _busy = false;

  /// Most recent backend error, or null.  Shown as a red banner above buttons.
  String? _error;

  // -------------------------------------------------------------------------
  // 2 — Import backup
  // -------------------------------------------------------------------------

  /// Multi-line import field: line 1 = passphrase, lines 2+ = backup JSON.
  final _phraseController = TextEditingController();

  // -------------------------------------------------------------------------
  // 3 — Identity
  // -------------------------------------------------------------------------

  /// Private identity name — shown to trusted contacts only.
  final _nameController = TextEditingController();

  /// Selected avatar colour index into kMaskAvatarColors.  Defaults to 0
  /// (brand blue) — users can change it by tapping a colour swatch.
  int _selectedColorIndex = 0;

  // -------------------------------------------------------------------------
  // 4 — Public profile
  // -------------------------------------------------------------------------

  /// Optional public display name.  If empty on "Next", no public profile
  /// is set (isPublic: false, displayName: null — §9.1 default).
  final _publicNameController = TextEditingController();

  // -------------------------------------------------------------------------
  // 5 — Disclosures scroll gate
  // -------------------------------------------------------------------------

  /// Controls the disclosures scroll view.  We listen to this to track whether
  /// the user has scrolled far enough to enable the "I understand" button.
  late final ScrollController _disclosuresScrollCtrl = ScrollController()
    ..addListener(_onDisclosuresScroll);

  /// True once the user has seen the whole disclosures list: either they
  /// scrolled to its bottom, or it fit without scrolling.  Only when true
  /// does the "I understand" button become active.
  bool _disclosuresRead = false;

  /// Whether the disclosures list is taller than its box, i.e. whether
  /// scrolling is possible at all.  Drives the "Scroll to read all" hint, so
  /// the hint never asks for a scroll that cannot happen.
  bool _disclosures_scrollable = false;

  /// Called by the ScrollController whenever the scroll position changes.
  void _onDisclosuresScroll() {
    // The controller may be attached to no viewport during step transitions.
    if (!_disclosuresScrollCtrl.hasClients) return;
    _apply_disclosure_metrics(_disclosuresScrollCtrl.position);
  }

  /// Called with fresh scroll metrics after every layout of the disclosures
  /// list (first layout, window resize, text-scale change) via a
  /// [ScrollMetricsNotification], which fires even when no scroll happens.
  bool _on_disclosure_metrics(ScrollMetricsNotification notification) {
    _apply_disclosure_metrics(notification.metrics);
    // Let the notification keep bubbling; nothing above cares, but there is
    // no reason to swallow it.
    return false;
  }

  /// Single rule for the disclosures gate, fed by both the scroll listener
  /// and the metrics notification.
  ///
  /// The list counts as read when it fits its box (`maxScrollExtent <= 0`:
  /// there is nothing to scroll to, so a scroll gate would be a dead end on
  /// tablets, landscape or small text scales) or when the user is within
  /// 32 px of the bottom (tolerance for scroll-physics rounding).  Once read,
  /// it stays read — a later resize that makes the list scroll again must
  /// not re-lock the button.
  void _apply_disclosure_metrics(ScrollMetrics metrics) {
    final scrollable = metrics.maxScrollExtent > 0;
    final read = _disclosuresRead || !scrollable || metrics.extentAfter <= 32.0;
    // Only rebuild when something the UI shows actually changed.
    if (scrollable == _disclosures_scrollable && read == _disclosuresRead) {
      return;
    }
    setState(() {
      _disclosures_scrollable = scrollable;
      _disclosuresRead = read;
    });
  }

  // -------------------------------------------------------------------------
  // 6 — Privacy style
  // -------------------------------------------------------------------------

  /// The §22.27 item 3 preset, as the backend `ThreatContext` level it maps
  /// to: 0 Normal (Everyday), 1 Elevated (More private), 2 Critical
  /// (Lockdown).  Everyday is the recommended default and is pre-selected.
  int _privacy_level = 0;

  // -------------------------------------------------------------------------
  // 7 — PIN Setup
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

  /// Whether to lock the identity when the phone screen locks (§3.6.4, §22.27).
  /// Defaults to true — opt-out to reduce protection, not opt-in.
  bool _requirePinAfterLock = true;

  /// Auto-lock timeout in seconds.  0 = require PIN immediately on screen lock.
  /// Options mirror §22.27: Immediately / 1 min / 5 min / 15 min.
  int _lockTimeoutSecs = 0;

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    _step = widget.initial_step;
    // Resumed run (§22.42): the identity already exists, so pre-fill its
    // stored name rather than asking the user to type it again.  A missing
    // or anonymous profile leaves the field empty, exactly like a first run.
    if (_step == OnboardingStep.identity) {
      final stored = context.read<BackendBridge>().fetchLocalIdentity()?.name;
      if (stored != null && stored.isNotEmpty) {
        _nameController.text = stored;
      }
    }
  }

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
  void _goTo(OnboardingStep target) {
    setState(() {
      _step = target;
      _error = null; // Clear any lingering error when changing steps.
    });
  }

  /// Handle the system Back gesture: step backwards inside the flow.
  ///
  /// See the file-level "Back navigation" note for the map.  Steps that have
  /// nothing safe to go back to (identity exists; done) ignore the gesture
  /// rather than leaving onboarding — leaving would strand a half-set-up
  /// identity behind the shell, which is the §22.42 resume rule's whole point.
  void _go_back() {
    switch (_step) {
      case OnboardingStep.welcome:
      case OnboardingStep.identity:
      case OnboardingStep.done:
        // Welcome is handled by PopScope.canPop; identity and done stay put.
        return;
      case OnboardingStep.importBackup:
        _goTo(OnboardingStep.welcome);
      case OnboardingStep.publicProfile:
        _goTo(OnboardingStep.identity);
      case OnboardingStep.disclosures:
        _goTo(OnboardingStep.publicProfile);
      case OnboardingStep.privacyStyle:
        _goTo(OnboardingStep.disclosures);
      case OnboardingStep.pinSetup:
        // An open PIN form or skip warning closes first; a second Back
        // then returns to the privacy style step.
        if (_showPinForm || _showSkipWarning) {
          setState(() {
            _showPinForm = false;
            _showSkipWarning = false;
            _pinMismatch = false;
          });
        } else {
          _goTo(OnboardingStep.privacyStyle);
        }
    }
  }

  /// Finish onboarding (§22.42.7): persist the `onboarding_complete` flag,
  /// then hand control back to app.dart together with the chosen [exit].
  ///
  /// The order is deliberate.  The flag is what tells the next launch that
  /// setup finished; if it cannot be persisted the app must stay on this
  /// step and say so, because moving to the shell would make the flag and
  /// the shell transition diverge — the next launch would resume onboarding.
  void _finish_onboarding(OnboardingExit exit) {
    final bridge = context.read<BackendBridge>();
    if (!bridge.setOnboardingComplete()) {
      setState(() => _error = "Couldn't finish setup. Try again.");
      return;
    }
    widget.onComplete(exit);
  }

  /// Persist the §22.27 privacy preset chosen on the Privacy style step and
  /// move on to the PIN offer.
  ///
  /// The backend stores the level in its settings vault, so a later launch
  /// starts in the chosen `ThreatContext` without any extra flag.  A failed
  /// write keeps the user on this step with the reason shown, rather than
  /// silently continuing in Everyday mode when they asked for Lockdown.
  void _save_privacy_style() {
    final bridge = context.read<BackendBridge>();
    if (!bridge.setThreatContext(_privacy_level)) {
      setState(
        () => _error =
            bridge.getLastError() ?? "Couldn't save your privacy style.",
      );
      return;
    }
    _goTo(OnboardingStep.pinSetup);
  }

  /// Forward action of the Your identity step: Next and the keyboard Done
  /// key share it, and both are ignored while the name is empty (§22.42.3).
  void _go_to_public_profile() {
    if (_nameController.text.trim().isEmpty) return;
    _goTo(OnboardingStep.publicProfile);
  }

  // -------------------------------------------------------------------------
  // Backend actions
  // -------------------------------------------------------------------------

  /// Create a fresh cryptographic identity via the Rust backend.
  ///
  /// Called when the user taps "Create new identity" on the Welcome screen.
  /// On success advances to OnboardingStep.identity.  On failure shows an error banner.
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

    await DebugLogger.logAndFlush('onboarding.identity.create.call_started');
    final timer = Stopwatch()..start();
    final ok = bridge.createIdentity();
    timer.stop();
    DebugLogger.log(
      'onboarding.identity.create.call_returned '
      'ok=$ok duration_ms=${timer.elapsedMilliseconds}',
    );
    if (!mounted) return;

    if (ok) {
      setState(() {
        _busy = false;
        _step = OnboardingStep.identity;
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
  /// On success advances to OnboardingStep.identity.
  Future<void> _doImport() async {
    final text = _phraseController.text.trim();
    if (text.isEmpty) {
      setState(() => _error = 'Please enter your passphrase and backup data.');
      return;
    }

    final newlineIdx = text.indexOf('\n');
    final passphrase = newlineIdx >= 0
        ? text.substring(0, newlineIdx).trim()
        : text;
    final backupJson = newlineIdx >= 0
        ? text.substring(newlineIdx + 1).trim()
        : '';

    if (backupJson.isEmpty) {
      setState(
        () => _error =
            'Paste your passphrase on the first line and the backup JSON below it.',
      );
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
        _step = OnboardingStep.identity;
      });
    } else {
      setState(() {
        _busy = false;
        _error =
            bridge.getLastError() ??
            'Import failed. Check your passphrase and backup data.';
      });
    }
  }

  /// Save private and public profiles at the end of the public-profile step.
  ///
  /// Writes both profiles to disk, then advances to the disclosures step.
  /// The single forward button ("Skip" or "Next") and the field's keyboard
  /// Done key both call this (§22.42.3b).
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

    _goTo(OnboardingStep.disclosures);
  }

  /// Set the PIN via bridge.setPin() after confirming the two fields match.
  ///
  /// On success hides the PIN form and advances to OnboardingStep.done.
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

    // Write the screen-lock security config (§3.6.4, §22.27).
    // Called immediately after PIN is set so the lock behaviour is active
    // from the user's very first session.  A failed write is reported: the
    // PIN is set, but the lock behaviour the user chose is not, and that
    // must not look like success.
    final config_ok = bridge.setSecurityConfig({
      'requirePinAfterLock': _requirePinAfterLock,
      'lockTimeoutSecs': _lockTimeoutSecs,
    });
    if (!config_ok) {
      setState(
        () => _error =
            bridge.getLastError() ?? "Couldn't save the lock settings.",
      );
      return;
    }

    // PIN set successfully — proceed to Done.
    _goTo(OnboardingStep.done);
  }

  /// Whether both PIN fields hold at least the 4-digit minimum (§22.42.5).
  /// Drives the Set PIN button and the confirm field's keyboard Done key.
  bool get _pin_ready =>
      _pinController.text.length >= 4 && _pinConfirmController.text.length >= 4;

  // -------------------------------------------------------------------------
  // Build — top-level scaffold
  // -------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // PopScope owns the system Back gesture (hardware button, predictive
    // back, Escape via the §22.36 input map).  Only the Welcome step lets
    // the pop through — there the app may exit; every other step stays
    // inside the flow and moves backwards via _go_back().
    //
    // Scaffold provides the background surface.  No AppBar — onboarding is
    // an immersive full-screen experience.
    return PopScope(
      canPop: _step == OnboardingStep.welcome,
      onPopInvokedWithResult: (did_pop, _) {
        // did_pop is true only when canPop allowed the route to close.
        if (!did_pop) _go_back();
      },
      child: Scaffold(
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
                  // Reduced motion (§22.1.7): the fade is skipped entirely.
                  duration: motion_duration(
                    context,
                    const Duration(milliseconds: 250),
                  ),
                  transitionBuilder: (child, anim) =>
                      FadeTransition(opacity: anim, child: child),
                  child: _buildCurrentStep(),
                ),
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
      OnboardingStep.welcome => _buildWelcome(),
      OnboardingStep.importBackup => _buildImportBackup(),
      OnboardingStep.identity => _buildIdentity(),
      OnboardingStep.publicProfile => _buildPublicProfile(),
      OnboardingStep.disclosures => _buildDisclosures(),
      OnboardingStep.privacyStyle => _buildPrivacyStyle(),
      OnboardingStep.pinSetup => _buildPinSetup(),
      OnboardingStep.done => _buildDone(),
    };
  }

  // =========================================================================
  // 1 — Welcome
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
      key: const ValueKey(OnboardingStep.welcome),
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
          style: Theme.of(
            context,
          ).textTheme.displaySmall?.copyWith(fontWeight: FontWeight.w700),
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
                      valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
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
            onPressed: _busy ? null : () => _goTo(OnboardingStep.importBackup),
            icon: const Icon(Icons.download_rounded),
            label: const Text('Import from backup'),
          ),
        ),

        const SizedBox(height: 32),
      ],
    );
  }

  // =========================================================================
  // 2 — Import Backup
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
      key: const ValueKey(OnboardingStep.importBackup),
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
          onPressed: _busy ? null : () => _goTo(OnboardingStep.welcome),
          child: const Text('Back'),
        ),

        const SizedBox(height: 16),
      ],
    );
  }

  // =========================================================================
  // 3 — Your Identity
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
  /// non-whitespace character.  A disabled forward action says why (§22.42
  /// design rule): while Next is disabled a helper line under it reads "Add a
  /// name to continue", and the keyboard Done key is the same action as Next.
  Widget _buildIdentity() {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    // Whether the forward action is available right now.
    final has_name = _nameController.text.trim().isNotEmpty;
    return Column(
      key: const ValueKey(OnboardingStep.identity),
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
          // The keyboard Done key is Next (§22.42.3); the handler ignores an
          // empty name exactly like the disabled button does.
          textInputAction: TextInputAction.done,
          onSubmitted: (_) => _go_to_public_profile(),
          decoration: const InputDecoration(
            labelText: 'Your name',
            hintText: 'What trusted contacts will call you',
          ),
          // Rebuild whenever the text changes so the Next button and its
          // helper line reflect the current state.
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
                // Reduced motion (§22.1.7): the border change is immediate.
                duration: motion_duration(
                  context,
                  const Duration(milliseconds: 150),
                ),
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  color: kMaskAvatarColors[i],
                  shape: BoxShape.circle,
                  // A 3px border on the selected swatch makes it obvious
                  // which colour is active without requiring an overlay icon.
                  border: selected
                      ? Border.all(
                          color: Theme.of(context).colorScheme.onSurface,
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
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        ),

        const SizedBox(height: 28),

        // Next button — disabled until a name is entered.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: has_name ? _go_to_public_profile : null,
            child: const Text('Next'),
          ),
        ),

        // A disabled forward action says why (§22.42.3).  Shown only while
        // Next is disabled, so the grey button is never the only signal;
        // it disappears as soon as a name exists.
        if (!has_name)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text(
              'Add a name to continue',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),

        const SizedBox(height: 16),
      ],
    );
  }

  // =========================================================================
  // 4 — Public Presence
  // =========================================================================

  /// Builds the Public Presence screen (§22.42.3b).
  ///
  /// This step is entirely optional.  The user can type a public display name
  /// that strangers on the mesh will see, or leave it blank to stay anonymous.
  ///
  /// One way forward per step (§22.42.3b): a single filled button whose label
  /// tells the truth about what pressing it does — "Skip" while the field is
  /// empty (no public profile is created) and "Next" once it has text (the
  /// public name is saved).  Both states, and the field's keyboard Done key,
  /// call _saveProfiles(), which writes both profiles and moves on to the
  /// disclosures step.
  Widget _buildPublicProfile() {
    // Label of the one forward button; it flips as the user types.
    final has_public_name = _publicNameController.text.trim().isNotEmpty;
    return Column(
      key: const ValueKey(OnboardingStep.publicProfile),
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
          // Keyboard Done is the same forward action as the button.
          textInputAction: TextInputAction.done,
          onSubmitted: (_) => _saveProfiles(),
          decoration: const InputDecoration(
            labelText: 'Public name (optional)',
            hintText: 'Visible to anyone on the mesh',
          ),
          // Rebuild on every keystroke so the button label follows the field.
          onChanged: (_) => setState(() {}),
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

        // The one forward button.  "Skip" and "Next" are the same action
        // with an honest label; no separate text Skip button is drawn.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: _saveProfiles,
            child: Text(has_public_name ? 'Next' : 'Skip'),
          ),
        ),

        const SizedBox(height: 16),
      ],
    );
  }

  // =========================================================================
  // 5 — How Mesh Infinity works (ambient disclosures)
  // =========================================================================

  /// Builds the Ambient Disclosures screen (§22.23, §22.27.1).
  ///
  /// This step is MANDATORY — it cannot be skipped.  The §22.23 ambient state
  /// disclosures must be communicated to the user before they can send any
  /// message.
  ///
  /// The "I understand" button is intentionally DISABLED until the user has
  /// seen the whole disclosure list — by scrolling to its bottom, or at once
  /// when the list fits its box and there is nothing to scroll.  This is not
  /// a legal trick — it is a UX mechanism to prevent the very common
  /// behaviour of tapping "OK" on a wall of text without reading any of it.
  /// Each disclosure is short, non-scary, and written in plain language
  /// (§22.27 "must not use fear-based language").
  ///
  /// Back from this step returns to Public presence; the only way forward
  /// from there is through this step again, so the gate cannot be bypassed.
  Widget _buildDisclosures() {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    // Per-theme status colours for disclosure icons.
    final colors = MeshColors.of(context);
    // Cap the list box at the window: roughly the height left after the
    // header, hint and button, never below 240 so a phone still gets a
    // usable box.  The list shrink-wraps inside the cap, so a tall window
    // shows every row without scrolling and the gate unlocks immediately
    // (see _apply_disclosure_metrics), while a short one keeps the
    // scroll-to-read behaviour obvious.  MediaQuery.sizeOf registers a
    // dependency, so a resize rebuilds this step and re-lays out the list.
    final box_max_height = (MediaQuery.sizeOf(context).height - 360).clamp(
      240.0,
      double.infinity,
    );

    return Column(
      key: const ValueKey(OnboardingStep.disclosures),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 24),

        // Header — inviting tone, not a legal notice.
        const _StepHeader(
          title: 'How Mesh Infinity works',
          subtitle: 'A few honest things worth knowing before you dive in.',
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
        // behaviour obvious.  Below the cap the list shrink-wraps, so the
        // box is exactly as tall as its content when that content fits.
        //
        // The NotificationListener receives a ScrollMetricsNotification after
        // every layout of the list, even when nothing scrolls, which is how
        // the gate learns that the content already fits.
        // ---------------------------------------------------------------------------
        Container(
          constraints: BoxConstraints(maxHeight: box_max_height),
          decoration: BoxDecoration(
            color: cs.surfaceContainerHighest.withValues(alpha: 0.5),
            borderRadius: BorderRadius.circular(12),
          ),
          child: NotificationListener<ScrollMetricsNotification>(
            onNotification: _on_disclosure_metrics,
            child: Scrollbar(
              // The Scrollbar widget overlays a visible drag handle on the right
              // edge of the scroll container, making it obvious the list scrolls.
              controller: _disclosuresScrollCtrl,
              thumbVisibility: true,
              child: ListView(
                // This is the scroll controller we listen to for "reached bottom".
                controller: _disclosuresScrollCtrl,
                // Size to content up to the cap (see box_max_height).
                shrinkWrap: true,
                padding: const EdgeInsets.all(16),
                children: [
                  // Brand blue as an icon foreground uses the per-theme
                  // token (§22.1.1, CMR-019); the 12% tint behind it is
                  // derived from the same colour inside _DisclosureItem.
                  _DisclosureItem(
                    icon: Icons.lock_outline_rounded,
                    iconColor: colors.brand_fg,
                    title: 'Your messages are end-to-end encrypted.',
                    body:
                        'Nobody — not even us — can read your messages. '
                        'Your identity key is generated on this device and '
                        'never leaves it.',
                  ),
                  const SizedBox(height: 16),
                  _DisclosureItem(
                    icon: Icons.hub_outlined,
                    iconColor: colors.sec_green,
                    title: 'Your device helps route others\' messages.',
                    body:
                        'Your device may relay encrypted messages for other '
                        'users on the mesh. You cannot read them, and '
                        'neither can anyone else. You can disable this in '
                        'Settings if needed.',
                  ),
                  const SizedBox(height: 16),
                  _DisclosureItem(
                    icon: Icons.visibility_off_outlined,
                    iconColor: colors.sec_amber,
                    title: 'Extra data keeps everyone\'s traffic private.',
                    body:
                        'The app sends a small amount of cover traffic to '
                        'prevent traffic analysis. This uses some battery '
                        'and data.',
                  ),
                  const SizedBox(height: 16),
                  _DisclosureItem(
                    icon: Icons.storage_outlined,
                    iconColor: colors.brand_fg,
                    title:
                        'Messages wait on trusted nodes for offline contacts.',
                    body:
                        'If a contact is offline, their messages are '
                        'temporarily stored on trusted mesh nodes until '
                        'they reconnect.',
                  ),
                  const SizedBox(height: 16),
                  _DisclosureItem(
                    icon: Icons.dns_outlined,
                    iconColor: colors.sec_green,
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
        ),

        const SizedBox(height: 12),

        // Hint text tells users what to do — shown only while there is
        // something left to scroll to.  When the list fits, or once it has
        // been read, asking the user to scroll would be asking for the
        // impossible, so the hint fades out.
        AnimatedOpacity(
          opacity: _disclosures_scrollable && !_disclosuresRead ? 1.0 : 0.0,
          // Reduced motion (§22.1.7): the hint appears and disappears at once.
          duration: motion_duration(context, const Duration(milliseconds: 200)),
          child: Text(
            'Scroll to read all',
            style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          ),
        ),

        const SizedBox(height: 12),

        // "I understand" button — disabled until the whole list was seen.
        //
        // This is the core of the scroll-gate pattern.  The button is
        // non-interactive (_disclosuresRead == false) while part of the list
        // is still below the fold.  Once the user reaches the bottom — or at
        // once when there is no fold — the button becomes tappable.  This is
        // the minimal friction that prevents a "click through without
        // reading" pattern while not being hostile (the user just has to
        // scroll, not tick boxes or pass a quiz).
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: _disclosuresRead
                ? () => _goTo(OnboardingStep.privacyStyle)
                : null,
            child: const Text('I understand'),
          ),
        ),

        const SizedBox(height: 16),
      ],
    );
  }

  // =========================================================================
  // 6 — Privacy style
  // =========================================================================

  /// Builds the Privacy style screen (§22.42.4a, §22.27 item 3).
  ///
  /// Three presets with the exact §22.27 titles and one-line descriptions,
  /// Everyday pre-selected.  The wording rules of §22.27 apply verbatim: no
  /// threat-model quiz and no examples that ask the user to self-identify as
  /// endangered — those explanations live in help, not here.
  ///
  /// Next is always enabled because a preset is always selected; it writes
  /// the matching `ThreatContext` through the bridge and moves to the PIN
  /// offer.  Back returns to the disclosures.
  Widget _buildPrivacyStyle() {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Column(
      key: const ValueKey(OnboardingStep.privacyStyle),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 24),

        // Title verbatim from §22.42.4a; the rows and helper line below are
        // the whole explanation, so no subtitle is drawn.
        const _StepHeader(title: 'Choose your default privacy style'),

        const SizedBox(height: 16),

        if (_error != null) ...[
          _ErrorBanner(message: _error!),
          const SizedBox(height: 16),
        ],

        // RadioGroup owns the selected value; each row only names its own.
        // The three rows map 1:1 onto the backend ThreatContext levels.
        RadioGroup<int>(
          groupValue: _privacy_level,
          onChanged: (v) => setState(() => _privacy_level = v ?? 0),
          child: const Column(
            children: [
              _PrivacyStyleRow(
                level: 0,
                title: 'Everyday',
                description:
                    'Fastest and most familiar; good for family, friends, '
                    'school, work, and communities.',
              ),
              _PrivacyStyleRow(
                level: 1,
                title: 'More private',
                description:
                    'Uses quieter discovery and fewer activity signals.',
              ),
              _PrivacyStyleRow(
                level: 2,
                title: 'Lockdown',
                description: 'Most private; slower and stricter.',
              ),
            ],
          ),
        ),

        const SizedBox(height: 8),

        // The choice is never final: say where it can be changed.
        Text(
          'You can change this any time in Settings → Privacy & Safety.',
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          textAlign: TextAlign.center,
        ),

        const SizedBox(height: 24),

        // Always enabled: a preset is always selected.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: _save_privacy_style,
            child: const Text('Next'),
          ),
        ),

        const SizedBox(height: 16),
      ],
    );
  }

  // =========================================================================
  // 7 — PIN Setup
  // =========================================================================

  /// Builds the PIN Setup screen (§22.42.5, §22.27.2).
  ///
  /// PIN setup is "strongly encouraged" but skippable with acknowledgment.
  /// Back from this step closes an open sub-form first, then returns to the
  /// privacy style step; Done never comes back here, so the PIN choice is
  /// final once Done is reached (a PIN can still be changed in Settings).
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
      key: const ValueKey(OnboardingStep.pinSetup),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 32),

        // Brand icon for the PIN concept — brand as a foreground reads the
        // per-theme token (§22.1.1, CMR-019).
        Icon(Icons.pin_outlined, size: 48, color: MeshColors.of(context).brand_fg),

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
  /// Inline PIN entry and confirmation.  4 to 16 digits (§22.27 / §22.42.5).
  /// "Set PIN" is disabled until both fields hold at least 4 digits, and the
  /// length rule is always visible as helper text under the confirm field
  /// (same wording as PinScreen, §22.10.10) so the disabled button says why.
  /// Done on the confirm field is the keyboard's Set PIN.  Mismatch is shown
  /// as error text on the confirm field.
  Widget _buildPinForm(ColorScheme cs, TextTheme tt) {
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
          // Next moves the keyboard focus to the confirm field.
          textInputAction: TextInputAction.next,
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
          // Done on the confirm field is the keyboard's "Set PIN"; it does
          // nothing while the form is invalid, exactly like the button.
          textInputAction: TextInputAction.done,
          onSubmitted: (_) {
            if (_pin_ready) _confirmPin();
          },
          onChanged: (_) => setState(() => _pinMismatch = false),
          decoration: InputDecoration(
            labelText: 'Confirm PIN',
            counterText: '',
            // The disabled Set PIN button says why: the length rule is
            // always visible (§22.42.5, same wording as PinScreen).
            helperText: '4 to 16 digits',
            // Show error text only if the user has attempted a confirmation
            // and the values don't match.
            errorText: _pinMismatch ? 'PINs do not match' : null,
          ),
        ),

        const SizedBox(height: 20),

        // --- Security controls (§3.6.4, §22.27) ----------------------------
        // "Require PIN after phone lock" — defaults enabled so users are
        // protected by default; opt-out is available but not the default path.
        CheckboxListTile(
          value: _requirePinAfterLock,
          onChanged: (v) => setState(() => _requirePinAfterLock = v ?? true),
          title: const Text('Require PIN after phone locks'),
          subtitle: const Text(
            'Locks your identity whenever the screen turns off.',
          ),
          controlAffinity: ListTileControlAffinity.leading,
          dense: true,
          contentPadding: EdgeInsets.zero,
        ),

        // Timeout dropdown — only shown when "require after lock" is enabled.
        if (_requirePinAfterLock) ...[
          const SizedBox(height: 8),
          DropdownButtonFormField<int>(
            initialValue: _lockTimeoutSecs,
            decoration: const InputDecoration(
              labelText: 'Lock after',
              isDense: true,
            ),
            items: const [
              DropdownMenuItem(value: 0, child: Text('Immediately')),
              DropdownMenuItem(value: 60, child: Text('1 minute')),
              DropdownMenuItem(value: 300, child: Text('5 minutes')),
              DropdownMenuItem(value: 900, child: Text('15 minutes')),
            ],
            onChanged: (v) => setState(() => _lockTimeoutSecs = v ?? 0),
          ),
        ],

        const SizedBox(height: 20),

        // Set PIN — disabled until both fields meet minimum length.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton(
            onPressed: _pin_ready ? _confirmPin : null,
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
                  style: TextButton.styleFrom(foregroundColor: cs.error),
                  onPressed: () => _goTo(OnboardingStep.done),
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
  // 8 — Done
  // =========================================================================

  /// Builds the Done screen (§22.42.7) — "what next".
  ///
  /// Two actions, both of which run _finish_onboarding(): the backend flag
  /// is persisted first, then widget.onComplete() dismisses the onboarding
  /// screen and shows AppShell.  The primary "Add a contact" additionally
  /// has app.dart push PairContactScreen (§22.8.3) on top of the shell; the
  /// secondary "Go to Chat" lands on the Chat section's empty state.  If
  /// persisting fails the step stays, with the error shown above the buttons.
  Widget _buildDone() {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    // Per-theme status colours (success check).
    final colors = MeshColors.of(context);

    return Column(
      key: const ValueKey(OnboardingStep.done),
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(height: 48),

        // Success icon.
        Container(
          width: 72,
          height: 72,
          decoration: BoxDecoration(
            color: colors.sec_green.withValues(alpha: 0.12),
            shape: BoxShape.circle,
          ),
          child: Icon(Icons.check_rounded, size: 40, color: colors.sec_green),
        ),

        const SizedBox(height: 24),

        Text(
          'You\'re set up',
          style: tt.headlineMedium?.copyWith(fontWeight: FontWeight.w700),
          textAlign: TextAlign.center,
        ),

        const SizedBox(height: 12),

        // One honest line: the app is ready, and nothing happens until the
        // user has a contact — which is why the primary action adds one.
        Text(
          'Mesh Infinity is ready. Nothing works until you have someone to '
          'talk to.',
          style: tt.bodyLarge?.copyWith(color: cs.onSurfaceVariant),
          textAlign: TextAlign.center,
        ),

        const SizedBox(height: 48),

        // Shown when the backend could not persist the onboarding flag; the
        // user can simply try again.
        if (_error != null) ...[
          _ErrorBanner(message: _error!),
          const SizedBox(height: 16),
        ],

        // Primary "what next": persists the flag, then app.dart opens
        // PairContactScreen on top of the shell.
        SizedBox(
          width: double.infinity,
          height: 52,
          child: FilledButton.icon(
            onPressed: () => _finish_onboarding(OnboardingExit.addContact),
            icon: const Icon(Icons.person_add_rounded),
            label: const Text('Add a contact'),
          ),
        ),

        const SizedBox(height: 8),

        // Secondary: persists the flag and lands on Chat's empty state.
        TextButton(
          onPressed: () => _finish_onboarding(OnboardingExit.chat),
          child: const Text('Go to Chat'),
        ),

        const SizedBox(height: 32),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// _PrivacyStyleRow
// ---------------------------------------------------------------------------

/// One preset row of the Privacy style step: a RadioListTile whose value is
/// the backend ThreatContext level the preset maps to.
///
/// The enclosing [RadioGroup] supplies the selected value and the change
/// handler, so the row itself only carries its own level and copy.
class _PrivacyStyleRow extends StatelessWidget {
  const _PrivacyStyleRow({
    required this.level,
    required this.title,
    required this.description,
  });

  /// Backend ThreatContext level: 0 Normal, 1 Elevated, 2 Critical.
  final int level;

  /// Preset title, verbatim from §22.27 item 3.
  final String title;

  /// One-line description, verbatim from §22.27 item 3.
  final String description;

  @override
  Widget build(BuildContext context) {
    return RadioListTile<int>(
      value: level,
      title: Text(title),
      subtitle: Text(description),
      contentPadding: EdgeInsets.zero,
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
      // The fallback glyph is a brand foreground (§22.1.1, CMR-019).
      errorBuilder: (context, error, _) => Icon(
        Icons.hub_rounded,
        size: size,
        color: MeshColors.of(context).brand_fg,
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
          // The fallback glyph is a brand foreground (§22.1.1, CMR-019).
          errorBuilder: (context, error, _) => Icon(
            Icons.hub_rounded,
            size: 56,
            color: MeshColors.of(context).brand_fg,
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
          Icon(
            Icons.error_outline_rounded,
            size: 18,
            color: cs.onErrorContainer,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              message,
              style: Theme.of(
                context,
              ).textTheme.bodySmall?.copyWith(color: cs.onErrorContainer),
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
