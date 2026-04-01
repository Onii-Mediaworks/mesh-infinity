// pin_screen.dart
//
// PinScreen — app PIN setup, change, removal, and unlock gate (§22.10.10).
//
// MODES:
// ------
// This one screen handles all PIN-related flows, determined by [PinScreenMode]:
//
//   setup      — first-time PIN creation (2 steps: enter → confirm)
//   change     — change existing PIN (3 steps: verify old → enter new → confirm new)
//   remove     — remove PIN (1 step: verify then confirm)
//   unlock     — re-authentication gate; no AppBar close button
//   setupDuress — set up the duress PIN (same UI as setup, different backend call)
//   testDuress  — verify duress PIN without triggering erase
//
// PIN DESIGN:
// -----------
// 4–16 digits.  We use a hidden text field that receives all keyboard input.
// The visible UI shows animated dots, not the actual digits (security).
// On mobile the hidden field opens the numeric keyboard.
// On desktop the field accepts keyboard events from the native keyboard.
//
// The hidden-field-with-visible-dots pattern is standard for PIN entry
// (used by iOS, Android, and countless banking apps).  Users are familiar
// with it.
//
// WRONG PIN BEHAVIOUR:
// --------------------
// Shake animation (150ms, 3 cycles left-right oscillation) + red fill for 400ms.
// After 5 failed attempts: 30-second lockout timer displayed.
// The lockout is enforced here in UI; real enforcement is in the backend
// (the backend doesn't need to trust the UI counter).
//
// DURESS PIN (§3.10):
// --------------------
// The duress PIN is entered identically to the normal PIN.  The backend
// determines via bridge.unlockIdentity() return value whether it was a duress
// unlock.  The UI never knows — it must look completely normal.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../../app/app_theme.dart';

// ---------------------------------------------------------------------------
// PinScreenMode enum
// ---------------------------------------------------------------------------

/// Determines which step sequence and AppBar configuration PinScreen uses.
enum PinScreenMode {
  // New PIN creation — two-step (enter + confirm).
  setup,
  // Change existing PIN — three-step (verify old + new + confirm new).
  change,
  // Remove PIN — one-step verification then backend call to disable.
  remove,
  // Re-authentication gate — single entry, no close button, no back navigation.
  unlock,
  // Set up a duress PIN — same two-step as setup but goes to different backend call.
  setupDuress,
  // Verify the duress PIN without triggering erase — used in EmergencyEraseScreen test flow.
  testDuress,
}

// ---------------------------------------------------------------------------
// PinScreen
// ---------------------------------------------------------------------------

/// Universal PIN screen covering setup, change, removal, unlock, and duress flows.
class PinScreen extends StatefulWidget {
  const PinScreen({super.key, required this.mode});

  // Which flow this screen is running.
  final PinScreenMode mode;

  @override
  State<PinScreen> createState() => _PinScreenState();
}

class _PinScreenState extends State<PinScreen>
    with SingleTickerProviderStateMixin {
  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  // Current step within the mode's step sequence (0-indexed).
  // setup: 0=enter, 1=confirm
  // change: 0=old, 1=new, 2=confirm-new
  // remove/unlock: 0=verify
  // setupDuress: 0=enter, 1=confirm
  // testDuress: 0=enter
  int _step = 0;

  // The PIN typed so far in the current step.
  final TextEditingController _pinController = TextEditingController();

  // The PIN from step 1 of setup/setupDuress/change, stored for comparison.
  String _firstPin = '';

  // Whether this entry was wrong (triggers shake + red fill).
  bool _wrong = false;

  // Number of consecutive failed attempts.  Lockout triggers at 5.
  int _failCount = 0;

  // Remaining lockout seconds after 5 failures.  0 = not locked out.
  int _lockoutSeconds = 0;

  // Timer used to tick down the lockout countdown.
  Timer? _lockoutTimer;

  // Shake animation controller — oscillates the dot row on wrong PIN.
  late final AnimationController _shakeController;
  late final Animation<double> _shakeAnimation;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();

    // Shake: 150ms total, 3 left-right oscillations.
    // Curve is a sinusoid so it eases in and out naturally.
    _shakeController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 400),
    );
    _shakeAnimation = Tween<double>(begin: 0, end: 1).animate(
      CurvedAnimation(parent: _shakeController, curve: Curves.elasticOut),
    );
  }

  @override
  void dispose() {
    _pinController.dispose();
    _shakeController.dispose();
    _lockoutTimer?.cancel();
    _pinFocusNode.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Step metadata helpers
  // ---------------------------------------------------------------------------

  // Maximum step index for this mode (0-indexed).
  int get _maxStep => switch (widget.mode) {
    PinScreenMode.setup       => 1,
    PinScreenMode.setupDuress => 1,
    PinScreenMode.change      => 2,
    PinScreenMode.remove      => 0,
    PinScreenMode.unlock      => 0,
    PinScreenMode.testDuress  => 0,
  };

  // Label shown above the dots.
  String get _stepLabel => switch (widget.mode) {
    PinScreenMode.setup => _step == 0 ? 'Create a PIN' : 'Confirm your PIN',
    PinScreenMode.setupDuress => _step == 0 ? 'Create a duress PIN' : 'Confirm your duress PIN',
    PinScreenMode.change => switch (_step) {
      0 => 'Enter your current PIN',
      1 => 'Enter new PIN',
      _ => 'Confirm new PIN',
    },
    PinScreenMode.remove      => 'Enter your PIN to remove it',
    PinScreenMode.unlock      => 'Enter your PIN',
    PinScreenMode.testDuress  => 'Enter your duress PIN',
  };

  // Subtitle below the step label.
  String get _stepSubtitle => switch (widget.mode) {
    PinScreenMode.setup => _step == 0 ? '4 to 16 digits' : 'Enter the same PIN again',
    PinScreenMode.setupDuress => _step == 0 ? '4 to 16 digits — different from your main PIN' : 'Enter the same duress PIN again',
    PinScreenMode.change => switch (_step) {
      1 => '4 to 16 digits',
      2 => 'Enter the same PIN again',
      _ => '',
    },
    PinScreenMode.remove      => '',
    PinScreenMode.unlock      => '',
    PinScreenMode.testDuress  => 'This will not erase anything — just verifies the PIN.',
  };

  // AppBar title.
  String get _appBarTitle => switch (widget.mode) {
    PinScreenMode.setup       => 'App PIN',
    PinScreenMode.setupDuress => 'Duress PIN',
    PinScreenMode.change      => 'Change PIN',
    PinScreenMode.remove      => 'Remove PIN',
    PinScreenMode.unlock      => 'Unlock',
    PinScreenMode.testDuress  => 'Test Duress PIN',
  };

  // ---------------------------------------------------------------------------
  // PIN entry handling
  // ---------------------------------------------------------------------------

  // Called every time the hidden text field changes.
  void _onPinChanged(String value) {
    // Cap at 16 digits (max PIN length).
    if (value.length > 16) {
      _pinController.text = value.substring(0, 16);
      _pinController.selection = TextSelection.collapsed(offset: 16);
      return;
    }

    // Clear the "wrong" state as soon as the user starts re-entering.
    if (_wrong) setState(() => _wrong = false);

    // Auto-advance when minimum length (4) is reached and the user hasn't
    // confirmed yet.  In practice we wait for explicit submission via
    // the Submit button or hardware Enter key.
    setState(() {}); // Rebuild to update the dot display.
  }

  // Called when the user submits the current step's PIN.
  void _submit() {
    final pin = _pinController.text;

    // Minimum length check — button is disabled below 4 digits, but
    // guard here in case of programmatic calls.
    if (pin.length < 4) return;

    // Lockout guard.
    if (_lockoutSeconds > 0) return;

    switch (widget.mode) {
      case PinScreenMode.setup:
      case PinScreenMode.setupDuress:
        _handleSetupStep(pin);

      case PinScreenMode.change:
        _handleChangeStep(pin);

      case PinScreenMode.remove:
        _handleRemove(pin);

      case PinScreenMode.unlock:
        _handleUnlock(pin);

      case PinScreenMode.testDuress:
        _handleTestDuress(pin);
    }
  }

  // Two-step setup: step 0 = store PIN, step 1 = confirm matches.
  void _handleSetupStep(String pin) {
    if (_step == 0) {
      // Store pin and move to confirmation step.
      _firstPin = pin;
      _pinController.clear();
      setState(() => _step = 1);
    } else {
      // Confirm step: pins must match.
      if (pin != _firstPin) {
        _triggerWrong();
        return;
      }
      // TODO(backend/security): call bridge.setupPin(pin) or bridge.setupDuressPin(pin).
      final isMain = widget.mode == PinScreenMode.setup;
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(isMain ? 'PIN set' : 'Duress PIN set')),
      );
    }
  }

  // Three-step change: 0 = verify old, 1 = enter new, 2 = confirm new.
  void _handleChangeStep(String pin) {
    if (_step == 0) {
      // TODO(backend/security): verify current PIN via bridge.verifyPin(pin).
      // Stub: always accept for now.
      _firstPin = '';
      _pinController.clear();
      setState(() => _step = 1);
    } else if (_step == 1) {
      _firstPin = pin;
      _pinController.clear();
      setState(() => _step = 2);
    } else {
      if (pin != _firstPin) {
        _triggerWrong();
        return;
      }
      // TODO(backend/security): call bridge.changePin(pin).
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('PIN changed')),
      );
    }
  }

  // Single-step removal.
  void _handleRemove(String pin) {
    // TODO(backend/security): verify PIN and disable via bridge.removePin().
    // Stub: always succeed.
    Navigator.pop(context);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('PIN removed')),
    );
  }

  // Single-step unlock.
  void _handleUnlock(String pin) {
    // TODO(backend/security): call bridge.unlockIdentity() and check return.
    // Stub: always succeed.  The real backend will also detect duress PINs here.
    Navigator.pop(context);
  }

  // Single-step duress PIN test — verifies without erasing.
  void _handleTestDuress(String pin) {
    // TODO(backend/security): call bridge.testDuressPin(pin).
    // Stub: always succeed.
    HapticFeedback.mediumImpact();
    Navigator.pop(context);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Duress PIN verified — it works.')),
    );
  }

  // Trigger the "wrong PIN" visual: shake + red fill + failure counter.
  void _triggerWrong() {
    HapticFeedback.vibrate();
    _pinController.clear();
    _failCount++;

    setState(() => _wrong = true);

    // Shake animation — plays once and stops.
    _shakeController.forward(from: 0);

    // Reset the red fill after 400ms (matching shake duration).
    Future.delayed(const Duration(milliseconds: 400), () {
      if (mounted) setState(() => _wrong = false);
    });

    // Start 30-second lockout after 5 failures.
    if (_failCount >= 5) {
      _failCount = 0;
      _lockoutSeconds = 30;
      _lockoutTimer = Timer.periodic(const Duration(seconds: 1), (t) {
        if (!mounted) {
          t.cancel();
          return;
        }
        setState(() {
          _lockoutSeconds--;
          if (_lockoutSeconds <= 0) t.cancel();
        });
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    final pinLen = _pinController.text.length;

    // In unlock mode there is no close button — the user cannot dismiss the
    // screen without entering the correct PIN.
    final canClose = widget.mode != PinScreenMode.unlock;

    return Scaffold(
      appBar: AppBar(
        title: Text(_appBarTitle),
        // CloseButton for modal flows (setup, change, remove, setupDuress).
        // No leading in unlock mode — prevents back-button dismissal.
        leading: canClose ? const CloseButton() : const SizedBox.shrink(),
        automaticallyImplyLeading: false,
      ),
      body: GestureDetector(
        // Tapping anywhere re-focuses the hidden text field so the keyboard
        // stays up and the dots remain interactive on mobile.
        onTap: () => FocusScope.of(context).requestFocus(_pinFocusNode),
        child: Column(
          children: [
            Expanded(
              child: Center(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 32),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      // Step label.
                      Text(
                        _stepLabel,
                        style: tt.titleMedium,
                        textAlign: TextAlign.center,
                      ),
                      if (_stepSubtitle.isNotEmpty) ...[
                        const SizedBox(height: 6),
                        Text(
                          _stepSubtitle,
                          style: tt.bodySmall?.copyWith(
                            color: cs.onSurfaceVariant,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ],
                      const SizedBox(height: 28),

                      // PIN dots row wrapped in a shake animation.
                      AnimatedBuilder(
                        animation: _shakeAnimation,
                        builder: (_, child) => Transform.translate(
                          // Sinusoidal shake: ±10px horizontal oscillation.
                          offset: Offset(
                            10 * _shakeAnimation.value *
                                ((_shakeController.value * 6).floor().isEven
                                    ? 1
                                    : -1),
                            0,
                          ),
                          child: child,
                        ),
                        child: _PinDots(
                          entered: pinLen,
                          wrong: _wrong,
                        ),
                      ),

                      const SizedBox(height: 28),

                      // Hidden text field — captures keyboard input on all platforms.
                      // Opacity 0 makes it invisible but still receives input.
                      Opacity(
                        opacity: 0,
                        child: SizedBox(
                          width: 1,
                          child: TextField(
                            controller: _pinController,
                            focusNode: _pinFocusNode,
                            autofocus: true,
                            keyboardType: const TextInputType.numberWithOptions(
                              signed: false,
                              decimal: false,
                            ),
                            obscureText: true,
                            maxLength: 16,
                            onChanged: _onPinChanged,
                            onSubmitted: (_) => _submit(),
                            // Remove the character counter that shows "N/16".
                            decoration: const InputDecoration(counterText: ''),
                          ),
                        ),
                      ),

                      // Lockout display — shown only during the 30-second cooldown.
                      if (_lockoutSeconds > 0) ...[
                        const SizedBox(height: 8),
                        Text(
                          'Too many attempts. Try again in $_lockoutSeconds seconds.',
                          style: tt.bodySmall?.copyWith(
                            color: cs.error,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ],

                      // Forgot PIN link — shown in unlock mode after first failure.
                      if (widget.mode == PinScreenMode.unlock &&
                          _failCount >= 1) ...[
                        const SizedBox(height: 16),
                        TextButton(
                          onPressed: () => _showForgotSheet(context),
                          child: const Text('Forgot PIN?'),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),

            // Submit button at the bottom of the screen.
            SafeArea(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(24, 0, 24, 16),
                child: SizedBox(
                  width: double.infinity,
                  child: FilledButton(
                    // Disabled below 4 digits or during lockout.
                    onPressed:
                        pinLen >= 4 && _lockoutSeconds == 0 ? _submit : null,
                    child: Text(
                      _step == _maxStep ? _finalButtonLabel : 'Continue',
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // The label on the final step's button (varies by mode).
  String get _finalButtonLabel => switch (widget.mode) {
    PinScreenMode.setup       => 'Set PIN',
    PinScreenMode.setupDuress => 'Set duress PIN',
    PinScreenMode.change      => 'Change PIN',
    PinScreenMode.remove      => 'Remove PIN',
    PinScreenMode.unlock      => 'Unlock',
    PinScreenMode.testDuress  => 'Verify',
  };

  // FocusNode for the hidden text field — allows re-focus on tap-outside.
  final FocusNode _pinFocusNode = FocusNode();

  // Show the "Forgot PIN?" bottom sheet (unlock mode only).
  void _showForgotSheet(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (_) => Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 16, 20, 4),
            child: Text(
              'Forgot your PIN?',
              style: Theme.of(context).textTheme.titleMedium,
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 0, 20, 16),
            child: Text(
              'Your PIN protects your identity and messages. Without it, '
              'there is no way to recover your existing data on this device.',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: cs.onSurfaceVariant,
                  ),
            ),
          ),
          // Restore path — erase then import from backup.
          ListTile(
            leading: Icon(Icons.restore_outlined, color: MeshTheme.brand),
            title: const Text('Erase and restore from backup'),
            subtitle: const Text(
              'If you have a backup, erase this device and restore from it.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              Navigator.pop(context);
              // TODO(backend/security): trigger emergency erase then open backup import.
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Backup restore not yet available.'),
                ),
              );
            },
          ),
          // Nuclear path — erase everything and start fresh.
          ListTile(
            leading: Icon(Icons.delete_forever_outlined, color: cs.error),
            title: const Text('Erase and start fresh'),
            subtitle: const Text(
              'Permanently delete everything. Create a new identity.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              Navigator.pop(context);
              // TODO(backend/security): confirm dialog then emergency erase.
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Emergency erase not yet available.'),
                ),
              );
            },
          ),
          const SizedBox(height: 8),
        ],
      ),
    );
  }

}

// ---------------------------------------------------------------------------
// _PinDots — visible PIN progress indicator
// ---------------------------------------------------------------------------

/// Renders 4–16 animated dots showing how many PIN digits have been entered.
///
/// Filled dots = digits entered; empty (outlined) circles = remaining slots.
/// When [wrong] is true, filled dots turn [MeshTheme.secRed] for visual feedback.
class _PinDots extends StatelessWidget {
  const _PinDots({required this.entered, required this.wrong});

  // Number of digits entered so far.
  final int entered;

  // Whether to show the "wrong PIN" red fill.
  final bool wrong;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // Show at least 4 dots, expanding up to 16 as the user types.
    // This gives visual feedback that longer PINs are possible without
    // showing an intimidating 16-dot row from the start.
    final displayCount = entered.clamp(4, 16);

    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: List.generate(displayCount, (i) {
        // Determine if this dot represents an entered digit.
        final isFilled = i < entered;

        // Colour: red for wrong, brand primary for correct, outline for empty.
        final color = isFilled
            ? (wrong ? MeshTheme.secRed : cs.primary)
            : cs.outline.withValues(alpha: 0.3);

        return AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          margin: const EdgeInsets.symmetric(horizontal: 6),
          width: 14,
          height: 14,
          decoration: BoxDecoration(
            color: color,
            shape: BoxShape.circle,
          ),
        );
      }),
    );
  }
}
