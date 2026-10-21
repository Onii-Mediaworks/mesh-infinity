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
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../app/motion.dart';
import '../../../app/app_theme.dart';
import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';
import 'killswitch_screen.dart';

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
}

// ---------------------------------------------------------------------------
// Backoff schedule (mirror of backend/identity/pin.rs `backoff_delay`)
// ---------------------------------------------------------------------------

/// Seconds the backend refuses a PIN attempt after [failures] consecutive
/// failures (§3.10).  The backend exposes no "seconds remaining" accessor
/// and its identity code is out of scope for the UI, so the schedule is
/// mirrored here to draw the lockout countdown.  The backend stays the
/// enforcer; this only labels the wait.
int pin_backoff_secs(int failures) {
  // Attempts 1-5 carry no delay.
  if (failures <= 5) return 0;
  return switch (failures) {
    6 => 30,
    7 => 120,
    8 => 600,
    9 => 3600,
    10 => 86400,
    _ => 259200,
  };
}

/// Formats a wait as "0:30", "2:00", "1:00:00" or "3 days" for the countdown.
String format_wait(int secs) {
  if (secs >= 172800) return '${(secs / 86400).ceil()} days';
  final h = secs ~/ 3600;
  final m = (secs % 3600) ~/ 60;
  final ss = (secs % 60).toString().padLeft(2, '0');
  if (h > 0) return '$h:${m.toString().padLeft(2, '0')}:$ss';
  return '$m:$ss';
}

// ---------------------------------------------------------------------------
// PinScreen
// ---------------------------------------------------------------------------

/// Universal PIN screen covering setup, change, removal, unlock, and duress flows.
class PinScreen extends StatefulWidget {
  const PinScreen({
    super.key,
    required this.mode,
    this.onUnlocked,
  });

  // Which flow this screen is running.
  final PinScreenMode mode;
  final VoidCallback? onUnlocked;

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
  int _step = 0;

  // The PIN typed so far in the current step.
  final TextEditingController _pinController = TextEditingController();

  // The PIN from step 1 of setup/setupDuress/change, stored for comparison.
  String _firstPin = '';
  String _currentPin = '';

  // Whether the last entry was wrong.  Stays true (text + icon visible)
  // until the next key press (§22.10.10); never cleared by a timer.
  bool _wrong = false;

  // Text of the wrong-entry line ("Wrong PIN" or a mismatch message).
  String _wrong_label = 'Wrong PIN';

  // Wrong verifications on this screen.  The backend holds the real counter
  // (never logged, §21.2.2); this session count only drives the countdown
  // and the last-two warning.
  int _failures = 0;

  // When the current lockout ends, and the whole seconds left until then.
  DateTime? _lock_until;
  int _lock_left = 0;
  Timer? _lock_timer;

  // Whether unlock has failed at least once in this session.
  bool _hasUnlockFailure = false;

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
    _lock_timer?.cancel();
    _pinFocusNode.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Step metadata helpers
  // ---------------------------------------------------------------------------

  // Maximum step index for this mode (0-indexed).
  int get _maxStep => switch (widget.mode) {
    PinScreenMode.setup => 1,
    PinScreenMode.change => 2,
    PinScreenMode.remove => 0,
    PinScreenMode.unlock => 0,
  };

  // Label shown above the dots.
  String get _stepLabel => switch (widget.mode) {
    PinScreenMode.setup => _step == 0 ? 'Create a PIN' : 'Confirm your PIN',
    PinScreenMode.change => switch (_step) {
      0 => 'Enter your current PIN',
      1 => 'Enter new PIN',
      _ => 'Confirm new PIN',
    },
    PinScreenMode.remove => 'Enter your PIN to remove it',
    PinScreenMode.unlock => 'Enter your PIN',
  };

  // Subtitle below the step label.
  String get _stepSubtitle => switch (widget.mode) {
    PinScreenMode.setup =>
      _step == 0 ? '4 to 16 digits' : 'Enter the same PIN again',
    PinScreenMode.change => switch (_step) {
      1 => '4 to 16 digits',
      2 => 'Enter the same PIN again',
      _ => '',
    },
    PinScreenMode.remove => '',
    PinScreenMode.unlock => '',
  };

  // AppBar title.
  String get _appBarTitle => switch (widget.mode) {
    PinScreenMode.setup => 'App PIN',
    PinScreenMode.change => 'Change PIN',
    PinScreenMode.remove => 'Remove PIN',
    PinScreenMode.unlock => 'Unlock',
  };

  // ---------------------------------------------------------------------------
  // PIN entry handling
  // ---------------------------------------------------------------------------

  // Called every time the hidden text field changes.
  void _onPinChanged(String value) {
    // Cap at 16 digits (max PIN length).
    if (value.length > 16) {
      _pinController.text = value.substring(0, 16);
      _pinController.selection = const TextSelection.collapsed(offset: 16);
      return;
    }

    // The wrong-PIN line is cleared by the next key press, not by a timer.
    // The same rebuild refreshes the dot display.
    setState(() => _wrong = false);
  }

  // Called when the user submits the current step's PIN.
  void _submit() {
    final pin = _pinController.text;

    // Minimum length check — button is disabled below 4 digits, but
    // guard here in case of programmatic calls.
    if (pin.length < 4) return;

    // Refuse while locked out; the backend would reject it anyway.
    if (_lock_left > 0) return;

    switch (widget.mode) {
      case PinScreenMode.setup:
        _handleSetupStep(pin);

      case PinScreenMode.change:
        _handleChangeStep(pin);

      case PinScreenMode.remove:
        _handleRemove(pin);

      case PinScreenMode.unlock:
        _handleUnlock(pin);
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
        _triggerWrong(label: "PINs don't match", counts: false);
        return;
      }
      final bridge = context.read<BackendBridge>();
      final ok = bridge.setPin(pin);
      if (!ok) {
        _triggerWrong(label: "Couldn't set PIN", counts: false);
        return;
      }
      context.read<SettingsState>().loadAll();
      Navigator.pop(context);
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('PIN set')));
    }
  }

  // Three-step change: 0 = verify old, 1 = enter new, 2 = confirm new.
  void _handleChangeStep(String pin) {
    if (_step == 0) {
      _currentPin = pin;
      _pinController.clear();
      setState(() => _step = 1);
    } else if (_step == 1) {
      _firstPin = pin;
      _pinController.clear();
      setState(() => _step = 2);
    } else {
      if (pin != _firstPin) {
        _triggerWrong(label: "PINs don't match", counts: false);
        return;
      }
      final bridge = context.read<BackendBridge>();
      final ok = bridge.changePin(_currentPin, pin);
      if (!ok) {
        _step = 0;
        _currentPin = '';
        _firstPin = '';
        _pinController.clear();
        _triggerWrong();
        return;
      }
      context.read<SettingsState>().loadAll();
      Navigator.pop(context);
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('PIN changed')));
    }
  }

  // Single-step removal.
  void _handleRemove(String pin) {
    final bridge = context.read<BackendBridge>();
    final ok = bridge.removePin(pin);
    if (!ok) {
      _triggerWrong();
      return;
    }
    context.read<SettingsState>().loadAll();
    Navigator.pop(context);
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(const SnackBar(content: Text('PIN removed')));
  }

  // Single-step unlock.
  void _handleUnlock(String pin) {
    final bridge = context.read<BackendBridge>();
    final unlocked = bridge.unlockIdentity(pin: pin);
    if (unlocked) {
      context.read<SettingsState>().loadAll();
      final onUnlocked = widget.onUnlocked;
      if (onUnlocked != null) {
        onUnlocked();
      } else {
        Navigator.pop(context);
      }
      return;
    }
    final message = bridge.getLastError();
    if (message != null && mounted) {
      context.read<SettingsState>().loadAll();
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(message)));
    }
    _triggerWrong();
  }

  // Show the wrong-entry feedback (§22.10.10): a text line with an icon that
  // stays until the next key press, plus a decorative shake.  [counts] is
  // true for a failed PIN verification (feeds lockout and tries-left) and
  // false for a setup mismatch, which the backend never counts.
  void _triggerWrong({String label = 'Wrong PIN', bool counts = true}) {
    HapticFeedback.vibrate();
    _pinController.clear();
    setState(() {
      _wrong = true;
      _wrong_label = label;
      _hasUnlockFailure = true;
      if (counts) _failures++;
    });
    if (counts) _start_lockout();

    // The shake is decoration only; under reduced motion (§22.1.7) it is
    // skipped and the text line carries the whole signal.
    if (!reduced_motion(context)) _shakeController.forward(from: 0);
  }

  // Begin the lockout countdown when the schedule demands a wait.
  void _start_lockout() {
    final wait = pin_backoff_secs(_failures);
    if (wait == 0) return;
    _lock_until = DateTime.now().add(Duration(seconds: wait));
    _lock_left = wait;
    _lock_timer?.cancel();
    _lock_timer = Timer.periodic(const Duration(seconds: 1), (_) {
      final left = _lock_until!.difference(DateTime.now()).inSeconds;
      if (!mounted) return;
      setState(() => _lock_left = left > 0 ? left : 0);
      if (left <= 0) _lock_timer?.cancel();
    });
  }

  // Attempts left before auto-wipe, or null when nothing may be shown.
  // CMR-023: only when the wipe is armed and only for the last two tries.
  int? _tries_left() {
    final settings = context.read<SettingsState>();
    if (!settings.wrongPinWipeEnabled || _failures == 0) return null;
    final left = settings.wrongPinWipeThreshold - _failures;
    return (left >= 1 && left <= 2) ? left : null;
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
        // CloseButton for modal flows (setup, change, remove).
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
                            10 *
                                _shakeAnimation.value *
                                ((_shakeController.value * 6).floor().isEven
                                    ? 1
                                    : -1),
                            0,
                          ),
                          child: child,
                        ),
                        child: _PinDots(entered: pinLen, wrong: _wrong),
                      ),

                      // Wrong-entry, lockout and tries-left lines.
                      _feedback(context),

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

                      // Forgot PIN link — shown in unlock mode after first failure.
                      if (widget.mode == PinScreenMode.unlock &&
                          _hasUnlockFailure) ...[
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
                    onPressed: (pinLen >= 4 && _lock_left == 0) ? _submit : null,
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

  // Text feedback under the dots, announced as a live region.  Every line
  // pairs an icon with words so colour is never the only signal (WCAG 1.4.1).
  Widget _feedback(BuildContext context) {
    final colors = MeshColors.of(context);
    final tt = Theme.of(context).textTheme;
    final tries = _tries_left();
    final lines = <(IconData, String)>[
      if (_wrong) (Icons.error_outline, _wrong_label),
      if (_lock_left > 0)
        (
          Icons.timer_outlined,
          'Too many attempts. Try again in ${format_wait(_lock_left)}',
        ),
      if (_wrong && tries != null)
        (
          Icons.warning_amber_rounded,
          '$tries ${tries == 1 ? 'try' : 'tries'} left before this device erases',
        ),
    ];
    return Semantics(
      liveRegion: true,
      child: Column(
        children: [
          for (final (icon, text) in lines)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(icon, size: 18, color: colors.sec_red),
                  const SizedBox(width: 6),
                  Flexible(
                    child: Text(
                      text,
                      style: tt.bodyMedium?.copyWith(color: colors.sec_red),
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  // The label on the final step's button (varies by mode).
  String get _finalButtonLabel => switch (widget.mode) {
    PinScreenMode.setup => 'Set PIN',
    PinScreenMode.change => 'Change PIN',
    PinScreenMode.remove => 'Remove PIN',
    PinScreenMode.unlock => 'Unlock',
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
              style: Theme.of(
                context,
              ).textTheme.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
          // Recovery path — erase everything and start fresh.
          ListTile(
            leading: Icon(Icons.delete_forever_outlined, color: cs.error),
            title: const Text('Erase and start fresh'),
            subtitle: const Text(
              'Permanently delete everything on this device and create a new identity.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              Navigator.pop(context);
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const KillswitchScreen()),
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
/// When [wrong] is true, filled dots turn the theme's `sec_red` for visual feedback.
class _PinDots extends StatelessWidget {
  const _PinDots({required this.entered, required this.wrong});

  // Number of digits entered so far.
  final int entered;

  // Whether to show the "wrong PIN" red fill.
  final bool wrong;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    // Per-theme status colours; sec_red is the "wrong PIN" fill.
    final colors = MeshColors.of(context);

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
            ? (wrong ? colors.sec_red : cs.primary)
            : cs.outline.withValues(alpha: 0.3);

        return AnimatedContainer(
          // Reduced motion (§22.1.7): dots change colour instantly.
          duration: motion_duration(context, const Duration(milliseconds: 150)),
          margin: const EdgeInsets.symmetric(horizontal: 6),
          width: 14,
          height: 14,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        );
      }),
    );
  }
}
