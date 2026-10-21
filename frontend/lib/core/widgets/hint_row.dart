// hint_row.dart
//
// HintRow — the optional one-line strip of controller hints (§22.36 rule 5).
//
// RULES IT ENFORCES
// -----------------
//   * Shows only actions that really dispatch on this screen: the screen
//     passes exactly the hints it handles, and each hint carries the intent
//     it stands for, so a hint can never name something that does nothing.
//   * Every hint is itself a tappable control that performs the action, via
//     InputMap.dispatch — the same path a key press takes — so the row
//     doubles as the touch route and is never decorative.
//   * Hidden until a gamepad has been seen or key-driven focus has
//     occurred (ShellState.hints_wanted), then visible for the session.
//   * Names the *physical* button (A/B/X/Y, L1/R1) when the last input was
//     a pad, and the key when it was a keyboard.
//   * SafeArea-aware so it clears the home indicator in every orientation.
//
// The hint chips are deliberately not focusable: a keyboard user already
// has the key, and an extra Tab stop per hint would clutter traversal.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../shell/input_map.dart';
import '../../shell/shell_state.dart';

/// One hint: a physical button name, a key name, a label and the intent.
class Hint {
  const Hint({
    required this.pad,
    required this.key,
    required this.label,
    required this.intent,
  });

  /// Physical gamepad button, e.g. 'X', 'Y', 'L1'.
  final String pad;

  /// Keyboard equivalent, e.g. 'Shift+F10', 'Ctrl+Tab'.
  final String key;

  /// What the action does, e.g. 'Menu', 'Reply'.
  final String label;

  /// The intent dispatched when the hint is tapped.
  final Intent intent;

  /// Context-menu hint shared by every list and thread screen.
  ///
  /// `static final` (not `const`) keeps snake_case without a lint carve-out.
  static final Hint context_menu = const Hint(
    pad: 'X',
    key: 'Shift+F10',
    label: 'Menu',
    intent: ContextMenuIntent(),
  );

  /// Section/tab switch hint for screens inside the shell.
  static final Hint section_next = const Hint(
    pad: 'R1',
    key: 'Ctrl+Tab',
    label: 'Next tab',
    intent: SectionStepIntent(1),
  );
}

/// Bottom-edge strip of tappable controller hints.
class HintRow extends StatelessWidget {
  const HintRow({super.key, required this.hints});

  /// The hints this screen really handles, in display order.
  final List<Hint> hints;

  @override
  Widget build(BuildContext context) {
    final shell = context.read<ShellState>();
    return ValueListenableBuilder<bool>(
      valueListenable: shell.hints_wanted,
      builder: (context, wanted, _) {
        // Collapsed entirely until a pad or key-driven focus has been seen.
        if (!wanted || hints.isEmpty) return const SizedBox.shrink();
        return ValueListenableBuilder<InputSource>(
          valueListenable: shell.last_input,
          builder: (context, source, _) {
            final cs = Theme.of(context).colorScheme;
            return Material(
              color: cs.surfaceContainerLow,
              child: SafeArea(
                top: false,
                child: SizedBox(
                  height: 36,
                  child: ListView(
                    // Horizontal so a long hint list scrolls instead of
                    // overflowing on narrow phones in portrait.
                    scrollDirection: Axis.horizontal,
                    padding: const EdgeInsets.symmetric(horizontal: 8),
                    children: [
                      for (final hint in hints)
                        _HintChip(hint: hint, source: source),
                    ],
                  ),
                ),
              ),
            );
          },
        );
      },
    );
  }
}

/// One tappable "[button] label" chip.
class _HintChip extends StatelessWidget {
  const _HintChip({required this.hint, required this.source});

  /// The hint to render.
  final Hint hint;

  /// Decides whether the pad button or the key name is shown.
  final InputSource source;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    // Keyboard users see the key; pad users (and touch users after a pad
    // was seen) see the physical button, per rule 8.
    final name = source == InputSource.keyboard ? hint.key : hint.pad;
    return InkWell(
      // Not a Tab stop: the key the chip names is the keyboard route.
      canRequestFocus: false,
      borderRadius: BorderRadius.circular(18),
      onTap: () => InputMap.dispatch(context, hint.intent),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Button name in a small pill so it reads as a key cap.
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: cs.secondaryContainer,
                borderRadius: BorderRadius.circular(6),
              ),
              child: Text(
                name,
                style: text.labelSmall?.copyWith(
                  color: cs.onSecondaryContainer,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
            const SizedBox(width: 6),
            Text(hint.label, style: text.labelMedium),
          ],
        ),
      ),
    );
  }
}
