// focusable_tile.dart
//
// FocusableTile — gives a list row or bubble its focus ring and its button
// routes for the §22.35 gestures (§22.36 rules 3 and 4).
//
// WHAT A SCREEN GETS BY WRAPPING A TILE
// -------------------------------------
//   * The shell focus ring (FocusRing) when the row is focused by key/pad.
//   * ContextMenuIntent  → `on_context_menu`: the same sheet the row shows on
//     long press, now reachable from Shift+F10 / Menu / X.
//   * SecondaryActionIntent → `on_secondary`: the row's screen-declared
//     secondary action (reply, mark as read…), reachable from Y.
//   * Optionally its own focus node (`owns_focus`) for children that are
//     not focusable on their own, such as a GestureDetector bubble.  Then
//     ActivateIntent → `on_activate` as well.
//
// The Actions widget sits above the row, so the intent lookup that starts at
// the focused InkWell finds these handlers before the shell-level ones.
// Touch behaviour is untouched: the row's own onTap / onLongPress remain.

import 'package:flutter/material.dart';

import '../../shell/input_map.dart';
import 'focus_ring.dart';

/// Focus ring plus intent routes for one list row, bubble or card.
class FocusableTile extends StatelessWidget {
  const FocusableTile({
    super.key,
    required this.child,
    this.radius = 0,
    this.owns_focus = false,
    this.on_context_menu,
    this.on_secondary,
    this.on_activate,
  });

  /// The row.  Must contain exactly one focusable control unless
  /// [owns_focus] is true, in which case it may contain none.
  final Widget child;

  /// Corner radius of [child], forwarded to the ring.
  final double radius;

  /// Wrap [child] in a focus node of its own.  Use for non-focusable
  /// children (a bubble built from GestureDetector); never for a ListTile
  /// or button, which would otherwise produce two Tab stops.
  final bool owns_focus;

  /// Opens the row's long-press sheet (ContextMenuIntent).
  final VoidCallback? on_context_menu;

  /// The row's secondary action (SecondaryActionIntent).
  final VoidCallback? on_secondary;

  /// Activation of an [owns_focus] child (ActivateIntent).  Ignored for
  /// children with their own node, whose own activate action is nearer.
  final VoidCallback? on_activate;

  @override
  Widget build(BuildContext context) {
    // Only register handlers that exist: an absent entry lets the intent
    // bubble up and, for keys, report "ignored" so nothing is swallowed.
    final actions = <Type, Action<Intent>>{
      if (on_context_menu != null)
        ContextMenuIntent: CallbackAction<ContextMenuIntent>(
          onInvoke: (_) {
            on_context_menu!();
            return null;
          },
        ),
      if (on_secondary != null)
        SecondaryActionIntent: CallbackAction<SecondaryActionIntent>(
          onInvoke: (_) {
            on_secondary!();
            return null;
          },
        ),
      if (owns_focus && on_activate != null)
        ActivateIntent: CallbackAction<ActivateIntent>(
          onInvoke: (_) {
            on_activate!();
            return null;
          },
        ),
    };

    // owns_focus: the Focus node makes the subtree a traversal stop and the
    // ring's trigger; its semantics flag tells screen readers it is focusable.
    final body = owns_focus ? Focus(child: child) : child;

    return Actions(
      actions: actions,
      child: FocusRing(radius: radius, child: body),
    );
  }
}
