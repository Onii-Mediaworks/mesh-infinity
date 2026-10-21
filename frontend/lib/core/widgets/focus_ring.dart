// focus_ring.dart
//
// FocusRing — the one focus idiom for keyboard and controller users
// (§22.36 rule 3).
//
// HOW IT WORKS
// ------------
// The wrapper inserts a non-focusable Focus node *above* the control.  A
// Focus node's `hasFocus` is true whenever it or any descendant holds the
// primary focus, so the ring reacts to the child's own focus node (a
// ListTile's InkWell, a button, a text field) without the child knowing.
// The wrapper adds no Tab stop: canRequestFocus is false and traversal
// skips it.
//
// WHEN IT IS DRAWN
// ----------------
// Only when both hold:
//   * FocusManager.highlightMode is `traditional` — Flutter's own signal
//     that the last interaction was not a touch; and
//   * ShellState.last_input is not `pointer` — so a mouse click on desktop
//     (which keeps traditional mode) does not light a ring either.
// After a tap, Flutter flips to `touch` mode and the ring disappears, which
// is the "not after a tap" clause of rule 3.
//
// GEOMETRY
// --------
// 2 dp outside the control's bounds, with the control's own radius enlarged
// by the same 2 dp so the ring stays concentric.  Drawn with
// MeshColors.focus_ring, which the theme contrast test holds to ≥3:1 on
// every ground.  Stack(clipBehavior: none) lets the ring overflow the
// control's box.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../app/app_theme.dart';
import '../../shell/shell_state.dart';

/// Draws the shell focus ring around [child] while a descendant has focus.
class FocusRing extends StatefulWidget {
  const FocusRing({super.key, required this.child, this.radius = 0});

  /// The focusable control (or a subtree containing exactly one).
  final Widget child;

  /// The child's corner radius; the ring uses radius + [ring_gap].
  final double radius;

  /// Distance between the control's edge and the ring, in dp (rule 3).
  ///
  /// `static final` keeps the project's snake_case naming without a lint
  /// carve-out; the values never change at runtime.
  static final double ring_gap = 2;

  /// Stroke width of the ring, in dp.
  static final double ring_width = 2;

  @override
  State<FocusRing> createState() => _FocusRingState();
}

class _FocusRingState extends State<FocusRing> {
  /// Whether the child subtree currently holds focus.
  bool _focused = false;

  /// Cached highlight mode; refreshed by the FocusManager listener.
  FocusHighlightMode _mode = FocusManager.instance.highlightMode;

  @override
  void initState() {
    super.initState();
    FocusManager.instance.addHighlightModeListener(_on_mode);
  }

  @override
  void dispose() {
    FocusManager.instance.removeHighlightModeListener(_on_mode);
    super.dispose();
  }

  /// Flutter flips the mode on touch (hide) and key (show) events.
  void _on_mode(FocusHighlightMode mode) {
    if (mounted) setState(() => _mode = mode);
  }

  @override
  Widget build(BuildContext context) {
    final shell = context.read<ShellState>();
    return Focus(
      canRequestFocus: false,
      skipTraversal: true,
      includeSemantics: false,
      onFocusChange: (focused) => setState(() => _focused = focused),
      child: ValueListenableBuilder<InputSource>(
        valueListenable: shell.last_input,
        child: widget.child,
        builder: (context, source, child) {
          final show =
              _focused &&
              _mode == FocusHighlightMode.traditional &&
              source != InputSource.pointer;
          // The child is always the Stack's first element, whether or not
          // the ring is drawn.  Moving it in and out of a Stack would
          // recreate its subtree — and with it the focus node that just
          // received focus — the moment the ring appeared.
          return Stack(
            clipBehavior: Clip.none,
            children: [
              child!,
              // Positioned with negative insets so the ring sits outside the
              // control's bounds; IgnorePointer keeps taps reaching the child.
              if (show)
                Positioned(
                  left: -FocusRing.ring_gap,
                  top: -FocusRing.ring_gap,
                  right: -FocusRing.ring_gap,
                  bottom: -FocusRing.ring_gap,
                  child: IgnorePointer(
                    child: DecoratedBox(
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(
                          widget.radius + FocusRing.ring_gap,
                        ),
                        border: Border.all(
                          color: MeshColors.of(context).focus_ring,
                          width: FocusRing.ring_width,
                        ),
                      ),
                    ),
                  ),
                ),
            ],
          );
        },
      ),
    );
  }
}
