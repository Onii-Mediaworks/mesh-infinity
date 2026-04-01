// tap_trigger.dart
//
// TapTrigger — transparent wrapper that fires a callback after N quick taps.
//
// HOW IT WORKS:
// -------------
// Wrap any existing widget with TapTrigger.  The child renders exactly as it
// would without the wrapper — there is no visible change.  When the user taps
// [count] times within [window], [onTriggered] fires.
//
// The tap count resets if [window] elapses between taps, so accidental taps
// during normal use don't creep toward the threshold over time.
//
// USAGE (from catalogue/local_tidbits.dart):
//   TapTrigger(
//     count: 7,
//     onTriggered: () => TidbitRegistry.instance.show('tiny_pong', context),
//     child: myLogoWidget,
//   )
//
// WHY THIS IS THE RIGHT PATTERN:
// -------------------------------
// Using a wrapper widget keeps trigger logic out of the wrapped widget.
// The wrapped widget never needs to know about tidbits.  This means we can
// add tidbits to any existing widget by wrapping it, without modifying it.

import 'package:flutter/material.dart';

// ---------------------------------------------------------------------------
// TapTrigger
// ---------------------------------------------------------------------------

/// Transparent tap-counting wrapper widget (§22.12.1).
///
/// Renders [child] exactly as-is.  Counts rapid taps — once [count] taps
/// occur within [window], fires [onTriggered] and resets the counter.
///
/// Parameters:
///   [count]       — number of taps required (default: 5)
///   [window]      — max time between first and last tap (default: 2s)
///   [onTriggered] — callback fired when the tap threshold is reached
///   [child]       — the widget to wrap
class TapTrigger extends StatefulWidget {
  const TapTrigger({
    super.key,
    required this.child,
    required this.onTriggered,
    this.count = 5,
    this.window = const Duration(seconds: 2),
  });

  // The widget being made tappable.  Rendered unchanged.
  final Widget child;

  // Callback that fires once the threshold is reached.
  final VoidCallback onTriggered;

  // How many taps are needed within [window] to trigger.
  final int count;

  // The time window within which all [count] taps must occur.
  // If more than [window] elapses between the first tap and the most recent
  // tap, the counter resets and the first tap becomes a new starting point.
  final Duration window;

  @override
  State<TapTrigger> createState() => _TapTriggerState();
}

class _TapTriggerState extends State<TapTrigger> {
  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  // Running count of taps since the window started.
  int _tapCount = 0;

  // The timestamp of the first tap in the current window.
  // null means no window is open (counter is at zero).
  DateTime? _windowStart;

  // ---------------------------------------------------------------------------
  // Tap handling
  // ---------------------------------------------------------------------------

  void _onTap() {
    final now = DateTime.now();

    // If there's an open window and it has expired, reset the counter.
    // The current tap becomes the new window start.
    if (_windowStart != null &&
        now.difference(_windowStart!) > widget.window) {
      _tapCount = 0;
      _windowStart = null;
    }

    // Record the window start on the first tap.
    _windowStart ??= now;

    // Increment the tap counter.
    _tapCount++;

    // Check whether we've hit the threshold.
    if (_tapCount >= widget.count) {
      // Reset before firing so that a second trigger can start fresh.
      _tapCount = 0;
      _windowStart = null;
      widget.onTriggered();
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // GestureDetector with behavior=opaque ensures we capture all taps on
    // the child area, even if the child has no inherent tap feedback.
    // The child is rendered completely unchanged.
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: _onTap,
      child: widget.child,
    );
  }
}
