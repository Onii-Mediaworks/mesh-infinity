// garden_gnome.dart
//
// GardenGnomeWidget — a rare gnome that appears in empty Garden states (§22.12.5 #20).
//
// WHAT IT DOES:
// -------------
// When the Garden Explore or Feed screen shows an empty state, there is a
// ~1-in-5 chance (based on the day-of-year so it persists through the day
// without random flicker) that a small gnome text-art appears below the
// normal empty-state copy.  Tapping the gnome shows a random quip in a
// bottom sheet.
//
// WHY THIS DESIGN:
// ----------------
// - Day-seed means the gnome shows up consistently for a day, then disappears.
//   This makes it feel like a "today you're lucky" event rather than random UI jitter.
// - The gnome is below the normal empty state, so it never obscures or replaces
//   the real UI — it's strictly additive.
// - The quips are gentle and thematic (mesh / garden / outdoors).  They don't
//   reference anything external or make promises the app can't keep.

import 'package:flutter/material.dart';

// ---------------------------------------------------------------------------
// GardenGnomeWidget
// ---------------------------------------------------------------------------

/// Conditionally renders a rare gnome easter egg below empty Garden states.
///
/// Wrap the widget inside any empty-state layout.  It is self-contained:
/// it decides whether to show based on the current date and renders nothing
/// if the day's seed does not match.
class GardenGnomeWidget extends StatelessWidget {
  const GardenGnomeWidget({super.key});

  // ---------------------------------------------------------------------------
  // Appearance probability
  // ---------------------------------------------------------------------------

  // 1-in-5 days show the gnome.  We use day-of-year as a seed so the gnome
  // is either visible or not for the entire day — never randomly flickers.
  static bool _shouldShow() {
    final doy = _dayOfYear(DateTime.now());
    // Simple modulo: every 5th day-of-year shows the gnome.
    return doy % 5 == 0;
  }

  // Compute day-of-year (1–366) for [date].
  static int _dayOfYear(DateTime date) {
    final start = DateTime(date.year, 1, 1);
    return date.difference(start).inDays + 1;
  }

  // ---------------------------------------------------------------------------
  // Quip list
  // ---------------------------------------------------------------------------

  // The quips are selected pseudo-randomly based on week-of-year so that a
  // single user doesn't see the same quip on consecutive gnome days.
  static const List<String> _quips = [
    "\"I've been tending this mesh since before you had a peer ID.\"",
    '"The best route is the one nobody knows about."',
    "\"I once relayed a message 47 hops. I don't talk about it.\"",
    '"Gardens grow better without servers, you know."',
    "\"Every empty garden is just a full garden that hasn't arrived yet.\"",
    '"I read your key exchange. Beautiful work. Genuinely."',
    '"The gnomes of the mesh ask only for latency under 200ms."',
    "\"I've been offline for six days. It was wonderful.\"",
    "\"Some say I'm an easter egg. I prefer 'senior network analyst'.\"",
    '"Between you and me? The WireGuard handshake is my favourite part."',
    '"I guard this garden. Mostly by standing here."',
    '"No servers were harmed in the making of this message."',
    '"The mesh remembers. I make sure of it."',
    '"Did you know gnomes invented peer-to-peer? True story."',
    '"I have a trust level of 8. I earned every bit of it."',
  ];

  static String _quip() {
    final weekOfYear = _dayOfYear(DateTime.now()) ~/ 7;
    return _quips[weekOfYear % _quips.length];
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // Self-deactivate when today is not a gnome day.
    if (!_shouldShow()) return const SizedBox.shrink();

    final cs = Theme.of(context).colorScheme;

    return Padding(
      padding: const EdgeInsets.only(top: 24),
      child: GestureDetector(
        onTap: () => _showQuip(context),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // ASCII-art gnome rendered in a monospace font.
            // Kept intentionally small (fits in ~8 characters wide) so it
            // doesn't visually compete with the real empty-state content.
            Text(
              '(• ◡ •)\n  /|\\',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 18,
                color: cs.onSurface.withValues(alpha: 0.25),
                height: 1.3,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              'tap the gnome',
              style: TextStyle(
                fontSize: 10,
                color: cs.onSurface.withValues(alpha: 0.18),
                letterSpacing: 0.5,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Quip bottom sheet
  // ---------------------------------------------------------------------------

  void _showQuip(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (_) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 8, 24, 40),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Big gnome art in the sheet.
            Text(
              '(• ◡ •)\n  /|\\',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 32,
                color: cs.onSurface.withValues(alpha: 0.7),
                height: 1.3,
              ),
            ),
            const SizedBox(height: 20),
            Text(
              _quip(),
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    fontStyle: FontStyle.italic,
                    color: cs.onSurfaceVariant,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              '— The Garden Gnome',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: cs.outline,
                  ),
            ),
          ],
        ),
      ),
    );
  }
}
