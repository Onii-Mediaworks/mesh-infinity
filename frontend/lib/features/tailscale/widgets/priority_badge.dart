// priority_badge.dart
//
// PriorityBadge — a compact inline badge marking an overlay instance as the
// designated priority instance in the multi-tailnet hub.
//
// WHAT IS THE PRIORITY INSTANCE?
// --------------------------------
// When Mesh Infinity manages multiple Tailscale instances simultaneously,
// exactly one is the "priority" instance.  The priority instance's routing
// table takes precedence when two active instances both advertise a route to
// the same destination IP prefix, and its exit-node selection wins any
// conflict.
//
// WHY A BADGE?
// ------------
// The badge gives users an at-a-glance signal about which tailnet "wins"
// routing disputes without requiring them to open the detail screen.  It
// follows the same pattern as Trust badges and Tier badges elsewhere in the
// app — a small, opinionated chip placed next to the item label.
//
// COMPACT MODE
// ------------
// The badge has two sizes:
//   Default (compact: false) — star icon + "Priority" label text.
//     Used in the hub screen header and in wider contexts.
//   Compact (compact: true) — star icon only, no text.
//     Used inside ListTile trailing areas where horizontal space is tight.
//
// DESIGN
// ------
// - Star icon (Icons.star) is universally understood to mean "preferred" or
//   "primary" — no localisation needed.
// - Uses the theme's primary colour family so it adapts to light/dark mode
//   and any future re-theming without hardcoded colour constants.
// - 22 px max height keeps it compact enough for a dense ListTile row.

import 'package:flutter/material.dart';
// Material widgets: Container, Row, Icon, Text, Theme.

// ---------------------------------------------------------------------------
// PriorityBadge
// ---------------------------------------------------------------------------

/// A compact badge indicating that the associated tailnet instance has been
/// designated as the routing-priority instance.
///
/// Used in [TailnetListTile] trailing areas and the [TailscaleHubScreen]
/// header when more than one instance is active.
///
/// Example usage:
/// ```dart
/// if (isPriority) const PriorityBadge(),            // full label
/// if (isPriority) const PriorityBadge(compact: true), // icon only
/// ```
class PriorityBadge extends StatelessWidget {
  /// Creates a [PriorityBadge].
  ///
  /// [compact] — when true, only the star icon is shown without the "Priority"
  ///   label text.  Use compact mode when horizontal space is tight (e.g.
  ///   inside a ListTile trailing area that already has a PopupMenuButton).
  const PriorityBadge({super.key, this.compact = false});

  /// When true, renders only the star icon without the "Priority" text label.
  ///
  /// Defaults to false (full label shown).
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // The badge is a pill-shaped container using the primary container colour
    // (a muted tint of the brand colour) so it is visually distinct but not
    // so loud that it dominates the row.
    return Container(
      // Constrain height so the badge never stretches a ListTile taller than
      // the standard 56 px density.  Width is intrinsic (wraps content).
      constraints: const BoxConstraints(maxHeight: 22),
      padding: EdgeInsets.symmetric(
        // Slightly more horizontal padding when the text label is also shown.
        horizontal: compact ? 5 : 8,
        vertical: 2,
      ),
      decoration: BoxDecoration(
        // primaryContainer gives a soft, on-brand tint that is legible against
        // both light and dark scaffold backgrounds without a hardcoded colour.
        color: cs.primaryContainer,
        borderRadius: BorderRadius.circular(99),
        // A fine border ensures the badge boundary is visible against both
        // light and dark surface colours, even when contrast is low.
        border: Border.all(
          color: cs.primary.withValues(alpha: 0.35),
          width: 0.75,
        ),
      ),
      child: Row(
        // shrink-wrap so the Container tightly wraps the content.
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.star,
            // 12 px keeps the star icon compact inside the 22 px tall badge.
            size: 12,
            color: cs.primary,
          ),
          // Text label is hidden in compact mode.
          if (!compact) ...[
            const SizedBox(width: 3),
            Text(
              'Priority',
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.w600,
                color: cs.onPrimaryContainer,
                // Tighter letter-spacing reduces the visual width of the label.
                letterSpacing: 0.2,
              ),
            ),
          ],
        ],
      ),
    );
  }
}
