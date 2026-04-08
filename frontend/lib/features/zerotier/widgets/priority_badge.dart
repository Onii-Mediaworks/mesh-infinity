// priority_badge.dart
//
// PriorityBadge — a compact inline badge marking a ZeroNet instance as the
// designated priority instance in the multi-zeronet hub.
//
// WHAT IS THE PRIORITY INSTANCE?
// --------------------------------
// When Mesh Infinity manages multiple ZeroTier instances simultaneously,
// exactly one is the "priority" instance.  The priority instance's routing
// table takes precedence when two active instances both advertise a route to
// the same destination IP prefix.  Only one instance can hold priority at a
// time; it is set via ZeroTierState.setPriority() and persisted by the backend.
//
// WHY A BADGE?
// ------------
// The badge gives users an at-a-glance signal about which ZeroNet "wins"
// routing disputes without requiring them to open the detail screen.  It
// follows the same visual pattern as Trust badges and Tier badges elsewhere
// in the app — a small, opinionated chip placed next to the item label.
//
// SELF-CONTAINED DESIGN
// ----------------------
// This widget is intentionally written independently of the Tailscale
// equivalent in features/tailscale/widgets/priority_badge.dart.  The two
// are similar but may diverge in the future (different icon, label copy, or
// theming decisions for each overlay type).  Importing from the tailscale
// directory would couple unrelated features together.
//
// COMPACT MODE
// ------------
// The badge has two sizes:
//   Default (compact: false) — star icon + "Priority" label text.
//     Used in contexts where there is enough horizontal space.
//   Compact (compact: true) — star icon only, no text.
//     Used inside ListTile trailing areas where horizontal space is limited.
//
// DESIGN
// ------
// - Star icon (Icons.star) is universally understood to mean "preferred" or
//   "primary" — no localisation needed.
// - Uses the theme's primary colour family so it adapts to light/dark mode
//   and any future re-theming without hardcoded colour constants.
// - 22 px max height keeps it compact enough for a dense ListTile row without
//   pushing the tile above the standard 56 px height.
//
// Spec ref: §5.23 ZeroTier overlay — multi-instance priority routing.

import 'package:flutter/material.dart';
// Material widgets: Container, Row, Icon, Text, Theme, BoxDecoration, Border.

// ---------------------------------------------------------------------------
// PriorityBadge
// ---------------------------------------------------------------------------

/// A compact badge indicating that the associated ZeroNet instance has been
/// designated as the routing-priority instance.
///
/// Used in [ZeroNetListTile] trailing areas when [isPriority] is true, and
/// potentially in the [ZeroTierHubScreen] header when multiple instances are
/// active.
///
/// Example usage:
/// ```dart
/// if (isPriority) const PriorityBadge(),             // full label
/// if (isPriority) const PriorityBadge(compact: true), // icon only
/// ```
///
/// Spec ref: §5.23 ZeroTier overlay — priority instance indicator.
class PriorityBadge extends StatelessWidget {
  /// Creates a [PriorityBadge].
  ///
  /// [compact] — when true, only the star icon is shown without the "Priority"
  ///   label text.  Use compact mode when horizontal space is tight, e.g.
  ///   inside a ListTile trailing area that already has a PopupMenuButton.
  const PriorityBadge({super.key, this.compact = false});

  /// When true, renders only the star icon without the "Priority" text label.
  ///
  /// Defaults to false (full label + icon shown).
  final bool compact;

  @override
  Widget build(BuildContext context) {
    // Resolve the colour scheme from the app theme — keeps the badge
    // consistent with the rest of the UI in both light and dark mode.
    final cs = Theme.of(context).colorScheme;

    // The badge is a pill-shaped container using the primary container colour
    // (a muted tint of the brand colour) so it is visually distinct but not
    // loud enough to dominate the list tile row it lives in.
    return Container(
      // Constrain height so the badge never stretches a ListTile taller than
      // the standard 56 px density.  Width is intrinsic (wraps content).
      constraints: const BoxConstraints(maxHeight: 22),
      padding: EdgeInsets.symmetric(
        // Slightly more horizontal padding when the text label is also shown
        // because text + icon together need more breathing room.
        horizontal: compact ? 5 : 8,
        vertical: 2,
      ),
      decoration: BoxDecoration(
        // primaryContainer gives a soft, on-brand tint that is legible
        // against both light and dark scaffold backgrounds without a hardcoded
        // colour constant (adapts to theme changes automatically).
        color: cs.primaryContainer,
        // borderRadius: 99 — a large value guarantees fully rounded "pill"
        // ends regardless of the actual badge width.
        borderRadius: BorderRadius.circular(99),
        // A fine border ensures the badge boundary is visible against both
        // light and dark surface colours, even when contrast is low.
        border: Border.all(
          color: cs.primary.withValues(alpha: 0.35),
          width: 0.75,
        ),
      ),
      child: Row(
        // mainAxisSize.min shrink-wraps the row to its content so the
        // Container does not expand to fill its parent's width.
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            // Solid star = "this one is the favourite/priority".
            Icons.star,
            // 12 px keeps the star icon compact inside the 22 px tall badge.
            size: 12,
            color: cs.primary,
          ),

          // In non-compact mode, show the "Priority" text label next to the
          // star.  The text is hidden in compact mode to save horizontal space.
          if (!compact) ...[
            const SizedBox(width: 3),
            Text(
              'Priority',
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.w600,
                // onPrimaryContainer is the correct accessible foreground
                // colour for text drawn on top of primaryContainer.
                color: cs.onPrimaryContainer,
                // Slightly tighter letter-spacing reduces the visual width
                // of the label without sacrificing legibility at 10 px.
                letterSpacing: 0.2,
              ),
            ),
          ],
        ],
      ),
    );
  }
}
