import 'package:flutter/material.dart';

import '../../../backend/models/peer_models.dart';

/// A visual badge that communicates a peer's trust level at a glance.
///
/// Trust levels (0–8) are defined in the spec (§9) and stored in [TrustLevel].
/// Each level has a distinct colour, icon, short label, and full label — see
/// [TrustLevel] in peer_models.dart for the mapping.
///
/// Three display variants are available, selected by [compact] and [showLabel]:
///
/// | compact | showLabel | Use case                                        |
/// |---------|-----------|--------------------------------------------------|
/// | true    | (any)     | 20×20 circle with level number — list rows       |
/// | false   | false     | Icon + short label pill — conversation list      |
/// | false   | true      | Icon + full label pill — peer detail screen      |
///
/// All three variants wrap their content in a [Semantics] node so screen
/// readers announce the trust level to users who rely on assistive technology.
///
/// Colours use [withValues(alpha: …)] (not [withOpacity]) to produce a tinted
/// background without fully saturating the surface — this ensures legibility
/// in both light and dark modes regardless of the level colour.
class TrustBadge extends StatelessWidget {
  const TrustBadge({
    super.key,
    required this.level,
    this.compact = false,
    this.showLabel = true,
  });

  /// The trust level to display (0 = Unknown … 8 = Fully trusted).
  final TrustLevel level;

  /// When true, renders a small 20×20 circle showing the numeric level value.
  /// Intended for use in list rows where horizontal space is limited.
  final bool compact;

  /// When [compact] is false, controls whether the full label or the short
  /// label is shown next to the trust icon.
  /// - true  (default): full label, e.g. "Trusted" — used in detail screens.
  /// - false: short label, e.g. "T3" — used in compact conversation rows.
  final bool showLabel;

  @override
  Widget build(BuildContext context) {
    if (compact) {
      // Compact variant: a small bordered circle containing the numeric level.
      // The circle background is a 15%-opacity tint of the level colour, and
      // the border is the full level colour — this makes the badge readable
      // without dominating the row it appears in.
      return Semantics(
        // Screen readers announce "Trust: Trusted" rather than just "3",
        // giving assistive technology users the same semantic information as
        // sighted users reading the full label elsewhere.
        label: 'Trust: ${level.label}',
        child: Container(
          width: 20,
          height: 20,
          decoration: BoxDecoration(
            // 15% opacity tint — visible but not distracting in a list row.
            color: level.color.withValues(alpha: 0.15),
            border: Border.all(color: level.color, width: 1.5),
            shape: BoxShape.circle,
          ),
          child: Center(
            child: Text(
              '${level.value}',
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.w700,
                color: level.color,
              ),
            ),
          ),
        ),
      );
    }

    if (!showLabel) {
      // Icon + short label pill — used in conversation list rows where the
      // full label would take up too much horizontal space.
      // The pill uses a 12% opacity background and a 40% opacity border so
      // it reads as a secondary element behind the room name and message preview.
      return Semantics(
        label: 'Trust: ${level.label}',
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
          decoration: BoxDecoration(
            color: level.color.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: level.color.withValues(alpha: 0.4)),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(level.icon, size: 12, color: level.color),
              const SizedBox(width: 3),
              Text(
                level.shortLabel,
                style: TextStyle(
                  fontSize: 11,
                  color: level.color,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
      );
    }

    // Full label pill — used in the peer detail screen where there is
    // enough room to show the complete trust level name (e.g. "Trusted").
    // Slightly larger padding and icon than the short-label variant to match
    // the detail screen's visual hierarchy.
    return Semantics(
      // Screen reader announcement uses the more specific "Trust level: …"
      // phrasing rather than just "Trust: …" to distinguish it from the
      // compact variant's announcement.
      label: 'Trust level: ${level.label}',
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: level.color.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: level.color.withValues(alpha: 0.4)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            // 14px icon — slightly larger than the short-label variant (12px)
            // to match the detail screen's label text size.
            Icon(level.icon, size: 14, color: level.color),
            const SizedBox(width: 4),
            Text(
              level.label,
              style: TextStyle(
                fontSize: 12,
                color: level.color,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
