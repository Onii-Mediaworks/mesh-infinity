import 'package:flutter/material.dart';

import '../../../backend/models/peer_models.dart';

/// Three display variants of the trust level badge.
///
/// - compact: true  — 20×20 circle with level number (for list rows)
/// - compact: false, showLabel: false — icon + short label pill (conversation list)
/// - compact: false, showLabel: true  — full pill with level name (detail screen)
class TrustBadge extends StatelessWidget {
  const TrustBadge({
    super.key,
    required this.level,
    this.compact = false,
    this.showLabel = true,
  });

  final TrustLevel level;
  final bool compact;
  final bool showLabel;

  @override
  Widget build(BuildContext context) {
    if (compact) {
      return Semantics(
        label: 'Trust: ${level.label}',
        child: Container(
          width: 20,
          height: 20,
          decoration: BoxDecoration(
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
      // Icon + short label pill — used in conversation list
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

    // Full pill with label — used in peer detail screen
    return Semantics(
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
