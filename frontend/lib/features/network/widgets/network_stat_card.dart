import 'package:flutter/material.dart';

/// NetworkStatCard — a compact "icon + big number + label" metric tile.
///
/// Used in the statistics grid on NetworkScreen and MetricsScreen to display
/// a single counter (e.g. "Active Connections: 4") in a scannable card format.
///
/// The icon provides quick visual identification; the large bold [value]
/// is the primary content; the smaller [label] names the metric.
///
/// Sizing: the card fills whatever width its parent assigns (typically a
/// GridView cell).  `mainAxisSize: MainAxisSize.min` lets the column shrink-
/// wrap its height so the card does not waste space in shorter grid rows.
class NetworkStatCard extends StatelessWidget {
  const NetworkStatCard({
    super.key,
    required this.label,
    required this.value,
    this.icon,
  });

  /// Short human-readable name for the metric, e.g. "Active Connections".
  final String label;

  /// Pre-formatted string value to display prominently, e.g. "4" or "1.2 MB".
  /// Callers are responsible for formatting — this widget does not transform
  /// raw numbers.
  final String value;

  /// Optional icon shown above the value.  When null the icon row is omitted
  /// entirely so cards without icons don't have an empty gap at the top.
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Icon row — only rendered when an icon was provided.
            if (icon != null) ...[
              Icon(icon, size: 24, color: cs.primary),
              const SizedBox(height: 8),
            ],
            // Large bold value — the number the user is scanning for.
            Text(
              value,
              style: Theme.of(context).textTheme.titleLarge?.copyWith(
                color: cs.primary,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 4),
            // Small label below the value — centred to match the value.
            Text(
              label,
              style: Theme.of(context).textTheme.labelSmall?.copyWith(
                color: cs.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
