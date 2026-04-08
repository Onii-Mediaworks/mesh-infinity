import 'package:flutter/material.dart';

/// A reusable centred placeholder shown when a list or screen has no content.
///
/// Every major list screen (contacts, rooms, files, etc.) uses this widget
/// instead of writing ad-hoc empty-state layouts, which keeps the visual
/// language consistent across the app.
///
/// Two modes are available:
///
/// - **Normal mode** (`compact: false`, the default): shows icon (64px),
///   [title], [body] text, and an optional [action] button.  Use this as the
///   primary full-screen empty state.
///
/// - **Compact mode** (`compact: true`): shows a smaller icon (40px) and only
///   the [title].  The [body] and [action] are hidden.  Use this when the
///   widget must fit inside a card or a small section of a larger screen where
///   the full layout would look cramped.
class EmptyState extends StatelessWidget {
  const EmptyState({
    super.key,
    required this.icon,
    required this.title,
    required this.body,
    this.action,
    this.compact = false,
  });

  /// The illustrative icon shown above the title.
  /// Choose a contextually appropriate icon (e.g. [Icons.people_outline] for
  /// an empty contacts list).
  final IconData icon;

  /// Short headline text, e.g. "No contacts yet".
  final String title;

  /// Longer explanatory text shown below the title in normal mode.
  /// Hidden in compact mode to save space.
  final String body;

  /// Optional call-to-action widget (typically a [FilledButton.tonal]).
  /// Shown below the body in normal mode; hidden in compact mode.
  /// Null means no action is available (read-only empty state).
  final Widget? action;

  /// When true, reduces icon size and suppresses [body] and [action] text.
  /// Use compact mode when embedding this widget inside a list card or a
  /// small container where the full layout does not fit.
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        // Horizontal padding prevents text running to the screen edges on
        // narrow devices.
        padding: const EdgeInsets.symmetric(horizontal: 32),
        child: Column(
          // MainAxisSize.min lets the column shrink to its content height,
          // which allows Center to vertically centre the group properly.
          mainAxisSize: MainAxisSize.min,
          children: [
            // Icon size differs by mode: large (64px) grabs attention in
            // full-screen empty states; small (40px) stays unobtrusive when
            // embedded in a compact context.
            // outline colour keeps the icon subdued — this is a secondary
            // visual element, not a focal point.
            Icon(icon, size: compact ? 40 : 64, color: colorScheme.outline),
            SizedBox(height: compact ? 8 : 16),
            Text(title, style: Theme.of(context).textTheme.titleMedium),

            // Body text and action are only rendered in normal mode.
            // The spread operator (...) conditionally inserts zero or more
            // widgets into the children list — cleaner than using `if` on
            // individual widgets.
            if (!compact) ...[
              const SizedBox(height: 8),
              Text(
                body,
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  // onSurfaceVariant is slightly de-emphasised relative to
                  // onSurface, signalling that this is secondary text.
                  color: colorScheme.onSurfaceVariant,
                ),
                textAlign: TextAlign.center,
              ),
            ],

            // Action widget (e.g. a "Create room" button) is rendered only
            // when provided and only in normal mode.
            if (action != null) ...[const SizedBox(height: 24), action!],
          ],
        ),
      ),
    );
  }
}
