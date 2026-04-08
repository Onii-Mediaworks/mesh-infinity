// advanced_warning_dialog.dart
//
// AdvancedWarningDialog — an AlertDialog shown before the user adds a second
// (or further) ZeroTier instance.
//
// WHY WARN?
// ----------
// Running multiple simultaneous ZeroTier clients is an advanced workflow.
// Each instance consumes:
//   • A ZeroTier API key (one per controller account).
//   • A separate VPN tunnel slot on mobile (iOS/Android enforce a single
//     active VPN tunnel; Mesh Infinity shares this slot with the mesh router).
//   • Memory and CPU for the ZeroTier connection loop.
//
// Users who haven't deliberately sought out multi-instance should understand
// what they're enabling.  The dialog is intentionally not a blocker — it
// presents the trade-offs and lets the user confirm or cancel.
//
// DESIGN INTENT
// --------------
// The dialog is self-contained and stateless.  It returns a bool future via
// showDialog so the caller (ZeroNetSetupSheet) can decide what to do:
//   true  → user confirmed, proceed with setup sheet
//   false → user cancelled, do nothing
//
// This widget is written independently of any Tailscale equivalent.
// It imports nothing from the tailscale feature directory.
//
// Spec ref: §5.23 ZeroTier overlay — multi-instance advanced mode.

import 'package:flutter/material.dart';

// ---------------------------------------------------------------------------
// AdvancedWarningDialog
// ---------------------------------------------------------------------------

/// Alert dialog warning the user that adding a second ZeroNet instance is an
/// advanced operation with resource and platform implications.
///
/// Show via [showAdvancedWarningDialog] rather than constructing directly,
/// so the caller always gets a well-typed `Future<bool>`.
class AdvancedWarningDialog extends StatelessWidget {
  /// Number of existing instances already configured.
  ///
  /// Used to tailor the warning message — "a second" vs "another" instance.
  final int existingCount;

  /// Creates an [AdvancedWarningDialog].
  const AdvancedWarningDialog({super.key, required this.existingCount});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Determine the ordinal for the warning copy ("second", "third", etc.)
    // so the message is accurate and not permanently hardcoded as "second".
    final ordinal = _ordinal(existingCount + 1);

    return AlertDialog(
      // Warning icon in amber — signals caution without the severity of red.
      icon: const Icon(
        Icons.warning_amber_rounded,
        // Use a fixed amber instead of theme.tertiary to match the Mesh
        // Infinity secAmber semantic color (F59E0B) for all warning states.
        color: Color(0xFFF59E0B),
        size: 36,
      ),

      title: Text('Adding a $ordinal ZeroNet'),

      content: Column(
        // Shrink the dialog height to fit content — avoids unnecessary
        // empty space when shown on tablets.
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Primary warning paragraph.
          Text(
            'Running multiple ZeroTier instances simultaneously is an advanced '
            'configuration. Please read the notes below before continuing.',
            style: tt.bodyMedium,
          ),
          const SizedBox(height: 16),

          // Bulleted trade-off list — keeps the dialog scannable rather than
          // a wall of text.
          _BulletPoint(
            icon: Icons.smartphone_outlined,
            color: cs.primary,
            text: 'On iOS and Android, all ZeroTier instances share one VPN '
                'tunnel slot with Mesh Infinity\'s mesh router. Performance '
                'may be affected.',
          ),
          const SizedBox(height: 8),

          _BulletPoint(
            icon: Icons.memory_outlined,
            color: cs.primary,
            text: 'Each instance maintains its own connection loop and '
                'consumes additional memory and CPU.',
          ),
          const SizedBox(height: 8),

          _BulletPoint(
            icon: Icons.key_outlined,
            color: cs.primary,
            text: 'Each instance requires a separate API key from its '
                'controller — you cannot reuse the same key across instances.',
          ),
          const SizedBox(height: 8),

          _BulletPoint(
            icon: Icons.route_outlined,
            color: cs.primary,
            text: 'Designate one instance as "Priority" to tell Mesh Infinity '
                'which overlay to prefer for routing decisions.',
          ),
          const SizedBox(height: 16),

          // Reassurance line — the dialog is not blocking, just informing.
          Text(
            'You can remove instances at any time from the ZeroTier hub.',
            style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          ),
        ],
      ),

      actions: [
        // Cancel: do not proceed with adding a new instance.
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),

        // Confirm: user understood the trade-offs, open setup sheet.
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('I understand, continue'),
        ),
      ],
    );
  }

  // ---------------------------------------------------------------------------
  // _ordinal helper
  // ---------------------------------------------------------------------------

  /// Returns the English ordinal string for [n]: "second", "third", etc.
  ///
  /// Hardcodes the first few since they are irregular.  Falls back to
  /// "[n]th" for any value above 10 (practically unreachable for instances).
  static String _ordinal(int n) => switch (n) {
    1 => 'first',
    2 => 'second',
    3 => 'third',
    4 => 'fourth',
    5 => 'fifth',
    _ => '${n}th',
  };
}

// ---------------------------------------------------------------------------
// _BulletPoint (private)
// ---------------------------------------------------------------------------

/// A single bullet-point row used inside [AdvancedWarningDialog].
///
/// Uses an [Icon] instead of a typographic bullet to make each item more
/// scannable and to reinforce the meaning of each trade-off visually.
class _BulletPoint extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String text;

  const _BulletPoint({
    required this.icon,
    required this.color,
    required this.text,
  });

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Icon anchored to the first line of text via CrossAxisAlignment.start.
        Icon(icon, size: 16, color: color),
        const SizedBox(width: 8),
        Expanded(
          child: Text(text, style: tt.bodySmall),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// showAdvancedWarningDialog
// ---------------------------------------------------------------------------

/// Shows the [AdvancedWarningDialog] and returns `true` if the user confirmed,
/// `false` if they cancelled or dismissed.
///
/// Usage:
/// ```dart
/// final confirmed = await showAdvancedWarningDialog(context, existingCount: 1);
/// if (confirmed) { /* proceed */ }
/// ```
Future<bool> showAdvancedWarningDialog(
  BuildContext context, {
  required int existingCount,
}) async {
  // showDialog returns null when the dialog is dismissed by tapping outside.
  // We treat null as cancellation (false) so the caller never gets null.
  final result = await showDialog<bool>(
    context: context,
    // barrierDismissible: true (default) — tapping outside counts as cancel.
    builder: (_) => AdvancedWarningDialog(existingCount: existingCount),
  );
  return result ?? false;
}
