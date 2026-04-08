// advanced_warning_dialog.dart
//
// AdvancedWarningDialog — an AlertDialog shown before the user adds a second
// (or subsequent) tailnet instance to their Mesh Infinity node.
//
// WHY WARN AT ALL?
// ----------------
// Running multiple Tailscale instances simultaneously on a single device is
// an advanced configuration with real operational risks:
//
//   1. ROUTING CONFLICTS — two instances can both advertise routes to
//      overlapping IP prefixes (e.g. both tailtets include a 10.x.x.x
//      subnet).  Without a clear priority setting, the OS will use whichever
//      route was installed last, which may not be what the user wants.
//
//   2. EXIT NODE AMBIGUITY — if both instances have an active exit node, only
//      one can actually route internet-destined traffic out.  The user must
//      designate a priority instance to make this deterministic.
//
//   3. BATTERY / PERFORMANCE — each WireGuard instance has its own keepalive
//      loop and control-plane polling.  On mobile, two active instances
//      consume roughly twice the background network and CPU of one.
//
//   4. FIREWALL COMPLEXITY — corporate MDM policies or device firewalls may
//      not permit multiple simultaneous VPN tunnels, causing the second
//      instance to silently fail or the VPN slot to be stolen.
//
// We do NOT block the user — they may have a legitimate reason (e.g. a
// DevOps engineer who needs their Work tailnet and a personal Home tailnet
// active at the same time).  We just require informed consent.
//
// RETURN VALUE
// ------------
// showAdvancedWarningDialog() returns a Future<bool?> from showDialog():
//   true  — user confirmed ("I understand, add anyway")
//   false / null — user cancelled or dismissed
//
// The caller (TailnetSetupSheet) awaits the future before proceeding.

import 'package:flutter/material.dart';
// AlertDialog, TextButton, showDialog.

// ---------------------------------------------------------------------------
// showAdvancedWarningDialog — convenience function
// ---------------------------------------------------------------------------

/// Show the advanced multi-tailnet warning dialog and return whether the user
/// confirmed.
///
/// Returns `true` if the user tapped "I understand, add anyway", or `false`
/// (or null) if they cancelled or dismissed the dialog.
///
/// [context] — must be the BuildContext of an ancestor widget with a
///   Navigator (i.e. anywhere inside a MaterialApp scaffold).
///
/// Spec reference: §5.22 (multi-instance configuration safeguards)
Future<bool> showAdvancedWarningDialog(BuildContext context) async {
  // showDialog returns T? — the value passed to Navigator.pop().
  // We default to false if the user dismisses without tapping a button
  // (e.g. taps outside the dialog or presses the back button).
  final confirmed = await showDialog<bool>(
    context: context,
    // barrierDismissible: true allows the user to tap outside to cancel.
    // This is correct here — we want the escape hatch to be accessible.
    barrierDismissible: true,
    builder: (ctx) => const _AdvancedWarningDialog(),
  );
  // Coerce null (barrier dismiss) to false.
  return confirmed == true;
}

// ---------------------------------------------------------------------------
// _AdvancedWarningDialog — internal StatelessWidget
// ---------------------------------------------------------------------------

/// Internal widget that renders the alert dialog content.
///
/// This is private (_) because consumers should use [showAdvancedWarningDialog]
/// rather than pushing the dialog directly — the convenience function handles
/// the null-coercion and result type uniformly.
class _AdvancedWarningDialog extends StatelessWidget {
  const _AdvancedWarningDialog();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return AlertDialog(
      // The icon sits above the title — a warning icon immediately communicates
      // the intent of this dialog before the user reads any text.
      icon: Icon(
        Icons.warning_amber_rounded,
        size: 40,
        // Use the tertiary colour (warm amber-adjacent in Material3 palettes)
        // to distinguish this "caution" icon from error red.
        color: cs.tertiary,
      ),

      title: const Text('Advanced feature — multiple tailnets'),

      // The content describes the risks in plain language.  We aim for
      // comprehension by a technically literate but non-expert user — someone
      // who knows what a VPN is but may not be a network engineer.
      content: Column(
        // Column is mainAxisSize.min so the dialog height wraps the content
        // rather than expanding to fill the screen.
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Running multiple tailnets simultaneously on one device is an '
            'advanced configuration. Before continuing, please be aware of '
            'the following:',
            style: tt.bodyMedium,
          ),
          const SizedBox(height: 16),

          // Bullet list of risks.  Each item uses a leading dot and wraps
          // naturally — no fixed-width columns needed.
          _BulletItem(
            icon: Icons.alt_route_outlined,
            iconColor: cs.tertiary,
            text: 'Routing conflicts: overlapping IP prefixes between tailnets '
                'may cause unexpected traffic routing. Set a priority tailnet '
                'to resolve conflicts.',
          ),
          const SizedBox(height: 10),

          _BulletItem(
            icon: Icons.exit_to_app_outlined,
            iconColor: cs.tertiary,
            text: 'Exit node ambiguity: only one tailnet\'s exit node can be '
                'active at a time. The priority instance wins.',
          ),
          const SizedBox(height: 10),

          _BulletItem(
            icon: Icons.battery_alert_outlined,
            iconColor: cs.tertiary,
            text: 'Battery and performance: each active instance maintains its '
                'own WireGuard tunnel and control-plane connection.',
          ),
          const SizedBox(height: 10),

          _BulletItem(
            icon: Icons.star_outline,
            iconColor: cs.primary,
            text: 'After adding, set a priority tailnet in the hub to ensure '
                'deterministic routing.',
          ),
        ],
      ),

      // Actions: Cancel (left/secondary) and confirm (right/primary).
      // The confirm button is NOT destructive-red — adding a tailnet is not
      // destructive.  It is a tonal filled button to indicate "proceed with
      // awareness" rather than a plain TextButton.
      actions: [
        // Cancel — closes dialog, returns false.
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),

        // Confirm — closes dialog, returns true.
        FilledButton.tonal(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('I understand, add anyway'),
        ),
      ],

      // Align actions to the right (default) and add some padding so the
      // buttons don't crowd the content.
      actionsPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
    );
  }
}

// ---------------------------------------------------------------------------
// _BulletItem — private helper widget
// ---------------------------------------------------------------------------

/// A single bullet-point row with an icon and a text description.
///
/// Used inside [_AdvancedWarningDialog] to list the risks of running multiple
/// tailnet instances.  Kept private because it is specific to this dialog.
class _BulletItem extends StatelessWidget {
  const _BulletItem({
    required this.icon,
    required this.iconColor,
    required this.text,
  });

  /// The leading icon that categorises this risk item.
  final IconData icon;

  /// Colour applied to the leading icon.
  final Color iconColor;

  /// The explanatory text for this risk item.
  final String text;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Icon aligned to the first line of text via top padding.
        Padding(
          padding: const EdgeInsets.only(top: 1),
          child: Icon(icon, size: 16, color: iconColor),
        ),
        const SizedBox(width: 10),
        // Text fills the remaining width and wraps naturally.
        Expanded(
          child: Text(
            text,
            style: tt.bodySmall,
          ),
        ),
      ],
    );
  }
}
