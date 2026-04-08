// key_expiry_banner.dart
//
// KeyExpiryBanner — an amber warning strip shown when a Tailscale WireGuard
// key is within 7 days of expiry.
//
// WHY DOES THE KEY EXPIRE?
// ------------------------
// Tailscale issues time-limited device certificates (WireGuard key pairs)
// that are signed by the control plane.  By default, a key expires after 180
// days unless the user re-authenticates.  When the key expires, the device is
// automatically removed from the tailnet and cannot communicate with peers
// until the user signs in again.
//
// WHY 7 DAYS?
// -----------
// Seven days gives the user a comfortable window to notice the warning and
// re-authenticate before service is interrupted.  The Rust backend fires a
// TailscaleKeyExpiryWarningEvent when it detects expiry within this window
// (§5.23.3 of the spec).
//
// DESIGN RATIONALE
// ----------------
// We use an amber / warning colour rather than red to communicate "attention
// needed soon" rather than "already broken".  A red banner at 7 days would
// feel like false urgency.  The colour transitions to red only when
// daysRemaining == 0 (key expires today), indicating genuine emergency.
//
// The banner is NOT a full MaterialBanner (which stacks below the AppBar and
// pushes down content).  Instead it is a themed Container that sits inline
// at the top of the detail view content — easier to dismiss and less
// disruptive to the layout of the surrounding tab content.

import 'package:flutter/material.dart';
// Material widgets: Container, Row, Icon, Text, TextButton, Theme.

// ---------------------------------------------------------------------------
// KeyExpiryBanner
// ---------------------------------------------------------------------------

/// Inline warning strip shown when a Tailscale instance's WireGuard key is
/// within 7 days of expiry.
///
/// Displays [daysRemaining] and a "Re-authenticate" action button that calls
/// [onReauth] when tapped.
///
/// Spec reference: §5.23.3 (key expiry warning event)
///
/// Example usage (in TailnetDetailScreen overview tab):
/// ```dart
/// if (instance.isKeyExpiringSoon)
///   KeyExpiryBanner(
///     daysRemaining: instance.daysUntilKeyExpiry,
///     onReauth: () => context.read<TailscaleState>().reauth(instance.id),
///   ),
/// ```
class KeyExpiryBanner extends StatelessWidget {
  /// Creates a [KeyExpiryBanner].
  ///
  /// [daysRemaining] — whole days until the key expires (floor division).
  ///   Pass 0 to indicate the key expires today.
  ///
  /// [onReauth] — callback invoked when the user taps "Re-authenticate".
  ///   Typically calls TailscaleState.reauth(instanceId).
  const KeyExpiryBanner({
    super.key,
    required this.daysRemaining,
    required this.onReauth,
  });

  /// Whole days remaining until the WireGuard key expires.
  ///
  /// The calling code should pass TailnetInstance.daysUntilKeyExpiry.
  final int daysRemaining;

  /// Callback for the "Re-authenticate" action button.
  ///
  /// The caller is responsible for the actual bridge call so that the banner
  /// widget stays decoupled from TailscaleState.  This follows the same
  /// pattern as other action widgets in the app.
  final VoidCallback onReauth;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Choose colour based on urgency:
    //   0 days  → error colours (expiring today, red)
    //   1–6 days → amber / warning colours
    //
    // We build the amber from the tertiary container because the standard
    // Material3 colour scheme does not include a dedicated "warning" role.
    // Tertiary is typically a warm complement to the primary blue brand colour.
    final bool critical = daysRemaining == 0;

    final Color backgroundColor = critical
        ? cs.errorContainer
        : cs.tertiaryContainer;

    final Color foregroundColor = critical
        ? cs.onErrorContainer
        : cs.onTertiaryContainer;

    final IconData icon = critical
        ? Icons.error_outline
        : Icons.warning_amber_outlined;

    // Human-readable expiry string:
    //   0 → "Expires today"
    //   1 → "Expires in 1 day"
    //   N → "Expires in N days"
    final String expiryText = switch (daysRemaining) {
      0 => 'Key expires today — re-authenticate immediately',
      1 => 'Key expires in 1 day — please re-authenticate',
      _ => 'Key expires in $daysRemaining days — re-authenticate to avoid disruption',
    };

    return Container(
      // Full-width banner sits flush with the parent's horizontal padding.
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: backgroundColor,
        borderRadius: BorderRadius.circular(8),
        // Border reinforces the warning boundary against the surrounding card.
        border: Border.all(
          color: foregroundColor.withValues(alpha: 0.30),
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Warning icon aligned to the first line of the message text.
          Padding(
            padding: const EdgeInsets.only(top: 1),
            child: Icon(icon, size: 18, color: foregroundColor),
          ),
          const SizedBox(width: 10),
          // Message and action occupy the remaining width.
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Expiry message — primary information.
                Text(
                  expiryText,
                  style: tt.bodySmall?.copyWith(
                    color: foregroundColor,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 6),
                // Re-authenticate action button — compact, inline.
                // Uses a text button rather than a filled button so the banner
                // does not look too "heavy" when embedded in a tab page.
                TextButton(
                  onPressed: onReauth,
                  style: TextButton.styleFrom(
                    foregroundColor: foregroundColor,
                    padding: const EdgeInsets.symmetric(
                      horizontal: 10,
                      vertical: 4,
                    ),
                    minimumSize: Size.zero,
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                    side: BorderSide(
                      color: foregroundColor.withValues(alpha: 0.50),
                    ),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(6),
                    ),
                  ),
                  child: const Text(
                    'Re-authenticate',
                    style: TextStyle(fontSize: 12),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
