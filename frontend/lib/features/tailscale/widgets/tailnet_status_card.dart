// tailnet_status_card.dart
//
// TailnetStatusCard — a themed container card that displays the key status
// fields for one Tailscale instance.
//
// ROLE IN THE UI
// --------------
// This card appears at the top of the Overview tab in TailnetDetailScreen.
// It gives the user an immediate snapshot of whether the tailnet is connected,
// what IP address they have, what device name is registered, and when their
// key expires.
//
// DESIGN SIMILARITY TO THE LEGACY SCREEN
// ----------------------------------------
// The existing single-instance TailscaleSetupScreen used a private _StatusCard
// widget with a title and a list of text lines.  TailnetStatusCard is the
// multi-instance successor — it follows the same visual pattern (bordered
// container, label-large title, body-medium lines) but is public and
// structured to receive a typed TailnetInstance model rather than a list of
// arbitrary strings.
//
// WHY A SEPARATE FILE?
// --------------------
// The card is used in two places: TailnetDetailScreen (overview tab) and
// potentially in TailnetListTile expanded mode.  Extracting it to its own
// file keeps both screens thin and avoids duplicating the layout code.

import 'package:flutter/material.dart';
// Material widgets: Container, Column, Text, BoxDecoration, Theme.

import '../../../features/network/network_state.dart';
// OverlayClientStatus — needed by _statusLine() to produce a human-readable
// status string.

import '../models/tailnet_instance.dart';
// TailnetInstance — the typed model this card displays.

// ---------------------------------------------------------------------------
// TailnetStatusCard
// ---------------------------------------------------------------------------

/// A bordered card showing the operational status of one [TailnetInstance].
///
/// Displays: connection status, device name, device IP, tailnet name,
/// controller URL, relay mode preference, and key expiry timestamp.
///
/// Does NOT show the key expiry warning banner — that is handled separately
/// by [KeyExpiryBanner] which appears above this card when the key is
/// expiring soon.
///
/// Spec reference: §5.22 (multi-instance overlay status display)
class TailnetStatusCard extends StatelessWidget {
  /// Creates a [TailnetStatusCard] for the given [instance].
  const TailnetStatusCard({
    super.key,
    required this.instance,
  });

  /// The tailnet instance whose status to display.
  ///
  /// The card reads only display-relevant fields — it does not mutate state.
  final TailnetInstance instance;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Build the list of non-empty display lines.
    //
    // We skip null/empty strings so the card never shows blank rows.
    // The order matches what a network engineer would expect: status first,
    // then the device identity fields, then the infrastructure fields.
    final lines = [
      // Human-readable status — always shown.
      _statusLine(instance.status),

      // Device identity within the tailnet.
      if (instance.deviceName != null && instance.deviceName!.isNotEmpty)
        'Device: ${instance.deviceName}',

      if (instance.deviceIp != null && instance.deviceIp!.isNotEmpty)
        'Address: ${instance.deviceIp}',

      // Tailnet and controller information.
      if (instance.tailnetName != null && instance.tailnetName!.isNotEmpty)
        'Tailnet: ${instance.tailnetName}',

      if (instance.controller != null && instance.controller!.isNotEmpty)
        'Controller: ${instance.controller}'
      else
        'Controller: Tailscale (vendor)',
      // ↑ Fallback label for when controller is null/empty (= vendor Tailscale).
      //   This makes it explicit to the user which control plane is in use.

      // Relay preference — always shown because it directly affects privacy.
      if (instance.preferMeshRelay)
        'Relay: Mesh relay preferred (avoids Tailscale DERP)'
      else
        'Relay: Tailscale DERP (default)',

      // Active exit node — only shown when set.
      if (instance.activeExitNode != null &&
          instance.activeExitNode!.isNotEmpty)
        'Exit node: ${instance.activeExitNode}',

      // Key expiry — only shown when the backend reported a non-zero timestamp.
      if (instance.keyExpiryUnixMs > 0)
        'Key expiry: ${_formatExpiry(instance.keyExpiryUnixMs)}',

      // Peer count — useful at a glance without opening the Peers tab.
      'Peers: ${instance.peerCount}',
    ];

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        // surfaceContainerHighest is the standard slightly-elevated surface tone
        // used throughout the app for cards and info boxes.
        color: cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: cs.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Section title — uses labelLarge to match the existing _StatusCard.
          Text('Status', style: tt.labelLarge),
          const SizedBox(height: 10),

          // Render each non-empty line as a separate Text widget with a small
          // bottom margin so the lines breathe without excessive spacing.
          for (final line in lines)
            Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: Text(
                line,
                style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
              ),
            ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Convert [OverlayClientStatus] to a human-readable string for display.
///
/// This mirrors the _statusLabel() free function in tailscale_setup_screen.dart
/// but lives here as a private function to avoid cross-file coupling.
String _statusLine(OverlayClientStatus status) => switch (status) {
  OverlayClientStatus.notConfigured => 'Status: Not configured',
  OverlayClientStatus.connecting    => 'Status: Connecting…',
  OverlayClientStatus.connected     => 'Status: Connected',
  OverlayClientStatus.disconnected  => 'Status: Disconnected',
  OverlayClientStatus.error         => 'Status: Error',
};

/// Format a Unix timestamp (milliseconds) as a human-readable local date/time.
///
/// Example: 1720000000000 → "2024-07-03 15:06:40"
/// The caller has already verified that [unixMs] > 0 before calling this.
String _formatExpiry(int unixMs) {
  final dt = DateTime.fromMillisecondsSinceEpoch(unixMs).toLocal();
  // Manual two-digit padding for month, day, hour, minute, second.
  final y  = dt.year.toString();
  final mo = dt.month.toString().padLeft(2, '0');
  final d  = dt.day.toString().padLeft(2, '0');
  final h  = dt.hour.toString().padLeft(2, '0');
  final mi = dt.minute.toString().padLeft(2, '0');
  final s  = dt.second.toString().padLeft(2, '0');
  return '$y-$mo-$d $h:$mi:$s';
}
