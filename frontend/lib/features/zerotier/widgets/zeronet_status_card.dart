// zeronet_status_card.dart
//
// ZeroNetStatusCard — a card widget that shows a summary of one ZeroNet
// instance's connection state.
//
// PURPOSE
// --------
// The Overview tab of [ZeroNetDetailScreen] leads with this card so the user
// immediately sees the most important facts about an instance:
//   • Current connection status (connected / connecting / error / etc.)
//   • This device's ZeroTier Node ID on this instance
//   • The controller URL (ZeroTier Central or self-hosted)
//   • Relay mode (direct / vendor relay / mesh relay preferred)
//   • Number of joined networks and visible members
//
// WHY A SEPARATE WIDGET?
// -----------------------
// The status card is visually complex (several rows of labeled data) and is
// reused in potential future contexts (e.g. a compact hub-level summary).
// Extracting it keeps [ZeroNetDetailScreen] focused on layout/navigation
// rather than detail rendering.
//
// Spec ref: §5.23 ZeroTier overlay.

import 'package:flutter/material.dart';

import '../../network/network_state.dart';
// OverlayClientStatus — the connection state enum shared across overlays.

import '../models/zeronet_instance.dart';
// ZeroNetInstance — the data model we're rendering.

// ---------------------------------------------------------------------------
// ZeroNetStatusCard
// ---------------------------------------------------------------------------

/// Card widget showing the full connection summary for one ZeroNet instance.
///
/// Displayed in the Overview tab of [ZeroNetDetailScreen].
class ZeroNetStatusCard extends StatelessWidget {
  /// The instance whose status is displayed.
  final ZeroNetInstance instance;

  /// Creates a [ZeroNetStatusCard] for the given [instance].
  const ZeroNetStatusCard({super.key, required this.instance});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Resolve a semantic color for the status indicator dot.
    final statusColor = _statusColor(instance.status);

    return Card(
      // Card styling comes from the app-wide CardThemeData in app_theme.dart —
      // rounded corners, zero elevation, surface-container background.
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ---- Header row: status dot + label ----------------------------
            Row(
              children: [
                // Colored dot — instant visual signal without reading text.
                Container(
                  width: 10,
                  height: 10,
                  decoration: BoxDecoration(
                    color: statusColor,
                    shape: BoxShape.circle,
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  _statusLabel(instance.status),
                  style: tt.titleSmall?.copyWith(color: cs.onSurface),
                ),
              ],
            ),

            const SizedBox(height: 12),
            const Divider(height: 1),
            const SizedBox(height: 12),

            // ---- Detail rows -----------------------------------------------
            // Each _row() call renders a labeled key-value pair.

            // Node ID — the ZeroTier identity of this device on this instance.
            // 10 hex chars, e.g. "deadbeef01".  Shown in monospace to make
            // hex strings easier to read and compare character-by-character.
            if (instance.nodeId != null && instance.nodeId!.isNotEmpty)
              _row(
                context,
                label: 'Node ID',
                value: instance.nodeId!,
                mono: true,
              ),

            // Controller — which authority governs membership in this instance.
            // "https://my.zerotier.com" = ZeroTier Central SaaS.
            // Any other URL = self-hosted (full sovereignty).
            if (instance.controller != null && instance.controller!.isNotEmpty)
              _row(
                context,
                label: 'Controller',
                value: instance.controller!,
              ),

            // Relay mode — whether traffic goes through ZeroTier's servers or
            // through Mesh Infinity's own relay infrastructure.
            _row(
              context,
              label: 'Relay mode',
              value: instance.preferMeshRelay
                  ? 'Mesh relay preferred'
                  : 'ZeroTier relay (default)',
            ),

            // Network count — how many ZeroTier networks are joined.
            _row(
              context,
              label: 'Networks',
              value: '${instance.networkCount}',
            ),

            // Member count — peers visible across all networks.
            _row(
              context,
              label: 'Members',
              value: '${instance.memberCount}',
            ),
          ],
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // _row helper
  // ---------------------------------------------------------------------------

  /// Renders a single labeled key-value row.
  ///
  /// [mono] forces the value into a monospace font — useful for node IDs,
  /// network IDs, and IP addresses where character alignment matters.
  Widget _row(
    BuildContext context, {
    required String label,
    required String value,
    bool mono = false,
  }) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Padding(
      // Small bottom margin separates rows without needing explicit Dividers.
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Label: fixed width keeps values left-aligned across all rows.
          // 96 dp is wide enough for "Controller" (the longest label here).
          SizedBox(
            width: 96,
            child: Text(
              label,
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
          // Value: expands to fill remaining width; wraps on long strings.
          Expanded(
            child: Text(
              value,
              style: tt.bodySmall?.copyWith(
                color: cs.onSurface,
                fontFamily: mono ? 'monospace' : null,
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Static helpers
  // ---------------------------------------------------------------------------

  /// Human-readable label for [OverlayClientStatus].
  static String _statusLabel(OverlayClientStatus s) => switch (s) {
    OverlayClientStatus.notConfigured => 'Not configured',
    OverlayClientStatus.connecting    => 'Connecting…',
    OverlayClientStatus.connected     => 'Connected',
    OverlayClientStatus.disconnected  => 'Disconnected',
    OverlayClientStatus.error         => 'Error',
  };

  /// Semantic color for [OverlayClientStatus] from the Mesh Infinity palette.
  static Color _statusColor(OverlayClientStatus s) => switch (s) {
    OverlayClientStatus.connected     => const Color(0xFF22C55E), // secGreen
    OverlayClientStatus.connecting    => const Color(0xFFF59E0B), // secAmber
    OverlayClientStatus.disconnected  => const Color(0xFF9CA3AF), // neutral grey
    OverlayClientStatus.error         => const Color(0xFFEF4444), // secRed
    OverlayClientStatus.notConfigured => const Color(0xFF9CA3AF), // neutral grey
  };
}
