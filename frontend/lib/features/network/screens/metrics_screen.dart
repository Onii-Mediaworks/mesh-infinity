// metrics_screen.dart
//
// MetricsScreen — detailed network privacy and performance statistics (§22.9.2).
//
// WHAT THIS SCREEN SHOWS:
// -----------------------
// Four stat cards presenting live data from the Rust backend:
//
//   Privacy card      — cover traffic, anonymity set, real-vs-cover ratio bar,
//                       how many peers this device is currently routing for.
//   Connection card   — active tunnels, peers in map, threat context, connection
//                       mode, store-and-forward nodes in use.
//   Activity card     — today's message counts and data transferred.
//   Transport card    — per-transport byte breakdown (clearnet / Tor / I2P / etc.).
//
// WHY SHOW COVER TRAFFIC?
// -----------------------
// Cover traffic is extra encrypted data sent to make real traffic harder to
// distinguish from noise (traffic analysis resistance, §4.7).  Showing it
// lets users verify the feature is active and understand the bandwidth cost.
//
// DATA SOURCE:
// ------------
// NetworkState.stats (NetworkStatsModel) provides: bytesSent, bytesReceived,
// activeConnections, gossipMapSize, sfPendingMessages, wireGuardSessions.
// Extra metrics (coverTrafficBytes, anonymitySetEstimate, etc.) are stubs
// until the backend exposes them via mi_get_extended_metrics().
//
// Reached from: Network → Status → "Detailed metrics" tile.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app/app_theme.dart';
import '../network_state.dart';

// ---------------------------------------------------------------------------
// MetricsScreen
// ---------------------------------------------------------------------------

/// Shows detailed network privacy and performance metrics in four cards.
class MetricsScreen extends StatelessWidget {
  const MetricsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final stats = net.stats;

    // We always show the screen even if stats are null — each card shows
    // placeholder zeroes so the layout is stable from first render.
    final bytesSent = stats?.bytesSent ?? 0;
    final bytesReceived = stats?.bytesReceived ?? 0;
    final activeTunnels = stats?.wireGuardSessions ?? 0;
    final networkMapSize = stats?.gossipMapSize ?? 0;
    final sfNodes = stats?.sfPendingMessages ?? 0;

    // Stub metrics — not yet in NetworkStatsModel.
    // TODO(backend/metrics): wire mi_get_extended_metrics() and decode these.
    const int coverTrafficBytes = 0;
    const int peersRoutedFor = 0;
    const int anonymitySetEstimate = 0;

    // Real-vs-cover traffic ratio.  Guard against division by zero when both
    // counters are zero (fresh start / no traffic yet).
    final totalBytes = bytesSent + coverTrafficBytes;
    final realRatio = totalBytes > 0 ? bytesSent / totalBytes : 0.5;

    return Scaffold(
      appBar: AppBar(title: const Text('Network Metrics')),
      body: RefreshIndicator(
        // Pull-to-refresh reloads the stats snapshot from the backend.
        onRefresh: net.loadAll,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // ── Privacy card ─────────────────────────────────────────────
            // Shows cover traffic and anonymity metrics.  These are the most
            // privacy-sensitive numbers — surfaced first because users who
            // care about them care a lot.
            _MetricsCard(
              title: 'Privacy',
              children: [
                _MetricRow(
                  icon: Icons.shield_outlined,
                  label: 'Cover traffic today',
                  value: _formatBytes(coverTrafficBytes),
                  tooltip:
                      'Extra encrypted data sent to make your real traffic '
                      'harder to distinguish from others.',
                ),
                const _MetricRow(
                  icon: Icons.people_outline,
                  label: 'Routing for others',
                  value: '$peersRoutedFor peers',
                  tooltip:
                      'Your device helped route encrypted messages for this '
                      'many other users today.',
                ),
                const _MetricRow(
                  icon: Icons.blur_circular_outlined,
                  label: 'Anonymity set estimate',
                  value: '~$anonymitySetEstimate nodes',
                  tooltip:
                      'Your traffic blends with approximately this many other '
                      'nodes. Larger is better.',
                ),
                const SizedBox(height: 8),

                // Real-vs-cover traffic ratio bar.
                // Green = cover (good), brand blue = real (actual payload).
                // A healthy ratio shows more green than blue.
                Text(
                  'Real vs cover traffic',
                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                ),
                const SizedBox(height: 4),
                ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: Row(
                    children: [
                      Flexible(
                        flex: (realRatio * 100).round().clamp(1, 99),
                        child: Container(
                          height: 8,
                          color: MeshTheme.brand,
                        ),
                      ),
                      Flexible(
                        flex: (100 - realRatio * 100).round().clamp(1, 99),
                        child: Container(
                          height: 8,
                          color: MeshTheme.secGreen.withValues(alpha: 0.4),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 4),
                Row(
                  children: [
                    const _LegendDot(color: MeshTheme.brand),
                    const SizedBox(width: 4),
                    Text(
                      'Real (${(realRatio * 100).round()}%)',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                    const SizedBox(width: 12),
                    const _LegendDot(color: MeshTheme.secGreen),
                    const SizedBox(width: 4),
                    Text(
                      'Cover (${(100 - realRatio * 100).round()}%)',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              ],
            ),

            const SizedBox(height: 12),

            // ── Connection card ───────────────────────────────────────────
            _MetricsCard(
              title: 'Connection',
              children: [
                _MetricRow(
                  icon: Icons.hub_outlined,
                  label: 'Active tunnels',
                  value: '$activeTunnels',
                ),
                _MetricRow(
                  icon: Icons.people_outline,
                  label: 'Peers in map',
                  value: '$networkMapSize',
                ),
                _MetricRow(
                  icon: Icons.inbox_outlined,
                  label: 'S&F nodes in use',
                  value: '$sfNodes',
                ),
                _MetricRow(
                  icon: Icons.settings_ethernet_outlined,
                  label: 'Connection mode',
                  value: _connectionModeLabel(net),
                ),
              ],
            ),

            const SizedBox(height: 12),

            // ── Activity card ─────────────────────────────────────────────
            _MetricsCard(
              title: "Today's activity",
              children: [
                _MetricRow(
                  icon: Icons.upload_outlined,
                  label: 'Data sent',
                  value: _formatBytes(bytesSent),
                ),
                _MetricRow(
                  icon: Icons.download_outlined,
                  label: 'Data received',
                  value: _formatBytes(bytesReceived),
                ),
                _MetricRow(
                  icon: Icons.route_outlined,
                  label: 'Routing entries',
                  value: '${stats?.routingEntries ?? 0}',
                ),
                _MetricRow(
                  icon: Icons.sync_alt_outlined,
                  label: 'Clearnet connections',
                  value: '${stats?.clearnetConnections ?? 0}',
                ),
              ],
            ),

            const SizedBox(height: 12),

            // ── Transport card ─────────────────────────────────────────────
            // Breakdown of which transport each byte travelled through.
            // Stub data until the backend exposes per-transport counters.
            _MetricsCard(
              title: 'Transport usage',
              children: [
                _TransportRow(
                  name: 'Clearnet',
                  bytes: stats?.clearnetConnections ?? 0,
                  total: bytesSent > 0 ? bytesSent : 1,
                ),
                _TransportRow(
                  name: 'Tor',
                  bytes: 0, // TODO(backend/metrics): mi_get_transport_bytes('tor')
                  total: bytesSent > 0 ? bytesSent : 1,
                ),
                _TransportRow(
                  name: 'I2P',
                  bytes: 0, // TODO(backend/metrics): mi_get_transport_bytes('i2p')
                  total: bytesSent > 0 ? bytesSent : 1,
                ),
                _TransportRow(
                  name: 'Local (mDNS)',
                  bytes: 0, // TODO(backend/metrics): mi_get_transport_bytes('mdns')
                  total: bytesSent > 0 ? bytesSent : 1,
                ),
              ],
            ),

            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Formatting helpers
  // ---------------------------------------------------------------------------

  /// Formats a byte count as a human-readable string with appropriate unit.
  static String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  /// Returns a plain-language label for the current connection mode.
  static String _connectionModeLabel(NetworkState net) {
    if (net.settings?.enableTor == true) return 'Tor';
    if (net.settings?.enableI2p == true) return 'I2P';
    if (net.settings?.enableClearnet == true) return 'Clearnet';
    return 'Unknown';
  }
}

// ---------------------------------------------------------------------------
// _MetricsCard — card container for one stats group
// ---------------------------------------------------------------------------

/// Wraps a titled group of metric rows in a Material card.
class _MetricsCard extends StatelessWidget {
  const _MetricsCard({required this.title, required this.children});

  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: Theme.of(context).textTheme.titleSmall,
            ),
            const SizedBox(height: 12),
            ...children,
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _MetricRow — one label/value pair with optional icon and tooltip
// ---------------------------------------------------------------------------

/// A single metric displayed as icon + label + value, with optional tooltip.
///
/// The value is right-aligned and bold to make it easy to scan down the list.
/// The tooltip icon (ⓘ) is small and muted so it doesn't compete visually.
class _MetricRow extends StatelessWidget {
  const _MetricRow({
    required this.icon,
    required this.label,
    required this.value,
    this.tooltip,
  });

  final IconData icon;
  final String label;
  final String value;

  /// Optional longer explanation shown in a tooltip.  When null, the info
  /// icon is not rendered.
  final String? tooltip;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(icon, size: 18, color: cs.onSurfaceVariant),
          const SizedBox(width: 10),
          Expanded(child: Text(label, style: tt.bodyMedium)),
          Text(
            value,
            style: tt.bodyMedium?.copyWith(fontWeight: FontWeight.w600),
          ),
          if (tooltip != null)
            Padding(
              padding: const EdgeInsets.only(left: 4),
              child: Tooltip(
                message: tooltip!,
                child: Icon(
                  Icons.info_outline,
                  size: 14,
                  color: cs.onSurfaceVariant,
                ),
              ),
            ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _TransportRow — per-transport byte share bar
// ---------------------------------------------------------------------------

/// Shows one transport's byte share as a label + proportional bar segment.
///
/// The bar shows what fraction of total sent bytes went through this transport.
class _TransportRow extends StatelessWidget {
  const _TransportRow({
    required this.name,
    required this.bytes,
    required this.total,
  });

  final String name;
  final int bytes;

  /// Total bytes sent across all transports — used to compute the fraction.
  final int total;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;
    final fraction = bytes / total; // 0.0–1.0

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(child: Text(name, style: tt.bodySmall)),
              Text(
                MetricsScreen._formatBytes(bytes),
                style: tt.bodySmall?.copyWith(fontWeight: FontWeight.w600),
              ),
            ],
          ),
          const SizedBox(height: 2),
          // Proportional bar — full width represents 100% of bytes sent.
          ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: LinearProgressIndicator(
              value: fraction.clamp(0.0, 1.0),
              minHeight: 4,
              backgroundColor: cs.surfaceContainerHighest,
              valueColor: AlwaysStoppedAnimation<Color>(cs.primary),
            ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _LegendDot — small coloured square for chart legends
// ---------------------------------------------------------------------------

/// A 10×10 rounded square used as a colour legend indicator.
class _LegendDot extends StatelessWidget {
  const _LegendDot({required this.color});

  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 10,
      height: 10,
      decoration: BoxDecoration(
        color: color,
        borderRadius: BorderRadius.circular(2),
      ),
    );
  }
}
