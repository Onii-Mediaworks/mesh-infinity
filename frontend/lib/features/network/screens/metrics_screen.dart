import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../network_state.dart';

/// MetricsScreen — a detailed view of live network counters and privacy posture.
///
/// Shows four grouped cards:
///   1. Privacy posture — current VPN mode, connection status, kill-switch state,
///      and a plain-language summary of what the current route implies.
///   2. Connection — active WireGuard tunnels, active connections, gossip map
///      size, and Store-and-Forward (S&F) backlog.
///   3. Activity — data sent/received, routing entries, clearnet connections.
///   4. Transport usage — a mini bar-chart showing the relative share of each
///      transport type based on connection counts.
///
/// All values are pulled from [NetworkState.stats] which is fetched on demand.
/// When a metric is not yet exposed by the backend this screen says so directly
/// rather than fabricating placeholder numbers.
///
/// Pull-to-refresh triggers [NetworkState.loadAll].
class MetricsScreen extends StatelessWidget {
  const MetricsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    // stats is null until the first loadAll() call that returns data.
    // Guard with ?? 0 throughout to show zeroes rather than null crashes.
    final stats = net.stats;

    final bytesSent = stats?.bytesSent ?? 0;
    final bytesReceived = stats?.bytesReceived ?? 0;
    final activeConnections = stats?.activeConnections ?? 0;
    // wireGuardSessions = the number of active WireGuard key-exchange tunnels.
    // WireGuard is the encrypted tunnel layer used between mesh peers.
    final activeTunnels = stats?.wireGuardSessions ?? 0;
    // gossipMapSize = how many nodes are in the routing gossip table.
    // Gossip routing: each node learns the topology by exchanging small
    // "I know these nodes" messages with its neighbours.
    final networkMapSize = stats?.gossipMapSize ?? 0;
    // sfPendingMessages = messages waiting in the Store-and-Forward buffer.
    // S&F: when a destination is unreachable, messages are held locally and
    // retried later, enabling asynchronous delivery across intermittent links.
    final sfNodes = stats?.sfPendingMessages ?? 0;

    // totalConnectionUnits is the denominator for the transport-usage bars.
    // We floor at 1 to avoid division-by-zero when there are no connections.
    final totalConnectionUnits = activeConnections > 0 ? activeConnections : 1;

    return Scaffold(
      appBar: AppBar(title: const Text('Network Metrics')),
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // ── Card 1: Privacy posture ───────────────────────────────────
            // Answers "what is my current routing privacy level?"
            _MetricsCard(
              title: 'Privacy posture',
              children: [
                _MetricRow(
                  icon: Icons.shield_outlined,
                  label: 'Routing mode',
                  value: _vpnModeLabel(net.vpnMode),
                  // Tooltip provides extra context for users unfamiliar with
                  // mesh-only vs exit-node vs off.
                  tooltip: 'How Mesh Infinity currently routes your traffic.',
                ),
                _MetricRow(
                  icon: Icons.route_outlined,
                  label: 'Connection status',
                  value: _routingStatusLabel(net),
                  tooltip: 'Whether mesh VPN routing is connected, blocked, or inactive.',
                ),
                _MetricRow(
                  icon: Icons.block_outlined,
                  label: 'Kill switch',
                  value: net.vpnKillSwitch ? 'On' : 'Off',
                  // Kill switch: blocks ALL internet traffic if the VPN tunnel
                  // drops unexpectedly, preventing unintentional clearnet leaks.
                  tooltip: 'Blocks internet-bound traffic when an exit-node route drops.',
                ),
                const SizedBox(height: 12),
                // Plain-language summary of the privacy implications.
                Text(
                  _privacySummary(net),
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                ),
              ],
            ),
            const SizedBox(height: 12),

            // ── Card 2: Connection ────────────────────────────────────────
            _MetricsCard(
              title: 'Connection',
              children: [
                _MetricRow(
                  icon: Icons.hub_outlined,
                  label: 'Active tunnels',
                  value: '$activeTunnels',
                ),
                _MetricRow(
                  icon: Icons.sync_alt_outlined,
                  label: 'Active connections',
                  value: '$activeConnections',
                ),
                _MetricRow(
                  icon: Icons.people_outline,
                  label: 'Peers in map',
                  value: '$networkMapSize',
                ),
                // S&F backlog: non-zero means there are messages waiting for
                // an offline peer.  High values may indicate routing issues.
                _MetricRow(
                  icon: Icons.inbox_outlined,
                  label: 'S&F backlog',
                  value: '$sfNodes',
                ),
              ],
            ),
            const SizedBox(height: 12),

            // ── Card 3: Activity ──────────────────────────────────────────
            _MetricsCard(
              title: 'Activity',
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
                // routingEntries: the number of entries in the local routing
                // table that maps destination node IDs to next-hop addresses.
                _MetricRow(
                  icon: Icons.route_outlined,
                  label: 'Routing entries',
                  value: '${stats?.routingEntries ?? 0}',
                ),
                // clearnetConnections: active TCP/IP connections that are NOT
                // using an anonymising overlay (Tor/I2P).  High values on a
                // privacy-focused device may warrant investigation.
                _MetricRow(
                  icon: Icons.public_outlined,
                  label: 'Clearnet connections',
                  value: '${stats?.clearnetConnections ?? 0}',
                ),
              ],
            ),
            const SizedBox(height: 12),

            // ── Card 4: Transport usage ───────────────────────────────────
            // Shows relative usage of each transport as a mini progress bar.
            // This helps users understand which transports are actually active
            // vs just enabled in settings.
            _MetricsCard(
              title: 'Transport usage',
              children: [
                _TransportRow(
                  name: 'WireGuard sessions',
                  count: activeTunnels,
                  total: totalConnectionUnits,
                ),
                _TransportRow(
                  name: 'Clearnet connections',
                  count: stats?.clearnetConnections ?? 0,
                  total: totalConnectionUnits,
                ),
                _TransportRow(
                  name: 'Store-and-forward backlog',
                  count: sfNodes,
                  total: totalConnectionUnits,
                ),
                const SizedBox(height: 12),
                // Honest caveat: per-transport byte accounting is not exposed
                // yet, so we only show what the backend actually provides.
                Text(
                  'Per-transport byte accounting and cover-traffic metrics are '
                  'not exposed by the backend yet, so this screen only shows '
                  'live counters that are actually available.',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                ),
              ],
            ),
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }

  /// Maps the backend VPN mode string to a human-readable label.
  static String _vpnModeLabel(String mode) => switch (mode) {
        'mesh_only'      => 'Mesh only',
        'exit_node'      => 'Exit node',
        'policy_based'   => 'Policy-based',
        _                => 'Off',
      };

  /// Summarises the VPN connection status in a single word, with special
  /// handling for the "starting" intermediate state that appears between
  /// "off" and the first "connected" event.
  static String _routingStatusLabel(NetworkState net) => switch (net.vpnConnectionStatus) {
        'connected'     => 'Connected',
        'connecting'    => 'Connecting',
        'blocked'       => 'Blocked by kill switch',
        'disconnecting' => 'Disconnecting',
        // vpnConnectionStatus may be an empty string or "disconnected" before
        // the tunnel has fully come up even though isVpnActive is already true.
        _ => net.isVpnActive ? 'Starting' : 'Inactive',
      };

  /// Returns a plain-language description of the privacy implications of the
  /// current VPN security posture code (owned by the Rust backend).
  ///
  /// The posture string combines mode + exit path into a single summary key
  /// so the UI doesn't have to reconstruct the implications from multiple fields.
  static String _privacySummary(NetworkState net) {
    return switch (net.vpnSecurityPosture) {
      'mesh_only' =>
        'Mesh destinations use encrypted mesh routing. Regular internet '
        'traffic still uses your normal network path.',
      'exit_node' =>
        'Internet traffic leaves through the selected exit node. Websites see '
        'that node\'s IP, and the operator can still see your destinations '
        'after the traffic leaves the mesh.',
      'policy_based' =>
        'Different apps or destinations can take different paths. Review your '
        'rules carefully so sensitive traffic does not follow the wrong path.',
      _ =>
        'No mesh VPN routing is active, so this screen is showing general '
        'network counters only.',
    };
  }

  /// Formats a raw byte count into a human-readable string with appropriate
  /// binary unit (B, KB, MB, GB).  Uses 1024-based divisions (binary prefixes)
  /// because network traffic is typically measured in binary units.
  static String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }
}

/// _MetricsCard — a titled card container that groups related metrics.
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
            Text(title, style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 12),
            ...children,
          ],
        ),
      ),
    );
  }
}

/// _MetricRow — a labelled key/value row with an icon and optional tooltip.
///
/// Used throughout the metrics cards to display a single counter or status
/// field.  The icon provides quick visual scanning; the tooltip explains
/// non-obvious abbreviations (e.g. "S&F" for Store-and-Forward).
class _MetricRow extends StatelessWidget {
  const _MetricRow({
    required this.icon,
    required this.label,
    required this.value,
    this.tooltip,
  });

  final IconData icon;
  final String label;

  /// The current value to display on the right side of the row.
  final String value;

  /// Optional tooltip text shown on a small info icon next to the value.
  /// Use for metrics whose meaning may not be immediately obvious.
  final String? tooltip;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(icon, size: 18, color: theme.colorScheme.onSurfaceVariant),
          const SizedBox(width: 10),
          Expanded(child: Text(label, style: theme.textTheme.bodyMedium)),
          // Bold value on the right for easy scanning down the column.
          Text(
            value,
            style: theme.textTheme.bodyMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          // Optional inline help icon — only rendered when a tooltip is provided.
          if (tooltip != null)
            Padding(
              padding: const EdgeInsets.only(left: 4),
              child: Tooltip(
                message: tooltip!,
                child: Icon(
                  Icons.info_outline,
                  size: 14,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
        ],
      ),
    );
  }
}

/// _TransportRow — one row in the "Transport usage" card.
///
/// Shows the transport name, its raw count, and a thin progress bar whose
/// fill fraction represents that transport's share of total active connections.
///
/// The bar is purely informational — it helps users spot which transport is
/// dominant without needing to do mental arithmetic.
class _TransportRow extends StatelessWidget {
  const _TransportRow({
    required this.name,
    required this.count,
    required this.total,
  });

  final String name;

  /// Raw count of connections using this transport.
  final int count;

  /// Total connections across ALL transports (the denominator for the bar).
  /// Must be >= 1; the caller is responsible for clamping.
  final int total;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    // fraction is always in [0, 1] — clamped below to handle rounding edge cases.
    final fraction = count / total;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(child: Text(name, style: theme.textTheme.bodySmall)),
              // Right-aligned count.
              Text(
                '$count',
                style: theme.textTheme.bodySmall?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 2),
          // Thin progress bar — 4 dp height so it is present but not distracting.
          ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: LinearProgressIndicator(
              // clamp to [0.0, 1.0] in case counts exceed total due to timing.
              value: fraction.clamp(0.0, 1.0),
              minHeight: 4,
              backgroundColor: theme.colorScheme.surfaceContainerHighest,
              valueColor: AlwaysStoppedAnimation<Color>(theme.colorScheme.primary),
            ),
          ),
        ],
      ),
    );
  }
}
