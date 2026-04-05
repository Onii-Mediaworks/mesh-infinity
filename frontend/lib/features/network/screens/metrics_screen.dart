import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../network_state.dart';

/// Shows network metrics backed by real runtime state.
///
/// When a metric is not currently exposed by the backend, this screen says so
/// directly instead of fabricating placeholder values.
class MetricsScreen extends StatelessWidget {
  const MetricsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final stats = net.stats;

    final bytesSent = stats?.bytesSent ?? 0;
    final bytesReceived = stats?.bytesReceived ?? 0;
    final activeConnections = stats?.activeConnections ?? 0;
    final activeTunnels = stats?.wireGuardSessions ?? 0;
    final networkMapSize = stats?.gossipMapSize ?? 0;
    final sfNodes = stats?.sfPendingMessages ?? 0;
    final totalConnectionUnits = activeConnections > 0 ? activeConnections : 1;

    return Scaffold(
      appBar: AppBar(title: const Text('Network Metrics')),
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            _MetricsCard(
              title: 'Privacy posture',
              children: [
                _MetricRow(
                  icon: Icons.shield_outlined,
                  label: 'Routing mode',
                  value: _vpnModeLabel(net.vpnMode),
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
                  tooltip: 'Blocks internet-bound traffic when an exit-node route drops.',
                ),
                const SizedBox(height: 12),
                Text(
                  _privacySummary(net),
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                ),
              ],
            ),
            const SizedBox(height: 12),
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
                _MetricRow(
                  icon: Icons.inbox_outlined,
                  label: 'S&F backlog',
                  value: '$sfNodes',
                ),
              ],
            ),
            const SizedBox(height: 12),
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
                _MetricRow(
                  icon: Icons.route_outlined,
                  label: 'Routing entries',
                  value: '${stats?.routingEntries ?? 0}',
                ),
                _MetricRow(
                  icon: Icons.public_outlined,
                  label: 'Clearnet connections',
                  value: '${stats?.clearnetConnections ?? 0}',
                ),
              ],
            ),
            const SizedBox(height: 12),
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

  static String _vpnModeLabel(String mode) => switch (mode) {
        'mesh_only' => 'Mesh only',
        'exit_node' => 'Exit node',
        'policy_based' => 'Policy-based',
        _ => 'Off',
      };

  static String _routingStatusLabel(NetworkState net) => switch (net.vpnConnectionStatus) {
        'connected' => 'Connected',
        'connecting' => 'Connecting',
        'blocked' => 'Blocked by kill switch',
        'disconnecting' => 'Disconnecting',
        _ => net.isVpnActive ? 'Starting' : 'Inactive',
      };

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

  static String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }
}

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
          Text(
            value,
            style: theme.textTheme.bodyMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
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

class _TransportRow extends StatelessWidget {
  const _TransportRow({
    required this.name,
    required this.count,
    required this.total,
  });

  final String name;
  final int count;
  final int total;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final fraction = count / total;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(child: Text(name, style: theme.textTheme.bodySmall)),
              Text(
                '$count',
                style: theme.textTheme.bodySmall?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 2),
          ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: LinearProgressIndicator(
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
