import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'network_state.dart';
import 'screens/metrics_screen.dart';
import 'screens/exit_node_screen.dart';
import 'screens/app_connector_screen.dart';

class NetworkStatusScreen extends StatelessWidget {
  const NetworkStatusScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final stats = net.stats;
    final s = net.settings;

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // Connection health card
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Connection',
                        style: Theme.of(context).textTheme.titleSmall),
                    const SizedBox(height: 12),
                    _StatusRow(
                      label: 'Peers connected',
                      value: '${net.totalPeers}',
                    ),
                    _StatusRow(
                      label: 'WireGuard sessions',
                      value: '${stats?.wireGuardSessions ?? 0}',
                    ),
                    _StatusRow(
                      label: 'Clearnet connections',
                      value: '${stats?.clearnetConnections ?? 0}',
                    ),
                    _StatusRow(
                      label: 'Avg latency',
                      value: stats != null
                          ? '${stats.avgLatencyMs} ms'
                          : '—',
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Routing posture',
                        style: Theme.of(context).textTheme.titleSmall),
                    const SizedBox(height: 12),
                    _StatusRow(
                      label: 'Mode',
                      value: _routingModeLabel(net.vpnMode),
                    ),
                    _StatusRow(
                      label: 'Status',
                      value: _routingStatusLabel(net.vpnConnectionStatus),
                    ),
                    _StatusRow(
                      label: 'Kill switch',
                      value: net.vpnKillSwitch ? 'On' : 'Off',
                    ),
                    if (net.selectedExitNodeId != null)
                      _StatusRow(
                        label: 'Exit node',
                        value: _exitNodeLabel(net.selectedExitNodeId!),
                        mono: true,
                      ),
                    if (net.selectedTailscaleExitNode != null)
                      _StatusRow(
                        label: 'Tailscale exit',
                        value: net.selectedTailscaleExitNode!,
                      ),
                    if (net.selectedExitProfileId != null)
                      _StatusRow(
                        label: 'Exit profile',
                        value: _exitNodeLabel(net.selectedExitProfileId!),
                        mono: true,
                      ),
                    if (net.vpnExitRouteKind != 'none')
                      _StatusRow(
                        label: 'Exit path',
                        value: _exitRouteLabel(net.vpnExitRouteKind),
                      ),
                    const SizedBox(height: 8),
                    Text(
                      _routingImpactSummary(net),
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            // Traffic card
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Traffic',
                        style: Theme.of(context).textTheme.titleSmall),
                    const SizedBox(height: 12),
                    _StatusRow(
                      label: 'Bytes sent',
                      value: stats != null
                          ? _formatBytes(stats.bytesSent)
                          : '—',
                    ),
                    _StatusRow(
                      label: 'Bytes received',
                      value: stats != null
                          ? _formatBytes(stats.bytesReceived)
                          : '—',
                    ),
                    _StatusRow(
                      label: 'Bandwidth',
                      value: stats != null
                          ? '${stats.bandwidthKbps} kbps'
                          : '—',
                    ),
                    _StatusRow(
                      label: 'Packets lost',
                      value: '${stats?.packetsLost ?? 0}',
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            // Routing card
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Routing',
                        style: Theme.of(context).textTheme.titleSmall),
                    const SizedBox(height: 12),
                    _StatusRow(
                      label: 'Routing entries',
                      value: '${stats?.routingEntries ?? 0}',
                    ),
                    _StatusRow(
                      label: 'Gossip map size',
                      value: '${stats?.gossipMapSize ?? 0}',
                    ),
                    _StatusRow(
                      label: 'Delivered routes',
                      value: '${stats?.deliveredRoutes ?? 0}',
                    ),
                    _StatusRow(
                      label: 'Failed routes',
                      value: '${stats?.failedRoutes ?? 0}',
                    ),
                    _StatusRow(
                      label: 'Pending S&F messages',
                      value: '${stats?.sfPendingMessages ?? 0}',
                    ),
                  ],
                ),
              ),
            ),
            if (s != null) ...[
              const SizedBox(height: 12),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Node mode',
                          style: Theme.of(context).textTheme.titleSmall),
                      const SizedBox(height: 12),
                      _StatusRow(
                        label: 'Mode',
                        value: _nodeModeName(s.nodeMode),
                      ),
                      _StatusRow(
                        label: 'Pairing code',
                        value: (s.pairingCode?.isNotEmpty ?? false)
                            ? s.pairingCode!
                            : '—',
                        mono: true,
                      ),
                    ],
                  ),
                ),
              ),
            ],

            // ── Quick links to sub-screens ─────────────────────────────
            // MetricsScreen and AppConnectorScreen are separate destinations
            // rather than inline content — they're too detailed for a status
            // overview but reachable with one tap from here.
            const SizedBox(height: 12),
            ListTile(
              leading: const Icon(Icons.analytics_outlined),
              title: const Text('Detailed metrics'),
              subtitle: const Text('Transport, routing, and traffic counters'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => const MetricsScreen(),
                ),
              ),
            ),
            ListTile(
              leading: const Icon(Icons.route_outlined),
              title: const Text('Exit Node'),
              subtitle: const Text('Route internet traffic through a trusted contact'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => const ExitNodeScreen(),
                ),
              ),
            ),
            ListTile(
              leading: const Icon(Icons.apps_outlined),
              title: const Text('App Connector'),
              subtitle: const Text('Choose which apps follow your mesh route'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => const AppConnectorScreen(),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  String _nodeModeName(int mode) => switch (mode) {
    0 => 'Leaf',
    1 => 'Relay',
    2 => 'Full node',
    _ => 'Custom mode $mode',
  };

  String _routingModeLabel(String mode) => switch (mode) {
    'mesh_only' => 'Mesh only',
    'exit_node' => 'Exit node',
    'policy_based' => 'Policy-based',
    _ => 'Off',
  };

  String _routingStatusLabel(String status) => switch (status) {
    'connected' => 'Connected',
    'connecting' => 'Connecting',
    'blocked' => 'Blocked',
    'disconnecting' => 'Disconnecting',
    _ => 'Inactive',
  };

  String _exitNodeLabel(String peerId) =>
      peerId.length > 12 ? '${peerId.substring(0, 12)}...' : peerId;

  String _routingImpactSummary(NetworkState net) {
    return switch (net.vpnSecurityPosture) {
      'mesh_only' =>
        'Mesh-routed traffic stays inside the mesh. Your usual internet path '
        'does not change.',
      'exit_node_profile' =>
        'Traffic leaves through the selected exit node and then through that '
        'node\'s chosen network profile. Websites see that profile\'s egress IP.',
      'exit_node' =>
        net.vpnExitNodeSeesDestinations
            ? 'Internet traffic leaves through the selected exit node. '
              'Websites see that node\'s IP, and the operator can see '
              'destinations after traffic leaves the mesh.'
            : 'Internet traffic leaves through the selected exit route with '
              'additional protection before it reaches the public internet.',
      'policy_based_profile' =>
        net.vpnExitNodeSeesDestinations
            ? 'Different traffic can take different paths, including exit '
              'profiles. That means some apps may leave through an operator-'
              'controlled route with a different public IP.'
            : 'Different traffic can take different paths through saved rules, '
              'including profile-based exits.',
      'policy_based' =>
        net.vpnExitNodeSeesDestinations
            ? 'Different traffic can take different paths. Some rules may send '
              'traffic out through an exit node, which can then see internet '
              'destinations.'
            : 'Different traffic can take different paths. Saved rules decide '
              'which apps stay on the normal network and which use the mesh.',
      _ =>
        'No mesh VPN routing is active. Your traffic keeps its normal network path.',
    };
  }

  String _exitRouteLabel(String routeKind) => switch (routeKind) {
    'peer_exit' => 'Trusted peer exit',
    'profile_exit' => 'Exit profile',
    'profile_only' => 'Profile-defined exit',
    _ => 'None',
  };
}

class _StatusRow extends StatelessWidget {
  const _StatusRow({required this.label, required this.value, this.mono = false});
  final String label;
  final String value;
  final bool mono;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Text(
            label,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
          ),
          const Spacer(),
          Text(
            value,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  fontFamily: mono ? 'monospace' : null,
                  fontWeight: FontWeight.w600,
                ),
          ),
        ],
      ),
    );
  }
}
