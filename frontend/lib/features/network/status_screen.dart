import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'network_state.dart';
import 'screens/metrics_screen.dart';
import 'screens/exit_node_screen.dart';
import 'screens/app_connector_screen.dart';

/// NetworkStatusScreen — the overview card in the Network section's Status tab.
///
/// Provides a quick summary of the most important network health indicators
/// without drowning the user in raw counters.  Detailed data is reachable via
/// the three quick-link tiles at the bottom.
///
/// Sections:
///   1. Connection — peer count, WireGuard sessions, clearnet connections,
///      average latency.
///   2. Routing posture — VPN mode, connection status, kill switch, exit node
///      or profile, and a plain-language privacy summary.
///   3. Traffic — cumulative bytes sent/received, bandwidth, packet loss.
///   4. Routing — routing table size, gossip map, delivered/failed routes,
///      Store-and-Forward backlog.
///   5. Node mode — client/relay/full-node designation and pairing code.
///   6. Quick links — one-tap navigation to MetricsScreen, ExitNodeScreen,
///      and AppConnectorScreen.
///
/// All values come from [NetworkState].  Pull-to-refresh calls
/// [NetworkState.loadAll] which re-fetches everything from the Rust backend.
class NetworkStatusScreen extends StatelessWidget {
  const NetworkStatusScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final stats = net.stats;
    // s may be null before the first loadAll() completes.
    final s = net.settings;

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // ── Connection health ─────────────────────────────────────────
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
                    // wireGuardSessions: the number of active WireGuard
                    // key-exchange tunnels.  Each session = one secured peer link.
                    _StatusRow(
                      label: 'WireGuard sessions',
                      value: '${stats?.wireGuardSessions ?? 0}',
                    ),
                    // clearnetConnections: active TCP/IP connections not using
                    // an anonymising overlay (Tor/I2P).
                    _StatusRow(
                      label: 'Clearnet connections',
                      value: '${stats?.clearnetConnections ?? 0}',
                    ),
                    // null stats = no data yet; show "—" instead of 0 to signal
                    // "we don't know" rather than "latency is zero".
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

            // ── Routing posture ────────────────────────────────────────────
            // Answers: "is the VPN on, and what does it do to my traffic?"
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
                    // selectedExitNodeId is null when no mesh-peer exit is
                    // chosen, so we only show this row when it is set.
                    if (net.selectedExitNodeId != null)
                      _StatusRow(
                        label: 'Exit node',
                        // Show a truncated ID rather than the full 64-char hex.
                        value: _exitNodeLabel(net.selectedExitNodeId!),
                        mono: true,
                      ),
                    // Tailscale exit: separate from mesh peer exit.
                    if (net.selectedTailscaleExitNode != null)
                      _StatusRow(
                        label: 'Tailscale exit',
                        value: net.selectedTailscaleExitNode!,
                      ),
                    // Exit profile: an additional routing layer applied on top
                    // of the exit node path.
                    if (net.selectedExitProfileId != null)
                      _StatusRow(
                        label: 'Exit profile',
                        value: _exitNodeLabel(net.selectedExitProfileId!),
                        mono: true,
                      ),
                    // vpnExitRouteKind classifies the active exit path type;
                    // "none" means no exit path is in use.
                    if (net.vpnExitRouteKind != 'none')
                      _StatusRow(
                        label: 'Exit path',
                        value: _exitRouteLabel(net.vpnExitRouteKind),
                      ),
                    const SizedBox(height: 8),
                    // Plain-language impact summary derived from the backend's
                    // composite vpnSecurityPosture code.
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

            // ── Traffic ────────────────────────────────────────────────────
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Traffic',
                        style: Theme.of(context).textTheme.titleSmall),
                    const SizedBox(height: 12),
                    // Show "—" when stats is null rather than claiming 0 bytes.
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

            // ── Routing table ──────────────────────────────────────────────
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Routing',
                        style: Theme.of(context).textTheme.titleSmall),
                    const SizedBox(height: 12),
                    // routingEntries: number of destination→next-hop mappings
                    // in the local routing table.
                    _StatusRow(
                      label: 'Routing entries',
                      value: '${stats?.routingEntries ?? 0}',
                    ),
                    // gossipMapSize: nodes known via gossip advertisements from
                    // connected peers — the "world map" of the mesh.
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
                    // sfPendingMessages: messages buffered in Store-and-Forward
                    // waiting for an offline destination to come online.
                    _StatusRow(
                      label: 'Pending S&F messages',
                      value: '${stats?.sfPendingMessages ?? 0}',
                    ),
                  ],
                ),
              ),
            ),

            // ── Node mode ─────────────────────────────────────────────────
            // Only rendered when settings have loaded; s is null before then.
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
                      // Mode 0 = leaf/client, 1 = relay, 2 = full node.
                      _StatusRow(
                        label: 'Mode',
                        value: _nodeModeName(s.nodeMode),
                      ),
                      // pairingCode: a short alphanumeric code that can be
                      // shared with another user to initiate pairing.
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

            // ── Quick links to sub-screens ─────────────────────────────────
            // MetricsScreen, ExitNodeScreen, and AppConnectorScreen are
            // separate destinations rather than inline content because they
            // are too detailed for a status overview.  One-tap reachability
            // here keeps the path short for users who navigate to them often.
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

  /// Formats a raw byte count into a human-readable binary-unit string.
  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  /// Maps the integer node-mode value to a label.
  ///
  /// 0 = Leaf: standard end-user node that does not forward traffic.
  /// 1 = Relay: forwards encrypted packets for peers that can't reach each other.
  /// 2 = Full node: participates in both leaf and relay roles.
  String _nodeModeName(int mode) => switch (mode) {
    0 => 'Leaf',
    1 => 'Relay',
    2 => 'Full node',
    _ => 'Custom mode $mode',
  };

  String _routingModeLabel(String mode) => switch (mode) {
    'mesh_only'    => 'Mesh only',
    'exit_node'    => 'Exit node',
    'policy_based' => 'Policy-based',
    _              => 'Off',
  };

  String _routingStatusLabel(String status) => switch (status) {
    'connected'     => 'Connected',
    'connecting'    => 'Connecting',
    'blocked'       => 'Blocked',
    'disconnecting' => 'Disconnecting',
    _               => 'Inactive',
  };

  /// Truncates a long peer or profile ID for compact display.
  String _exitNodeLabel(String peerId) =>
      peerId.length > 12 ? '${peerId.substring(0, 12)}...' : peerId;

  /// Returns a plain-language description of the current routing privacy impact.
  ///
  /// The vpnSecurityPosture code is owned by the Rust backend and combines
  /// VPN mode with exit-path details into a single summary key.
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
            // The exit node operator can observe which internet destinations
            // the user visits after traffic leaves the mesh.
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

  /// Maps backend exit-route-kind string to a display label.
  String _exitRouteLabel(String routeKind) => switch (routeKind) {
    'peer_exit'    => 'Trusted peer exit',
    'profile_exit' => 'Exit profile',
    'profile_only' => 'Profile-defined exit',
    _              => 'None',
  };
}

/// _StatusRow — a labelled key/value row used throughout the status cards.
///
/// [mono] enables monospace font for values like IDs and pairing codes.
class _StatusRow extends StatelessWidget {
  const _StatusRow({required this.label, required this.value, this.mono = false});

  final String label;
  final String value;

  /// When true the value is displayed in monospace, suitable for hex IDs and
  /// pairing codes that must be read character-by-character.
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
