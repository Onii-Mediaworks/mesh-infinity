import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../network_state.dart';
import '../../peers/peers_state.dart';
import '../../../backend/models/peer_models.dart';

/// VPN mode values matching the backend protocol.
enum VpnMode {
  off('off', 'Off'),
  meshOnly('mesh_only', 'Mesh Only'),
  exitNode('exit_node', 'Exit Node'),
  policyBased('policy_based', 'Policy-Based');

  const VpnMode(this.value, this.label);

  final String value;
  final String label;

  static VpnMode fromString(String v) =>
      VpnMode.values.firstWhere((e) => e.value == v, orElse: () => VpnMode.off);
}

/// VPN settings screen -- mode selection, exit node picker, kill switch,
/// and connection status.  Described in spec section 13.
class VpnScreen extends StatelessWidget {
  const VpnScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final peers = context.watch<PeersState>();
    final currentMode = VpnMode.fromString(net.vpnMode);
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Mesh VPN'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: net.loadAll,
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: ListView(
          children: [
            // ---- Mode Selector ----
            _Section(
              title: 'VPN Mode',
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                child: RadioGroup<VpnMode>(
                  groupValue: currentMode,
                  onChanged: (selected) {
                    if (selected == null) return;
                    _onModeChanged(context, net, selected);
                  },
                  child: Column(
                    children: [
                      for (final mode in VpnMode.values)
                        RadioListTile<VpnMode>(
                          title: Text(mode.label),
                          subtitle: Text(_modeDescription(mode)),
                          value: mode,
                        ),
                    ],
                  ),
                ),
              ),
            ),

            const Divider(height: 1),

            _Section(
              title: 'Security Impact',
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                child: Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          _securityHeadline(currentMode),
                          style: theme.textTheme.titleSmall,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          _securityBodyFromState(net),
                          style: theme.textTheme.bodyMedium,
                        ),
                        if (net.vpnExitNodeSeesDestinations) ...[
                          const SizedBox(height: 12),
                          Text(
                            'When traffic leaves through an exit node, the '
                            'operator can see its destinations after it leaves '
                            'the mesh. The kill switch helps prevent fallback '
                            'leaks if that route drops.',
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
              ),
            ),

            const Divider(height: 1),

            // ---- Exit Node Section ----
            if (currentMode == VpnMode.exitNode) ...[
              _Section(
                title: 'Exit Node',
                child: _ExitNodePicker(
                  peers: peers.peers,
                  tailscaleExitNodes: (net.tailscaleOverlay['exitNodes'] as List?)
                          ?.whereType<Map>()
                          .map((entry) => Map<String, dynamic>.from(entry))
                          .toList() ??
                      const <Map<String, dynamic>>[],
                  selectedId: net.selectedExitNodeId,
                  selectedTailscaleExitNode: net.selectedTailscaleExitNode,
                  onSelectedMesh: (peerId) {
                    net.setVpnMode(VpnMode.exitNode.value, exitNodePeerId: peerId);
                  },
                  onSelectedTailscale: (peerName) {
                    net.setVpnMode(VpnMode.exitNode.value, tailscaleExitNode: peerName);
                  },
                ),
              ),
              const Divider(height: 1),
            ],

            // ---- Kill Switch ----
            if (net.isVpnActive) ...[
              _Section(
                title: 'Kill Switch',
                child: Column(
                  children: [
                    SwitchListTile(
                      secondary: const Icon(Icons.block_outlined),
                      title: const Text('Block all traffic if VPN disconnects'),
                      subtitle: const Text(
                        'When enabled, all network traffic is blocked if the '
                        'VPN tunnel drops unexpectedly. This prevents data leaks '
                        'but may cause temporary loss of connectivity.',
                      ),
                      value: net.vpnKillSwitch,
                      onChanged: (v) => net.setVpnKillSwitch(v),
                    ),
                  ],
                ),
              ),
              const Divider(height: 1),
            ],

            // ---- Status Section ----
            if (net.isVpnActive) ...[
              _Section(
                title: 'Status',
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                  child: Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        children: [
                          _StatusRow(
                            label: 'Mode',
                            value: currentMode.label,
                          ),
                          if (currentMode == VpnMode.exitNode &&
                              net.selectedExitNodeId != null)
                            _StatusRow(
                              label: 'Exit Node',
                              value: _exitNodeName(
                                peers.peers,
                                net.selectedExitNodeId!,
                              ),
                            ),
                          if (currentMode == VpnMode.exitNode &&
                              net.selectedTailscaleExitNode != null)
                            _StatusRow(
                              label: 'Tailscale Exit',
                              value: net.selectedTailscaleExitNode!,
                            ),
                          if (net.selectedExitProfileId != null)
                            _StatusRow(
                              label: 'Exit Profile',
                              value: _shortId(net.selectedExitProfileId!),
                            ),
                          if (net.vpnExitRouteKind != 'none')
                            _StatusRow(
                              label: 'Exit Path',
                              value: _exitRouteLabel(net.vpnExitRouteKind),
                            ),
                          _StatusRow(
                            label: 'Connection',
                            value: _connectionStatusLabel(net.vpnConnectionStatus),
                            trailing: _connectionStatusDot(
                              theme,
                              net.vpnConnectionStatus,
                            ),
                          ),
                          if (net.vpnConnectionStatus == 'connected')
                            _StatusRow(
                              label: 'Uptime',
                              value: _formatUptime(net.vpnUptimeSeconds),
                            ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ],

            // ---- Empty state when VPN is off ----
            if (!net.isVpnActive)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 32, 16, 32),
                child: Column(
                  children: [
                    Icon(
                      Icons.vpn_lock_outlined,
                      size: 64,
                      color: theme.colorScheme.outline,
                    ),
                    const SizedBox(height: 16),
                    Text(
                      'VPN is off',
                      style: theme.textTheme.titleMedium?.copyWith(
                        color: theme.colorScheme.outline,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Select a VPN mode above to route your traffic '
                      'through the mesh network or an exit node.',
                      textAlign: TextAlign.center,
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.outline,
                      ),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }

  /// Fires when the user taps a VPN mode radio button.
  void _onModeChanged(BuildContext context, NetworkState net, VpnMode mode) {
    if (mode == VpnMode.exitNode) {
      net.setVpnMode(
        mode.value,
        exitNodePeerId: net.selectedExitNodeId,
        tailscaleExitNode: net.selectedTailscaleExitNode,
      );
    } else {
      net.setVpnMode(mode.value);
    }
  }

  String _modeDescription(VpnMode mode) => switch (mode) {
        VpnMode.off => 'Keep using your normal network path',
        VpnMode.meshOnly => 'Keep selected traffic inside the mesh without changing your public IP',
        VpnMode.exitNode => 'Send internet traffic out through a trusted exit node',
        VpnMode.policyBased => 'Let saved rules decide which traffic uses the mesh',
      };

  String _securityHeadline(VpnMode mode) => switch (mode) {
        VpnMode.off => 'Normal internet path',
        VpnMode.meshOnly => 'Mesh traffic is protected, internet traffic is unchanged',
        VpnMode.exitNode => 'Your IP changes, and the exit path matters',
        VpnMode.policyBased => 'Security depends on the rules you create',
      };

  String _securityBodyFromState(NetworkState net) => switch (net.vpnSecurityPosture) {
        'mesh_only' =>
          'Only mesh destinations use the mesh. Regular internet traffic still '
          'uses your normal connection.',
        'exit_node_profile' =>
          'Traffic leaves through an exit node and then through that node\'s '
          'selected network profile. Websites see the profile\'s egress IP, '
          'while the exit operator still controls the handoff into that route.',
        'exit_node' =>
          'Websites see the exit node\'s IP instead of yours. Your mesh '
          'identity stays hidden from the operator, but the operator can still '
          'see where your traffic goes after it leaves the mesh.',
        'policy_based_profile' =>
          'Different traffic can take different paths. Some rules may use an '
          'exit profile, which changes the public IP and adds another trust '
          'boundary to that traffic.',
        'policy_based' =>
          'Different traffic can take different paths. Some rules may stay in '
          'the mesh, some may use an exit node, and some may go directly to '
          'the internet.',
        _ =>
          'Mesh VPN is not affecting your internet traffic. Websites and '
          'networks see your normal connection as usual.',
      };

  String _connectionStatusLabel(String status) => switch (status) {
        'connected' => 'Connected',
        'connecting' => 'Connecting',
        'blocked' => 'Blocked by kill switch',
        'disconnecting' => 'Disconnecting',
        _ => 'Disconnected',
      };

  Widget _connectionStatusDot(ThemeData theme, String status) {
    final Color color;
    switch (status) {
      case 'connected':
        color = Colors.green;
      case 'connecting':
        color = Colors.orange;
      case 'blocked':
        color = theme.colorScheme.error;
      case 'disconnecting':
        color = theme.colorScheme.outline;
      default:
        color = theme.colorScheme.outline;
    }
    return Container(
      width: 10,
      height: 10,
      decoration: BoxDecoration(shape: BoxShape.circle, color: color),
    );
  }

  String _exitNodeName(List<PeerModel> peers, String peerId) {
    final match = peers.where((p) => p.id == peerId);
    if (match.isEmpty) {
      return peerId.length > 16 ? '${peerId.substring(0, 16)}...' : peerId;
    }
    return match.first.name.isNotEmpty ? match.first.name : peerId;
  }

  String _shortId(String value) =>
      value.length > 16 ? '${value.substring(0, 16)}...' : value;

  String _exitRouteLabel(String routeKind) => switch (routeKind) {
        'peer_exit' => 'Trusted peer exit',
        'tailscale_exit' => 'Tailscale exit',
        'tailscale_profile_exit' => 'Tailscale exit with profile',
        'profile_exit' => 'Exit profile',
        'profile_only' => 'Profile-defined exit',
        _ => 'None',
      };

  String _formatUptime(int seconds) {
    if (seconds < 60) return '${seconds}s';
    if (seconds < 3600) return '${seconds ~/ 60}m ${seconds % 60}s';
    final h = seconds ~/ 3600;
    final m = (seconds % 3600) ~/ 60;
    return '${h}h ${m}m';
  }
}

// ---------------------------------------------------------------------------
// Exit Node Picker
// ---------------------------------------------------------------------------

class _ExitNodePicker extends StatelessWidget {
  const _ExitNodePicker({
    required this.peers,
    required this.tailscaleExitNodes,
    required this.selectedId,
    required this.selectedTailscaleExitNode,
    required this.onSelectedMesh,
    required this.onSelectedTailscale,
  });

  final List<PeerModel> peers;
  final List<Map<String, dynamic>> tailscaleExitNodes;
  final String? selectedId;
  final String? selectedTailscaleExitNode;
  final ValueChanged<String> onSelectedMesh;
  final ValueChanged<String> onSelectedTailscale;

  @override
  Widget build(BuildContext context) {
    final exitNodes = peers.where((p) => p.canBeExitNode).toList();
    final theme = Theme.of(context);

    if (exitNodes.isEmpty && tailscaleExitNodes.isEmpty) {
      return Padding(
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        child: Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                Icon(
                  Icons.cloud_off_outlined,
                  size: 40,
                  color: theme.colorScheme.outline,
                ),
                const SizedBox(height: 12),
                Text(
                  'No exit nodes available',
                  style: theme.textTheme.titleSmall,
                ),
                const SizedBox(height: 8),
                Text(
                  'No mesh exits or Tailscale exits are available right now. '
                  'A trusted peer can offer a mesh exit, or a connected '
                  'tailnet can offer a Tailscale exit node.',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.outline,
                  ),
                ),
              ],
            ),
          ),
        ),
      );
    }

    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
      child: Column(
        children: [
          for (final node in exitNodes)
            Card(
              clipBehavior: Clip.antiAlias,
              child: ListTile(
                leading: Icon(
                  Icons.exit_to_app_outlined,
                  color: node.id == selectedId
                      ? theme.colorScheme.primary
                      : null,
                ),
                title: Text(
                  node.name.isNotEmpty ? node.name : node.id,
                  style: node.id == selectedId
                      ? TextStyle(
                          fontWeight: FontWeight.bold,
                          color: theme.colorScheme.primary,
                        )
                      : null,
                ),
                subtitle: Row(
                  children: [
                    _PeerStatusDot(status: node.status),
                    const SizedBox(width: 6),
                    Text(node.status),
                    if (node.latencyMs != null) ...[
                      const SizedBox(width: 12),
                      Icon(Icons.timer_outlined, size: 14,
                          color: theme.colorScheme.outline),
                      const SizedBox(width: 2),
                      Text('${node.latencyMs}ms'),
                    ],
                  ],
                ),
                trailing: node.id == selectedId
                    ? Icon(Icons.check_circle, color: theme.colorScheme.primary)
                    : const Icon(Icons.circle_outlined),
                onTap: () => onSelectedMesh(node.id),
              ),
            ),
          for (final node in tailscaleExitNodes)
            Card(
              clipBehavior: Clip.antiAlias,
              child: ListTile(
                leading: Icon(
                  Icons.route_outlined,
                  color: (node['name'] as String?) == selectedTailscaleExitNode
                      ? Colors.orange.shade700
                      : Colors.orange.shade400,
                ),
                title: Text(
                  node['name'] as String? ?? 'Tailscale exit',
                  style: (node['name'] as String?) == selectedTailscaleExitNode
                      ? TextStyle(
                          fontWeight: FontWeight.bold,
                          color: Colors.orange.shade700,
                        )
                      : null,
                ),
                subtitle: Builder(
                  builder: (context) {
                    final ip = node['ip'] as String?;
                    return Row(
                      children: [
                        Icon(
                          node['online'] == true ? Icons.circle : Icons.circle_outlined,
                          size: 10,
                          color: node['online'] == true
                              ? Colors.orange.shade700
                              : theme.colorScheme.outline,
                        ),
                        const SizedBox(width: 6),
                        Text(node['online'] == true ? 'Online' : 'Offline'),
                        if (ip != null && ip.isNotEmpty) ...[
                          const SizedBox(width: 12),
                          Icon(Icons.language_outlined, size: 14,
                              color: theme.colorScheme.outline),
                          const SizedBox(width: 2),
                          Text(ip),
                        ],
                      ],
                    );
                  },
                ),
                trailing: (node['name'] as String?) == selectedTailscaleExitNode
                    ? Icon(Icons.check_circle, color: Colors.orange.shade700)
                    : const Icon(Icons.circle_outlined),
                onTap: () => onSelectedTailscale(node['name'] as String? ?? ''),
              ),
            ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Shared small widgets
// ---------------------------------------------------------------------------

class _PeerStatusDot extends StatelessWidget {
  const _PeerStatusDot({required this.status});

  final String status;

  @override
  Widget build(BuildContext context) {
    final Color color;
    switch (status) {
      case 'online':
        color = Colors.green;
      case 'idle':
        color = Colors.orange;
      default:
        color = Colors.grey;
    }
    return Container(
      width: 8,
      height: 8,
      decoration: BoxDecoration(shape: BoxShape.circle, color: color),
    );
  }
}

class _StatusRow extends StatelessWidget {
  const _StatusRow({
    required this.label,
    required this.value,
    this.trailing,
  });

  final String label;
  final String value;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          SizedBox(
            width: 100,
            child: Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.outline,
              ),
            ),
          ),
          Expanded(
            child: Text(value, style: theme.textTheme.bodyMedium),
          ),
          if (trailing != null) trailing!,
        ],
      ),
    );
  }
}

class _Section extends StatelessWidget {
  const _Section({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 20, 16, 8),
          child: Text(
            title,
            style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        child,
      ],
    );
  }
}
