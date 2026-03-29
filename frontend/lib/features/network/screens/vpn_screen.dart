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
        title: const Text('VPN Settings'),
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

            // ---- Exit Node Section ----
            if (currentMode == VpnMode.exitNode) ...[
              _Section(
                title: 'Exit Node',
                child: _ExitNodePicker(
                  peers: peers.peers,
                  selectedId: net.selectedExitNodeId,
                  onSelected: (peerId) {
                    net.setVpnMode(VpnMode.exitNode.value, exitNodePeerId: peerId);
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
      // When switching to exit node mode without a previously selected node,
      // just set the mode -- the user picks a node from the list below.
      net.setVpnMode(mode.value, exitNodePeerId: net.selectedExitNodeId);
    } else {
      net.setVpnMode(mode.value);
    }
  }

  String _modeDescription(VpnMode mode) => switch (mode) {
        VpnMode.off => 'No VPN active -- traffic uses standard routing',
        VpnMode.meshOnly => 'Only mesh traffic is routed through the tunnel',
        VpnMode.exitNode => 'All traffic routed through a selected exit node',
        VpnMode.policyBased => 'Custom per-app or per-destination rules',
      };

  String _connectionStatusLabel(String status) => switch (status) {
        'connected' => 'Connected',
        'connecting' => 'Connecting...',
        _ => 'Disconnected',
      };

  Widget _connectionStatusDot(ThemeData theme, String status) {
    final Color color;
    switch (status) {
      case 'connected':
        color = Colors.green;
      case 'connecting':
        color = Colors.orange;
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
    required this.selectedId,
    required this.onSelected,
  });

  final List<PeerModel> peers;
  final String? selectedId;
  final ValueChanged<String> onSelected;

  @override
  Widget build(BuildContext context) {
    final exitNodes = peers.where((p) => p.canBeExitNode).toList();
    final theme = Theme.of(context);

    if (exitNodes.isEmpty) {
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
                  'Exit nodes are peers that have opted in to relay your '
                  'traffic to the wider internet. None of your connected '
                  'peers currently advertise this capability. Ask a trusted '
                  'peer to enable exit node mode, or check back later.',
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
                onTap: () => onSelected(node.id),
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
