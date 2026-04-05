import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app/app_theme.dart';
import '../../../backend/models/peer_models.dart';
import '../../peers/peers_state.dart';
import '../network_state.dart';

/// ExitNodeScreen lets the user pick which trusted contact, if any,
/// should route their internet traffic.
///
/// The backend currently exposes real exit-node availability through peer
/// capabilities and real connection state through NetworkState. This screen
/// intentionally sticks to that real state instead of inventing profile
/// options the backend does not yet advertise.
class ExitNodeScreen extends StatefulWidget {
  const ExitNodeScreen({super.key});

  @override
  State<ExitNodeScreen> createState() => _ExitNodeScreenState();
}

class _ExitNodeScreenState extends State<ExitNodeScreen> {
  /// The legal warning is shown once per screen session before connecting.
  bool _legalWarningShown = false;

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final peers = context.watch<PeersState>();
    final meshExitNodes = peers.peers.where((p) => p.canBeExitNode).toList()
      ..sort(_compareExitNodes);
    final tailscaleExitNodes = (net.tailscaleOverlay['exitNodes'] as List?)
            ?.whereType<Map>()
            .map((entry) => Map<String, dynamic>.from(entry))
            .toList() ??
        const <Map<String, dynamic>>[];

    return Scaffold(
      appBar: AppBar(
        title: const Text('Exit Nodes'),
        actions: [
          if (net.selectedExitNodeId != null || net.selectedTailscaleExitNode != null)
            TextButton(
              onPressed: () => _disconnect(context, net),
              child: const Text('Disconnect'),
            ),
        ],
      ),
      body: Column(
        children: [
          _ExplanationBanner(
            mode: net.vpnMode,
            selectedExitNodeId: net.selectedExitNodeId,
            connectionStatus: net.vpnConnectionStatus,
          ),
          Expanded(
            child: meshExitNodes.isEmpty && tailscaleExitNodes.isEmpty
                ? const _EmptyState(
                    title: 'No exit nodes available',
                    body: 'Mesh exit peers and Tailscale exit nodes appear here '
                        'when they are available.',
                    icon: Icons.route_outlined,
                  )
                : RefreshIndicator(
                    onRefresh: net.loadAll,
                    child: ListView.separated(
                      itemCount: meshExitNodes.length + tailscaleExitNodes.length,
                      separatorBuilder: (_, _) => const Divider(height: 1),
                      itemBuilder: (context, index) {
                        if (index < meshExitNodes.length) {
                          final peer = meshExitNodes[index];
                          final isActive =
                              peer.id == net.selectedExitNodeId && net.vpnMode == 'exit_node';
                          return _ExitNodeTile(
                            peer: peer,
                            isActive: isActive,
                            connectionStatus: net.vpnConnectionStatus,
                            onUse: () => _connectMesh(context, net, peer),
                            onDisconnect: () => _disconnect(context, net),
                          );
                        }
                        final entry = tailscaleExitNodes[index - meshExitNodes.length];
                        final name = entry['name'] as String? ?? 'Exit node';
                        final ip = entry['ip'] as String? ?? '';
                        final online = entry['online'] == true;
                        final isActive = name == net.selectedTailscaleExitNode &&
                            net.vpnMode == 'exit_node';
                        return _TailscaleExitNodeTile(
                          name: name,
                          ip: ip,
                          online: online,
                          isActive: isActive,
                          connectionStatus: net.vpnConnectionStatus,
                          onUse: () => _connectTailscale(context, net, name),
                          onDisconnect: () => _disconnect(context, net),
                        );
                      },
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  int _compareExitNodes(PeerModel a, PeerModel b) {
    if (a.isOnline != b.isOnline) {
      return a.isOnline ? -1 : 1;
    }
    final trustCompare = b.trustLevel.value.compareTo(a.trustLevel.value);
    if (trustCompare != 0) return trustCompare;
    final latencyA = a.latencyMs ?? 1 << 30;
    final latencyB = b.latencyMs ?? 1 << 30;
    final latencyCompare = latencyA.compareTo(latencyB);
    if (latencyCompare != 0) return latencyCompare;
    return _displayName(a).compareTo(_displayName(b));
  }

  Future<void> _connectMesh(
    BuildContext context,
    NetworkState net,
    PeerModel peer,
  ) async {
    if (!_legalWarningShown) {
      final proceed = await _showLegalWarning(context);
      if (!proceed) return;
      _legalWarningShown = true;
    }

    final ok = await net.setVpnMode('exit_node', exitNodePeerId: peer.id);
    if (!context.mounted) return;

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          ok
              ? 'Routing through ${_displayName(peer)}'
              : 'Couldn\'t enable that exit node right now',
        ),
      ),
    );
  }

  Future<void> _connectTailscale(
    BuildContext context,
    NetworkState net,
    String peerName,
  ) async {
    if (!_legalWarningShown) {
      final proceed = await _showLegalWarning(context, tailscale: true);
      if (!proceed) return;
      _legalWarningShown = true;
    }

    final ok = await net.setVpnMode('exit_node', tailscaleExitNode: peerName);
    if (!context.mounted) return;

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          ok
              ? 'Routing through Tailscale exit $peerName'
              : 'Couldn\'t enable that Tailscale exit node right now',
        ),
      ),
    );
  }

  Future<void> _disconnect(BuildContext context, NetworkState net) async {
    final ok = await net.setVpnMode('off');
    if (!context.mounted) return;

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          ok ? 'Exit node disconnected' : 'Couldn\'t disconnect the exit node',
        ),
      ),
    );
  }

  Future<bool> _showLegalWarning(BuildContext context, {bool tailscale = false}) async {
    return await showDialog<bool>(
          context: context,
          builder: (_) => AlertDialog(
            title: const Text('Before you connect'),
            content: Text(
              tailscale
                  ? 'Traffic routed through a Tailscale exit node appears to come from that node. '
                      'The exit node operator can see your clearnet destinations, and the Tailscale '
                      'or Headscale control plane still knows the device topology.\n\n'
                      'Use Tailscale exit nodes only when that tradeoff is acceptable.'
                  : 'Traffic routed through an exit node appears to come from that '
                      'node\'s internet connection. The operator can see which '
                      'destinations you reach.\n\n'
                      'Use exit nodes run by people you trust.',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('Connect'),
              ),
            ],
          ),
        ) ??
        false;
  }

  static String _displayName(PeerModel peer) =>
      peer.name.isNotEmpty ? peer.name : peer.id;
}

class _ExplanationBanner extends StatelessWidget {
  const _ExplanationBanner({
    required this.mode,
    required this.selectedExitNodeId,
    required this.connectionStatus,
  });

  final String mode;
  final String? selectedExitNodeId;
  final String connectionStatus;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      width: double.infinity,
      color: theme.colorScheme.surfaceContainerHighest,
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            _headline(),
            style: theme.textTheme.titleSmall,
          ),
          const SizedBox(height: 4),
          Text(
            _body(),
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  String _headline() {
    if (mode == 'exit_node' && selectedExitNodeId != null) {
      return switch (connectionStatus) {
        'connected' => 'Internet traffic is using an exit node',
        'connecting' => 'Connecting to your exit node',
        'blocked' => 'Exit-node traffic is blocked',
        'disconnecting' => 'Disconnecting from your exit node',
        _ => 'Exit node selected',
      };
    }
    return 'Choose who should route your internet traffic';
  }

  String _body() {
    if (mode == 'exit_node' && selectedExitNodeId != null) {
      return 'Your mesh identity stays hidden from the operator, but the '
          'operator can still see where your traffic goes after it leaves '
          'the mesh.';
    }
    return 'Pick a trusted contact only when you want your internet traffic '
        'to leave through their connection. If you don\'t need that, keep '
        'Mesh VPN in another mode.';
  }
}

class _ExitNodeTile extends StatelessWidget {
  const _ExitNodeTile({
    required this.peer,
    required this.isActive,
    required this.connectionStatus,
    required this.onUse,
    required this.onDisconnect,
  });

  final PeerModel peer;
  final bool isActive;
  final String connectionStatus;
  final VoidCallback onUse;
  final VoidCallback onDisconnect;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      leading: CircleAvatar(
        radius: 20,
        backgroundColor: MeshTheme.brand.withValues(alpha: 0.15),
        child: Text(
          _avatarLabel(peer),
          style: theme.textTheme.titleSmall?.copyWith(color: MeshTheme.brand),
        ),
      ),
      title: Text(_displayName(peer)),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 4),
        child: Wrap(
          spacing: 8,
          runSpacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            _StatusChip(
              icon: peer.trustLevel.icon,
              label: peer.trustLevel.label,
              color: peer.trustLevel.color,
            ),
            _StatusChip(
              icon: peer.isOnline ? Icons.circle : Icons.circle_outlined,
              label: peer.isOnline ? 'Online' : 'Offline',
              color: peer.isOnline
                  ? MeshTheme.secGreen
                  : theme.colorScheme.outline,
            ),
            if (peer.latencyMs != null)
              _StatusChip(
                icon: Icons.timer_outlined,
                label: '${peer.latencyMs} ms',
                color: theme.colorScheme.outline,
              ),
            if (isActive)
              _StatusChip(
                icon: Icons.route_outlined,
                label: _connectionLabel(connectionStatus),
                color: _connectionColor(theme, connectionStatus),
              ),
          ],
        ),
      ),
      trailing: isActive
          ? OutlinedButton(
              onPressed: onDisconnect,
              child: const Text('Disconnect'),
            )
          : FilledButton(
              onPressed: onUse,
              child: const Text('Use'),
            ),
    );
  }

  static String _displayName(PeerModel peer) =>
      peer.name.isNotEmpty ? peer.name : peer.id;

  static String _avatarLabel(PeerModel peer) {
    final label = _displayName(peer);
    return label.isEmpty ? '?' : label.substring(0, 1).toUpperCase();
  }

  static String _connectionLabel(String status) => switch (status) {
        'connected' => 'Connected',
        'connecting' => 'Connecting',
        'blocked' => 'Blocked',
        'disconnecting' => 'Disconnecting',
        _ => 'Selected',
      };

  static Color _connectionColor(ThemeData theme, String status) => switch (status) {
        'connected' => MeshTheme.secGreen,
        'connecting' => Colors.orange,
        'blocked' => theme.colorScheme.error,
        'disconnecting' => theme.colorScheme.outline,
        _ => theme.colorScheme.primary,
      };
}

class _TailscaleExitNodeTile extends StatelessWidget {
  const _TailscaleExitNodeTile({
    required this.name,
    required this.ip,
    required this.online,
    required this.isActive,
    required this.connectionStatus,
    required this.onUse,
    required this.onDisconnect,
  });

  final String name;
  final String ip;
  final bool online;
  final bool isActive;
  final String connectionStatus;
  final VoidCallback onUse;
  final VoidCallback onDisconnect;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      leading: CircleAvatar(
        radius: 20,
        backgroundColor: Colors.orange.withValues(alpha: 0.15),
        child: Icon(Icons.route_outlined, color: Colors.orange.shade700),
      ),
      title: Text(name),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 4),
        child: Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            _StatusChip(
              icon: online ? Icons.circle : Icons.circle_outlined,
              label: online ? 'Online' : 'Offline',
              color: online ? Colors.orange.shade700 : theme.colorScheme.outline,
            ),
            if (ip.isNotEmpty)
              _StatusChip(
                icon: Icons.language_outlined,
                label: ip,
                color: theme.colorScheme.outline,
              ),
            _StatusChip(
              icon: Icons.warning_amber_outlined,
              label: 'Tailscale exit',
              color: Colors.orange.shade700,
            ),
            if (isActive)
              _StatusChip(
                icon: Icons.route_outlined,
                label: _ExitNodeTile._connectionLabel(connectionStatus),
                color: _ExitNodeTile._connectionColor(theme, connectionStatus),
              ),
          ],
        ),
      ),
      trailing: isActive
          ? OutlinedButton(
              onPressed: onDisconnect,
              child: const Text('Disconnect'),
            )
          : FilledButton(
              onPressed: onUse,
              style: FilledButton.styleFrom(backgroundColor: Colors.orange.shade700),
              child: const Text('Use'),
            ),
    );
  }
}

class _StatusChip extends StatelessWidget {
  const _StatusChip({
    required this.icon,
    required this.label,
    required this.color,
  });

  final IconData icon;
  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.25)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 4),
          Text(
            label,
            style: Theme.of(context).textTheme.labelSmall?.copyWith(color: color),
          ),
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({
    required this.title,
    required this.body,
    required this.icon,
  });

  final String title;
  final String body;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 56, color: theme.colorScheme.outline),
            const SizedBox(height: 12),
            Text(title, style: theme.textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(
              body,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
