import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../network_state.dart';
import '../../peers/peers_state.dart';
import '../../../backend/models/peer_models.dart';

/// VpnMode — the four traffic-routing modes supported by the backend.
///
/// These strings must exactly match the `mode` field in the backend's VPN
/// status JSON.  Any change here must be coordinated with the Rust side.
enum VpnMode {
  /// VPN is completely off; all traffic uses the device's normal network path.
  off('off', 'Off'),

  /// Only traffic addressed to mesh peers routes through the mesh.  Regular
  /// internet traffic is unaffected and the device's public IP does not change.
  meshOnly('mesh_only', 'Mesh Only'),

  /// All internet traffic is routed through a chosen exit node.  Websites see
  /// the exit node's IP instead of the device's real IP.  The exit node
  /// operator can observe which internet destinations the traffic reaches after
  /// it leaves the mesh.
  exitNode('exit_node', 'Exit Node'),

  /// A rule engine decides per-app or per-destination which path to take.
  /// Security implications depend entirely on the rules the user has created.
  policyBased('policy_based', 'Policy-Based');

  const VpnMode(this.value, this.label);

  /// The backend string identifier for this mode.
  final String value;

  /// The human-readable label shown in the UI.
  final String label;

  /// Converts a raw backend string to the corresponding enum value.
  /// Falls back to [VpnMode.off] for any unknown string so the UI never
  /// shows a broken state — failing safe is better than failing noisily.
  static VpnMode fromString(String v) =>
      VpnMode.values.firstWhere((e) => e.value == v, orElse: () => VpnMode.off);
}

/// VpnScreen — mode selection, exit node picker, kill switch, and status.
///
/// Spec §13: "Traffic Routing" — this screen is the main control surface for
/// configuring how Mesh Infinity routes internet-bound traffic.
///
/// Layout:
///   1. VPN Mode radio group — selects between Off / Mesh Only / Exit Node /
///      Policy-Based.
///   2. Security Impact card — explains in plain language what the selected
///      mode implies for the user's privacy.
///   3. Exit Node section — visible only in exit-node mode; lets the user pick
///      which trusted peer (or Tailscale exit) should relay their traffic.
///   4. Kill Switch section — visible only when VPN is active.
///   5. Status card — live connection details.
///   6. Empty state — shown when VPN is off.
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
            // ── Mode Selector ─────────────────────────────────────────────
            // Each mode is a radio tile with a brief description so users can
            // understand what they are selecting without navigating away.
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
                          // _modeDescription gives a one-line plain-language
                          // summary so users understand what each mode does.
                          subtitle: Text(_modeDescription(mode)),
                          value: mode,
                        ),
                    ],
                  ),
                ),
              ),
            ),

            const Divider(height: 1),

            // ── Security Impact ────────────────────────────────────────────
            // This card is always visible so users can see the privacy
            // implications of the CURRENT mode without having to read docs.
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
                        // _securityBodyFromState reads the backend's posture
                        // code rather than deriving it from mode alone — the
                        // backend combines mode + exit-path into a single key.
                        Text(
                          _securityBodyFromState(net),
                          style: theme.textTheme.bodyMedium,
                        ),
                        // Extra exit-node operator warning when relevant.
                        // vpnExitNodeSeesDestinations = the backend has
                        // determined the current exit path has no additional
                        // privacy protection after it leaves the mesh.
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

            // ── Exit Node Section ──────────────────────────────────────────
            // Only shown in exit-node mode — the picker is irrelevant otherwise.
            if (currentMode == VpnMode.exitNode) ...[
              _Section(
                title: 'Exit Node',
                child: _ExitNodePicker(
                  peers: peers.peers,
                  // tailscaleExitNodes comes from the Tailscale overlay status
                  // map.  The cast chain handles both typed and untyped Maps
                  // returned from JSON decoding.
                  tailscaleExitNodes: (net.tailscaleOverlay['exitNodes'] as List?)
                          ?.whereType<Map>()
                          .map((entry) => Map<String, dynamic>.from(entry))
                          .toList() ??
                      const <Map<String, dynamic>>[],
                  selectedId: net.selectedExitNodeId,
                  selectedTailscaleExitNode: net.selectedTailscaleExitNode,
                  // Callbacks forward the selection immediately to the backend
                  // so the routing change takes effect without an extra "Save".
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

            // ── Kill Switch ────────────────────────────────────────────────
            // The kill switch is only meaningful when a VPN tunnel is active.
            // Showing it while VPN is off would be confusing.
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

            // ── Status Section ─────────────────────────────────────────────
            // Live status card: only rendered when the VPN is running.
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
                          // Exit node name — only relevant when a peer exit is active.
                          if (currentMode == VpnMode.exitNode &&
                              net.selectedExitNodeId != null)
                            _StatusRow(
                              label: 'Exit Node',
                              value: _exitNodeName(
                                peers.peers,
                                net.selectedExitNodeId!,
                              ),
                            ),
                          // Tailscale exit — separate from mesh peer exit.
                          if (currentMode == VpnMode.exitNode &&
                              net.selectedTailscaleExitNode != null)
                            _StatusRow(
                              label: 'Tailscale Exit',
                              value: net.selectedTailscaleExitNode!,
                            ),
                          // Exit profile — an additional routing layer applied
                          // on top of the exit node path.
                          if (net.selectedExitProfileId != null)
                            _StatusRow(
                              label: 'Exit Profile',
                              // Truncate long profile IDs to 16 chars for readability.
                              value: _shortId(net.selectedExitProfileId!),
                            ),
                          // vpnExitRouteKind classifies the active path type
                          // (peer exit, Tailscale exit, profile exit, etc.).
                          if (net.vpnExitRouteKind != 'none')
                            _StatusRow(
                              label: 'Exit Path',
                              value: _exitRouteLabel(net.vpnExitRouteKind),
                            ),
                          // Connection status with a coloured dot indicator.
                          _StatusRow(
                            label: 'Connection',
                            value: _connectionStatusLabel(net.vpnConnectionStatus),
                            trailing: _connectionStatusDot(
                              theme,
                              net.vpnConnectionStatus,
                            ),
                          ),
                          // Uptime — only meaningful once fully connected.
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

            // ── Empty state ────────────────────────────────────────────────
            // Shown when VPN is completely off — invites the user to pick a mode.
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

  /// Applies the selected VPN mode, preserving any existing exit node selection
  /// when switching to exit-node mode so the UI doesn't forget the last choice.
  void _onModeChanged(BuildContext context, NetworkState net, VpnMode mode) {
    if (mode == VpnMode.exitNode) {
      // Carry forward existing exit node selection when switching to exit-node
      // mode — avoids requiring the user to re-select an exit they already chose.
      net.setVpnMode(
        mode.value,
        exitNodePeerId: net.selectedExitNodeId,
        tailscaleExitNode: net.selectedTailscaleExitNode,
      );
    } else {
      net.setVpnMode(mode.value);
    }
  }

  /// One-line description of each mode shown as a radio subtitle.
  String _modeDescription(VpnMode mode) => switch (mode) {
        VpnMode.off          => 'Keep using your normal network path',
        VpnMode.meshOnly     => 'Keep selected traffic inside the mesh without changing your public IP',
        VpnMode.exitNode     => 'Send internet traffic out through a trusted exit node',
        VpnMode.policyBased  => 'Let saved rules decide which traffic uses the mesh',
      };

  /// One-line headline for the security impact card.
  String _securityHeadline(VpnMode mode) => switch (mode) {
        VpnMode.off          => 'Normal internet path',
        VpnMode.meshOnly     => 'Mesh traffic is protected, internet traffic is unchanged',
        VpnMode.exitNode     => 'Your IP changes, and the exit path matters',
        VpnMode.policyBased  => 'Security depends on the rules you create',
      };

  /// Returns the body text for the security impact card based on the backend's
  /// composite security posture code.  The posture code combines VPN mode with
  /// exit-path details, giving more nuanced descriptions than mode alone.
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

  /// Maps the backend connection status string to a display label.
  String _connectionStatusLabel(String status) => switch (status) {
        'connected'     => 'Connected',
        'connecting'    => 'Connecting',
        'blocked'       => 'Blocked by kill switch',
        'disconnecting' => 'Disconnecting',
        _               => 'Disconnected',
      };

  /// Returns a 10×10 colour dot indicating the connection health at a glance.
  Widget _connectionStatusDot(ThemeData theme, String status) {
    final Color color;
    switch (status) {
      case 'connected':
        color = Colors.green;
      case 'connecting':
        // Amber signals "in progress" — not yet healthy but not failed.
        color = Colors.orange;
      case 'blocked':
        // Red signals the kill-switch has halted traffic.
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

  /// Looks up a peer by ID and returns its display name.
  ///
  /// Falls back to a truncated peer ID when the peer is not found in the
  /// local list — this can happen if the peer was deleted after being selected
  /// as an exit node.
  String _exitNodeName(List<PeerModel> peers, String peerId) {
    final match = peers.where((p) => p.id == peerId);
    if (match.isEmpty) {
      // Truncate long IDs to 16 chars + ellipsis for readable display.
      return peerId.length > 16 ? '${peerId.substring(0, 16)}...' : peerId;
    }
    return match.first.name.isNotEmpty ? match.first.name : peerId;
  }

  /// Truncates a long ID or profile value for compact display in status rows.
  String _shortId(String value) =>
      value.length > 16 ? '${value.substring(0, 16)}...' : value;

  /// Maps the backend exit-route-kind string to a human-readable label.
  String _exitRouteLabel(String routeKind) => switch (routeKind) {
        'peer_exit'                => 'Trusted peer exit',
        'tailscale_exit'           => 'Tailscale exit',
        'tailscale_profile_exit'   => 'Tailscale exit with profile',
        'profile_exit'             => 'Exit profile',
        'profile_only'             => 'Profile-defined exit',
        _                          => 'None',
      };

  /// Formats a raw uptime in seconds into a human-readable "Xh Ym" string.
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

/// _ExitNodePicker — shows a selectable list of available exit nodes.
///
/// Two categories are displayed sequentially in the same list:
///   1. Mesh peers that have advertised exit-node capability ([peers] filtered
///      by [canBeExitNode]).
///   2. Tailscale exit nodes from the connected tailnet (if any).
///
/// Tapping a node immediately calls the appropriate callback to apply the
/// selection — no separate "Save" step is needed.
class _ExitNodePicker extends StatelessWidget {
  const _ExitNodePicker({
    required this.peers,
    required this.tailscaleExitNodes,
    required this.selectedId,
    required this.selectedTailscaleExitNode,
    required this.onSelectedMesh,
    required this.onSelectedTailscale,
  });

  /// All known peers; filtered internally to those that can be exit nodes.
  final List<PeerModel> peers;

  /// Exit nodes advertised by the connected Tailscale tailnet.
  final List<Map<String, dynamic>> tailscaleExitNodes;

  /// Currently selected mesh peer exit node ID, or null.
  final String? selectedId;

  /// Currently selected Tailscale exit node name, or null.
  final String? selectedTailscaleExitNode;

  /// Called with the chosen peer ID when a mesh exit node is selected.
  final ValueChanged<String> onSelectedMesh;

  /// Called with the peer name when a Tailscale exit node is selected.
  final ValueChanged<String> onSelectedTailscale;

  @override
  Widget build(BuildContext context) {
    // Only peers that have advertised the exit-node capability are shown.
    final exitNodes = peers.where((p) => p.canBeExitNode).toList();
    final theme = Theme.of(context);

    // Empty state: shown when neither mesh peers nor Tailscale exits are available.
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
          // ── Mesh peer exit nodes ──────────────────────────────────────
          for (final node in exitNodes)
            Card(
              clipBehavior: Clip.antiAlias,
              child: ListTile(
                leading: Icon(
                  Icons.exit_to_app_outlined,
                  // Highlight the leading icon in primary colour when selected.
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
                    // Online/idle/offline dot.
                    _PeerStatusDot(status: node.status),
                    const SizedBox(width: 6),
                    Text(node.status),
                    // Latency in ms — helps the user pick the fastest exit.
                    if (node.latencyMs != null) ...[
                      const SizedBox(width: 12),
                      Icon(Icons.timer_outlined, size: 14,
                          color: theme.colorScheme.outline),
                      const SizedBox(width: 2),
                      Text('${node.latencyMs}ms'),
                    ],
                  ],
                ),
                // Check-circle when selected, hollow circle when not.
                trailing: node.id == selectedId
                    ? Icon(Icons.check_circle, color: theme.colorScheme.primary)
                    : const Icon(Icons.circle_outlined),
                onTap: () => onSelectedMesh(node.id),
              ),
            ),
          // ── Tailscale exit nodes ──────────────────────────────────────
          // Orange accent distinguishes Tailscale exits from native mesh exits.
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
                        // Online/offline dot using Tailscale's status field.
                        Icon(
                          node['online'] == true ? Icons.circle : Icons.circle_outlined,
                          size: 10,
                          color: node['online'] == true
                              ? Colors.orange.shade700
                              : theme.colorScheme.outline,
                        ),
                        const SizedBox(width: 6),
                        Text(node['online'] == true ? 'Online' : 'Offline'),
                        // IP address when available (Tailscale assigns a
                        // 100.x.y.z CGNAT IP to each node in the tailnet).
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

/// _PeerStatusDot — a 8×8 coloured circle indicating a peer's connection state.
///
/// Green = online (actively reachable).
/// Orange = idle (authenticated but no recent traffic).
/// Grey = offline or unknown.
class _PeerStatusDot extends StatelessWidget {
  const _PeerStatusDot({required this.status});

  /// Backend status string: "online", "idle", or any other value.
  final String status;

  @override
  Widget build(BuildContext context) {
    final Color color;
    switch (status) {
      case 'online':
        color = Colors.green;
      case 'idle':
        // Idle: authenticated session exists but no recent keepalive traffic.
        color = Colors.orange;
      default:
        // Offline, unknown, or any future status we haven't handled yet.
        color = Colors.grey;
    }
    return Container(
      width: 8,
      height: 8,
      decoration: BoxDecoration(shape: BoxShape.circle, color: color),
    );
  }
}

/// _StatusRow — a two-column label/value row in the status card.
///
/// The label takes a fixed 100 dp width so values align into a column,
/// making the card easy to scan.  An optional trailing widget (e.g. a
/// colour dot) can be appended after the value.
class _StatusRow extends StatelessWidget {
  const _StatusRow({
    required this.label,
    required this.value,
    this.trailing,
  });

  final String label;
  final String value;

  /// Optional widget rendered after the value, e.g. a status dot.
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          // Fixed-width label column so all values start at the same x position.
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

/// _Section — a titled group container used throughout VpnScreen.
///
/// Renders the [title] in a bold label above the [child] content, providing
/// consistent spacing and visual grouping for the VPN settings.
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
