// exit_node_screen.dart
//
// ExitNodeScreen — browse and connect to exit nodes (§22.9.3).
//
// WHAT IS AN EXIT NODE?
// ---------------------
// An exit node routes your mesh traffic out to the regular internet.
// Your real IP address is hidden from the sites you visit — the exit
// node's IP appears instead.  Think of it like a VPN where the "server"
// is a trusted friend rather than a corporation.
//
// Key facts:
//   - The exit node operator CAN see your destination addresses (which sites
//     you visit) unless you also route through Tor or I2P.
//   - Your mesh identity is always hidden from the exit node — they only see
//     the packets, not who you are.
//   - Only trusted contacts who have enabled exit node hosting appear here.
//
// ROUTING PROFILES (§13.15):
//   Direct  — fastest, operator sees destination.
//   Via Tor — slower, operator cannot see destination.
//   Via I2P — experimental, I2P emissary path (best-effort).
//
// BACKEND STATUS:
// ---------------
// Exit node discovery is not yet wired in the backend.  The screen shows an
// empty state.  When §13.15 is implemented:
//   - Replace _availableNodes with data from bridge.fetchExitNodes().
//   - Wire _connect() to bridge.connectExitNode(nodeId, profile).
//   - Wire _disconnect() to bridge.disconnectExitNode().
//   - Show the legal warning AlertDialog on first connection per session.
//
// Reached from: Network → VPN → Exit Node tile.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app/app_theme.dart';
import '../network_state.dart';

// ---------------------------------------------------------------------------
// Exit node data model (stub)
// ---------------------------------------------------------------------------

/// Capabilities that an exit node may support.
///
/// The UI uses these to decide which routing profiles to offer.
class _ExitNodeCapabilities {
  const _ExitNodeCapabilities({
    required this.supportsDirectClearnet,
    required this.supportsTorRouting,
    required this.supportsI2PRouting,
    required this.bandwidthTier,
  });

  final bool supportsDirectClearnet;
  final bool supportsTorRouting;
  final bool supportsI2PRouting;

  /// Human-readable bandwidth tier label: 'Low', 'Standard', 'High'.
  final String bandwidthTier;
}

/// A single exit node offered by a trusted contact.
class _ExitNodeModel {
  const _ExitNodeModel({
    required this.id,
    required this.name,
    required this.trustLevel,
    required this.capabilities,
  });

  final String id;
  final String name;

  /// Trust level 0-8 — only contacts above a minimum threshold appear here.
  final int trustLevel;

  final _ExitNodeCapabilities capabilities;
}

/// Which path to use when traffic leaves the mesh and hits the internet.
enum ExitNodeProfile {
  /// Traffic goes directly to the internet from the exit node.
  direct,

  /// Traffic is routed through Tor before exiting.
  viaTor,

  /// Traffic is routed through I2P before exiting (experimental).
  viaI2P,
}

// ---------------------------------------------------------------------------
// ExitNodeScreen
// ---------------------------------------------------------------------------

/// Lists available exit nodes and allows the user to connect or disconnect.
class ExitNodeScreen extends StatefulWidget {
  const ExitNodeScreen({super.key});

  @override
  State<ExitNodeScreen> createState() => _ExitNodeScreenState();
}

class _ExitNodeScreenState extends State<ExitNodeScreen> {
  // Stub list — replaced by bridge.fetchExitNodes() when backend is ready.
  // TODO(backend/exit-node): load from NetworkState.availableExitNodes.
  final List<_ExitNodeModel> _availableNodes = const [];

  // Whether the one-per-session legal warning has been shown.
  bool _legalWarningShown = false;

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // The active exit node is identified by peer ID stored in NetworkState.
    final activeNodeId = net.selectedExitNodeId;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Exit Node'),
        actions: [
          // "Disconnect" button — only shown when an exit node is active.
          if (activeNodeId != null)
            TextButton(
              onPressed: () => _disconnect(context, net),
              child: const Text('Disconnect'),
            ),
        ],
      ),
      body: Column(
        children: [
          // ── Explanation banner ───────────────────────────────────────
          // Always visible — users should understand the trade-off every
          // time they open this screen, not just on first use (§22.22).
          Container(
            width: double.infinity,
            color: cs.surfaceContainerHighest,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            child: Text(
              'An exit node routes your traffic to the regular internet. '
              'Your mesh identity is hidden, but the exit node operator '
              'can see your destinations unless you route via Tor.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),

          // ── Active node header ───────────────────────────────────────
          if (activeNodeId != null)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Row(
                children: [
                  const Icon(Icons.check_circle_outline, size: 18, color: MeshTheme.secGreen),
                  const SizedBox(width: 8),
                  Text(
                    'Connected via exit node',
                    style: tt.titleSmall,
                  ),
                ],
              ),
            ),

          // ── Node list or empty state ─────────────────────────────────
          Expanded(
            child: _availableNodes.isEmpty
                ? const _EmptyState(
                    title: 'No exit nodes available',
                    body: 'Trusted contacts who offer exit node services '
                        'will appear here.',
                    icon: Icons.route_outlined,
                  )
                : RefreshIndicator(
                    onRefresh: net.loadAll,
                    child: ListView.separated(
                      itemCount: _availableNodes.length,
                      separatorBuilder: (_, _) => const Divider(height: 1),
                      itemBuilder: (ctx, i) => _ExitNodeTile(
                        node: _availableNodes[i],
                        isActive: _availableNodes[i].id == activeNodeId,
                        onConnect: (profile) =>
                            _connect(ctx, net, _availableNodes[i], profile),
                        onDisconnect: () => _disconnect(ctx, net),
                      ),
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Connect / disconnect
  // ---------------------------------------------------------------------------

  /// Shows the one-per-session legal warning, then connects to the exit node.
  Future<void> _connect(
    BuildContext context,
    NetworkState net,
    _ExitNodeModel node,
    ExitNodeProfile profile,
  ) async {
    // Show the legal warning once per session (§22.9.3 spec requirement).
    if (!_legalWarningShown) {
      final proceed = await _showLegalWarning(context);
      if (!proceed) return;
      _legalWarningShown = true;
    }

    // Connect via the backend (stub — net.setVpnMode wires to bridge).
    await net.setVpnMode('exit_node', exitNodePeerId: node.id);

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Connected via ${node.name} (${_profileLabel(profile)})',
          ),
        ),
      );
    }
  }

  Future<void> _disconnect(BuildContext context, NetworkState net) async {
    await net.setVpnMode('off');
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Exit node disconnected')),
      );
    }
  }

  /// Shows the exit node legal warning dialog.
  ///
  /// Returns true if the user tapped "I understand, connect"; false if Cancel.
  Future<bool> _showLegalWarning(BuildContext context) async {
    return await showDialog<bool>(
          context: context,
          builder: (_) => AlertDialog(
            title: const Text('Exit node usage'),
            content: const Text(
              'Traffic routed through an exit node appears to originate '
              'from that node\'s IP address. The exit node operator can '
              'see your destination addresses unless you select Tor or '
              'I2P routing.\n\n'
              'Only use exit nodes operated by people you trust.',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('I understand, connect'),
              ),
            ],
          ),
        ) ??
        false;
  }

  static String _profileLabel(ExitNodeProfile p) => switch (p) {
    ExitNodeProfile.direct => 'Direct',
    ExitNodeProfile.viaTor => 'Via Tor',
    ExitNodeProfile.viaI2P => 'Via I2P',
  };
}

// ---------------------------------------------------------------------------
// _ExitNodeTile — expandable row for one exit node
// ---------------------------------------------------------------------------

/// Shows an exit node as an expandable tile.
///
/// Collapsed: name + trust level + capability chips.
/// Expanded:  routing profile selector + connect/disconnect button.
class _ExitNodeTile extends StatefulWidget {
  const _ExitNodeTile({
    required this.node,
    required this.isActive,
    required this.onConnect,
    required this.onDisconnect,
  });

  final _ExitNodeModel node;
  final bool isActive;
  final void Function(ExitNodeProfile profile) onConnect;
  final VoidCallback onDisconnect;

  @override
  State<_ExitNodeTile> createState() => _ExitNodeTileState();
}

class _ExitNodeTileState extends State<_ExitNodeTile> {
  // Default to Direct; if the node doesn't support it, fall back to Tor.
  late ExitNodeProfile _selectedProfile = widget.node.capabilities.supportsDirectClearnet
      ? ExitNodeProfile.direct
      : ExitNodeProfile.viaTor;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;
    final caps = widget.node.capabilities;

    return ExpansionTile(
      // Collapsed: avatar + name + trust badge + capability chips.
      leading: CircleAvatar(
        radius: 18,
        backgroundColor: MeshTheme.brand.withValues(alpha: 0.15),
        child: Text(
          widget.node.name.isNotEmpty
              ? widget.node.name[0].toUpperCase()
              : '?',
          style: tt.titleSmall?.copyWith(color: MeshTheme.brand),
        ),
      ),
      title: Text(widget.node.name, style: tt.titleSmall),
      subtitle: Wrap(
        spacing: 4,
        runSpacing: 4,
        children: [
          if (caps.supportsDirectClearnet) const _CapChip(label: 'Direct'),
          if (caps.supportsTorRouting)
            const _CapChip(label: 'Tor', color: MeshTheme.secGreen),
          if (caps.supportsI2PRouting)
            const _CapChip(label: 'I2P', color: MeshTheme.brand),
          _CapChip(
            label: caps.bandwidthTier,
            icon: Icons.speed_outlined,
          ),
        ],
      ),
      // Expand active nodes by default so the user can quickly disconnect.
      initiallyExpanded: widget.isActive,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Routing profile selector.
              Text('Routing mode', style: tt.labelMedium),
              const SizedBox(height: 8),
              SegmentedButton<ExitNodeProfile>(
                segments: [
                  if (caps.supportsDirectClearnet)
                    const ButtonSegment(
                      value: ExitNodeProfile.direct,
                      label: Text('Direct'),
                      icon: Icon(Icons.public_outlined, size: 14),
                    ),
                  if (caps.supportsTorRouting)
                    const ButtonSegment(
                      value: ExitNodeProfile.viaTor,
                      label: Text('Via Tor'),
                      icon: Icon(Icons.security_outlined, size: 14),
                    ),
                  if (caps.supportsI2PRouting)
                    const ButtonSegment(
                      value: ExitNodeProfile.viaI2P,
                      label: Text('Via I2P'),
                      icon: Icon(Icons.vpn_lock_outlined, size: 14),
                    ),
                ],
                selected: {_selectedProfile},
                onSelectionChanged: (s) =>
                    setState(() => _selectedProfile = s.first),
              ),

              const SizedBox(height: 8),
              // Description of the selected profile.
              Text(
                _profileDescription(_selectedProfile),
                style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              ),

              const SizedBox(height: 16),

              // Connect or disconnect button — full width.
              if (widget.isActive)
                OutlinedButton(
                  onPressed: widget.onDisconnect,
                  style: OutlinedButton.styleFrom(
                    minimumSize: const Size(double.infinity, 44),
                  ),
                  child: const Text('Disconnect'),
                )
              else
                FilledButton.icon(
                  onPressed: () => widget.onConnect(_selectedProfile),
                  icon: const Icon(Icons.route_outlined),
                  label: const Text('Connect'),
                  style: FilledButton.styleFrom(
                    minimumSize: const Size(double.infinity, 44),
                  ),
                ),
            ],
          ),
        ),
      ],
    );
  }

  static String _profileDescription(ExitNodeProfile p) => switch (p) {
    ExitNodeProfile.direct =>
      'Your mesh identity is hidden, but the exit node sees your '
      'destination. No additional anonymization.',
    ExitNodeProfile.viaTor =>
      'Traffic routes through Tor before exiting. Slower, but the exit '
      'node cannot see your mesh identity or traffic pattern.',
    ExitNodeProfile.viaI2P =>
      'Traffic routes through I2P before exiting. Best-effort '
      '(I2P emissary is experimental).',
  };
}

// ---------------------------------------------------------------------------
// _CapChip — small label chip for node capabilities
// ---------------------------------------------------------------------------

/// A small chip showing a capability label, optionally with an icon.
class _CapChip extends StatelessWidget {
  const _CapChip({required this.label, this.color, this.icon});

  final String label;
  final Color? color;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final effectiveColor = color ?? cs.outline;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: effectiveColor.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: effectiveColor.withValues(alpha: 0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: 10, color: effectiveColor),
            const SizedBox(width: 3),
          ],
          Text(
            label,
            style: Theme.of(context).textTheme.labelSmall?.copyWith(
                  color: effectiveColor,
                ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _EmptyState — centred icon + title + body text
// ---------------------------------------------------------------------------

/// Reusable empty state widget for when the node list is empty.
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
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 56, color: cs.outline),
            const SizedBox(height: 12),
            Text(title, style: tt.titleMedium),
            const SizedBox(height: 4),
            Text(
              body,
              style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
