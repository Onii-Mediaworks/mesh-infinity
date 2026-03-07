import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../peers_state.dart';
import '../../../backend/models/peer_models.dart';
import '../../../features/settings/settings_state.dart';
import '../widgets/trust_badge.dart';

class PeerDetailScreen extends StatelessWidget {
  const PeerDetailScreen({super.key, required this.peerId});

  final String peerId;

  @override
  Widget build(BuildContext context) {
    final peer = context.watch<PeersState>().findPeer(peerId);
    if (peer == null) {
      return const Scaffold(body: Center(child: Text('Peer not found')));
    }

    return Scaffold(
      appBar: AppBar(title: Text(peer.name.isNotEmpty ? peer.name : 'Peer')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _HeaderCard(peer: peer),
          const SizedBox(height: 12),
          _InfoCard(peer: peer),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Trust', style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 12),
                  TrustBadge(level: peer.trustLevel),
                  const SizedBox(height: 16),
                  FilledButton.tonal(
                    onPressed: () => _showTrustSheet(context, peer),
                    child: const Text('Set Trust Level'),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  void _showTrustSheet(BuildContext context, PeerModel peer) {
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => _TrustSheet(peer: peer),
    );
  }
}

class _HeaderCard extends StatelessWidget {
  const _HeaderCard({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final statusColor = peer.isOnline ? Colors.green : Colors.grey;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            CircleAvatar(
              radius: 36,
              backgroundColor: cs.secondaryContainer,
              child: Text(
                peer.name.isNotEmpty ? peer.name[0].toUpperCase() : '?',
                style: TextStyle(
                  fontSize: 32,
                  fontWeight: FontWeight.bold,
                  color: cs.onSecondaryContainer,
                ),
              ),
            ),
            const SizedBox(height: 12),
            Text(
              peer.name.isNotEmpty ? peer.name : 'Unknown',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 4),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Container(
                  width: 8,
                  height: 8,
                  decoration: BoxDecoration(color: statusColor, shape: BoxShape.circle),
                ),
                const SizedBox(width: 6),
                Text(peer.status, style: Theme.of(context).textTheme.bodySmall),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _InfoCard extends StatelessWidget {
  const _InfoCard({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Peer ID', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: SelectableText(
                    peer.id,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.copy_outlined, size: 18),
                  tooltip: 'Copy peer ID',
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: peer.id));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Peer ID copied')),
                    );
                  },
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _TrustSheet extends StatelessWidget {
  const _TrustSheet({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    final settingsState = context.read<SettingsState>();
    final localPeerId = settingsState.settings?.localPeerId ?? '';

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'Set Trust Level',
                style: Theme.of(context).textTheme.titleMedium,
              ),
            ),
            const Divider(),
            for (final level in TrustLevel.values)
              ListTile(
                leading: TrustBadge(level: level, compact: true),
                title: Text(level.label),
                selected: peer.trustLevel == level,
                onTap: () {
                  Navigator.pop(context);
                  if (localPeerId.isNotEmpty) {
                    context.read<PeersState>().attestTrust(
                      localPeerId: localPeerId,
                      targetPeerId: peer.id,
                      trustLevel: level.value,
                    );
                  }
                },
              ),
          ],
        ),
      ),
    );
  }
}
