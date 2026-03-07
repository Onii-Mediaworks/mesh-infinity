import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../peers_state.dart';
import '../../../shell/shell_state.dart';
import '../widgets/peer_tile.dart';
import 'pair_peer_screen.dart';
import 'peer_detail_screen.dart';

class PeerListScreen extends StatelessWidget {
  const PeerListScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final peers = context.watch<PeersState>();
    final shell = context.watch<ShellState>();
    final isWide = MediaQuery.sizeOf(context).width >= 1200;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Peers'),
        actions: [
          IconButton(
            icon: const Icon(Icons.person_add_outlined),
            tooltip: 'Pair peer',
            onPressed: () => _openPair(context),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: peers.loadPeers,
        child: peers.loading
            ? const Center(child: CircularProgressIndicator())
            : peers.peers.isEmpty
                ? _EmptyState(onPairTap: () => _openPair(context))
                : ListView.builder(
                    itemCount: peers.peers.length,
                    itemBuilder: (context, i) {
                      final peer = peers.peers[i];
                      return PeerTile(
                        peer: peer,
                        selected: isWide && shell.selectedPeerId == peer.id,
                        onTap: () => _openPeer(context, peer.id, isWide),
                      );
                    },
                  ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _openPair(context),
        tooltip: 'Pair with peer',
        child: const Icon(Icons.person_add_outlined),
      ),
    );
  }

  Future<void> _openPair(BuildContext context) async {
    await Navigator.push<bool>(
      context,
      MaterialPageRoute(builder: (_) => const PairPeerScreen()),
    );
  }

  void _openPeer(BuildContext context, String peerId, bool isWide) {
    if (isWide) {
      context.read<ShellState>().selectPeer(peerId);
    } else {
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => PeerDetailScreen(peerId: peerId)),
      );
    }
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.onPairTap});

  final VoidCallback onPairTap;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.people_outline, size: 64, color: cs.outline),
          const SizedBox(height: 16),
          Text('No peers yet', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          TextButton.icon(
            onPressed: onPairTap,
            icon: const Icon(Icons.person_add_outlined),
            label: const Text('Pair with a peer'),
          ),
        ],
      ),
    );
  }
}
