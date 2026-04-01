import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../shell/shell_state.dart';
import '../peers/peers_state.dart';
import '../peers/screens/peer_detail_screen.dart';
import '../peers/screens/pair_peer_screen.dart';
import '../peers/widgets/peer_tile.dart';

class AllContactsScreen extends StatelessWidget {
  const AllContactsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final peers = context.watch<PeersState>();

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: peers.loadPeers,
        child: peers.peers.isEmpty
            ? _EmptyContacts(onAdd: () => _openPairing(context))
            : ListView.separated(
                itemCount: peers.peers.length,
                separatorBuilder: (ctx, i) =>
                    const Divider(height: 1, indent: 72),
                itemBuilder: (context, i) {
                  final peer = peers.peers[i];
                  return PeerTile(
                    peer: peer,
                    selected: false,
                    onTap: () => _openDetail(context, peer.id),
                  );
                },
              ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _openPairing(context),
        tooltip: 'Add contact',
        child: const Icon(Icons.person_add_outlined),
      ),
    );
  }

  void _openDetail(BuildContext context, String peerId) {
    final shell = context.read<ShellState>();
    final width = MediaQuery.sizeOf(context).width;
    shell.selectPeer(peerId);
    if (width < 1200) {
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => PeerDetailScreen(peerId: peerId)),
      ).then((_) => shell.selectPeer(null));
    }
  }

  void _openPairing(BuildContext context) {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const PairPeerScreen()),
    );
  }
}

class _EmptyContacts extends StatelessWidget {
  const _EmptyContacts({required this.onAdd});
  final VoidCallback onAdd;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.people_outline,
              size: 56, color: Theme.of(context).colorScheme.outline),
          const SizedBox(height: 16),
          Text(
            'No contacts yet',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                ),
          ),
          const SizedBox(height: 8),
          FilledButton.tonal(
            onPressed: onAdd,
            child: const Text('Add a contact'),
          ),
        ],
      ),
    );
  }
}
