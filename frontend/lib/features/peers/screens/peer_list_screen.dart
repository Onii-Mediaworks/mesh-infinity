import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/widgets/empty_state.dart';
import '../peers_state.dart';
import '../../../shell/shell_state.dart';
import '../widgets/peer_tile.dart';
import 'pair_peer_screen.dart';
import 'peer_detail_screen.dart';

class PeerListScreen extends StatefulWidget {
  const PeerListScreen({super.key});

  @override
  State<PeerListScreen> createState() => _PeerListScreenState();
}

class _PeerListScreenState extends State<PeerListScreen> {
  final TextEditingController _searchController = TextEditingController();

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final peers = context.watch<PeersState>();
    final shell = context.watch<ShellState>();
    final isWide = MediaQuery.sizeOf(context).width >= 1200;
    final query = _searchController.text.trim().toLowerCase();
    final filteredPeers =
        peers.peers.where((peer) {
          if (query.isEmpty) return true;
          return peer.name.toLowerCase().contains(query) ||
              peer.id.toLowerCase().contains(query);
        }).toList()..sort((a, b) {
          final onlineCompare = (b.isOnline ? 1 : 0).compareTo(
            a.isOnline ? 1 : 0,
          );
          if (onlineCompare != 0) return onlineCompare;
          final trustCompare = b.trustLevel.value.compareTo(a.trustLevel.value);
          if (trustCompare != 0) return trustCompare;
          return a.name.toLowerCase().compareTo(b.name.toLowerCase());
        });

    return Scaffold(
      appBar: AppBar(
        title: const Text('Contacts'),
        actions: [
          IconButton(
            icon: const Icon(Icons.person_add_outlined),
            tooltip: 'Add contact',
            onPressed: () => _openPair(context),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: peers.loadPeers,
        child: ListView(
          padding: const EdgeInsets.only(bottom: 16),
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
              child: TextField(
                controller: _searchController,
                decoration: InputDecoration(
                  prefixIcon: const Icon(Icons.search, size: 20),
                  hintText: 'Search contacts...',
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(999),
                    borderSide: BorderSide.none,
                  ),
                  filled: true,
                  isDense: true,
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 10,
                  ),
                  suffixIcon: query.isNotEmpty
                      ? IconButton(
                          icon: const Icon(Icons.clear, size: 18),
                          onPressed: () {
                            _searchController.clear();
                            setState(() {});
                          },
                        )
                      : null,
                ),
                onChanged: (_) => setState(() {}),
              ),
            ),
            if (peers.loading)
              const Padding(
                padding: EdgeInsets.only(top: 120),
                child: Center(child: CircularProgressIndicator()),
              )
            else if (peers.peers.isEmpty)
              EmptyState(
                icon: Icons.people_outline,
                title: 'No contacts yet',
                body: 'Pair with someone to add them.',
                action: FilledButton.icon(
                  onPressed: () => _openPair(context),
                  icon: const Icon(Icons.person_add_outlined),
                  label: const Text('Add a contact'),
                ),
              )
            else if (filteredPeers.isEmpty)
              EmptyState(
                icon: Icons.search_off_outlined,
                title: 'No contacts found',
                body: 'No contacts match "${_searchController.text.trim()}".',
                compact: true,
              )
            else
              ...filteredPeers.map(
                (peer) => PeerTile(
                  peer: peer,
                  selected: isWide && shell.selectedPeerId == peer.id,
                  onTap: () => _openPeer(context, peer.id, isWide),
                ),
              ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _openPair(context),
        tooltip: 'Add contact',
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
