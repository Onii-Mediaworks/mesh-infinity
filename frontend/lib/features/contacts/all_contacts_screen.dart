import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../shell/shell_state.dart';
import '../peers/peers_state.dart';
import 'screens/contact_detail_screen.dart';
import 'screens/pair_contact_screen.dart';
import '../peers/widgets/peer_tile.dart';

/// The "All Contacts" sub-page of the Contacts section.
///
/// Shows the full list of paired contacts from [PeersState].  Tapping a
/// contact opens [ContactDetailScreen].  A FAB and an "Add a contact" prompt
/// in the empty state both lead to [PairContactScreen].
///
/// This is one of three sub-pages in the Contacts section; the others are
/// [OnlineScreen] (presence-filtered) and [RequestsScreen] (pending requests).
class AllContactsScreen extends StatelessWidget {
  const AllContactsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes to PeersState so the list rebuilds whenever
    // the contact list changes (pairing completes, trust updated, etc.).
    final peers = context.watch<PeersState>();

    return Scaffold(
      body: RefreshIndicator(
        // Pull-to-refresh forces a fresh load from the Rust backend.
        onRefresh: peers.loadPeers,
        child: peers.peers.isEmpty
            ? _EmptyContacts(onAdd: () => _openPairing(context))
            : ListView.separated(
                itemCount: peers.peers.length,
                // Divider indented to 72px aligns with the text column,
                // not the leading avatar — consistent across all list screens.
                separatorBuilder: (ctx, i) =>
                    const Divider(height: 1, indent: 72),
                itemBuilder: (context, i) {
                  final peer = peers.peers[i];
                  return PeerTile(
                    peer: peer,
                    // selected: false — this list does not maintain a selected
                    // highlight; selection state lives in ShellState and is
                    // only meaningful in the wide-layout detail pane.
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

  /// Opens [ContactDetailScreen] for the given [peerId], adapting to layout.
  void _openDetail(BuildContext context, String peerId) {
    final shell = context.read<ShellState>();
    final width = MediaQuery.sizeOf(context).width;

    // Always inform ShellState of the selected peer so the wide-layout detail
    // pane can display it without a navigation push.
    shell.selectPeer(peerId);

    if (width < 1200) {
      // Narrow layout: no persistent detail pane, so push the screen directly.
      // The 1200px threshold matches the wide-layout breakpoint in AppShell.
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ContactDetailScreen(peerId: peerId)),
      // When the user returns from the detail screen, clear the selection so
      // the list row is no longer highlighted.
      ).then((_) => shell.selectPeer(null));
    }
    // Wide layout (≥ 1200px): the detail pane renders based on selectedPeerId;
    // setting it above is sufficient to switch the displayed contact.
  }

  /// Pushes [PairContactScreen] to start the "Add contact" flow.
  void _openPairing(BuildContext context) {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const PairContactScreen()),
    );
  }
}

/// Empty state shown when the user has no paired contacts.
///
/// Provides a direct path to the pairing flow so new users can immediately
/// add someone rather than looking for a FAB they may not have noticed.
class _EmptyContacts extends StatelessWidget {
  const _EmptyContacts({required this.onAdd});

  /// Callback invoked when the "Add a contact" button is tapped.
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
