// peer_list_screen.dart
//
// PeerListScreen — the main Contacts list with search, sort, and pair entry
// points.
//
// LAYOUT:
// -------
// The screen is a single ListView with a pinned search bar at the top,
// followed by either a loading spinner, an empty state, or the filtered and
// sorted peer list.
//
// SORT ORDER:
// -----------
// Online peers sort before offline peers. Within the same online state,
// higher-trust peers sort first (trust 8 > 0). Within the same trust level,
// peers sort alphabetically by display name. This order keeps the most useful
// contacts visible without the user needing to scroll.
//
// RESPONSIVE BEHAVIOUR (wide layout ≥ 1200 px):
// -----------------------------------------------
// On wide screens (desktop / landscape tablet), tapping a peer sets
// ShellState.selectedPeerId so the detail panel on the right renders that
// peer. On narrow screens, tapping pushes a full-screen ContactDetailScreen.
//
// Reached from: the Contacts section via ShellState.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/widgets/empty_state.dart';
import '../peers_state.dart';
import '../../../shell/shell_state.dart';
import '../widgets/peer_tile.dart';
import '../../contacts/screens/pair_contact_screen.dart';
import '../../contacts/screens/contact_detail_screen.dart';

/// Main contacts list screen.
///
/// Stateful because it owns the [TextEditingController] for the search field
/// and needs to trigger rebuilds when the query changes.
class PeerListScreen extends StatefulWidget {
  const PeerListScreen({super.key});

  @override
  State<PeerListScreen> createState() => _PeerListScreenState();
}

class _PeerListScreenState extends State<PeerListScreen> {
  /// Controls the live search field. Disposed in dispose() to free resources.
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

    // Wide layout threshold matches the shell breakpoint so the selected peer
    // highlight only activates when the detail panel is actually visible.
    final isWide = MediaQuery.sizeOf(context).width >= 1200;

    // Normalise to lower-case once — used for both name and ID matching below.
    final query = _searchController.text.trim().toLowerCase();

    final filteredPeers =
        peers.peers.where((peer) {
          // Empty query shows everything; otherwise match name OR peer ID
          // so power users can search by cryptographic ID prefix.
          if (query.isEmpty) return true;
          return peer.name.toLowerCase().contains(query) ||
              peer.id.toLowerCase().contains(query);
        }).toList()..sort((a, b) {
          // Primary sort: online peers before offline/idle peers.
          final onlineCompare = (b.isOnline ? 1 : 0).compareTo(
            a.isOnline ? 1 : 0,
          );
          if (onlineCompare != 0) return onlineCompare;

          // Secondary sort: higher trust level first (trust 8 = InnerCircle).
          final trustCompare = b.trustLevel.value.compareTo(a.trustLevel.value);
          if (trustCompare != 0) return trustCompare;

          // Tertiary sort: alphabetical by display name.
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
        // Pull-to-refresh triggers a full backend reload of the peer list.
        onRefresh: peers.loadPeers,
        child: ListView(
          padding: const EdgeInsets.only(bottom: 16),
          children: [
            // ── Search bar ────────────────────────────────────────────────
            // Inlined (not in AppBar) so it scrolls with the list and doesn't
            // take permanent vertical space on short screens.
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
              child: TextField(
                controller: _searchController,
                decoration: InputDecoration(
                  prefixIcon: const Icon(Icons.search, size: 20),
                  hintText: 'Search contacts...',
                  // Stadium (pill) border with no visible outline — softer
                  // appearance than the default rectangle.
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
                  // Clear button only appears when there is a query to clear,
                  // so the trailing area is empty when the field is blank.
                  suffixIcon: query.isNotEmpty
                      ? IconButton(
                          icon: const Icon(Icons.clear, size: 18),
                          onPressed: () {
                            _searchController.clear();
                            // setState forces a rebuild so filteredPeers
                            // recalculates with the now-empty query.
                            setState(() {});
                          },
                        )
                      : null,
                ),
                // Rebuild on every keystroke so filter results update live.
                onChanged: (_) => setState(() {}),
              ),
            ),

            // ── Body states ───────────────────────────────────────────────
            if (peers.loading)
              // Loading: the list hasn't arrived from the backend yet.
              const Padding(
                padding: EdgeInsets.only(top: 120),
                child: Center(child: CircularProgressIndicator()),
              )
            else if (peers.peers.isEmpty)
              // Empty (no peers at all): guide the user to pair their first contact.
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
              // Search returned nothing — the list has peers but none match.
              EmptyState(
                icon: Icons.search_off_outlined,
                title: 'No contacts found',
                body: 'No contacts match "${_searchController.text.trim()}".',
                compact: true,
              )
            else
              // Render each matching peer as a PeerTile.
              // `selected` highlights the tile on wide screens only, matching
              // the currently open detail panel.
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
      // FAB mirrors the AppBar action so the pairing entry point is always
      // reachable without scrolling back to the top.
      floatingActionButton: FloatingActionButton(
        onPressed: () => _openPair(context),
        tooltip: 'Add contact',
        child: const Icon(Icons.person_add_outlined),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Navigation helpers
  // ---------------------------------------------------------------------------

  /// Opens the QR / code pairing flow in a full-screen route.
  ///
  /// Returns a [bool] indicating whether a new contact was added — the return
  /// value is not currently consumed (peers refresh via EventBus instead).
  Future<void> _openPair(BuildContext context) async {
    await Navigator.push<bool>(
      context,
      MaterialPageRoute(builder: (_) => const PairContactScreen()),
    );
  }

  /// Opens the detail view for [peerId], adapting to the available screen width.
  ///
  /// On wide screens: updates [ShellState.selectedPeerId] so the master-detail
  /// panel on the right renders this peer.
  /// On narrow screens: pushes a full-screen [ContactDetailScreen].
  void _openPeer(BuildContext context, String peerId, bool isWide) {
    if (isWide) {
      context.read<ShellState>().selectPeer(peerId);
    } else {
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ContactDetailScreen(peerId: peerId)),
      );
    }
  }
}
