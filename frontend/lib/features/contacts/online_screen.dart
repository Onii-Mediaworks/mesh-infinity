import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../shell/shell_state.dart';
import '../peers/peers_state.dart';
import 'screens/contact_detail_screen.dart';
import '../peers/widgets/peer_tile.dart';

/// The "Online" sub-page of the Contacts section.
///
/// Filters the full contact list from [PeersState] to show only peers who
/// are currently reachable on the mesh — either actively online or idle
/// (connected but not recently active).
///
/// This view is useful for deciding whom to call or message when you want an
/// immediate response rather than sending to an offline peer whose device
/// will queue the message.
class OnlineScreen extends StatelessWidget {
  const OnlineScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // context.watch rebuilds this widget whenever PeersState changes, which
    // means the list updates in real-time as peers come and go.
    final peers = context.watch<PeersState>();

    // Include both "online" (actively connected) and "idle" (connected but
    // not recently active) peers.  Idle peers are still reachable for
    // messaging and calls, so they belong in this view rather than being
    // hidden with offline peers.
    final online = peers.peers.where((p) => p.isOnline || p.isIdle).toList();

    return Scaffold(
      body: RefreshIndicator(
        // Pull-to-refresh requests a fresh presence snapshot from the backend.
        onRefresh: peers.loadPeers,
        child: online.isEmpty
            ? Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // wifi_off icon communicates "no network reachability"
                    // rather than "no contacts" — distinct from the AllContacts
                    // empty state icon.
                    Icon(Icons.wifi_off_outlined,
                        size: 56,
                        color: Theme.of(context).colorScheme.outline),
                    const SizedBox(height: 16),
                    Text(
                      'No contacts online',
                      style:
                          Theme.of(context).textTheme.titleMedium?.copyWith(
                                color:
                                    Theme.of(context).colorScheme.outline,
                              ),
                    ),
                  ],
                ),
              )
            : ListView.separated(
                itemCount: online.length,
                // Indent the divider to 72px so it aligns with the text column,
                // consistent with the other contact list screens.
                separatorBuilder: (ctx, i) =>
                    const Divider(height: 1, indent: 72),
                itemBuilder: (context, i) {
                  final peer = online[i];
                  return PeerTile(
                    peer: peer,
                    // selected: false — this list has no persistent selection
                    // highlight; the detail pane is driven by ShellState.
                    selected: false,
                    onTap: () {
                      final shell = context.read<ShellState>();
                      final width = MediaQuery.sizeOf(context).width;

                      // Notify ShellState of the selection so the wide-layout
                      // detail pane updates without a navigation push.
                      shell.selectPeer(peer.id);

                      if (width < 1200) {
                        // Narrow layout: push the detail screen onto the stack.
                        // The 1200px threshold matches the wide-layout breakpoint
                        // in AppShell — below it there is no detail pane.
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (_) =>
                                ContactDetailScreen(peerId: peer.id),
                          ),
                        // Clear the shell selection when returning so the list
                        // row highlight is removed after the user pops back.
                        ).then((_) => shell.selectPeer(null));
                      }
                    },
                  );
                },
              ),
      ),
    );
  }
}
