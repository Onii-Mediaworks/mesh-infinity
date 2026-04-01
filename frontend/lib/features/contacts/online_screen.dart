import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../shell/shell_state.dart';
import '../peers/peers_state.dart';
import 'screens/contact_detail_screen.dart';
import '../peers/widgets/peer_tile.dart';

class OnlineScreen extends StatelessWidget {
  const OnlineScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final peers = context.watch<PeersState>();
    final online = peers.peers.where((p) => p.isOnline || p.isIdle).toList();

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: peers.loadPeers,
        child: online.isEmpty
            ? Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
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
                separatorBuilder: (ctx, i) =>
                    const Divider(height: 1, indent: 72),
                itemBuilder: (context, i) {
                  final peer = online[i];
                  return PeerTile(
                    peer: peer,
                    selected: false,
                    onTap: () {
                      final shell = context.read<ShellState>();
                      final width = MediaQuery.sizeOf(context).width;
                      shell.selectPeer(peer.id);
                      if (width < 1200) {
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (_) =>
                                ContactDetailScreen(peerId: peer.id),
                          ),
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
