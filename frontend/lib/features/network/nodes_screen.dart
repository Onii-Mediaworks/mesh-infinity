import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/models/network_models.dart';
import 'network_state.dart';

// Nodes — discovered mesh nodes (mDNS + gossip map).
// Spec: "Network → Nodes = all mesh participants including relay-only and
// unknown nodes" (distinct from Contacts → Online = paired contacts).
class NodesScreen extends StatelessWidget {
  const NodesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final nodes = net.discoveredPeers;

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: nodes.isEmpty
            ? Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.device_hub,
                        size: 56,
                        color: Theme.of(context).colorScheme.outline),
                    const SizedBox(height: 16),
                    Text(
                      'No nodes discovered',
                      style:
                          Theme.of(context).textTheme.titleMedium?.copyWith(
                                color: Theme.of(context).colorScheme.outline,
                              ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Enable mDNS in Transports to find nodes on your LAN.',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Theme.of(context).colorScheme.outline,
                          ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              )
            : ListView.separated(
                itemCount: nodes.length,
                separatorBuilder: (ctx, i) =>
                    const Divider(height: 1, indent: 56),
                itemBuilder: (context, i) => _NodeTile(node: nodes[i]),
              ),
      ),
    );
  }
}

class _NodeTile extends StatelessWidget {
  const _NodeTile({required this.node});
  final DiscoveredPeerModel node;

  @override
  Widget build(BuildContext context) {
    final label = node.displayName.isNotEmpty ? node.displayName : node.id;
    final shortId = node.id.length > 12
        ? '${node.id.substring(0, 12)}…'
        : node.id;

    return ListTile(
      leading: const CircleAvatar(
        child: Icon(Icons.router, size: 20),
      ),
      title: Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: Text(
        node.address.isNotEmpty ? node.address : shortId,
        style: Theme.of(context).textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
            ),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: node.canPair
          ? const Tooltip(
              message: 'Can pair',
              child: Icon(Icons.link, size: 18),
            )
          : null,
    );
  }
}
