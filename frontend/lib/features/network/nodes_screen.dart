import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/models/network_models.dart';
import 'network_state.dart';

/// NodesScreen — lists every mesh node this device has discovered.
///
/// "Nodes" and "Contacts" are deliberately separate concepts:
///   - Nodes (this screen): every mesh participant this device has heard from,
///     including relay-only nodes and anonymous newcomers.  Discovery happens
///     via mDNS (local LAN broadcasts) and the gossip routing map (nodes
///     advertised by peers we are already connected to).
///   - Contacts / Online (Contacts tab): only nodes we have explicitly paired
///     with — i.e. nodes whose identity key we have verified and stored.
///
/// The distinction matters for privacy: a node can be on the mesh and help
/// route traffic without ever knowing the identities of the nodes it relays
/// for.  This screen is useful for administrators and power users who want to
/// see the full mesh topology.
///
/// Pull-to-refresh triggers [NetworkState.loadAll] which re-fetches the peer
/// list from the Rust backend.
class NodesScreen extends StatelessWidget {
  const NodesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    // discoveredPeers is populated by the backend's mDNS listener and gossip
    // map — it is empty until mDNS is enabled or at least one peer is known.
    final nodes = net.discoveredPeers;

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: nodes.isEmpty
            // Empty state — shown when no nodes have been discovered yet.
            // The hint text nudges the user toward enabling mDNS, which is the
            // most common way to find nodes on a local network.
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
            // List of discovered nodes with a hairline divider between rows.
            // The divider is indented (indent: 56) to align with the tile text,
            // not the leading icon, matching Material 3 list conventions.
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

/// _NodeTile — one row in the nodes list.
///
/// Shows the node's display name (or truncated ID if unnamed), its network
/// address or short ID, and a pairing-available indicator.
class _NodeTile extends StatelessWidget {
  const _NodeTile({required this.node});

  /// The discovered peer data to display.
  final DiscoveredPeerModel node;

  @override
  Widget build(BuildContext context) {
    // Prefer the human-readable display name; fall back to the raw peer ID
    // when the node hasn't advertised a name (common for relay-only nodes).
    final label = node.displayName.isNotEmpty ? node.displayName : node.id;

    // Truncate long IDs for display: show the first 12 characters followed by
    // an ellipsis.  Full IDs are 64+ hex chars; showing the whole thing would
    // overflow the subtitle.
    final shortId = node.id.length > 12
        ? '${node.id.substring(0, 12)}…'
        : node.id;

    return ListTile(
      // Router icon signals that this is a network node, not a contact profile.
      leading: const CircleAvatar(
        child: Icon(Icons.router, size: 20),
      ),
      title: Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
      // Show the IP address when available (useful for LAN nodes found via mDNS).
      // Fall back to the short peer ID when no address was advertised.
      subtitle: Text(
        node.address.isNotEmpty ? node.address : shortId,
        style: Theme.of(context).textTheme.bodySmall?.copyWith(
              // Monospace font for addresses and IDs — easier to read hex/IP.
              fontFamily: 'monospace',
            ),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      // "Can pair" badge — shown when the node has advertised a public key
      // and supports the Mesh Infinity pairing handshake.  Nodes without this
      // capability (e.g. legacy relay nodes) cannot be added as contacts.
      trailing: node.canPair
          ? const Tooltip(
              message: 'Can pair',
              child: Icon(Icons.link, size: 18),
            )
          : null,
    );
  }
}
