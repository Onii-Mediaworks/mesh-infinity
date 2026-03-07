import 'package:flutter/material.dart';

import '../../../backend/models/peer_models.dart';
import 'trust_badge.dart';

class PeerTile extends StatelessWidget {
  const PeerTile({
    super.key,
    required this.peer,
    required this.selected,
    required this.onTap,
  });

  final PeerModel peer;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final statusColor = peer.isOnline
        ? Colors.green
        : peer.isIdle
            ? Colors.orange
            : Colors.grey;

    return ListTile(
      selected: selected,
      selectedTileColor: cs.primaryContainer.withValues(alpha: 0.3),
      leading: Stack(
        children: [
          CircleAvatar(
            backgroundColor: cs.secondaryContainer,
            child: Text(
              peer.name.isNotEmpty ? peer.name[0].toUpperCase() : '?',
              style: TextStyle(color: cs.onSecondaryContainer, fontWeight: FontWeight.bold),
            ),
          ),
          Positioned(
            right: 0,
            bottom: 0,
            child: Container(
              width: 10,
              height: 10,
              decoration: BoxDecoration(
                color: statusColor,
                shape: BoxShape.circle,
                border: Border.all(color: cs.surface, width: 1.5),
              ),
            ),
          ),
        ],
      ),
      title: Text(peer.name.isNotEmpty ? peer.name : peer.id.substring(0, 12)),
      subtitle: Text(
        peer.status,
        style: Theme.of(context).textTheme.bodySmall,
      ),
      trailing: TrustBadge(level: peer.trustLevel, compact: true),
      onTap: onTap,
    );
  }
}
