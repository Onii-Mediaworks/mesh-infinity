import 'package:flutter/material.dart';

import '../../../backend/models/room_models.dart';

class ThreadListTile extends StatelessWidget {
  const ThreadListTile({
    super.key,
    required this.room,
    required this.selected,
    required this.onTap,
    required this.onDelete,
  });

  final RoomSummary room;
  final bool selected;
  final VoidCallback onTap;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListTile(
      selected: selected,
      selectedTileColor: cs.primaryContainer.withValues(alpha: 0.3),
      leading: CircleAvatar(
        backgroundColor: cs.primaryContainer,
        child: Text(
          room.name.isNotEmpty ? room.name[0].toUpperCase() : '?',
          style: TextStyle(color: cs.onPrimaryContainer, fontWeight: FontWeight.bold),
        ),
      ),
      title: Text(room.name, maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: room.lastMessage.isNotEmpty
          ? Text(
              room.lastMessage,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.bodySmall,
            )
          : null,
      trailing: room.unreadCount > 0
          ? Badge(
              label: Text('${room.unreadCount}'),
              backgroundColor: cs.primary,
              textColor: cs.onPrimary,
            )
          : null,
      onTap: onTap,
      onLongPress: () => _showDeleteDialog(context),
    );
  }

  void _showDeleteDialog(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete Room'),
        content: Text('Delete "${room.name}"? This cannot be undone.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.pop(ctx);
              onDelete();
            },
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }
}
