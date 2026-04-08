import 'package:flutter/material.dart';

import '../../../backend/models/room_models.dart';

/// ThreadListTile — a single row in the Rooms / Direct-Messages list.
///
/// Displays:
///   - A circular avatar with the room's initial letter (or a fallback icon
///     for rooms with no name).
///   - The room name (or a generic label if the name is empty).
///   - The most recent message preview, truncated to one line.
///   - An unread-count badge when there are unread messages.
///
/// Long-pressing asks the user to confirm before deleting the room.
class ThreadListTile extends StatelessWidget {
  const ThreadListTile({
    super.key,
    required this.room,
    required this.selected,
    required this.onTap,
    required this.onDelete,
  });

  /// The room data to display, including name, last message, and unread count.
  final RoomSummary room;

  /// Whether this tile is the currently active room (highlights background).
  final bool selected;

  /// Called when the user taps the tile to open the room.
  final VoidCallback onTap;

  /// Called after the user confirms deletion of this room.
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // Choose the avatar icon based on room type.  Group rooms (forums, channels)
    // get a multi-bubble icon; direct (1:1) rooms get a person icon.
    final leadingIcon = room.isGroup
        ? Icons.forum_outlined
        : Icons.person_outline;

    // Fallback label used when the room has no name — tells the user whether
    // this is a Garden channel or a private chat without exposing any IDs.
    final fallbackLabel = room.isGroup ? 'Garden' : 'Chat';

    return ListTile(
      selected: selected,
      // Subtle tinted highlight for the active tile without full contrast.
      selectedTileColor: cs.primaryContainer.withValues(alpha: 0.3),
      leading: CircleAvatar(
        backgroundColor: cs.primaryContainer,
        child: room.name.isNotEmpty
            // First letter of the room name as an initial — faster to scan
            // than a generic icon for users who have many rooms.
            ? Text(
                room.name[0].toUpperCase(),
                style: TextStyle(
                  color: cs.onPrimaryContainer,
                  fontWeight: FontWeight.bold,
                ),
              )
            // Fallback icon when the room has no name yet (e.g. a newly
            // created room that hasn't been named, or a one-shot pairing room).
            : Icon(leadingIcon, color: cs.onPrimaryContainer),
      ),
      title: Text(
        room.name.isNotEmpty ? room.name : fallbackLabel,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      // Only render a subtitle row when there is something to show — an empty
      // subtitle would leave an awkward blank line below the title.
      subtitle: room.lastMessage.isNotEmpty
          ? Text(
              room.lastMessage,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.bodySmall,
            )
          : null,
      // Unread badge: shown only when there are unread messages (> 0).
      // null collapses the trailing slot so nothing takes up space.
      trailing: room.unreadCount > 0
          ? Badge(
              label: Text('${room.unreadCount}'),
              backgroundColor: cs.primary,
              textColor: cs.onPrimary,
            )
          : null,
      onTap: onTap,
      // Long-press to delete: hides a destructive action behind a gesture that
      // is harder to trigger accidentally than a swipe or a single tap.
      onLongPress: () => _showDeleteDialog(context),
    );
  }

  /// Shows a confirmation dialog before deleting the room.
  ///
  /// Deletion is permanent on this device, so we require an explicit
  /// confirmation rather than offering an undo snackbar.
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
