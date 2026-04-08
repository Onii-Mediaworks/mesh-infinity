import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/models/room_models.dart';
import '../../shell/shell_state.dart';
import '../messaging/messaging_state.dart';
import '../messaging/screens/thread_screen.dart';
import '../messaging/screens/create_room_screen.dart';

/// The "Rooms" sub-page of the Chat section.
///
/// Shows a scrollable list of group message rooms (rooms where [RoomSummary.isGroup]
/// is true).  Each row is a [_RoomTile] that opens the room's [ThreadScreen].
/// If no group rooms exist yet, [_EmptyRooms] is shown with a shortcut to
/// create one.
///
/// A floating action button is always visible to let the user create a new
/// group room even when the list is non-empty.
class RoomsScreen extends StatelessWidget {
  const RoomsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes to MessagingState — rebuilds whenever rooms
    // change (e.g. after a loadRooms() call or a live backend event).
    final messaging = context.watch<MessagingState>();

    // Filter to group rooms only.  DMs (isGroup == false) are shown in the
    // DirectScreen sibling sub-page, not here.
    final rooms = messaging.rooms.where((r) => r.isGroup).toList();

    return Scaffold(
      body: RefreshIndicator(
        // Pull-to-refresh reloads the full room list from the backend.
        onRefresh: messaging.loadRooms,
        child: rooms.isEmpty
            ? _EmptyRooms(onCreateRoom: () => _openCreateRoom(context))
            : ListView.separated(
                itemCount: rooms.length,
                // Divider indented to 72px aligns with the text column,
                // not the leading avatar — consistent with _DmTile.
                separatorBuilder: (ctx, i) =>
                    const Divider(height: 1, indent: 72),
                itemBuilder: (context, i) =>
                    _RoomTile(room: rooms[i]),
              ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _openCreateRoom(context),
        tooltip: 'New room',
        child: const Icon(Icons.add),
      ),
    );
  }

  /// Pushes [CreateRoomScreen] as a full-page modal route.
  void _openCreateRoom(BuildContext context) {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const CreateRoomScreen()),
    );
  }
}

/// A single row in the group-room list, representing one room.
class _RoomTile extends StatelessWidget {
  const _RoomTile({required this.room});

  /// The group room to display.
  final RoomSummary room;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: CircleAvatar(
        // primaryContainer distinguishes group-room avatars from DM avatars
        // (which use secondaryContainer) — helps users scan at a glance.
        backgroundColor:
            Theme.of(context).colorScheme.primaryContainer,
        child: Text(
          // '#' fallback signals "this is a room" when the name is empty,
          // borrowing the IRC/Slack convention for channel names.
          room.name.isNotEmpty ? room.name[0].toUpperCase() : '#',
          style: TextStyle(
            color: Theme.of(context).colorScheme.onPrimaryContainer,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
      title: Text(
        room.name,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        // Bold title visually flags unread messages without requiring the user
        // to look at the badge — the text weight alone signals activity.
        style: room.unreadCount > 0
            ? const TextStyle(fontWeight: FontWeight.w700)
            : null,
      ),
      // Last message preview — only shown when a message exists.
      subtitle: room.lastMessage.isNotEmpty
          ? Text(
              room.lastMessage,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                // onSurfaceVariant de-emphasises the preview relative to the
                // room name, matching the visual hierarchy in most chat apps.
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            )
          : null,
      // Delegate the unread badge to _UnreadBadge to avoid duplicating the
      // pill-decoration code that also appears in _DmTile.
      trailing: room.unreadCount > 0
          ? _UnreadBadge(count: room.unreadCount)
          : null,
      onTap: () => _open(context, room.id),
    );
  }

  /// Opens the room's [ThreadScreen], adapting to the current screen width.
  void _open(BuildContext context, String roomId) {
    final shell = context.read<ShellState>();
    final width = MediaQuery.sizeOf(context).width;

    // Inform ShellState of the active room in both layouts — the wide-layout
    // detail pane uses this to display the correct thread.
    shell.selectRoom(roomId);

    if (width < 1200) {
      // Narrow layout: no persistent detail pane, so push ThreadScreen on the
      // navigation stack.  The 1200px threshold matches the wide-layout
      // breakpoint in AppShell.
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ThreadScreen(roomId: roomId)),
      // Clear the shell selection when returning so the list row is no longer
      // highlighted after the user pops back.
      ).then((_) => shell.selectRoom(null));
    }
    // Wide layout (≥ 1200px): the detail pane is already visible;
    // setting selectedRoomId above is sufficient to switch the displayed thread.
  }
}

/// Unread count badge displayed in the trailing position of a room list tile.
///
/// Capped at "99+" because very large numbers overflow the pill container on
/// narrow screens and are not meaningfully different from a user perspective —
/// anything over 99 is "a lot of unread messages".
class _UnreadBadge extends StatelessWidget {
  const _UnreadBadge({required this.count});

  /// The number of unread messages in the room.
  final int count;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
      decoration: BoxDecoration(
        // Primary colour makes the badge visually prominent — it is the
        // most important piece of information in a busy room list.
        color: Theme.of(context).colorScheme.primary,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Text(
        count > 99 ? '99+' : '$count',
        style: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w700,
          // White contrasts against any primary colour in both themes.
          color: Colors.white,
        ),
      ),
    );
  }
}

/// Empty state shown when the user has not joined or created any group rooms.
///
/// Provides a single action button to jump straight to room creation,
/// removing friction for new users.
class _EmptyRooms extends StatelessWidget {
  const _EmptyRooms({required this.onCreateRoom});

  /// Callback invoked when the "Create a room" button is tapped.
  final VoidCallback onCreateRoom;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.chat_bubble_outline,
            size: 56,
            // outline colour keeps the icon subdued — secondary visual element.
            color: Theme.of(context).colorScheme.outline,
          ),
          const SizedBox(height: 16),
          Text(
            'No rooms yet',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
              color: Theme.of(context).colorScheme.outline,
            ),
          ),
          const SizedBox(height: 8),
          FilledButton.tonal(
            onPressed: onCreateRoom,
            child: const Text('Create a room'),
          ),
        ],
      ),
    );
  }
}
