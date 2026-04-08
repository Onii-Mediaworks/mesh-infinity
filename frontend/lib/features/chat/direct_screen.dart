import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/models/room_models.dart';
import '../../shell/shell_state.dart';
import '../messaging/messaging_state.dart';
import '../messaging/screens/thread_screen.dart';

/// The "Direct" sub-page of the Chat section.
///
/// Shows a scrollable list of one-to-one (non-group) message rooms.  Each
/// entry is a [_DmTile] that opens the conversation's [ThreadScreen] when
/// tapped.  If there are no DM rooms, [_EmptyDirect] is shown instead.
///
/// This screen is one of the sub-pages managed by [SectionBottomBar] inside
/// the Chat section; the Rooms sub-page is its sibling.
class DirectScreen extends StatelessWidget {
  const DirectScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // context.watch<MessagingState>() subscribes this widget to MessagingState.
    // Any time rooms are loaded or updated, this widget rebuilds automatically.
    final messaging = context.watch<MessagingState>();

    // Filter to only non-group rooms — DMs are individual conversations
    // between exactly two peers (isGroup == false).
    final dms = messaging.rooms.where((r) => !r.isGroup).toList();

    return Scaffold(
      body: RefreshIndicator(
        // Pull-to-refresh triggers a full reload of all rooms from the backend.
        onRefresh: messaging.loadRooms,
        child: dms.isEmpty
            ? const _EmptyDirect()
            : ListView.separated(
                itemCount: dms.length,
                // Divider with an indent of 72px — indented to align with the
                // text column rather than running under the leading avatar.
                separatorBuilder: (ctx, i) =>
                    const Divider(height: 1, indent: 72),
                itemBuilder: (context, i) => _DmTile(room: dms[i]),
              ),
      ),
    );
  }
}

/// A single row in the DM list, representing one direct message room.
class _DmTile extends StatelessWidget {
  const _DmTile({required this.room});

  /// The DM room to display.
  final RoomSummary room;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: CircleAvatar(
        // secondaryContainer gives DM avatars a different colour from group
        // room avatars (which use primaryContainer), helping users distinguish
        // the two room types at a glance.
        backgroundColor: Theme.of(context).colorScheme.secondaryContainer,
        child: Text(
          // Initial letter of the peer's name.  Falls back to '?' for rooms
          // with an empty or missing name (e.g. a room created before the peer
          // has set a display name).
          room.name.isNotEmpty ? room.name[0].toUpperCase() : '?',
          style: TextStyle(
            color: Theme.of(context).colorScheme.onSecondaryContainer,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
      title: Text(
        room.name,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        // Bold title signals unread messages — a common mobile chat convention
        // that lets users scan for new activity without reading each row.
        style: room.unreadCount > 0
            ? const TextStyle(fontWeight: FontWeight.w700)
            : null,
      ),
      // Show the most recent message as a subtitle only if one exists.
      // An absent lastMessage (empty string) means the room was just created.
      subtitle: room.lastMessage.isNotEmpty
          ? Text(
              room.lastMessage,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            )
          : null,
      // Unread badge — shown as a pill in the trailing position.
      // Capped at "99+" to prevent the badge from overflowing its container
      // with very large unread counts (e.g. after a long offline period).
      trailing: room.unreadCount > 0
          ? Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primary,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                room.unreadCount > 99 ? '99+' : '${room.unreadCount}',
                style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                  color: Colors.white,
                ),
              ),
            )
          : null,
      onTap: () {
        final shell = context.read<ShellState>();
        final width = MediaQuery.sizeOf(context).width;

        // Inform ShellState of the selected room regardless of layout — the
        // desktop detail pane uses selectedRoomId to decide what to display.
        shell.selectRoom(room.id);

        if (width < 1200) {
          // On narrow screens (phones, small tablets) the detail pane does not
          // exist, so we push ThreadScreen as a full-page route.
          // The 1200px threshold matches the wide-layout breakpoint in
          // AppShell — below it, the navigation is always single-column.
          Navigator.push(
            context,
            MaterialPageRoute(
                builder: (_) => ThreadScreen(roomId: room.id)),
          // When the user pops back from ThreadScreen, clear the selected
          // room so the shell does not show a stale selection highlight.
          ).then((_) => shell.selectRoom(null));
        }
        // On wide screens (≥ 1200px), the detail pane is always visible
        // alongside the list — no navigation push needed.
      },
    );
  }
}

/// Empty state shown when the user has no direct message conversations.
///
/// Directs the user to the pairing flow as the first step to starting a DM —
/// you can only message contacts you have paired with (§10.1.1).
class _EmptyDirect extends StatelessWidget {
  const _EmptyDirect();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.chat_outlined,
              size: 56,
              color: Theme.of(context).colorScheme.outline),
          const SizedBox(height: 16),
          Text(
            'No direct messages',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                ),
          ),
          const SizedBox(height: 8),
          Text(
            'Pair with a contact to start a conversation.',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                ),
          ),
        ],
      ),
    );
  }
}
