// channels_screen.dart
//
// ChannelsScreen is sub-page 0 of the Garden section.  It shows the list of
// group rooms ("gardens") the local user is a member of.
//
// WHAT IS A "GARDEN"?
// -------------------
// In Mesh Infinity's terminology, a "garden" is a named group conversation —
// the multi-participant equivalent of a direct-message room.  Gardens are
// backed by the same Room concept as direct chats; the distinction is the
// `isGroup` flag on RoomSummary.  The Chat section shows rooms where
// isGroup == false (direct messages); the Garden section shows rooms where
// isGroup == true.
//
// NAVIGATION
// ----------
// • Tapping a garden tile on a narrow screen (< 1200 px) pushes ThreadScreen
//   as a full-page route.
// • On wide screens (≥ 1200 px) the tile updates ShellState.selectedRoomId,
//   which the side-panel in the shell listens to in order to display
//   ThreadScreen in the detail pane without pushing a route.
//
// EMPTY STATE
// -----------
// If the user belongs to no gardens, _EmptyGarden is shown.  Its "Find a
// garden" button calls ShellState.selectSubPage(2) to navigate the user
// to the Explore sub-page (index 2) where discoverable public gardens are listed.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/models/room_models.dart';
// RoomSummary — typed model for one room: id, name, isGroup, lastMessage,
// unreadCount, timestamp.
import '../../shell/shell_state.dart';
// ShellState — controls which section/sub-page/room is currently active.
import '../messaging/messaging_state.dart';
// MessagingState — owns the rooms list and exposes loadRooms() / selectRoom().
import '../messaging/screens/thread_screen.dart';
// ThreadScreen — the full message thread view for a room.

/// Lists the group rooms ("gardens") the user has joined.
///
/// Gardens are group-type rooms (RoomSummary.isGroup == true) — they use the
/// same backend Room concept as direct chats but are presented differently
/// in the UI to emphasise the community/channel nature.
class ChannelsScreen extends StatelessWidget {
  const ChannelsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes this build to MessagingState changes so the
    // list rebuilds when a garden is joined, a message arrives, or unread
    // counts update.
    final messaging = context.watch<MessagingState>();

    // Filter to only the group-type rooms — direct-message rooms are shown
    // in the Chat section, not here.
    final gardens = messaging.rooms.where((r) => r.isGroup).toList();

    return Scaffold(
      body: RefreshIndicator(
        // Pull-to-refresh re-fetches the room list from the backend.
        onRefresh: messaging.loadRooms,
        child: gardens.isEmpty
            ? _EmptyGarden(
                // Navigate to the Explore tab (sub-page index 2) when the
                // user wants to discover public gardens to join.
                onExplore: () =>
                    context.read<ShellState>().selectSubPage(2), // → Explore
              )
            : ListView.separated(
                itemCount: gardens.length,
                // 1px divider indented to 72px to align with the text
                // start point past the avatar (40px) + padding.
                separatorBuilder: (ctx, i) =>
                    const Divider(height: 1, indent: 72),
                itemBuilder: (context, i) =>
                    _GardenTile(room: gardens[i]),
              ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _GardenTile — one row in the channels list
// ---------------------------------------------------------------------------

/// Displays a single garden's name, last-message preview, and unread count.
///
/// Tapping opens the garden's thread view.  Navigation is responsive:
///   - Narrow (< 1200 px): push [ThreadScreen] as a full-page route.
///   - Wide (≥ 1200 px): update [ShellState.selectedRoomId] to show the
///     thread in the master-detail side pane without a route push.
class _GardenTile extends StatelessWidget {
  const _GardenTile({required this.room});
  final RoomSummary room;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      // Avatar: first letter of the garden name on a tertiary-container circle.
      // Falls back to 'G' if the name is empty (should not happen in practice).
      leading: CircleAvatar(
        backgroundColor: Theme.of(context).colorScheme.tertiaryContainer,
        child: Text(
          room.name.isNotEmpty ? room.name[0].toUpperCase() : 'G',
          style: TextStyle(
            color: Theme.of(context).colorScheme.onTertiaryContainer,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),

      // Garden name — bold when there are unread messages to draw attention.
      title: Text(
        room.name,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: room.unreadCount > 0
            ? const TextStyle(fontWeight: FontWeight.w700)
            : null,
      ),

      // Last-message preview — null subtitle omits the row entirely rather
      // than showing an empty line.
      subtitle: room.lastMessage.isNotEmpty
          ? Text(room.lastMessage,
              maxLines: 1, overflow: TextOverflow.ellipsis)
          : null,

      // Unread badge — shown only when unreadCount > 0.
      // Caps at "99+" to keep the pill narrow on small screens.
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

        // Tell MessagingState the active room so messages are loaded
        // and the unread counter is cleared.
        shell.selectRoom(room.id);

        if (width < 1200) {
          // Narrow layout: push the thread as a full-page route.
          // When the user pops back, clear the selected room in ShellState
          // so the side pane does not remain highlighted.
          Navigator.push(
            context,
            MaterialPageRoute(
                builder: (_) => ThreadScreen(roomId: room.id)),
          ).then((_) => shell.selectRoom(null));
        }
        // Wide layout: ShellState.selectRoom() already updated the selected
        // room ID, which the detail pane listens to.  No route push needed.
      },
    );
  }
}

// ---------------------------------------------------------------------------
// _EmptyGarden — zero-state placeholder
// ---------------------------------------------------------------------------

/// Shown when the user has not joined any gardens yet.
///
/// The "Find a garden" button navigates to the Explore sub-page so the user
/// can browse public or open gardens without leaving the Garden section.
class _EmptyGarden extends StatelessWidget {
  const _EmptyGarden({required this.onExplore});

  /// Callback that navigates to the Explore sub-page (index 2).
  final VoidCallback onExplore;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Forest icon is the brand icon for Gardens throughout the app.
          Icon(Icons.forest_outlined,
              size: 56,
              color: Theme.of(context).colorScheme.outline),
          const SizedBox(height: 16),
          Text(
            'No gardens joined yet',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                ),
          ),
          const SizedBox(height: 8),
          FilledButton.tonal(
            onPressed: onExplore,
            child: const Text('Find a garden'),
          ),
        ],
      ),
    );
  }
}
