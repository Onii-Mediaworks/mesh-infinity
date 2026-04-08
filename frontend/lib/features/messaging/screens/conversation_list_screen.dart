// conversation_list_screen.dart
//
// ConversationListScreen is the main list screen for the Chat section.
// It shows all direct-message rooms (rooms where isGroup == false).
//
// WHY DOES THIS ONLY SHOW DIRECT ROOMS?
// --------------------------------------
// Group rooms ("gardens") are shown separately in the Garden section.
// The Chat section is specifically for one-on-one (and future small-group)
// private conversations.  Filtering here keeps the two sections coherent
// without duplicating entries.
//
// RESPONSIVE LAYOUT
// -----------------
// Width ≥ 1200 px (wide / desktop):
//   • Tapping a room tile sets ShellState.selectedRoomId.
//   • The shell's detail pane listens to selectedRoomId and renders
//     ThreadScreen inline — no route push.
//   • The selected tile is highlighted (ThreadListTile.selected == true).
//
// Width < 1200 px (mobile / narrow):
//   • Tapping a room pushes ThreadScreen as a full-page route.
//   • No highlight — the whole screen is replaced by the thread.
//
// SEARCH
// ------
// The search icon in the AppBar pushes MessageSearchScreen (the quick
// in-list search).  If the search returns a roomId, we open that room the
// same way a tile tap would.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/widgets/empty_state.dart';
// EmptyState — shared zero-data placeholder widget.
import '../messaging_state.dart';
// MessagingState — the single source of truth for rooms and messages.
import '../../../shell/shell_state.dart';
// ShellState — controls active section, sub-page, and selected room ID.
// AppSection enum lives here too (used to navigate to the contacts section).
import '../widgets/thread_list_tile.dart';
// ThreadListTile — renders one conversation row (avatar, name, preview, badge).
import 'create_room_screen.dart';
// CreateRoomScreen — contact-picker for starting a new direct conversation.
import 'thread_screen.dart';
// ThreadScreen — the full message thread view.
import 'search_screen.dart';
// MessageSearchScreen — local full-text search across all message history.

/// Main list of direct conversations in the Chat section.
///
/// StatelessWidget because all mutable data lives in [MessagingState] and
/// [ShellState].  The screen is purely a projection of those states.
class ConversationListScreen extends StatelessWidget {
  const ConversationListScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes this build to both state objects.
    // MessagingState drives the room list content.
    // ShellState drives the selected-room highlight on wide layouts.
    final messaging = context.watch<MessagingState>();
    final shell = context.watch<ShellState>();

    // True on desktop/wide tablet — triggers inline detail-pane navigation.
    final isWide = MediaQuery.sizeOf(context).width >= 1200;

    // Filter to direct (non-group) rooms only — groups live in Garden section.
    final directRooms = messaging.rooms.where((room) => !room.isGroup).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Chat'),
        actions: [
          // Search button — pushes MessageSearchScreen.
          // On return, if the search yielded a roomId, open that room.
          IconButton(
            icon: const Icon(Icons.search_outlined),
            tooltip: 'Search messages',
            onPressed: () async {
              // await the push so we can act on the returned roomId.
              final roomId = await Navigator.push<String>(
                context,
                MaterialPageRoute(builder: (_) => const MessageSearchScreen()),
              );
              // context.mounted: guard in case the user also popped this screen
              // while the search was open (unlikely but defensive).
              if (roomId != null && context.mounted) {
                _openRoom(context, roomId, false);
              }
            },
          ),
          // Compose button — same action as the FAB for reachability.
          IconButton(
            icon: const Icon(Icons.edit_outlined),
            tooltip: 'New conversation',
            onPressed: () => _openCreateRoom(context),
          ),
        ],
      ),
      body: RefreshIndicator(
        // Pull-to-refresh re-fetches rooms from the backend.
        onRefresh: messaging.loadRooms,
        child: directRooms.isEmpty
            ? EmptyState(
                icon: Icons.chat_bubble_outline,
                title: 'No conversations yet',
                body: 'Add a contact, then start chatting.',
                // Direct the user to the Contacts section to add someone.
                // Once a contact is added, they can start a conversation here.
                action: FilledButton.icon(
                  onPressed: () => shell.selectSection(AppSection.contacts),
                  icon: const Icon(Icons.person_add_outlined),
                  label: const Text('Add a contact'),
                ),
              )
            : ListView.builder(
                itemCount: directRooms.length,
                itemBuilder: (context, i) {
                  final room = directRooms[i];
                  return ThreadListTile(
                    room: room,
                    // Highlight this tile on wide layouts when it is the
                    // currently open room in the detail pane.
                    selected: isWide && shell.selectedRoomId == room.id,
                    onTap: () => _openRoom(context, room.id, isWide),
                    onDelete: () => messaging.deleteRoom(room.id),
                  );
                },
              ),
      ),
      // FAB — always visible, provides a large tap target for starting a
      // conversation without needing to reach the AppBar.
      floatingActionButton: FloatingActionButton(
        onPressed: () => _openCreateRoom(context),
        tooltip: 'New conversation',
        child: const Icon(Icons.add),
      ),
    );
  }

  /// Pushes [CreateRoomScreen] to let the user pick a contact and start a
  /// direct conversation.
  ///
  /// CreateRoomScreen pops with the new room's ID on success.  We do not
  /// act on the returned ID here because MessagingState.loadRooms() is
  /// called by CreateRoomScreen before it pops, so the list updates itself.
  Future<void> _openCreateRoom(BuildContext context) async {
    await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const CreateRoomScreen()),
    );
  }

  /// Opens a room either inline (wide) or as a pushed route (narrow).
  ///
  /// [isWide] determines the navigation strategy:
  ///   - Wide: update ShellState.selectedRoomId; the shell renders ThreadScreen
  ///     in its detail pane.
  ///   - Narrow: push ThreadScreen as a full-screen route.
  ///
  /// In both cases [MessagingState.selectRoom] is called to load messages
  /// and clear the unread badge for this room.
  void _openRoom(BuildContext context, String roomId, bool isWide) {
    final messaging = context.read<MessagingState>();

    // selectRoom tells the backend which room is focused and loads its messages.
    messaging.selectRoom(roomId);

    if (isWide) {
      // Wide layout: update the shell's selected room; the detail pane
      // subscribes to this and renders ThreadScreen inline.
      context.read<ShellState>().selectRoom(roomId);
    } else {
      // Narrow layout: push ThreadScreen as a full-screen route.
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ThreadScreen(roomId: roomId)),
      );
    }
  }
}
