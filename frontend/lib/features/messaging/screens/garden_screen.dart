// garden_screen.dart
//
// GardenScreen is the group-conversation list screen within the messaging
// feature tree.  It is mounted as part of the messaging navigation shell
// and shows all rooms where isGroup == true ("gardens" / communities).
//
// RELATIONSHIP TO channels_screen.dart
// --------------------------------------
// The Garden *section* of the app has its own ChannelsScreen (garden/channels_screen.dart)
// which also lists group rooms.  This GardenScreen serves as the Garden view
// *within the messaging section* when the app is using the unified messaging
// navigation model.  Both screens draw from the same MessagingState data but
// may differ in navigation behaviour or surrounding UI context.
//
// RESPONSIVE NAVIGATION (same pattern as ConversationListScreen)
// ---------------------------------------------------------------
// • Width ≥ 1200 px: tap updates ShellState.selectedRoomId; detail pane
//   renders ThreadScreen inline.
// • Width < 1200 px: tap pushes ThreadScreen as a full-page route.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/widgets/empty_state.dart';
// EmptyState — shared zero-data placeholder.
import '../../../shell/shell_state.dart';
// ShellState — controls selected room for the wide-layout detail pane.
import '../messaging_state.dart';
// MessagingState — source of truth for the rooms list.
import '../widgets/thread_list_tile.dart';
// ThreadListTile — the shared room-list row widget (avatar, name, preview, badge).
import 'create_group_screen.dart';
// CreateGroupScreen — form for creating a new group (name, description, policy).
import 'thread_screen.dart';
// ThreadScreen — full message thread view for a room.

/// Lists all group rooms ("gardens") the user is a member of.
///
/// Provides a FAB and an AppBar icon for creating new gardens.
/// Uses [ThreadListTile] with the same tile shape as direct-chat rooms for
/// visual consistency.
class GardenScreen extends StatelessWidget {
  const GardenScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes to MessagingState AND ShellState so the screen
    // rebuilds when a new message arrives (unread badge change) or when the
    // wide-layout selection changes (highlight update).
    final messaging = context.watch<MessagingState>();
    final shell = context.watch<ShellState>();

    // Wide layouts use master-detail side-by-side presentation.
    final isWide = MediaQuery.sizeOf(context).width >= 1200;

    // Filter to group-type rooms — direct rooms are in ConversationListScreen.
    final communities = messaging.rooms.where((room) => room.isGroup).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Garden'),
        actions: [
          // AppBar action mirrors the FAB for reachability on large screens.
          IconButton(
            icon: const Icon(Icons.group_add_outlined),
            tooltip: 'Create garden',
            onPressed: () => _openCreateGroup(context),
          ),
        ],
      ),
      body: RefreshIndicator(
        // Pull-to-refresh re-fetches rooms from the backend.
        onRefresh: messaging.loadRooms,
        child: communities.isEmpty
            ? EmptyState(
                icon: Icons.groups_outlined,
                title: 'No gardens yet',
                body:
                    'Create a shared space for ongoing group and community conversations.',
                action: FilledButton.icon(
                  onPressed: () => _openCreateGroup(context),
                  icon: const Icon(Icons.group_add_outlined),
                  label: const Text('Create a garden'),
                ),
              )
            : ListView.builder(
                itemCount: communities.length,
                itemBuilder: (context, index) {
                  final community = communities[index];
                  return ThreadListTile(
                    room: community,
                    // Highlight on wide layout when this is the open room.
                    selected:
                        isWide && shell.selectedRoomId == community.id,
                    onTap: () => _openCommunity(context, community.id, isWide),
                    onDelete: () => messaging.deleteRoom(community.id),
                  );
                },
              ),
      ),
      // Extended FAB with a label for discoverability — the user may not
      // immediately recognise the AppBar icon's purpose.
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _openCreateGroup(context),
        icon: const Icon(Icons.add),
        label: const Text('New garden'),
      ),
    );
  }

  /// Pushes [CreateGroupScreen] and, if a group was successfully created,
  /// immediately opens its thread.
  ///
  /// Awaiting the push lets us react to the returned roomId before the
  /// navigator stack settles — necessary so the user lands in the new
  /// thread without an extra tap.
  Future<void> _openCreateGroup(BuildContext context) async {
    final roomId = await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const CreateGroupScreen()),
    );
    // If a garden was created, open its thread immediately.
    // Check context.mounted because the push was async and this widget
    // might have been disposed by the time it completes.
    if (roomId != null && context.mounted) {
      _openCommunity(context, roomId, MediaQuery.sizeOf(context).width >= 1200);
    }
  }

  /// Opens a community thread, either inline (wide) or as a pushed route (narrow).
  ///
  /// Same responsive-navigation pattern as ConversationListScreen._openRoom().
  ///   Wide:   update ShellState.selectedRoomId → detail pane rebuilds.
  ///   Narrow: push ThreadScreen as a full-screen route.
  void _openCommunity(BuildContext context, String roomId, bool isWide) {
    final messaging = context.read<MessagingState>();

    // Tell the backend and MessagingState which room is now active — this
    // loads messages and clears the unread badge.
    messaging.selectRoom(roomId);

    if (isWide) {
      // Wide layout: update the shell's selected room so the detail pane
      // renders ThreadScreen without a route push.
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
