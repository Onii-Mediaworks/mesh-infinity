import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/widgets/empty_state.dart';
import '../../../shell/shell_state.dart';
import '../messaging_state.dart';
import '../widgets/thread_list_tile.dart';
import 'create_group_screen.dart';
import 'thread_screen.dart';

class GardenScreen extends StatelessWidget {
  const GardenScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final messaging = context.watch<MessagingState>();
    final shell = context.watch<ShellState>();
    final isWide = MediaQuery.sizeOf(context).width >= 1200;
    final communities = messaging.rooms.where((room) => room.isGroup).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Garden'),
        actions: [
          IconButton(
            icon: const Icon(Icons.group_add_outlined),
            tooltip: 'Create garden',
            onPressed: () => _openCreateGroup(context),
          ),
        ],
      ),
      body: RefreshIndicator(
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
                    selected:
                        isWide && shell.selectedCommunityId == community.id,
                    onTap: () => _openCommunity(context, community.id, isWide),
                    onDelete: () => messaging.deleteRoom(community.id),
                  );
                },
              ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _openCreateGroup(context),
        icon: const Icon(Icons.add),
        label: const Text('New garden'),
      ),
    );
  }

  Future<void> _openCreateGroup(BuildContext context) async {
    final roomId = await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const CreateGroupScreen()),
    );
    if (roomId != null && context.mounted) {
      _openCommunity(context, roomId, MediaQuery.sizeOf(context).width >= 1200);
    }
  }

  void _openCommunity(BuildContext context, String roomId, bool isWide) {
    final messaging = context.read<MessagingState>();
    messaging.selectRoom(roomId);

    if (isWide) {
      context.read<ShellState>().selectCommunity(roomId);
    } else {
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ThreadScreen(roomId: roomId)),
      );
    }
  }
}
