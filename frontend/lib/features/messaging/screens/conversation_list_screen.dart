import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../messaging_state.dart';
import '../../../shell/shell_state.dart';
import '../widgets/thread_list_tile.dart';
import 'create_group_screen.dart';
import 'create_room_screen.dart';
import 'thread_screen.dart';
import 'search_screen.dart';

class ConversationListScreen extends StatelessWidget {
  const ConversationListScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final messaging = context.watch<MessagingState>();
    final shell = context.watch<ShellState>();
    final isWide = MediaQuery.sizeOf(context).width >= 1200;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Conversations'),
        actions: [
          IconButton(
            icon: const Icon(Icons.search_outlined),
            tooltip: 'Search messages',
            onPressed: () async {
              final roomId = await Navigator.push<String>(
                context,
                MaterialPageRoute(
                  builder: (_) => const MessageSearchScreen(),
                ),
              );
              if (roomId != null && context.mounted) {
                _openRoom(context, roomId, false);
              }
            },
          ),
          IconButton(
            icon: const Icon(Icons.group_add_outlined),
            tooltip: 'New group',
            onPressed: () => _openCreateGroup(context),
          ),
          IconButton(
            icon: const Icon(Icons.edit_outlined),
            tooltip: 'New conversation',
            onPressed: () => _openCreateRoom(context),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: messaging.loadRooms,
        child: messaging.rooms.isEmpty
            ? _EmptyState(onCreateTap: () => _openCreateRoom(context))
            : ListView.builder(
                itemCount: messaging.rooms.length,
                itemBuilder: (context, i) {
                  final room = messaging.rooms[i];
                  return ThreadListTile(
                    room: room,
                    selected: isWide && shell.selectedRoomId == room.id,
                    onTap: () => _openRoom(context, room.id, isWide),
                    onDelete: () => messaging.deleteRoom(room.id),
                  );
                },
              ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _openCreateRoom(context),
        tooltip: 'New conversation',
        child: const Icon(Icons.add),
      ),
    );
  }

  Future<void> _openCreateGroup(BuildContext context) async {
    final roomId = await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const CreateGroupScreen()),
    );
    if (roomId != null && context.mounted) {
      _openRoom(context, roomId, MediaQuery.sizeOf(context).width >= 1200);
    }
  }

  Future<void> _openCreateRoom(BuildContext context) async {
    await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const CreateRoomScreen()),
    );
  }

  void _openRoom(BuildContext context, String roomId, bool isWide) {
    final messaging = context.read<MessagingState>();
    messaging.selectRoom(roomId);

    if (isWide) {
      context.read<ShellState>().selectRoom(roomId);
    } else {
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ThreadScreen(roomId: roomId)),
      );
    }
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.onCreateTap});

  final VoidCallback onCreateTap;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.chat_bubble_outline, size: 64, color: cs.outline),
          const SizedBox(height: 16),
          Text('No conversations yet', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          TextButton.icon(
            onPressed: onCreateTap,
            icon: const Icon(Icons.add),
            label: const Text('Create one'),
          ),
        ],
      ),
    );
  }
}
