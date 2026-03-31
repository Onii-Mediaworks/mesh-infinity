import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/widgets/empty_state.dart';
import '../messaging_state.dart';
import '../../../shell/shell_state.dart';
import '../widgets/thread_list_tile.dart';
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
    final directRooms = messaging.rooms.where((room) => !room.isGroup).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Chat'),
        actions: [
          IconButton(
            icon: const Icon(Icons.search_outlined),
            tooltip: 'Search messages',
            onPressed: () async {
              final roomId = await Navigator.push<String>(
                context,
                MaterialPageRoute(builder: (_) => const MessageSearchScreen()),
              );
              if (roomId != null && context.mounted) {
                _openRoom(context, roomId, false);
              }
            },
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
        child: directRooms.isEmpty
            ? EmptyState(
                icon: Icons.chat_bubble_outline,
                title: 'No conversations yet',
                body: 'Add a contact, then start chatting.',
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
