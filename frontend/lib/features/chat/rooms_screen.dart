import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/models/room_models.dart';
import '../../shell/shell_state.dart';
import '../messaging/messaging_state.dart';
import '../messaging/screens/thread_screen.dart';
import '../messaging/screens/create_room_screen.dart';

class RoomsScreen extends StatelessWidget {
  const RoomsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final messaging = context.watch<MessagingState>();
    final rooms = messaging.rooms.where((r) => r.isGroup).toList();

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: messaging.loadRooms,
        child: rooms.isEmpty
            ? _EmptyRooms(onCreateRoom: () => _openCreateRoom(context))
            : ListView.separated(
                itemCount: rooms.length,
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

  void _openCreateRoom(BuildContext context) {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const CreateRoomScreen()),
    );
  }
}

class _RoomTile extends StatelessWidget {
  const _RoomTile({required this.room});
  final RoomSummary room;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: CircleAvatar(
        backgroundColor:
            Theme.of(context).colorScheme.primaryContainer,
        child: Text(
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
        style: room.unreadCount > 0
            ? const TextStyle(fontWeight: FontWeight.w700)
            : null,
      ),
      subtitle: room.lastMessage.isNotEmpty
          ? Text(
              room.lastMessage,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            )
          : null,
      trailing: room.unreadCount > 0
          ? _UnreadBadge(count: room.unreadCount)
          : null,
      onTap: () => _open(context, room.id),
    );
  }

  void _open(BuildContext context, String roomId) {
    final shell = context.read<ShellState>();
    final width = MediaQuery.sizeOf(context).width;
    if (width >= 1200) {
      shell.selectRoom(roomId);
    } else {
      shell.selectRoom(roomId);
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ThreadScreen(roomId: roomId)),
      ).then((_) => shell.selectRoom(null));
    }
  }
}

class _UnreadBadge extends StatelessWidget {
  const _UnreadBadge({required this.count});
  final int count;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primary,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Text(
        count > 99 ? '99+' : '$count',
        style: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w700,
          color: Colors.white,
        ),
      ),
    );
  }
}

class _EmptyRooms extends StatelessWidget {
  const _EmptyRooms({required this.onCreateRoom});
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
