import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/models/room_models.dart';
import '../../shell/shell_state.dart';
import '../messaging/messaging_state.dart';
import '../messaging/screens/thread_screen.dart';

class DirectScreen extends StatelessWidget {
  const DirectScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final messaging = context.watch<MessagingState>();
    final dms = messaging.rooms.where((r) => !r.isGroup).toList();

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: messaging.loadRooms,
        child: dms.isEmpty
            ? const _EmptyDirect()
            : ListView.separated(
                itemCount: dms.length,
                separatorBuilder: (ctx, i) =>
                    const Divider(height: 1, indent: 72),
                itemBuilder: (context, i) => _DmTile(room: dms[i]),
              ),
      ),
    );
  }
}

class _DmTile extends StatelessWidget {
  const _DmTile({required this.room});
  final RoomSummary room;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: CircleAvatar(
        backgroundColor: Theme.of(context).colorScheme.secondaryContainer,
        child: Text(
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
        style: room.unreadCount > 0
            ? const TextStyle(fontWeight: FontWeight.w700)
            : null,
      ),
      subtitle: room.lastMessage.isNotEmpty
          ? Text(
              room.lastMessage,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            )
          : null,
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
        shell.selectRoom(room.id);
        if (width < 1200) {
          Navigator.push(
            context,
            MaterialPageRoute(
                builder: (_) => ThreadScreen(roomId: room.id)),
          ).then((_) => shell.selectRoom(null));
        }
      },
    );
  }
}

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
