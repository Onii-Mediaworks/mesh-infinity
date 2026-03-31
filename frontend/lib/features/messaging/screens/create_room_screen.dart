import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/peer_models.dart';
import '../../../core/widgets/empty_state.dart';
import '../../peers/peers_state.dart';
import '../messaging_state.dart';
import 'create_group_screen.dart';

class CreateRoomScreen extends StatefulWidget {
  const CreateRoomScreen({super.key});

  @override
  State<CreateRoomScreen> createState() => _CreateRoomScreenState();
}

class _CreateRoomScreenState extends State<CreateRoomScreen> {
  final TextEditingController _searchController = TextEditingController();
  bool _creating = false;

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _startConversation(PeerModel peer) async {
    setState(() => _creating = true);
    final roomName = peer.name.isNotEmpty
        ? peer.name
        : peer.id.substring(0, 12);
    final id = await context.read<MessagingState>().createRoom(roomName);
    if (!mounted) return;
    if (id != null) {
      Navigator.pop(context, id);
    } else {
      setState(() => _creating = false);
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Failed to create room')));
    }
  }

  Future<void> _createGroup() async {
    final roomId = await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const CreateGroupScreen()),
    );
    if (roomId != null && mounted) {
      Navigator.pop(context, roomId);
    }
  }

  @override
  Widget build(BuildContext context) {
    final peersState = context.watch<PeersState>();
    final query = _searchController.text.trim().toLowerCase();
    final contacts =
        peersState.peers.where((peer) {
          if (query.isEmpty) return true;
          return peer.name.toLowerCase().contains(query) ||
              peer.id.toLowerCase().contains(query);
        }).toList()..sort(
          (a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()),
        );

    return Scaffold(
      appBar: AppBar(
        title: const Text('New Conversation'),
        leading: const CloseButton(),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: TextField(
              controller: _searchController,
              autofocus: true,
              decoration: InputDecoration(
                prefixIcon: const Icon(Icons.search),
                hintText: 'Search contacts...',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(999),
                ),
                isDense: true,
              ),
              onChanged: (_) => setState(() {}),
            ),
          ),
          ListTile(
            leading: CircleAvatar(
              backgroundColor: Theme.of(context).colorScheme.primaryContainer,
              child: Icon(
                Icons.group_add_outlined,
                color: Theme.of(context).colorScheme.onPrimaryContainer,
              ),
            ),
            title: const Text('New group conversation'),
            onTap: _creating ? null : _createGroup,
          ),
          const Divider(height: 1),
          Expanded(
            child: peersState.peers.isEmpty
                ? const EmptyState(
                    icon: Icons.people_outline,
                    title: 'No contacts yet',
                    body:
                        'Add contacts first, then start a conversation from here.',
                  )
                : contacts.isEmpty
                ? const EmptyState(
                    icon: Icons.search_off_outlined,
                    title: 'No contacts found',
                    body: 'Try a different name or peer ID.',
                    compact: true,
                  )
                : ListView.builder(
                    itemCount: contacts.length,
                    itemBuilder: (context, index) {
                      final contact = contacts[index];
                      final title = contact.name.isNotEmpty
                          ? contact.name
                          : contact.id.substring(0, 12);
                      return ListTile(
                        leading: CircleAvatar(
                          child: Text(title[0].toUpperCase()),
                        ),
                        title: Text(title),
                        subtitle: Text(contact.trustLevel.label),
                        trailing: contact.isOnline
                            ? const Icon(
                                Icons.circle,
                                size: 10,
                                color: Colors.green,
                              )
                            : null,
                        onTap: _creating
                            ? null
                            : () => _startConversation(contact),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}
