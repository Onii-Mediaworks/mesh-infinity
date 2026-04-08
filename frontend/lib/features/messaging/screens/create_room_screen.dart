// create_room_screen.dart
//
// CreateRoomScreen lets the user start a new conversation from their contact list.
// It is pushed from ConversationListScreen's FAB / compose icon.
//
// TWO PATHS FROM THIS SCREEN
// --------------------------
//   1. New direct conversation — user taps a contact tile.
//      → _startConversation() creates a direct-message room and pops with roomId.
//
//   2. New group conversation — user taps the "New group conversation" tile
//      at the top.
//      → Pushes CreateGroupScreen, then pops with the returned roomId.
//
// WHY DOES THE ROOM USE THE CONTACT'S NAME?
// -----------------------------------------
// The backend stores a room's name as a display label.  For direct rooms the
// label is the peer's display name (or a truncated peer ID as a fallback),
// so the room appears in the list with the contact's name rather than as
// "Room #abc123...".
//
// WHY IS THERE A SEARCH FIELD?
// ----------------------------
// Contacts are sorted alphabetically, but users with many contacts benefit from
// live filtering.  The search runs entirely client-side (no backend call) —
// it filters the already-loaded PeersState.peers list on every keystroke.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/peer_models.dart';
// PeerModel — typed peer data: id, name, isOnline, trustLevel.
import '../../../core/widgets/empty_state.dart';
// EmptyState — shared zero-data placeholder.
import '../../peers/peers_state.dart';
// PeersState — ChangeNotifier owning the paired-peer list.
import '../messaging_state.dart';
// MessagingState — exposes createRoom() which calls the backend.
import 'create_group_screen.dart';
// CreateGroupScreen — pushed when the user wants a group conversation.

/// Contact-picker for starting a new direct or group conversation.
///
/// Pops with the new room's ID (String) on success, or without a value if
/// the user cancels.
class CreateRoomScreen extends StatefulWidget {
  const CreateRoomScreen({super.key});

  @override
  State<CreateRoomScreen> createState() => _CreateRoomScreenState();
}

class _CreateRoomScreenState extends State<CreateRoomScreen> {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// Controller for the search/filter TextField.
  final TextEditingController _searchController = TextEditingController();

  /// True while a room-creation or group-creation call is in flight.
  /// Disables all tap targets to prevent racing concurrent creates.
  bool _creating = false;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void dispose() {
    // Release the text input resources held by the controller.
    _searchController.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  /// Creates a direct-message room with [peer] and navigates there.
  ///
  /// The room name is the peer's display name, falling back to a 12-character
  /// truncated peer ID if the name is empty (e.g. unnamed peers discovered via
  /// Bluetooth who have not set a profile name).
  ///
  /// On success: pops the screen with the new roomId so the caller
  /// (ConversationListScreen) can open the thread.
  ///
  /// On failure: shows a SnackBar and clears the _creating flag so the user
  /// can try again (e.g. if the peer went offline between tap and create).
  Future<void> _startConversation(PeerModel peer) async {
    setState(() => _creating = true);

    // Use the peer's display name as the room label; fall back to the first
    // 12 characters of the peer ID if the name has not been set.
    final roomName = peer.name.isNotEmpty
        ? peer.name
        : peer.id.substring(0, 12);

    final id = await context.read<MessagingState>().createRoom(roomName);

    // Guard: user could navigate away while the async call was in flight.
    if (!mounted) return;

    if (id != null) {
      // Pop with the new roomId so the caller can navigate to the thread.
      Navigator.pop(context, id);
    } else {
      // Creation failed — clear the spinner and let the user try again.
      setState(() => _creating = false);
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Failed to create room')));
    }
  }

  /// Pushes [CreateGroupScreen] and, if a group was created, pops this screen
  /// with the returned roomId so the navigation chain propagates all the way
  /// back to ConversationListScreen (or GardenScreen).
  Future<void> _createGroup() async {
    final roomId = await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const CreateGroupScreen()),
    );
    // If CreateGroupScreen returned a roomId, bubble it up to our caller.
    if (roomId != null && mounted) {
      Navigator.pop(context, roomId);
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes to PeersState so the list updates if a peer
    // connects or disconnects while the screen is open.
    final peersState = context.watch<PeersState>();

    // Client-side filter — runs on every keystroke without a backend call.
    // Compares against both name and peer ID so the user can search by
    // partial ID for peers they haven't named yet.
    final query = _searchController.text.trim().toLowerCase();
    final contacts =
        peersState.peers.where((peer) {
          if (query.isEmpty) return true; // No filter — show all.
          return peer.name.toLowerCase().contains(query) ||
              peer.id.toLowerCase().contains(query);
        }).toList()
        // Sort alphabetically by lowercase name so the list is predictable.
        ..sort(
          (a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()),
        );

    return Scaffold(
      appBar: AppBar(
        title: const Text('New Conversation'),
        // CloseButton pops the screen; semantically more correct than a
        // BackButton since this is a modal-style workflow.
        leading: const CloseButton(),
      ),
      body: Column(
        children: [
          // Search / filter field — autofocused so the keyboard appears
          // immediately and the user can start typing a name.
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: TextField(
              controller: _searchController,
              autofocus: true,
              decoration: InputDecoration(
                prefixIcon: const Icon(Icons.search),
                hintText: 'Search contacts...',
                border: OutlineInputBorder(
                  // Very large radius produces a pill/stadium shape which
                  // is the M3 recommended style for search fields.
                  borderRadius: BorderRadius.circular(999),
                ),
                isDense: true,
              ),
              // Rebuild the list on every keystroke to apply the new filter.
              onChanged: (_) => setState(() {}),
            ),
          ),

          // "New group conversation" entry — always visible above the contact
          // list so the user can start a group without needing to scroll.
          ListTile(
            leading: CircleAvatar(
              backgroundColor: Theme.of(context).colorScheme.primaryContainer,
              child: Icon(
                Icons.group_add_outlined,
                color: Theme.of(context).colorScheme.onPrimaryContainer,
              ),
            ),
            title: const Text('New group conversation'),
            // Disable during an in-flight create to prevent concurrent ops.
            onTap: _creating ? null : _createGroup,
          ),
          const Divider(height: 1),

          // Contact list — takes all remaining height.
          Expanded(
            child: peersState.peers.isEmpty
                ? const EmptyState(
                    // No peers at all — direct the user to pair first.
                    icon: Icons.people_outline,
                    title: 'No contacts yet',
                    body:
                        'Add contacts first, then start a conversation from here.',
                  )
                : contacts.isEmpty
                ? const EmptyState(
                    // Contacts exist but none match the search query.
                    icon: Icons.search_off_outlined,
                    title: 'No contacts found',
                    body: 'Try a different name or peer ID.',
                    // compact: true uses smaller icon + tighter spacing —
                    // appropriate for a search-mismatch state where the
                    // user knows contacts exist but typed the wrong thing.
                    compact: true,
                  )
                : ListView.builder(
                    itemCount: contacts.length,
                    itemBuilder: (context, index) {
                      final contact = contacts[index];
                      // Display name: use the peer's set name, or a truncated
                      // peer ID if the name has not been set.
                      final title = contact.name.isNotEmpty
                          ? contact.name
                          : contact.id.substring(0, 12);
                      return ListTile(
                        leading: CircleAvatar(
                          // First letter of the display name as the avatar initial.
                          child: Text(title[0].toUpperCase()),
                        ),
                        title: Text(title),
                        // Show the peer's trust level label as a secondary
                        // line so the user can gauge relationship depth
                        // before starting a conversation.
                        subtitle: Text(contact.trustLevel.label),
                        // Green dot indicates the peer is currently online
                        // and likely to receive messages promptly.
                        trailing: contact.isOnline
                            ? const Icon(
                                Icons.circle,
                                size: 10,
                                color: Colors.green,
                              )
                            : null,
                        // Disable taps while a room-create is in flight.
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
