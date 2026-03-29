import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/message_models.dart';
import '../messaging_state.dart';

/// Full-text search across all local message history.
///
/// Spec section 10.4: "Full-text search across all local message history.
/// Search is performed locally on the device; no search query leaves the
/// device."
class MessageSearchScreen extends StatefulWidget {
  const MessageSearchScreen({super.key});

  @override
  State<MessageSearchScreen> createState() => _MessageSearchScreenState();
}

class _MessageSearchScreenState extends State<MessageSearchScreen> {
  final _controller = TextEditingController();
  List<MessageModel> _results = [];
  bool _searching = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _search(String query) {
    if (query.trim().length < 2) {
      setState(() => _results = []);
      return;
    }

    setState(() => _searching = true);
    final messaging = context.read<MessagingState>();
    final results = messaging.searchMessages(query.trim());
    setState(() {
      _results = results;
      _searching = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: TextField(
          controller: _controller,
          autofocus: true,
          decoration: const InputDecoration(
            hintText: 'Search messages...',
            border: InputBorder.none,
          ),
          onChanged: _search,
        ),
        actions: [
          if (_controller.text.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.clear),
              onPressed: () {
                _controller.clear();
                setState(() => _results = []);
              },
            ),
        ],
      ),
      body: _searching
          ? const Center(child: CircularProgressIndicator())
          : _results.isEmpty
              ? Center(
                  child: Text(
                    _controller.text.isEmpty
                        ? 'Type to search messages'
                        : 'No results found',
                    style: theme.textTheme.bodyLarge?.copyWith(
                      color: theme.colorScheme.onSurface.withAlpha(150),
                    ),
                  ),
                )
              : ListView.builder(
                  itemCount: _results.length,
                  itemBuilder: (context, index) {
                    final msg = _results[index];
                    return ListTile(
                      leading: Icon(
                        msg.isOutgoing
                            ? Icons.arrow_upward
                            : Icons.arrow_downward,
                        color: msg.isOutgoing
                            ? theme.colorScheme.primary
                            : theme.colorScheme.secondary,
                      ),
                      title: Text(
                        msg.text,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                      subtitle: Text(
                        '${msg.sender} \u2022 ${msg.timestamp}',
                        style: theme.textTheme.bodySmall,
                      ),
                      onTap: () {
                        // Navigate back with the room ID so the caller
                        // can open the thread and scroll to this message.
                        Navigator.of(context).pop(msg.roomId);
                      },
                    );
                  },
                ),
    );
  }
}
