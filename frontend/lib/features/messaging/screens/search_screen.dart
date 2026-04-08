// search_screen.dart
//
// MessageSearchScreen is a lightweight quick-search screen pushed from the
// Chat section's AppBar search icon.
//
// HOW IS THIS DIFFERENT FROM ConversationSearchScreen?
// -----------------------------------------------------
// ConversationSearchScreen (conversation_search_screen.dart) is the full-
// featured search with debouncing, inline match highlighting, and per-result
// room context display.
//
// MessageSearchScreen is the simpler version: no debouncing (searches
// synchronously on every keystroke), no highlighting, simpler list tiles.
// It exists because it was the original search implementation and is still
// used by the Chat section's AppBar icon path.
//
// PRIVACY GUARANTEE
// -----------------
// All searching happens locally — the query is passed to the Rust backend
// which scans the on-device SQLite message store.  No query text ever
// leaves the device (§10.4).
//
// RESULT NAVIGATION
// -----------------
// Tapping a result pops this screen with the room ID so the caller
// (ConversationListScreen) can open the correct thread and scroll to the
// relevant message.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/message_models.dart';
// MessageModel — typed result: id, roomId, sender, text, timestamp, isOutgoing.
import '../messaging_state.dart';
// MessagingState — searchMessages() calls through BackendBridge to Rust.

/// Quick full-text search across all local message history (§10.4).
///
/// Pushed from [ConversationListScreen]'s search icon.
/// Pops with the selected [roomId] so the caller can open the thread.
class MessageSearchScreen extends StatefulWidget {
  const MessageSearchScreen({super.key});

  @override
  State<MessageSearchScreen> createState() => _MessageSearchScreenState();
}

class _MessageSearchScreenState extends State<MessageSearchScreen> {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// Controller for the AppBar search field.
  final _controller = TextEditingController();

  /// Results from the most recent search call.
  List<MessageModel> _results = [];

  /// True while the synchronous search call is running.
  /// Because the search is synchronous (FFI call), this flag transitions
  /// true → false within a single microtask, so the spinner is rarely visible.
  /// It is kept for correctness and future async implementations.
  bool _searching = false;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void dispose() {
    // Release platform text-input resources.
    _controller.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Search logic
  // ---------------------------------------------------------------------------

  /// Called on every keystroke in the search field.
  ///
  /// Queries shorter than 2 characters are ignored to avoid flooding the
  /// backend with single-character queries that would return too many results.
  ///
  /// The search is synchronous (no debounce) — fast enough for the typical
  /// local message store size.  For very large stores, consider adding a
  /// Timer-based debounce like ConversationSearchScreen uses.
  void _search(String query) {
    if (query.trim().length < 2) {
      // Clear results and stop spinner for short / empty queries.
      setState(() => _results = []);
      return;
    }

    setState(() => _searching = true);

    // context.read (not .watch) — we only need to call the method, not
    // subscribe this widget to MessagingState rebuilds.
    final messaging = context.read<MessagingState>();
    final results = messaging.searchMessages(query.trim());

    setState(() {
      _results = results;
      _searching = false;
    });
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        // The AppBar title IS the search field — autofocused so the keyboard
        // opens immediately and the user can type without an extra tap.
        title: TextField(
          controller: _controller,
          autofocus: true,
          decoration: const InputDecoration(
            hintText: 'Search messages...',
            // Remove the underline — the AppBar provides visual containment
            // and a border inside it looks redundant.
            border: InputBorder.none,
          ),
          onChanged: _search,
        ),
        actions: [
          // Clear button — only visible when there is text to clear.
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
          // Spinner while the synchronous search runs.
          ? const Center(child: CircularProgressIndicator())
          : _results.isEmpty
              // Two sub-states: idle (empty field) vs no-results.
              ? Center(
                  child: Text(
                    _controller.text.isEmpty
                        ? 'Type to search messages'
                        : 'No results found',
                    style: theme.textTheme.bodyLarge?.copyWith(
                      // Muted colour distinguishes the hint from real content.
                      color: theme.colorScheme.onSurface.withAlpha(150),
                    ),
                  ),
                )
              // Results list — one tile per matching message.
              : ListView.builder(
                  itemCount: _results.length,
                  itemBuilder: (context, index) {
                    final msg = _results[index];
                    return ListTile(
                      // Arrow direction indicates outgoing vs incoming so
                      // the user can quickly identify whether they sent
                      // the matching message or received it.
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
                      // Sender name and timestamp in the subtitle give
                      // enough context to identify which conversation this
                      // result belongs to without opening it.
                      subtitle: Text(
                        // \u2022 is a bullet (•) used as a separator.
                        '${msg.sender} \u2022 ${msg.timestamp}',
                        style: theme.textTheme.bodySmall,
                      ),
                      onTap: () {
                        // Return the room ID to the caller (ConversationListScreen)
                        // so it can navigate to the correct thread.
                        // The message ID is NOT returned here; scrolling to
                        // a specific message is handled by ConversationSearchScreen
                        // (the full-featured variant) instead.
                        Navigator.of(context).pop(msg.roomId);
                      },
                    );
                  },
                ),
    );
  }
}
