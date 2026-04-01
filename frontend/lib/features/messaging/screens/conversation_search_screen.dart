// conversation_search_screen.dart
//
// This file implements the ConversationSearchScreen — full-text search
// across all locally stored message history (§22.5.5).
//
// WHAT DOES THIS SCREEN DO?
// -------------------------
// The user types a query.  The screen passes the query to the Rust backend
// via BackendBridge.searchMessages(), which scans the local SQLite message
// store and returns a ranked list of matching MessageModels.
//
// KEY DESIGN DECISIONS
// --------------------
// 1. SEARCH IS LOCAL — no query ever leaves the device.  All matching
//    happens inside Rust against the on-device database.  This is a
//    privacy guarantee, not just a performance choice.
//
// 2. DEBOUNCING — we wait 300 ms after the last keystroke before running
//    the search.  This avoids hammering the backend on every character and
//    gives a snappy feel without unnecessary CPU work.
//
// 3. HIGHLIGHTING — matched substrings are highlighted in brand blue so
//    the user instantly sees WHY a result matched.  [_HighlightedText]
//    does this by splitting the text around query occurrences and using
//    a RichText widget with different TextSpans for highlighted vs normal.
//
// 4. SCROLL-TO-MESSAGE — tapping a result opens the thread for that room
//    AND eventually scrolls to the specific message (§22.5.5).  The
//    scroll-to parameter is forwarded to ThreadScreen for future wiring;
//    the scroll animation is implemented there, not here.
//
// 5. THREE UI STATES
//    - Idle (empty query): EmptyState with search icon + "type to search".
//    - Searching: LinearProgressIndicator below AppBar while the query runs.
//    - Results / no-results: ListView or no-results EmptyState.

import 'dart:async';
// dart:async provides Timer, which we use to debounce the search query.
// Debouncing means: restart a timer on every keystroke; only fire the
// search when the timer completes without being restarted.  This prevents
// calling the backend on every character typed.

import 'package:flutter/material.dart';
// Provider gives us context.read to access MessagingState without passing
// it manually through every constructor call.
import 'package:provider/provider.dart';

// MessageModel holds a single message returned by searchMessages().
// Fields we use: id (scroll target), roomId (which thread to open),
// sender (display name), text (body to highlight), timestamp.
import '../../../backend/models/message_models.dart';
// AppTheme.brand is the kBrand color (0xFF2C6EE2) used for highlighted text.
import '../../../app/app_theme.dart';
// EmptyState — the shared zero-data placeholder widget.
// We use it for both the idle state and the no-results state.
import '../../../core/widgets/empty_state.dart';
// MessagingState.searchMessages() — calls through BackendBridge to Rust.
import '../messaging_state.dart';
// ThreadScreen — the actual conversation view.  Tapping a search result
// opens the thread for that room.
import 'thread_screen.dart';

// ---------------------------------------------------------------------------
// ConversationSearchScreen (§22.5.5)
// ---------------------------------------------------------------------------

/// Full-text search across all locally stored message history.
///
/// Pushed from ConversationListScreen's search icon (§22.5.1).
///
/// The AppBar title IS the search field — autofocused on open.
/// A clear button appears in the AppBar actions when the field is non-empty.
class ConversationSearchScreen extends StatefulWidget {
  const ConversationSearchScreen({super.key});

  @override
  State<ConversationSearchScreen> createState() =>
      _ConversationSearchScreenState();
}

class _ConversationSearchScreenState extends State<ConversationSearchScreen> {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// Controls the AppBar search TextField.
  final TextEditingController _searchController = TextEditingController();

  /// The results of the most recent completed search.
  /// Empty while searching or when the query is blank.
  List<MessageModel> _results = [];

  /// True while a search is in progress — shows LinearProgressIndicator.
  bool _searching = false;

  /// Debounce timer.  Cancelled and restarted on every keystroke so the
  /// backend is only queried after 300 ms of typing inactivity.
  Timer? _debounce;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void dispose() {
    // Always cancel the debounce timer before disposing.  If the user closes
    // the screen mid-debounce and the timer fires, it would call setState on
    // a disposed widget, throwing a Flutter framework error.
    _debounce?.cancel();

    // Always dispose of TextEditingControllers to release the underlying
    // platform text input resources.
    _searchController.dispose();

    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Search logic
  // ---------------------------------------------------------------------------

  /// Called on every character change in the search field.
  ///
  /// Implements debouncing: cancels any existing timer and starts a new 300 ms
  /// countdown.  The search runs only when the countdown completes without
  /// being reset.  This means: if the user types "hello" in rapid succession,
  /// only one search for "hello" is triggered, not one per character.
  void _onSearchChanged(String query) {
    // Cancel the previous timer so we don't fire stale searches.
    _debounce?.cancel();

    // If the query is too short, clear results immediately — no need to wait.
    if (query.trim().length < 2) {
      setState(() {
        _results = [];
        _searching = false;
      });
      return;
    }

    // Show searching indicator immediately so the UI feels responsive.
    setState(() => _searching = true);

    // Start a 300 ms timer.  When it fires without being cancelled, run
    // the actual search against the backend.
    _debounce = Timer(const Duration(milliseconds: 300), () => _runSearch(query.trim()));
  }

  /// Executes the actual backend query and updates state with results.
  ///
  /// [query] is already trimmed by the caller.  This method calls into
  /// MessagingState which proxies to BackendBridge.searchMessages() → Rust.
  void _runSearch(String query) {
    // context.read (not .watch) — we only need to call the method, not
    // subscribe this method to MessagingState rebuilds.
    final results = context.read<MessagingState>().searchMessages(query);

    // Update both results and searching flag in one setState to produce a
    // single frame rebuild rather than two.
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
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(
        // BackButton is implicit from Navigator but we make it explicit here
        // to clarify intent — this is a pushed route, not a root screen.
        leading: const BackButton(),

        // The AppBar title IS the search field.  autofocus pops the keyboard
        // open as soon as the screen appears, so the user can type immediately.
        title: TextField(
          controller: _searchController,
          autofocus: true,
          decoration: const InputDecoration(
            hintText: 'Search messages...',
            // Remove underline and borders — the AppBar provides visual
            // containment; a border inside it would look redundant.
            border: InputBorder.none,
            contentPadding: EdgeInsets.zero,
          ),
          onChanged: _onSearchChanged,
        ),

        // Clear button appears only when there is text to clear.
        // Pressing it clears the controller, empties results, and lets
        // the user start a fresh query without closing the screen.
        actions: [
          if (_searchController.text.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.close),
              tooltip: 'Clear search',
              onPressed: () => setState(() {
                _searchController.clear();
                _results = [];
                _searching = false;
              }),
            ),
        ],
      ),

      body: Column(
        children: [
          // Searching indicator — a thin horizontal progress bar below the
          // AppBar.  Uses LinearProgressIndicator (indeterminate) because
          // we don't know how long the Rust query will take.
          // Animates in/out by switching between a sized and zero-height box.
          AnimatedContainer(
            duration: const Duration(milliseconds: 150),
            height: _searching ? 3 : 0,
            child: _searching
                ? LinearProgressIndicator(
                    backgroundColor: colorScheme.surfaceContainerHighest,
                    valueColor: AlwaysStoppedAnimation(colorScheme.primary),
                  )
                : null,
          ),

          // Main content area — fills remaining screen height.
          Expanded(child: _buildBody(colorScheme, textTheme)),
        ],
      ),
    );
  }

  /// Returns the appropriate body widget based on current search state.
  ///
  /// Three states:
  ///   1. Idle — query is blank or too short.  Show friendly prompt.
  ///   2. No results — query ran but returned nothing.  Show muted message.
  ///   3. Results — display the ranked list of matching messages.
  Widget _buildBody(ColorScheme colorScheme, TextTheme textTheme) {
    // Idle state: show the "type to search" prompt.
    if (_searchController.text.trim().length < 2) {
      return const EmptyState(
        icon: Icons.search,
        title: 'Search your messages',
        body: 'Type to search across all conversations.',
        // compact: true uses a smaller icon and tighter spacing —
        // appropriate for a prompt that appears immediately without
        // the user having done anything yet.
        compact: true,
      );
    }

    // No-results state (search ran but found nothing).
    if (!_searching && _results.isEmpty) {
      return EmptyState(
        icon: Icons.search_off_outlined,
        title: 'No results',
        body: 'No messages match "${_searchController.text}".',
      );
    }

    // Results state — a separated list, one tile per matching message.
    return ListView.separated(
      // Separator: thin 1px divider indented past the avatar (72px = 40px
      // avatar width + 16px leading padding + 16px spacing).
      separatorBuilder: (_, _) => const Divider(height: 1, indent: 72),
      itemCount: _results.length,
      itemBuilder: (ctx, i) {
        final msg = _results[i];
        return _SearchResultTile(
          message: msg,
          query: _searchController.text,
          onTap: () => Navigator.push(
            ctx,
            MaterialPageRoute(
              builder: (_) => ThreadScreen(
                roomId: msg.roomId,
                // Pass the message ID so ThreadScreen can scroll to it.
                // Scroll implementation lives in ThreadScreen (§22.5.2).
                scrollToMessageId: msg.id,
              ),
            ),
          ),
        );
      },
    );
  }
}

// ---------------------------------------------------------------------------
// _SearchResultTile — one result row in the search list (§22.5.5)
// ---------------------------------------------------------------------------

/// Displays a single search result: sender avatar, name, timestamp, and the
/// matching message body with query terms highlighted in brand blue.
class _SearchResultTile extends StatelessWidget {
  const _SearchResultTile({
    required this.message,
    required this.query,
    required this.onTap,
  });

  /// The matching message to display.
  final MessageModel message;

  /// The search query — passed to [_HighlightedText] for match highlighting.
  final String query;

  /// Called when the user taps the tile to open the thread.
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return ListTile(
      // Sender avatar — initial letter on a primary container circle.
      // Size 40 as specified in §22.5.5 (radius 20).
      leading: CircleAvatar(
        radius: 20,
        backgroundColor: colorScheme.primaryContainer,
        child: Text(
          message.sender.isNotEmpty ? message.sender[0].toUpperCase() : '?',
          style: TextStyle(
            color: colorScheme.onPrimaryContainer,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),

      // Title row: sender name on the left, timestamp on the right.
      // The Row with Expanded ensures the name truncates gracefully and
      // the timestamp never overflows off screen.
      title: Row(
        children: [
          Expanded(
            child: Text(
              message.sender,
              style: textTheme.titleSmall,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          const SizedBox(width: 8),
          Text(
            message.timestamp,
            style: textTheme.bodySmall?.copyWith(
              color: colorScheme.onSurfaceVariant,
              // Slightly smaller than bodySmall to keep the timestamp compact.
              fontSize: 11,
            ),
          ),
        ],
      ),

      // Highlighted message body — the query match is coloured in brand blue
      // so the user instantly sees which part of the text matched.
      subtitle: _HighlightedText(
        text: message.text,
        query: query,
        maxLines: 2,
        baseStyle: textTheme.bodySmall?.copyWith(
          color: colorScheme.onSurfaceVariant,
        ),
      ),

      onTap: onTap,
    );
  }
}

// ---------------------------------------------------------------------------
// _HighlightedText — RichText widget that colours query matches (§22.5.5)
// ---------------------------------------------------------------------------

/// Renders [text] with all occurrences of [query] highlighted.
///
/// Highlighting is done by splitting the text around the query string
/// (case-insensitive) and building a [RichText] with two [TextSpan] styles:
///   - Normal text: rendered in [baseStyle].
///   - Matched text: rendered in kBrand (brand blue) with a subtle tint.
///
/// If [query] is empty or not found, the text renders entirely in [baseStyle].
class _HighlightedText extends StatelessWidget {
  const _HighlightedText({
    required this.text,
    required this.query,
    this.maxLines,
    this.baseStyle,
  });

  /// The full message body to render.
  final String text;

  /// The search query to highlight within [text].
  final String query;

  /// Maximum number of lines before ellipsising.  Passed to RichText.
  final int? maxLines;

  /// Style for non-highlighted text.  Defaults to bodySmall if null.
  final TextStyle? baseStyle;

  @override
  Widget build(BuildContext context) {
    // If the query is blank, render plain text — no highlighting needed.
    if (query.isEmpty) {
      return Text(text, style: baseStyle, maxLines: maxLines,
          overflow: TextOverflow.ellipsis);
    }

    // Build a list of TextSpans by splitting the text around query matches.
    // We do a case-insensitive split so "Hello" matches "hello" in the text.
    final spans = <TextSpan>[];

    // Lowercase both strings for the search, but render original casing.
    final lowerText = text.toLowerCase();
    final lowerQuery = query.toLowerCase();
    int start = 0;

    // Walk through the text finding each occurrence of the query.
    while (true) {
      // Find the next match starting from [start].
      final matchIndex = lowerText.indexOf(lowerQuery, start);

      if (matchIndex == -1) {
        // No more matches — append the remaining tail as normal text.
        if (start < text.length) {
          spans.add(TextSpan(text: text.substring(start), style: baseStyle));
        }
        break;
      }

      // Append any text before this match in the default style.
      if (matchIndex > start) {
        spans.add(TextSpan(
          text: text.substring(start, matchIndex),
          style: baseStyle,
        ));
      }

      // Append the matched portion highlighted in brand blue.
      // We preserve original casing (text.substring) but colour it.
      spans.add(TextSpan(
        text: text.substring(matchIndex, matchIndex + query.length),
        style: (baseStyle ?? const TextStyle()).copyWith(
          // MeshTheme.brand = 0xFF2C6EE2 — the primary brand colour.
          color: MeshTheme.brand,
          // Subtle background tint draws the eye to the match without
          // being visually aggressive.
          backgroundColor: MeshTheme.brand.withValues(alpha: 0.12),
          fontWeight: FontWeight.w600,
        ),
      ));

      // Advance past this match to continue searching.
      start = matchIndex + query.length;
    }

    // RichText renders a list of TextSpans with heterogeneous styles in a
    // single paragraph — more efficient than nesting multiple Text widgets.
    return RichText(
      text: TextSpan(children: spans),
      maxLines: maxLines,
      overflow: TextOverflow.ellipsis,
    );
  }
}
